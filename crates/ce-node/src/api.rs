use anyhow::Result;
use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::{HeaderMap, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{delete, get, post, put},
    Json, Router,
};
use bollard::{container::RemoveContainerOptions, Docker};
use ce_chain::{channel_receipt_bytes, payer_settle_bytes, Block, Tx, TxKind};
use ce_container::{exec_in_container, ExecSpec};
use ce_identity::{verify, Identity, NodeId};
use ce_mesh::{MeshHandle, RpcRequest, RpcResponse, peer_id_from_node_id};
use ce_protocol::{BurnProof, Capability, CellAddress, CellSignal};
use futures::stream::{self, Stream};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    convert::Infallible,
    path::PathBuf,
    sync::{Arc, Mutex as StdMutex},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{broadcast, mpsc};

use crate::{
    Atlas, CeJobStatus, ChainHandle, JobRecord, JobStore, PeerCapacity, SignalRing, TxPool,
};

/// Per-sender last-accepted timestamp (ms). Used to enforce strictly increasing
/// nonces and close replay attacks within the 5-minute freshness window.
type NonceCache = Arc<StdMutex<HashMap<NodeId, u64>>>;

#[derive(Clone)]
struct ApiState {
    docker: Option<Docker>,
    chain: ChainHandle,
    host_node_id: NodeId,
    identity: Arc<Identity>,
    mesh_handle: MeshHandle,
    signals: SignalRing,
    /// Push channel — subscribers receive every validated CEP-1 signal instantly.
    signal_tx: broadcast::Sender<CellSignal>,
    /// Push channel — subscribers receive every accepted block instantly.
    block_tx: broadcast::Sender<Block>,
    /// Push channel — subscribers receive every accepted transaction instantly.
    tx_tx: broadcast::Sender<Tx>,
    send_nonce: Arc<AtomicU64>,
    job_store: JobStore,
    pool: TxPool,
    /// Poke the job manager to check for newly-signed settlements immediately.
    settle_notify_tx: mpsc::Sender<()>,
    /// CE data directory; used to load devices.toml for sync/exec auth.
    data_dir: PathBuf,
    /// Anti-replay: last accepted timestamp per sender NodeId.
    nonce_cache: NonceCache,
    /// Peer capacity atlas updated by incoming capacity signals.
    atlas: Atlas,
    /// libp2p listen port — used by GET /bootstrap to build multiaddrs.
    listen_port: u16,
    /// This node's capability self-tags — what grant selectors are matched against.
    self_tags: Arc<Vec<String>>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(ErrorBody { error: msg.into() })).into_response()
}

/// Serde helpers: 128-bit credit amounts (base units) are carried in JSON as decimal
/// **strings**, not numbers. Values in base units routinely exceed JavaScript's 2^53
/// safe-integer limit, so a JSON number would silently lose precision. Internally
/// everything stays integer base units; only the JSON boundary uses strings.
mod amount_str {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        String::deserialize(d)?.trim().parse().map_err(serde::de::Error::custom)
    }
}
mod amount_str_i128 {
    use serde::Serializer;
    // Serialize-only: the i128 field (balance) is response-only.
    pub fn serialize<S: Serializer>(v: &i128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
}
mod amount_str_opt {
    use serde::Serializer;
    pub fn serialize<S: Serializer>(v: &Option<u128>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(x) => s.serialize_str(&x.to_string()),
            None => s.serialize_none(),
        }
    }
}

/// Snapshot returned by GET /status.
#[derive(Debug, Serialize)]
pub struct NodeStatusResponse {
    pub node_id: String,
    pub height: u64,
    pub difficulty: u8,
    #[serde(with = "amount_str_i128")]
    pub balance: i128,
}

// ----- POST /jobs/bid -----

#[derive(Debug, Deserialize)]
pub struct BidRequest {
    pub image: String,
    #[serde(default)]
    pub cmd: Vec<String>,
    #[serde(default)]
    pub env: Vec<(String, String)>,
    pub cpu_cores: u32,
    pub mem_mb: u64,
    pub duration_secs: u64,
    #[serde(with = "amount_str")]
    pub bid: u128,
}

#[derive(Debug, Serialize)]
pub struct BidResponse {
    /// 64-hex-char CE job ID; use with GET /jobs/:id and POST /jobs/:id/settle.
    pub job_id: String,
}

async fn bid_job(
    State(state): State<ApiState>,
    Json(req): Json<BidRequest>,
) -> Response {
    let payer = state.identity.node_id();

    // Require a positive on-chain balance before accepting the bid.
    let balance = state.chain.balance(payer).await;
    if balance <= 0 {
        return err(
            StatusCode::PAYMENT_REQUIRED,
            format!("payer balance is {balance}; must be positive to bid"),
        );
    }

    // Derive a unique job_id from the current timestamp and node identity.
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let job_id: [u8; 32] = Sha256::digest(
        bincode::serialize(&(ts, payer, req.image.as_str())).unwrap_or_default(),
    )
    .into();

    let kind = ce_chain::TxKind::JobBid {
        job_id,
        payer,
        bid: req.bid,
        image: req.image,
        cmd: req.cmd,
        env: req.env,
        cpu_cores: req.cpu_cores,
        mem_mb: req.mem_mb,
        duration_secs: req.duration_secs,
    };
    let data = bincode::serialize(&kind).expect("serialize JobBid");
    let sig = state.identity.sign(&data);
    let tx = ce_chain::Tx::new(kind, payer, sig);

    state.pool.add(tx.clone()).await;
    let _ = state.mesh_handle.broadcast_tx(&tx).await;

    // Record a Pending entry so GET /jobs/:id works on this node immediately.
    {
        let mut store = state.job_store.lock().await;
        store.insert(
            job_id,
            JobRecord {
                job_id,
                payer,
                container_id: None,
                status: CeJobStatus::Pending,
                payer_sig: None,
                cost: None,
                bid: req.bid,
                duration_secs: req.duration_secs,
            },
        );
    }

    (StatusCode::CREATED, Json(BidResponse { job_id: hex::encode(job_id) })).into_response()
}

// ----- GET /jobs/:id -----

#[derive(Debug, Serialize)]
pub struct JobStatusResponse {
    pub job_id: String,
    /// "pending" | "running" | "awaiting_settlement" | "settled" | "failed"
    pub status: String,
    pub container_id: Option<String>,
    #[serde(with = "amount_str_opt")]
    pub cost: Option<u128>,
}

fn status_string(s: &CeJobStatus) -> String {
    match s {
        CeJobStatus::Pending => "pending".into(),
        CeJobStatus::Running => "running".into(),
        CeJobStatus::AwaitingSettlement => "awaiting_settlement".into(),
        CeJobStatus::Settled => "settled".into(),
        CeJobStatus::Failed(msg) => format!("failed: {msg}"),
    }
}

async fn job_status(State(state): State<ApiState>, Path(id): Path<String>) -> Response {
    let job_id: [u8; 32] = match hex::decode(&id).ok().and_then(|b| b.try_into().ok()) {
        Some(arr) => arr,
        None => return err(StatusCode::BAD_REQUEST, "job id must be 64 hex chars"),
    };

    let store = state.job_store.lock().await;
    match store.get(&job_id) {
        Some(record) => (
            StatusCode::OK,
            Json(JobStatusResponse {
                job_id: id,
                status: status_string(&record.status),
                container_id: record.container_id.clone(),
                cost: record.cost,
            }),
        )
            .into_response(),
        None => err(StatusCode::NOT_FOUND, "job not found"),
    }
}

// ----- POST /jobs/:id/settle -----

#[derive(Debug, Deserialize)]
pub struct SettleRequest {
    /// Agreed settlement amount in base units.
    #[serde(with = "amount_str")]
    pub cost: u128,
    /// Payer's Ed25519 signature over payer_settle_bytes(job_id, host, cost) v2, 128 hex chars.
    pub payer_sig: String,
}

async fn settle_job(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(req): Json<SettleRequest>,
) -> Response {
    let job_id: [u8; 32] = match hex::decode(&id).ok().and_then(|b| b.try_into().ok()) {
        Some(arr) => arr,
        None => return err(StatusCode::BAD_REQUEST, "job id must be 64 hex chars"),
    };

    let payer_sig: [u8; 64] =
        match hex::decode(&req.payer_sig).ok().and_then(|b| b.try_into().ok()) {
            Some(arr) => arr,
            None => return err(StatusCode::BAD_REQUEST, "payer_sig must be 128 hex chars"),
        };

    let payer = {
        let store = state.job_store.lock().await;
        match store.get(&job_id) {
            Some(r) => r.payer,
            None => return err(StatusCode::NOT_FOUND, "job not found"),
        }
    };

    // Verify the payer co-signature before storing (host is bound in v2 to prevent sig theft).
    let bytes = payer_settle_bytes(&job_id, &state.host_node_id, req.cost);
    if verify(&payer, &bytes, &payer_sig).is_err() {
        return err(StatusCode::BAD_REQUEST, "invalid payer signature");
    }

    {
        let mut store = state.job_store.lock().await;
        if let Some(r) = store.get_mut(&job_id) {
            r.payer_sig = Some(payer_sig);
            r.cost = Some(req.cost);
        }
    }

    // Wake the job manager so it processes the new signature promptly.
    let _ = state.settle_notify_tx.send(()).await;

    StatusCode::ACCEPTED.into_response()
}

// ----- DELETE /jobs/:id -----

async fn stop_job(State(state): State<ApiState>, Path(id): Path<String>) -> Response {
    let docker = match &state.docker {
        Some(d) => d,
        None => return err(StatusCode::SERVICE_UNAVAILABLE, "Docker not available on this node"),
    };

    // id may be either a CE job_id (hex) or a Docker container ID.
    // Resolve to Docker container ID via the job store when possible.
    let container_id = if let Ok(bytes) = hex::decode(&id) {
        if let Ok(arr) = <[u8; 32]>::try_from(bytes) {
            let store = state.job_store.lock().await;
            store.get(&arr).and_then(|r| r.container_id.clone()).unwrap_or(id)
        } else {
            id
        }
    } else {
        id
    };

    let opts = RemoveContainerOptions { force: true, ..Default::default() };
    match docker.remove_container(&container_id, Some(opts)).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err(StatusCode::NOT_FOUND, format!("remove container: {e}")),
    }
}

// ----- GET /status -----

async fn node_status(State(state): State<ApiState>) -> Response {
    let snap = state.chain.chain_status(state.host_node_id).await;
    (
        StatusCode::OK,
        Json(NodeStatusResponse {
            node_id: hex::encode(state.host_node_id),
            height: snap.height,
            difficulty: snap.difficulty,
            balance: snap.balance,
        }),
    )
        .into_response()
}

// ----- CEP-1 signals -----

#[derive(Debug, Serialize)]
struct SignalView {
    from: String,
    to: String,
    capabilities: Vec<Capability>,
    payload_hex: String,
    burn_proof: Option<BurnProofView>,
    nonce: u64,
    id: String,
}

#[derive(Debug, Serialize)]
struct BurnProofView {
    tx_id: String,
    #[serde(with = "amount_str")]
    amount: u128,
    block_height: u64,
    block_hash: String,
}

fn signal_view(s: &CellSignal) -> SignalView {
    let to = match &s.to {
        CellAddress::Broadcast => "broadcast".to_string(),
        CellAddress::Node(n) => hex::encode(n),
    };
    SignalView {
        from: hex::encode(s.from),
        to,
        capabilities: s.capabilities.clone(),
        payload_hex: hex::encode(&s.payload),
        burn_proof: s.burn_proof.as_ref().map(|b| BurnProofView {
            tx_id: hex::encode(b.tx_id),
            amount: b.amount,
            block_height: b.block_height,
            block_hash: hex::encode(b.block_hash),
        }),
        nonce: s.nonce,
        id: hex::encode(s.id()),
    }
}

async fn list_signals(State(state): State<ApiState>) -> Response {
    let ring = state.signals.lock().await;
    let out: Vec<SignalView> = ring.iter().map(signal_view).collect();
    (StatusCode::OK, Json(out)).into_response()
}

#[derive(Debug, Deserialize)]
pub struct SendSignalRequest {
    #[serde(default)]
    pub payload_hex: String,
    pub to: String,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    pub burn_tx_id_hex: Option<String>,
}

#[derive(Debug, Serialize)]
struct SendSignalResponse {
    id: String,
    nonce: u64,
}

async fn send_signal(
    State(state): State<ApiState>,
    Json(req): Json<SendSignalRequest>,
) -> Response {
    let to = if req.to == "broadcast" {
        CellAddress::Broadcast
    } else {
        match hex::decode(&req.to).ok().and_then(|b| b.try_into().ok()) {
            Some(arr) => CellAddress::Node(arr),
            None => {
                return err(
                    StatusCode::BAD_REQUEST,
                    "`to` must be \"broadcast\" or a 64-hex-char node id",
                );
            }
        }
    };

    let payload = match hex::decode(&req.payload_hex) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("payload_hex: {e}")),
    };

    let burn_proof = if let Some(tx_hex) = req.burn_tx_id_hex.as_deref() {
        let tx_id: [u8; 32] = match hex::decode(tx_hex).ok().and_then(|b| b.try_into().ok()) {
            Some(arr) => arr,
            None => return err(StatusCode::BAD_REQUEST, "burn_tx_id_hex must be 64 hex chars"),
        };
        let Some((tx, height, hash)) = state.chain.tx_by_id(tx_id).await else {
            return err(
                StatusCode::BAD_REQUEST,
                "burn_tx_id_hex does not match any tx in the local chain",
            );
        };
        let Some(amount) = tx_value(&tx) else {
            return err(StatusCode::BAD_REQUEST, "referenced tx has no burnable amount");
        };
        Some(BurnProof { tx_id, amount, block_height: height, block_hash: hash })
    } else {
        // No burn_tx_id_hex supplied. The local node is implicitly trusted — the API
        // is only reachable on localhost — so we allow free payloads from here.
        None
    };

    let nonce = state.send_nonce.fetch_add(1, Ordering::Relaxed);
    let signal = CellSignal::build(
        state.identity.node_id(),
        to,
        req.capabilities,
        payload,
        burn_proof,
        nonce,
        &state.identity,
    );

    if let Err(e) = state.mesh_handle.broadcast_signal(&signal).await {
        return err(StatusCode::INTERNAL_SERVER_ERROR, format!("broadcast: {e}"));
    }

    {
        let mut ring = state.signals.lock().await;
        if ring.len() >= 100 {
            ring.pop_front();
        }
        ring.push_back(signal.clone());
    }

    (
        StatusCode::ACCEPTED,
        Json(SendSignalResponse { id: hex::encode(signal.id()), nonce }),
    )
        .into_response()
}

fn tx_value(tx: &ce_chain::Tx) -> Option<u128> {
    use ce_chain::TxKind;
    match &tx.kind {
        TxKind::Transfer { amount, .. } => Some(*amount),
        TxKind::UptimeReward { amount, .. } => Some(*amount),
        TxKind::JobBid { bid, .. } => Some(*bid),
        TxKind::JobSettle { cost, .. } => Some(*cost),
        TxKind::Heartbeat { amount, .. } => Some(*amount),
        TxKind::JobExpire { .. }
        | TxKind::TrustGrant { .. }
        | TxKind::ChannelOpen { .. }
        | TxKind::ChannelClose { .. }
        | TxKind::ChannelExpire { .. } => None,
    }
}

// ----- Device auth -----

/// Verify CE device auth headers against the request body and the devices registry.
///
/// - `body`: the raw request body bytes (already read by the caller).
///   The signature commits to SHA256(body), so a tampered body invalidates the sig.
/// - `nonce_cache`: per-sender last-accepted timestamp; enforces strictly
///   increasing nonces to prevent replay within the 5-minute window.
fn verify_device_auth(
    headers: &HeaderMap,
    method: &str,
    path: &str,
    data_dir: &std::path::Path,
    body: &[u8],
    nonce_cache: &NonceCache,
    required: crate::grants::Permission,
    self_tags: &[String],
) -> Result<NodeId, Response> {
    let from_hex = headers
        .get("x-ce-from")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "missing X-CE-From"))?;
    let ts_str = headers
        .get("x-ce-timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "missing X-CE-Timestamp"))?;
    let sig_hex = headers
        .get("x-ce-sig")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "missing X-CE-Sig"))?;

    let from: NodeId = crate::auth::parse_from_header(from_hex)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "X-CE-From must be 64 hex chars"))?;

    let ts_ms: u64 = ts_str
        .parse()
        .map_err(|_| err(StatusCode::BAD_REQUEST, "bad X-CE-Timestamp"))?;

    let sig_bytes = hex::decode(sig_hex)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "bad X-CE-Sig"))?;
    let sig: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| err(StatusCode::BAD_REQUEST, "X-CE-Sig must be 128 hex chars"))?;

    // Freshness: timestamp must be within ±5 minutes of server time.
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    if now_ms.abs_diff(ts_ms) > 5 * 60 * 1000 {
        return Err(err(StatusCode::UNAUTHORIZED, "X-CE-Timestamp out of range"));
    }

    // Anti-replay: require strictly increasing timestamp per sender.
    {
        let mut cache = nonce_cache.lock().expect("nonce cache poisoned");
        if let Some(&last) = cache.get(&from) {
            if ts_ms <= last {
                return Err(err(
                    StatusCode::UNAUTHORIZED,
                    format!("replayed request: ts {ts_ms} <= last accepted {last}"),
                ));
            }
        }
        // Update before signature check so a burst of replays can't race through.
        cache.insert(from, ts_ms);
    }

    // Signature covers method + path + timestamp + SHA256(body).
    let bytes = crate::auth::auth_bytes(method, path, ts_ms, body);
    if let Err(_) = verify(&from, &bytes, &sig) {
        // On bad sig, roll back the nonce update so the client can retry with a newer ts.
        let mut cache = nonce_cache.lock().expect("nonce cache poisoned");
        cache.remove(&from);
        return Err(err(StatusCode::UNAUTHORIZED, "invalid CE signature"));
    }

    // Authorization: a trusted admin has full scope; otherwise the request must carry a
    // scoped grant (X-CE-Grant header) covering this action on this workspace.
    let devices = crate::devices::Devices::load_or_empty(&data_dir.join("machines.toml"));
    let grant = match headers.get("x-ce-grant").and_then(|v| v.to_str().ok()) {
        Some(token) => match crate::grants::SignedGrant::decode(token) {
            Ok(g) => Some(g),
            Err(_) => return Err(err(StatusCode::BAD_REQUEST, "malformed X-CE-Grant")),
        },
        None => None,
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    if let Err(reason) =
        crate::grants::authorize(&devices, self_tags, now, &from, required, grant.as_ref())
    {
        return Err(err(StatusCode::FORBIDDEN, reason));
    }

    Ok(from)
}

// ----- PUT /sync/*path -----

async fn sync_put(
    State(state): State<ApiState>,
    headers: HeaderMap,
    req: Request,
) -> Response {
    let path = req.uri().path().to_string();

    // Read body FIRST — auth signature commits to SHA256(body).
    let body_bytes = match axum::body::to_bytes(req.into_body(), 256 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("read body: {e}")),
    };

    if let Err(resp) =
        verify_device_auth(&headers, "PUT", &path, &state.data_dir, &body_bytes, &state.nonce_cache, crate::grants::Permission::Sync, &state.self_tags)
    {
        return resp;
    }

    // Resolve the target path under the user's home directory.
    let rel = path.trim_start_matches("/sync/");
    let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    let target = home.join(rel);
    let canonical_home = home.canonicalize().unwrap_or(home.clone());

    let canonical_target = match target.parent() {
        Some(p) => {
            let _ = std::fs::create_dir_all(p);
            match target.canonicalize().ok().or_else(|| {
                p.canonicalize().ok().map(|cp| cp.join(target.file_name().unwrap_or_default()))
            }) {
                Some(c) => c,
                None => return err(StatusCode::BAD_REQUEST, "cannot resolve target path"),
            }
        }
        None => return err(StatusCode::BAD_REQUEST, "invalid path"),
    };
    if !canonical_target.starts_with(&canonical_home) {
        return err(StatusCode::BAD_REQUEST, "path traversal not allowed");
    }

    if let Some(parent) = canonical_target.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return err(StatusCode::INTERNAL_SERVER_ERROR, format!("mkdir: {e}"));
        }
    }
    if let Err(e) = std::fs::write(&canonical_target, &body_bytes) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, format!("write: {e}"));
    }

    tracing::info!("sync PUT {} ({} bytes)", canonical_target.display(), body_bytes.len());
    StatusCode::NO_CONTENT.into_response()
}

// ----- GET /sync/*path -----

async fn sync_get(
    State(state): State<ApiState>,
    headers: HeaderMap,
    req: Request,
) -> Response {
    let path = req.uri().path().to_string();
    // GET has no body; sign against empty bytes.
    if let Err(resp) =
        verify_device_auth(&headers, "GET", &path, &state.data_dir, b"", &state.nonce_cache, crate::grants::Permission::Sync, &state.self_tags)
    {
        return resp;
    }

    let rel = path.trim_start_matches("/sync/");
    let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    let target = home.join(rel);
    let canonical_home = home.canonicalize().unwrap_or(home.clone());
    let canonical_target = match target.canonicalize() {
        Ok(c) => c,
        Err(_) => return err(StatusCode::NOT_FOUND, "file not found"),
    };
    if !canonical_target.starts_with(&canonical_home) {
        return err(StatusCode::BAD_REQUEST, "path traversal not allowed");
    }

    match std::fs::read(&canonical_target) {
        Ok(data) => (StatusCode::OK, Body::from(data)).into_response(),
        Err(_) => err(StatusCode::NOT_FOUND, "file not found"),
    }
}

// ----- POST /exec -----

#[derive(Debug, Deserialize)]
pub struct ExecRequest {
    /// Docker image to run the command in, e.g. "rust:latest" or "alpine:latest".
    pub image: String,
    /// Command and arguments, e.g. ["cargo", "build", "--release"].
    pub cmd: Vec<String>,
    /// Working directory relative to `~/` (e.g. `~/code/ce` or `code/ce`). Defaults to `~/`.
    #[serde(default)]
    pub cwd: Option<String>,
}

#[derive(Debug, Serialize)]
struct ExecResponse {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

async fn exec_command(State(state): State<ApiState>, headers: HeaderMap, req: Request) -> Response {
    // Read body first — auth signature must commit to the body hash.
    let body_bytes = match axum::body::to_bytes(req.into_body(), 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("read body: {e}")),
    };

    if let Err(resp) =
        verify_device_auth(&headers, "POST", "/exec", &state.data_dir, &body_bytes, &state.nonce_cache, crate::grants::Permission::Exec, &state.self_tags)
    {
        return resp;
    }

    let req: ExecRequest = match serde_json::from_slice(&body_bytes) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("invalid JSON: {e}")),
    };

    if req.cmd.is_empty() {
        return err(StatusCode::BAD_REQUEST, "cmd must not be empty");
    }
    if req.image.is_empty() {
        return err(StatusCode::BAD_REQUEST, "image must not be empty");
    }

    let docker = match &state.docker {
        Some(d) => d,
        None => return err(StatusCode::SERVICE_UNAVAILABLE, "Docker not available on this node"),
    };

    let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    let spec = ExecSpec { image: req.image.clone(), cmd: req.cmd.clone(), cwd: req.cwd.clone() };

    match exec_in_container(docker, &spec, &home).await {
        Ok((stdout, stderr, exit_code)) => {
            let exit_code = exit_code as i32;
            tracing::info!(
                "exec {:?} image={} → exit {exit_code}",
                req.cmd, req.image
            );
            (
                StatusCode::OK,
                Json(ExecResponse { stdout, stderr, exit_code }),
            )
                .into_response()
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, format!("exec failed: {e}")),
    }
}

// ----- GET /jobs -----

#[derive(Debug, Serialize)]
struct JobListItem {
    job_id: String,
    status: String,
    payer: String,
    container_id: Option<String>,
    #[serde(with = "amount_str_opt")]
    cost: Option<u128>,
    #[serde(with = "amount_str")]
    bid: u128,
}

async fn list_jobs(State(state): State<ApiState>) -> Response {
    let store = state.job_store.lock().await;
    let jobs: Vec<JobListItem> = store
        .values()
        .map(|r| JobListItem {
            job_id: hex::encode(r.job_id),
            status: status_string(&r.status),
            payer: hex::encode(r.payer),
            container_id: r.container_id.clone(),
            cost: r.cost,
            bid: r.bid,
        })
        .collect();
    (StatusCode::OK, Json(jobs)).into_response()
}

// ----- POST /transfer -----

#[derive(Debug, Deserialize)]
pub struct TransferRequest {
    /// Recipient NodeId as 64 hex chars.
    pub to: String,
    #[serde(with = "amount_str")]
    pub amount: u128,
}

#[derive(Debug, Serialize)]
struct TransferResponse {
    tx_id: String,
}

async fn transfer(State(state): State<ApiState>, Json(req): Json<TransferRequest>) -> Response {
    let to: NodeId = match hex::decode(&req.to).ok().and_then(|b| b.try_into().ok()) {
        Some(arr) => arr,
        None => return err(StatusCode::BAD_REQUEST, "`to` must be 64 hex chars"),
    };
    if req.amount == 0 {
        return err(StatusCode::BAD_REQUEST, "amount must be > 0");
    }
    let from = state.identity.node_id();
    let balance = state.chain.balance(from).await;
    if balance < req.amount as i128 {
        return err(
            StatusCode::PAYMENT_REQUIRED,
            format!("balance {balance} insufficient for transfer {}", req.amount),
        );
    }
    let kind = ce_chain::TxKind::Transfer { from, to, amount: req.amount };
    let data = bincode::serialize(&kind).expect("serialize Transfer");
    let sig = state.identity.sign(&data);
    let tx = ce_chain::Tx::new(kind, from, sig);
    let tx_id = hex::encode(tx.id());
    state.pool.add(tx.clone()).await;
    let _ = state.mesh_handle.broadcast_tx(&tx).await;
    (StatusCode::CREATED, Json(TransferResponse { tx_id })).into_response()
}

// ----- POST /mesh-exec -----
//
// Routes an exec request to a remote trusted device through the CE mesh (/ce/rpc/1).
// The local node must be running with a relay connection; the target is identified by
// CE NodeId (not an IP address). See docs/architecture.md for the full flow.

#[derive(Debug, Deserialize)]
struct MeshExecRequest {
    /// CE NodeId of the target device (64 hex chars).
    node_id: String,
    /// Optional relay circuit multiaddr for dialing the target if not yet in the DHT.
    /// Corresponds to the `multiaddr` field in machines.toml.
    #[serde(default)]
    hint_multiaddr: String,
    image: String,
    #[serde(default)]
    cmd: Vec<String>,
    #[serde(default)]
    cwd: Option<String>,
}

async fn mesh_exec(State(state): State<ApiState>, Json(req): Json<MeshExecRequest>) -> Response {
    let node_id: NodeId = match hex::decode(&req.node_id).ok().and_then(|b| b.try_into().ok()) {
        Some(arr) => arr,
        None => return err(StatusCode::BAD_REQUEST, "`node_id` must be 64 hex chars"),
    };
    let peer_id = match peer_id_from_node_id(&node_id) {
        Ok(p) => p,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("invalid node_id: {e}")),
    };
    if req.cmd.is_empty() {
        return err(StatusCode::BAD_REQUEST, "cmd must not be empty");
    }

    // Provide the relay circuit as a dial hint so the swarm can reach the target even
    // if it isn't already in the Kademlia routing table.
    if !req.hint_multiaddr.is_empty() {
        let _ = state.mesh_handle.dial(req.hint_multiaddr).await;
    }

    let rpc_req = RpcRequest::Exec {
        from_node: state.host_node_id,
        image: req.image,
        cmd: req.cmd,
        cwd: req.cwd,
        // The proxy node is itself a trusted admin of the target in the personal-fleet case.
        // Forwarding a caller-supplied grant through the proxy is a future enhancement.
        grant: None,
    };

    match state.mesh_handle.send_rpc(peer_id, rpc_req).await {
        Ok(RpcResponse::ExecResult { stdout, stderr, exit_code }) => (
            StatusCode::OK,
            Json(serde_json::json!({ "stdout": stdout, "stderr": stderr, "exit_code": exit_code })),
        )
            .into_response(),
        Ok(RpcResponse::Error(e)) => err(StatusCode::BAD_GATEWAY, e),
        Ok(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "unexpected rpc response type"),
        Err(e) => err(StatusCode::GATEWAY_TIMEOUT, format!("mesh rpc failed: {e}")),
    }
}

// ----- POST /mesh-deploy -----
//
// Directed placement: deploy a long-running cell on a SPECIFIC remote host through the mesh,
// vs. broadcasting a JobBid to whoever accepts. Returns the host-assigned job_id.

#[derive(Debug, Deserialize)]
struct MeshDeployRequest {
    /// CE NodeId of the target host (64 hex chars).
    node_id: String,
    /// Optional relay circuit multiaddr dial hint.
    #[serde(default)]
    hint_multiaddr: String,
    image: String,
    #[serde(default)]
    cmd: Vec<String>,
    cpu_cores: u32,
    mem_mb: u64,
    duration_secs: u64,
    /// Funding committed for the cell, in base units (string).
    #[serde(with = "amount_str")]
    bid: u128,
    /// Optional scoped grant token (from `ce grant`), forwarded to the host.
    #[serde(default)]
    grant: Option<String>,
}

/// Decode an optional grant token to RPC-ready bincode bytes; validates the token.
fn grant_to_bytes(token: &Option<String>) -> Result<Option<Vec<u8>>, Response> {
    match token {
        Some(t) => match crate::grants::SignedGrant::decode(t) {
            Ok(g) => Ok(Some(bincode::serialize(&g).unwrap_or_default())),
            Err(_) => Err(err(StatusCode::BAD_REQUEST, "malformed grant token")),
        },
        None => Ok(None),
    }
}

async fn mesh_deploy(State(state): State<ApiState>, Json(req): Json<MeshDeployRequest>) -> Response {
    let node_id: NodeId = match hex::decode(&req.node_id).ok().and_then(|b| b.try_into().ok()) {
        Some(arr) => arr,
        None => return err(StatusCode::BAD_REQUEST, "`node_id` must be 64 hex chars"),
    };
    let peer_id = match peer_id_from_node_id(&node_id) {
        Ok(p) => p,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("invalid node_id: {e}")),
    };
    if req.image.is_empty() {
        return err(StatusCode::BAD_REQUEST, "image must not be empty");
    }
    let grant = match grant_to_bytes(&req.grant) {
        Ok(g) => g,
        Err(resp) => return resp,
    };
    if !req.hint_multiaddr.is_empty() {
        let _ = state.mesh_handle.dial(req.hint_multiaddr).await;
    }

    let rpc_req = RpcRequest::Deploy {
        from_node: state.host_node_id,
        image: req.image,
        cmd: req.cmd,
        cpu_cores: req.cpu_cores,
        mem_mb: req.mem_mb,
        duration_secs: req.duration_secs,
        bid: req.bid,
        grant,
    };

    match state.mesh_handle.send_rpc(peer_id, rpc_req).await {
        Ok(RpcResponse::Deployed { job_id }) => {
            (StatusCode::OK, Json(serde_json::json!({ "job_id": job_id }))).into_response()
        }
        Ok(RpcResponse::Error(e)) => err(StatusCode::BAD_GATEWAY, e),
        Ok(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "unexpected rpc response type"),
        Err(e) => err(StatusCode::GATEWAY_TIMEOUT, format!("mesh rpc failed: {e}")),
    }
}

// ----- POST /mesh-kill -----

#[derive(Debug, Deserialize)]
struct MeshKillRequest {
    node_id: String,
    #[serde(default)]
    hint_multiaddr: String,
    /// The 64-hex job id returned by /mesh-deploy.
    job_id: String,
    #[serde(default)]
    grant: Option<String>,
}

async fn mesh_kill(State(state): State<ApiState>, Json(req): Json<MeshKillRequest>) -> Response {
    let node_id: NodeId = match hex::decode(&req.node_id).ok().and_then(|b| b.try_into().ok()) {
        Some(arr) => arr,
        None => return err(StatusCode::BAD_REQUEST, "`node_id` must be 64 hex chars"),
    };
    let peer_id = match peer_id_from_node_id(&node_id) {
        Ok(p) => p,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("invalid node_id: {e}")),
    };
    let grant = match grant_to_bytes(&req.grant) {
        Ok(g) => g,
        Err(resp) => return resp,
    };
    if !req.hint_multiaddr.is_empty() {
        let _ = state.mesh_handle.dial(req.hint_multiaddr).await;
    }

    let rpc_req = RpcRequest::Kill { from_node: state.host_node_id, job_id: req.job_id, grant };
    match state.mesh_handle.send_rpc(peer_id, rpc_req).await {
        Ok(RpcResponse::Killed) => StatusCode::NO_CONTENT.into_response(),
        Ok(RpcResponse::Error(e)) => err(StatusCode::BAD_GATEWAY, e),
        Ok(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "unexpected rpc response type"),
        Err(e) => err(StatusCode::GATEWAY_TIMEOUT, format!("mesh rpc failed: {e}")),
    }
}

// ----- PUT /mesh-sync/:node_id/*path -----
//
// Writes a single file on a remote trusted device through the CE mesh.
// `:node_id` = 64 hex char CE NodeId of target. `*path` = path relative to target's `~/`.
// Query param `hint` = optional relay circuit multiaddr dial hint.

async fn mesh_sync_put(
    State(state): State<ApiState>,
    Path((node_id_hex, file_path)): Path<(String, String)>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
    body: axum::body::Bytes,
) -> Response {
    let node_id: NodeId = match hex::decode(&node_id_hex).ok().and_then(|b| b.try_into().ok()) {
        Some(arr) => arr,
        None => return err(StatusCode::BAD_REQUEST, "node_id must be 64 hex chars"),
    };
    let peer_id = match peer_id_from_node_id(&node_id) {
        Ok(p) => p,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("invalid node_id: {e}")),
    };

    if let Some(hint) = params.get("hint") {
        if !hint.is_empty() {
            let _ = state.mesh_handle.dial(hint.clone()).await;
        }
    }

    let rpc_req = RpcRequest::SyncFile {
        from_node: state.host_node_id,
        path: file_path,
        data: body.to_vec(),
        grant: None,
    };

    match state.mesh_handle.send_rpc(peer_id, rpc_req).await {
        Ok(RpcResponse::SyncAck) => StatusCode::NO_CONTENT.into_response(),
        Ok(RpcResponse::Error(e)) => err(StatusCode::BAD_GATEWAY, e),
        Ok(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "unexpected rpc response type"),
        Err(e) => err(StatusCode::GATEWAY_TIMEOUT, format!("mesh rpc failed: {e}")),
    }
}

// ----- GET /bootstrap -----

#[derive(Serialize)]
struct BootstrapResponse {
    peers: Vec<String>,
}

async fn get_bootstrap(State(state): State<ApiState>) -> Response {
    let peer_id = match ce_mesh::peer_id_from_secret(state.identity.secret_bytes()) {
        Ok(p) => p.to_string(),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "peer id unavailable"),
    };
    let port = state.listen_port;
    let mut peers = vec![];

    // CE_EXTERNAL_IP: explicit public IPv4, set on relay nodes.
    if let Ok(ext_ip) = std::env::var("CE_EXTERNAL_IP") {
        peers.push(format!("/ip4/{ext_ip}/tcp/{port}/p2p/{peer_id}"));
    }
    // CE_EXTERNAL_HOST: DNS hostname for the relay (e.g. relay.ce-net.com).
    if let Ok(hostname) = std::env::var("CE_EXTERNAL_HOST") {
        peers.push(format!("/dns4/{hostname}/tcp/{port}/p2p/{peer_id}"));
    }

    // If neither env var is set, return just the peer_id so clients can at least
    // learn it from their known host.
    if peers.is_empty() {
        peers.push(format!("/p2p/{peer_id}"));
    }

    (StatusCode::OK, Json(BootstrapResponse { peers })).into_response()
}

// ----- SSE push streams -----
//
// Three endpoints that push events the instant they arrive — no polling required.
// Clients connect once and stay connected; the server delivers each event as a
// newline-delimited JSON Server-Sent Event.
//
// Usage:
//   curl -N http://localhost:8080/signals/stream
//   curl -N http://localhost:8080/blocks/stream
//   curl -N http://localhost:8080/transactions/stream

#[derive(Debug, Serialize)]
struct BlockView {
    index: u64,
    hash: String,
    prev_hash: String,
    timestamp: u64,
    miner: String,
    tx_count: usize,
    nonce: u64,
}

fn block_view(b: &Block) -> BlockView {
    BlockView {
        index: b.index,
        hash: hex::encode(b.hash()),
        prev_hash: hex::encode(b.prev_hash),
        timestamp: b.timestamp,
        miner: hex::encode(b.miner),
        tx_count: b.transactions.len(),
        nonce: b.nonce,
    }
}

#[derive(Debug, Serialize)]
struct TxStreamView {
    id: String,
    origin: String,
    kind: &'static str,
    /// Credit amount in base units associated with this tx (0 for kinds without one).
    #[serde(with = "amount_str")]
    amount: u128,
}

fn tx_stream_view(tx: &Tx) -> TxStreamView {
    let (kind, amount) = match &tx.kind {
        TxKind::Transfer { amount, .. } => ("Transfer", *amount),
        TxKind::UptimeReward { amount, .. } => ("UptimeReward", *amount),
        TxKind::JobBid { bid, .. } => ("JobBid", *bid),
        TxKind::JobSettle { cost, .. } => ("JobSettle", *cost),
        TxKind::JobExpire { .. } => ("JobExpire", 0),
        TxKind::TrustGrant { .. } => ("TrustGrant", 0),
        TxKind::Heartbeat { amount, .. } => ("Heartbeat", *amount),
        TxKind::ChannelOpen { capacity, .. } => ("ChannelOpen", *capacity),
        TxKind::ChannelClose { cumulative, .. } => ("ChannelClose", *cumulative),
        TxKind::ChannelExpire { .. } => ("ChannelExpire", 0),
    };
    TxStreamView { id: hex::encode(tx.id()), origin: hex::encode(tx.origin), kind, amount }
}

/// Build a lazily-polled SSE stream from a broadcast receiver.
///
/// Each item produced by the receiver is converted to JSON via `view_fn` and
/// sent as an SSE data event. Lagged receivers (slow clients) log a warning and
/// skip the dropped messages rather than closing the connection.
///
/// `view_fn` is threaded through the `unfold` state so the borrow checker is
/// satisfied without unsafe code. Requires `F: Clone` which all fn-pointers and
/// simple closures automatically satisfy.
fn sse_broadcast<T, V, F>(
    rx: broadcast::Receiver<T>,
    view_fn: F,
) -> impl Stream<Item = Result<Event, Infallible>>
where
    T: Clone + Send + 'static,
    V: Serialize,
    F: Fn(&T) -> V + Clone + Send + 'static,
{
    // Package (rx, view_fn) as the unfold state so both are threaded through each call.
    stream::unfold((rx, view_fn), |(mut rx, view_fn)| async move {
        loop {
            match rx.recv().await {
                Ok(item) => {
                    let json = serde_json::to_string(&view_fn(&item)).unwrap_or_default();
                    return Some((Ok(Event::default().data(json)), (rx, view_fn)));
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("SSE stream lagged {n} messages — slow consumer");
                    // Loop again; don't close the connection.
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    })
}

async fn stream_signals(
    State(state): State<ApiState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.signal_tx.subscribe();
    Sse::new(sse_broadcast(rx, |sig: &CellSignal| signal_view(sig)))
        .keep_alive(KeepAlive::default())
}

async fn stream_blocks(
    State(state): State<ApiState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.block_tx.subscribe();
    Sse::new(sse_broadcast(rx, |b: &Block| block_view(b))).keep_alive(KeepAlive::default())
}

async fn stream_transactions(
    State(state): State<ApiState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.tx_tx.subscribe();
    Sse::new(sse_broadcast(rx, |tx: &Tx| tx_stream_view(tx))).keep_alive(KeepAlive::default())
}

// ----- GET /atlas -----

#[derive(Debug, Serialize)]
struct AtlasEntry {
    node_id: String,
    #[serde(flatten)]
    capacity: PeerCapacity,
}

async fn get_atlas(State(state): State<ApiState>) -> Response {
    let map = state.atlas.lock().await;
    let entries: Vec<AtlasEntry> = map
        .iter()
        .map(|(node_id, cap)| AtlasEntry { node_id: hex::encode(node_id), capacity: cap.clone() })
        .collect();
    (StatusCode::OK, Json(entries)).into_response()
}

// ----- GET /beacon -----
//
// Verifiable public randomness from the PoW chain: the tip block hash is unpredictable
// (it took work to find) and globally agreed. Schedulers can seed host selection from it so
// the choice is reproducible and auditable (nobody cherry-picked who ran the work). For
// high-stakes use, derive from a confirmed-depth block rather than the volatile tip.

async fn get_beacon(State(state): State<ApiState>) -> Response {
    let snap = state.chain.sync_snap().await;
    (
        StatusCode::OK,
        Json(serde_json::json!({ "height": snap.height, "hash": hex::encode(snap.tip_hash) })),
    )
        .into_response()
}

// ----- GET /history/:node_id -----
//
// Per-node interaction history (the reputation substrate). CE reports the immutable facts;
// apps derive their own per-relationship trust. Amounts are base-unit strings.

#[derive(Debug, Serialize)]
struct HistoryResponse {
    node_id: String,
    jobs_hosted: u64,
    jobs_paid: u64,
    heartbeats_hosted: u64,
    heartbeats_paid: u64,
    expiries: u64,
    #[serde(with = "amount_str")]
    earned: u128,
    #[serde(with = "amount_str")]
    spent: u128,
    first_height: u64,
    last_height: u64,
}

async fn get_history(State(state): State<ApiState>, Path(id): Path<String>) -> Response {
    let node_id: NodeId = match hex::decode(&id).ok().and_then(|b| b.try_into().ok()) {
        Some(arr) => arr,
        None => return err(StatusCode::BAD_REQUEST, "node_id must be 64 hex chars"),
    };
    let s = state.chain.node_history(node_id).await;
    let resp = HistoryResponse {
        node_id: id,
        jobs_hosted: s.jobs_hosted,
        jobs_paid: s.jobs_paid,
        heartbeats_hosted: s.heartbeats_hosted,
        heartbeats_paid: s.heartbeats_paid,
        expiries: s.expiries,
        earned: s.earned,
        spent: s.spent,
        first_height: s.first_height,
        last_height: s.last_height,
    };
    (StatusCode::OK, Json(resp)).into_response()
}

// ----- Payment channels -----
//
// Off-chain micropayment channels (docs/payment-channels.md). The payer opens a channel
// (locking capacity), streams signed receipts to the host off-chain, and the host redeems the
// highest receipt on-chain to settle. Only open/close touch the chain. Amounts are base-unit strings.

/// Default channel lifetime if the caller doesn't set one: ~24h at 10s/block.
const DEFAULT_CHANNEL_BLOCKS: u64 = 8_640;

#[derive(Debug, Deserialize)]
struct ChannelOpenRequest {
    /// Host NodeId (64 hex) this channel pays.
    host: String,
    #[serde(with = "amount_str")]
    capacity: u128,
    /// Block height after which the payer may reclaim via expire. 0 = default lifetime.
    #[serde(default)]
    expiry_height: u64,
}

async fn channel_open(State(state): State<ApiState>, Json(req): Json<ChannelOpenRequest>) -> Response {
    let host: NodeId = match hex::decode(&req.host).ok().and_then(|b| b.try_into().ok()) {
        Some(arr) => arr,
        None => return err(StatusCode::BAD_REQUEST, "`host` must be 64 hex chars"),
    };
    let payer = state.identity.node_id();
    if host == payer {
        return err(StatusCode::BAD_REQUEST, "cannot open a channel to self");
    }
    if req.capacity == 0 {
        return err(StatusCode::BAD_REQUEST, "capacity must be > 0");
    }
    // Free balance must cover the capacity (it will be locked).
    let free = state.chain.balance(payer).await - state.chain.locked_balance(payer).await as i128;
    if free < req.capacity as i128 {
        return err(StatusCode::PAYMENT_REQUIRED, format!("free balance {free} insufficient for capacity {}", req.capacity));
    }
    let snap = state.chain.sync_snap().await;
    let expiry_height = if req.expiry_height == 0 { snap.height + DEFAULT_CHANNEL_BLOCKS } else { req.expiry_height };

    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;
    let channel_id: [u8; 32] =
        Sha256::digest(bincode::serialize(&(ts, payer, host)).unwrap_or_default()).into();

    let kind = TxKind::ChannelOpen { channel_id, payer, host, capacity: req.capacity, expiry_height };
    submit_tx(&state, kind, payer).await;
    (StatusCode::CREATED, Json(serde_json::json!({ "channel_id": hex::encode(channel_id) }))).into_response()
}

#[derive(Debug, Deserialize)]
struct ReceiptRequest {
    channel_id: String,
    host: String,
    #[serde(with = "amount_str")]
    cumulative: u128,
}

/// Sign an off-chain receipt as the payer (this node). The caller hands the receipt to the host,
/// who later redeems the highest one via close. No tx — purely a signature.
async fn channel_receipt(State(state): State<ApiState>, Json(req): Json<ReceiptRequest>) -> Response {
    let channel_id: [u8; 32] = match hex::decode(&req.channel_id).ok().and_then(|b| b.try_into().ok()) {
        Some(a) => a,
        None => return err(StatusCode::BAD_REQUEST, "channel_id must be 64 hex chars"),
    };
    let host: NodeId = match hex::decode(&req.host).ok().and_then(|b| b.try_into().ok()) {
        Some(a) => a,
        None => return err(StatusCode::BAD_REQUEST, "host must be 64 hex chars"),
    };
    let sig = state.identity.sign(&channel_receipt_bytes(&channel_id, &host, req.cumulative));
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "channel_id": req.channel_id,
            "cumulative": req.cumulative.to_string(),
            "payer_sig": hex::encode(sig),
        })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct ChannelCloseRequest {
    #[serde(with = "amount_str")]
    cumulative: u128,
    /// Payer's receipt signature (128 hex) over channel_receipt_bytes(channel_id, host, cumulative).
    payer_sig: String,
}

/// Close a channel by redeeming the payer's highest receipt. Called on the HOST node.
async fn channel_close(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(req): Json<ChannelCloseRequest>,
) -> Response {
    let channel_id: [u8; 32] = match hex::decode(&id).ok().and_then(|b| b.try_into().ok()) {
        Some(a) => a,
        None => return err(StatusCode::BAD_REQUEST, "channel id must be 64 hex chars"),
    };
    let payer_sig: [u8; 64] = match hex::decode(&req.payer_sig).ok().and_then(|b| b.try_into().ok()) {
        Some(a) => a,
        None => return err(StatusCode::BAD_REQUEST, "payer_sig must be 128 hex chars"),
    };
    let host = state.identity.node_id();
    let kind = TxKind::ChannelClose { channel_id, cumulative: req.cumulative, payer_sig };
    submit_tx(&state, kind, host).await;
    (StatusCode::ACCEPTED, Json(serde_json::json!({ "status": "submitted" }))).into_response()
}

/// Reclaim a channel after its expiry. Called on the PAYER node.
async fn channel_expire(State(state): State<ApiState>, Path(id): Path<String>) -> Response {
    let channel_id: [u8; 32] = match hex::decode(&id).ok().and_then(|b| b.try_into().ok()) {
        Some(a) => a,
        None => return err(StatusCode::BAD_REQUEST, "channel id must be 64 hex chars"),
    };
    let payer = state.identity.node_id();
    let kind = TxKind::ChannelExpire { channel_id, payer };
    submit_tx(&state, kind, payer).await;
    (StatusCode::ACCEPTED, Json(serde_json::json!({ "status": "submitted" }))).into_response()
}

#[derive(Debug, Serialize)]
struct ChannelView {
    channel_id: String,
    payer: String,
    host: String,
    #[serde(with = "amount_str")]
    capacity: u128,
    expiry_height: u64,
}

async fn list_channels(State(state): State<ApiState>) -> Response {
    let chans: Vec<ChannelView> = state
        .chain
        .list_channels()
        .await
        .into_iter()
        .map(|(id, payer, host, capacity, expiry_height)| ChannelView {
            channel_id: hex::encode(id),
            payer: hex::encode(payer),
            host: hex::encode(host),
            capacity,
            expiry_height,
        })
        .collect();
    (StatusCode::OK, Json(chans)).into_response()
}

/// Sign `kind` with the node identity, add to the pool, and broadcast.
async fn submit_tx(state: &ApiState, kind: TxKind, origin: NodeId) {
    let data = bincode::serialize(&kind).expect("serialize tx");
    let sig = state.identity.sign(&data);
    let tx = Tx::new(kind, origin, sig);
    state.pool.add(tx.clone()).await;
    let _ = state.mesh_handle.broadcast_tx(&tx).await;
}

// ----- Router -----

#[allow(clippy::too_many_arguments)]
pub async fn start(
    chain: ChainHandle,
    identity: Arc<Identity>,
    mesh_handle: MeshHandle,
    signals: SignalRing,
    signal_tx: broadcast::Sender<CellSignal>,
    block_tx: broadcast::Sender<Block>,
    tx_tx: broadcast::Sender<Tx>,
    send_nonce: Arc<AtomicU64>,
    port: u16,
    listen_port: u16,
    job_store: JobStore,
    pool: TxPool,
    settle_notify_tx: mpsc::Sender<()>,
    data_dir: PathBuf,
    atlas: Atlas,
    docker: Option<Docker>,
    self_tags: Vec<String>,
) -> Result<()> {
    if docker.is_none() {
        tracing::warn!("Docker unavailable — job routes and exec will return 503");
    }
    let host_node_id = identity.node_id();
    let nonce_cache: NonceCache = Arc::new(StdMutex::new(HashMap::new()));
    let state = ApiState {
        docker,
        chain,
        host_node_id,
        identity,
        mesh_handle,
        signals,
        signal_tx,
        block_tx,
        tx_tx,
        send_nonce,
        job_store,
        pool,
        settle_notify_tx,
        data_dir,
        nonce_cache,
        atlas,
        listen_port,
        self_tags: Arc::new(self_tags),
    };

    let app = Router::new()
        .route("/jobs/bid", post(bid_job))
        .route("/jobs", get(list_jobs))
        .route("/jobs/:id", get(job_status))
        .route("/jobs/:id/settle", post(settle_job))
        .route("/jobs/:id", delete(stop_job))
        .route("/transfer", post(transfer))
        .route("/status", get(node_status))
        .route("/signals", get(list_signals))
        .route("/signals/send", post(send_signal))
        // SSE push streams — no polling required.
        .route("/signals/stream", get(stream_signals))
        .route("/blocks/stream", get(stream_blocks))
        .route("/transactions/stream", get(stream_transactions))
        .route("/health", get(|| async { "ok" }))
        .route("/bootstrap", get(get_bootstrap))
        .route("/atlas", get(get_atlas))
        .route("/beacon", get(get_beacon))
        .route("/history/:node_id", get(get_history))
        .route("/channels", get(list_channels))
        .route("/channels/open", post(channel_open))
        .route("/channels/receipt", post(channel_receipt))
        .route("/channels/:id/close", post(channel_close))
        .route("/channels/:id/expire", post(channel_expire))
        // Personal mesh OS: direct HTTP auth for LAN use (legacy, kept for compatibility).
        .route("/sync/*path", put(sync_put).get(sync_get))
        .route("/exec", post(exec_command))
        // Personal mesh OS: relay-routed mesh RPCs (correct path for NAT traversal).
        .route("/mesh-exec", post(mesh_exec))
        .route("/mesh-deploy", post(mesh_deploy))
        .route("/mesh-kill", post(mesh_kill))
        .route("/mesh-sync/:node_id/*path", put(mesh_sync_put))
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("API listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
