use anyhow::Result;
use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use bollard::{container::RemoveContainerOptions, Docker};
use ce_chain::{payer_settle_bytes, Chain};
use ce_container::{exec_in_container, ExecSpec};
use ce_identity::{verify, Identity, NodeId};
use ce_mesh::MeshHandle;
use ce_protocol::{BurnProof, Capability, CellAddress, CellSignal};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex as StdMutex},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, Mutex};

use crate::{Atlas, CeJobStatus, JobRecord, JobStore, PeerCapacity, SignalRing, TxPool};

/// Per-sender last-accepted timestamp (ms). Used to enforce strictly increasing
/// nonces and close replay attacks within the 5-minute freshness window.
type NonceCache = Arc<StdMutex<HashMap<NodeId, u64>>>;

#[derive(Clone)]
struct ApiState {
    docker: Option<Docker>,
    chain: Arc<Mutex<Chain>>,
    host_node_id: NodeId,
    identity: Arc<Identity>,
    mesh_handle: MeshHandle,
    signals: SignalRing,
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
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(ErrorBody { error: msg.into() })).into_response()
}

/// Snapshot returned by GET /status.
#[derive(Debug, Serialize)]
pub struct NodeStatusResponse {
    pub node_id: String,
    pub height: u64,
    pub difficulty: u8,
    pub balance: i64,
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
    pub bid: u64,
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
    let balance = state.chain.lock().await.balance(&payer);
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
    pub cost: Option<u64>,
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
    /// Agreed settlement amount in credits.
    pub cost: u64,
    /// Payer's Ed25519 signature over payer_settle_bytes(job_id, cost), 128 hex chars.
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

    // Verify the payer co-signature before storing.
    let bytes = payer_settle_bytes(&job_id, req.cost);
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
    let chain = state.chain.lock().await;
    let node_id = hex::encode(state.host_node_id);
    let balance = chain.balance(&state.host_node_id);
    (
        StatusCode::OK,
        Json(NodeStatusResponse {
            node_id,
            height: chain.height(),
            difficulty: chain.difficulty,
            balance,
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
    amount: u64,
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
        let chain = state.chain.lock().await;
        let Some((tx, height, hash)) = chain.tx_by_id(&tx_id) else {
            return err(
                StatusCode::BAD_REQUEST,
                "burn_tx_id_hex does not match any tx in the local chain",
            );
        };
        let Some(amount) = tx_value(&tx) else {
            return err(StatusCode::BAD_REQUEST, "referenced tx has no burnable amount");
        };
        Some(BurnProof { tx_id, amount, block_height: height, block_hash: hash })
    } else if !payload.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "burn_tx_id_hex is required when payload_hex is non-empty",
        );
    } else {
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

fn tx_value(tx: &ce_chain::Tx) -> Option<u64> {
    use ce_chain::TxKind;
    match &tx.kind {
        TxKind::Transfer { amount, .. } => Some(*amount),
        TxKind::UptimeReward { amount, .. } => Some(*amount),
        TxKind::JobBid { bid, .. } => Some(*bid),
        TxKind::JobSettle { cost, .. } => Some(*cost),
        TxKind::Heartbeat { amount, .. } => Some(*amount),
        TxKind::JobExpire { .. } | TxKind::TrustGrant { .. } => None,
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

    // Trust check: sender must be in the local device registry.
    let devices = crate::devices::Devices::load_or_empty(&data_dir.join("machines.toml"));
    if !devices.is_trusted(&from) {
        return Err(err(StatusCode::FORBIDDEN, "sender is not a trusted device"));
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
        verify_device_auth(&headers, "PUT", &path, &state.data_dir, &body_bytes, &state.nonce_cache)
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
        verify_device_auth(&headers, "GET", &path, &state.data_dir, b"", &state.nonce_cache)
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
        verify_device_auth(&headers, "POST", "/exec", &state.data_dir, &body_bytes, &state.nonce_cache)
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
    cost: Option<u64>,
    bid: u64,
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
    pub amount: u64,
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
    let balance = state.chain.lock().await.balance(&from);
    if balance < req.amount as i64 {
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

// ----- Router -----

#[allow(clippy::too_many_arguments)]
pub async fn start(
    chain: Arc<Mutex<Chain>>,
    identity: Arc<Identity>,
    mesh_handle: MeshHandle,
    signals: SignalRing,
    send_nonce: Arc<AtomicU64>,
    port: u16,
    job_store: JobStore,
    pool: TxPool,
    settle_notify_tx: mpsc::Sender<()>,
    data_dir: PathBuf,
    atlas: Atlas,
) -> Result<()> {
    let docker = Docker::connect_with_socket_defaults().ok();
    if docker.is_none() {
        tracing::warn!("Docker unavailable — job routes will return 503");
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
        send_nonce,
        job_store,
        pool,
        settle_notify_tx,
        data_dir,
        nonce_cache,
        atlas,
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
        .route("/health", get(|| async { "ok" }))
        .route("/atlas", get(get_atlas))
        // Personal mesh OS: authenticated file sync and remote exec.
        .route("/sync/*path", put(sync_put).get(sync_get))
        .route("/exec", post(exec_command))
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("API listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
