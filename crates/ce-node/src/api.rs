use anyhow::Result;
use axum::{
    extract::{Path, Query, Request, State},
    http::{header::AUTHORIZATION, Method, StatusCode},
    middleware::{self, Next},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{delete, get, post},
    Json, Router,
};
use bollard::{container::RemoveContainerOptions, Docker};
use ce_chain::{channel_receipt_bytes, payer_settle_bytes, Block, ChunkReceipt, Tx, TxKind};
use ce_identity::{verify, Identity, NodeId};
use ce_mesh::{AppPubSubMsg, MeshHandle, RpcRequest, RpcResponse, app_pubsub_bytes, peer_id_from_node_id};
use ce_protocol::{BurnProof, Capability, CellAddress, CellSignal};
use futures::stream::{self, Stream};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    convert::Infallible,
    path::PathBuf,
    sync::Arc,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{broadcast, mpsc};

use crate::{
    AppInbox, AppMessage, Atlas, CeJobStatus, ChainHandle, JobRecord, JobStore, NetGraph,
    PeerCapacity, RttStat, SignalRing, TxPool,
};

/// Per-sender last-accepted timestamp (ms). Used to enforce strictly increasing
/// nonces and close replay attacks within the 5-minute freshness window.

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
    /// Recent inbound app-message ring (snapshot for `GET /mesh/messages`).
    app_inbox: AppInbox,
    /// Push channel — subscribers receive every inbound app message instantly.
    app_msg_tx: broadcast::Sender<AppMessage>,
    send_nonce: Arc<AtomicU64>,
    job_store: JobStore,
    pool: TxPool,
    /// Poke the job manager to check for newly-signed settlements immediately.
    settle_notify_tx: mpsc::Sender<()>,
    /// CE data directory; used for the local blob store.
    data_dir: PathBuf,
    /// Peer capacity atlas updated by incoming capacity signals.
    atlas: Atlas,
    /// Per-peer round-trip latency, the ground-truth edges of the network graph.
    netgraph: NetGraph,
    /// libp2p listen port — used by GET /bootstrap to build multiaddrs.
    listen_port: u16,
    /// Stream control for opening outbound TCP tunnels over the mesh.
    tunnel_control: ce_mesh::StreamControl,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(ErrorBody { error: msg.into() })).into_response()
}

/// Is this `Origin` header a loopback origin? Accepts `http`/`https` schemes with host
/// `localhost`, `127.0.0.1`, or `[::1]`, with an optional `:port`. Used to scope read-only CORS to
/// the same machine so a hostile public page cannot read this node's API from a victim's browser.
fn is_localhost_origin(origin: &str) -> bool {
    let rest = match origin.strip_prefix("http://").or_else(|| origin.strip_prefix("https://")) {
        Some(r) => r,
        None => return false,
    };
    // Drop an optional :port (but keep IPv6 brackets intact: "[::1]:8080" -> host "[::1]").
    let host = if let Some(stripped) = rest.strip_prefix("[::1]") {
        return stripped.is_empty() || stripped.starts_with(':');
    } else {
        rest.split(':').next().unwrap_or("")
    };
    host == "localhost" || host == "127.0.0.1"
}

/// Constant-time byte comparison (avoids timing oracles on the token check).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Derive the API bearer token from the node identity and persist it to `<data_dir>/api.token`
/// (chmod 600) so same-host clients can read it. Deterministic in the identity secret — no RNG
/// and no rotation-vs-storage problem; rotating it means rotating the node key. If the file
/// already holds a non-empty token we keep it (lets an operator override with a custom secret).
fn load_or_create_api_token(data_dir: &std::path::Path, identity_seed: &[u8; 32]) -> String {
    // Operator/CI override: a fixed token via the environment takes precedence over the file.
    if let Ok(env_tok) = std::env::var("CE_API_TOKEN") {
        let t = env_tok.trim().to_string();
        if !t.is_empty() {
            return t;
        }
    }
    let path = data_dir.join("api.token");
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let t = existing.trim().to_string();
        if !t.is_empty() {
            return t;
        }
    }
    let mut h = Sha256::new();
    h.update(b"ce-api-token-v1");
    h.update(identity_seed);
    let token = hex::encode(h.finalize());
    let _ = std::fs::create_dir_all(data_dir);
    if std::fs::write(&path, &token).is_ok() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
    }
    token
}

/// Axum middleware: require `Authorization: Bearer <api.token>` on every mutating (non-GET/HEAD)
/// request. Read-only requests pass through untouched.
async fn require_api_token(
    State(token): State<Arc<String>>,
    req: Request,
    next: Next,
) -> Response {
    let read_only = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if !read_only {
        let presented = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));
        let ok = presented
            .map(|t| ct_eq(t.trim().as_bytes(), token.as_bytes()))
            .unwrap_or(false);
        if !ok {
            return err(
                StatusCode::UNAUTHORIZED,
                "missing or invalid API token (send Authorization: Bearer <data_dir>/api.token)",
            );
        }
    }
    next.run(req).await
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
    /// Credits in circulation (emitted minus burned), base units as a decimal string.
    #[serde(with = "amount_str")]
    pub circulating_supply: u128,
    /// Credits destroyed by the settlement burn so far, base units as a decimal string.
    #[serde(with = "amount_str")]
    pub burned_total: u128,
    /// This node's active host bond, base units as a decimal string.
    #[serde(with = "amount_str")]
    pub bond: u128,
    /// This node's consensus weight = min(bond, earned-work-score), base units as a decimal string.
    #[serde(with = "amount_str")]
    pub weight: u128,
    /// Spendable balance (balance minus all locks, clamped at 0), base units as a decimal string.
    #[serde(with = "amount_str")]
    pub free: u128,
    /// Credits locked in this node's open payment channels, base units as a decimal string.
    #[serde(with = "amount_str")]
    pub locked_channels: u128,
    /// Credits locked in this node's active bond (== `bond`), base units as a decimal string.
    #[serde(with = "amount_str")]
    pub locked_bond: u128,
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
            circulating_supply: snap.circulating_supply,
            burned_total: snap.burned_total,
            bond: snap.bond,
            weight: snap.weight,
            free: snap.free,
            locked_channels: snap.locked_channels,
            locked_bond: snap.locked_bond,
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
        TxKind::HostBond { amount, .. } => Some(*amount),
        TxKind::JobExpire { .. }
        | TxKind::ChannelOpen { .. }
        | TxKind::ChannelClose { .. }
        | TxKind::ChannelExpire { .. }
        | TxKind::NameClaim { .. }
        | TxKind::RevokeCapability { .. }
        | TxKind::HostUnbond { .. }
        | TxKind::SlashEquivocation { .. } => None,
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
    // Pre-screen on FREE balance (total minus funds locked by open bids/channels/bond) — the same
    // quantity validators require when they append the Transfer (mirrors `channel_open`). Screening
    // on total balance would 201-accept a transfer of locked funds that then never mines.
    let free = state.chain.balance(from).await - state.chain.locked_balance(from).await as i128;
    if free < req.amount as i128 {
        return err(
            StatusCode::PAYMENT_REQUIRED,
            format!("free balance {free} insufficient for transfer {}", req.amount),
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

// ----- POST /capabilities/revoke -----

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    /// The nonce of a capability this node issued (issuer == this node).
    pub nonce: u64,
}

/// Revoke a capability this node issued by submitting an on-chain `RevokeCapability { issuer, nonce }`
/// signed by this node. Revoking any link invalidates that link and its whole subtree once the tx
/// is mined. See docs/capabilities.md.
/// Snapshot the in-memory chain to disk on demand (the "dump" for ephemeral/in-memory nodes).
/// Token-gated. Persisting nodes also expose it so an operator can force a flush.
async fn chain_save(State(state): State<ApiState>) -> Response {
    let path = state.data_dir.join("chain").join("chain.json");
    match state.chain.save(path.clone()).await {
        Ok(()) => Json(serde_json::json!({ "saved": path.display().to_string() })).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, format!("save failed: {e}")),
    }
}

/// Read-only: the on-chain revoked `(issuer, nonce)` set, so apps (e.g. rdev) can deny revoked
/// capability chains. Issuer is hex-encoded.
async fn get_revoked(State(state): State<ApiState>) -> Response {
    let pairs = state.chain.revoked_pairs().await;
    let out: Vec<serde_json::Value> = pairs
        .iter()
        .map(|(issuer, nonce)| serde_json::json!({ "issuer": hex::encode(issuer), "nonce": nonce }))
        .collect();
    Json(out).into_response()
}

async fn revoke_capability(State(state): State<ApiState>, Json(req): Json<RevokeRequest>) -> Response {
    let issuer = state.identity.node_id();
    let kind = ce_chain::TxKind::RevokeCapability { issuer, nonce: req.nonce };
    let data = bincode::serialize(&kind).expect("serialize RevokeCapability");
    let sig = state.identity.sign(&data);
    let tx = ce_chain::Tx::new(kind, issuer, sig);
    let tx_id = hex::encode(tx.id());
    state.pool.add(tx.clone()).await;
    let _ = state.mesh_handle.broadcast_tx(&tx).await;
    (StatusCode::CREATED, Json(serde_json::json!({ "tx_id": tx_id }))).into_response()
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
    /// Docker image (Docker workload). Mutually exclusive with `wasm_module`.
    #[serde(default)]
    image: Option<String>,
    #[serde(default)]
    cmd: Vec<String>,
    /// WASM module content hash, 64 hex (Wasm workload). Mutually exclusive with `image`.
    #[serde(default)]
    wasm_module: Option<String>,
    /// Exported entry function for a Wasm workload (default "entry").
    #[serde(default)]
    wasm_entry: Option<String>,
    cpu_cores: u32,
    mem_mb: u64,
    duration_secs: u64,
    /// Funding committed for the cell, in base units (string).
    #[serde(with = "amount_str")]
    bid: u128,
    /// Optional scoped grant token (from `ce grant`), forwarded to the host.
    #[serde(default)]
    grant: Option<String>,
    /// Content-addressed input CIDs (64 hex each) the cell needs. The host stages each from the
    /// data layer before launch (Stage 4).
    #[serde(default)]
    inputs: Vec<String>,
}

/// Build the polymorphic `Workload` from a deploy request (Docker via `image`, or Wasm via
/// `wasm_module`), returning its bincode bytes for the RPC.
fn workload_bytes(req: &MeshDeployRequest) -> Result<Vec<u8>, Response> {
    let inputs = parse_cids(&req.inputs)?;
    let workload = if let Some(image) = &req.image {
        ce_runtime::Workload::Docker { image: image.clone(), cmd: req.cmd.clone(), env: vec![], inputs }
    } else if let Some(hash_hex) = &req.wasm_module {
        let module_hash: [u8; 32] = hex::decode(hash_hex)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, "wasm_module must be 64 hex chars"))?;
        ce_runtime::Workload::Wasm {
            module_hash,
            entry: req.wasm_entry.clone().unwrap_or_else(|| "entry".to_string()),
            args: vec![],
            inputs,
        }
    } else {
        return Err(err(StatusCode::BAD_REQUEST, "provide either `image` or `wasm_module`"));
    };
    Ok(bincode::serialize(&workload).unwrap_or_default())
}

/// Parse a list of 64-hex CIDs into 32-byte arrays.
fn parse_cids(hexes: &[String]) -> Result<Vec<[u8; 32]>, Response> {
    hexes
        .iter()
        .map(|h| {
            hex::decode(h)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, "each input must be 64 hex chars"))
        })
        .collect()
}

/// Decode an optional capability-chain token (hex) to RPC-ready bincode bytes; validates the token.
fn caps_to_bytes(token: &Option<String>) -> Result<Option<Vec<u8>>, Response> {
    match token {
        Some(t) => match ce_cap::decode_chain(t) {
            Ok(chain) => Ok(Some(ce_cap::encode_chain_bytes(&chain))),
            Err(_) => Err(err(StatusCode::BAD_REQUEST, "malformed capability token")),
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
    let workload = match workload_bytes(&req) {
        Ok(w) => w,
        Err(resp) => return resp,
    };
    let grant = match caps_to_bytes(&req.grant) {
        Ok(g) => g,
        Err(resp) => return resp,
    };
    if !req.hint_multiaddr.is_empty() {
        let _ = state.mesh_handle.dial(req.hint_multiaddr).await;
    }

    let rpc_req = RpcRequest::Deploy {
        from_node: state.host_node_id,
        workload,
        cpu_cores: req.cpu_cores,
        mem_mb: req.mem_mb,
        duration_secs: req.duration_secs,
        bid: req.bid,
        grant,
    };

    match state.mesh_handle.send_rpc(peer_id, rpc_req).await {
        Ok(RpcResponse::Deployed { job_id, output }) => {
            (StatusCode::OK, Json(serde_json::json!({ "job_id": job_id, "output": output }))).into_response()
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
    let grant = match caps_to_bytes(&req.grant) {
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

// ----- POST /tunnel -----
//
// Forward a local TCP port to a remote port on a target node over the mesh (TCP-over-libp2p).
// Binds 127.0.0.1:local_port; each accepted connection opens a `/ce/tunnel/1` stream to the target,
// writes a header (remote_port + capability chain), and splices bytes both ways. Returns once the
// listener is bound; the forwarding runs in the background until the node stops.

#[derive(Debug, Deserialize)]
pub struct TunnelRequest {
    /// Target node id (64 hex chars).
    pub node_id: String,
    /// Local TCP port to bind on 127.0.0.1.
    pub local_port: u16,
    /// Remote TCP port on the target to forward to.
    pub remote_port: u16,
    /// Capability chain token (hex) authorizing the tunnel (needs the `tunnel` ability).
    #[serde(default)]
    pub caps: Option<String>,
    /// Optional relay circuit multiaddr dial hint.
    #[serde(default)]
    pub hint: Option<String>,
}

async fn open_tunnel(State(state): State<ApiState>, Json(req): Json<TunnelRequest>) -> Response {
    let node_id: NodeId = match hex::decode(&req.node_id).ok().and_then(|b| b.try_into().ok()) {
        Some(arr) => arr,
        None => return err(StatusCode::BAD_REQUEST, "node_id must be 64 hex chars"),
    };
    let peer_id = match peer_id_from_node_id(&node_id) {
        Ok(p) => p,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("invalid node_id: {e}")),
    };
    if let Some(h) = &req.hint {
        if !h.is_empty() {
            let _ = state.mesh_handle.dial(h.clone()).await;
        }
    }
    // Validate the capability token now and carry its canonical bytes in each stream header.
    let caps_bytes = match &req.caps {
        Some(t) => match ce_cap::decode_chain(t) {
            Ok(c) => ce_cap::encode_chain_bytes(&c),
            Err(_) => return err(StatusCode::BAD_REQUEST, "malformed capability token"),
        },
        None => Vec::new(),
    };

    let listener = match tokio::net::TcpListener::bind(("127.0.0.1", req.local_port)).await {
        Ok(l) => l,
        Err(e) => {
            return err(StatusCode::INTERNAL_SERVER_ERROR, format!("bind 127.0.0.1:{}: {e}", req.local_port));
        }
    };

    let remote_port = req.remote_port;
    let control = state.tunnel_control.clone();
    tokio::spawn(async move {
        loop {
            let conn = match listener.accept().await {
                Ok((c, _)) => c,
                Err(e) => {
                    tracing::warn!("tunnel listener: {e}");
                    break;
                }
            };
            let mut control = control.clone();
            let caps_bytes = caps_bytes.clone();
            tokio::spawn(async move {
                if let Err(e) = drive_tunnel_conn(&mut control, peer_id, conn, remote_port, &caps_bytes).await {
                    tracing::debug!("tunnel conn closed: {e}");
                }
            });
        }
    });

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "local_port": req.local_port,
            "remote_port": remote_port,
            "node_id": req.node_id,
        })),
    )
        .into_response()
}

/// Open a tunnel stream to `peer`, send the header, and splice `conn` to it both ways.
async fn drive_tunnel_conn(
    control: &mut ce_mesh::StreamControl,
    peer: ce_mesh::CePeerId,
    mut conn: tokio::net::TcpStream,
    remote_port: u16,
    caps_bytes: &[u8],
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    use tokio_util::compat::FuturesAsyncReadCompatExt;

    let stream = control
        .open_stream(peer, ce_mesh::TUNNEL_PROTOCOL)
        .await
        .map_err(|e| anyhow::anyhow!("open tunnel stream: {e}"))?;
    let mut s = stream.compat();
    s.write_all(&remote_port.to_be_bytes()).await?;
    s.write_all(&(caps_bytes.len() as u32).to_be_bytes()).await?;
    s.write_all(caps_bytes).await?;
    tokio::io::copy_bidirectional(&mut conn, &mut s).await?;
    Ok(())
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
        TxKind::Heartbeat { amount, .. } => ("Heartbeat", *amount),
        TxKind::ChannelOpen { capacity, .. } => ("ChannelOpen", *capacity),
        TxKind::ChannelClose { cumulative, .. } => ("ChannelClose", *cumulative),
        TxKind::ChannelExpire { .. } => ("ChannelExpire", 0),
        TxKind::NameClaim { .. } => ("NameClaim", 0),
        TxKind::RevokeCapability { .. } => ("RevokeCapability", 0),
        TxKind::HostBond { amount, .. } => ("HostBond", *amount),
        TxKind::HostUnbond { .. } => ("HostUnbond", 0),
        TxKind::SlashEquivocation { .. } => ("SlashEquivocation", 0),
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

// ----- GET /netgraph -----
//
// Raw latency edges measured from this node to its connected peers (libp2p ping RTT, smoothed).
// The foundational network-graph primitive (see `docs/compute-fabric.md`); the `ce-graph` SDK
// assembles Vivaldi coordinates and global topology on top of these per-node snapshots.

#[derive(Debug, Serialize)]
struct NetGraphEntry {
    peer: String,
    #[serde(flatten)]
    rtt: RttStat,
}

async fn get_netgraph(State(state): State<ApiState>) -> Response {
    let map = state.netgraph.lock().await;
    let edges: Vec<NetGraphEntry> = map
        .iter()
        .map(|(peer, rtt)| NetGraphEntry { peer: peer.clone(), rtt: rtt.clone() })
        .collect();
    (StatusCode::OK, Json(edges)).into_response()
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
    // --- Windowed slice (share-ratio recency input) ---
    // These are the recent-window facts a torrent-style share ratio needs so it computes a REAL
    // ratio over recent volume, not a recency proxy off `last_height`. `recent_earned` is
    // hosting income (post-burn) and `recent_spent` is consumption (gross) over the last
    // `window_blocks` blocks. Observational read-model walked from blocks (like burned_total),
    // never consensus. `window_partial` is true on a pruned/short chain that does not cover the
    // whole window — query an archive node for the full slice.
    window_blocks: u64,
    #[serde(with = "amount_str")]
    recent_earned: u128,
    #[serde(with = "amount_str")]
    recent_spent: u128,
    window_partial: bool,
}

async fn get_history(State(state): State<ApiState>, Path(id): Path<String>) -> Response {
    let node_id: NodeId = match hex::decode(&id).ok().and_then(|b| b.try_into().ok()) {
        Some(arr) => arr,
        None => return err(StatusCode::BAD_REQUEST, "node_id must be 64 hex chars"),
    };
    let s = state.chain.node_history(node_id).await;
    let w = state.chain.node_history_windowed(node_id, ce_chain::RATIO_WINDOW_BLOCKS).await;
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
        window_blocks: w.window_blocks,
        recent_earned: w.recent_earned,
        recent_spent: w.recent_spent,
        window_partial: w.partial,
    };
    (StatusCode::OK, Json(resp)).into_response()
}

// ----- GET /transactions/:node_id -----
//
// Itemized, paginated read of a node's confirmed transactions from the chain. This complements the
// aggregate `GET /history/:node_id` (NodeStats) with the per-tx list a wallet/history view needs.
//
// PRIVACY: this returns only PUBLIC, on-chain facts. Every settlement and transfer leg is already
// world-readable to anyone holding the chain; this endpoint exposes nothing the ledger does not, for
// any node, not just self. It is not a private statement. On a pruned light node only
// post-checkpoint transactions are visible (archive nodes hold full history).

/// Default and maximum page size for `GET /transactions/:node_id`.
const TX_PAGE_DEFAULT: usize = 100;
const TX_PAGE_MAX: usize = 500;

#[derive(Debug, Deserialize)]
struct TxQuery {
    /// Max items to return (default 100, capped at 500).
    limit: Option<usize>,
    /// Exclude transactions at block height `>= before` — the cursor for the next (older) page.
    before: Option<u64>,
}

#[derive(Debug, Serialize)]
struct TxRecord {
    /// Content-addressed transaction id (64 hex).
    tx_id: String,
    /// Block height the tx was confirmed at.
    height: u64,
    /// Tx kind, e.g. Transfer | JobSettle | Heartbeat | ChannelClose | UptimeReward | ...
    kind: String,
    /// Amount moved relative to this tx, base units as a decimal string ("0" for amount-less kinds).
    #[serde(with = "amount_str")]
    amount: u128,
    /// The other party in this tx relative to the queried node (64 hex), when there is one.
    counterparty: Option<String>,
    /// Value direction relative to the queried node: "in", "out", or "self".
    direction: String,
}

/// Classify a tx relative to `node`: (kind label, amount, counterparty, direction).
fn classify_tx(kind: &TxKind, node: &NodeId) -> (&'static str, u128, Option<NodeId>, &'static str) {
    match kind {
        TxKind::Transfer { from, to, amount } => {
            let dir = if to == node && from == node {
                "self"
            } else if to == node {
                "in"
            } else {
                "out"
            };
            let cp = if from == node { Some(*to) } else { Some(*from) };
            ("Transfer", *amount, cp, dir)
        }
        TxKind::UptimeReward { amount, .. } => ("UptimeReward", *amount, None, "in"),
        TxKind::JobBid { payer, bid, .. } => {
            let dir = if payer == node { "out" } else { "self" };
            ("JobBid", *bid, None, dir)
        }
        TxKind::JobSettle { host, payer, cost, .. } => {
            let (dir, cp) = if host == node {
                ("in", Some(*payer))
            } else {
                ("out", Some(*host))
            };
            ("JobSettle", *cost, cp, dir)
        }
        TxKind::JobExpire { .. } => ("JobExpire", 0, None, "self"),
        TxKind::Heartbeat { cell, host, amount, .. } => {
            let (dir, cp) = if host == node {
                ("in", Some(*cell))
            } else {
                ("out", Some(*host))
            };
            ("Heartbeat", *amount, cp, dir)
        }
        TxKind::ChannelOpen { payer, host, capacity, .. } => {
            let (dir, cp) = if payer == node {
                ("out", Some(*host))
            } else {
                ("in", Some(*payer))
            };
            ("ChannelOpen", *capacity, cp, dir)
        }
        // payer/host are not in the ChannelClose tx; origin is the host (v0 close rule), so a match
        // here means this node closed (received) the channel.
        TxKind::ChannelClose { cumulative, .. } => ("ChannelClose", *cumulative, None, "in"),
        TxKind::ChannelExpire { .. } => ("ChannelExpire", 0, None, "self"),
        TxKind::NameClaim { .. } => ("NameClaim", 0, None, "self"),
        TxKind::RevokeCapability { .. } => ("RevokeCapability", 0, None, "self"),
        TxKind::HostBond { amount, .. } => ("HostBond", *amount, None, "self"),
        TxKind::HostUnbond { .. } => ("HostUnbond", 0, None, "self"),
        TxKind::SlashEquivocation { offender, reporter, .. } => {
            let (dir, cp) = if reporter == node {
                ("in", Some(*offender))
            } else {
                ("out", Some(*reporter))
            };
            ("SlashEquivocation", 0, cp, dir)
        }
    }
}

async fn get_transactions(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Query(q): Query<TxQuery>,
) -> Response {
    let node_id: NodeId = match hex::decode(&id).ok().and_then(|b| b.try_into().ok()) {
        Some(arr) => arr,
        None => return err(StatusCode::BAD_REQUEST, "node_id must be 64 hex chars"),
    };
    let limit = q.limit.unwrap_or(TX_PAGE_DEFAULT).clamp(1, TX_PAGE_MAX);
    let rows = state.chain.transactions_for(node_id, q.before, limit).await;
    let records: Vec<TxRecord> = rows
        .into_iter()
        .map(|(tx, height, tx_id)| {
            let (kind, amount, cp, dir) = classify_tx(&tx.kind, &node_id);
            TxRecord {
                tx_id: hex::encode(tx_id),
                height,
                kind: kind.to_string(),
                amount,
                counterparty: cp.map(hex::encode),
                direction: dir.to_string(),
            }
        })
        .collect();
    (StatusCode::OK, Json(records)).into_response()
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

// ----- Relay payment (POST /relay/pay) -----

#[derive(Debug, Deserialize)]
struct RelayPayRequest {
    /// The relay's NodeId (64 hex) — the channel host being paid.
    relay: String,
    /// Open payment channel this node (payer) holds with the relay.
    channel_id: String,
    /// Cumulative total authorised to the relay so far (base units, decimal string). The caller
    /// raises it over time to keep paying for ongoing relay service.
    #[serde(with = "amount_str")]
    cumulative: u128,
}

/// Pay a relay for relay service (`POST /relay/pay`). Signs a payment-channel receipt and sends it
/// to the relay over the mesh; the relay verifies it against the channel and its price and records
/// it. Called on the PAYER (client) node. Re-call periodically with a rising cumulative.
async fn relay_pay(State(state): State<ApiState>, Json(req): Json<RelayPayRequest>) -> Response {
    let relay: NodeId = match hex::decode(&req.relay).ok().and_then(|b| b.try_into().ok()) {
        Some(a) => a,
        None => return err(StatusCode::BAD_REQUEST, "relay must be 64 hex chars"),
    };
    let channel_id: [u8; 32] = match hex::decode(&req.channel_id).ok().and_then(|b| b.try_into().ok()) {
        Some(a) => a,
        None => return err(StatusCode::BAD_REQUEST, "channel_id must be 64 hex chars"),
    };
    let peer_id = match peer_id_from_node_id(&relay) {
        Ok(p) => p,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad relay id: {e}")),
    };
    // Sign the receipt: payer authorises the relay (host) to redeem up to `cumulative`.
    let sig = state.identity.sign(&channel_receipt_bytes(&channel_id, &relay, req.cumulative));
    let rpc = RpcRequest::RelayReceipt {
        from_node: state.host_node_id,
        channel_id,
        cumulative: req.cumulative,
        payer_sig: sig.to_vec(),
    };
    match state.mesh_handle.send_rpc(peer_id, rpc).await {
        Ok(RpcResponse::RelayAck) => {
            (StatusCode::OK, Json(serde_json::json!({ "status": "paid" }))).into_response()
        }
        Ok(RpcResponse::Error(e)) => err(StatusCode::BAD_GATEWAY, e),
        Ok(_) => err(StatusCode::BAD_GATEWAY, "unexpected response"),
        Err(e) => err(StatusCode::BAD_GATEWAY, format!("relay payment failed: {e}")),
    }
}

// ----- Naming (POST /names/claim, GET /names/:name) -----

#[derive(Debug, Deserialize)]
struct NameClaimRequest {
    name: String,
}

/// Claim a unique human-readable name for this node (`POST /names/claim`). Submits a `NameClaim`
/// tx; it takes effect once mined. First claim wins (consensus-enforced).
async fn claim_name(State(state): State<ApiState>, Json(req): Json<NameClaimRequest>) -> Response {
    if !ce_chain::is_valid_name(&req.name) {
        return err(
            StatusCode::BAD_REQUEST,
            "name must be 3-32 chars: lowercase a-z, 0-9, hyphen (not leading/trailing)",
        );
    }
    let node = state.host_node_id;
    submit_tx(&state, TxKind::NameClaim { name: req.name, node }, node).await;
    (StatusCode::ACCEPTED, Json(serde_json::json!({ "status": "submitted" }))).into_response()
}

/// Resolve a claimed name to its owning NodeId (`GET /names/:name`).
async fn resolve_name(State(state): State<ApiState>, Path(name): Path<String>) -> Response {
    match state.chain.resolve_name(&name).await {
        Some(node) => (
            StatusCode::OK,
            Json(serde_json::json!({ "name": name, "node_id": hex::encode(node) })),
        )
            .into_response(),
        None => err(StatusCode::NOT_FOUND, "name not claimed"),
    }
}

// ----- Service discovery (POST /discovery/advertise, GET /discovery/find/:service) -----

#[derive(Debug, Deserialize)]
struct AdvertiseRequest {
    service: String,
}

/// Advertise that this node provides a named service, discoverable via the DHT (`POST
/// /discovery/advertise`). Re-call periodically: provider records expire.
async fn advertise_service(State(state): State<ApiState>, Json(req): Json<AdvertiseRequest>) -> Response {
    match state.mesh_handle.advertise_service(&req.service).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "status": "advertised" }))).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, format!("advertise failed: {e}")),
    }
}

/// Find the NodeIds of nodes advertising a named service (`GET /discovery/find/:service`).
async fn find_service(State(state): State<ApiState>, Path(service): Path<String>) -> Response {
    match state.mesh_handle.find_service(&service).await {
        Ok(nodes) => {
            let ids: Vec<String> = nodes.iter().map(hex::encode).collect();
            (StatusCode::OK, Json(serde_json::json!({ "service": service, "providers": ids }))).into_response()
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, format!("find failed: {e}")),
    }
}

/// Sign `kind` with the node identity, add to the pool, and broadcast.
async fn submit_tx(state: &ApiState, kind: TxKind, origin: NodeId) {
    let data = bincode::serialize(&kind).expect("serialize tx");
    let sig = state.identity.sign(&data);
    let tx = Tx::new(kind, origin, sig);
    state.pool.add(tx.clone()).await;
    let _ = state.mesh_handle.broadcast_tx(&tx).await;
}

// ----- Content-addressed blobs (PUT/GET /blobs) -----
//
// A minimal content-addressed store (a precursor to the data layer): upload bytes, get back their
// sha256; fetch by hash. WASM modules referenced by `Workload::Wasm { module_hash }` are resolved
// from here. The hash is self-verifying, so blobs are immutable and tamper-evident.

async fn put_blob(State(state): State<ApiState>, body: axum::body::Bytes) -> Response {
    let hash: [u8; 32] = Sha256::digest(&body).into();
    let hex = hex::encode(hash);
    let dir = state.data_dir.join("blobs");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, format!("blob dir: {e}"));
    }
    if let Err(e) = std::fs::write(dir.join(&hex), &body) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, format!("store blob: {e}"));
    }
    // Announce to the DHT that we now provide this chunk, so peers can fetch it (Stage 2).
    let _ = state.mesh_handle.provide_chunk(hash).await;
    (StatusCode::CREATED, Json(serde_json::json!({ "hash": hex }))).into_response()
}

async fn get_blob(State(state): State<ApiState>, Path(hash): Path<String>) -> Response {
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return err(StatusCode::BAD_REQUEST, "hash must be 64 hex chars");
    }
    if let Ok(bytes) = std::fs::read(state.data_dir.join("blobs").join(&hash)) {
        return (StatusCode::OK, bytes).into_response();
    }
    // Not held locally — pull it from the mesh: find providers via the DHT, fetch from one, and
    // verify the bytes against the requested hash before serving (content addressing makes this
    // trustless). The fetched chunk is cached + re-announced, so popular data self-replicates.
    let mut cid = [0u8; 32];
    if hex::decode_to_slice(&hash, &mut cid).is_err() {
        return err(StatusCode::BAD_REQUEST, "hash must be 64 hex chars");
    }
    match fetch_chunk_from_mesh(&state, cid).await {
        Some(bytes) => (StatusCode::OK, bytes).into_response(),
        None => err(StatusCode::NOT_FOUND, "blob not found (locally or in mesh)"),
    }
}

/// Pull a content-addressed chunk from the mesh: discover providers via the DHT, `FetchChunk` from
/// each in turn, and accept the first reply whose bytes hash to `cid`. On success the chunk is
/// stored locally and re-announced. Returns `None` if no provider yields valid bytes in time.
async fn fetch_chunk_from_mesh(state: &ApiState, cid: [u8; 32]) -> Option<Vec<u8>> {
    let providers = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        state.mesh_handle.find_providers(cid),
    )
    .await
    .ok()?
    .ok()?;

    for peer in providers {
        let req = RpcRequest::FetchChunk { from_node: state.host_node_id, cid, receipt: None };
        if let Ok(RpcResponse::ChunkData { bytes, .. }) = state.mesh_handle.send_rpc(peer, req).await
        {
            let got: [u8; 32] = Sha256::digest(&bytes).into();
            if got != cid {
                continue; // wrong/tampered bytes — try the next provider
            }
            let dir = state.data_dir.join("blobs");
            let _ = std::fs::create_dir_all(&dir);
            let _ = std::fs::write(dir.join(hex::encode(cid)), &bytes);
            let _ = state.mesh_handle.provide_chunk(cid).await;
            return Some(bytes);
        }
    }
    None
}

#[derive(Debug, Deserialize)]
struct DataFetchRequest {
    /// The provider (channel host) to fetch from and pay.
    provider: String,
    /// Content id (sha256 hex) of the chunk to fetch.
    cid: String,
    /// Open payment channel this node (payer) holds with the provider.
    channel_id: String,
    /// Monotonic cumulative this node authorises the provider to redeem — must cover the running
    /// cost of all chunks fetched on this channel so far. The caller tracks it across fetches.
    #[serde(with = "amount_str")]
    cumulative: u128,
}

/// Paid chunk fetch (Stage 3): sign a payment-channel receipt for `cumulative` and pull the chunk
/// from `provider` over the mesh, paying as we go. Called on the PAYER node. The provider verifies
/// the receipt before serving; we verify the returned bytes against `cid`, then cache + announce.
async fn data_fetch(State(state): State<ApiState>, Json(req): Json<DataFetchRequest>) -> Response {
    let provider: NodeId = match hex::decode(&req.provider).ok().and_then(|b| b.try_into().ok()) {
        Some(a) => a,
        None => return err(StatusCode::BAD_REQUEST, "provider must be 64 hex chars"),
    };
    let mut cid = [0u8; 32];
    if hex::decode_to_slice(&req.cid, &mut cid).is_err() {
        return err(StatusCode::BAD_REQUEST, "cid must be 64 hex chars");
    }
    let channel_id: [u8; 32] = match hex::decode(&req.channel_id).ok().and_then(|b| b.try_into().ok()) {
        Some(a) => a,
        None => return err(StatusCode::BAD_REQUEST, "channel_id must be 64 hex chars"),
    };
    let peer_id = match peer_id_from_node_id(&provider) {
        Ok(p) => p,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad provider id: {e}")),
    };

    // Sign the receipt: payer authorises the provider (host) to redeem up to `cumulative`.
    let payer_sig = state.identity.sign(&channel_receipt_bytes(&channel_id, &provider, req.cumulative));
    let receipt = ChunkReceipt { channel_id, cumulative: req.cumulative, payer_sig };
    let receipt_bytes = bincode::serialize(&receipt).expect("serialize receipt");

    let rpc = RpcRequest::FetchChunk {
        from_node: state.host_node_id,
        cid,
        receipt: Some(receipt_bytes),
    };
    match state.mesh_handle.send_rpc(peer_id, rpc).await {
        Ok(RpcResponse::ChunkData { bytes, .. }) => {
            let got: [u8; 32] = Sha256::digest(&bytes).into();
            if got != cid {
                return err(StatusCode::BAD_GATEWAY, "provider returned bytes that do not match cid");
            }
            let dir = state.data_dir.join("blobs");
            let _ = std::fs::create_dir_all(&dir);
            let _ = std::fs::write(dir.join(hex::encode(cid)), &bytes);
            let _ = state.mesh_handle.provide_chunk(cid).await;
            (StatusCode::OK, bytes).into_response()
        }
        Ok(RpcResponse::Error(e)) => err(StatusCode::BAD_GATEWAY, e),
        Ok(_) => err(StatusCode::BAD_GATEWAY, "unexpected response"),
        Err(e) => err(StatusCode::BAD_GATEWAY, format!("mesh fetch failed: {e}")),
    }
}

// ----- App messaging (POST /mesh/send, GET /mesh/messages[/stream]) -----

#[derive(Debug, Deserialize)]
struct SendMessageRequest {
    /// Recipient NodeId (64 hex).
    to: String,
    /// App-chosen topic namespace.
    topic: String,
    /// Opaque payload, hex-encoded.
    #[serde(default)]
    payload_hex: String,
}

/// Send a directed, signed application message to a node over the mesh (`POST /mesh/send`). The
/// receiving node enqueues it for its local app; `AppAck` confirms enqueue.
async fn send_message(State(state): State<ApiState>, Json(req): Json<SendMessageRequest>) -> Response {
    let to: NodeId = match hex::decode(&req.to).ok().and_then(|b| b.try_into().ok()) {
        Some(a) => a,
        None => return err(StatusCode::BAD_REQUEST, "to must be 64 hex chars"),
    };
    let payload = match hex::decode(&req.payload_hex) {
        Ok(p) => p,
        Err(_) => return err(StatusCode::BAD_REQUEST, "payload_hex must be valid hex"),
    };
    let peer_id = match peer_id_from_node_id(&to) {
        Ok(p) => p,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad recipient id: {e}")),
    };
    let rpc = RpcRequest::AppMessage { from_node: state.host_node_id, topic: req.topic, payload };
    match state.mesh_handle.send_rpc(peer_id, rpc).await {
        Ok(RpcResponse::AppAck) => {
            (StatusCode::OK, Json(serde_json::json!({ "status": "delivered" }))).into_response()
        }
        Ok(RpcResponse::Error(e)) => err(StatusCode::BAD_GATEWAY, e),
        Ok(_) => err(StatusCode::BAD_GATEWAY, "unexpected response"),
        Err(e) => err(StatusCode::BAD_GATEWAY, format!("mesh send failed: {e}")),
    }
}

/// Snapshot of recently-received app messages (`GET /mesh/messages`).
async fn list_messages(State(state): State<ApiState>) -> Response {
    let msgs: Vec<AppMessage> = state.app_inbox.lock().await.iter().cloned().collect();
    (StatusCode::OK, Json(msgs)).into_response()
}

/// SSE push stream of inbound app messages (`GET /mesh/messages/stream`).
async fn stream_messages(
    State(state): State<ApiState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.app_msg_tx.subscribe();
    Sse::new(sse_broadcast(rx, |m: &AppMessage| m.clone())).keep_alive(KeepAlive::default())
}

#[derive(Debug, Deserialize)]
struct AppRequestRequest {
    /// Recipient NodeId (64 hex).
    to: String,
    topic: String,
    #[serde(default)]
    payload_hex: String,
    /// How long to wait for the peer's app to reply, in milliseconds (default 30s).
    #[serde(default)]
    timeout_ms: Option<u64>,
}

/// Send a request to a node and wait for its app's reply (sync request/response, `POST
/// /mesh/request`). The peer surfaces the request to its app, which answers via `/mesh/reply`;
/// the reply payload is returned here. Times out if the app does not answer.
async fn mesh_request(State(state): State<ApiState>, Json(req): Json<AppRequestRequest>) -> Response {
    let to: NodeId = match hex::decode(&req.to).ok().and_then(|b| b.try_into().ok()) {
        Some(a) => a,
        None => return err(StatusCode::BAD_REQUEST, "to must be 64 hex chars"),
    };
    let payload = match hex::decode(&req.payload_hex) {
        Ok(p) => p,
        Err(_) => return err(StatusCode::BAD_REQUEST, "payload_hex must be valid hex"),
    };
    let peer_id = match peer_id_from_node_id(&to) {
        Ok(p) => p,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad recipient id: {e}")),
    };
    let timeout = std::time::Duration::from_millis(req.timeout_ms.unwrap_or(30_000));
    let rpc = RpcRequest::AppRequest { from_node: state.host_node_id, topic: req.topic, payload };
    match tokio::time::timeout(timeout, state.mesh_handle.send_rpc(peer_id, rpc)).await {
        Ok(Ok(RpcResponse::AppReply { payload })) => {
            (StatusCode::OK, Json(serde_json::json!({ "payload_hex": hex::encode(payload) }))).into_response()
        }
        Ok(Ok(RpcResponse::Error(e))) => err(StatusCode::BAD_GATEWAY, e),
        Ok(Ok(_)) => err(StatusCode::BAD_GATEWAY, "unexpected response"),
        Ok(Err(e)) => err(StatusCode::BAD_GATEWAY, format!("mesh request failed: {e}")),
        Err(_) => err(StatusCode::GATEWAY_TIMEOUT, "peer app did not reply in time"),
    }
}

#[derive(Debug, Deserialize)]
struct ReplyRequest {
    /// The `reply_token` from the inbound request message.
    token: u64,
    #[serde(default)]
    payload_hex: String,
}

/// Answer a request previously received with a `reply_token` (`POST /mesh/reply`). Sends the
/// reply back over the held mesh channel to the original requester.
async fn mesh_reply(State(state): State<ApiState>, Json(req): Json<ReplyRequest>) -> Response {
    let payload = match hex::decode(&req.payload_hex) {
        Ok(p) => p,
        Err(_) => return err(StatusCode::BAD_REQUEST, "payload_hex must be valid hex"),
    };
    match state.mesh_handle.respond_rpc(req.token, RpcResponse::AppReply { payload }).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "status": "replied" }))).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, format!("reply failed: {e}")),
    }
}

#[derive(Debug, Deserialize)]
struct SubscribeRequest {
    topic: String,
}

/// Subscribe this node to an app pub/sub topic so received messages land in the inbox + stream
/// (`POST /mesh/subscribe`). Idempotent; the subscription lasts for the node's lifetime.
async fn subscribe_topic(State(state): State<ApiState>, Json(req): Json<SubscribeRequest>) -> Response {
    match state.mesh_handle.subscribe_app(&req.topic).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "status": "subscribed" }))).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, format!("subscribe failed: {e}")),
    }
}

#[derive(Debug, Deserialize)]
struct PublishRequest {
    topic: String,
    #[serde(default)]
    payload_hex: String,
}

/// Publish a signed app pub/sub message to a topic (`POST /mesh/publish`). The node signs the
/// message with its identity (so subscribers verify authorship) and broadcasts it; it also
/// subscribes to the topic so it participates in the topic mesh.
async fn publish_topic(State(state): State<ApiState>, Json(req): Json<PublishRequest>) -> Response {
    let payload = match hex::decode(&req.payload_hex) {
        Ok(p) => p,
        Err(_) => return err(StatusCode::BAD_REQUEST, "payload_hex must be valid hex"),
    };
    // Subscribe so we're in the topic mesh before publishing (idempotent).
    let _ = state.mesh_handle.subscribe_app(&req.topic).await;

    let nonce = state.send_nonce.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let sig = state.identity.sign(&app_pubsub_bytes(&req.topic, &payload, nonce));
    let msg = AppPubSubMsg {
        from: state.host_node_id,
        topic: req.topic.clone(),
        payload,
        nonce,
        sig: sig.to_vec(),
    };
    let data = bincode::serialize(&msg).expect("serialize app pubsub");
    match state.mesh_handle.publish_app(&req.topic, data).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "status": "published" }))).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, format!("publish failed: {e}")),
    }
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
    // Address the HTTP API binds to. Defaults to `127.0.0.1` (loopback only). Setting this to
    // `0.0.0.0` exposes the API on all interfaces and is only safe behind a firewall + the token.
    api_bind: String,
    listen_port: u16,
    job_store: JobStore,
    pool: TxPool,
    settle_notify_tx: mpsc::Sender<()>,
    data_dir: PathBuf,
    atlas: Atlas,
    netgraph: NetGraph,
    docker: Option<Docker>,
    // When set, serve the API over TLS with a cert keyed by this Ed25519 seed (the node
    // identity). Clients pin the cert against the node's NodeId. None = plain HTTP.
    tls_seed: Option<[u8; 32]>,
    app_inbox: AppInbox,
    app_msg_tx: broadcast::Sender<AppMessage>,
    tunnel_control: ce_mesh::StreamControl,
) -> Result<()> {
    if docker.is_none() {
        tracing::warn!("Docker unavailable — job routes return 503");
    }
    let host_node_id = identity.node_id();
    // Derive + persist the API token before `identity`/`data_dir` are moved into the state.
    let api_token = Arc::new(load_or_create_api_token(&data_dir, &identity.secret_bytes()));
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
        app_inbox,
        app_msg_tx,
        send_nonce,
        job_store,
        pool,
        settle_notify_tx,
        data_dir,
        atlas,
        netgraph,
        listen_port,
        tunnel_control,
    };

    let app = Router::new()
        .route("/jobs/bid", post(bid_job))
        .route("/jobs", get(list_jobs))
        .route("/jobs/:id", get(job_status))
        .route("/jobs/:id/settle", post(settle_job))
        .route("/jobs/:id", delete(stop_job))
        .route("/transfer", post(transfer))
        .route("/capabilities/revoke", post(revoke_capability))
        .route("/capabilities/revoked", get(get_revoked))
        .route("/chain/save", post(chain_save))
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
        .route("/netgraph", get(get_netgraph))
        .route("/beacon", get(get_beacon))
        .route("/history/:node_id", get(get_history))
        .route("/transactions/:node_id", get(get_transactions))
        .route("/channels", get(list_channels))
        .route("/channels/open", post(channel_open))
        .route("/channels/receipt", post(channel_receipt))
        .route("/channels/:id/close", post(channel_close))
        .route("/channels/:id/expire", post(channel_expire))
        .route("/blobs", post(put_blob))
        .route("/blobs/:hash", get(get_blob))
        .route("/data/fetch", post(data_fetch))
        .route("/mesh/send", post(send_message))
        .route("/mesh/messages", get(list_messages))
        .route("/mesh/messages/stream", get(stream_messages))
        .route("/mesh/subscribe", post(subscribe_topic))
        .route("/mesh/publish", post(publish_topic))
        .route("/mesh/request", post(mesh_request))
        .route("/mesh/reply", post(mesh_reply))
        .route("/names/claim", post(claim_name))
        .route("/names/:name", get(resolve_name))
        .route("/discovery/advertise", post(advertise_service))
        .route("/discovery/find/:service", get(find_service))
        .route("/relay/pay", post(relay_pay))
        // Personal mesh OS: direct HTTP auth for LAN use (legacy, kept for compatibility).
        // Personal mesh OS: relay-routed mesh RPCs (correct path for NAT traversal).
        .route("/mesh-deploy", post(mesh_deploy))
        .route("/mesh-kill", post(mesh_kill))
        .route("/tunnel", post(open_tunnel))
        .with_state(state);

    // Token-gate every mutating (non-GET) request. The token is derived from the node identity
    // and written to <data_dir>/api.token (chmod 600) so same-host clients (the `ce` CLI, ce-rs
    // apps) can read it. Read-only GETs stay open. This defends against same-host attackers,
    // CSRF/SSRF, and (with the localhost bind) the network. Mesh-originated value ops are
    // unaffected — they arrive over the Noise-authenticated libp2p RPC path, not this HTTP API.
    let app = app.layer(middleware::from_fn_with_state(api_token.clone(), require_api_token));

    // Read-only, localhost-scoped CORS so a browser dashboard served from http://localhost can fetch
    // the GET/SSE read surfaces (status, history, transactions, atlas, beacon, streams). Scoped to
    // GET only: mutating routes (POST/PUT/DELETE) are NOT made cross-origin-reachable — a browser
    // preflight for a non-GET method receives no allow, and the api.token already gates writes. The
    // origin predicate reflects only loopback origins (http(s)://localhost|127.0.0.1|[::1][:port]),
    // so a hostile public web page cannot read this node's API from a victim's browser.
    let cors = tower_http::cors::CorsLayer::new()
        .allow_methods([Method::GET])
        .allow_origin(tower_http::cors::AllowOrigin::predicate(|origin, _req| {
            origin
                .to_str()
                .map(is_localhost_origin)
                .unwrap_or(false)
        }));
    let app = app.layer(cors);

    let addr = format!("{api_bind}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    if !api_bind.starts_with("127.") && api_bind != "localhost" && api_bind != "::1" {
        tracing::warn!(
            "API bound to {api_bind} (non-loopback) — the API is reachable beyond this host; \
             ensure a firewall and rely on the api.token for auth"
        );
    }

    match tls_seed {
        None => {
            tracing::info!("API listening on http://{addr}");
            axum::serve(listener, app).await?;
        }
        Some(seed) => {
            // TLS-from-identity: serve over rustls with a cert keyed by the node identity.
            // Clients pin the cert to this node's NodeId (ce-tls). The mesh is Noise-encrypted
            // separately; this protects the direct HTTP API.
            use hyper_util::rt::{TokioExecutor, TokioIo};
            use hyper_util::server::conn::auto::Builder as ConnBuilder;
            use hyper_util::service::TowerToHyperService;

            let server_config = ce_tls::server_config(&seed)?;
            let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            tracing::info!("API listening on https://{addr} (TLS-from-identity, NodeId-pinned)");
            loop {
                let (stream, _peer) = match listener.accept().await {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!("tls accept (tcp): {e}");
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                let svc = TowerToHyperService::new(app.clone());
                tokio::spawn(async move {
                    let tls = match acceptor.accept(stream).await {
                        Ok(t) => t,
                        Err(e) => {
                            tracing::debug!("tls handshake failed: {e}");
                            return;
                        }
                    };
                    let io = TokioIo::new(tls);
                    if let Err(e) = ConnBuilder::new(TokioExecutor::new()).serve_connection(io, svc).await {
                        tracing::debug!("tls connection: {e}");
                    }
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localhost_origins_accepted() {
        for o in [
            "http://localhost",
            "http://localhost:8844",
            "https://localhost:3000",
            "http://127.0.0.1",
            "http://127.0.0.1:5173",
            "http://[::1]",
            "http://[::1]:8080",
        ] {
            assert!(is_localhost_origin(o), "should accept {o}");
        }
    }

    #[test]
    fn non_localhost_origins_rejected() {
        for o in [
            "http://evil.com",
            "https://ce-net.com",
            "http://127.0.0.1.evil.com",
            "http://localhost.evil.com",
            "ftp://localhost",
            "localhost",
            "",
        ] {
            assert!(!is_localhost_origin(o), "should reject {o}");
        }
    }

    #[test]
    fn classify_tx_direction_relative_to_node() {
        let a: NodeId = [1u8; 32];
        let b: NodeId = [2u8; 32];

        // Transfer out: a pays b.
        let (kind, amount, cp, dir) =
            classify_tx(&TxKind::Transfer { from: a, to: b, amount: 500 }, &a);
        assert_eq!((kind, amount, dir), ("Transfer", 500, "out"));
        assert_eq!(cp, Some(b));

        // Same Transfer, viewed by the recipient b: it is "in".
        let (_, _, cp, dir) =
            classify_tx(&TxKind::Transfer { from: a, to: b, amount: 500 }, &b);
        assert_eq!(dir, "in");
        assert_eq!(cp, Some(a));

        // JobSettle: host earns -> "in"; payer pays -> "out".
        let settle = TxKind::JobSettle {
            job_id: [9u8; 32],
            host: a,
            payer: b,
            cpu_ms: 0,
            mem_mb: 0,
            cost: 1_000,
            payer_sig: [0u8; 64],
        };
        let (_, amount, cp, dir) = classify_tx(&settle, &a);
        assert_eq!((amount, dir), (1_000, "in"));
        assert_eq!(cp, Some(b));
        let (_, _, _, dir) = classify_tx(&settle, &b);
        assert_eq!(dir, "out");

        // UptimeReward is always incoming, no counterparty.
        let (kind, amount, cp, dir) =
            classify_tx(&TxKind::UptimeReward { node: a, amount: 7, epoch: 1 }, &a);
        assert_eq!((kind, amount, cp, dir), ("UptimeReward", 7, None, "in"));
    }
}
