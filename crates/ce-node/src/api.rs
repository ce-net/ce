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
use ce_identity::{verify, Identity, NodeId};
use ce_mesh::MeshHandle;
use ce_protocol::{BurnProof, Capability, CellAddress, CellSignal};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    sync::Arc,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, Mutex};

use crate::{CeJobStatus, JobRecord, JobStore, SignalRing, TxPool};

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
        TxKind::JobExpire { .. } | TxKind::TrustGrant { .. } => None,
    }
}

// ----- Device auth -----

/// Canonical bytes the client signs for authenticated sync/exec requests.
/// scheme: b"ce-auth-v1" SP method SP path SP timestamp_le_u64
fn auth_bytes(method: &str, path: &str, timestamp_ms: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"ce-auth-v1 ");
    buf.extend_from_slice(method.as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(path.as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(&timestamp_ms.to_le_bytes());
    buf
}

/// Extract and verify CE device auth headers. Returns the verified sender NodeId on success.
/// Headers: X-CE-From (64 hex), X-CE-Timestamp (unix ms u64), X-CE-Sig (128 hex).
fn verify_device_auth(
    headers: &HeaderMap,
    method: &str,
    path: &str,
    data_dir: &std::path::Path,
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

    let from_bytes = hex::decode(from_hex)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "bad X-CE-From"))?;
    let from: NodeId = from_bytes
        .try_into()
        .map_err(|_| err(StatusCode::BAD_REQUEST, "X-CE-From must be 64 hex chars"))?;

    let ts_ms: u64 = ts_str
        .parse()
        .map_err(|_| err(StatusCode::BAD_REQUEST, "bad X-CE-Timestamp"))?;

    let sig_bytes = hex::decode(sig_hex)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "bad X-CE-Sig"))?;
    let sig: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| err(StatusCode::BAD_REQUEST, "X-CE-Sig must be 128 hex chars"))?;

    // Timestamp must be within ±5 minutes of server time.
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let diff = now_ms.abs_diff(ts_ms);
    if diff > 5 * 60 * 1000 {
        return Err(err(StatusCode::UNAUTHORIZED, "X-CE-Timestamp out of range"));
    }

    let bytes = auth_bytes(method, path, ts_ms);
    verify(&from, &bytes, &sig)
        .map_err(|_| err(StatusCode::UNAUTHORIZED, "invalid CE signature"))?;

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
    if let Err(resp) = verify_device_auth(&headers, "PUT", &path, &state.data_dir) {
        return resp;
    }

    // Strip the leading "/sync/" prefix to get the relative path.
    let rel = req.uri().path().trim_start_matches("/sync/");
    let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    let target = home.join(rel);

    // Prevent path traversal outside the home directory.
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

    let body_bytes = match axum::body::to_bytes(req.into_body(), 256 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("read body: {e}")),
    };

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
    if let Err(resp) = verify_device_auth(&headers, "GET", &path, &state.data_dir) {
        return resp;
    }

    let rel = req.uri().path().trim_start_matches("/sync/");
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

    let data = match std::fs::read(&canonical_target) {
        Ok(d) => d,
        Err(_) => return err(StatusCode::NOT_FOUND, "file not found"),
    };

    (StatusCode::OK, Body::from(data)).into_response()
}

// ----- POST /exec -----

#[derive(Debug, Deserialize)]
pub struct ExecRequest {
    /// Command to run, e.g. ["cargo", "build", "--release"].
    pub cmd: Vec<String>,
    /// Working directory (relative to home dir or absolute). Defaults to home.
    #[serde(default)]
    pub cwd: Option<String>,
}

#[derive(Debug, Serialize)]
struct ExecResponse {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

async fn exec_command(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<ExecRequest>,
) -> Response {
    // Build the path string for auth (fixed, not from URI since body carries the command).
    let path = "/exec";
    if let Err(resp) = verify_device_auth(&headers, "POST", path, &state.data_dir) {
        return resp;
    }

    if req.cmd.is_empty() {
        return err(StatusCode::BAD_REQUEST, "cmd must not be empty");
    }

    let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    let cwd = match &req.cwd {
        Some(c) => {
            let p = if c.starts_with('~') {
                home.join(c.trim_start_matches("~/").trim_start_matches('~'))
            } else {
                PathBuf::from(c)
            };
            p
        }
        None => home,
    };

    let result = tokio::process::Command::new(&req.cmd[0])
        .args(&req.cmd[1..])
        .current_dir(&cwd)
        .output()
        .await;

    match result {
        Ok(output) => {
            let exit_code = output.status.code().unwrap_or(-1);
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            tracing::info!(
                "exec {:?} in {} → exit {}",
                req.cmd,
                cwd.display(),
                exit_code
            );
            (StatusCode::OK, Json(ExecResponse { stdout, stderr, exit_code })).into_response()
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, format!("exec failed: {e}")),
    }
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
) -> Result<()> {
    let docker = Docker::connect_with_socket_defaults().ok();
    if docker.is_none() {
        tracing::warn!("Docker unavailable — job routes will return 503");
    }
    let host_node_id = identity.node_id();
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
    };

    let app = Router::new()
        .route("/jobs/bid", post(bid_job))
        .route("/jobs/:id", get(job_status))
        .route("/jobs/:id/settle", post(settle_job))
        .route("/jobs/:id", delete(stop_job))
        .route("/status", get(node_status))
        .route("/signals", get(list_signals))
        .route("/signals/send", post(send_signal))
        .route("/health", get(|| async { "ok" }))
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
