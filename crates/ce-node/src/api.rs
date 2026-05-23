use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
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
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("API listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
