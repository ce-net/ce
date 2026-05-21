use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use bollard::{
    container::{
        CreateContainerOptions, InspectContainerOptions, RemoveContainerOptions,
        StartContainerOptions,
    },
    image::CreateImageOptions,
    models::HostConfig,
    Docker,
};
use futures::StreamExt;
use ce_chain::Chain;
use ce_identity::NodeId;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

#[derive(Clone)]
struct ApiState {
    /// None when Docker socket is unavailable — job routes return 503.
    docker: Option<Docker>,
    chain: Arc<Mutex<Chain>>,
    host_node_id: NodeId,
}

#[derive(Debug, Deserialize)]
pub struct RunJobRequest {
    pub image: String,
    /// Hex-encoded NodeId (32 bytes = 64 hex chars) of the account paying for this job.
    pub payer: String,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub cmd: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RunJobResponse {
    /// CE job ID — equals the Docker container ID; use with /jobs/:id routes.
    pub job_id: String,
}

#[derive(Debug, Serialize)]
pub struct JobStatus {
    pub container_id: String,
    pub status: String,
    pub image: String,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(ErrorBody { error: msg.into() })).into_response()
}

/// Snapshot returned by GET /status — used by ce-deploy for consensus checks.
#[derive(Debug, Serialize)]
pub struct NodeStatusResponse {
    pub node_id: String,
    pub height: u64,
    pub difficulty: u8,
    pub balance: i64,
}

pub async fn start(chain: Arc<Mutex<Chain>>, host_node_id: NodeId, port: u16) -> Result<()> {
    let docker = Docker::connect_with_socket_defaults().ok();
    if docker.is_none() {
        tracing::warn!("Docker unavailable — job routes will return 503");
    }
    let state = ApiState { docker, chain, host_node_id };

    let app = Router::new()
        .route("/jobs/run", post(run_job))
        .route("/jobs/:id", get(job_status))
        .route("/jobs/:id", delete(stop_job))
        .route("/status", get(node_status))
        .route("/health", get(|| async { "ok" }))
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("API listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

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

async fn run_job(
    State(state): State<ApiState>,
    Json(req): Json<RunJobRequest>,
) -> Response {
    // Decode and validate payer node ID.
    let payer: NodeId = match hex::decode(&req.payer)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(arr) => arr,
        None => return err(StatusCode::BAD_REQUEST, "payer must be a 64-hex-char node ID"),
    };

    // Enforce positive balance before launching anything.
    let balance = state.chain.lock().await.balance(&payer);
    if balance <= 0 {
        return err(
            StatusCode::PAYMENT_REQUIRED,
            format!("payer balance is {balance}; must be positive to run jobs"),
        );
    }

    // Build env list and labels with owned Strings.
    let env_list: Vec<String> = req.env.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let mut labels: HashMap<String, String> = HashMap::new();
    labels.insert("ce.payer".into(), req.payer.clone());
    labels.insert("ce.host".into(), hex::encode(state.host_node_id));

    let cmd: Option<Vec<String>> = if req.cmd.is_empty() { None } else { Some(req.cmd) };
    let image = req.image;

    let config: bollard::container::Config<String> = bollard::container::Config {
        image: Some(image.clone()),
        env: Some(env_list),
        cmd,
        labels: Some(labels),
        host_config: Some(HostConfig {
            auto_remove: Some(false),
            ..Default::default()
        }),
        ..Default::default()
    };

    let docker = match &state.docker {
        Some(d) => d,
        None => return err(StatusCode::SERVICE_UNAVAILABLE, "Docker not available on this node"),
    };

    // Pull image if not present locally — Docker create returns 404 for missing images.
    let mut pull_stream = docker.create_image(
        Some(CreateImageOptions { from_image: image.as_str(), ..Default::default() }),
        None,
        None,
    );
    while let Some(ev) = pull_stream.next().await {
        if let Err(e) = ev {
            return err(StatusCode::INTERNAL_SERVER_ERROR, format!("pull image: {e}"));
        }
    }

    let create_opts = CreateContainerOptions { name: String::new(), platform: None };
    let container = match docker.create_container(Some(create_opts), config).await {
        Ok(c) => c,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, format!("create container: {e}")),
    };

    let id = container.id;
    if let Err(e) = docker
        .start_container(&id, None::<StartContainerOptions<String>>)
        .await
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, format!("start container: {e}"));
    }

    (StatusCode::CREATED, Json(RunJobResponse { job_id: id }))
        .into_response()
}

async fn job_status(State(state): State<ApiState>, Path(id): Path<String>) -> Response {
    let docker = match &state.docker {
        Some(d) => d,
        None => return err(StatusCode::SERVICE_UNAVAILABLE, "Docker not available on this node"),
    };
    match docker
        .inspect_container(&id, Some(InspectContainerOptions { size: false }))
        .await
    {
        Ok(info) => {
            let status = info
                .state
                .and_then(|s| s.status)
                .map(|s| format!("{s:?}"))
                .unwrap_or_else(|| "unknown".into());
            let image = info.image.unwrap_or_default();
            (StatusCode::OK, Json(JobStatus { container_id: id, status, image })).into_response()
        }
        Err(e) => err(StatusCode::NOT_FOUND, format!("container not found: {e}")),
    }
}

async fn stop_job(State(state): State<ApiState>, Path(id): Path<String>) -> Response {
    let docker = match &state.docker {
        Some(d) => d,
        None => return err(StatusCode::SERVICE_UNAVAILABLE, "Docker not available on this node"),
    };
    let opts = RemoveContainerOptions { force: true, ..Default::default() };
    match docker.remove_container(&id, Some(opts)).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err(StatusCode::NOT_FOUND, format!("remove container: {e}")),
    }
}
