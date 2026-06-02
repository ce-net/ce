use anyhow::{anyhow, Result};
use bollard::container::{
    CreateContainerOptions, ListContainersOptions, LogOutput, LogsOptions,
    RemoveContainerOptions, StartContainerOptions, StatsOptions, WaitContainerOptions,
};
use bollard::image::CreateImageOptions;
use bollard::models::HostConfig;
use bollard::Docker;
use ce_identity::NodeId;
use futures::StreamExt;
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::warn;

const METERING_INTERVAL_SECS: u64 = 10;
const CREDITS_PER_CPU_SECOND: u64 = 10;
const CREDITS_PER_GB_SECOND: u64 = 1;

#[derive(Debug)]
pub struct MeterReading {
    pub job_id: String,
    pub payer: NodeId,
    pub host: NodeId,
    pub cpu_ms: u64,
    pub mem_mb: u64,
    pub cost: u64,
}

/// Parameters for launching a CE-managed container.
#[derive(Debug, Clone)]
pub struct JobSpec {
    pub job_id: [u8; 32],
    pub image: String,
    pub cmd: Vec<String>,
    /// Key-value pairs passed as environment variables.
    pub env: Vec<(String, String)>,
    pub cpu_cores: u32,
    pub mem_mb: u64,
    pub payer: NodeId,
}

#[derive(Clone)]
pub struct ContainerManager {
    pub docker: Docker,
    host_node_id: NodeId,
    /// "runsc" when gVisor is detected; None uses the default runc runtime.
    runtime: Option<String>,
}

impl ContainerManager {
    pub async fn new(host_node_id: NodeId) -> Result<Self> {
        let docker = Docker::connect_with_socket_defaults()?;
        let runtime = detect_runtime(&docker).await;
        Ok(Self { docker, host_node_id, runtime })
    }

    /// Pull the image (if not cached) and start a sandboxed container for the job.
    /// Returns the Docker container ID.
    pub async fn launch_job(&self, spec: &JobSpec) -> Result<String> {
        let mut pull_stream = self.docker.create_image(
            Some(CreateImageOptions { from_image: spec.image.as_str(), ..Default::default() }),
            None,
            None,
        );
        while let Some(ev) = pull_stream.next().await {
            ev?;
        }

        let env_list: Vec<String> = spec.env.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let mut labels: HashMap<String, String> = HashMap::new();
        labels.insert("ce.payer".into(), hex::encode(spec.payer));
        labels.insert("ce.host".into(), hex::encode(self.host_node_id));
        labels.insert("ce.job_id".into(), hex::encode(spec.job_id));

        let cmd: Option<Vec<String>> =
            if spec.cmd.is_empty() { None } else { Some(spec.cmd.clone()) };

        let config = bollard::container::Config {
            image: Some(spec.image.clone()),
            env: Some(env_list),
            cmd,
            labels: Some(labels),
            host_config: Some(HostConfig {
                runtime: self.runtime.clone(),
                nano_cpus: Some(spec.cpu_cores as i64 * 1_000_000_000),
                memory: Some((spec.mem_mb * 1024 * 1024) as i64),
                // No direct internet; all traffic must route through CE.
                network_mode: Some("none".to_string()),
                auto_remove: Some(false),
                ..Default::default()
            }),
            ..Default::default()
        };

        let create_opts = CreateContainerOptions::<String> { name: String::new(), platform: None };
        let container = self.docker.create_container(Some(create_opts), config).await?;
        let container_id = container.id;

        self.docker
            .start_container(&container_id, None::<StartContainerOptions<String>>)
            .await?;

        Ok(container_id)
    }

    /// Block until a container exits and return its exit code.
    pub async fn wait_for_exit(&self, container_id: &str) -> Result<i64> {
        wait_for_exit_impl(&self.docker, container_id).await
    }

    /// Force-remove a running container (used when a cell's wallet is exhausted).
    pub async fn stop_job(&self, container_id: &str) -> Result<()> {
        use bollard::container::RemoveContainerOptions;
        self.docker
            .remove_container(container_id, Some(RemoveContainerOptions { force: true, ..Default::default() }))
            .await?;
        Ok(())
    }

    /// Runs the metering loop indefinitely. Call this in a spawned task.
    pub async fn run(self, reading_tx: mpsc::Sender<MeterReading>) -> Result<()> {
        let mut interval = tokio::time::interval(Duration::from_secs(METERING_INTERVAL_SECS));
        loop {
            interval.tick().await;
            let containers = match list_ce_containers(&self.docker).await {
                Ok(c) => c,
                Err(e) => {
                    warn!("list containers: {e}");
                    continue;
                }
            };
            for (container_id, payer) in containers {
                match snapshot_stats(&self.docker, &container_id).await {
                    Ok((cpu_ms, mem_mb)) => {
                        let cost = compute_cost(cpu_ms, mem_mb, METERING_INTERVAL_SECS);
                        let reading = MeterReading {
                            job_id: container_id,
                            payer,
                            host: self.host_node_id,
                            cpu_ms,
                            mem_mb,
                            cost,
                        };
                        if reading_tx.send(reading).await.is_err() {
                            return Ok(());
                        }
                    }
                    Err(e) => warn!("stats for {container_id}: {e}"),
                }
            }
        }
    }
}

/// Parameters for a sandboxed remote exec.
pub struct ExecSpec {
    /// Docker image to run the command in.
    pub image: String,
    /// Command and arguments.
    pub cmd: Vec<String>,
    /// Working directory. Interpreted relative to `~/` (e.g., `~/code/ce` or `code/ce`).
    /// Defaults to the workspace root (`~/`) when None.
    pub cwd: Option<String>,
}

/// Run a command in a temporary sandboxed container and return (stdout, stderr, exit_code).
///
/// The caller's home directory is bind-mounted read-write at `/workspace` inside the
/// container, giving the command access to synced files without touching the host
/// process or the rest of the filesystem.
///
/// Isolation: gVisor when available, network=none, 1 CPU / 512 MB limits, auto-removed.
pub async fn exec_in_container(
    docker: &Docker,
    spec: &ExecSpec,
    home_dir: &Path,
) -> Result<(String, String, i64)> {
    // Pull image if not cached.
    let mut pull = docker.create_image(
        Some(CreateImageOptions { from_image: spec.image.as_str(), ..Default::default() }),
        None,
        None,
    );
    while let Some(ev) = pull.next().await {
        ev?;
    }

    // Resolve cwd inside the container. Everything maps into /workspace.
    let working_dir = resolve_container_cwd(spec.cwd.as_deref());

    let home_str = home_dir.to_string_lossy().to_string();
    let runtime = detect_runtime(docker).await;

    let config = bollard::container::Config {
        image: Some(spec.image.clone()),
        cmd: if spec.cmd.is_empty() { None } else { Some(spec.cmd.clone()) },
        working_dir: Some(working_dir),
        host_config: Some(HostConfig {
            runtime,
            // Home directory bind-mounted at /workspace — synced files are accessible.
            binds: Some(vec![format!("{home_str}:/workspace:rw")]),
            network_mode: Some("none".to_string()),
            nano_cpus: Some(1_000_000_000),
            memory: Some(512 * 1024 * 1024),
            auto_remove: Some(false),
            ..Default::default()
        }),
        ..Default::default()
    };

    let opts = CreateContainerOptions::<String> { name: String::new(), platform: None };
    let container = docker.create_container(Some(opts), config).await?;
    let cid = container.id;

    docker.start_container(&cid, None::<StartContainerOptions<String>>).await?;

    let exit_code = wait_for_exit_impl(docker, &cid).await.unwrap_or(-1);

    // Collect stdout/stderr after the container exits.
    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut log_stream = docker.logs(
        &cid,
        Some(LogsOptions::<String> { stdout: true, stderr: true, ..Default::default() }),
    );
    while let Some(chunk) = log_stream.next().await {
        match chunk? {
            LogOutput::StdOut { message } => stdout.push_str(&String::from_utf8_lossy(&message)),
            LogOutput::StdErr { message } => stderr.push_str(&String::from_utf8_lossy(&message)),
            _ => {}
        }
    }

    let _ = docker
        .remove_container(&cid, Some(RemoveContainerOptions { force: true, ..Default::default() }))
        .await;

    Ok((stdout, stderr, exit_code))
}

/// Map a caller-supplied cwd into a path inside /workspace.
/// Handles `~/foo`, `foo` (relative), and `/absolute` paths.
fn resolve_container_cwd(cwd: Option<&str>) -> String {
    match cwd {
        None => "/workspace".into(),
        Some(c) if c == "~" || c == "~/" => "/workspace".into(),
        Some(c) if c.starts_with("~/") => format!("/workspace/{}", &c[2..]),
        Some(c) if c.starts_with('/') => {
            // Absolute host path — strip a leading /workspace prefix if given,
            // otherwise map directly (best-effort; container may not find it).
            if let Some(rest) = c.strip_prefix("/workspace") {
                format!("/workspace{rest}")
            } else {
                c.to_string()
            }
        }
        Some(c) => format!("/workspace/{c}"),
    }
}

/// Probe Docker info for the "runsc" (gVisor) runtime entry.
/// Always logs a warning when gVisor is absent so operators are clearly notified.
async fn detect_runtime(docker: &Docker) -> Option<String> {
    let has_runsc = docker
        .info()
        .await
        .ok()
        .and_then(|i| i.runtimes)
        .map(|r| r.contains_key("runsc"))
        .unwrap_or(false);

    if has_runsc {
        Some("runsc".to_string())
    } else {
        warn!("gVisor not available, falling back to runc — NOT recommended for production");
        None
    }
}

async fn wait_for_exit_impl(docker: &Docker, container_id: &str) -> Result<i64> {
    let mut stream =
        docker.wait_container(container_id, None::<WaitContainerOptions<String>>);
    match stream.next().await {
        Some(Ok(resp)) => return Ok(resp.status_code),
        Some(Err(_)) | None => {}
    }
    // Container may have already exited before wait_container was called.
    // Fall back to inspect to get the exit code.
    let info = docker.inspect_container(container_id, None).await?;
    let code = info
        .state
        .and_then(|s| s.exit_code)
        .unwrap_or(-1);
    Ok(code)
}

/// Returns (container_id, payer_node_id) for running CE-managed containers.
async fn list_ce_containers(docker: &Docker) -> Result<Vec<(String, NodeId)>> {
    let mut filters = HashMap::new();
    filters.insert("status", vec!["running"]);

    let containers = docker
        .list_containers(Some(ListContainersOptions {
            all: false,
            filters,
            ..Default::default()
        }))
        .await?;

    let mut result = Vec::new();
    for c in containers {
        let id = c.id.unwrap_or_default();
        let payer = c.labels.as_ref().and_then(|l| l.get("ce.payer")).and_then(|s| {
            let bytes = hex::decode(s).ok()?;
            let arr: [u8; 32] = bytes.try_into().ok()?;
            Some(arr)
        });
        if let Some(payer) = payer {
            result.push((id, payer));
        }
    }
    Ok(result)
}

async fn snapshot_stats(docker: &Docker, container_id: &str) -> Result<(u64, u64)> {
    let mut stream = docker.stats(
        container_id,
        Some(StatsOptions { stream: false, one_shot: true }),
    );
    let stats =
        stream.next().await.ok_or_else(|| anyhow!("no stats for {container_id}"))??;

    let cpu_delta = stats
        .cpu_stats
        .cpu_usage
        .total_usage
        .saturating_sub(stats.precpu_stats.cpu_usage.total_usage);
    let cpu_ms = cpu_delta / 1_000_000;

    let mem_mb = stats.memory_stats.usage.unwrap_or(0) / (1024 * 1024);

    Ok((cpu_ms, mem_mb))
}

fn compute_cost(cpu_ms: u64, mem_mb: u64, interval_secs: u64) -> u64 {
    let cpu_credits = (cpu_ms / 1000) * CREDITS_PER_CPU_SECOND;
    let mem_gb_secs = (mem_mb * interval_secs) / 1024;
    let mem_credits = mem_gb_secs * CREDITS_PER_GB_SECOND;
    cpu_credits + mem_credits
}

/// `Runtime` backend that runs workloads as sandboxed Docker containers — the Docker impl of the
/// `ce-runtime` seam. WASM (`ce-wasm`) plugs in as a sibling impl; `ce-node` dispatches by tag.
pub struct DockerRuntime {
    manager: ContainerManager,
    host_node_id: NodeId,
}

impl DockerRuntime {
    pub async fn new(host_node_id: NodeId) -> Result<Self> {
        Ok(Self { manager: ContainerManager::new(host_node_id).await?, host_node_id })
    }
}

#[async_trait::async_trait]
impl ce_runtime::Runtime for DockerRuntime {
    fn tag(&self) -> &'static str {
        "docker"
    }

    async fn launch(
        &self,
        workload: &ce_runtime::Workload,
        limits: &ce_runtime::Limits,
        job_id: [u8; 32],
    ) -> Result<(ce_runtime::Handle, Option<String>)> {
        let (image, cmd, env) = match workload {
            ce_runtime::Workload::Docker { image, cmd, env, .. } => (image.clone(), cmd.clone(), env.clone()),
            other => {
                return Err(anyhow!("docker runtime cannot run a '{}' workload", other.required_tag()));
            }
        };
        // `payer` here only populates the container's informational ce.payer label; the
        // authoritative payer for billing lives in ce-node's JobRecord (heartbeat loop).
        let spec = JobSpec {
            job_id,
            image,
            cmd,
            env,
            cpu_cores: limits.cpu_cores,
            mem_mb: limits.mem_mb,
            payer: self.host_node_id,
        };
        // Containers are detached and stream their own I/O — no captured output artifact.
        Ok((ce_runtime::Handle(self.manager.launch_job(&spec).await?), None))
    }

    async fn stop(&self, handle: &ce_runtime::Handle) -> Result<()> {
        self.manager.stop_job(&handle.0).await
    }
}
