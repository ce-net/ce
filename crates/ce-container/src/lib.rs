use anyhow::{anyhow, Result};
use bollard::container::{ListContainersOptions, StatsOptions};
use bollard::Docker;
use ce_chain::TxKind;
use ce_identity::NodeId;
use futures::StreamExt;
use std::collections::HashMap;
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

pub struct ContainerManager {
    docker: Docker,
    host_node_id: NodeId,
}

impl ContainerManager {
    pub fn new(host_node_id: NodeId) -> Result<Self> {
        let docker = Docker::connect_with_socket_defaults()?;
        Ok(Self { docker, host_node_id })
    }

    /// Runs the metering loop indefinitely. Call this in a spawned task.
    pub async fn run(self, reading_tx: mpsc::Sender<MeterReading>) -> Result<()> {
        let mut interval = tokio::time::interval(Duration::from_secs(METERING_INTERVAL_SECS));
        loop {
            interval.tick().await;
            let containers = match list_ce_containers(&self.docker).await {
                Ok(c) => c,
                Err(e) => { warn!("list containers: {e}"); continue; }
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
    let stats = stream.next().await.ok_or_else(|| anyhow!("no stats for {container_id}"))??;

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

pub fn meter_reading_to_tx_kind(r: &MeterReading) -> TxKind {
    TxKind::Meter {
        job_id: r.job_id.clone(),
        payer: r.payer,
        host: r.host,
        cpu_ms: r.cpu_ms,
        mem_mb: r.mem_mb,
        cost: r.cost,
    }
}
