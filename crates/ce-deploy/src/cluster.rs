use anyhow::{anyhow, Result};
use crate::{hetzner::{HetznerClient, Server}, ssh};
use tokio::time::{sleep, Duration};
use tracing::info;

const P2P_PORT: u16 = 4001;
const API_PORT: u16 = 8080;

/// A running CE node on a remote server.
#[derive(Debug)]
pub struct NodeHandle {
    pub server: Server,
    pub node_id: String,
    pub p2p_port: u16,
    pub api_port: u16,
}

impl NodeHandle {
    pub fn ip(&self) -> &str {
        self.server.ip()
    }

    pub fn api_url(&self) -> String {
        format!("http://{}:{}", self.ip(), self.api_port)
    }

    /// Full libp2p multiaddr including peer ID — use as bootstrap address.
    pub fn multiaddr(&self) -> String {
        format!("/ip4/{}/tcp/{}/p2p/{}", self.ip(), self.p2p_port, self.node_id)
    }
}

/// A provisioned CE cluster on Hetzner.
pub struct Cluster {
    pub nodes: Vec<NodeHandle>,
    hetzner: HetznerClient,
    #[allow(dead_code)]
    ssh_key_path: String,
}

impl Cluster {
    /// Provision `n` servers, deploy the CE binary, and start all nodes.
    /// The first node is the genesis node; all others bootstrap from it.
    pub async fn provision(
        n: usize,
        hetzner_token: impl Into<String>,
        ssh_key_name: impl Into<String>,
        ssh_key_path: impl Into<String>,
        ce_binary: impl Into<String>,
    ) -> Result<Self> {
        let hetzner = HetznerClient::new(hetzner_token, ssh_key_name);
        let ssh_key_path: String = ssh_key_path.into();
        let ce_binary: String = ce_binary.into();

        // Use a short timestamp suffix so names are unique across test runs.
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() % 100_000; // 5 digits, fits in Hetzner's 63-char limit

        // Create all servers concurrently.
        info!("provisioning {n} Hetzner servers");
        let mut create_tasks = Vec::new();
        for i in 0..n {
            let h = hetzner.clone();
            create_tasks.push(tokio::spawn(async move {
                h.create_server(&format!("ce-{ts}-{i}")).await
            }));
        }

        let mut servers: Vec<Server> = Vec::new();
        for task in create_tasks {
            servers.push(task.await??);
        }

        // Wait for all servers to become reachable concurrently.
        info!("waiting for all servers to be ready");
        let mut wait_tasks = Vec::new();
        for server in &servers {
            let h = hetzner.clone();
            let key = ssh_key_path.clone();
            let id = server.id;
            wait_tasks.push(tokio::spawn(async move {
                h.wait_until_running(id, &key).await
            }));
        }
        let mut ready_servers: Vec<Server> = Vec::new();
        for task in wait_tasks {
            ready_servers.push(task.await??);
        }

        // Provision system packages and deploy binary to all servers concurrently.
        info!("deploying CE binary");
        let mut deploy_tasks = Vec::new();
        for server in &ready_servers {
            let ip = server.ip().to_string();
            let key = ssh_key_path.clone();
            let bin = ce_binary.clone();
            deploy_tasks.push(tokio::spawn(async move {
                tokio::task::spawn_blocking(move || {
                    ssh::provision(&ip, &key)?;
                    ssh::deploy_binary(&ip, &key, &bin)
                })
                .await?
            }));
        }
        for task in deploy_tasks {
            task.await??;
        }

        // Start node 0 first (no bootstrap), then all others from node 0.
        info!("starting CE nodes");
        let mut nodes: Vec<NodeHandle> = Vec::new();

        let first = &ready_servers[0];
        let key = ssh_key_path.clone();
        let ip0 = first.ip().to_string();
        let node_id_0 = tokio::task::spawn_blocking(move || {
            ssh::start_node(&ip0, &key, P2P_PORT, API_PORT, None)
        })
        .await??;

        nodes.push(NodeHandle {
            server: first.clone(),
            node_id: node_id_0,
            p2p_port: P2P_PORT,
            api_port: API_PORT,
        });

        let bootstrap = nodes[0].multiaddr();
        for server in ready_servers.iter().skip(1) {
            let ip = server.ip().to_string();
            let key = ssh_key_path.clone();
            let bs = bootstrap.clone();
            let node_id = tokio::task::spawn_blocking(move || {
                ssh::start_node(&ip, &key, P2P_PORT, API_PORT, Some(&bs))
            })
            .await??;
            nodes.push(NodeHandle {
                server: server.clone(),
                node_id,
                p2p_port: P2P_PORT,
                api_port: API_PORT,
            });
        }

        info!("cluster of {} nodes ready", nodes.len());
        Ok(Self { nodes, hetzner, ssh_key_path })
    }

    /// Wait until all nodes have reached at least `min_height` on their chains.
    pub async fn wait_for_height(&self, min_height: u64, timeout_secs: u64) -> Result<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
        let client = reqwest::Client::new();

        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(anyhow!("timeout waiting for all nodes to reach height {min_height}"));
            }
            sleep(Duration::from_secs(3)).await;

            let mut all_ready = true;
            for node in &self.nodes {
                match get_height(&client, &node.api_url()).await {
                    Ok(h) if h >= min_height => {
                        info!("node {} at height {h}", node.ip());
                    }
                    Ok(h) => {
                        info!("node {} at height {h}, waiting for {min_height}", node.ip());
                        all_ready = false;
                    }
                    Err(e) => {
                        info!("node {} not responding: {e}", node.ip());
                        all_ready = false;
                    }
                }
            }
            if all_ready {
                return Ok(());
            }
        }
    }

    /// Assert all nodes agree on chain height (within `tolerance` blocks of each other).
    pub async fn assert_consensus(&self, tolerance: u64) -> Result<()> {
        let client = reqwest::Client::new();
        let mut heights = Vec::new();
        for node in &self.nodes {
            heights.push(get_height(&client, &node.api_url()).await?);
        }
        let min = *heights.iter().min().unwrap();
        let max = *heights.iter().max().unwrap();
        if max - min > tolerance {
            return Err(anyhow!(
                "nodes out of consensus: heights={heights:?}, spread={}", max - min
            ));
        }
        info!("consensus ok: heights={heights:?}");
        Ok(())
    }

    /// Tear down all servers. Best-effort: logs errors but does not fail.
    pub async fn destroy(&self) {
        for node in &self.nodes {
            let id = node.server.id;
            match self.hetzner.delete_server(id).await {
                Ok(()) => info!("destroyed server {id}"),
                Err(e) => tracing::error!("failed to destroy server {id}: {e}"),
            }
        }
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

async fn get_height(client: &reqwest::Client, api_url: &str) -> Result<u64> {
    #[derive(serde::Deserialize)]
    struct Status { height: u64 }
    let status: Status = client
        .get(format!("{api_url}/status"))
        .send()
        .await?
        .json()
        .await?;
    Ok(status.height)
}
