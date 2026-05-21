use anyhow::{anyhow, Result};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use tokio::time::{sleep, Duration};
use tracing::{info, warn};

const API_BASE: &str = "https://api.hetzner.cloud/v1";
const POLL_INTERVAL_MS: u64 = 3_000;
const READY_TIMEOUT_SECS: u64 = 120;

#[derive(Debug, Clone, Deserialize)]
pub struct Server {
    pub id: u64,
    pub name: String,
    pub status: String,
    pub public_net: PublicNet,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PublicNet {
    pub ipv4: Ipv4Net,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Ipv4Net {
    pub ip: String,
}

impl Server {
    pub fn ip(&self) -> &str {
        &self.public_net.ipv4.ip
    }
}

#[derive(Debug, Serialize)]
struct CreateServerRequest<'a> {
    name: &'a str,
    server_type: &'a str,
    image: &'a str,
    ssh_keys: Vec<&'a str>,
    location: &'a str,
}

#[derive(Debug, Deserialize)]
struct CreateServerResponse {
    server: Server,
}

#[derive(Debug, Deserialize)]
struct GetServerResponse {
    server: Server,
}

#[derive(Debug, Deserialize)]
struct ListServersResponse {
    servers: Vec<Server>,
}

#[derive(Debug, Clone)]
pub struct HetznerClient {
    token: String,
    http: reqwest::Client,
    /// Hetzner SSH key name (must already exist in your Hetzner project).
    pub ssh_key_name: String,
}

impl HetznerClient {
    pub fn new(token: impl Into<String>, ssh_key_name: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            ssh_key_name: ssh_key_name.into(),
            http: reqwest::Client::new(),
        }
    }

    fn auth(&self) -> String {
        format!("Bearer {}", self.token)
    }

    /// Create a cx23 (2 vCPU, 4GB RAM) server in Nuremberg with Ubuntu 22.04.
    /// Retries up to 10 times on IP/server limit errors to absorb the delay
    /// after a previous server is deleted.
    pub async fn create_server(&self, name: &str) -> Result<Server> {
        let body = CreateServerRequest {
            name,
            server_type: "cx23",
            image: "ubuntu-22.04",
            ssh_keys: vec![&self.ssh_key_name],
            location: "nbg1",
        };

        for attempt in 0..10u32 {
            let resp = self.http
                .post(format!("{API_BASE}/servers"))
                .header(AUTHORIZATION, self.auth())
                .header(CONTENT_TYPE, "application/json")
                .json(&body)
                .send()
                .await?;

            if resp.status().is_success() {
                let data: CreateServerResponse = resp.json().await?;
                info!("created server {} (id={}) ip={}", data.server.name, data.server.id, data.server.ip());
                return Ok(data.server);
            }

            let text = resp.text().await.unwrap_or_default();
            // Retry on resource limit exceeded — IPs take a few seconds to be released after deletion.
            if text.contains("resource_limit_exceeded") && attempt < 9 {
                let delay = 5 + attempt * 3;
                warn!("resource limit, retrying in {delay}s (attempt {}/9): {text}", attempt + 1);
                sleep(Duration::from_secs(delay as u64)).await;
                continue;
            }
            return Err(anyhow!("create server failed: {text}"));
        }

        Err(anyhow!("create server failed after 10 attempts"))
    }

    pub async fn get_server(&self, id: u64) -> Result<Server> {
        let resp = self.http
            .get(format!("{API_BASE}/servers/{id}"))
            .header(AUTHORIZATION, self.auth())
            .send()
            .await?;
        let data: GetServerResponse = resp.json().await?;
        Ok(data.server)
    }

    /// Poll until the server status is "running" and SSH is accepting connections.
    pub async fn wait_until_running(&self, id: u64, ssh_key_path: &str) -> Result<Server> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(READY_TIMEOUT_SECS);

        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(anyhow!("timeout waiting for server {id} to become ready"));
            }
            sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;

            let server = self.get_server(id).await?;
            if server.status != "running" {
                info!("server {} status: {}", id, server.status);
                continue;
            }

            // Probe SSH — success means the server is truly ready.
            match crate::ssh::probe(server.ip(), ssh_key_path).await {
                Ok(()) => {
                    info!("server {} is ready at {}", id, server.ip());
                    return Ok(server);
                }
                Err(e) => {
                    warn!("server {} SSH not yet ready: {e}", id);
                }
            }
        }
    }

    pub async fn delete_server(&self, id: u64) -> Result<()> {
        let resp = self.http
            .delete(format!("{API_BASE}/servers/{id}"))
            .header(AUTHORIZATION, self.auth())
            .send()
            .await?;
        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("delete server {id} failed: {text}"));
        }
        info!("deleted server {id}");
        Ok(())
    }

    pub async fn list_servers(&self) -> Result<Vec<Server>> {
        let resp = self.http
            .get(format!("{API_BASE}/servers"))
            .header(AUTHORIZATION, self.auth())
            .send()
            .await?;
        let data: ListServersResponse = resp.json().await?;
        Ok(data.servers)
    }
}
