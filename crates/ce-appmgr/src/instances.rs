//! Global instance tracking via ce-hub.
//!
//! `ce-appmgr` is the per-node control-plane agent; ce-hub is the global registry.
//! Every running app instance — local or placed on a remote node — is registered
//! and heartbeated here, so `ce app ps` and the app-facing API can answer "what is
//! running, where, and is it healthy" across the whole mesh.
//!
//! This targets ce-hub's planned app-instance facet (`/app-instances`), which
//! extends ce-hub's existing live-node/instance tracker. The agent registers on
//! start, heartbeats on the supervisor's health interval, and deregisters on stop;
//! ce-hub expires instances whose heartbeat lapses.
//!
//! This is the live census of the fabric: designed so that, across millions of
//! churning devices, the network always has an up-to-date map of what is running and
//! where without any node holding global state. Heartbeat-and-expire keeps that map
//! self-healing as donors join and drop, and it is the substrate scheduling and
//! re-placement read to pack pooled compute onto healthy nodes.

use crate::manifest::Runtime;
use crate::placement::Placement;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Liveness of a tracked instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Health {
    Starting,
    Healthy,
    Unhealthy,
    Stopped,
}

/// One running (or recently-stopped) app instance in the global registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceRecord {
    /// Stable id: `<node_id>:<app>:<nonce>`. Unique across the mesh.
    pub id: String,
    pub app: String,
    pub version: String,
    /// CE node id this instance runs on.
    pub node_id: String,
    pub runtime: Runtime,
    /// How it was placed (for audit / re-placement).
    pub placement: Placement,
    pub health: Health,
    /// Unix seconds the instance started (stamped by the agent, not the script).
    pub started_unix: u64,
    /// Free-form metrics the app or supervisor reports (cpu, mem, rps...).
    #[serde(default)]
    pub metrics: serde_json::Value,
}

impl InstanceRecord {
    /// Build a stable instance id from its parts.
    pub fn make_id(node_id: &str, app: &str, nonce: u64) -> String {
        format!("{node_id}:{app}:{nonce}")
    }
}

/// Filter for querying the global registry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InstanceFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    /// Only instances at or above this health (e.g. `Healthy` to hide dead ones).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_health: Option<Health>,
}

/// ce-hub-backed global instance registry client.
#[derive(Debug, Clone)]
pub struct HubInstances {
    base: String,
    client: reqwest::Client,
}

impl HubInstances {
    /// `base` is the ce-hub origin (e.g. `https://ce-net.com`).
    pub fn new(base: impl Into<String>) -> Self {
        HubInstances {
            base: base.into().trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/app-instances{}", self.base, path)
    }

    /// Register (or replace) an instance. Idempotent on `rec.id`.
    pub async fn register(&self, rec: &InstanceRecord) -> Result<()> {
        let url = self.url("");
        self.client
            .put(&url)
            .json(rec)
            .send()
            .await
            .with_context(|| format!("registering instance at {url}"))?
            .error_for_status()
            .with_context(|| format!("ce-hub rejected instance registration for {}", rec.id))?;
        Ok(())
    }

    /// Heartbeat an instance: refresh health + metrics, reset the expiry timer.
    pub async fn heartbeat(&self, id: &str, health: Health, metrics: serde_json::Value) -> Result<()> {
        let url = self.url(&format!("/{id}/heartbeat"));
        let body = serde_json::json!({ "health": health, "metrics": metrics });
        self.client
            .post(&url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("heartbeating {id}"))?
            .error_for_status()
            .with_context(|| format!("ce-hub rejected heartbeat for {id}"))?;
        Ok(())
    }

    /// Deregister an instance (graceful stop). Idempotent.
    pub async fn deregister(&self, id: &str) -> Result<()> {
        let url = self.url(&format!("/{id}"));
        let resp = self
            .client
            .delete(&url)
            .send()
            .await
            .with_context(|| format!("deregistering {id}"))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        resp.error_for_status()
            .with_context(|| format!("ce-hub rejected deregister for {id}"))?;
        Ok(())
    }

    /// Query the global registry. `ce app ps` and the app-facing `/instances` call
    /// read through this (the latter scoped to what the caller may see).
    pub async fn list(&self, filter: &InstanceFilter) -> Result<Vec<InstanceRecord>> {
        let mut url = self.url("");
        let mut q: Vec<String> = Vec::new();
        if let Some(app) = &filter.app {
            q.push(format!("app={app}"));
        }
        if let Some(node) = &filter.node_id {
            q.push(format!("node={node}"));
        }
        if !q.is_empty() {
            url.push('?');
            url.push_str(&q.join("&"));
        }
        let recs: Vec<InstanceRecord> = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("listing instances at {url}"))?
            .error_for_status()
            .context("ce-hub returned an error listing instances")?
            .json()
            .await
            .context("decoding instance list")?;
        // min_health is applied client-side so the hub stays a dumb store.
        let recs = match filter.min_health {
            Some(Health::Healthy) => recs
                .into_iter()
                .filter(|r| matches!(r.health, Health::Healthy))
                .collect(),
            _ => recs,
        };
        Ok(recs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_id_is_stable() {
        let id = InstanceRecord::make_id("nodeAA", "postgres", 7);
        assert_eq!(id, "nodeAA:postgres:7");
    }

    #[test]
    fn filter_serializes_sparsely() {
        let f = InstanceFilter { app: Some("rdev".into()), ..Default::default() };
        let s = serde_json::to_string(&f).unwrap();
        assert!(s.contains("rdev"));
        assert!(!s.contains("node_id"), "None fields must be skipped: {s}");
    }
}
