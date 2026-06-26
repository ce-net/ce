//! ce-hub-backed [`Registry`]: fetch app manifests over HTTP.
//!
//! Manifests live in ce-hub's app store at `GET /apps/<name>/ceapp.toml` (the same
//! file store that already serves app assets, `ce-hub/src/main.rs`). This is the
//! M0/M1 single-version registry; a multi-version solver replaces the lookup once
//! ce-hub records version history. Discovery falls back gracefully when the hub is
//! unreachable so `ce app info` on an already-installed app still works offline.

use crate::manifest::AppManifest;
use crate::resolver::Registry;
use anyhow::{Context, Result, anyhow};

/// HTTP client for the ce-hub app registry.
#[derive(Debug, Clone)]
pub struct HubRegistry {
    base: String,
    client: reqwest::Client,
}

impl HubRegistry {
    /// `base` is the ce-hub origin, e.g. `https://ce-net.com` or `http://127.0.0.1:8970`.
    pub fn new(base: impl Into<String>) -> Self {
        HubRegistry {
            base: base.into().trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
        }
    }

    fn manifest_url(&self, name: &str) -> String {
        format!("{}/apps/{}/ceapp.toml", self.base, name)
    }

    /// Fetch and parse a manifest, with a clear error if the app or its manifest
    /// is missing from the hub.
    pub async fn fetch(&self, name: &str) -> Result<AppManifest> {
        let url = self.manifest_url(name);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("requesting manifest from {url}"))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(anyhow!(
                "app '{name}' not found in registry (no ceapp.toml at {url})"
            ));
        }
        let resp = resp
            .error_for_status()
            .with_context(|| format!("registry returned an error for {url}"))?;
        let body = resp.text().await.context("reading manifest body")?;
        AppManifest::parse(&body).with_context(|| format!("parsing manifest for '{name}'"))
    }
}

impl Registry for HubRegistry {
    async fn manifest(&self, name: &str) -> Result<AppManifest> {
        self.fetch(name).await
    }
}
