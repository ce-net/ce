//! ce-hub-backed [`Registry`]: fetch app manifests over HTTP.
//!
//! Manifests live in ce-hub's app store at `GET /apps/<name>/ceapp.toml` (the same
//! file store that already serves app assets, `ce-hub/src/main.rs`). This is the
//! M0/M1 single-version registry; a multi-version solver replaces the lookup once
//! ce-hub records version history. Discovery falls back gracefully when the hub is
//! unreachable so `ce app info` on an already-installed app still works offline.
//!
//! This is the shared front door through which the whole fabric discovers and trusts
//! software: the detached signature sidecar is designed so that any of millions of
//! nodes can verify a manifest's publisher before executing its code, and the offline
//! fallback keeps already-installed apps usable under partition — so the network's app
//! catalog stays both globally consistent and resilient to losing the hub.

use crate::manifest::AppManifest;
use crate::resolver::Registry;
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

/// A detached signature over a manifest's exact bytes, served alongside it at
/// `/apps/<name>/ceapp.sig`. The publisher is a CE node id; the signature is the
/// node's Ed25519 signature over the raw `ceapp.toml` bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureSidecar {
    /// Publisher CE node id (64 hex).
    pub publisher: String,
    /// Ed25519 signature over the manifest bytes (128 hex = 64 bytes).
    pub signature: String,
}

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

    /// Fetch the EXACT manifest bytes (not parsed) — required for signature
    /// verification, which is over the published bytes.
    pub async fn fetch_raw(&self, name: &str) -> Result<String> {
        let url = self.manifest_url(name);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("requesting manifest bytes from {url}"))?
            .error_for_status()
            .with_context(|| format!("registry error for {url}"))?;
        resp.text().await.context("reading manifest bytes")
    }

    /// Fetch the detached signature sidecar, or `None` if the app is unsigned.
    pub async fn fetch_signature(&self, name: &str) -> Result<Option<SignatureSidecar>> {
        let url = format!("{}/apps/{}/ceapp.sig", self.base, name);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("requesting signature from {url}"))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let sig: SignatureSidecar = resp
            .error_for_status()
            .with_context(|| format!("registry error for {url}"))?
            .json()
            .await
            .context("decoding signature sidecar")?;
        Ok(Some(sig))
    }
}

impl Registry for HubRegistry {
    async fn manifest(&self, name: &str) -> Result<AppManifest> {
        self.fetch(name).await
    }
}
