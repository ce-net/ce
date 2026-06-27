//! `ceapp.toml` — the one manifest that describes how to install, run, sandbox,
//! and supervise any app or system through `ce`.
//!
//! A manifest is platform-agnostic at the *command* level: the same file installs
//! the right thing on every host. The `runtime` field selects how, in order of
//! universality:
//!
//! - [`Runtime::Oci`]    — any legacy app/system as an OCI image (the default for
//!   non-CE software; portable by construction; gVisor-sandboxed).
//! - [`Runtime::Native`] — a prebuilt host binary, resolved per (os, arch).
//! - [`Runtime::Wasm`]   — one `.wasm` module for all platforms (optional tier).
//! - [`Runtime::Recipe`] — build-from-source fallback, promoted to a cached artifact.
//!
//! One signed manifest is what lets the donated hardware pool stay coherent: the same
//! `ceapp.toml` is designed to install the right thing on a Mac laptop, an x86 relay,
//! or an ARM phone, so across a fleet of millions of mismatched machines an app is
//! described once and runs everywhere. The tiered runtimes are the bridge that turns
//! that diversity into a single, uniformly usable compute substrate.

use anyhow::{Result, bail};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A parsed, validated `ceapp.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppManifest {
    pub app: AppMeta,
    #[serde(default)]
    pub native: Option<NativeArtifact>,
    #[serde(default)]
    pub oci: Option<OciSpec>,
    #[serde(default)]
    pub wasm: Option<WasmArtifact>,
    #[serde(default)]
    pub recipe: Option<RecipeSpec>,
    #[serde(default)]
    pub deps: Deps,
    #[serde(default)]
    pub sandbox: Sandbox,
    #[serde(default)]
    pub daemon: Option<Daemon>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppMeta {
    pub name: String,
    pub version: Version,
    #[serde(default)]
    pub summary: String,
    pub runtime: Runtime,
    /// Capability strings this app PROVIDES to its host node while running, advertised in the node's atlas
    /// tags so placement can route apps that `requires` them here (e.g. ce-serve provides `http-ingress`).
    /// Opaque, community-defined vocabulary — `ce` only carries + matches the strings, hardcodes nothing.
    #[serde(default)]
    pub provides: Vec<String>,
    /// CE node id of the publisher; the manifest is signed by this key.
    #[serde(default)]
    pub publisher: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Runtime {
    /// Any legacy app/system as an OCI image — the universal substrate.
    Oci,
    /// Prebuilt host binary, resolved per (os, arch).
    Native,
    /// One portable, strongly-sandboxed `.wasm` module.
    Wasm,
    /// Build-from-source derivation, cached as an artifact after first build.
    Recipe,
}

/// `[native]` — content-addressed binaries keyed by `host_target()`.
///
/// `bin` (a scalar) is declared before `artifacts` (a table) so TOML serialization
/// emits the value before the table, satisfying TOML's value-before-table rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeArtifact {
    /// Entrypoint executable name inside the fetched artifact.
    pub bin: String,
    /// `"<os>-<arch>"` -> content digest (e.g. `"blake3:..."`).
    #[serde(default)]
    pub artifacts: BTreeMap<String, String>,
}

/// `[oci]` — any legacy app/system as a pinned image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciSpec {
    pub image: String,
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default)]
    pub volumes: Vec<String>,
}

/// `[wasm]` — one module for every platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmArtifact {
    pub artifact: String,
    #[serde(default)]
    pub wasi: bool,
}

/// `[recipe]` — build-from-source fallback for software with no image/binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipeSpec {
    pub source: String,
    #[serde(default)]
    pub build: Vec<String>,
    /// Where to build (`relay`, `desktop`, `host`); cached afterwards.
    #[serde(default)]
    pub target: String,
}

/// `[deps]` — the dependency graph, resolved across all tiers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Deps {
    /// Other ce apps, as `"name <semver-req>"` (e.g. `"ce-storage >= 0.2"`).
    #[serde(default)]
    pub apps: Vec<String>,
    /// Systems that must be running for this app (e.g. `"postgres"`).
    #[serde(default)]
    pub services: Vec<String>,
    /// ce-cap abilities the app requires (e.g. `exec`, `sync`) — what must be GRANTED to run it.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Node capability strings this app REQUIRES for PLACEMENT — matched against a node's atlas tags
    /// (node-intrinsic like `gpu`/`wasm`/`docker`/os/arch, UNION app-provided like `http-ingress`). An
    /// install with these only lands on nodes that advertise all of them. Opaque strings; nothing hardcoded.
    #[serde(default)]
    pub requires: Vec<String>,
    /// Host features; value `"optional"` means degrade rather than fail.
    #[serde(default)]
    pub system: BTreeMap<String, String>,
}

/// `[sandbox]` — the isolation + scoping profile applied on every run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sandbox {
    #[serde(default)]
    pub tier: SandboxTier,
    /// Network policy: `mesh-only` | `loopback` | `egress:<allowlist>` | `none`.
    #[serde(default = "default_net")]
    pub net: String,
    /// Explicit filesystem mounts; default is the app's private dir only.
    #[serde(default)]
    pub fs: Vec<String>,
    /// `scoped` mints an attenuated per-run capability; `inherit` reuses ce's.
    #[serde(default = "default_capability")]
    pub capability: String,
}

impl Default for Sandbox {
    fn default() -> Self {
        Sandbox {
            tier: SandboxTier::default(),
            net: default_net(),
            fs: Vec::new(),
            capability: default_capability(),
        }
    }
}

fn default_net() -> String {
    "mesh-only".to_string()
}
fn default_capability() -> String {
    "scoped".to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SandboxTier {
    #[default]
    Gvisor,
    Runc,
    Wasm,
    /// No isolation — must be explicit and is audited; never a default.
    None,
}

/// `[daemon]` — present iff the app is a long-running system, not a one-shot CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Daemon {
    #[serde(default)]
    pub enabled: bool,
    /// Args the supervisor passes when launching the daemon (e.g. `["agent"]` so a
    /// multi-command native binary starts in its daemon mode rather than its CLI mode).
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_restart")]
    pub restart: String,
    /// Liveness probe the single ce supervisor polls (URL or command).
    #[serde(default)]
    pub health: Option<String>,
}

fn default_restart() -> String {
    "on-failure".to_string()
}

impl AppManifest {
    /// Parse and validate a `ceapp.toml`. Validation enforces that the section
    /// matching `runtime` is present, so install can't reach a dead artifact.
    pub fn parse(toml_str: &str) -> Result<Self> {
        let m: AppManifest = toml::from_str(toml_str)?;
        m.validate()?;
        Ok(m)
    }

    /// Serialize back to canonical TOML (used by `ce app publish`).
    pub fn to_toml(&self) -> Result<String> {
        Ok(toml::to_string_pretty(self)?)
    }

    fn validate(&self) -> Result<()> {
        if self.app.name.trim().is_empty() {
            bail!("manifest [app].name is empty");
        }
        match self.app.runtime {
            Runtime::Native => {
                let Some(n) = &self.native else {
                    bail!("runtime = \"native\" but no [native] section");
                };
                if n.bin.trim().is_empty() {
                    bail!("[native].bin is empty");
                }
                // NB: `artifacts` may be empty here. A local dev manifest (`ce app install ./app`) has the
                // binary on disk and needs no published digests; `ce app publish` fills `artifacts`, and
                // `materialize` enforces the per-target digest when installing from a registry.
            }
            Runtime::Oci => {
                let Some(o) = &self.oci else {
                    bail!("runtime = \"oci\" but no [oci] section");
                };
                if o.image.trim().is_empty() {
                    bail!("[oci].image is empty");
                }
            }
            Runtime::Wasm => {
                let Some(w) = &self.wasm else {
                    bail!("runtime = \"wasm\" but no [wasm] section");
                };
                if w.artifact.trim().is_empty() {
                    bail!("[wasm].artifact is empty");
                }
            }
            Runtime::Recipe => {
                let Some(r) = &self.recipe else {
                    bail!("runtime = \"recipe\" but no [recipe] section");
                };
                if r.source.trim().is_empty() {
                    bail!("[recipe].source is empty");
                }
            }
        }
        Ok(())
    }

    /// Resolve the content digest of the native artifact for a host target,
    /// e.g. `host_target()` -> `"blake3:..."`. `None` if this manifest isn't
    /// native or doesn't ship that platform.
    pub fn native_digest(&self, target: &str) -> Option<&str> {
        self.native
            .as_ref()
            .and_then(|n| n.artifacts.get(target))
            .map(String::as_str)
    }

    /// Whether this manifest describes a supervised long-running system.
    pub fn is_daemon(&self) -> bool {
        self.daemon.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NATIVE: &str = r#"
        [app]
        name = "rdev"
        version = "0.4.1"
        summary = "Remote exec + sync"
        runtime = "native"
        publisher = "c0be11e0ce0a"

        [native]
        bin = "rdev"
        artifacts."darwin-arm64" = "blake3:aaaa"
        artifacts."linux-amd64"  = "blake3:bbbb"

        [deps]
        apps = ["ce-storage >= 0.2"]
        capabilities = ["exec", "sync"]
    "#;

    const OCI: &str = r#"
        [app]
        name = "postgres"
        version = "16.0.0"
        runtime = "oci"

        [oci]
        image = "docker.io/library/postgres:16"
        ports = ["5432"]

        [daemon]
        enabled = false
        health = "http://127.0.0.1:5432"
    "#;

    #[test]
    fn parses_native_and_resolves_digest() {
        let m = AppManifest::parse(NATIVE).unwrap();
        assert_eq!(m.app.name, "rdev");
        assert_eq!(m.app.runtime, Runtime::Native);
        assert_eq!(m.native_digest("darwin-arm64"), Some("blake3:aaaa"));
        assert_eq!(m.native_digest("windows-amd64"), None);
        assert_eq!(m.deps.apps, vec!["ce-storage >= 0.2"]);
        // Defaulted sandbox.
        assert_eq!(m.sandbox.tier, SandboxTier::Gvisor);
        assert_eq!(m.sandbox.net, "mesh-only");
        assert!(!m.is_daemon());
    }

    #[test]
    fn parses_oci_daemon() {
        let m = AppManifest::parse(OCI).unwrap();
        assert_eq!(m.app.runtime, Runtime::Oci);
        assert!(m.is_daemon());
        assert_eq!(m.oci.as_ref().unwrap().image, "docker.io/library/postgres:16");
    }

    #[test]
    fn rejects_runtime_without_section() {
        let bad = r#"
            [app]
            name = "x"
            version = "1.0.0"
            runtime = "native"
        "#;
        assert!(AppManifest::parse(bad).is_err());
    }

    #[test]
    fn roundtrips_through_toml() {
        let m = AppManifest::parse(OCI).unwrap();
        let s = m.to_toml().unwrap();
        let m2 = AppManifest::parse(&s).unwrap();
        assert_eq!(m2.app.name, m.app.name);
        assert_eq!(m2.app.version, m.app.version);
    }
}
