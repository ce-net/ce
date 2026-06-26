//! Run planning: turn an installed app into a concrete execution plan per tier.
//!
//! This is the platform-agnostic *decision* of what to execute and how to sandbox
//! it; the actual execution (spawning a process, launching a gVisor container via
//! `ce-container`, instantiating a wasm module via `ce-wasm`) happens in the `ce`
//! binary, which owns those runtime deps. Keeping the plan here makes it unit-
//! testable without Docker or wasmtime.
//!
//! Isolating the sandbox decision in pure, testable code is a safety prerequisite for
//! the pool: donated devices run arbitrary published apps, so every host must derive
//! the same gVisor/WASI confinement and resource envelope from the manifest the same
//! way. Designed so that, replicated across millions of nodes, untrusted compute is
//! always fenced identically rather than by per-machine, hand-tuned configuration.

use crate::manifest::{Runtime, SandboxTier};
use crate::store::{InstalledApp, Store};
use anyhow::{Result, anyhow};
use std::path::PathBuf;

/// Default resource envelope for an oci one-shot/daemon when the manifest doesn't
/// pin one. Matches `ce-container`'s conservative exec defaults.
pub const DEFAULT_CPU_CORES: u32 = 1;
pub const DEFAULT_MEM_MB: u64 = 512;

/// A concrete, per-tier execution plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunPlan {
    /// Spawn a host process from the materialized native binary.
    Native { bin: PathBuf, args: Vec<String> },
    /// Run an oci image, sandboxed (gVisor when available).
    Oci {
        image: String,
        /// Command override; empty = the image's default entrypoint.
        cmd: Vec<String>,
        env: Vec<(String, String)>,
        cpu_cores: u32,
        mem_mb: u64,
        /// Prefer the gVisor (`runsc`) runtime.
        gvisor: bool,
        /// True for a long-running system (detach), false for a one-shot CLI.
        daemon: bool,
        net: String,
    },
    /// Execute a wasm module (WASI) via the wasm runtime.
    Wasm { module: PathBuf, args: Vec<String> },
    /// A recipe app — build/run is deferred to the relay build path.
    Recipe { source: String },
}

/// Compute the [`RunPlan`] for an installed app, given the user's pass-through args.
pub fn plan_run(store: &Store, app: &InstalledApp, args: Vec<String>) -> Result<RunPlan> {
    let m = &app.manifest;
    let vdir = store.version_dir(&m.app.name, &m.app.version.to_string());
    match m.app.runtime {
        Runtime::Native => {
            let bin = m
                .native
                .as_ref()
                .map(|n| n.bin.clone())
                .ok_or_else(|| anyhow!("native manifest missing [native].bin"))?;
            Ok(RunPlan::Native { bin: vdir.join(bin), args })
        }
        Runtime::Oci => {
            let image = m
                .oci
                .as_ref()
                .map(|o| o.image.clone())
                .ok_or_else(|| anyhow!("oci manifest missing [oci].image"))?;
            Ok(RunPlan::Oci {
                image,
                cmd: args,
                env: Vec::new(),
                cpu_cores: DEFAULT_CPU_CORES,
                mem_mb: DEFAULT_MEM_MB,
                gvisor: matches!(m.sandbox.tier, SandboxTier::Gvisor),
                daemon: m.is_daemon(),
                net: m.sandbox.net.clone(),
            })
        }
        Runtime::Wasm => Ok(RunPlan::Wasm {
            module: vdir.join(format!("{}.wasm", m.app.name)),
            args,
        }),
        Runtime::Recipe => Ok(RunPlan::Recipe {
            source: m.recipe.as_ref().map(|r| r.source.clone()).unwrap_or_default(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::AppManifest;
    use crate::store::{InstalledApp, Store};

    fn installed(toml: &str) -> InstalledApp {
        InstalledApp {
            manifest: AppManifest::parse(toml).unwrap(),
            target: "linux-amd64".into(),
            digest: None,
        }
    }

    #[test]
    fn native_plan_points_at_version_dir_bin() {
        let app = installed(
            r#"
            [app]
            name = "tool"
            version = "2.1.0"
            runtime = "native"
            [native]
            bin = "tool"
            artifacts."linux-amd64" = "sha256:aa"
            "#,
        );
        let store = Store::new("/data");
        let plan = plan_run(&store, &app, vec!["--help".into()]).unwrap();
        match plan {
            RunPlan::Native { bin, args } => {
                assert!(bin.ends_with("apps/tool/2.1.0/tool"), "{bin:?}");
                assert_eq!(args, vec!["--help".to_string()]);
            }
            other => panic!("expected Native, got {other:?}"),
        }
    }

    #[test]
    fn oci_daemon_plan_sets_gvisor_and_daemon() {
        let app = installed(
            r#"
            [app]
            name = "postgres"
            version = "16.0.0"
            runtime = "oci"
            [oci]
            image = "postgres:16"
            [sandbox]
            tier = "gvisor"
            net = "loopback"
            [daemon]
            enabled = false
            "#,
        );
        let store = Store::new("/data");
        let plan = plan_run(&store, &app, vec![]).unwrap();
        match plan {
            RunPlan::Oci { image, gvisor, daemon, net, .. } => {
                assert_eq!(image, "postgres:16");
                assert!(gvisor);
                assert!(daemon);
                assert_eq!(net, "loopback");
            }
            other => panic!("expected Oci, got {other:?}"),
        }
    }

    #[test]
    fn oci_cli_plan_passes_args_as_cmd_not_daemon() {
        let app = installed(
            r#"
            [app]
            name = "ffmpeg"
            version = "6.0.0"
            runtime = "oci"
            [oci]
            image = "ffmpeg:6"
            "#,
        );
        let store = Store::new("/data");
        let plan = plan_run(&store, &app, vec!["-i".into(), "in.mp4".into()]).unwrap();
        match plan {
            RunPlan::Oci { cmd, daemon, .. } => {
                assert_eq!(cmd, vec!["-i".to_string(), "in.mp4".to_string()]);
                assert!(!daemon);
            }
            other => panic!("expected Oci, got {other:?}"),
        }
    }
}
