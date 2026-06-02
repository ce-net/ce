//! CE execution-runtime seam.
//!
//! Defines *what* a unit of work is ([`Workload`]) and the interface for running it
//! ([`Runtime`]), independent of *how* it runs. Today's backend is Docker (`ce-container`); WASM
//! (`ce-wasm`) plugs in as a second [`Runtime`]. The node holds a registry of
//! `Vec<Arc<dyn Runtime>>` and dispatches each job to the first runtime that [`Runtime::can_run`].
//!
//! This is the only seam the rest of CE needs: placement (capability tags), the economy
//! (heartbeats/channels bill a job, not how it ran), and consensus are all payload-agnostic.
//! See `docs/runtime.md`.

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// A unit of work to run, independent of the execution backend.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Workload {
    /// A Docker/OCI container image with an optional command + environment.
    Docker {
        image: String,
        #[serde(default)]
        cmd: Vec<String>,
        #[serde(default)]
        env: Vec<(String, String)>,
        /// Content-addressed input blobs (data-layer CIDs) the cell needs. The host stages these
        /// into its local store (fetching from the mesh) before launch. See `docs/data-layer.md`.
        #[serde(default)]
        inputs: Vec<[u8; 32]>,
    },
    /// A WebAssembly module, **content-addressed** by the sha256 of its bytes. The host resolves
    /// the bytes (blob store / data layer) and MUST verify `sha256(bytes) == module_hash` before
    /// running — tamper-proof delivery, and the hash is a natural cache key.
    Wasm {
        module_hash: [u8; 32],
        /// Exported function to invoke (e.g. "_start" / "main").
        entry: String,
        #[serde(default)]
        args: Vec<String>,
        /// Content-addressed input blobs (data-layer CIDs). Staged like a Docker workload's.
        #[serde(default)]
        inputs: Vec<[u8; 32]>,
    },
}

impl Workload {
    /// The capability self-tag a host must advertise to run this workload (`"docker"` / `"wasm"`).
    /// This is what atlas/fleet placement filters on — no runtime-specific placement code.
    pub fn required_tag(&self) -> &'static str {
        match self {
            Workload::Docker { .. } => "docker",
            Workload::Wasm { .. } => "wasm",
        }
    }

    /// Every content-addressed dependency the host must have locally before launch: the declared
    /// `inputs`, plus a Wasm workload's `module_hash`. The host stages each from the data layer
    /// (Stage 4). The module is first so a missing module fails fast.
    pub fn content_deps(&self) -> Vec<[u8; 32]> {
        match self {
            Workload::Docker { inputs, .. } => inputs.clone(),
            Workload::Wasm { module_hash, inputs, .. } => {
                let mut deps = Vec::with_capacity(inputs.len() + 1);
                deps.push(*module_hash);
                deps.extend_from_slice(inputs);
                deps
            }
        }
    }
}

/// Resource limits for a job. A Docker backend maps these to cgroup limits; a WASM backend maps
/// `cpu_cores` to a fuel rate and `mem_mb` to a linear-memory cap.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Limits {
    pub cpu_cores: u32,
    pub mem_mb: u64,
}

/// An opaque handle to a running workload (e.g. a Docker container id, or a WASM instance id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handle(pub String);

/// A usage reading for billing/metering, normalized across backends.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct Usage {
    pub cpu_ms: u64,
    pub mem_mb: u64,
}

/// An execution backend. Implemented by `ce-container` (Docker) and `ce-wasm` (wasmtime).
#[async_trait]
pub trait Runtime: Send + Sync {
    /// The capability self-tag this runtime provides (`"docker"`, `"wasm"`). Advertised by the
    /// host so jobs can be placed on capable hosts.
    fn tag(&self) -> &'static str;

    /// Whether this runtime can execute `workload`. Default: the workload's required tag matches.
    fn can_run(&self, workload: &Workload) -> bool {
        workload.required_tag() == self.tag()
    }

    /// Launch the workload. Returns a handle for metering/stopping, plus an optional **output CID**
    /// (hex sha256) — set when the workload ran to completion and produced output that the runtime
    /// published to the data layer (e.g. a WASI command's stdout). `None` for detached/streaming
    /// workloads (containers, long-running cells) that produce no captured artifact.
    async fn launch(
        &self,
        workload: &Workload,
        limits: &Limits,
        job_id: [u8; 32],
    ) -> Result<(Handle, Option<String>)>;

    /// Stop and remove a running workload.
    async fn stop(&self, handle: &Handle) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_tag_maps_workload_to_capability() {
        let d = Workload::Docker { image: "alpine".into(), cmd: vec![], env: vec![], inputs: vec![] };
        let w = Workload::Wasm { module_hash: [0u8; 32], entry: "_start".into(), args: vec![], inputs: vec![] };
        assert_eq!(d.required_tag(), "docker");
        assert_eq!(w.required_tag(), "wasm");
    }

    #[test]
    fn workload_round_trips_through_serde() {
        let w = Workload::Wasm {
            module_hash: [7u8; 32],
            entry: "main".into(),
            args: vec!["x".into()],
            inputs: vec![[1u8; 32], [2u8; 32]],
        };
        let bytes = serde_json::to_vec(&w).unwrap();
        let back: Workload = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(w, back);
    }

    #[test]
    fn content_deps_lists_module_then_inputs() {
        let w = Workload::Wasm {
            module_hash: [9u8; 32],
            entry: "entry".into(),
            args: vec![],
            inputs: vec![[1u8; 32], [2u8; 32]],
        };
        assert_eq!(w.content_deps(), vec![[9u8; 32], [1u8; 32], [2u8; 32]]);
        let d = Workload::Docker {
            image: "x".into(),
            cmd: vec![],
            env: vec![],
            inputs: vec![[5u8; 32]],
        };
        assert_eq!(d.content_deps(), vec![[5u8; 32]]);
    }

    // A trivial runtime to confirm the trait is object-safe (usable as `dyn Runtime`).
    struct Noop;
    #[async_trait]
    impl Runtime for Noop {
        fn tag(&self) -> &'static str {
            "noop"
        }
        async fn launch(&self, _w: &Workload, _l: &Limits, _id: [u8; 32]) -> Result<(Handle, Option<String>)> {
            Ok((Handle("noop".into()), None))
        }
        async fn stop(&self, _h: &Handle) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn trait_is_object_safe() {
        let runtimes: Vec<std::sync::Arc<dyn Runtime>> = vec![std::sync::Arc::new(Noop)];
        assert!(!runtimes[0].can_run(&Workload::Docker { image: "x".into(), cmd: vec![], env: vec![], inputs: vec![] }));
    }
}
