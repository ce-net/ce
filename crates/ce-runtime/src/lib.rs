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

    /// Launch the workload (detached). Returns a handle for metering/stopping.
    async fn launch(&self, workload: &Workload, limits: &Limits, job_id: [u8; 32]) -> Result<Handle>;

    /// Stop and remove a running workload.
    async fn stop(&self, handle: &Handle) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_tag_maps_workload_to_capability() {
        let d = Workload::Docker { image: "alpine".into(), cmd: vec![], env: vec![] };
        let w = Workload::Wasm { module_hash: [0u8; 32], entry: "_start".into(), args: vec![] };
        assert_eq!(d.required_tag(), "docker");
        assert_eq!(w.required_tag(), "wasm");
    }

    #[test]
    fn workload_round_trips_through_serde() {
        let w = Workload::Wasm { module_hash: [7u8; 32], entry: "main".into(), args: vec!["x".into()] };
        let bytes = serde_json::to_vec(&w).unwrap();
        let back: Workload = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(w, back);
    }

    // A trivial runtime to confirm the trait is object-safe (usable as `dyn Runtime`).
    struct Noop;
    #[async_trait]
    impl Runtime for Noop {
        fn tag(&self) -> &'static str {
            "noop"
        }
        async fn launch(&self, _w: &Workload, _l: &Limits, _id: [u8; 32]) -> Result<Handle> {
            Ok(Handle("noop".into()))
        }
        async fn stop(&self, _h: &Handle) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn trait_is_object_safe() {
        let runtimes: Vec<std::sync::Arc<dyn Runtime>> = vec![std::sync::Arc::new(Noop)];
        assert!(!runtimes[0].can_run(&Workload::Docker { image: "x".into(), cmd: vec![], env: vec![] }));
    }
}
