//! The Guardian seam — CE's content-free pre-execution screening primitive.
//!
//! Before an untrusted workload runs on a host, the node asks a [`Guardian`] whether it may. This
//! crate defines **only the seam**: the trait, the request it screens, and the verdict it returns,
//! plus a fail-closed default. It contains **no AI, no policy, and no notion of what
//! "cryptomining" or "DDoS" means** — that vocabulary lives entirely in the `ce-guardian` app, the
//! same way reputation lives outside `ce-cap`. See `docs/guardian.md` and `docs/primitives.md`.
//!
//! The node holds an `Arc<dyn Guardian>` and calls [`Guardian::screen`] at the one chokepoint every
//! execution path passes through (after capability authorization, before any container or module is
//! created). A [`GuardVerdict::Deny`] refuses the launch.

use async_trait::async_trait;
use ce_identity::NodeId;
use serde::{Deserialize, Serialize};

/// The artifact a job will execute, content-addressed so a verdict can be cached per identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactRef {
    /// A Docker image and its pinned content digest (`sha256:...`), if known.
    Docker { image: String, digest: Option<String> },
    /// A WASM module addressed by the sha256 of its bytes.
    Wasm { module_hash: [u8; 32] },
}

/// Resource ceilings the workload requested. Kept minimal and self-contained so this crate stays
/// free of runtime dependencies; the screener treats them as advisory signal, not policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub cpu_cores: u32,
    pub mem_mb: u64,
    /// Number of GPUs requested (0 = none).
    pub gpus: u32,
}

/// Everything a [`Guardian`] needs to decide whether a workload may run. Assembled by the node at
/// the launch chokepoint from the already-authorized job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardRequest {
    /// The runtime tag this workload targets, e.g. `"docker"` or `"wasm"`.
    pub required_tag: String,
    /// The artifact to be executed.
    pub artifact: ArtifactRef,
    /// Entrypoint / command and its arguments, if any.
    pub cmd_entry_args: Vec<String>,
    /// Environment variable *keys* (never values — values may carry secrets).
    pub env_keys: Vec<String>,
    /// Content hashes of declared inputs.
    pub inputs: Vec<[u8; 32]>,
    /// Requested resource ceilings.
    pub limits: Limits,
    /// The paying node.
    pub payer: NodeId,
    /// The job identifier.
    pub job_id: [u8; 32],
    /// The authorized capability chain bytes (read-only context; screening never re-does authz).
    pub cap_chain: Vec<u8>,
}

/// The screening outcome. `Deny` carries a human-readable reason and the opaque category strings the
/// app matched (CE assigns them no meaning).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardVerdict {
    Allow,
    Deny { reason: String, categories: Vec<String> },
}

impl GuardVerdict {
    /// Was the workload allowed to run?
    pub fn is_allowed(&self) -> bool {
        matches!(self, GuardVerdict::Allow)
    }
}

/// The screening seam. An implementation inspects the request and returns a verdict; the node
/// refuses to launch on [`GuardVerdict::Deny`]. Implementations must be `Send + Sync` so the node can
/// hold one behind an `Arc` across its async runtime.
#[async_trait]
pub trait Guardian: Send + Sync {
    async fn screen(&self, req: &GuardRequest) -> GuardVerdict;
}

/// The fail-closed default: deny everything. A node with no `ce-guardian` app wired in must refuse
/// untrusted workloads rather than run them unscreened. The reason string is asserted by the CI
/// boundary gate, so keep it stable.
pub struct DenyAllGuardian;

#[async_trait]
impl Guardian for DenyAllGuardian {
    async fn screen(&self, _req: &GuardRequest) -> GuardVerdict {
        GuardVerdict::Deny {
            reason: "no guardian configured".to_string(),
            categories: vec![],
        }
    }
}

/// Allows everything. For tests and explicitly-opted-in trusted deployments only — never ship this
/// as the production screener.
pub struct AllowAllGuardian;

#[async_trait]
impl Guardian for AllowAllGuardian {
    async fn screen(&self, _req: &GuardRequest) -> GuardVerdict {
        GuardVerdict::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> GuardRequest {
        GuardRequest {
            required_tag: "wasm".to_string(),
            artifact: ArtifactRef::Wasm { module_hash: [7u8; 32] },
            cmd_entry_args: vec![],
            env_keys: vec![],
            inputs: vec![],
            limits: Limits::default(),
            payer: [1u8; 32],
            job_id: [2u8; 32],
            cap_chain: vec![],
        }
    }

    #[tokio::test]
    async fn deny_all_is_fail_closed() {
        let v = DenyAllGuardian.screen(&req()).await;
        assert!(!v.is_allowed());
        match v {
            GuardVerdict::Deny { reason, .. } => assert_eq!(reason, "no guardian configured"),
            GuardVerdict::Allow => panic!("DenyAllGuardian must deny"),
        }
    }

    #[tokio::test]
    async fn allow_all_permits() {
        assert!(AllowAllGuardian.screen(&req()).await.is_allowed());
    }

    #[test]
    fn request_and_verdict_roundtrip_bincode_free_via_serde_json() {
        // The seam types must serialize so the node can ship a request to an out-of-process app.
        let r = req();
        let s = serde_json::to_string(&r).unwrap();
        let back: GuardRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }
}
