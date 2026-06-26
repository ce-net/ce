//! The app-facing control API (CtlAPI).
//!
//! Every managed app instance is handed a per-instance API so it can declare and
//! spawn its own dependencies, install what it needs, and discover other instances
//! — at runtime, without the operator pre-wiring everything. This is a Dapr-style
//! sidecar API, but mesh-native and capability-secured.
//!
//! Transport (wired in the `ce` binary): a per-instance Unix domain socket
//! bind-mounted into the sandbox at `/run/ce/ctl.sock` (oci), or `CE_CTL_SOCK` for
//! native, or a host import for wasm. Cross-node calls proxy over the mesh. The app
//! also receives `CE_INSTANCE_TOKEN`.
//!
//! Security: every call carries the instance token, which the agent maps to the
//! instance's scoped, attenuated capability (derived from the app's install-time
//! cap). An app can only ensure/install what its capability AND its declared
//! manifest `[deps]` permit — no escalation. Install/spawn requests additionally
//! pass an optional ce-gov policy scan and a resource/credit budget. This module
//! defines the wire types and the [`ControlPlane`] behavior the agent implements;
//! the socket/mesh transport and the ce-cap/ce-gov gates live in the `ce` binary.

use crate::instances::InstanceRecord;
use crate::placement::Placement;
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Identity + authority of the caller, resolved by the agent from the instance
/// token before any handler runs. Handlers must treat this as the security
/// boundary: never act beyond what `capabilities` and `declared_deps` allow.
#[derive(Debug, Clone)]
pub struct CallerContext {
    /// The calling instance's id (`<node>:<app>:<nonce>`).
    pub instance_id: String,
    /// The calling app's name (for matching against declared deps).
    pub app: String,
    /// ce-cap abilities the instance's scoped capability grants (opaque strings).
    pub capabilities: Vec<String>,
    /// App names this instance's manifest declared as deps — the allow-set for
    /// `ensure_dep`/`install`. Empty means "declare deps in the manifest first".
    pub declared_deps: Vec<String>,
}

impl CallerContext {
    /// Whether the caller may act on dependency `name`: it must have been declared
    /// in the manifest. (The capability check is layered on top by the agent.)
    pub fn may_use_dep(&self, name: &str) -> bool {
        self.declared_deps.iter().any(|d| d == name)
    }
}

/// `POST /deps/ensure` — idempotently resolve + install + start a dependency and
/// return a connection handle scoped to the caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnsureDepRequest {
    pub name: String,
    /// Optional semver requirement (e.g. `>= 16`); defaults to the manifest's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_req: Option<String>,
    /// Where to place it: defaults to the caller's own node (`self`).
    #[serde(default)]
    pub placement: Placement,
}

/// Connection info for an ensured dependency. `endpoint` is whatever the dependency
/// exposes (a mesh address, a loopback `host:port`, a unix socket path) — the app
/// uses it directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepHandle {
    pub name: String,
    pub instance_id: String,
    pub endpoint: String,
    /// True if this call started a new instance; false if it joined an existing one.
    pub created: bool,
}

/// `POST /install` — install (not necessarily start) an app/system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallRequest {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_req: Option<String>,
    #[serde(default)]
    pub placement: Placement,
}

/// `GET /instances` — query the global registry, scoped to what the caller may see.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InstancesQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
}

/// Why a request was denied — surfaced to the app and audited.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    /// The dependency was not declared in the caller's manifest `[deps]`.
    NotDeclared,
    /// The caller's capability does not grant the required ability.
    CapabilityDenied,
    /// A ce-gov policy scan rejected the request.
    PolicyDenied,
    /// The caller is over its resource/credit budget.
    BudgetExceeded,
}

impl std::fmt::Display for DenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            DenyReason::NotDeclared => "dependency not declared in manifest [deps]",
            DenyReason::CapabilityDenied => "capability does not grant this action",
            DenyReason::PolicyDenied => "rejected by governance policy",
            DenyReason::BudgetExceeded => "resource/credit budget exceeded",
        };
        write!(f, "{s}")
    }
}

/// The behavior the per-node agent implements to serve managed apps. The transport
/// (unix socket / mesh) decodes a request, resolves a [`CallerContext`] from the
/// instance token, runs the security gates, then calls the matching method here.
///
/// `async fn` in trait (stable, edition 2024). Implemented by the agent in `ce`.
#[allow(async_fn_in_trait)]
pub trait ControlPlane {
    /// Ensure a declared dependency is running and return how to reach it.
    async fn ensure_dep(&self, caller: &CallerContext, req: EnsureDepRequest) -> Result<DepHandle>;

    /// Install an app/system the caller is authorized for (does not start it).
    async fn install(&self, caller: &CallerContext, req: InstallRequest) -> Result<()>;

    /// List instances visible to the caller.
    async fn instances(
        &self,
        caller: &CallerContext,
        query: InstancesQuery,
    ) -> Result<Vec<InstanceRecord>>;
}

/// Shared pre-flight gate used by `ensure_dep`/`install` implementations: a request
/// to act on `dep` is allowed only if it was declared in the manifest. Capability,
/// policy, and budget checks are layered on by the agent (they need ce-cap/ce-gov,
/// which live outside this crate). Returns the precise [`DenyReason`] on refusal.
pub fn precheck_declared(caller: &CallerContext, dep: &str) -> std::result::Result<(), DenyReason> {
    if caller.may_use_dep(dep) {
        Ok(())
    } else {
        Err(DenyReason::NotDeclared)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller() -> CallerContext {
        CallerContext {
            instance_id: "n:web:1".into(),
            app: "web".into(),
            capabilities: vec!["exec".into()],
            declared_deps: vec!["postgres".into()],
        }
    }

    #[test]
    fn declared_dep_passes_undeclared_denied() {
        let c = caller();
        assert!(precheck_declared(&c, "postgres").is_ok());
        assert!(matches!(
            precheck_declared(&c, "redis"),
            Err(DenyReason::NotDeclared)
        ));
    }

    #[test]
    fn ensure_request_defaults_to_local_placement() {
        let json = r#"{ "name": "postgres" }"#;
        let req: EnsureDepRequest = serde_json::from_str(json).unwrap();
        assert!(req.placement.is_local());
        assert_eq!(req.name, "postgres");
    }

    #[test]
    fn deny_reason_serializes_snake_case() {
        let s = serde_json::to_string(&DenyReason::CapabilityDenied).unwrap();
        assert_eq!(s, "\"capability_denied\"");
    }
}
