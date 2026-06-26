//! ce-appmgr — the universal app & system manager that turns `ce` into the single
//! root-installed binary on a host.
//!
//! Everything else — CE-native apps, arbitrary legacy apps, and whole systems — is
//! installed, resolved, sandboxed, and supervised *through* `ce`. This crate holds
//! the platform-agnostic core:
//!
//! - [`manifest`]  — the `ceapp.toml` format (`oci`/`native`/`wasm`/`recipe` tiers).
//! - [`platform`]  — host (os, arch) resolution for native artifacts.
//! - [`resolver`]  — dependency resolution across tiers into an ordered install plan.
//! - [`registry`]  — ce-hub-backed manifest source.
//! - [`store`]     — the on-disk install store + ce-owned launcher shims.
//! - [`placement`] — where an app runs (global: `self`/`node`/`tag`/`fleet`/`nearest`).
//! - [`instances`] — global instance tracking via ce-hub (`ce app ps`).
//! - [`ctlapi`]    — the per-instance, capability-scoped app-facing control API.
//!
//! Runtime execution (oci via ce-container, wasm via ce-wasm), the single daemon
//! supervisor, global placement over mesh-deploy, and the ce-cap/ce-gov security
//! gates are wired in the `ce` binary on top of these primitives.
//!
//! Design: `PLAN/ce-app-package-runtime.md`.
//!
//! **Toward the global supercomputer**: for one open fabric to host *everything* —
//! apps, games, LLMs, research tools, even whole legacy systems — something has to install and
//! supervise any of them, on any host, under one capability-sandboxed roof. This is that layer.
//! It is how a stranger's machine can safely run your app, and how the long tail of existing
//! software gets onto the pool without bespoke per-app plumbing.

pub mod ctlapi;
pub mod instances;
pub mod manifest;
pub mod materialize;
pub mod placement;
pub mod platform;
pub mod registry;
pub mod resolver;
pub mod run;
pub mod store;
pub mod supervisor;

pub use ctlapi::{
    CallerContext, ControlPlane, CtlEnvelope, CtlRequest, CtlResponse, DenyReason, DepHandle,
    EnsureDepRequest, InstallRequest, InstancesQuery, precheck_declared,
};
pub use instances::{Health, HubInstances, InstanceFilter, InstanceRecord};
pub use manifest::{AppManifest, Runtime, SandboxTier};
pub use materialize::{BlobClient, Materialized, materialize};
pub use run::{RunPlan, plan_run};
pub use supervisor::{DaemonPolicy, RestartPolicy, daemon_args, daemon_policy, enabled_daemons};
pub use placement::Placement;
pub use platform::host_target;
pub use registry::{HubRegistry, SignatureSidecar};
pub use resolver::{DepSpec, Plan, PlanItem, Registry, resolve};
pub use store::{InstalledApp, Store, default_store};
