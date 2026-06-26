//! ce-deploy — provisioning and deployment tooling for ce-net relays and clusters.
//!
//! Stands up **ce-net** infrastructure: Hetzner server provisioning, SSH-based deploy, and
//! multi-node cluster orchestration for the Hetzner end-to-end test suite. This is operator
//! tooling, not part of the node's runtime path.

pub mod cluster;
pub mod hetzner;
pub mod ssh;

pub use cluster::{Cluster, NodeHandle};
pub use hetzner::HetznerClient;
