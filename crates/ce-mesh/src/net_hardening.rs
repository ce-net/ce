//! Phase 5 (P5) — libp2p network hardening.
//!
//! Governs: design `3` net row + `6` Phase 5 + sybil-resistance.md 4.3. Closes V8 (eclipse /
//! routing / beacon-grind). MUST ship WITH or BEFORE Phase 8 (held_escrow), because
//! forfeit-on-disappearance depends on >=3-relay multi-epoch unreachability confirmation being
//! real (design `2(d)`/`2(c)` H18).
//!
//! Scope (all in ce-mesh, no consensus change):
//!  - gossipsub P4 (invalid-message) then P5 (application) peer scoring; slashed/revoked peers
//!    driven to -300 (below graylist) — design `2(e)`.
//!  - connection limits + per-/24 (and per-ASN) caps to bound an eclipse attacker's peer share.
//!  - >=3 independent relays / multiple bootstrap domains (today: single Hetzner relay + single
//!    bootstrap domain — baseline N1/N8) so a host reachable only via one relay is a structural
//!    BRIDGE (feeds MeritRank connectivity-decay, design `2(e)`).
//!  - relay-reachability evidence the chain's disappearance detection reads (held_escrow H18).

use std::time::Duration;

/// Gossipsub application-score floor a slashed/revoked peer is driven to (design `2(e)`): below
/// the graylist threshold so it is dropped from the mesh. TODO(P5).
pub const SLASHED_PEER_SCORE: f64 = -300.0;

/// Maximum peers admitted from a single /24 IPv4 block (and, later, per ASN), to bound an eclipse
/// attacker's share of a victim's peer set. TODO(P5): calibrate against sybil-resistance.md 4.3.
pub const MAX_PEERS_PER_24: usize = 2;

/// Minimum number of INDEPENDENT relays a node should maintain reservations with, so no single
/// relay can censor it and disappearance can be confirmed across a quorum (design `2(d)` H18).
pub const MIN_INDEPENDENT_RELAYS: usize = 3;

/// Multi-epoch window over which a peer must be unreachable across `MIN_INDEPENDENT_RELAYS` before
/// its disappearance is reported as confirmed to the chain (design `2(c)`/`2(d)` H18). TODO(P5).
pub const UNREACHABILITY_WINDOW: Duration = Duration::from_secs(0); // TODO(P5): real multi-epoch span.

/// Build the gossipsub peer-scoring parameters (P4 invalid-message + P5 application weights).
/// Returns an opaque config the `Mesh` builder applies. `Mesh` is `!Sync`, so this is a free
/// function producing config, never a method holding the swarm across an await (CLAUDE.md).
///
/// TODO(P5): construct `libp2p::gossipsub::PeerScoreParams` + `PeerScoreThresholds` per
/// sybil-resistance.md 4.3. Stub returns unit so the scaffold compiles without the gossipsub types.
pub fn peer_score_config() {
    // TODO(P5)
}

/// Whether admitting `peer_ip`'s /24 would exceed `MAX_PEERS_PER_24` given the current peer set.
/// TODO(P5): real /24 bucketing over connected peers.
pub fn admit_within_subnet_cap(_current_same_24: usize) -> bool {
    true // TODO(P5)
}

/// Whether `peer` is a structural BRIDGE: reachable only through a single relay (the signature of
/// every sock-puppet farm, design `2(e)` connectivity-decay). Feeds the app-layer MeritRank scorer.
/// TODO(P5): derive from the relay-reservation / path diversity view.
pub fn is_bridge_peer(_distinct_relay_paths: usize) -> bool {
    false // TODO(P5)
}

/// Whether a peer has been unreachable across >=MIN_INDEPENDENT_RELAYS over UNREACHABILITY_WINDOW —
/// the evidence the chain's `held_escrow`/`capacity_audit` disappearance forfeiture requires (H18).
/// TODO(P5): track per-relay reachability probes.
pub fn disappearance_confirmed(_distinct_unreachable_relays: usize, _window_elapsed: Duration) -> bool {
    false // TODO(P5)
}
