//! Phase 8 (P8) — held escrow (farm-then-defect / V7 reducer) + MeritRank substrate.
//!
//! Governs: design `2(d)` "Held escrow" + `2(e)` MeritRank + `6` Phase 8. Closes V7, bounds V6.
//! PREREQUISITE: the lineage-based distinct-counterparty earned-accounting (`lineage.rs`, P9/`2(f)`)
//! must land first. PREREQUISITE: Phase 5 net hardening (`ce-mesh/net_hardening.rs`) must ship
//! WITH or BEFORE this phase, because forfeit-on-disappearance depends on >=3-relay multi-epoch
//! unreachability confirmation (H18).
//!
//! Held escrow is DETERRENT-ONLY with NO restitution anchor — compute has no persistent artifact
//! and no repair cost (`1` thesis, H13). Size it against max-gain-from-defection (the `2(a)`
//! inequality), not a repair cost. Three corrections over Storj (H13):
//!  - a host may NEVER accept a job whose value exceeds its currently-forfeitable held balance +
//!    standing-bond headroom (the `2(a)` admission gate — this is what makes "wait for escrow to
//!    release then take one big job" impossible);
//!  - the release schedule depends on cumulative DISTINCT-COUNTERPARTY VERIFIED value (lineage.rs),
//!    NOT wall-clock tenure (so a farm cannot run down the clock with self-dealt work);
//!  - release LAGS the longest open audit/dispute window:
//!    `release = max(unbond_window, longest_in_flight_job_dispute_window)`.
//!
//! MeritRank itself (the decayed personalized random walk) is an APP-LAYER scorer (scheduler),
//! NOT a node primitive (design `2(e)`); this module provides only the on-chain held-balance
//! ledger + the graceful-vs-abrupt-exit detection that the scorer and the verify dial read.

use ce_identity::NodeId;

/// Basis points of each `UptimeReward`/`JobSettle` earning back-loaded into the held balance
/// (design `2(d)` Storj-style back-load). TODO(P8): calibrate; placeholder 0 so the scaffold is a
/// no-op until wired.
pub const HELD_FRACTION_BPS: u128 = 0; // TODO(P8): set (Storj-style back-load).

/// The portion of a single earning that is withheld into the host's held balance.
/// Integer-only. TODO(P8): `gross * HELD_FRACTION_BPS / 10_000`.
pub fn withheld_portion(gross: u128) -> u128 {
    let _ = gross;
    0 // TODO(P8)
}

/// Block height at which a held balance may be released: lags the longest in-flight dispute window
/// (design `2(d)`). `unbond_release` is the standing-bond release height; `longest_dispute_end` is
/// the end height of the longest open audit/dispute the host is exposed to.
///
/// TODO(P8): `max(unbond_release, longest_dispute_end)`.
pub fn release_height(unbond_release: u64, longest_dispute_end: u64) -> u64 {
    unbond_release.max(longest_dispute_end)
}

/// Whether a host may accept a job of `job_value`: its `forfeitable_held + bond_headroom` must
/// cover it (design `2(d)` correction (1) / the `2(a)` admission gate). This is the rule that makes
/// farm-then-defect loss-making.
///
/// TODO(P8): real comparison; cooperate with `bond_gate::admit_job` so the two gates compose.
pub fn can_accept_job(forfeitable_held: u128, bond_headroom: u128, job_value: u128) -> bool {
    forfeitable_held.saturating_add(bond_headroom) >= job_value
}

/// Outcome of a host's exit, deciding whether the held balance is released or forfeited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitKind {
    /// Graceful exit (explicit unbond, served out the dispute window): held balance is released.
    Graceful,
    /// Confirmed abrupt disappearance (unreachable across >=3 relays over a multi-epoch window):
    /// held balance is forfeited (burned, deterrent-only — no restitution target).
    AbruptConfirmed,
    /// Not yet confirmed (could be censorship/eclipse): no action (H18 safety valve).
    Unconfirmed,
}

/// Validate forfeiture of a host's held balance: only on `ExitKind::AbruptConfirmed` (or slash),
/// never on a single missed challenge. Returns the amount to forfeit (burn) or None.
///
/// TODO(P8): implement; consensus-critical; depends on net_hardening relay-reachability evidence.
pub fn validate_forfeiture(_host: &NodeId, _held_balance: u128, _exit: ExitKind) -> Option<u128> {
    None // TODO(P8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_lags_longest_window() {
        assert_eq!(release_height(2016, 3000), 3000);
        assert_eq!(release_height(5000, 3000), 5000);
    }

    #[test]
    fn admission_requires_coverage() {
        assert!(can_accept_job(100, 50, 150));
        assert!(!can_accept_job(100, 50, 151));
    }
}
