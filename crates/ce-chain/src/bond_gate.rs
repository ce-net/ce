//! Phase 4 (P4) — bond gate, capacity-proportional sizing, per-job slice-locking.
//!
//! Governs: design `2(a)` ("Bonded identity — influence proportional to slashable stake") and the
//! `6` Phase 4 entry. Closes V1/V3 cost floor AND the rehypothecation hole (red-team H1, H3, H5,
//! H22). Extends consensus.md (HostBond/HostUnbond already implemented) by WIRING the gate.
//!
//! What this phase must enforce (all integer-only, deterministic, no floats — consensus math):
//!  - bond gates `CapacityAd` publication AND `UptimeReward` eligibility;
//!  - capacity-proportional bond sizing `bond(C)` PLUS an absolute floor `T_floor` (H3);
//!  - the aggregate-exposure ADMISSION GATE: accepting a job locks
//!    `slice_j = at_risk_value_j / P(detect)_j` of bond headroom; a bid that would drive
//!    `active_bond - sum_open_slices` negative is REFUSED (H1, no rehypothecation);
//!  - single-job value ceiling `<= bond * P(detect_current)` (H22 — closes "reputation buys a
//!    cheaper cheat");
//!  - required endogenous held fraction for high tiers + distinct bond != earned credits (H5).
//!
//! INTERIM until slice-locking lands: a hard per-host concurrent-high-value-job cap of 1
//! (sybil-resistance.md 4.2).
//!
//! This module is a PURE policy layer over chain state: it reads `Chain` (active_bond, open
//! exposure) and returns admit/refuse decisions + the slice to lock. The actual lock bookkeeping
//! is wired into `Chain::append`/`apply_block_to_cache` via the `BondGate` outputs.

use ce_identity::NodeId;

/// Basis-point precision for `P(detect)` (probabilities carried as integer bps, never floats).
pub const PDETECT_BPS_DENOM: u128 = 10_000;

/// Absolute minimum bond floor in base units, independent of the capacity-proportional term
/// (design `2(a)` H3 / `2(b2)`). No host may bond below this. TODO(P4): size in reward-days so it
/// survives halvings (Filecoin/Sia pattern); the constant here is a placeholder default.
pub const T_FLOOR: u128 = 0; // TODO(P4): set to a reward-day-denominated floor.

/// Network-wide bonded-stake threshold below which high-value stranger jobs are refused
/// (design `2(a)` H3 fix (2): "gate high-value job routing on TotalBondedStake > T_threshold").
pub const T_THRESHOLD: u128 = 0; // TODO(P4).

/// Capacity-proportional bond requirement for a host advertising `capacity_units` of capacity,
/// combined with the absolute floor. Design `2(a)`: faking 100x capacity must cost ~100x bond
/// (the Filecoin property), but never below `T_FLOOR`.
///
/// TODO(P4): implement `max(T_FLOOR, capacity_units * per_unit_reward_days)`; integer-only.
pub fn required_bond(capacity_units: u64) -> u128 {
    let _ = capacity_units;
    T_FLOOR
}

/// The bond slice an in-flight job of at-risk value `at_risk_value` at detection probability
/// `p_detect_bps` locks (design `2(a)` admission gate): `slice = at_risk_value / P(detect)`.
/// Higher assurance tier => higher P(detect) => smaller slice => more concurrency.
///
/// TODO(P4): `at_risk_value * PDETECT_BPS_DENOM / p_detect_bps` with saturating/zero guards.
pub fn job_bond_slice(at_risk_value: u128, p_detect_bps: u128) -> u128 {
    let _ = (at_risk_value, p_detect_bps);
    0 // TODO(P4)
}

/// The maximum single-job value a host may accept given its `active_bond` and current detection
/// probability (design `4`/H22): `bond * P(detect_current)`. Lowering P(detect) via reputation
/// automatically lowers this ceiling, keeping `locked_slice > gain/P(detect)` invariant by
/// admission control.
///
/// TODO(P4): `active_bond * p_detect_current_bps / PDETECT_BPS_DENOM`.
pub fn single_job_value_ceiling(active_bond: u128, p_detect_current_bps: u128) -> u128 {
    let _ = (active_bond, p_detect_current_bps);
    0 // TODO(P4)
}

/// Decision returned by the admission gate when a host attempts to accept a new job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BondAdmission {
    /// Accept; lock this many base units of bond headroom as the job's slice.
    Admit { slice: u128 },
    /// Refuse: accepting would drive aggregate exposure past the bond (402-style).
    Refuse,
}

/// Aggregate-exposure admission decision (design `2(a)` ADMISSION GATE, H1). `unlocked_headroom`
/// is `active_bond - sum_open_slices`; `at_risk_value`/`p_detect_bps` size the new slice.
///
/// TODO(P4): refuse when `slice > unlocked_headroom`; otherwise Admit{slice}. Also enforce the
/// interim per-host concurrent-high-value cap = 1 until slice-locking is fully wired.
pub fn admit_job(unlocked_headroom: u128, at_risk_value: u128, p_detect_bps: u128) -> BondAdmission {
    let _ = (unlocked_headroom, at_risk_value, p_detect_bps);
    BondAdmission::Admit { slice: 0 } // TODO(P4): real gate.
}

/// Whether `host` is eligible to publish a `CapacityAd` / earn `UptimeReward`: it must hold an
/// active bond >= `required_bond(claimed_capacity)`. Design `2(a)` ("bond gates capacity-ad
/// publication AND UptimeReward eligibility").
///
/// TODO(P4): wire against `Chain::active_bond(host)` from the append validation path.
pub fn bond_gates_role(active_bond: u128, claimed_capacity: u64) -> bool {
    active_bond >= required_bond(claimed_capacity)
}

/// The required endogenous (earned-and-held) fraction of total effective bond for high tiers, so
/// an outside lender cannot supply 100% of collateral on day one (design `2(a)` H5(i)). Carried
/// as integer bps. TODO(P4).
pub fn required_endogenous_fraction_bps() -> u128 {
    0 // TODO(P4)
}

/// Marker placeholder so callers in `lib.rs` have a stable symbol to dispatch a `CapacityAd`
/// bond-gate check through while the body is filled in. Returns Ok (identity) for the scaffold.
///
/// TODO(P4): replace with the real per-tx validation that the append() bond-gate arm calls.
pub fn validate_capacity_ad_bond(_host: &NodeId, _active_bond: u128, _claimed_capacity: u64) -> bool {
    true // TODO(P4): bond_gates_role + endogenous-fraction + T_THRESHOLD checks.
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO(P4): real tests. Scaffold-level sanity only.
    #[test]
    fn scaffold_compiles() {
        assert_eq!(required_bond(0), T_FLOOR);
        assert_eq!(admit_job(0, 0, 1), BondAdmission::Admit { slice: 0 });
        assert!(bond_gates_role(T_FLOOR, 0));
    }
}
