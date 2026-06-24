//! Phase 4 (P4) — bond gate, capacity-proportional sizing, per-job slice-locking.
//!
//! Governs: design `2(a)` ("Bonded identity — influence proportional to slashable stake") and the
//! `6` Phase 4 entry. Closes V1/V3 cost floor AND the rehypothecation hole (red-team H1, H3, H5,
//! H22). Extends consensus.md (HostBond/HostUnbond already implemented) by WIRING the gate.
//!
//! What this phase enforces (all integer-only, deterministic, no floats — consensus math):
//!  - bond gates `CapacityAd` publication AND `UptimeReward` eligibility;
//!  - capacity-proportional bond sizing `bond(C)` PLUS an absolute floor `T_FLOOR` (H3);
//!  - the aggregate-exposure ADMISSION GATE: accepting a job locks
//!    `slice_j = at_risk_value_j / P(detect)_j` of bond headroom; a bid that would drive
//!    `active_bond - sum_open_slices` negative is REFUSED (H1, no rehypothecation);
//!  - single-job value ceiling `<= bond * P(detect_current)` (H22 — closes "reputation buys a
//!    cheaper cheat");
//!  - required endogenous held fraction for high tiers + distinct bond != earned credits (H5).
//!
//! INTERIM until slice-locking is fully wired through the JobBid acceptance path: a hard per-host
//! concurrent-high-value-job cap of 1 (sybil-resistance.md 4.2), exposed via
//! [`interim_high_value_cap_ok`]. The aggregate-exposure gate ([`admit_job`]) is the real,
//! non-interim mechanism and is what callers should drive once they track open slices.
//!
//! This module is a PURE policy layer over chain state: it reads bond/headroom figures and returns
//! admit/refuse decisions + the slice to lock. All math is `u128`, saturating, deterministic — it is
//! consensus-reachable (the `append()` `CapacityAd` arm calls [`bond_gates_role`]), so it must never
//! panic, never use floats, and never depend on iteration order.
//!
//! ## Integer-probability convention
//! Probabilities `P(detect)` are carried as integer basis points against [`PDETECT_BPS_DENOM`]
//! (`10_000`). `p_detect_bps = 10_000` is `P=1.0` (certain detection); `p_detect_bps = 2_500` is
//! `P=0.25`. `p_detect_bps == 0` ("undetectable") yields an infinite slice (saturated to
//! `u128::MAX`) and a zero value-ceiling, so an un-auditable job can never be admitted — exactly the
//! conservative direction.

use ce_identity::NodeId;

/// Basis-point precision for `P(detect)` (probabilities carried as integer bps, never floats).
/// `10_000 bps == P(detect) = 1.0`.
pub const PDETECT_BPS_DENOM: u128 = 10_000;

/// Basis-point precision for the endogenous-fraction knob (`10_000 bps == 100%`).
pub const ENDOGENOUS_BPS_DENOM: u128 = 10_000;

/// Capacity-proportional bond term: base units of bond required PER advertised capacity unit, on top
/// of the absolute floor. Sizing in a fixed per-unit term keeps "fake 100x capacity costs ~100x bond"
/// (the Filecoin property, design `2(a)`). Conservative default — calibration is empirical
/// (design `5` open problem 9 / FIP-style re-tuning). `1 credit` per capacity unit.
pub const PER_UNIT_BOND: u128 = 1_000_000_000_000_000_000; // == ce-chain CREDIT (1 credit / unit).

/// Absolute minimum bond floor in base units, independent of the capacity-proportional term
/// (design `2(a)` H3 / `2(b2)`). No host may bond below this to publish capacity or (when the gate
/// is enabled) earn `UptimeReward`. Set to `1_000` credits — roughly one reward-day of emission at
/// the base rate — so it survives early-network cheapness without being denominated in a halving-
/// sensitive raw block reward here. TODO(P4 calibration): re-derive in reward-days on live data.
pub const T_FLOOR: u128 = 1_000 * PER_UNIT_BOND; // 1_000 credits.

/// Network-wide bonded-stake threshold below which high-value stranger jobs are refused
/// (design `2(a)` H3 fix (2): "gate high-value job routing on `TotalBondedStake > T_THRESHOLD`").
/// During bootstrap the network is "high-trust / low-value only" — stranger high-value work is
/// forbidden until total bonded stake crosses this floor. Default = `10 * T_FLOOR` (ten floor-bonds
/// of distinct-origin stake). TODO(P4 calibration): tune on live `total_bonded()`.
pub const T_THRESHOLD: u128 = 10 * T_FLOOR;

/// Required endogenous (earned-and-held) fraction of total effective bond for high-tier roles, so an
/// outside lender cannot supply 100% of collateral on day one (design `2(a)` H5(i)). Carried as
/// integer bps against [`ENDOGENOUS_BPS_DENOM`]. Default 25% (`2_500 bps`). Conservative; calibrate.
pub const REQUIRED_ENDOGENOUS_BPS: u128 = 2_500;

/// Capacity-proportional bond requirement for a host advertising `capacity_units`, combined with the
/// absolute floor (design `2(a)`): `max(T_FLOOR, capacity_units * PER_UNIT_BOND)`. Faking 100x
/// capacity costs ~100x bond, but never below `T_FLOOR`. Saturating, integer-only, deterministic.
pub fn required_bond(capacity_units: u64) -> u128 {
    let proportional = (capacity_units as u128).saturating_mul(PER_UNIT_BOND);
    proportional.max(T_FLOOR)
}

/// The bond slice an in-flight job of at-risk value `at_risk_value` at detection probability
/// `p_detect_bps` locks (design `2(a)` admission gate): `slice = ceil(at_risk_value / P(detect))`.
/// Higher assurance tier => higher `P(detect)` => smaller slice => more concurrency.
///
/// Computed as `ceil(at_risk_value * PDETECT_BPS_DENOM / p_detect_bps)`. The ceiling makes the gate
/// conservative (it never under-locks by a rounding base unit). `p_detect_bps == 0` (undetectable)
/// saturates to `u128::MAX` so such a job can never fit any finite headroom.
pub fn job_bond_slice(at_risk_value: u128, p_detect_bps: u128) -> u128 {
    if p_detect_bps == 0 {
        return u128::MAX;
    }
    // ceil(at_risk * DENOM / p) = (at_risk * DENOM + p - 1) / p, with saturation on the product.
    let scaled = at_risk_value.saturating_mul(PDETECT_BPS_DENOM);
    // saturating_add keeps the +(p-1) ceiling bump from wrapping at the u128 ceiling.
    scaled.saturating_add(p_detect_bps - 1) / p_detect_bps
}

/// The maximum single-job value a host may accept given its `active_bond` and current detection
/// probability (design `4`/H22): `bond * P(detect_current)`. Lowering `P(detect)` via reputation
/// automatically lowers this ceiling, keeping the `locked_slice > gain/P(detect)` invariant by
/// admission control rather than by hoping a once-sized bond was large enough.
///
/// `floor(active_bond * p_detect_current_bps / PDETECT_BPS_DENOM)`. Floor here is conservative: it
/// never lets a job exceed `bond * P`. `p_detect_current_bps == 0` => ceiling 0 (admit nothing).
pub fn single_job_value_ceiling(active_bond: u128, p_detect_current_bps: u128) -> u128 {
    let p = p_detect_current_bps.min(PDETECT_BPS_DENOM); // clamp: P never exceeds 1.0.
    active_bond.saturating_mul(p) / PDETECT_BPS_DENOM
}

/// Decision returned by the admission gate when a host attempts to accept a new job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BondAdmission {
    /// Accept; lock this many base units of bond headroom as the job's slice.
    Admit { slice: u128 },
    /// Refuse: accepting would drive aggregate exposure past the bond, or the single-job value would
    /// exceed `bond * P(detect_current)` (H22), or the job is undetectable (402-style).
    Refuse,
}

/// Aggregate-exposure admission decision (design `2(a)` ADMISSION GATE, H1, H22).
///
/// - `active_bond`: the host's standing, slashable bond (caps the value ceiling).
/// - `unlocked_headroom`: `active_bond - Σ_open_slices` — bond not already pledged to in-flight jobs.
/// - `at_risk_value` / `p_detect_bps`: size the new job's slice and check the value ceiling.
///
/// Refuses when (a) the job is undetectable (`p_detect_bps == 0`), or (b) the single-job value
/// exceeds `active_bond * P(detect_current)` (H22 — closes "reputation buys a cheaper cheat"), or
/// (c) the slice `> unlocked_headroom` (H1 — no rehypothecation: K concurrent high-value jobs need K
/// slices of UNLOCKED bond). Otherwise [`BondAdmission::Admit`] with the slice the caller must lock.
pub fn admit_job(
    active_bond: u128,
    unlocked_headroom: u128,
    at_risk_value: u128,
    p_detect_bps: u128,
) -> BondAdmission {
    if p_detect_bps == 0 {
        return BondAdmission::Refuse; // undetectable work is never admissible.
    }
    // H22: single-job value ceiling = bond * P(detect_current). Never accept above it.
    if at_risk_value > single_job_value_ceiling(active_bond, p_detect_bps) {
        return BondAdmission::Refuse;
    }
    // H1: aggregate-exposure gate — the slice must fit UNLOCKED headroom.
    let slice = job_bond_slice(at_risk_value, p_detect_bps);
    if slice > unlocked_headroom {
        return BondAdmission::Refuse;
    }
    BondAdmission::Admit { slice }
}

/// INTERIM rule (design `2(a)` / sybil-resistance.md 4.2): until per-job slice-locking is fully wired
/// through the JobBid-acceptance path, cap a host at ONE concurrent high-value job. Returns whether a
/// host already running `open_high_value_jobs` may accept one more. The real gate is [`admit_job`];
/// this is the carried-forward stopgap a scheduler can apply on top while open-slice tracking lands.
pub fn interim_high_value_cap_ok(open_high_value_jobs: u64) -> bool {
    open_high_value_jobs == 0
}

/// Whether `active_bond` is enough to publish a `CapacityAd` / earn `UptimeReward` for a host
/// claiming `claimed_capacity`: it must hold `active_bond >= required_bond(claimed_capacity)`.
/// Design `2(a)` ("bond gates capacity-ad publication AND UptimeReward eligibility").
pub fn bond_gates_role(active_bond: u128, claimed_capacity: u64) -> bool {
    active_bond >= required_bond(claimed_capacity)
}

/// The required endogenous (earned-and-held) fraction of total effective bond for high tiers, so an
/// outside lender cannot supply 100% of collateral on day one (design `2(a)` H5(i)). Integer bps
/// against [`ENDOGENOUS_BPS_DENOM`].
pub fn required_endogenous_fraction_bps() -> u128 {
    REQUIRED_ENDOGENOUS_BPS
}

/// Whether the endogenous (earned-and-held) portion of a host's effective bond satisfies the
/// required fraction (design `2(a)` H5(i), distinct bond != earned credits, H5(ii)). `endogenous` is
/// the earned-and-held collateral; `total_effective_bond` is endogenous + externally-supplied.
/// Holds iff `endogenous * DENOM >= total_effective_bond * REQUIRED_ENDOGENOUS_BPS`. Integer-only,
/// cross-multiplied to avoid division-rounding bias. A zero total trivially satisfies (no role yet).
pub fn endogenous_fraction_ok(endogenous: u128, total_effective_bond: u128) -> bool {
    if total_effective_bond == 0 {
        return true;
    }
    let need = total_effective_bond.saturating_mul(REQUIRED_ENDOGENOUS_BPS);
    let have = endogenous.saturating_mul(ENDOGENOUS_BPS_DENOM);
    have >= need
}

/// Whether the network has enough distinct-origin bonded stake to route high-value stranger work
/// (design `2(a)` H3 fix (2)): `total_distinct_origin_bonded > T_THRESHOLD`. During bootstrap this is
/// false — strangers are forced to low-value / high-trust work until the network thickens.
pub fn high_value_routing_allowed(total_distinct_origin_bonded: u128) -> bool {
    total_distinct_origin_bonded > T_THRESHOLD
}

/// `append()`-reachable bond-gate validation for a `CapacityAd` (design `2(a)`, wired into the
/// host-bond/slash match in `Chain::append`). A `CapacityAd` is valid only if the host already holds
/// `active_bond >= required_bond(claimed_capacity)`. This is the consensus gate that makes faking
/// capacity cost bond (V3 cost floor). Pure, deterministic, never panics.
///
/// (The endogenous-fraction and `T_THRESHOLD` checks are routing/role policy that the scheduler app
/// and `ce-node` eligibility layer apply via [`endogenous_fraction_ok`] /
/// [`high_value_routing_allowed`]; they are NOT consensus-fatal for ad publication itself, so they
/// are deliberately not enforced in the chain `append()` arm.)
pub fn validate_capacity_ad_bond(_host: &NodeId, active_bond: u128, claimed_capacity: u64) -> bool {
    bond_gates_role(active_bond, claimed_capacity)
}

/// `ce-node`/consensus eligibility predicate for `UptimeReward` (design `2(a)`: "bond gates ...
/// `UptimeReward` eligibility").
///
/// Bond-gated, but **genesis-exempt**: a node holding a genesis bootstrap weight (`genesis_weight >
/// 0`) is eligible regardless of bond, so the cold-start network can still produce blocks before
/// anyone has bonded (mirrors `Chain::consensus_weight`'s genesis fallback — otherwise the chain
/// dead-locks and the existing mining/consensus tests break). Once a node has left the bootstrap set
/// (`genesis_weight == 0`) it must hold at least the floor bond to keep earning emission.
///
/// NOTE: this is intentionally surfaced as a predicate consumed by the `ce-node` block-production /
/// eligibility layer rather than hard-wired as an `append()` reject, because tightening UptimeReward
/// emission is a network-config rollout step (Phase 4 "bootstrap = low-value, high-trust"): flipping
/// it on in `append()` unconditionally would reject every legacy un-bonded miner mid-chain. The pure
/// rule lives here; the rollout switch lives in `ce-node`.
pub fn uptime_reward_eligible(active_bond: u128, genesis_weight: u128) -> bool {
    genesis_weight > 0 || active_bond >= T_FLOOR
}

#[cfg(test)]
mod tests {
    use super::*;

    const C: u128 = PER_UNIT_BOND; // one credit, for readability.

    // ---- required_bond: capacity-proportional + absolute floor (H3) ----

    #[test]
    fn required_bond_enforces_floor_in_early_network() {
        // Zero / tiny capacity still costs the absolute floor — no near-zero bonds (H3).
        assert_eq!(required_bond(0), T_FLOOR);
        assert_eq!(required_bond(1), T_FLOOR); // 1 unit * 1 credit < floor => floor wins.
        assert_eq!(required_bond(999), T_FLOOR);
    }

    #[test]
    fn required_bond_is_capacity_proportional_above_floor() {
        // Faking 100x capacity costs ~100x bond (the Filecoin property) once above the floor.
        let one_unit_cost = PER_UNIT_BOND;
        assert_eq!(required_bond(1_000), 1_000 * one_unit_cost); // exactly at floor boundary.
        assert_eq!(required_bond(2_000), 2_000 * one_unit_cost);
        assert_eq!(required_bond(200_000), 200_000 * one_unit_cost);
        // proportional: 100x the capacity => 100x the bond (above the floor regime).
        assert_eq!(required_bond(200_000), 100 * required_bond(2_000));
    }

    #[test]
    fn required_bond_saturates_not_overflows() {
        // Absurd capacity must saturate, never panic/overflow (consensus-reachable).
        assert_eq!(required_bond(u64::MAX), (u64::MAX as u128).saturating_mul(PER_UNIT_BOND));
    }

    // ---- bond_gates_role: unbonded node can't publish capacity / earn reward ----

    #[test]
    fn unbonded_node_cannot_publish_capacity() {
        // No bond => not eligible to advertise any capacity (V1/V3 cost floor).
        assert!(!bond_gates_role(0, 0));
        assert!(!bond_gates_role(0, 10_000));
        assert!(!bond_gates_role(T_FLOOR - 1, 0)); // just below the floor: still refused.
    }

    #[test]
    fn floor_bond_admits_low_capacity_ad_only() {
        // A floor bond covers capacity up to the floor's worth, not 100x it.
        assert!(bond_gates_role(T_FLOOR, 0));
        assert!(bond_gates_role(T_FLOOR, 1_000)); // required_bond(1_000) == T_FLOOR.
        assert!(!bond_gates_role(T_FLOOR, 1_001)); // needs > floor to advertise 1_001 units.
    }

    #[test]
    fn validate_capacity_ad_bond_matches_gate() {
        let host = [7u8; 32];
        assert!(!validate_capacity_ad_bond(&host, 0, 5));
        assert!(validate_capacity_ad_bond(&host, required_bond(5), 5));
        assert!(!validate_capacity_ad_bond(&host, required_bond(5) - 1, 5));
    }

    // ---- UptimeReward eligibility: genesis-exempt, else floor-bonded ----

    #[test]
    fn uptime_reward_genesis_exempt_but_bond_gated_after() {
        // Bootstrap (genesis weight) node mines without a bond — cold-start must not deadlock.
        assert!(uptime_reward_eligible(0, 1));
        // Post-bootstrap (no genesis weight): unbonded node can NOT earn UptimeReward.
        assert!(!uptime_reward_eligible(0, 0));
        assert!(!uptime_reward_eligible(T_FLOOR - 1, 0));
        // A floor-bonded node can.
        assert!(uptime_reward_eligible(T_FLOOR, 0));
    }

    // ---- job_bond_slice: slice = ceil(at_risk / P(detect)) ----

    #[test]
    fn slice_scales_inversely_with_detection_probability() {
        let at_risk = 100 * C;
        // P=1.0 (10_000 bps): slice == at_risk.
        assert_eq!(job_bond_slice(at_risk, PDETECT_BPS_DENOM), at_risk);
        // P=0.5 (5_000 bps): slice == 2 * at_risk (lower assurance => bigger slice).
        assert_eq!(job_bond_slice(at_risk, 5_000), 2 * at_risk);
        // P=0.25 (2_500 bps): slice == 4 * at_risk.
        assert_eq!(job_bond_slice(at_risk, 2_500), 4 * at_risk);
    }

    #[test]
    fn slice_rounds_up_never_under_locks() {
        // 1 base unit at P=0.3 (3_000 bps): exact = 10000/3000 = 3.33.. => ceil to 4.
        assert_eq!(job_bond_slice(1, 3_000), 4);
        // Exactly divisible: no spurious +1.
        assert_eq!(job_bond_slice(3, 10_000), 3);
        assert_eq!(job_bond_slice(2, 5_000), 4);
    }

    #[test]
    fn undetectable_job_locks_infinite_slice() {
        assert_eq!(job_bond_slice(1, 0), u128::MAX);
    }

    // ---- single_job_value_ceiling: bond * P(detect_current) (H22) ----

    #[test]
    fn value_ceiling_tracks_detection_probability() {
        let bond = 1_000 * C;
        assert_eq!(single_job_value_ceiling(bond, PDETECT_BPS_DENOM), bond); // P=1.0 => full bond.
        assert_eq!(single_job_value_ceiling(bond, 5_000), bond / 2); // P=0.5 => half.
        assert_eq!(single_job_value_ceiling(bond, 0), 0); // undetectable => admit nothing.
    }

    #[test]
    fn value_ceiling_clamps_probability_to_one() {
        let bond = 1_000 * C;
        // A bogus P > 1.0 is clamped so the ceiling never exceeds the bond.
        assert_eq!(single_job_value_ceiling(bond, 99_999), bond);
    }

    // ---- admit_job: the aggregate-exposure gate (H1 + H22) ----

    #[test]
    fn admit_locks_a_slice_when_headroom_suffices() {
        let bond = 1_000 * C;
        // value 100 credits at P=0.5: ceiling = bond*0.5 = 500 credits >= 100 OK; slice = 200.
        let v = 100 * C;
        assert_eq!(
            admit_job(bond, bond, v, 5_000),
            BondAdmission::Admit { slice: 200 * C }
        );
    }

    #[test]
    fn one_bond_cannot_back_k_concurrent_high_value_jobs() {
        // THE rehypothecation test (H1): bond = 1000 credits, P=1.0 so slice == value.
        // Each job is at the value ceiling (== bond). The FIRST job locks the whole bond; a SECOND
        // concurrent job of the same value finds zero unlocked headroom and is REFUSED.
        let bond = 1_000 * C;
        let v = 1_000 * C; // == ceiling at P=1.0.
        // First job: full headroom, admits, locks the entire bond.
        let first = admit_job(bond, bond, v, PDETECT_BPS_DENOM);
        assert_eq!(first, BondAdmission::Admit { slice: bond });
        // Second job, now with zero unlocked headroom (bond - first slice == 0): REFUSED.
        assert_eq!(admit_job(bond, 0, v, PDETECT_BPS_DENOM), BondAdmission::Refuse);
        // Even a tiny second job is refused once headroom is exhausted.
        assert_eq!(admit_job(bond, 0, 1, PDETECT_BPS_DENOM), BondAdmission::Refuse);
    }

    #[test]
    fn lower_assurance_exhausts_headroom_faster() {
        // At P=0.25 the slice is 4x the value, so a bond backs far fewer concurrent jobs — the dial
        // and the bond are one system (design 2(a)).
        let bond = 1_000 * C;
        let v = 100 * C; // ceiling at P=0.25 is bond*0.25 = 250 credits >= 100, OK.
        // slice = 4 * 100 = 400 credits. Two such jobs (800) fit; a third (1200) does not.
        let s = 400 * C;
        assert_eq!(admit_job(bond, bond, v, 2_500), BondAdmission::Admit { slice: s });
        assert_eq!(admit_job(bond, bond - s, v, 2_500), BondAdmission::Admit { slice: s });
        assert_eq!(admit_job(bond, bond - 2 * s, v, 2_500), BondAdmission::Refuse);
    }

    #[test]
    fn admit_refuses_value_above_ceiling_even_with_headroom() {
        // H22: a job whose value exceeds bond * P(detect_current) is refused even if raw headroom
        // would (naively) fit the slice — closes "reputation buys a cheaper cheat".
        let bond = 1_000 * C;
        // P=0.5 => ceiling = 500 credits. A 600-credit job exceeds the ceiling.
        let v = 600 * C;
        // Plenty of headroom available, but still refused on the ceiling.
        assert_eq!(admit_job(bond, u128::MAX, v, 5_000), BondAdmission::Refuse);
        // At the ceiling exactly it is admitted (slice = 2 * 500 = 1000 == bond).
        assert_eq!(
            admit_job(bond, bond, 500 * C, 5_000),
            BondAdmission::Admit { slice: bond }
        );
    }

    #[test]
    fn admit_refuses_undetectable_work() {
        assert_eq!(admit_job(u128::MAX, u128::MAX, 1, 0), BondAdmission::Refuse);
    }

    // ---- interim per-host concurrent high-value cap = 1 ----

    #[test]
    fn interim_cap_allows_one_then_refuses() {
        assert!(interim_high_value_cap_ok(0));
        assert!(!interim_high_value_cap_ok(1));
        assert!(!interim_high_value_cap_ok(5));
    }

    // ---- endogenous fraction (H5) ----

    #[test]
    fn endogenous_fraction_requires_earned_held_share() {
        // 25% required. total 1000 credits, need >= 250 endogenous.
        let total = 1_000 * C;
        assert!(endogenous_fraction_ok(250 * C, total));
        assert!(endogenous_fraction_ok(1_000 * C, total));
        assert!(!endogenous_fraction_ok(249 * C, total));
        assert!(!endogenous_fraction_ok(0, total));
        // No role yet (zero total) trivially satisfies.
        assert!(endogenous_fraction_ok(0, 0));
    }

    // ---- high-value routing gate (H3 fix 2) ----

    #[test]
    fn high_value_routing_gated_on_total_bonded() {
        assert!(!high_value_routing_allowed(0));
        assert!(!high_value_routing_allowed(T_THRESHOLD)); // strict >, not >=.
        assert!(high_value_routing_allowed(T_THRESHOLD + 1));
    }

    #[test]
    fn t_floor_is_nonzero_and_below_threshold() {
        // Sanity on the calibration constants: the floor is a real, non-zero early-network barrier
        // and the routing threshold sits above it.
        assert!(T_FLOOR > 0);
        assert!(T_THRESHOLD > T_FLOOR);
        assert_eq!(required_endogenous_fraction_bps(), REQUIRED_ENDOGENOUS_BPS);
    }
}
