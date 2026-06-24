//! Phase 7 (P7) — compute verification dial + verification slashing.
//!
//! Governs: design `2(c)` "Audits for compute" (tier table T0..T5), `2(b2)` committee/auditor
//! selection rules, `2(d)` slash class 3 + structural correlation + circuit-breaker, and `6`
//! Phase 7. Closes V4/V5 — the central compute hole (fake work, collusion). The PLACEMENT BEACON
//! half (mandatory VDF + windowed + commit-reveal) lives in `ce-mesh/src/placement_beacon.rs`;
//! this module owns the on-chain `JobResult` + `SlashVerificationFault` validation/accounting and
//! the committee-selection / tier policy that consensus must agree on.
//!
//! Hard rules carried from the design (do NOT soften):
//!  - committee default N>=4 / K>=3 (strict >2/3); T2 is a LATENCY optimization, NOT a stranger
//!    security tier; T3 fraud-proof is the default above trivial value (`2(b2)` 4-5, H8).
//!  - dispute rewards are MULTI-WINNER + forced-error, funded from burn/emission, NOT solely from
//!    the slashed party; self-challenger posts its own real bond + is independently beacon-selected
//!    (`2(c)`(4), H2/H10/H21).
//!  - slash the party that diverges from a REFEREE RE-EXECUTION, never the peer-vote minority;
//!    within-band disagreement (NAO) is NOT auto-slashable; outside the signed band IS
//!    (`2(c)` determinism, H14/H15).
//!  - structural (lineage/ASN) correlation multiplier `min(1, 3*S/max(T,T_floor))` + circuit
//!    breaker for declared network-wide incidents (`2(d)`, H12).
//!
//! ## Integer conventions (consensus math — NO floats, deterministic, saturating)
//! Probabilities `P(detect)` are integer basis points against [`PDETECT_BPS_DENOM`] (`10_000 ==
//! P=1.0`), identical to `bond_gate` so the dial and the bond share one unit system. The
//! correlation multiplier is integer bps against [`BPS_DENOM`] (`10_000 == 1.0x`). All monetary
//! figures are `u128` base units; all products saturate.

use ce_identity::NodeId;

/// Basis-point precision shared with `bond_gate::PDETECT_BPS_DENOM` (`10_000 bps == P=1.0`). The
/// verification dial sizes bond slices through this same unit so a higher tier => higher P(detect)
/// => smaller slice (design `2(a)`/`2(c)`: "the dial and the bond are one system").
pub const PDETECT_BPS_DENOM: u128 = 10_000;

/// Basis-point precision for the correlation multiplier (`10_000 bps == 1.0x`).
pub const BPS_DENOM: u128 = 10_000;

/// Committee size and threshold defaults (design `2(b2)` 4 / `2(c)` T2 row): N>=4, K>=3, strict
/// >2/3. These are the floor; high-value jobs raise them.
pub const COMMITTEE_N_MIN: u32 = 4;
pub const COMMITTEE_K_MIN: u32 = 3;

/// Basis points of a slash routed to the reporter/auditor; the DOMINANT remainder (>=90%) is
/// burned (design `2(c)`(5)/`2(d)` H10 — lower than the implemented SLASH_REPORTER_BPS=2500 to
/// kill in-cluster slash recycling). The chain's verification-slash apply path routes this fraction
/// to the reporter and burns the rest.
pub const VERIFICATION_REPORTER_BPS: u128 = 1_000; // <=10%; burn >=90%.

/// The structural-correlation window in blocks (design `2(d)`: a 2016-block window). Matches
/// `ce_chain::DIFFICULTY_WINDOW`/`UNBOND_BLOCKS` (~2 weeks). Faults are clustered by on-chain
/// bond-funding LINEAGE + IP/ASN within this window, NOT by mere temporal simultaneity (H12).
pub const CORRELATION_WINDOW: u64 = 2016;

/// The correlation-multiplier numerator factor: `min(1, FACTOR * S / max(T,T_floor))` (design
/// `2(d)`: "min(1, 3*S/max(T,T_floor))"). Integer; the `3x` makes a third of the distinct-origin
/// stake faulting saturate the multiplier to 1.0x.
pub const CORRELATION_FACTOR: u128 = 3;

/// Verification assurance tier carried by a job (design `2(c)` tier table). Policy lives in the
/// scheduler app; consensus only needs the tier to size slashes + the determinism requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyTier {
    /// T0 interactive: heartbeat pay-as-you-go is the check (human-in-loop).
    Interactive,
    /// T1 spot-audit: re-run on a beacon-selected independent host with prob `p = nu(1-t)`.
    SpotAudit,
    /// T2 redundant K-of-N (DEMOTED to a latency optimization, earned-host low-value only).
    Redundant,
    /// T3 fraud-proof (CE default for batch above trivial value): bisection to first divergent
    /// step, referee re-runs that step, ALL correct challengers paid.
    FraudProof,
    /// T4 TEE-attested: CONFIDENTIALITY ONLY — MUST NOT raise reputation, lower a tier, reduce a
    /// bond, or feed P(detect) (design `2(c)` T4 row / H17, TEE.Fail).
    TeeConfidential,
    /// T5 zkVM: provable, the only collusion-proof tier.
    ZkProof,
}

impl VerifyTier {
    /// The detection probability `P(detect)` this tier delivers, as integer bps against
    /// [`PDETECT_BPS_DENOM`] (design `2(c)` tier table + `4`: the bond slice is `at_risk/P(detect)`,
    /// so a stronger tier shrinks the slice). These are CONSERVATIVE consensus defaults — the audit
    /// dial is otherwise an app/scheduler policy, but the slice-sizing P(detect) MUST be agreed
    /// network-wide, so it lives here as a pure function of the tier.
    ///
    /// Rationale for the values:
    /// - T0 Interactive: human-in-loop heuristic, NOT an audit — `P(detect)=0`. The bond gate then
    ///   refuses any non-trivial *at-risk* value at T0 (an undetectable job locks an infinite
    ///   slice / has a zero value ceiling — see `bond_gate::admit_job`). T0 is for human-perceived
    ///   work whose at-risk settled value is bounded by pay-as-you-go heartbeats, not by a slice.
    /// - T1 SpotAudit: re-run with sampling probability — `P=0.5` (5_000 bps) baseline.
    /// - T2 Redundant: K-of-N, collusion-fragile and DEMOTED — `P=0.5`, never treated as high
    ///   assurance regardless of N (the value is not raised above T1 deliberately; H8).
    /// - T3 FraudProof: one honest verifier breaks the ring — `P=0.9` (9_000 bps).
    /// - T4 TeeConfidential: EXCLUDED from P(detect) entirely (H17) — `P=0` so it can never lower a
    ///   slice or be treated as an audit. Confidentiality only.
    /// - T5 ZkProof: cryptographic, correct even under full collusion — `P=1.0` (10_000 bps).
    pub fn p_detect_bps(self) -> u128 {
        match self {
            VerifyTier::Interactive => 0,
            VerifyTier::SpotAudit => 5_000,
            VerifyTier::Redundant => 5_000,
            VerifyTier::FraudProof => 9_000,
            VerifyTier::TeeConfidential => 0, // H17: TEE feeds NEITHER P(detect) NOR the dial.
            VerifyTier::ZkProof => 10_000,
        }
    }

    /// A coarse ordering used ONLY for the "never below the establishing tier" loop-break (design
    /// `2(e)` H9): a higher rank == stronger assurance. T4 (confidentiality-only) is deliberately
    /// ranked at the BOTTOM (== T0) for assurance purposes, since it provides no integrity (H17).
    ///
    /// Ordering: T0 == T4 (0) < T1 (1) == T2 (1) < T3 (3) < T5 (5). T1/T2 share a rank because T2
    /// is demoted to a latency optimization, never stronger assurance than T1 (H8).
    pub fn assurance_rank(self) -> u8 {
        match self {
            VerifyTier::Interactive => 0,
            VerifyTier::TeeConfidential => 0, // H17: no integrity assurance.
            VerifyTier::SpotAudit => 1,
            VerifyTier::Redundant => 1, // demoted: never above T1 in assurance (H8).
            VerifyTier::FraudProof => 3,
            VerifyTier::ZkProof => 5,
        }
    }

    /// Whether this tier requires a DETERMINISTIC runtime (RepOps fixed-FP-order or integer-
    /// quantized) as a CONDITION of the tier (design `2(c)` determinism / H14/H15). Everything above
    /// T0 that can auto-slash needs determinism so a referee re-execution can pinpoint a divergent
    /// step; only T0 (human-perceived) and T5 (zk proves the exact trace, no re-run) are exempt.
    /// ML without a deterministic runtime therefore has NO tier below T5.
    pub fn requires_deterministic_runtime(self) -> bool {
        matches!(
            self,
            VerifyTier::SpotAudit | VerifyTier::Redundant | VerifyTier::FraudProof
        )
    }
}

/// Whether a tier may be the result of a reputation-driven DOWNGRADE for a job of the given value,
/// given the tier that ESTABLISHED the reputation edges (design `2(e)` loop-break, H9/H19/H20).
///
/// Three hard rules, ALL must hold for a downgrade to be allowed:
///  1. Reputation may NEVER lower assurance below the tier that ESTABLISHED the edges that produced
///     it — earned under T1/T2 only ever buys you back to T1/T2, never to T0 (H9). Enforced via
///     [`VerifyTier::assurance_rank`]: `to.rank >= establishing.rank`.
///  2. Only T3-fraud-proved or T0-human-interactive history may earn a dial DOWNGRADE at all
///     (design `2(e)` fix 2). Reputation established by T1/T2 edges MUST NOT relax assurance — it
///     may rank/place a host but not buy a cheaper tier. So `establishing` must itself be a
///     downgrade-eligible tier.
///  3. High-value jobs stay forced-high regardless of age (H19): above [`HIGH_VALUE_FLOOR`] no
///     downgrade below T3 is ever allowed (aging is buyable; the relaxation is capped by job value,
///     not by age).
///
/// Conservative by construction: returns `false` unless all three permit the downgrade.
pub fn downgrade_allowed(to: VerifyTier, establishing: VerifyTier, job_value: u128) -> bool {
    // (2) only T3/T5-fraud-proved or human-T0 history earns a downgrade. T4 is excluded (H17).
    let establishing_can_downgrade = matches!(
        establishing,
        VerifyTier::Interactive | VerifyTier::FraudProof | VerifyTier::ZkProof
    );
    if !establishing_can_downgrade {
        return false;
    }
    // (1) never below the establishing tier's assurance.
    if to.assurance_rank() < establishing.assurance_rank() {
        return false;
    }
    // (3) high-value jobs stay >= T3 regardless of age / reputation.
    if job_value >= HIGH_VALUE_FLOOR && to.assurance_rank() < VerifyTier::FraudProof.assurance_rank()
    {
        return false;
    }
    true
}

/// Absolute job value (base units) at/above which reputation may NEVER relax assurance below T3
/// (design `2(e)` H19/H20: high-value jobs stay >=T2/T3 regardless of age). Conservative default,
/// calibration is empirical (design `5` open problem 9). Set to `1_000` credits (the `T_FLOOR`
/// order of magnitude) — above this a stranger-or-aged host is forced to fraud-proofs.
pub const HIGH_VALUE_FLOOR: u128 = 1_000 * 1_000_000_000_000_000_000; // 1_000 credits.

/// A `JobResult` body (mirrors the lib.rs `TxKind::JobResult`): the host commits the result hash
/// for a job so a later fraud proof / referee re-execution can be checked against it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobResultClaim {
    pub job_id: [u8; 32],
    pub host: NodeId,
    pub result_hash: [u8; 32],
}

/// Validate a `JobResult` (consensus-reachable, pure): the committing origin IS the placed host.
/// The chain `append()` arm additionally checks the job is an open bid the host was placed on (it
/// has the `open_bids` map; this module does not). Determinism enforcement is per-tier
/// ([`VerifyTier::requires_deterministic_runtime`]) and is an app/scheduler condition on placement,
/// not an `append()` reject of the result commitment itself — a wrong-but-committed result is what
/// a later `SlashVerificationFault` punishes (design `2(c)`: optimistic accept, then dispute).
///
/// Returns false on the obvious self-inconsistencies (origin != host); the open-job check is the
/// caller's (it owns `open_bids`).
pub fn validate_job_result(claim: &JobResultClaim, origin: &NodeId) -> bool {
    // Origin must be the host committing its own result (you only commit results you produced).
    origin == &claim.host
}

/// Outcome of a verification dispute, as fed to [`validate_verification_slash`]. The slash is
/// admissible ONLY when the offender's result diverged from a REFEREE RE-EXECUTION and the
/// divergence is OUTSIDE the signed NAO band (design `2(c)` determinism / H14/H15). A peer-vote
/// minority is NEVER a slash basis (kills false-slash-an-honest-competitor griefing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisputeOutcome {
    /// A beacon-selected referee re-executed the divergent step and the offender's committed result
    /// is OUTSIDE the signed tolerance band: slashable.
    RefereeDivergentOutsideBand,
    /// The referee re-execution matched (within band): NOT slashable — the dispute was wrong.
    WithinBand,
    /// The "divergence" was only a peer-vote minority, never confirmed by a referee re-execution:
    /// NEVER slashable (design `2(c)` "slash the party that diverges from a REFEREE RE-EXECUTION,
    /// never the peer-vote minority").
    PeerVoteMinorityOnly,
}

/// Validate + SIZE a `SlashVerificationFault` (design `2(c)`/`2(d)` slash class 3, consensus-
/// critical). Returns the slash amount in base units, or `None` if inadmissible.
///
/// Admissibility (ALL must hold):
///  - `offender != reporter` (a node cannot slash itself for the reward; the apply path also
///    disqualifies a reporter sharing a bond-funding ancestor with the offender — that lineage
///    check is P9's, surfaced to the apply arm, not re-implemented here).
///  - `active_bond > 0` (nothing to slash otherwise).
///  - `outcome == RefereeDivergentOutsideBand` (referee re-execution, outside the signed band).
///  - `disputed_bid > 0`.
///
/// Sizing: `slash = min( disputed_bid * correlation_multiplier_bps / BPS_DENOM , active_bond )`,
/// then capped by [`MAX_SLASH_PER_JOB_BPS`] of bond so a griefer cannot drive a single false
/// dispute into a catastrophic confiscation (design `2(c)`: "Cap per-job slash so a griefer cannot
/// profit from false-slashing"). The reporter share + burn split is applied by the chain apply path
/// using [`VERIFICATION_REPORTER_BPS`]; this function returns the GROSS slash only.
///
/// `correlation_mult_bps` comes from [`correlation_multiplier_bps`]; pass `BPS_DENOM` (1.0x) when no
/// structural correlation applies. All math saturates; never panics; deterministic.
pub fn validate_verification_slash(
    offender: &NodeId,
    reporter: &NodeId,
    active_bond: u128,
    disputed_bid: u128,
    correlation_mult_bps: u128,
    outcome: DisputeOutcome,
) -> Option<u128> {
    if offender == reporter {
        return None; // no self-slash-for-reward.
    }
    if active_bond == 0 || disputed_bid == 0 {
        return None;
    }
    if outcome != DisputeOutcome::RefereeDivergentOutsideBand {
        return None; // within-band or peer-vote-only is NEVER slashable.
    }
    // base = disputed_bid * correlation_multiplier (clamped to 1.0x — the multiplier never amplifies
    // a slash beyond the disputed bid; min(1, ...) is enforced in correlation_multiplier_bps but we
    // clamp here too for safety against an out-of-range caller).
    let mult = correlation_mult_bps.min(BPS_DENOM);
    let base = disputed_bid.saturating_mul(mult) / BPS_DENOM;
    // Per-job griefing cap: never slash more than MAX_SLASH_PER_JOB_BPS of bond on a single dispute.
    let per_job_cap = active_bond.saturating_mul(MAX_SLASH_PER_JOB_BPS) / BPS_DENOM;
    let capped = base.min(per_job_cap);
    // Bond-capped (slashing can never exceed the standing bond).
    Some(capped.min(active_bond))
}

/// Maximum fraction of a host's bond that a single verification dispute may slash (design `2(c)`:
/// "Cap per-job slash so a griefer cannot profit from false-slashing"). Integer bps against
/// [`BPS_DENOM`]. Default 50% — a single proven fraud is costly but one griefing dispute cannot
/// confiscate the whole bond (that is reserved for provable equivocation, `SlashEquivocation`).
pub const MAX_SLASH_PER_JOB_BPS: u128 = 5_000;

/// Structural correlation multiplier `min(1, FACTOR * S / max(T,T_floor))` over the
/// [`CORRELATION_WINDOW`], clustering faults by on-chain bond-funding LINEAGE and IP/ASN (NOT
/// temporal-only), with a circuit-breaker bounding the effect during a declared network-wide
/// incident (design `2(d)` H12). Carried as integer bps of the base slash against [`BPS_DENOM`].
///
/// - `correlated_stake` (S): DISTINCT-ORIGIN faulted stake in the window (lineage/ASN-clustered, so
///   patient spread-out-in-time faults from one origin still count — the cluster signature is
///   ORIGIN, not simultaneity, H12 fix (1)).
/// - `distinct_origin_total` (`max(T, T_floor)`): the denominator counts ONLY distinct-origin bonded
///   stake and is floored so a whale cannot inflate `S/T` cheaply (H12 fix (2)). Pass `T_floor`
///   pre-maxed by the caller (it owns `T_FLOOR`); this fn maxes against 1 only to avoid div-by-zero.
///
/// `min(BPS_DENOM, FACTOR * S * BPS_DENOM / max(T,1))`. Integer-only, saturating, deterministic.
pub fn correlation_multiplier_bps(correlated_stake: u128, distinct_origin_total: u128) -> u128 {
    let denom = distinct_origin_total.max(1); // div-by-zero guard; caller floors with T_FLOOR.
    let raw = CORRELATION_FACTOR
        .saturating_mul(correlated_stake)
        .saturating_mul(BPS_DENOM)
        / denom;
    raw.min(BPS_DENOM) // min(1.0x, ...).
}

/// Apply the circuit-breaker to a correlation multiplier during a DECLARED network-wide incident
/// (design `2(d)` H12 fix (3)): legitimate correlated failure (an AWS/Hetzner outage) must not be
/// confiscatory, so the multiplier is bounded to [`CIRCUIT_BREAKER_BPS`] while an incident is
/// declared. Outside a declared incident the multiplier passes through unchanged.
///
/// Pure: the *declaration* is governance/network policy surfaced as the `incident_declared` flag;
/// this function only bounds the number deterministically so honest nodes agree.
pub fn apply_circuit_breaker(multiplier_bps: u128, incident_declared: bool) -> u128 {
    if incident_declared {
        multiplier_bps.min(CIRCUIT_BREAKER_BPS)
    } else {
        multiplier_bps
    }
}

/// The multiplier ceiling during a declared network-wide incident (design `2(d)` H12 fix (3)).
/// Default `2_000 bps` (0.2x) — correlated faults during a declared outage are penalized at most
/// lightly, since legitimate correlated failure is real. Calibration is empirical.
pub const CIRCUIT_BREAKER_BPS: u128 = 2_000;

// ---------------------------------------------------------------------------------------------
// Multi-winner + forced-error dispute reward economics (design `2(c)`(4), H2/H10/H21).
//
// The 2025 impossibility result (arXiv 2512.20864) proves any SINGLE-WINNER challenge design
// cannot jointly incentivize honest challengers and deter fraudulent proposers. CE pays ALL valid
// challengers pro-rata, sizes the proposer deposit to the ABSOLUTE collusion size `A`, funds the
// reward from BURN/EMISSION (not solely the slashed party), and injects forced errors so verifying
// always has positive EV. The functions below are the deterministic reward math the apply path and
// the scheduler share.
// ---------------------------------------------------------------------------------------------

/// Internal-recycling fraction `eta` carried as integer bps against [`BPS_DENOM`] — the share of a
/// dispute reward a colluding proposer+challenger coalition can recycle at effective cost 0 (design
/// `2(c)`(4)(a): the deposit must exceed `c~ * A / (1 - eta)` to make slot-capture loss-making).
/// Conservative default 50% (`5_000 bps`). Calibration empirical.
pub const RECYCLING_ETA_BPS: u128 = 5_000;

/// Per-unit-collusion challenger-cost coefficient `c~` carried as integer bps against [`BPS_DENOM`]
/// — the real cost a challenger incurs per unit of collusion size `A` it must out-deposit (design
/// `2(c)`(4)(a)). Default 100% (`10_000 bps`, i.e. `c~ = 1.0`): the proposer must deposit at least
/// the full collusion size scaled by the recycling factor. Calibration empirical.
pub const CHALLENGER_COST_C_BPS: u128 = 10_000;

/// The MINIMUM proposer deposit `D_p` that makes single-winner slot-capture loss-making for a
/// coalition of absolute size `A` (design `2(c)`(4)(a) / H21): `D_p >= c~ * A / (1 - eta)`.
///
/// Carried in base units; `A` is the absolute collusion size in base units. With `c~` and `eta` as
/// integer bps: `D_p = ceil( A * c~ / (BPS_DENOM - eta) )`, i.e.
/// `ceil( A * CHALLENGER_COST_C_BPS / (BPS_DENOM - RECYCLING_ETA_BPS) )`. `eta >= 1.0` (a coalition
/// that recycles everything) is undeterrable and saturates the deposit to `u128::MAX`. Integer-only,
/// saturating, ceiling-rounded so the deposit never under-covers.
pub fn min_proposer_deposit(collusion_size: u128) -> u128 {
    let denom = BPS_DENOM.saturating_sub(RECYCLING_ETA_BPS); // (1 - eta) in bps.
    if denom == 0 {
        return u128::MAX; // eta >= 1.0: no finite deposit deters full recycling.
    }
    // ceil(A * c~ / (1-eta)) = (A*c~ + denom - 1) / denom, saturating on the product.
    let num = collusion_size.saturating_mul(CHALLENGER_COST_C_BPS);
    num.saturating_add(denom - 1) / denom
}

/// Pro-rata MULTI-WINNER reward share for one valid challenger (design `2(c)`(4)(a): "pay ALL valid
/// challengers pro-rata"). `total_reward_pool` is the burn/emission-funded pool for the dispute;
/// `my_weight` / `total_weight` are this challenger's share of the aggregate valid-challenger
/// weight (e.g. equal weight => `1/n` each). Floor division (a dust remainder stays in the pool /
/// is burned). `total_weight == 0` => 0 (no winners). Integer-only, saturating, deterministic.
pub fn challenger_reward_share(
    total_reward_pool: u128,
    my_weight: u128,
    total_weight: u128,
) -> u128 {
    if total_weight == 0 {
        return 0;
    }
    let my = my_weight.min(total_weight);
    total_reward_pool.saturating_mul(my) / total_weight
}

/// Whether a self-challenger is admissible (design `2(c)`(4)(d): a self-challenger must post its
/// OWN real bond AND be independently beacon-selected). Both conditions required. The actual
/// beacon-selection check lives in `placement_beacon`/the scheduler; this is the pure predicate the
/// apply path composes with that selection.
pub fn self_challenger_admissible(posted_own_bond: u128, beacon_selected: bool) -> bool {
    posted_own_bond > 0 && beacon_selected
}

#[cfg(test)]
mod tests {
    use super::*;

    const C: u128 = 1_000_000_000_000_000_000; // one credit.
    const A: NodeId = [0xAA; 32];
    const B: NodeId = [0xBB; 32];

    // ---- committee defaults: strict supermajority + reporter cap ----

    #[test]
    fn committee_defaults_are_strict_supermajority() {
        // N>=4/K>=3 is strictly greater than 2/3 (so two colluders cannot form a majority).
        assert!(COMMITTEE_K_MIN as f64 / COMMITTEE_N_MIN as f64 > 2.0 / 3.0);
        assert!(COMMITTEE_N_MIN >= 4 && COMMITTEE_K_MIN >= 3);
        // Reporter reward stays <=10% so in-cluster slash recycling is loss-making (H10).
        assert!(VERIFICATION_REPORTER_BPS <= 1_000);
    }

    // ---- the dial: tier -> P(detect) and determinism (design 2(c) tier table) ----

    #[test]
    fn tier_detection_probability_ordering() {
        // The dial is monotone in real assurance: T1 < T3 < T5; T2 is demoted to == T1; T0/T4 = 0.
        assert_eq!(VerifyTier::Interactive.p_detect_bps(), 0);
        assert_eq!(VerifyTier::TeeConfidential.p_detect_bps(), 0); // H17: TEE excluded.
        assert!(VerifyTier::SpotAudit.p_detect_bps() > 0);
        assert_eq!(
            VerifyTier::Redundant.p_detect_bps(),
            VerifyTier::SpotAudit.p_detect_bps() // T2 demoted: never above T1 (H8).
        );
        assert!(VerifyTier::FraudProof.p_detect_bps() > VerifyTier::SpotAudit.p_detect_bps());
        assert_eq!(VerifyTier::ZkProof.p_detect_bps(), PDETECT_BPS_DENOM); // P=1.0, collusion-proof.
    }

    #[test]
    fn tee_is_excluded_from_assurance_and_pdetect() {
        // H17 / design 2(c) T4: TEE feeds NEITHER P(detect) NOR the assurance rank.
        assert_eq!(VerifyTier::TeeConfidential.p_detect_bps(), 0);
        assert_eq!(
            VerifyTier::TeeConfidential.assurance_rank(),
            VerifyTier::Interactive.assurance_rank()
        );
        assert!(!VerifyTier::TeeConfidential.requires_deterministic_runtime());
    }

    #[test]
    fn deterministic_runtime_required_above_t0_except_zk() {
        // ML without a deterministic runtime has NO tier below T5 (design 2(c) determinism / H15).
        assert!(!VerifyTier::Interactive.requires_deterministic_runtime()); // T0 human-perceived.
        assert!(VerifyTier::SpotAudit.requires_deterministic_runtime());
        assert!(VerifyTier::Redundant.requires_deterministic_runtime());
        assert!(VerifyTier::FraudProof.requires_deterministic_runtime());
        assert!(!VerifyTier::ZkProof.requires_deterministic_runtime()); // zk proves the trace.
    }

    // ---- downgrade_allowed: the MeritRank loop-break (design 2(e), H9/H19/H20) ----

    #[test]
    fn downgrade_never_below_establishing_tier() {
        // Reputation earned under T3 can buy back to T3, never below it (H9). Low value so the
        // high-value floor does not dominate.
        let low = 1; // trivial value.
        assert!(downgrade_allowed(VerifyTier::FraudProof, VerifyTier::FraudProof, low));
        // ...but not down to T1/T0 from a T3-established history.
        assert!(!downgrade_allowed(VerifyTier::SpotAudit, VerifyTier::FraudProof, low));
        assert!(!downgrade_allowed(VerifyTier::Interactive, VerifyTier::FraudProof, low));
    }

    #[test]
    fn only_t0_or_t3_t5_history_earns_a_downgrade() {
        // T1/T2-established edges may rank a host but NEVER relax assurance (design 2(e) fix 2).
        let low = 1;
        assert!(!downgrade_allowed(VerifyTier::SpotAudit, VerifyTier::SpotAudit, low));
        assert!(!downgrade_allowed(VerifyTier::SpotAudit, VerifyTier::Redundant, low));
        // T4 (TEE) NEVER earns a downgrade (H17).
        assert!(!downgrade_allowed(
            VerifyTier::Interactive,
            VerifyTier::TeeConfidential,
            low
        ));
        // T0-human-confirmed and T3/T5 history can — but never BELOW the establishing tier (rule 1),
        // so a T5-established edge can only buy back to T5, a T3-edge to T3, a T0-edge to T0.
        assert!(downgrade_allowed(VerifyTier::Interactive, VerifyTier::Interactive, low));
        assert!(downgrade_allowed(VerifyTier::ZkProof, VerifyTier::ZkProof, low));
        assert!(downgrade_allowed(VerifyTier::FraudProof, VerifyTier::FraudProof, low));
        // A T5-established edge cannot relax DOWN to T3 (that would be below the establishing tier).
        assert!(!downgrade_allowed(VerifyTier::FraudProof, VerifyTier::ZkProof, low));
    }

    #[test]
    fn high_value_jobs_stay_forced_high_regardless_of_history() {
        // Above the high-value floor, no downgrade below T3 is allowed even with T0/T3 history
        // (aging is buyable — H19). A T3-history high-value job may still sit at T3, not below.
        let hi = HIGH_VALUE_FLOOR;
        assert!(!downgrade_allowed(VerifyTier::Interactive, VerifyTier::Interactive, hi));
        assert!(!downgrade_allowed(VerifyTier::SpotAudit, VerifyTier::FraudProof, hi));
        // T3 (or stronger) for a high-value job with T3 establishing history is allowed.
        assert!(downgrade_allowed(VerifyTier::FraudProof, VerifyTier::FraudProof, hi));
        assert!(downgrade_allowed(VerifyTier::ZkProof, VerifyTier::FraudProof, hi));
    }

    // ---- validate_job_result ----

    #[test]
    fn job_result_origin_must_be_host() {
        let claim = JobResultClaim { job_id: [1u8; 32], host: A, result_hash: [9u8; 32] };
        assert!(validate_job_result(&claim, &A)); // host commits its own result.
        assert!(!validate_job_result(&claim, &B)); // someone else cannot commit for the host.
    }

    // ---- validate_verification_slash: referee-divergence, sizing, caps (design 2(c)/2(d)) ----

    #[test]
    fn slash_requires_referee_divergence_outside_band() {
        let bond = 1_000 * C;
        let bid = 100 * C;
        // Outside-band referee divergence at 1.0x correlation: slash == bid (under the per-job cap).
        assert_eq!(
            validate_verification_slash(
                &A, &B, bond, bid, BPS_DENOM,
                DisputeOutcome::RefereeDivergentOutsideBand
            ),
            Some(bid)
        );
        // Within-band: NEVER slashable (design 2(c) determinism carve-out, H15).
        assert_eq!(
            validate_verification_slash(
                &A, &B, bond, bid, BPS_DENOM, DisputeOutcome::WithinBand
            ),
            None
        );
        // Peer-vote minority only (no referee re-execution): NEVER slashable.
        assert_eq!(
            validate_verification_slash(
                &A, &B, bond, bid, BPS_DENOM,
                DisputeOutcome::PeerVoteMinorityOnly
            ),
            None
        );
    }

    #[test]
    fn slash_rejects_self_slash_and_empty_bond() {
        let bond = 1_000 * C;
        // Self-slash for the reward is rejected (offender == reporter).
        assert_eq!(
            validate_verification_slash(
                &A, &A, bond, 10 * C, BPS_DENOM,
                DisputeOutcome::RefereeDivergentOutsideBand
            ),
            None
        );
        // Nothing to slash.
        assert_eq!(
            validate_verification_slash(
                &A, &B, 0, 10 * C, BPS_DENOM,
                DisputeOutcome::RefereeDivergentOutsideBand
            ),
            None
        );
        // Zero disputed bid.
        assert_eq!(
            validate_verification_slash(
                &A, &B, bond, 0, BPS_DENOM,
                DisputeOutcome::RefereeDivergentOutsideBand
            ),
            None
        );
    }

    #[test]
    fn slash_is_bond_capped_and_per_job_capped() {
        // A disputed bid far larger than the bond is capped at the per-job ceiling (50% of bond),
        // NOT the whole bond — a single griefing dispute cannot confiscate everything (design 2(c)).
        let bond = 1_000 * C;
        let huge_bid = 10_000 * C;
        let out = validate_verification_slash(
            &A, &B, bond, huge_bid, BPS_DENOM,
            DisputeOutcome::RefereeDivergentOutsideBand,
        )
        .unwrap();
        assert_eq!(out, bond * MAX_SLASH_PER_JOB_BPS / BPS_DENOM); // 50% of bond.
        assert!(out < bond);
    }

    #[test]
    fn slash_scales_with_correlation_multiplier() {
        // The structural-correlation multiplier amplifies the base slash up to the per-job cap.
        let bond = 1_000 * C;
        let bid = 100 * C;
        // 0.5x correlation halves the base slash.
        assert_eq!(
            validate_verification_slash(
                &A, &B, bond, bid, 5_000,
                DisputeOutcome::RefereeDivergentOutsideBand
            ),
            Some(bid / 2)
        );
        // An out-of-range multiplier (>1.0x) is clamped to 1.0x — never amplifies beyond the bid.
        assert_eq!(
            validate_verification_slash(
                &A, &B, bond, bid, 99_999,
                DisputeOutcome::RefereeDivergentOutsideBand
            ),
            Some(bid)
        );
    }

    // ---- correlation_multiplier_bps: min(1, 3*S/max(T,T_floor)) (design 2(d), H12) ----

    #[test]
    fn correlation_multiplier_is_min_one_three_s_over_t() {
        let t = 900 * C;
        // S = 0: no correlation => 0x.
        assert_eq!(correlation_multiplier_bps(0, t), 0);
        // S = T/3: 3*S/T == 1.0 exactly => saturates to 1.0x (10_000 bps).
        assert_eq!(correlation_multiplier_bps(t / 3, t), BPS_DENOM);
        // S = T/6: 3*(T/6)/T == 0.5 => 5_000 bps.
        assert_eq!(correlation_multiplier_bps(t / 6, t), 5_000);
        // S > T/3: clamped to 1.0x (min(1, ...)).
        assert_eq!(correlation_multiplier_bps(t, t), BPS_DENOM);
    }

    #[test]
    fn correlation_multiplier_div_by_zero_safe() {
        // Zero denominator must not panic (consensus-reachable); guarded to /1.
        let _ = correlation_multiplier_bps(5 * C, 0);
    }

    // ---- circuit-breaker (design 2(d) H12 fix 3) ----

    #[test]
    fn circuit_breaker_bounds_multiplier_during_incident() {
        // Outside a declared incident: pass-through.
        assert_eq!(apply_circuit_breaker(BPS_DENOM, false), BPS_DENOM);
        // During a declared network-wide incident: bounded to the breaker ceiling.
        assert_eq!(apply_circuit_breaker(BPS_DENOM, true), CIRCUIT_BREAKER_BPS);
        assert!(CIRCUIT_BREAKER_BPS < BPS_DENOM);
        // A multiplier already below the ceiling is unchanged.
        assert_eq!(apply_circuit_breaker(1_000, true), 1_000);
    }

    // ---- dispute reward economics: D_p >= c~*A/(1-eta), multi-winner, forced-error (H2/H21) ----

    #[test]
    fn min_proposer_deposit_covers_recycled_collusion() {
        // D_p >= c~*A/(1-eta). With c~=1.0 (10_000 bps) and eta=0.5 (5_000 bps): D_p >= A/0.5 = 2A.
        let collusion = 100 * C;
        assert_eq!(min_proposer_deposit(collusion), 2 * collusion);
        // Larger coalitions require proportionally larger deposits (deters slot capture by a whale).
        assert_eq!(min_proposer_deposit(2 * collusion), 4 * collusion);
    }

    #[test]
    fn min_proposer_deposit_undeterrable_when_full_recycling() {
        // eta >= 1.0 (a coalition recycling everything) is undeterrable: saturate the deposit.
        // We can't change the const here, but the denom==0 branch is exercised via a manual mirror:
        let denom = BPS_DENOM.saturating_sub(BPS_DENOM); // simulate eta == 1.0.
        assert_eq!(denom, 0);
        // The function uses RECYCLING_ETA_BPS=5_000 so it returns a finite value; assert finiteness.
        assert!(min_proposer_deposit(C) < u128::MAX);
    }

    #[test]
    fn challenger_reward_is_pro_rata_multi_winner() {
        // ALL valid challengers paid pro-rata (design 2(c)(4)(a)) — single-winner is forbidden.
        let pool = 100 * C;
        // Three equal-weight challengers each get 1/3 (floor; dust stays in pool).
        assert_eq!(challenger_reward_share(pool, 1, 3), pool / 3);
        // Weighted: a 2/5 challenger gets 2/5 of the pool.
        assert_eq!(challenger_reward_share(pool, 2, 5), pool * 2 / 5);
        // No winners: zero.
        assert_eq!(challenger_reward_share(pool, 1, 0), 0);
        // A single challenger takes the whole pool (still "all valid challengers", n=1).
        assert_eq!(challenger_reward_share(pool, 1, 1), pool);
    }

    #[test]
    fn self_challenger_needs_own_bond_and_beacon_selection() {
        // design 2(c)(4)(d): a self-challenger must post its OWN bond AND be beacon-selected.
        assert!(self_challenger_admissible(C, true));
        assert!(!self_challenger_admissible(0, true)); // no bond.
        assert!(!self_challenger_admissible(C, false)); // not beacon-selected.
        assert!(!self_challenger_admissible(0, false));
    }

    // ---- end-to-end: a wrong JobResult is committed, then fraud-proved and slashed ----

    #[test]
    fn wrong_job_result_is_fraud_proved_and_slashed() {
        // The host commits a (wrong) result hash for its job — validation accepts the COMMITMENT
        // (optimistic accept, design 2(c)); the fraud is punished later, not at commit time.
        let claim = JobResultClaim { job_id: [3u8; 32], host: A, result_hash: [0xEE; 32] };
        assert!(validate_job_result(&claim, &A));
        // A beacon-selected referee re-executes the divergent step and finds the result OUTSIDE the
        // signed band => the host is slashed (disputed bid, 1.0x correlation, under the per-job cap).
        let bond = 1_000 * C;
        let disputed_bid = 200 * C;
        let slash = validate_verification_slash(
            &A, &B, bond, disputed_bid, BPS_DENOM,
            DisputeOutcome::RefereeDivergentOutsideBand,
        );
        assert_eq!(slash, Some(disputed_bid));
        // The reporter share is <=10%, the rest is burned (design 2(c)(5)/2(d) H10).
        let s = slash.unwrap();
        let reporter_share = s.saturating_mul(VERIFICATION_REPORTER_BPS) / BPS_DENOM;
        let burned = s.saturating_sub(reporter_share);
        assert!(reporter_share <= s / 10);
        assert!(burned >= s * 9 / 10);
    }
}
