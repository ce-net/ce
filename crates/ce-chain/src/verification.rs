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

use ce_identity::NodeId;

/// Committee size and threshold defaults (design `2(b2)` 4 / `2(c)` T2 row): N>=4, K>=3, strict
/// >2/3. These are the floor; high-value jobs raise them.
pub const COMMITTEE_N_MIN: u32 = 4;
pub const COMMITTEE_K_MIN: u32 = 3;

/// Basis points of a slash routed to the reporter/auditor; the DOMINANT remainder (>=90%) is
/// burned (design `2(c)`(5)/`2(d)` H10 — lower than the implemented SLASH_REPORTER_BPS=2500 to
/// kill in-cluster slash recycling). TODO(P7): wire lib.rs to use this for verification slashes.
pub const VERIFICATION_REPORTER_BPS: u128 = 1_000; // <=10%; burn >=90%.

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

/// Whether a tier may be the result of a reputation-driven DOWNGRADE for a job of the given value.
/// Design `2(e)` loop-break: reputation may NEVER lower the tier below the tier that ESTABLISHED
/// the edges that produced it, and high-value jobs stay >=T2/T3 regardless of age (H9/H19/H20).
///
/// TODO(P7): implement against the establishing-tier + job-value ceiling. Conservative stub:
/// allow no downgrade.
pub fn downgrade_allowed(_to: VerifyTier, _establishing: VerifyTier, _job_value: u128) -> bool {
    false // TODO(P7): only T3/T5-fraud-proved or human-T0 history earns a capped downgrade.
}

/// A `JobResult` body (mirrors the lib.rs TxKind::JobResult): the host commits the result hash for
/// a job so a later fraud proof / referee re-execution can be checked against it.
///
/// TODO(P7): finalize fields identical to TxKind::JobResult.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobResultClaim {
    pub job_id: [u8; 32],
    pub host: NodeId,
    pub result_hash: [u8; 32],
}

/// Validate a `JobResult`: origin == host, references an open job the host was placed on, and the
/// host ran a deterministic runtime where the tier requires it (design `2(c)` determinism — ML
/// without a deterministic runtime has no tier below T5).
///
/// TODO(P7). Identity stub for the scaffold.
pub fn validate_job_result(_claim: &JobResultClaim) -> bool {
    true // TODO(P7)
}

/// Validate a `SlashVerificationFault`: the offender's result diverged from a REFEREE
/// RE-EXECUTION (never a peer-vote minority), the divergence is outside the signed NAO band, and
/// the offender is the placed host. Returns the slash amount (disputed bid * multiplier, capped at
/// bond) or None if inadmissible. Caps per-job slash so a griefer cannot profit from false-slashing.
///
/// TODO(P7): implement; consensus-critical. The multiplier comes from `correlation_multiplier`.
pub fn validate_verification_slash(_offender: &NodeId, _active_bond: u128) -> Option<u128> {
    None // TODO(P7)
}

/// Structural correlation multiplier `min(1, 3*S/max(T,T_floor))` over the 2016-block window,
/// clustering faults by on-chain bond-funding LINEAGE and IP/ASN (NOT temporal-only), with a
/// circuit-breaker bounding the effect during a declared network-wide incident (design `2(d)`
/// H12). Carried as integer bps of the base slash.
///
/// `correlated_stake` is S (distinct-origin faulted stake in window), `distinct_origin_total` is
/// `max(T, T_floor)`. TODO(P7): `min(BPS_DENOM, 3 * S * BPS_DENOM / max(T,T_floor))`, plus the
/// circuit-breaker cap; integer-only.
pub fn correlation_multiplier_bps(correlated_stake: u128, distinct_origin_total: u128) -> u128 {
    let _ = (correlated_stake, distinct_origin_total);
    10_000 // TODO(P7): identity (1.0x) for the scaffold.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committee_defaults_are_strict_supermajority() {
        assert!(COMMITTEE_K_MIN as f64 / COMMITTEE_N_MIN as f64 > 2.0 / 3.0);
        assert!(VERIFICATION_REPORTER_BPS <= 1_000);
    }
}
