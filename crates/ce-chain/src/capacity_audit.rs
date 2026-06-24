//! Phase 6 (P6) — capacity audits: continuous, unpredictable, all-capacity, job-bound.
//!
//! Governs: design `2(c)` "Capacity audit (catches V3)" + `6` Phase 6. Closes V3 (fake capacity)
//! as a DETERRENT (heuristic, never proof — `5` problem 7). Replaces the defeatable periodic
//! benchmark (red-team H7/H16) with inline-probe + parallel-full-capacity + job-session-bound
//! challenges. A miss is provable by on-chain ABSENCE of a `ChallengeResponse` => self-healing
//! `FaultFee = 1/32 bond` (NOT confiscation — flaky-hardware safety valve), and disappearance must
//! be confirmed across >=3 independent relays over a multi-epoch window before any forfeiture
//! (design `2(d)` H18 — this depends on Phase 5 net hardening shipping with/before this).
//!
//! Wires the `CapacityAd`, `ChallengeResponse`, and `SlashCapacityChallenge` TxKinds (see lib.rs).
//! Pure chain-side validation + the FaultFee accounting; the actual benchmark execution + probe
//! issuance is a node/mesh driver (ce-node, ce-mesh placement_beacon), not consensus.

use ce_identity::NodeId;

/// FaultFee denominator: a missed capacity challenge costs `1/FAULT_FEE_DIVISOR` of the bond,
/// self-healing (design `2(d)` slash class 2; Filecoin 3.51-day fault-fee shape).
pub const FAULT_FEE_DIVISOR: u128 = 32;

/// The FaultFee charged for a single provable missed capacity challenge: `bond / 32`.
/// Integer-only; self-healing (recover and stop paying), NOT confiscation.
pub fn fault_fee(active_bond: u128) -> u128 {
    active_bond / FAULT_FEE_DIVISOR
}

/// Number of independent relays across which a host must be unreachable, over a multi-epoch
/// window, before disappearance is treated as a fault (design `2(c)`/`2(d)` H18 eclipse safety
/// valve). TODO(P6): wire to the Phase 5 net-hardening relay set.
pub const MIN_DISTINCT_RELAYS_FOR_FAULT: u32 = 3;

/// A capacity advertisement's on-chain payload (the `CapacityAd` TxKind body, mirrored here for
/// validation helpers). The host claims `capacity_units` and signs an equivocation-bindable
/// statement per epoch so two conflicting ads for one epoch are slashable via `SlashEquivocation`.
///
/// TODO(P6): finalize fields with the lib.rs TxKind::CapacityAd definition (keep them identical).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityClaim {
    pub host: NodeId,
    pub capacity_units: u64,
    pub epoch: u64,
}

/// Validate a `CapacityAd`: origin == host, bond gates the claimed capacity (P4 bond_gate), and
/// the claim's growth rate is capped (design `2(c)`: "Cap advertised C growth rate"). Returns
/// whether the ad is admissible.
///
/// TODO(P6): implement; call `crate::bond_gate::bond_gates_role` + growth-rate cap from chain
/// state. Identity stub for the scaffold.
pub fn validate_capacity_ad(_claim: &CapacityClaim, _active_bond: u128) -> bool {
    true // TODO(P6)
}

/// Validate a `ChallengeResponse`: it answers an outstanding beacon-seeded challenge bound to the
/// host's job session, within the deadline (design `2(c)` anti-collusion: byte-identical to normal
/// jobs, bound to the SAME execution context). Returns whether the response clears the challenge.
///
/// TODO(P6): implement deadline + session-binding + parallel-full-capacity sizing checks.
pub fn validate_challenge_response(_host: &NodeId, _epoch: u64) -> bool {
    true // TODO(P6)
}

/// Validate a `SlashCapacityChallenge`: a provable miss (on-chain absence of a `ChallengeResponse`
/// for a confirmed challenge) charges `fault_fee(bond)`, NOT the whole bond, and only after the
/// >=3-relay multi-epoch unreachability confirmation. Returns the FaultFee to charge, or None if
/// the slash is inadmissible (e.g. host responded, or disappearance not yet confirmed).
///
/// TODO(P6): implement; this is the consensus-critical accounting the append() arm calls.
pub fn validate_capacity_slash(_offender: &NodeId, _active_bond: u128) -> Option<u128> {
    None // TODO(P6): Some(fault_fee(bond)) when the miss is provable.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fault_fee_is_one_thirtysecond() {
        assert_eq!(fault_fee(32_000), 1_000);
        assert_eq!(fault_fee(31), 0); // floor division, sub-divisor bonds round to 0
    }
}
