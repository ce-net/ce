//! Phase 9 (P9) — bond-funding lineage graph + lineage-based earned-accounting.
//!
//! Governs: design `2(f)` "distinct-counterparty earned-accounting", `2(b2)` distinct-origin
//! committee rules, `2(d)` structural correlation, and `6` Phase 9. This module owns the on-chain
//! bond-funding / fund-flow LINEAGE graph that several phases read:
//!  - P4 (bond_gate): distinct bond != earned credits.
//!  - P7 (verification): distinct-origin committee supermajority + structural correlation
//!    clustering by lineage/ASN.
//!  - P8 (held_escrow): release schedule by distinct-COUNTERPARTY verified value.
//!  - P9 itself: `earned_work_score` refinement — distinct by BOND-FUNDING LINEAGE (NOT PeerId,
//!    which is Sybil-farmable, H6/H14/H21), recursively MeritRank-weighted, per-counterparty capped.
//!
//! NOTE (`2(f)`): this lineage-based refinement is a PREREQUISITE for Phase 8, not a later item —
//! until it lands, earned-weight/MeritRank may NOT relax the verification tier for any high-value
//! job. The transfer graph is already on-chain and auditable via `/history`; this builds the
//! lineage view over it. Integer-only, deterministic.

use ce_identity::NodeId;

/// Maximum hop distance within which two bonds tracing to a common on-chain funding ancestor are
/// treated as the same origin (design `2(c)`(5)/`2(f)` "within K hops"). TODO(P9): calibrate.
pub const LINEAGE_K_HOPS: u32 = 8;

/// Per-counterparty cap on contribution to `earned_work_score` (design `2(f)` "Cap per-counterparty
/// contribution"), in base units. TODO(P9): calibrate; 0 placeholder = uncapped until wired.
pub const PER_COUNTERPARTY_CAP: u128 = 0; // TODO(P9): set a real cap.

/// Whether two nodes' bonds/balances trace to a common on-chain funding source within
/// `LINEAGE_K_HOPS` (design `2(f)` "Distinct by BOND-FUNDING LINEAGE"). Used to discount
/// earned-credit and to seat distinct-origin committees.
///
/// TODO(P9): walk the on-chain transfer/funding graph; deterministic BFS bounded by K hops.
/// Conservative stub: treat identical nodes as common-origin, all others as distinct.
pub fn common_funding_origin(a: &NodeId, b: &NodeId) -> bool {
    a == b // TODO(P9): real K-hop lineage walk over the transfer graph.
}

/// The lineage-distinct, recursively-MeritRank-weighted, per-counterparty-capped earned-work score
/// for `node` (design `2(f)`). Replaces the naive `NodeStats.earned` sum for the purpose of
/// consensus weight + dial-downgrade eligibility once wired.
///
/// `raw_earned` is the per-counterparty earnings; `counterparty_merit_bps` weights each by the
/// giver's own MeritRank (recursively); lineage-common counterparties are collapsed to one origin.
///
/// TODO(P9): implement; integer-only. Identity stub returns the unweighted sum so the scaffold
/// preserves current behavior until the real construction lands.
pub fn lineage_earned_work_score(per_counterparty: &[(NodeId, u128, u128)]) -> u128 {
    // (counterparty, raw_earned, counterparty_merit_bps)
    per_counterparty
        .iter()
        .map(|(_, raw, _)| *raw)
        .fold(0u128, |a, b| a.saturating_add(b)) // TODO(P9): lineage + recursive weighting + cap.
}

/// Count the distinct funding ORIGINS represented in a set of nodes (design `2(b2)` distinct-origin
/// supermajority / `2(d)` structural-correlation denominator). Collapses common-origin nodes.
///
/// TODO(P9): partition by `common_funding_origin`. Stub counts unique node ids.
pub fn distinct_origin_count(nodes: &[NodeId]) -> usize {
    let mut seen: std::collections::HashSet<NodeId> = std::collections::HashSet::new();
    for n in nodes {
        seen.insert(*n);
    }
    seen.len() // TODO(P9): collapse by lineage, not by identity.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaffold_sums_unweighted() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let rows = [(a, 100u128, 10_000u128), (b, 50u128, 10_000u128)];
        assert_eq!(lineage_earned_work_score(&rows), 150);
        assert_eq!(distinct_origin_count(&[a, b, a]), 2);
        assert!(common_funding_origin(&a, &a));
        assert!(!common_funding_origin(&a, &b));
    }
}
