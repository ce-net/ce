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
//!
//! # Why lineage (not PeerId) — the wash-trade closure (design `2(f)`, red-team H6/H14/H21)
//!
//! The 80% settlement burn (P0/`f`) makes a wash cycle lossy but is "a one-time toll a patient whale
//! pays" — `earned_work_score` still counts burn-discounted self-dealing, so a whale who funds M
//! sock-puppet keys generates O(M^2) "distinct-counterparty" edges from M bonds and the naive
//! PeerId-distinct metric would *reward* buying identities. This module makes wash-trading by
//! patience unprofitable with three integer-deterministic constructions, all keyed on the on-chain
//! FUND-FLOW graph (already auditable, no new persisted state):
//!
//!  1. **Distinct by BOND-FUNDING LINEAGE, not PeerId.** Counterparties whose funds trace to a common
//!     on-chain origin within `LINEAGE_K_HOPS` are collapsed to a single origin. M sock-puppets funded
//!     from one wallet count as ONE counterparty, not M. A node's earnings from its OWN funding origin
//!     (self-dealing through puppets) contribute ZERO — the defining wash-trade case.
//!  2. **Recursively MeritRank-weighted.** Each counterparty's contribution is scaled by that
//!     counterparty's own standing (`merit_bps`); earnings from un-reputed cluster members (whose
//!     own merit is ~0 because *their* earnings trace back to the same origin) contribute ~0. This is
//!     the actual Tribler/MeritRank construction — feedback weighted by the giver's standing — applied
//!     to `earned_work_score`, not only to reputation (the PLAN previously applied it to one not both).
//!  3. **Per-counterparty (per-ORIGIN) cap.** No single funding origin may contribute more than
//!     `PER_COUNTERPARTY_CAP` to `earned_work_score`, so even a lineage-disjoint but high-volume
//!     single counterparty cannot dominate the score (limits a 2-operator collusion).

use ce_identity::NodeId;
use std::collections::{HashMap, HashSet, VecDeque};

/// Maximum hop distance within which two bonds tracing to a common on-chain funding ancestor are
/// treated as the same origin (design `2(c)`(5)/`2(f)` "within K hops"). TODO(P9): calibrate on live
/// data (design `5`(9): all thresholds are tuning, not theory).
pub const LINEAGE_K_HOPS: u32 = 8;

/// Per-counterparty (per-funding-ORIGIN) cap on contribution to `earned_work_score`
/// (design `2(f)` "Cap per-counterparty contribution"), in base units. Bounds how much a single
/// lineage-disjoint origin can pump the score — the 2-operator-collusion ceiling. `0` is the
/// scaffold sentinel meaning "uncapped"; the integrator sets a real cap when wiring
/// (TODO(P9): calibrate, e.g. a small multiple of one expected-tenure revenue).
pub const PER_COUNTERPARTY_CAP: u128 = 0;

/// Basis-point denominator for the recursive MeritRank weighting (`merit_bps / 10_000`).
pub const MERIT_BPS_DENOM: u128 = 10_000;

/// The on-chain fund-flow lineage graph: a directed view of "X funded Y" edges derived from
/// confirmed `Transfer` and bond-funding flows. Built deterministically from blocks (the transfer
/// graph is already on-chain — design `2(f)`); never persisted, rebuilt like the other `#[serde(skip)]`
/// caches. The lineage walk is a bounded BFS over the *reverse* edges (follow funds back to source).
#[derive(Debug, Clone, Default)]
pub struct LineageGraph {
    /// `funder -> {recipients}`: a directed edge `(from -> to)` for every confirmed fund flow.
    /// We walk it in reverse (recipient back to funders) to find a node's funding ancestors.
    incoming: HashMap<NodeId, HashSet<NodeId>>,
}

impl LineageGraph {
    /// Build a lineage graph from an explicit edge list `(from, to)` — `from` funded `to`. Pure and
    /// deterministic; the integrator feeds it the confirmed `Transfer { from, to, .. }` flows (and
    /// any other fund-flow edges) walked from `Chain::blocks`. Order-independent (a set per node).
    pub fn from_edges(edges: &[(NodeId, NodeId)]) -> Self {
        let mut incoming: HashMap<NodeId, HashSet<NodeId>> = HashMap::new();
        for (from, to) in edges {
            if from == to {
                continue; // self-loops carry no lineage information.
            }
            incoming.entry(*to).or_default().insert(*from);
        }
        Self { incoming }
    }

    /// Record one funding edge `from -> to` (`from` funded `to`).
    pub fn add_edge(&mut self, from: NodeId, to: NodeId) {
        if from != to {
            self.incoming.entry(to).or_default().insert(from);
        }
    }

    /// The set of funding ancestors of `node` reachable within `k` reverse hops, INCLUDING `node`
    /// itself (a node is trivially in its own lineage). Deterministic bounded BFS; a node with no
    /// recorded funders has lineage `{node}` (it is its own origin — e.g. a genesis/mined balance).
    pub fn ancestors_within(&self, node: &NodeId, k: u32) -> HashSet<NodeId> {
        let mut seen: HashSet<NodeId> = HashSet::new();
        let mut frontier: VecDeque<(NodeId, u32)> = VecDeque::new();
        seen.insert(*node);
        frontier.push_back((*node, 0));
        while let Some((cur, depth)) = frontier.pop_front() {
            if depth >= k {
                continue;
            }
            if let Some(funders) = self.incoming.get(&cur) {
                for f in funders {
                    if seen.insert(*f) {
                        frontier.push_back((*f, depth + 1));
                    }
                }
            }
        }
        seen
    }

    /// Whether `a` and `b` trace to a COMMON on-chain funding source within `LINEAGE_K_HOPS`
    /// (design `2(f)` "Distinct by BOND-FUNDING LINEAGE"). True iff their bounded funding-ancestor
    /// sets intersect (they share an origin, or one funded the other within K hops). Used to discount
    /// earned-credit and to seat distinct-origin committees. Symmetric and deterministic.
    pub fn common_funding_origin(&self, a: &NodeId, b: &NodeId) -> bool {
        if a == b {
            return true;
        }
        let anc_a = self.ancestors_within(a, LINEAGE_K_HOPS);
        // Walk b's ancestors and short-circuit on the first shared node.
        let mut seen: HashSet<NodeId> = HashSet::new();
        let mut frontier: VecDeque<(NodeId, u32)> = VecDeque::new();
        seen.insert(*b);
        frontier.push_back((*b, 0));
        if anc_a.contains(b) {
            return true;
        }
        while let Some((cur, depth)) = frontier.pop_front() {
            if depth >= LINEAGE_K_HOPS {
                continue;
            }
            if let Some(funders) = self.incoming.get(&cur) {
                for f in funders {
                    if anc_a.contains(f) {
                        return true;
                    }
                    if seen.insert(*f) {
                        frontier.push_back((*f, depth + 1));
                    }
                }
            }
        }
        false
    }

    /// A deterministic canonical ORIGIN representative for `node`: the lexicographically-smallest
    /// node id in its bounded funding-ancestor set. Two nodes with a common origin within K hops that
    /// is reachable from both will (usually) map to the same representative; the authoritative
    /// "are these the same origin?" test is `common_funding_origin`, but a canonical key is needed to
    /// PARTITION a set into origins in `O(n)` lookups. Deterministic (min over a set).
    pub fn origin_key(&self, node: &NodeId) -> NodeId {
        self.ancestors_within(node, LINEAGE_K_HOPS)
            .into_iter()
            .min()
            .unwrap_or(*node)
    }

    /// Partition `nodes` into distinct funding ORIGINS (design `2(b2)` distinct-origin supermajority /
    /// `2(d)` structural-correlation denominator). Collapses common-origin nodes via the union-find of
    /// `common_funding_origin`, so the count is robust to bond-splitting (M sock-puppets from one
    /// wallet count as 1). Returns the number of distinct origins. `O(n^2)` pairwise in the worst case
    /// — committees are small (`N>=4`), so this is fine; for large sets the integrator can switch to
    /// `origin_key` bucketing. Deterministic.
    pub fn distinct_origin_count(&self, nodes: &[NodeId]) -> usize {
        // Union-find over the pairwise common-origin relation: robust even when the shared ancestor
        // is reachable from each member but the members map to different `origin_key` minima.
        let uniq: Vec<NodeId> = {
            let mut s: Vec<NodeId> = nodes.to_vec();
            s.sort_unstable();
            s.dedup();
            s
        };
        let n = uniq.len();
        let mut parent: Vec<usize> = (0..n).collect();
        fn find(parent: &mut [usize], mut x: usize) -> usize {
            while parent[x] != x {
                parent[x] = parent[parent[x]];
                x = parent[x];
            }
            x
        }
        for i in 0..n {
            for j in (i + 1)..n {
                if self.common_funding_origin(&uniq[i], &uniq[j]) {
                    let (ri, rj) = (find(&mut parent, i), find(&mut parent, j));
                    if ri != rj {
                        parent[ri.max(rj)] = ri.min(rj);
                    }
                }
            }
        }
        let mut roots: HashSet<usize> = HashSet::new();
        for i in 0..n {
            let r = find(&mut parent, i);
            roots.insert(r);
        }
        roots.len()
    }
}

/// One counterparty's contribution to a node's earned-work score, before lineage collapsing /
/// weighting / capping. `merit_bps` is the counterparty's OWN MeritRank standing in basis points
/// (recursive weighting input, design `2(f)`); `raw_earned` is the post-burn credits this node
/// earned hosting work for that counterparty (mirrors `NodeStats.earned`'s post-burn semantics).
#[derive(Debug, Clone, Copy)]
pub struct CounterpartyEarning {
    /// The counterparty (payer) this node earned credits from.
    pub counterparty: NodeId,
    /// Post-burn credits earned from this counterparty (base units).
    pub raw_earned: u128,
    /// The counterparty's own MeritRank standing, in basis points (`0..=MERIT_BPS_DENOM`, clamped).
    pub merit_bps: u128,
}

/// The lineage-distinct, recursively-MeritRank-weighted, per-counterparty-capped earned-work score
/// for `earner` (design `2(f)`). This is the Sybil-resistant replacement for the naive
/// `NodeStats.earned` sum that `Chain::earned_work_score` returns today; the integrator swaps it in
/// behind that function (it is a strict refinement — a single honest lineage-disjoint counterparty
/// with full merit and an uncapped cap reproduces the raw sum).
///
/// Construction (integer-only, deterministic):
///  1. **Drop self-dealing.** Earnings from a counterparty sharing `earner`'s OWN funding origin are
///     wash trades (the puppet is funded by the earner) and contribute ZERO.
///  2. **Collapse by funding origin.** Counterparties sharing a funding origin are merged into one
///     origin bucket (so M sock-puppets from one wallet are one counterparty, not M). The bucket's
///     merit is the MINIMUM merit among its members (a cluster is only as reputable as its weakest
///     laundering hop — prevents one high-merit front legitimizing a cluster).
///  3. **Recursive MeritRank weight.** Each origin bucket's earnings are scaled by `merit_bps`.
///  4. **Per-origin cap.** Each bucket contributes at most `PER_COUNTERPARTY_CAP` (0 = uncapped).
///
/// `graph` supplies the on-chain fund-flow lineage; `earner` is the node being scored.
pub fn lineage_earned_work_score(
    graph: &LineageGraph,
    earner: &NodeId,
    earnings: &[CounterpartyEarning],
) -> u128 {
    // Bucket earnings by funding origin, dropping self-dealing. We accumulate raw earnings per origin
    // representative and track the minimum merit seen for that origin (weakest-hop rule).
    // `merged_origin` maps each origin representative to (raw_earned, min_merit_bps).
    let mut origins: Vec<NodeId> = Vec::new();
    let mut raw_by_origin: HashMap<NodeId, u128> = HashMap::new();
    let mut merit_by_origin: HashMap<NodeId, u128> = HashMap::new();

    for e in earnings {
        // 1. Self-dealing: counterparty shares the earner's own funding origin → wash trade → 0.
        if graph.common_funding_origin(earner, &e.counterparty) {
            continue;
        }
        // 2. Collapse: find an existing origin bucket this counterparty is common-origin with.
        let merit = e.merit_bps.min(MERIT_BPS_DENOM);
        let mut placed: Option<NodeId> = None;
        for o in &origins {
            if graph.common_funding_origin(o, &e.counterparty) {
                placed = Some(*o);
                break;
            }
        }
        let key = match placed {
            Some(o) => o,
            None => {
                origins.push(e.counterparty);
                e.counterparty
            }
        };
        *raw_by_origin.entry(key).or_insert(0) = raw_by_origin
            .get(&key)
            .copied()
            .unwrap_or(0)
            .saturating_add(e.raw_earned);
        // Weakest-hop merit: the minimum merit among the bucket's members.
        let cur = merit_by_origin.entry(key).or_insert(merit);
        if merit < *cur {
            *cur = merit;
        }
    }

    // 3 + 4. Weight each origin bucket by its merit and cap it, then sum. Deterministic order
    // (iterate the `origins` vec, which preserves first-seen order) — sum is commutative anyway.
    let mut total: u128 = 0;
    for o in &origins {
        let raw = raw_by_origin.get(o).copied().unwrap_or(0);
        let merit = merit_by_origin.get(o).copied().unwrap_or(0);
        // Recursive MeritRank weight: raw * merit_bps / 10_000, integer-only (floor).
        let weighted = mul_bps(raw, merit);
        let capped = if PER_COUNTERPARTY_CAP == 0 {
            weighted
        } else {
            weighted.min(PER_COUNTERPARTY_CAP)
        };
        total = total.saturating_add(capped);
    }
    total
}

/// `value * bps / 10_000`, integer-only with a 256-bit-safe intermediate (no float, no overflow on
/// `u128 * 10_000`). Floors. Used for the recursive MeritRank weighting.
fn mul_bps(value: u128, bps: u128) -> u128 {
    // value and bps are each <= u128::MAX / 10_000 in practice (bps <= 10_000), but guard anyway with
    // a widening multiply via u256-by-hand: split value into hi/lo 64-bit limbs.
    let bps = bps.min(MERIT_BPS_DENOM);
    if bps == 0 {
        return 0;
    }
    if bps == MERIT_BPS_DENOM {
        return value;
    }
    // value * bps can exceed u128 for huge `value`; do (value / DENOM) * bps + ((value % DENOM)*bps)/DENOM.
    let q = value / MERIT_BPS_DENOM;
    let r = value % MERIT_BPS_DENOM;
    q.saturating_mul(bps)
        .saturating_add(r.saturating_mul(bps) / MERIT_BPS_DENOM)
}

/// Count the distinct funding ORIGINS represented in a set of nodes (design `2(b2)` distinct-origin
/// supermajority / `2(d)` structural-correlation denominator). Free function over an explicit graph;
/// collapses common-origin nodes (so bond-splitting does not inflate the count).
pub fn distinct_origin_count(graph: &LineageGraph, nodes: &[NodeId]) -> usize {
    graph.distinct_origin_count(nodes)
}

/// Whether two nodes trace to a common on-chain funding source within `LINEAGE_K_HOPS`. Free-function
/// form over an explicit graph (the contract's named entry point). See
/// [`LineageGraph::common_funding_origin`].
pub fn common_funding_origin(graph: &LineageGraph, a: &NodeId, b: &NodeId) -> bool {
    graph.common_funding_origin(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> NodeId {
        [b; 32]
    }

    #[test]
    fn empty_graph_treats_distinct_ids_as_distinct_origins() {
        let g = LineageGraph::default();
        let a = id(1);
        let b = id(2);
        assert!(common_funding_origin(&g, &a, &a)); // reflexive
        assert!(!common_funding_origin(&g, &a, &b));
        assert_eq!(distinct_origin_count(&g, &[a, b, a]), 2);
    }

    #[test]
    fn shared_funder_within_k_hops_is_common_origin() {
        // origin O funds A and B directly: A and B share an origin.
        let o = id(10);
        let a = id(11);
        let b = id(12);
        let g = LineageGraph::from_edges(&[(o, a), (o, b)]);
        assert!(common_funding_origin(&g, &a, &b));
        assert!(common_funding_origin(&g, &o, &a));
        // A and B and O all collapse to one origin.
        assert_eq!(distinct_origin_count(&g, &[a, b, o]), 1);
    }

    #[test]
    fn lineage_chain_beyond_k_hops_is_distinct() {
        // A long funding chain o0 -> o1 -> ... -> oN. With LINEAGE_K_HOPS hop bound, the two ends are
        // distinct once they are more than K hops apart.
        let n = (LINEAGE_K_HOPS as usize) + 4;
        let nodes: Vec<NodeId> = (0..=n).map(|i| id(i as u8)).collect();
        let edges: Vec<(NodeId, NodeId)> =
            (0..n).map(|i| (nodes[i], nodes[i + 1])).collect();
        let g = LineageGraph::from_edges(&edges);
        // Adjacent nodes are common-origin.
        assert!(common_funding_origin(&g, &nodes[0], &nodes[1]));
        // The two ends are > K hops apart: NOT common-origin (lineage decays with distance).
        assert!(!common_funding_origin(&g, &nodes[0], &nodes[n]));
    }

    #[test]
    fn distinct_origin_count_collapses_sockpuppets() {
        // A whale W funds 5 sock-puppets p1..p5. They are ONE origin, not five — bond-splitting does
        // not inflate the distinct-origin count (design 2(b2)/2(f), H8/H14).
        let w = id(50);
        let puppets: Vec<NodeId> = (51..=55).map(id).collect();
        let edges: Vec<(NodeId, NodeId)> = puppets.iter().map(|p| (w, *p)).collect();
        let g = LineageGraph::from_edges(&edges);
        assert_eq!(distinct_origin_count(&g, &puppets), 1);
        // Add a genuinely-disjoint honest host H (its own origin): now 2 distinct origins.
        let h = id(99);
        let mut all = puppets.clone();
        all.push(h);
        assert_eq!(distinct_origin_count(&g, &all), 2);
    }

    #[test]
    fn lineage_disjoint_vs_connected_score_differently() {
        // A lineage-disjoint counterparty SET scores strictly higher than a lineage-connected one,
        // via the weakest-hop merit collapse: same-origin counterparties merge into one origin bucket
        // that takes the MINIMUM merit among its members, so a high-merit front cannot drag a
        // low-merit sibling up to full weight. (With an uncapped cap, pure same-origin SUMMING is
        // identical to disjoint summing — the discount is the recursive-merit collapse and the
        // distinct-origin count, exercised here and in the cap/count tests.)
        let e = id(1);
        let c1 = id(2);
        let c2 = id(3);
        // c1 full merit, c2 low merit.
        let earnings = [
            CounterpartyEarning { counterparty: c1, raw_earned: 100, merit_bps: 10_000 },
            CounterpartyEarning { counterparty: c2, raw_earned: 100, merit_bps: 1_000 },
        ];

        // Case A: lineage-DISJOINT → each weighted by its OWN merit: 100*1.0 + 100*0.1 = 110.
        let g_disjoint = LineageGraph::default();
        let disjoint = lineage_earned_work_score(&g_disjoint, &e, &earnings);
        assert_eq!(disjoint, 110, "disjoint: each counterparty keeps its own merit");

        // Case B: c1, c2 share origin O → collapse to ONE bucket, raw 200, merit = min(1.0, 0.1) = 0.1
        // → 200 * 0.1 = 20. Strictly lower than the disjoint 110.
        let o = id(9);
        let g_connected = LineageGraph::from_edges(&[(o, c1), (o, c2)]);
        let connected = lineage_earned_work_score(&g_connected, &e, &earnings);
        assert_eq!(connected, 20, "same-origin: weakest-hop merit collapses the bucket");
        assert!(connected < disjoint, "lineage-connected scores strictly lower");

        // And the distinct-origin COUNT differs (2 vs 1) — the property P7 committees / P8 release read.
        assert_eq!(distinct_origin_count(&g_disjoint, &[c1, c2]), 2);
        assert_eq!(distinct_origin_count(&g_connected, &[c1, c2]), 1);
    }

    #[test]
    fn wash_cycle_earns_zero_net_distinct_weight() {
        // The defining wash trade: E funds its own puppet P, then routes "jobs" P->E to pump earned.
        // Because P shares E's funding origin, the earnings are self-dealing and contribute ZERO.
        let e = id(1);
        let p = id(2);
        // E funds P (E -> P): P is in E's lineage.
        let g = LineageGraph::from_edges(&[(e, p)]);
        assert!(common_funding_origin(&g, &e, &p), "puppet shares earner's origin");
        let earnings = [CounterpartyEarning { counterparty: p, raw_earned: 1_000_000, merit_bps: 10_000 }];
        let score = lineage_earned_work_score(&g, &e, &earnings);
        assert_eq!(score, 0, "wash-cycle self-dealing earns zero distinct weight");
    }

    #[test]
    fn unreputed_cluster_member_contributes_near_zero() {
        // Recursive MeritRank weighting: a lineage-disjoint counterparty with ~0 merit contributes ~0,
        // even though it is "distinct". A cluster of low-merit members cannot pump the score.
        let e = id(1);
        let low = id(2); // distinct origin but no standing
        let g = LineageGraph::default();
        let earnings = [CounterpartyEarning { counterparty: low, raw_earned: 1_000_000, merit_bps: 1 }];
        let score = lineage_earned_work_score(&g, &e, &earnings);
        // 1_000_000 * 1 / 10_000 = 100. Tiny relative to the raw 1_000_000.
        assert_eq!(score, 100);
        // Zero merit → zero contribution.
        let zero = [CounterpartyEarning { counterparty: low, raw_earned: 1_000_000, merit_bps: 0 }];
        assert_eq!(lineage_earned_work_score(&g, &e, &zero), 0);
    }

    #[test]
    fn weakest_hop_merit_rule_for_a_cluster() {
        // Two same-origin counterparties: one high-merit front (10000), one low-merit (500). They
        // collapse to one origin and the bucket takes the MINIMUM merit (weakest hop), so the
        // high-merit front cannot legitimize the cluster.
        let e = id(1);
        let c_front = id(2);
        let c_back = id(3);
        let o = id(9);
        let g = LineageGraph::from_edges(&[(o, c_front), (o, c_back)]);
        let earnings = [
            CounterpartyEarning { counterparty: c_front, raw_earned: 100, merit_bps: 10_000 },
            CounterpartyEarning { counterparty: c_back, raw_earned: 100, merit_bps: 500 },
        ];
        // Collapsed raw = 200, merit = min(10000, 500) = 500 → 200 * 500 / 10_000 = 10.
        assert_eq!(lineage_earned_work_score(&g, &e, &earnings), 10);
    }

    #[test]
    fn honest_disjoint_full_merit_reproduces_raw_sum() {
        // The refinement is a strict generalization: honest, lineage-disjoint, full-merit work with
        // the cap disabled reproduces the naive `NodeStats.earned` sum (backward-compatible identity).
        assert_eq!(PER_COUNTERPARTY_CAP, 0, "cap disabled in the scaffold default");
        let e = id(1);
        let g = LineageGraph::default();
        let earnings: Vec<CounterpartyEarning> = (2..=6)
            .map(|b| CounterpartyEarning { counterparty: id(b), raw_earned: 37, merit_bps: 10_000 })
            .collect();
        assert_eq!(lineage_earned_work_score(&g, &e, &earnings), 37 * 5);
    }

    #[test]
    fn mul_bps_is_exact_and_overflow_safe() {
        assert_eq!(mul_bps(100, 10_000), 100);
        assert_eq!(mul_bps(100, 0), 0);
        assert_eq!(mul_bps(100, 5_000), 50);
        assert_eq!(mul_bps(1, 5_000), 0); // floor
        // Large value near u128::MAX does not overflow (would if done as value*bps directly).
        let big = u128::MAX / 2;
        let half = mul_bps(big, 5_000);
        assert!(half <= big / 2 + 1 && half >= big / 2 - 1);
    }
}
