//! `ce-meritrank` — APP-LAYER MeritRank reputation scorer over CE's `/history` work-ledger.
//!
//! Governs: design `2(e)` "Sybil-resistant reputation — MeritRank over the /history work-ledger".
//! Source: Tribler TrustChain (Layer 1) + MeritRank (Nasrulin/de Vos/Pouwelse, BRAINS 2022,
//! arXiv 2207.09950). This is **NOT a node primitive** and **NOT on any consensus path** (design
//! `2(e)`: "computed as an app-layer scorer (scheduler)"); it is a personalized read-model the
//! scheduler runs to *rank* hosts and to propose a *capped* verification-dial downgrade. It must
//! never be folded back into `consensus_weight` / `earned_work_score` (that is P9's lineage job, on
//! the chain) — this crate only reads the public ledger facts and the chain's own
//! [`VerifyTier`]/[`downgrade_allowed`] dial rules.
//!
//! ## The two-layer split (design `2(e)`), kept explicit
//!  - **Layer 1 (ledger)** is CE's existing `/history` double-signed records (payer-cosigned
//!    `JobSettle`, `HostBond`, `SlashEquivocation` proofs). Tamper-evident, but ZERO Sybil
//!    resistance by itself (it faithfully records fabricated self-dealing).
//!  - **Layer 2 (reputation)** — THIS crate — is a decayed, seed-PERSONALIZED random walk over that
//!    log. Three decay knobs are the actual defense (design `2(e)`):
//!     - transitivity decay `(1-alpha)^d`: reputation laundered through long Sybil chains evaporates
//!       with graph distance `d` from the seed;
//!     - connectivity decay `(1-beta)` on narrow cuts: a node reachable only through a single bridge
//!       (the structural signature of every sock-puppet farm) is discounted (pairs with the
//!       >=3-relay / IP-diversity hardening of P5 — `net_hardening::is_bridge_peer`);
//!     - epoch decay `(1-gamma)`: ages out stale reputation (FRESHNESS only — the paper found epoch
//!       decay did NOT improve Sybil tolerance, so we treat it as recency, never as a defense).
//!
//! ## The loop-break (design `2(e)`, red-team H9/H19/H20 — the load-bearing correctness property)
//! MeritRank's bound only holds if every honest->Sybil edge is backed by REAL delivered work. CE's
//! `JobSettle` proves nothing executed (V4), and three of the four edge "establishers" (spot-checked
//! T1, redundant T2, bond-backed) are exactly the tiers broken by committee-capture (H8). A cluster
//! that captures its own T1 auditor / T2 majority would manufacture "established work" edges and
//! launder them into reputation -> cheaper tier -> lower P(detect) -> cheaper self-audit: a
//! positive-feedback loop. The three fixes, enforced here:
//!  1. **Reputation may NEVER lower the verification tier below the tier that ESTABLISHED the edges
//!     that produced it** — and only **T3-fraud-proved or T0-human-interactive** edges may earn a
//!     dial downgrade at all. Both are delegated to the chain's [`downgrade_allowed`], so this crate
//!     and consensus share ONE definition.
//!  2. Only [`EdgeKind::is_downgrade_eligible`] edges contribute to the *downgrade* score; T1/T2/T4
//!     edges may rank a host but **must not relax assurance**.
//!  3. Connectivity decay `(1-beta)` is applied to history dominated by a narrow committee/bond
//!     lineage (a bridge), so a self-auditing cluster cannot pump itself.
//!
//! ## Default-off gate (P8 task note / design `2(f)`/`6`)
//! Until the P9 lineage distinct-counterparty accounting lands, MeritRank MUST NOT relax any
//! high-value tier. [`MeritRankConfig::allow_high_value_downgrade`] defaults to `false`; with it off,
//! [`MeritScorer::proposed_downgrade`] refuses to downgrade any job at/above
//! [`ce_chain::verification::HIGH_VALUE_FLOOR`] regardless of score — the flag the task requires.
//!
//! ## Integer-only, deterministic
//! Even though this is app-layer, the walk is computed in fixed-point **integer basis points** (no
//! floats), so two honest schedulers reading the same ledger compute the SAME score — a prerequisite
//! for using it in any shared placement/dial decision (design `9` reproducibility). All decay is
//! integer multiply-then-floor-divide; saturating throughout.

use std::collections::HashMap;

use ce_chain::verification::{VerifyTier, downgrade_allowed};
use ce_identity::NodeId;

/// Fixed-point scale: scores and decay factors are integers out of `SCALE` (== 1.0). `10_000` gives
/// basis-point precision, matching the chain's `BPS_DENOM` so the units compose cleanly.
pub const SCALE: u64 = 10_000;

/// MeritRank decay parameters, in basis points of `SCALE`. Defaults track the source experiments
/// (alpha ~= 0.4) but are app-tunable; calibration is empirical (design `9`, MeritRank is
/// Sybil-TOLERANT not Sybil-proof — the bound is empirical ~1.5-2.5x, NOT a theorem, so no guaranteed
/// `c` is written into code, design `2(e)`).
#[derive(Debug, Clone, Copy)]
pub struct MeritRankConfig {
    /// Transitivity decay `alpha` (bps of `SCALE`). Each extra hop from the seed multiplies a path's
    /// contribution by `(SCALE - alpha_bps)`. Default 4_000 (alpha = 0.4).
    pub alpha_bps: u64,
    /// Connectivity decay `beta` (bps of `SCALE`) applied to a host whose history is reachable only
    /// through a narrow cut / single bridge. Default 5_000 (beta = 0.5 — halve a bridge-only host).
    pub beta_bps: u64,
    /// Epoch decay `gamma` (bps of `SCALE`) per epoch of age. FRESHNESS only (the paper found it did
    /// not improve Sybil tolerance). Default 1_000 (gamma = 0.1).
    pub gamma_bps: u64,
    /// Maximum walk depth (hops from the seed). Beyond this, transitivity decay has shrunk a path's
    /// contribution to noise; bounding depth also bounds compute. Default 6.
    pub max_depth: u32,
    /// FLAG (default `false`): allow a MeritRank-driven downgrade to relax a HIGH-VALUE job's tier.
    /// MUST stay false until P9 lineage distinct-counterparty accounting lands (design `2(f)`/`6`,
    /// P8 task note). With it false, high-value jobs are never relaxed regardless of score.
    pub allow_high_value_downgrade: bool,
}

impl Default for MeritRankConfig {
    fn default() -> Self {
        Self {
            alpha_bps: 4_000,
            beta_bps: 5_000,
            gamma_bps: 1_000,
            max_depth: 6,
            allow_high_value_downgrade: false, // P8 flag default-OFF until P9 lineage (design 2f/6).
        }
    }
}

/// How an edge's underlying work was ESTABLISHED — the load-bearing field for the H9 loop-break. The
/// scorer reads this from the on-chain job's `verify:` tier (the tier the work was actually audited
/// at), NOT from anything the rated host can forge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    /// T0 human-interactive: a human perceived the output (pay-as-you-go heartbeats). Downgrade-eligible.
    HumanInteractive,
    /// T3 fraud-proved: a referee re-execution settled a dispute (one honest verifier breaks the ring).
    /// Downgrade-eligible.
    FraudProved,
    /// T5 zk-proved: cryptographically correct. Downgrade-eligible (strongest).
    ZkProved,
    /// T1 spot-audit / T2 redundant: may RANK a host but MUST NOT relax assurance (H9 — these are the
    /// committee-capturable tiers a self-auditing cluster mints).
    SampledOrRedundant,
    /// T4 TEE-attested: EXCLUDED entirely (design `2(c)`/`2(e)` H17, TEE.Fail) — neither ranks nor
    /// relaxes. Contributes 0.
    TeeAttested,
}

impl EdgeKind {
    /// Map to the chain's [`VerifyTier`] so the shared [`downgrade_allowed`] rule is the single
    /// source of truth for "may this establish a downgrade".
    pub fn verify_tier(self) -> VerifyTier {
        match self {
            EdgeKind::HumanInteractive => VerifyTier::Interactive,
            EdgeKind::FraudProved => VerifyTier::FraudProof,
            EdgeKind::ZkProved => VerifyTier::ZkProof,
            EdgeKind::SampledOrRedundant => VerifyTier::SpotAudit,
            EdgeKind::TeeAttested => VerifyTier::TeeConfidential,
        }
    }

    /// Whether an edge of this kind may EARN a dial downgrade (design `2(e)` fix 2): only
    /// T0-human-interactive or T3/T5-fraud/zk-proved history. T1/T2 and T4 may rank but not relax.
    pub fn is_downgrade_eligible(self) -> bool {
        matches!(
            self,
            EdgeKind::HumanInteractive | EdgeKind::FraudProved | EdgeKind::ZkProved
        )
    }

    /// Whether an edge of this kind counts at all toward ranking (T4/TEE is excluded entirely, H17).
    pub fn counts_for_ranking(self) -> bool {
        !matches!(self, EdgeKind::TeeAttested)
    }
}

/// One directed work-ledger edge `from --(value)--> to`: a payer (`from`) paid a host (`to`) for work
/// established at `kind`, `age_epochs` ago. Mirrors a `/history` double-signed `JobSettle`/`Heartbeat`
/// record. `value` is post-burn base units (the chain's `NodeStats.earned` semantics).
///
/// `origin_id` is the BOND-FUNDING lineage origin of `from` (P9 `lineage::common_funding_origin`
/// collapses these). The scorer uses it for connectivity decay: history whose payers all trace to one
/// origin is a bridge and is discounted — the structural defense against a self-auditing cluster. The
/// app passes `from` itself as a conservative origin until P9 lineage is wired (then it passes the
/// true funding origin, tightening the bridge detection).
#[derive(Debug, Clone, Copy)]
pub struct WorkEdge {
    pub from: NodeId,
    pub to: NodeId,
    pub value: u128,
    pub kind: EdgeKind,
    pub age_epochs: u32,
    pub origin_id: NodeId,
}

/// A personalized MeritRank scorer seeded at one node (the scheduler's own node — design `2(e)`:
/// "each node using its own node as the seed; personalized, not global trust"). Build it from the
/// `/history` edges, then query [`MeritScorer::score`] / [`MeritScorer::proposed_downgrade`].
pub struct MeritScorer {
    seed: NodeId,
    cfg: MeritRankConfig,
    /// Adjacency: payer -> list of edges out of that payer.
    out: HashMap<NodeId, Vec<WorkEdge>>,
}

impl MeritScorer {
    /// Build a personalized scorer seeded at `seed` over the given work-ledger edges.
    pub fn new(seed: NodeId, cfg: MeritRankConfig, edges: impl IntoIterator<Item = WorkEdge>) -> Self {
        let mut out: HashMap<NodeId, Vec<WorkEdge>> = HashMap::new();
        for e in edges {
            out.entry(e.from).or_default().push(e);
        }
        Self { seed, cfg, out }
    }

    /// Apply `n` successive transitivity decays `(1-alpha)^n` to a fixed-point value (integer).
    fn transitivity_decay(&self, mut v: u128, hops: u32) -> u128 {
        let keep = (SCALE - self.cfg.alpha_bps.min(SCALE)) as u128;
        for _ in 0..hops {
            v = v.saturating_mul(keep) / SCALE as u128;
        }
        v
    }

    /// Apply epoch decay `(1-gamma)^age` to a fixed-point value (integer). Capped at a small number
    /// of epochs of effect (after which the value is negligible) to bound compute.
    fn epoch_decay(&self, mut v: u128, age_epochs: u32) -> u128 {
        let keep = (SCALE - self.cfg.gamma_bps.min(SCALE)) as u128;
        // 64 epochs of gamma=0.1 already decays to <0.1% — clamp so a huge age cannot loop forever.
        for _ in 0..age_epochs.min(64) {
            v = v.saturating_mul(keep) / SCALE as u128;
        }
        v
    }

    /// Apply one connectivity decay `(1-beta)` to a fixed-point value (integer): used when a host's
    /// contributing history is dominated by a single bridge / narrow funding-origin cut.
    fn connectivity_decay(&self, v: u128) -> u128 {
        let keep = (SCALE - self.cfg.beta_bps.min(SCALE)) as u128;
        v.saturating_mul(keep) / SCALE as u128
    }

    /// The personalized MeritRank reputation of `target`, in fixed-point units (`SCALE` == "1.0"
    /// worth of seed-anchored, work-backed, decayed contribution). Higher == more trustworthy FROM
    /// THE SEED'S PERSPECTIVE.
    ///
    /// `downgrade_relevant_only`: when true, only [`EdgeKind::is_downgrade_eligible`] edges count
    /// (the score that may relax the dial — design `2(e)` fix 2). When false, all ranking-eligible
    /// edges count (the score that may rank/place a host but not relax assurance).
    ///
    /// The walk is a bounded DFS of value-flow paths from the seed to `target`, each path's
    /// contribution decayed by transitivity (per hop), epoch (per edge age, taking the path's oldest
    /// edge), and connectivity (if the path's payers collapse to a single funding origin / bridge).
    /// Self-edges and the seed rating itself contribute 0 (you cannot vouch for yourself — the core
    /// anti-self-dealing rule).
    pub fn score(&self, target: &NodeId, downgrade_relevant_only: bool) -> u128 {
        if target == &self.seed {
            return 0; // a node does not rate itself (kills trivial self-pumping).
        }
        let mut visited = vec![self.seed];
        self.walk(&self.seed, target, 0, &mut visited, downgrade_relevant_only)
    }

    /// Bounded DFS summing decayed path contributions from `current` toward `target`.
    fn walk(
        &self,
        current: &NodeId,
        target: &NodeId,
        depth: u32,
        visited: &mut Vec<NodeId>,
        downgrade_relevant_only: bool,
    ) -> u128 {
        if depth >= self.cfg.max_depth {
            return 0;
        }
        let Some(edges) = self.out.get(current) else {
            return 0;
        };
        let mut acc: u128 = 0;
        for e in edges {
            // No self-edges (a payer paying itself is self-dealing — contributes nothing).
            if e.from == e.to {
                continue;
            }
            // Exclude entirely-excluded edge kinds (T4/TEE, H17) and, when scoring for downgrades,
            // anything not downgrade-eligible (T1/T2, H9).
            if !e.kind.counts_for_ranking() {
                continue;
            }
            if downgrade_relevant_only && !e.kind.is_downgrade_eligible() {
                continue;
            }
            if e.to == *target {
                // A direct contribution to the target: value, transitivity-decayed by the hops it
                // took to reach `current` plus this final hop, epoch-decayed by this edge's age.
                let mut c = e.value.min(u128::from(u64::MAX)); // clamp absurd values into range
                c = self.transitivity_decay(c, depth + 1);
                c = self.epoch_decay(c, e.age_epochs);
                // Connectivity decay: if the path so far is a bridge (all payers collapse to ONE
                // funding origin, including this edge's), discount it — a self-auditing cluster funds
                // its own raters from one origin, so its edges are bridge-only and get halved.
                if self.path_is_bridge(visited, e) {
                    c = self.connectivity_decay(c);
                }
                acc = acc.saturating_add(c);
            } else if !visited.contains(&e.to) {
                // Recurse along the value-flow path (no cycles — `visited` guards them).
                visited.push(e.to);
                let sub = self.walk(&e.to, target, depth + 1, visited, downgrade_relevant_only);
                // Sub-path already carries `depth+1` transitivity; nothing extra here.
                acc = acc.saturating_add(sub);
                visited.pop();
            }
        }
        acc
    }

    /// Whether the path that reached this edge is a structural BRIDGE: every payer on it (the seed
    /// excluded) plus this edge's payer collapses to a SINGLE bond-funding origin. That is the
    /// signature of a sock-puppet farm vouching for itself (design `2(e)` connectivity-decay, pairs
    /// with P5 `net_hardening::is_bridge_peer`). The seed is excluded because the seed is the honest
    /// observer, not a sock-puppet.
    fn path_is_bridge(&self, visited: &[NodeId], edge: &WorkEdge) -> bool {
        // The seed at index 0 is the honest observer, never a sock-puppet. A DIRECT edge from the
        // seed (no intermediate payers) is therefore NEVER a bridge — only laundering THROUGH
        // intermediate cluster payers that collapse to one funding origin is. So require at least one
        // intermediate payer (the launder hops) before the bridge penalty can apply.
        let intermediates: Vec<NodeId> = visited.iter().skip(1).copied().collect();
        if intermediates.is_empty() {
            return false;
        }
        let mut origins: std::collections::HashSet<NodeId> = std::collections::HashSet::new();
        for node in &intermediates {
            // Funding origin this node uses as a payer (any of its out-edges carries it); fall back
            // to the node id itself (conservative: distinct origin) if it never pays.
            let origin = self
                .out
                .get(node)
                .and_then(|es| es.first())
                .map(|e| e.origin_id)
                .unwrap_or(*node);
            origins.insert(origin);
        }
        origins.insert(edge.origin_id);
        // A bridge: every intermediate payer AND this final edge trace to ONE common funding origin.
        origins.len() == 1
    }

    /// Propose a verification-dial tier for a job, given the host's establishing tier, the job value,
    /// and the *baseline* tier the scheduler would otherwise use. This is the ONLY place MeritRank
    /// touches assurance, and it can ONLY DOWNGRADE (never raise risk beyond baseline) and NEVER below
    /// the establishing tier — all delegated to the chain's [`downgrade_allowed`] (design `2(e)` H9).
    ///
    /// Returns the proposed tier (== `baseline` when no downgrade is permitted). Rules:
    ///  - The candidate downgrade target is `establishing` itself (you can be relaxed back TO the tier
    ///    that established your reputation, never below it — H9).
    ///  - The chain's [`downgrade_allowed`] must approve `(to=establishing, establishing, job_value)`:
    ///    enforces "establishing must be downgrade-eligible" AND "high-value stays >= T3".
    ///  - The flag [`MeritRankConfig::allow_high_value_downgrade`] must be on for any high-value job
    ///    (default OFF until P9 lineage — P8 task note / design `2(f)`).
    ///  - A minimum downgrade-relevant score [`MIN_DOWNGRADE_SCORE`] must be met (a host with almost
    ///    no fraud-proved history is NOT relaxed — cold-start strangers stay forced-high, design `5`
    ///    open problem 4).
    ///  - We only ever return the LOWER-RISK of {baseline, establishing} — never raise above baseline.
    pub fn proposed_downgrade(
        &self,
        host: &NodeId,
        establishing: VerifyTier,
        baseline: VerifyTier,
        job_value: u128,
    ) -> VerifyTier {
        // Flag gate: high-value jobs are never relaxed until P9 lineage lands.
        if !self.cfg.allow_high_value_downgrade
            && job_value >= ce_chain::verification::HIGH_VALUE_FLOOR
        {
            return baseline;
        }
        // Earn-the-downgrade gate: need real fraud-proved/human-confirmed reputation.
        if self.score(host, true) < MIN_DOWNGRADE_SCORE {
            return baseline;
        }
        // The chain owns the loop-break rules; ask it whether relaxing TO the establishing tier is OK
        // for this value. If not, keep baseline.
        if !downgrade_allowed(establishing, establishing, job_value) {
            return baseline;
        }
        // Only relax if `establishing` is actually lower-risk than baseline; never raise risk.
        if establishing.assurance_rank() < baseline.assurance_rank() {
            // establishing is WEAKER than baseline -> relaxing would drop assurance to establishing,
            // which is allowed by downgrade_allowed above (it already enforced >= establishing and
            // the high-value floor). Return establishing as the relaxed tier.
            establishing
        } else {
            // establishing is already >= baseline: no relaxation buys anything; keep baseline.
            baseline
        }
    }
}

/// Minimum downgrade-relevant MeritRank score (fixed-point) a host must reach before any dial
/// downgrade is proposed. Below this, the host is treated as a cold-start stranger and stays at the
/// baseline tier (design `5` open problem 4: strangers are forced-high; reputation helps repeat
/// counterparties, never first contact). Calibration is empirical (design `9`). One `SCALE` ==
/// roughly "one full unit of seed-anchored fraud-proved work".
pub const MIN_DOWNGRADE_SCORE: u128 = SCALE as u128;

#[cfg(test)]
mod tests {
    use super::*;

    fn n(b: u8) -> NodeId {
        [b; 32]
    }

    /// A fraud-proved edge `from -> to` of `value`, fresh (age 0), with `from`'s own id as its
    /// funding origin (the conservative distinct-origin default).
    fn fp_edge(from: NodeId, to: NodeId, value: u128) -> WorkEdge {
        WorkEdge { from, to, value, kind: EdgeKind::FraudProved, age_epochs: 0, origin_id: from }
    }

    // ---- edge-kind classification (H9/H17 loop-break inputs) ----

    #[test]
    fn only_t0_t3_t5_edges_are_downgrade_eligible() {
        assert!(EdgeKind::HumanInteractive.is_downgrade_eligible());
        assert!(EdgeKind::FraudProved.is_downgrade_eligible());
        assert!(EdgeKind::ZkProved.is_downgrade_eligible());
        // T1/T2 may rank but never relax assurance (H9).
        assert!(!EdgeKind::SampledOrRedundant.is_downgrade_eligible());
        // T4/TEE is excluded entirely (H17).
        assert!(!EdgeKind::TeeAttested.is_downgrade_eligible());
        assert!(!EdgeKind::TeeAttested.counts_for_ranking());
    }

    // ---- decay knobs (design 2(e)) ----

    #[test]
    fn transitivity_decay_shrinks_with_distance() {
        let s = MeritScorer::new(n(0), MeritRankConfig::default(), []);
        let base = 10_000u128;
        let one = s.transitivity_decay(base, 1);
        let two = s.transitivity_decay(base, 2);
        // alpha=0.4 => keep 0.6 per hop.
        assert_eq!(one, 6_000);
        assert_eq!(two, 3_600);
        assert!(two < one && one < base, "laundering through hops evaporates value");
    }

    #[test]
    fn epoch_decay_ages_out_stale_reputation() {
        let s = MeritScorer::new(n(0), MeritRankConfig::default(), []);
        let fresh = s.epoch_decay(10_000, 0);
        let old = s.epoch_decay(10_000, 5);
        assert_eq!(fresh, 10_000, "fresh reputation is undecayed");
        assert!(old < fresh, "stale reputation decays (freshness, not a Sybil defense)");
        // gamma=0.1 => 0.9^5 ~= 0.59 => 5904 by integer flooring.
        assert_eq!(old, 5_904);
    }

    #[test]
    fn connectivity_decay_halves_a_bridge() {
        let s = MeritScorer::new(n(0), MeritRankConfig::default(), []);
        assert_eq!(s.connectivity_decay(10_000), 5_000); // beta=0.5
    }

    // ---- a node never rates itself ----

    #[test]
    fn seed_does_not_rate_itself() {
        let seed = n(0);
        let edges = [fp_edge(seed, seed, 1_000_000)]; // self-edge
        let s = MeritScorer::new(seed, MeritRankConfig::default(), edges);
        assert_eq!(s.score(&seed, true), 0, "self-score is always 0");
    }

    // ---- a direct honest fraud-proved edge earns reputation ----

    #[test]
    fn direct_fraud_proved_edge_earns_score() {
        let seed = n(0);
        let host = n(1);
        // The seed itself paid the host for fraud-proved work: a strong direct edge.
        let edges = [fp_edge(seed, host, 100_000)];
        let s = MeritScorer::new(seed, MeritRankConfig::default(), edges);
        let sc = s.score(&host, true);
        assert!(sc > 0, "a direct fraud-proved edge from the seed earns reputation");
    }

    #[test]
    fn t1_t2_edges_do_not_earn_a_downgrade_score() {
        let seed = n(0);
        let host = n(1);
        // Only a sampled (T1) edge exists: it may rank, but earns ZERO downgrade-relevant score.
        let edges = [WorkEdge {
            from: seed,
            to: host,
            value: 1_000_000,
            kind: EdgeKind::SampledOrRedundant,
            age_epochs: 0,
            origin_id: seed,
        }];
        let s = MeritScorer::new(seed, MeritRankConfig::default(), edges);
        assert_eq!(s.score(&host, true), 0, "T1/T2 history cannot relax the dial (H9)");
        assert!(s.score(&host, false) > 0, "but it may still rank the host");
    }

    // ---- THE headline test: a self-auditing cluster fails to pump its score ----

    #[test]
    fn self_auditing_cluster_cannot_pump_its_score() {
        // Cluster of sock-puppets ALL funded from one origin `farm`, laundering fake fraud-proved
        // value down a chain C1 -> C2 -> C3 -> C4 to manufacture reputation for the target C4, from
        // the perspective of an HONEST seed that has no real relationship with the cluster.
        let seed = n(0); // honest scheduler, NOT part of the cluster
        let farm = n(200); // the single bond-funding origin of the whole cluster
        let (c1, c2, c3, c4) = (n(1), n(2), n(3), n(4));
        let value = 10_000_000u128;
        let cluster_edge = |from, to| WorkEdge {
            from,
            to,
            value, // huge fake value
            kind: EdgeKind::FraudProved, // they even claim the strongest establishing tier
            age_epochs: 0,
            origin_id: farm, // BUT every payer traces to ONE funding origin (the giveaway)
        };
        // A single launder chain (deterministic single path to C4 so the suppression is exact).
        let edges = [cluster_edge(c1, c2), cluster_edge(c2, c3), cluster_edge(c3, c4)];
        let s = MeritScorer::new(seed, MeritRankConfig::default(), edges);

        // PROPERTY 1 (the core personalized-walk defense): from an honest seed with NO edge into the
        // farm, the whole cluster is unreachable -> reputation is ZERO no matter how much fake work
        // they self-deal. This is what actually stops a self-auditing cluster.
        assert_eq!(s.score(&c4, true), 0, "no honest edge in => the cluster earns ZERO reputation");
        assert_eq!(s.score(&c1, true), 0);

        // PROPERTY 2 (decay bites even after the farm buys ONE real entry edge): the seed once used
        // C1, so the farm has a single honest foothold. Laundering that foothold's trust down the
        // chain to C4 is suppressed by transitivity decay (per hop) AND connectivity decay (the whole
        // chain is one funding origin => a bridge). C4 (3 hops, bridge) is FAR below C1 (1 hop).
        let mut with_entry = edges.to_vec();
        with_entry.push(WorkEdge {
            from: seed,
            to: c1,
            value,
            kind: EdgeKind::FraudProved,
            age_epochs: 0,
            origin_id: seed, // the honest seed is its own origin
        });
        let s2 = MeritScorer::new(seed, MeritRankConfig::default(), with_entry);
        let direct_c1 = s2.score(&c1, true); // C1 is a direct, honest, real edge (1 hop)
        let laundered_c4 = s2.score(&c4, true); // C4 reachable only THROUGH the farm bridge (3 hops)
        assert!(direct_c1 > 0);
        assert!(laundered_c4 > 0, "the one real foothold does leak SOME trust onward");
        assert!(
            laundered_c4 < direct_c1,
            "laundered C4 reputation is strictly less than the one real direct edge"
        );
        // Heavily suppressed: direct C1 is 1 hop (0.6 of value); laundered C4 is 3 hops
        // (0.6^3 = 0.216) x a bridge halving (0.5) ~= 0.108 of value — ~5.5x laundering loss vs the
        // one real edge. So laundered_c4 * 5 < direct_c1.
        assert!(
            laundered_c4 * 5 < direct_c1,
            "laundered reputation is suppressed >5x by transitivity + connectivity decay"
        );
    }

    // ---- THE no-downgrade-below-establishing-tier invariant (H9) ----

    #[test]
    fn never_downgrades_below_the_establishing_tier() {
        let seed = n(0);
        let host = n(1);
        // Give the host a big, real, fraud-proved direct edge from the seed (max reputation).
        let edges = [fp_edge(seed, host, 100_000_000)];
        let s = MeritScorer::new(seed, MeritRankConfig::default(), edges);
        let low_value = 1u128; // below HIGH_VALUE_FLOOR
        // Establishing tier is T1 SpotAudit (NOT downgrade-eligible): even with huge reputation, the
        // dial must NOT relax — downgrade_allowed refuses a non-downgrade-eligible establisher (H9).
        let proposed = s.proposed_downgrade(
            &host,
            VerifyTier::SpotAudit,   // establishing
            VerifyTier::FraudProof,  // baseline the scheduler would use
            low_value,
        );
        assert_eq!(
            proposed,
            VerifyTier::FraudProof,
            "reputation established under T1 can never buy a downgrade (H9 loop-break)"
        );
    }

    #[test]
    fn relaxes_only_to_the_establishing_tier_not_below() {
        let seed = n(0);
        let host = n(1);
        let edges = [fp_edge(seed, host, 100_000_000)];
        let s = MeritScorer::new(seed, MeritRankConfig::default(), edges);
        let low_value = 1u128;
        // Establishing tier is T3 FraudProof (downgrade-eligible), baseline is the same. A host with
        // strong fraud-proved history can be relaxed TO T3 but the result is never below T3.
        let proposed =
            s.proposed_downgrade(&host, VerifyTier::FraudProof, VerifyTier::FraudProof, low_value);
        assert!(
            proposed.assurance_rank() >= VerifyTier::FraudProof.assurance_rank(),
            "never relaxed below the establishing tier"
        );
    }

    #[test]
    fn high_value_jobs_are_never_downgraded_while_flag_off() {
        let seed = n(0);
        let host = n(1);
        let edges = [fp_edge(seed, host, 1_000_000_000_000_000_000_000)]; // huge real reputation
        let s = MeritScorer::new(seed, MeritRankConfig::default(), edges); // flag default OFF
        let high_value = ce_chain::verification::HIGH_VALUE_FLOOR; // at the high-value floor
        let proposed =
            s.proposed_downgrade(&host, VerifyTier::FraudProof, VerifyTier::ZkProof, high_value);
        assert_eq!(
            proposed,
            VerifyTier::ZkProof,
            "high-value jobs stay at baseline until P9 lineage lands (flag default-off, design 2f/6)"
        );
    }

    #[test]
    fn cold_start_stranger_is_not_downgraded() {
        let seed = n(0);
        let stranger = n(9);
        // No edges to the stranger at all -> score 0 -> below MIN_DOWNGRADE_SCORE -> baseline kept.
        let s = MeritScorer::new(seed, MeritRankConfig::default(), []);
        let proposed = s.proposed_downgrade(
            &stranger,
            VerifyTier::Interactive,
            VerifyTier::FraudProof,
            1u128,
        );
        assert_eq!(
            proposed,
            VerifyTier::FraudProof,
            "a stranger with no fraud-proved history stays forced-high (design 5 open problem 4)"
        );
    }

    #[test]
    fn flag_on_allows_high_value_relaxation_when_earned() {
        // Sanity: with the flag explicitly ON (post-P9) and strong fraud-proved reputation, a
        // high-value job CAN relax down to the (downgrade-eligible) establishing T3 from a T5
        // baseline — proving the gate is the ONLY thing blocking it pre-P9.
        let seed = n(0);
        let host = n(1);
        let edges = [fp_edge(seed, host, 1_000_000_000_000_000_000_000)];
        let mut cfg = MeritRankConfig::default();
        cfg.allow_high_value_downgrade = true;
        let s = MeritScorer::new(seed, cfg, edges);
        let high_value = ce_chain::verification::HIGH_VALUE_FLOOR;
        let proposed =
            s.proposed_downgrade(&host, VerifyTier::FraudProof, VerifyTier::ZkProof, high_value);
        assert_eq!(proposed, VerifyTier::FraudProof, "earned + flag-on relaxes T5 baseline to T3");
    }

    #[test]
    fn determinism_two_scorers_agree() {
        // Two honest schedulers reading the SAME ledger compute the SAME integer score (no floats).
        let seed = n(0);
        let host = n(1);
        let edges = vec![fp_edge(seed, host, 123_456), fp_edge(host, n(2), 7_890)];
        let a = MeritScorer::new(seed, MeritRankConfig::default(), edges.clone());
        let b = MeritScorer::new(seed, MeritRankConfig::default(), edges);
        assert_eq!(a.score(&host, true), b.score(&host, true));
        assert_eq!(a.score(&n(2), true), b.score(&n(2), true));
    }
}
