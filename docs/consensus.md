# CE consensus: from wasted PoW to earned trust (CE-TWLE)

Status: design recommendation, 2026-06-05. Produced by a multi-agent bake-off: CE-specific
requirements pinned from the code, six candidate consensus models each designed concretely for CE,
every design red-teamed by two adversaries (Sybil/economic-capture + liveness/centralization),
scored by a three-judge panel, and synthesized into one recommendation. This is a **pre-launch
architecture decision**, not yet implemented. Companion: [sybil-resistance.md](sybil-resistance.md)
(the marketplace-correctness layer) and [threat-model.md](threat-model.md).

---

## 1. The question this answers

> "Is it even possible to build a coin based on trust, not wasted compute? Limit hashrate and it's
> easy to Sybil; don't and we're just another Bitcoin wasting compute."

**Yes — but not as *free* trust.** Douceur's impossibility theorem is the hard wall: you cannot have
**open** + **free identities** + **Sybil-resistance** simultaneously. PoW gives up free identities
(influence costs hash). Naive trust gives up Sybil-resistance (free trust is manufacturable —
EigenTrust self-dealing). The only way to keep an *open, free-identity* network Sybil-resistant is
to make **consensus power** (not identity) cost a scarce, non-manufacturable thing — and that thing
does not have to be wasted hash.

CE's answer: **consensus power = earned, non-transferable trust, anchored by a slashable bond, with
credits earned by verified work rather than mined.** Block ordering is done by VRF leader election
(near-zero compute), not by burning cycles. That is a coin based on trust that is also
Sybil-resistant and wastes no compute.

---

## 2. The recommendation: CE-TWLE (Trust-Weighted Leader Election)

A VRF slot-leadership chain (Ouroboros-Praos / Filecoin Expected-Consensus lineage) where a node's
win probability is proportional to its consensus weight

```
W(node, h) = min( active slashable HostBond ,  earned-work-score )      // read at height h − LOOKBACK
```

evaluated from **confirmed-depth** chain state, plus three keystone grafts the red-team proved are
non-optional:

1. **A mandatory non-refundable settlement burn** on every JobSettle/Heartbeat, with earned-work-score
   counting only *burned-and-net-outflow* value. This is the single change that converts the
   universal wash-trade leak from free to capital-costly. **Without it, no design on the panel is
   shippable.**
2. **Equivocation slashing** — two VRF-valid blocks for one slot under one key burns 100% of that
   node's bond and zeroes its weight. Prices nothing-at-stake negative-EV.
3. **A multi-operator, decaying, threshold-checkpointed genesis-root set** — *not* the three
   correlated founder keys.

### How a block gets produced (no wasted compute, no mesh round-trips)

- Time is fixed `SLOT_SECS = 10s` slots. For slot `s` on tip height `H`:
  `seed = SHA256("ce-twle-v1" || hash(block at H−LOOKBACK) || s)` — the seed comes from
  already-confirmed state (`LOOKBACK ≥ FINALITY_DEPTH`, ~64), so the current leader cannot grind it.
- Each eligible node `i` (with `W_i > 0`) computes `ticket_i = H(VRF_prove(sk_i, seed))` and is a
  valid leader for slot `s` iff `ticket_i < threshold · W_i` (Filecoin EC style — 0..n winners per
  slot, empty slots normal and self-healing).
- The leader builds a block in the **existing `Block` struct** (`nonce`→VRF proof bytes,
  `difficulty`→a weight-class tag), runs it through the **existing `append()`** for all
  tx/balance/double-spend validation, seals it Ed25519, and gossips it. A receiver verifies the VRF
  proof, the ticket inequality, leader eligibility, timestamp window, and tx rules — **purely from
  embedded proofs + local confirmed state.** No quorum query, no synchronous round-trip.
- Block-production cost is **one VRF + one signature.** Zero wasted compute — the owner's actual goal.

### Fork choice, double-spend, finality (mostly reused verbatim)

- Fork choice stays CE's existing **local heaviest-suffix `try_reorg`** — the only change is
  `Block::work()` returns `W(miner, h−LOOKBACK)` (a deterministic `u128`) instead of `2^difficulty`.
- Double-spend prevention is the **existing in-block accumulator** (`ce-chain/src/lib.rs:838–1071`),
  which the audit found to be the strongest part of the code — same-type and cross-type spends both
  guarded, cross-block replay blocked by tx dedup + monotonic Heartbeat epochs. Reused unchanged.
- Finality: **soft-final at `FINALITY_DEPTH`** (~12 blocks / ~2 min), **hard-final** once a
  threshold-signed checkpoint (the existing `Checkpoint` struct, now with a k-of-n threshold sig)
  seals it. Checkpoints are **off the block-production path**, so losing the signer threshold
  degrades finality latency without halting block production.

---

## 3. Why CE-TWLE (and why every pure model failed)

The decisive empirical result of the bake-off: **the red-team broke all six candidates, and five of
them broke for the *same two reasons*.** That convergence is the real finding.

| Candidate | Judge avg | Red-team verdict | Why it failed |
|---|---|---|---|
| **Useful-work (PoUW)** | **29.4 (1st)** | sybil: fatal · liveness: **viable-with-fixes** | Delivered compute can only *weight*, never *order* (Primecoin/Gridcoin/Filecoin/Mina all confirm). Wash-trade leak fatal until the burn; reorg-grind closable via confirmed-depth `W`. **The only non-fatal liveness verdict in the field** → chosen as the spine. |
| Bonded BFT (Tendermint/HotStuff) | 27.5 | both fatal | Relies on a distinct-counterparty NodeStats field that does not exist; wash-trade leak; classic BFT **halts** under partition (violates CE's "minority keeps consensing" requirement). |
| Minimalist (no global coin) | 26.2 | both fatal | Pruning makes the root-signed checkpoint *be* the history → checkpoint author defines weight; wash-trade leak. Elegant but capture-prone. |
| Avalanche / Snow (sub-sampled voting) | 24.5 | both fatal | Self-contradiction: "seal in 1 trivial hash" vs. reuse PoW-work fork choice; resolving it hands the chain to founders; probabilistic liveness under attack; wash-trade leak. |
| FBA / Stellar quorum slices | 22.7 | both fatal | Non-deterministic reward split → per-round halt (violates "no synchronous mesh round-trips"); 2/3-roots-forever intersection rule = permanent founder dependence (Stellar's 2019 67-min halt is the precedent). |
| Pure trust-graph (soulbound rep) | 17.9 | sybil: serious · liveness: fatal | On CE's actual 3-founder topology, "settled-work trust" *is* founder trust — weight never flows to outsiders. The purest "coin based on trust" scored **last** precisely because trust with no capital anchor and no independent counterparties centralizes completely. |

**The two universal flaws (every design):**
1. **The wash-trade leak.** `NodeStats` (`ce-chain/src/lib.rs:452`) are scalar counters incremented
   unconditionally by `JobSettle`/`Heartbeat`/`ChannelClose` with only `payer≠host` guards and
   **no fee/burn** (the code's own comment at line 769 admits "forgeable credits buy compute on the
   whole fleet"). A two-key A↔B wash cycle pumps earned-weight at **zero net cost.** Fix: the
   mandatory burn + net-outflow accounting (§2 keystone 1).
2. **The genesis-centralization trap.** The three CLAUDE.md keys (laptop/desktop/relay) are a
   **single-operator, single-NAT, single-Hetzner-account correlated set.** Every red-team flagged
   this as a single-fault global halt and checkpoint-capture vector. Fix: independent multi-operator
   genesis roots + threshold checkpoints + adoption-driven decay (§4).

CE-TWLE wins because it (a) builds *on* the proven truth that work weights but does not order,
(b) has the field's only closable liveness story (VRF can't be forced to fork; the one grind is
killed by confirmed-depth `W`), and (c) is a true module swap — it degrades cleanly to bond-only PoS
if the earned anchor is stripped, where rivals degrade to a halt, a cheap-51% PoW fallback, or
permanent founder capture.

---

## 4. The honest costs (Douceur, stated plainly)

CE **keeps open + free identities** and pays for Sybil-resistance by making **consensus power**
non-free. A fresh key can spend, receive, and hold credits, and join the mesh — but **cannot order
the ledger or earn issuance** until it has posted a slashable bond *and* done real, capital-burning,
externally-paid work over wall-clock time. **Permissionless to participate; earned to secure.**

Concretely surrendered vs. PoW:
- **No permissionless block production from a cold key** — a fresh unbonded no-history node has zero
  weight (PoW lets any CPU mine immediately).
- **No zero-trust genesis** — replaced by an auditable, decaying, multi-operator federation that can
  halt its *finality* path (not production) under correlated root failure. Disclosed, not hidden.
- **Partition = soft-fork-then-reconcile-by-weight** — a conscious CAP choice: availability for
  ordering, safety for finality (halt the checkpoint rather than finalize a stolen-machine ledger).
- **Partial capital-as-power via the bond** — accepted deliberately as the only Sybil cost that
  scales with attacker scale, softened (not removed) by `min(bond, work)` coupling + the burn.

And the irreducible floor: even fully built, the anchor makes Sybil capture **costly, never
impossible** (cluster detection is undecidable). That is the most any system under Douceur can
offer, and it is **contingent on the separate correctness layer** ([sybil-resistance.md](sybil-resistance.md))
keeping per-job cost real. If that layer is weak, the anchor degrades to "Cosmos with extra steps."

---

## 4.1 Governance: sovereign-start, earned-distribution (DECISION)

CE-net's chosen posture (2026-06-05): **start with all the power, distribute it as it is earned,
assume hostility throughout.** This is the correct bootstrap, not a contradiction — every trust graph
seeds from a human-vetted honest set (the SybilLimit "honest seed"); decentralized-from-zero is
impossible (Douceur) and in practice hands power to whoever shows up first, often the attacker.

The load-bearing principle: **the moment CE-net holds all the power is the moment it has the most
credibility to commit to giving it up.** So the distribution rule is encoded in-protocol *now*, while
CE-net is the only signer — a one-way ratchet that a future coerced/compromised CE-net cannot quietly
reverse. Distribution is not a promise; it is shipped mechanism, conditional and auditable on-chain.

Design rules that implement this:

1. **Earned-driven decay, never a clock.** Founder weight `W_founder(h) = genesis_grant ·
   f(independent earned weight in existence)`, not `g(wall_clock)`. A time-bomb would hand the network
   to whoever holds weight at expiry — under hostility, possibly the attacker. Earned-driven decay
   keeps CE-net sovereign if no legitimate operators appear, and dilutes CE-net automatically the
   moment they do.
2. **Human-vetted first widening.** CE-net personally verifies the first independent root operators
   (distinct humans, ISPs, jurisdictions) and grants them `consensus:produce` + a checkpoint seat via
   on-chain `ce-cap` grants, one at a time, each revocable. The criterion transitions to purely
   on-chain ("independent earned weight across distinct economic/network clusters") only *after* the
   set is wide enough to defend itself. Distributing faster than you can verify is how a hostile actor
   captures the handoff itself.
3. **The ratchet, set today.** Pre-commit on-chain that once N genuinely-independent rooted operators
   with real earned weight exist, CE-net's *unilateral* powers (solo checkpoint revert, emergency
   halt) extinguish automatically in code. CE-net retains the power to *eject* a captured operator
   (revocation) long after it loses the power to *act alone*.

Three phases: **Sovereign** (CE-net is producer + validator + finalizer + main earner — accepted, not
apologized for) → **Vetted federation** (k-of-n checkpoint grows ~1 → 5-of-9 as real humans are
verified; earned-driven founder decay begins) → **Earned-open** (permissionless bonding; no single
party, including CE-net, can revert or halt).

The unsolved-in-general hard part (disclosed): defining "independent" and "earned" in an
attacker-proof on-chain way is the Sybil problem one level up (cluster detection is undecidable). This
is *why* the seed is out-of-band human knowledge first and only later on-chain criteria — and why the
distribution is deliberately slow, earned, and revocable.

## 5. Open risks (do not paper over these)

1. **Wash-trade residual.** Burn + net-outflow makes Sybil-by-patience costly, not impossible.
   Acceptable only if the bond/redundant-verification correctness layer holds.
2. **Burn calibration.** Too low → wash-trading stays cheap; too high → honest users taxed. Live
   mechanism-design parameter with no proven CE-scale setting.
3. **Early-network plutocracy.** When earned-score is thin, `W → bond`, so capital buys
   disproportionate early weight. Softened by per-cluster weight cap + saturating earned-score.
4. **Genesis-decay dilemma (irreducible).** On a perpetually-thin network you can have "no guaranteed
   halt" XOR "guaranteed decentralization," not both. Adoption-driven decay avoids the halt but makes
   decentralization contingent.
5. **Independent-root recruitment** is a social/operational problem the protocol can't solve. If
   genuinely independent genesis operators (different people, ISPs, jurisdictions) can't be recruited,
   the single-fault-halt and checkpoint-capture risks remain real.
6. **Censorship-by-silence.** A plurality-`W` coalition can refuse to include a target's txs without
   equivocating (unslashable). A real BFT-class gap; partially mitigated because any honest leader's
   slot includes the tx.
7. **New consensus-critical code** (VRF verify, slash detection, weight oracle) is far less
   battle-tested than `append()`. A bug here is forged finality (catastrophic) or chronic halts.

---

## 6. CE fit and new primitives

**Reused verbatim** (verified against the tree): the whole `TxKind` enum + tx validation; the
in-block double-spend accumulator (`lib.rs:838–1071`); `locked_balance()`/balance/free-balance
(`:1291`); `NodeStats` + O(1) `node_history()` (`:452`/`:708`); heaviest-suffix `try_reorg`
(`:1149`) with only `Block::work()` (`:374`) swapped; `cumulative_work` (`:531`); median-time-past +
future-drift timestamp bounds; the `Block` struct + Ed25519 seal; `Checkpoint`/prune/archive
(`:418`); ce-cap roots + attenuating chains + revocation; ce-identity; `/beacon` (now the VRF seed at
confirmed depth — exactly its documented purpose); Gossipsub topics + Strict+Signed envelopes; the
HTTP/SSE surface. The pacemaker/VRF lives in a new `ce-twle` module driven by ce-mesh events as free
fns (Mesh is `!Sync` — same constraint as today). All weight/slash math is integer-only/deterministic
(the Filecoin Dec-2020 non-determinism-halt lesson: no floats, no map-iteration-order, GPU output off
the consensus path).

**New primitives** (small, generic, no product semantics — respects the CE-vs-app boundary):
1. `TxKind::HostBond` / `HostUnbond` — slow-release locks via existing `locked_balance`.
2. `TxKind::SlashEquivocation{offender, slot, sig_a, sig_b}` — generic double-sign evidence, mirrors
   the existing `revoked`/`is_revoked` set pattern.
3. A settlement **burn** fraction on `JobSettle`/`Heartbeat` (the keystone).
4. A VRF proof field on `Block` + O(1) verify in `append()` replacing `meets_difficulty`.
5. A pure deterministic `W(node, height) = min(bond, earned_work_score)` over NodeStats + ce-cap
   grants + decay, computed at `height − LOOKBACK`.
6. A confirmed-depth beacon seed + weighted VRF sampler.
7. `Checkpoint` gains a k-of-n threshold-sig field.

---

## 7. Build phases (Phase 0 ships on the live PoW chain *now*)

The migration is a **clean-break** (requirement §10's on-disk version rule was written for exactly
this PoW→new-consensus case); balances/NodeStats/open-bids/heartbeat-epochs carry forward via a final
signed checkpoint into the new genesis, so **no credits are lost and PoW miners lose nothing**.

- **Phase 0 — Substrate hardening (ships on the LIVE PoW chain, no consensus change):** add the
  mandatory settlement burn + net-outflow/burned-value accounting + per-counterparty caps. **This
  closes the wash-trade leak independently and de-risks everything downstream — do this first.**
  - **Status: the settlement burn is IMPLEMENTED** (`ce-chain`, branch `phase0-settlement-burn`).
    `JobSettle`/`Heartbeat`/`ChannelClose` now debit the payer the full gross amount, credit the host
    `gross − burn`, and destroy the burn (`SETTLEMENT_BURN_BPS = 100`, i.e. 1.00%, a pre-launch
    tunable — see §5 "burn calibration"). `NodeStats.earned` tracks the host's net gain; a new
    `burned_total()` / `circulating_supply()` are exposed and surfaced on `/status`. Validation is
    unchanged (the burn is deterministic and the payer debit — the only balance-checked side — is the
    same). Tests prove a wash trade between two attacker-owned keys now destroys the burn every cycle
    rather than netting to zero. **Still TODO in this phase:** net-outflow/cluster accounting and
    per-counterparty caps (these belong with the Phase 2 weight oracle, since they only matter once
    `earned` feeds consensus weight; the burn alone closes the *economic* leak today).
- **Phase 1 — Bond + slash: IMPLEMENTED** (`ce-chain`, branch `phase0-settlement-burn`).
  `TxKind::HostBond { host, amount, nonce }` locks credits as a slow-release bond (reuses
  `locked_balance`, validated against every other in-block debit so it can't double-spend);
  `HostUnbond` starts a `UNBOND_BLOCKS` (2016) window during which funds stay locked and slashable,
  then auto-release lazily. `TxKind::SlashEquivocation { offender, reporter, proof }` carries a
  self-contained `EquivocationProof` (two offender-signed statements for one `(domain, epoch)` via
  `equivocation_signed_bytes`); a valid proof against an active bond burns 100% of it —
  `SLASH_REPORTER_BPS` (25%) to the reporter, the rest destroyed — idempotent per
  `(offender, domain, epoch)`, recorded in `NodeStats.slashes`. Accessors `bond_of`/`total_bonded`.
  **Not yet wired:** the bond does not yet *gate* `UptimeReward`/capacity eligibility (Phase 2/3, the
  weight oracle and VRF), and there is no CLI/HTTP bonding surface — chain primitives only. The proof
  format is forward-compatible: future VRF block tickets and capacity ads sign through
  `equivocation_signed_bytes`, making double-signing slashable.
- **Phase 2 — Weight oracle: IMPLEMENTED** (`ce-chain`, branch `phase0-settlement-burn`).
  `consensus_weight(node) = min(active_bond, earned_work_score)` — pure, integer-only, deterministic
  (survives a cache rebuild). `earned_work_score` v0 = `NodeStats.earned` (net-of-burn, so washing it
  costs real capital; the net-outflow/distinct-counterparty refinement is still TODO). Both terms must
  be non-zero: you can't buy weight without working, or earn weight without staking; a fresh/unbonded/
  fully-slashed node has `W=0`. `LOOKBACK=64` defined for Phase 3 to read weight at confirmed depth.
  `bond` and `weight` surfaced on `/status`. **Not yet wired:** `W` does not yet drive block production
  or fork choice (Phase 3, the VRF + seal swap — the first real consensus change), and genesis
  bootstrap weight `max(genesis_grant·decay, W)` is Phase 5.
- **Phase 3 — VRF leader election + seal swap: IMPLEMENTED** (`ce-chain`, branch
  `phase0-settlement-burn`). PoW is gone. `leader_seed` (slot bound to a confirmed block),
  `vrf_ticket`/`vrf_verify` (Ed25519-signature-as-VRF), `leader_threshold` (~1 leader/slot,
  weight-proportional). `Block` gains `weight` + `vrf_proof`; `nonce`/`difficulty` are vestigial.
  `append()` now checks slot-spacing (slot strictly increases → consensus-enforced block rate, killing
  the cheap-51% pacing footgun), `block.weight == consensus_weight(miner)` (non-zero), and a valid VRF
  proof below threshold; `Block::work()` returns the weight so the heaviest-weight suffix wins.
  `try_reorg` carries `genesis_weights` into the candidate chain so fork weights are validated. A
  bootstrap fallback (total weight 0 → accept seal+slot) keeps unconfigured/dev chains and the test
  suite working; production sets `genesis_weights` so it never triggers. **Residual (v0):** seed is
  parent-confirmed at `LOOKBACK=64` via `confirmed_seed`; the ce-node mining loop still produces via
  the legacy path under the fallback (real-VRF mining-loop wiring + `genesis_weights` in `NodeConfig`
  is the next small increment). The obsolete PoW difficulty/retarget tests were removed.
- **Phase 5 — Independent genesis + threshold checkpoints:** assemble the multi-operator root set in
  ce-cap, add k-of-n threshold sig to `Checkpoint`, wire adoption-driven decay.
- **Phase 6 — Shadow run (M0):** compute TWLE eligibility in parallel with canonical PoW on the live
  mesh; validate threshold/decay constants. Zero risk, fully reversible.
- **Phase 7 — Cutover (M1–M3):** gated on independence + adoption metrics; snapshot, version-bump,
  clean-break resync. Only this phase is irreversible.
- **Phase 8 — Property/adversarial tests:** wash-trade-with-burn, reorg-weight-grind (must fail with
  `LOOKBACK`), partition merge, equivocation slash, 1000-node Byzantine-majority survival.

Phases 0–4 land on the PoW chain; only Phase 7 is irreversible.

---

## 8. Prior art the design steals from

- **Ouroboros Praos / Filecoin Expected Consensus** — VRF slot leadership, 0..n winners/slot,
  confirmed-depth seed. The spine.
- **Ethereum PoS / Tendermint slashing** — equivocation slashing, weight caps.
- **Filecoin collateral** — bond sizing in expected-reward-days; useful-work weights issuance, never
  orders.
- **Stellar SCP (2019 halt) / Ripple UNL** — the cautionary tale: trust-quorum liveness and
  founder-dependence; why CE picks VRF over leaderless SCP.
- **Vitalik "Decentralized Society" (soulbound) / SybilLimit** — non-transferable, attack-edge-bounded
  reputation.
- **Primecoin / Gridcoin / Mina** — why proof-of-useful-work can weight but not order.
