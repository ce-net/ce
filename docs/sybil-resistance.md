# CE Sybil resistance and mesh security

Status: research + audit, 2026-06-05. This document is the result of a code audit plus
adversarial verification (every finding was checked by two independent skeptics against the
real code) and a primary-source literature review. It supersedes nothing in
[threat-model.md](threat-model.md) — it extends it. Read that first for the mint -> pay ->
authorize -> execute -> contain framing; this document is the deep dive on **Sybil resistance**
specifically, plus the network-, marketplace-, and DoS-layer findings the threat model did not
yet cover.

CE aims to be global compute infrastructure. A break here does not cost "fake credits" — it
costs **control of machines**. The bar is correspondingly high.

> **Consensus follow-on:** the audit's finding that PoW is the wrong backbone for CE led to a full
> consensus bake-off — see [consensus.md](consensus.md). The recommendation (**CE-TWLE**: VRF
> leader election weighted by `min(bond, earned-work)`, no wasted compute) depends on this document's
> bond + verification machinery as its scarce anchor. The two are one system: consensus decides
> *whose vote counts*; this layer decides *whether the work was real*.

---

## 1. The one insight that frames everything

CE has **two distinct trust layers, and they need separate Sybil defenses. The current design
only addresses one.**

- **Consensus layer** (who writes blocks / mints credits): defended by PoW. Influence is
  proportional to hashpower, not to identity count. Spinning up 10,000 keypairs grants **zero**
  extra consensus weight. This part is sound and matches Nakamoto ("1-CPU-1-vote").
- **Peer / DHT / relay / marketplace layer** (who routes messages, advertises capacity, earns
  reputation, who you connect to, who you pay): **PoW does nothing here.** Peer identities are
  free Ed25519 keypairs. This is where CE is currently open.

This split is the load-bearing result of the literature. Douceur's 2002 impossibility theorem:
*without a central certifying authority, identities cannot be made Sybil-proof — only costly.*
PoW makes **consensus** costly; it leaves **network and marketplace** identities free. Bitcoin
has exactly this gap — it is why eclipse (Heilman 2015) and Erebus (Tran 2020) attacks exist
*despite* PoW.

The design goal is therefore not "make Sybils impossible" (unachievable) but **"make every thing
a Sybil can do unprofitable."** Today most of them are free.

A second framing, equally important: on a **young, low-difficulty** chain even the consensus-layer
protection is economically thin. CE sits at `MIN_DIFFICULTY = 8` bits (~256 hashes/block). Renting
enough hashpower to out-mine a small mesh costs ~nothing (cf. crypto51.app: many real PoW chains
cost under $1k/hour to 51%). So both layers need explicit, separate hardening before credits can
be treated as value.

---

## 2. What is already right (do not regress these)

The audit confirmed these defenses are real and correctly implemented:

- **Consensus integrity**: real Nakamoto PoW; difficulty retarget is deterministic and a miner
  cannot understate it; **fork choice is by cumulative work** (`ce-chain` `try_reorg`), not block
  count or longest-chain — the CLAUDE.md "first-wins" note is stale; timestamp median-time-past +
  future-drift bounds; sync-before-mine; supply-cap enforcement. Three plausible consensus
  attacks were specifically **checked and refuted** (see §5).
- **Control API**: not open. Binds `127.0.0.1` by default, every mutating endpoint requires a
  Bearer token (`<data_dir>/api.token`, chmod 600), the public relay firewalls `:8844` and nginx
  proxies only `/health`, `/bootstrap`, and read-only SSE.
- **Capability chains** (`ce-cap`): signed, attenuating, root-anchored, on-chain revocation.
  Structurally the right model — it is exactly what io.net lacked in their April 2024 breach.
- **Mesh transport auth**: libp2p-Noise authenticates the sender NodeId end-to-end; inbound RPC
  verifies `from_node` against the transport PeerId (`peer_id_from_node_id(&from_node) ==
  from_peer`). RPCs cannot be spoofed without the private key.
- **Gossipsub envelope signing**: `ValidationMode::Strict` + `MessageAuthenticity::Signed`. Every
  gossip message on all 7 topics is Ed25519-signed by its publisher. Origin spoofing at the
  transport layer is already impossible. (The gap is *application-level validation feedback*, not
  envelope signing — see finding N1.)
- **Signature domain separation**: two suspected cross-protocol signature-replay issues were
  **checked and refuted** — the signing helpers (`payer_settle_bytes`, `channel_receipt_bytes`,
  app-pubsub bytes) are adequately domain-separated.

---

## 3. Verified findings catalog

Severity is the adjudicated severity after adversarial verification (two skeptics per finding: one
checking code-correctness, one checking real-world exploitability/economics). "Status" reflects
their agreement: **confirmed** = both stand it up; **partial** = real but narrower than first
stated; **disputed** = skeptics split on severity.

### Consensus layer

| # | Finding | Sev | Status |
|---|---------|-----|--------|
| C1 | Cheap 51% via the pacing footgun | critical | confirmed |

**C1 — Cheap 51% via pacing footgun.** Honest nodes self-throttle mining to one attempt per
`mining_interval_secs` (default **10s**, `ce-node/src/lib.rs:223,395`; ticker at `:628`). An
attacker deletes that throttle and mines flat-out. At `MIN_DIFFICULTY = 8`
(`ce-chain/src/lib.rs:13`) blocks cost ~256 hashes, so one box produces a genuinely heavier
**valid** chain; honest nodes correctly reorg to it (cumulative-work fork choice), rewriting
history and the credits minted into it. Demonstrated: 895 valid blocks in 22s vs an honest mesh's
17 (~52x). Note the latent inconsistency that makes this worse: difficulty retargets toward
`TARGET_BLOCK_SECS = 600` (`ce-chain/src/lib.rs:11`) but at the 8-bit floor that target is never
reached, so **pacing — not difficulty — is the only thing limiting honest block rate.** Already
documented in [threat-model.md](threat-model.md); restated here because it is the dominant risk.
Fix directions: make block production genuinely difficulty-bound (remove the self-limiting pace),
raise `MIN_DIFFICULTY` substantially, and add **signed checkpoints / finality** (the standard
young-chain defense).

### Marketplace / economy layer

| # | Finding | Sev | Status |
|---|---------|-----|--------|
| E1 | Sybil mining reward inflation | medium | partial |
| E2 | Unverified capacity advertisement | high | disputed |
| E3 | Unconsented heartbeat drain (host bills a cell with no bid) | high | **FIXED** |
| E4 | Wash-traded reputation / unverified job work | low | partial |
| E5 | Off-chain receipt reuse across host restart | medium | confirmed |
| E6 | Heartbeat drains bid/channel/bond-locked funds (cross-type double-spend) | high | **FIXED** |

**E1 — Sybil mining inflation.** `UptimeReward` pays a flat per-block emission
(`ce-node/src/lib.rs:646`), and identities are free, so N identities on one machine earn ~N times
the reward share. Downgraded to **medium** on verification because total emission is still bounded
by PoW: the network can only produce so many blocks per unit time regardless of identity count, so
this is really "one machine with hashrate H gets H's worth of reward split across its identities" —
the harm is concentration, not unbounded minting. It becomes severe only when combined with C1
(unthrottled mining) or a bond-free reward model. The fix is the same bond that fixes E2/E3:
gate `UptimeReward` eligibility on a stake.

**E2 — Unverified capacity advertisement.** Capacity `CellSignal`s are *signed* (authorship) but
the values (`cpu`, `mem_mb`, `tag:gpu`) are never verified for truth
(`parse_capacity_signal`, `ce-node/src/lib.rs:2083`); the atlas trusts whatever is broadcast. A
Sybil advertises 1000 cores + `tag:gpu` and wins JobBids it cannot serve. This is precisely the
io.net April-2024 incident (1.8M fake GPUs registered for airdrop farming). Skeptics split on
severity (one noted the payer still gates payment via co-signature, bounding loss to wasted job
placement) — treat as **high** because it poisons scheduling decisions network-wide. Fix:
bond-and-challenge capacity (see §4.1).

**E3 — Unconsented heartbeat drain (FIXED).** Previously a `Heartbeat` was signed only by the host,
with no cell co-signature and no on-chain bid linkage; validation checked only host signature,
monotonic epoch, and cell balance. A malicious/modified host could bill any funded cell up to its
**entire free balance** with no bid and no proof work ran — a direct credit-theft surface (the old
`rogue_host_heartbeat_drains_cell_without_bid` test asserted this passed as a "KNOWN LIMITATION").

**Fixed in `ce-chain`:** a `Heartbeat` now carries a `job_id` and is only valid against an OPEN
`JobBid` whose `payer` equals the billed `cell` — i.e. the cell's own signed bid is the
authorization. Cumulative heartbeat cost billed against a job is bounded by that bid's locked escrow
(tracked in a `heartbeat_spent` cache); heartbeats draw the escrow down and the remainder unlocks on
`JobSettle`/`JobExpire`, and `JobSettle.cost` is likewise bounded by the *remaining* escrow so a job
cannot be double-charged. **Security property enforced: a host can never bill a cell beyond what that
cell escrowed via a `JobBid` the payer signed.** The rogue test is flipped to assert rejection
(regression), plus positive tests (`legit_heartbeat_within_open_bid_settles`,
`heartbeat_bounded_by_bid_escrow`, `heartbeat_rejects_exceeding_escrow`) confirm legitimate
long-running billing still settles within escrow. The residual, lower-severity gap is metering
*accuracy within* a consented budget (over-billing for compute not delivered, up to the bid) — tie
that to the verification dial (§4.2); it is no longer an unauthorized-billing hole.

**E4 — Wash-traded reputation.** `JobSettle` validates the payer co-signature and `cost <= bid`
but never verifies the host executed anything (`ce-chain/src/lib.rs:905`). One attacker runs
payer A + host B and self-settles to fabricate B's `/history` track record. Downgraded to **low**
on verification: the wash trade only moves the attacker's *own* credits between its own identities
(net-zero minus nothing, since no fee), so it buys a fake reputation but costs real mined credits
to stage, and only pays off if some honest party later trusts that reputation. It is the
**EigenTrust self-promotion / whitewashing** problem (any reputation system with free identities
and positive-feedback scoring is Sybil-vulnerable unless anchored to a cost). Fix: anchor
reputation to a bond, and never let reputation alone buy out redundant verification on high-value
jobs.

**E6 — Heartbeat cross-type double-spend (found during Phase 1 implementation, FIXED).**
`Heartbeat` validation checked the cell's *total* balance, not its *free* balance — it never
subtracted `locked_balance` (or in-block bids/bonds), unlike the transfer/bid/channel paths. A node
could lock its whole balance in a `JobBid` and still have those same credits drained by a
`Heartbeat`, leaving a negative free balance and double-spending the locked funds. Fixed in
`ce-chain` (`apply`/validation): the heartbeat check subtracts `locked_balance(cell)` plus the
cell's in-block bids and bonds. After the E3 fix, heartbeats bill against the bid escrow directly
(locked, pre-consented funds), so this cross-type drain is doubly closed; the regression test is
`heartbeat_bounded_by_bid_escrow` (formerly `heartbeat_cannot_drain_locked_funds`).

**E5 — Off-chain receipt reuse across restart.** Payment-channel receipts sign only
`(channel_id, host, cumulative)` with no per-channel served-state binding
(`ce-chain/src/lib.rs:285-286`); the host's `served` ledger is in-memory and resets on restart
(`ce-node/src/lib.rs:132-133`). After a host restart, a payer replays an old receipt for
`cumulative=X` and gets up to X of service again for free. Confirmed. Fix: persist the served
high-water mark per channel to disk, or bind receipts to monotonic per-channel state.

### Network layer

| # | Finding | Sev | Status |
|---|---------|-----|--------|
| N1 | No application validation feedback / no peer scoring / no rate limits | high | confirmed |
| N2 | Four gossip topics carry an unauthenticated in-payload node_id | high | confirmed |
| N3 | No DHT (Kademlia) eclipse hardening / no IP-diversity caps | high | confirmed |
| N4 | `allowed_peers` is dead code | high | confirmed |
| N5 | Sybil peer flooding via DHT/mDNS address injection, no connection filtering | medium | partial |
| N6 | `synced` flag race — mines on stale tip after one PeerHeight | high | confirmed |
| N7 | CellSignal nonce replay after node restart | high | confirmed |
| N8 | Single relay + single bootstrap domain chokepoint | medium | partial |

**N1 — No scoring / no validation feedback / no rate limits.** No `with_peer_score` anywhere in
`ce-mesh`; gossipsub never calls `report_message_validation_result`, so the P4 invalid-message
penalty cannot fire; no connection limits (the `libp2p-connection-limits` crate is not even a
dependency); no per-peer rate limiting. The whole gossipsub v1.1 Sybil/DoS defense layer is off.
This is the highest-leverage network fix and §4.3 specifies it concretely.

**N2 — Unauthenticated in-payload node_id.** `ce-heights`, `ce-syncreq`, `ce-syncresp`, and
`ce-segments` carry a `node_id` field in the payload that is **not** cross-checked against the
authenticated publisher (`decode_gossip`, `ce-mesh/src/lib.rs:1076-1116`). The gossipsub envelope
proves *which peer published*, but the payload can name a *different* node, letting a peer forge
height/sync-response claims that trigger reorg evaluation or poison segment-replica selection.
(Contrast: `CellSignal` and app-pubsub verify a payload signature.) Fix: either drop the redundant
`node_id` field and trust the authenticated publisher, or require a payload signature, and feed
malformed messages to P4 via `Reject`. Note: a *related* claim ("unsigned topics allow spoofed
capacity ads because burn_proof is optional") was **refuted** — capacity ads are signed; the issue
is value-truth (E2), not signature.

**N3 — No DHT eclipse hardening.** Default libp2p Kademlia, no IP-diversity filter (rust-libp2p
has no built-in equivalent of go-ipfs 0.7's `peerdiversity`), provider records unverified
(`ce-mesh/src/lib.rs:645-649`, `add_address` at `:721,733,804`). A Sybil set can fill routing
tables and answer `GetProviders` with attacker peers. IPFS hit exactly this (the 29TB
pregenerated-PeerID attack) and fixed it with IP-diversity caps. Fix in §4.3.

**N4 — `allowed_peers` is dead code.** Populated (`ce-mesh/src/lib.rs:720,731`) and documented as
"non-members are immediately disconnected" (`:577`), but **nothing enforces it.** Either wire it on
`ConnectionEstablished` or delete it so it does not read as a live protection.

**N5 — Sybil peer flooding.** mDNS-discovered and identify-advertised peers are added and dialed
without filtering; combined with N3, an attacker injects many addresses. Partial: real, but the
practical ceiling is set by connection limits (absent — see N1) rather than a distinct mechanism.
Fixed by the same connection-limits + diversity-cap work.

**N6 — `synced` flag race.** A node sets `synced = true` after a single PeerHeight announcement at
or below its own height, without confirming blocks were actually received
(`ce-node/src/lib.rs:967-972`), then mines on its own (possibly stale) tip. Under an eclipse, an
attacker uses this to keep a victim mining a doomed fork while the attacker builds a heavier one.
Fix: require actual block delivery / a quorum of peer heights before clearing the sync gate.

**N7 — CellSignal nonce replay after restart.** Per-sender `last_nonce` replay protection is
in-memory and resets on restart (`ce-node/src/lib.rs:864,1322-1332,1370`), so a captured signal
replays 100% after a victim restart. The companion DoS (**N7b, confirmed high**) is that the
`last_nonce` map is unbounded and never cleaned up — a Sybil broadcasting from many free identities
grows it without limit. Fix: persist nonces (or a monotonic timestamp) across restart, bound the
map, and expire idle senders.

**N8 — Single relay + bootstrap chokepoint.** One Hetzner relay (`178.105.145.170`) and one
bootstrap domain (`ce-net.com`) is a topological partition/observation chokepoint (an Erebus-style
position) and a single point of failure. Partial severity (it is operational risk more than a
direct exploit) but **structurally important**: the roadmap's "multi-bootstrap resilience" is a
*security* item. Run >=3 independent relays/bootstrap domains.

### DoS layer

| # | Finding | Sev | Status |
|---|---------|-----|--------|
| D1 | Kill-RPC authorization is coarse — any "kill" cap kills any job | high | confirmed |
| D2 | Unpaid relay window — free relaying before first receipt | high | confirmed |
| D3 | AppRequest response-channel leak (10-min timeouts held) | high | confirmed |
| D4 | SSE stream resource exhaustion (unbounded subscribers) | high | disputed |
| D5 | Relay circuit exhaustion (default libp2p relay config) | medium | disputed |

**D1 — Kill-RPC authorization bypass.** The mesh-kill handler checks the caller holds a "kill"
capability but does **not** verify the caller is the job's payer/owner before stopping the
container (`ce-node/src/lib.rs:1704,1708-1709`; `JobRecord.payer` exists at `:111` and deploy sets
it at `:1649` but kill never reads it). Anyone holding *any* "kill" capability — including a coarse
or self-issued-then-accepted one — can terminate *any* job by `job_id`. This is an
authorization-granularity bug: the capability gates the *action class*, not the *resource
instance*. Fix: bind the kill to the job's `payer`/owner (the capability resource must scope to the
job or its owner, and the handler must check it). This is the most important *new* finding from the
hunt — categorized as capability/authz, high.

**D2 — Unpaid relay window.** The relay charges per `RelayReceipt`, but `first_receipt_secs` is set
on the *first* receipt (`ce-node/src/lib.rs:1449-1452`), and the relay server uses
`relay::Config::default()` with no admission control (`ce-mesh/src/lib.rs:678`). Bytes relayed
before the first receipt are free. Fix: meter/withhold relay until a reservation is paid, and set
explicit relay limits (§4.3).

**D3 — AppRequest response-channel leak.** `pending_inbound` is an unbounded map
(`ce-mesh/src/lib.rs:567`); entries are removed only on `respond_rpc` (`:955`), and `InboundFailure`
does not correlate back to clean them up (`:872-874`). An app that never replies leaves channels
held for the full 10-minute libp2p timeout. Fix: bound the map, and remove entries on
inbound-failure / timeout.

**D4 — SSE subscriber exhaustion / D5 — relay circuit exhaustion.** Disputed severity (one skeptic
each judged them low-impact under realistic conditions), but both are cheap to fix and worth doing:
cap concurrent SSE subscribers, and replace `relay::Config::default()` with explicit reservation
limits (§4.3).

---

## 4. The defense design

The literature is unambiguous about the hierarchy. **Cheap-but-weak defenses raise nuisance cost;
only economic defenses change the attacker's math.** Three pillars, in leverage order.

### 4.1 Pillar 1 — Bond + slashing (the economic backbone)

This is the single highest-leverage change. It turns "spin up 10,000 identities" from a scripting
problem into a *capital* problem, and it is the thing the current "hunch" design is missing. CE
already has the substrate: `i128` balances with a "locked" concept (`JobBid` locks `bid`,
`ChannelOpen` locks `capacity`, `locked_balance()` sums them), `NodeStats` reputation, and
`/beacon` verifiable randomness. A bond is just another lock with a slow release.

**Design (grounded in Filecoin / Ethereum / Akash):**

- **One standing `HostBond` per host**, gating *both* capacity-ad publication *and* `UptimeReward`
  eligibility. Do **not** bond per-job (the existing `JobBid` lock already covers payer-side risk,
  Akash-style) and do **not** bond raw mining (PoW already pays its own cost; bonding mining
  centralizes it). The bond gates the *marketplace role*, not block production.
- **Size in expected-reward-days, not fixed credits** (Filecoin sizes StoragePledge this way, so
  it survives halvings/price swings): `bond >= 2 x (max JobSettle revenue the capacity ad unlocks
  per challenge interval)` plus a capacity-proportional term so faking 100x capacity costs ~100x
  bond.
- **Slash only on the three on-chain-provable fault classes:**
  1. **Equivocation** (two conflicting host-signed messages) -> burn 100% of bond. Filecoin
     `ReportConsensusFault` model.
  2. **Fake capacity** caught by a `/beacon`-seeded challenge whose miss is provable by on-chain
     *absence* of a `ChallengeResponse` -> `FaultFee = 1/32 of bond` (Ethereum's initial-penalty
     fraction), self-healing, NOT confiscation (this is the flaky-hardware safety valve).
  3. **Failed redundant verification** (minority result-hash vs >2/3 supermajority on a `verify=k`
     job) -> slash = disputed `bid` x penalty multiplier, capped at bond.
- **The decisive honest-host protection: an Ethereum-style correlation multiplier**
  `min(1, 3 * S/T)` over a 2016-block window (S = bonded stake slashed for the same fault class in
  the window, T = total bonded stake). A lone host whose GPU crashes loses only the tiny FaultFee;
  a colluding ring that fails together loses near-100%. This mathematically separates "my hardware
  failed" from "we coordinated an attack."
- **Never auto-slash for non-deterministic/GPU output correctness** (not on-chain-provable — that
  is Akash's deliberate choice; leave it to withheld `JobSettle` co-signatures + `NodeStats`).
  **Route slashed stake to reporter-reward + burn**, never to the payer or other hosts (avoids
  fraudulent-dispute and self-slashing-collusion incentives). Make every slash tx idempotent via a
  `slashed` set mirroring the existing `revoked` set. Unbonding period `UNBOND_BLOCKS = 2016`
  (~one difficulty epoch) during which funds stay slashable so a host cannot cheat-then-flee.

New `TxKind` sketches (`HostBond`, `HostUnbond`, `CapacityAd`, `ChallengeResponse`, `JobResult`,
`SlashEquivocation`, `SlashCapacityChallenge`, `SlashVerificationFault`) follow the existing
signed-message + lock patterns; full forms are in the research appendix (commit notes).

**Pitfalls (do not mis-implement):** redundant verification only proves minority-vs-consensus, not
absolute correctness — require k>=3, >2/3 supermajority, beacon-seeded verifier selection (not
payer choice), deterministic jobs only. Provable-by-absence is eclipse-sensitive — a censored
`ChallengeResponse` looks like a fault, which is exactly why missed challenges are a FaultFee, not
confiscation. The correlation penalty has a self-slashing griefing edge — bound M and cap
per-window slash.

### 4.2 Pillar 2 — Verification as a per-job dial

Per [primitives.md](primitives.md), verification *policy* is an **app** (scheduler) concern, not a
node primitive. Keep it there. The job request carries one `verify:` enum; cost and latency scale
with the tier, and the tier defaults track the trust gradient (strangers forced high, earned hosts
cheap, owned hosts T0).

| Tier | Assurance | Cost | Use |
|------|-----------|------|-----|
| **T0 interactive/visualized** | human perception | ~0 | games, render, sims, shells. Heartbeat pay-as-you-go *is* the check. CE's native case. |
| **T1 spot-checked** | probabilistic audit | 1x + e | single host; re-run on an independent beacon-selected host with prob `p = nu*(1-t)` (Golem's reputation-weighted sampling); mismatch -> slash + auditor jackpot (Truebit's verifier-dilemma fix). Deterministic jobs only. |
| **T2 redundant K-of-N** | majority vote | Nx | default N=3/K=2, hosts chosen by `/beacon` so neither requester nor colluder can steer placement; compare output hash (deterministic) or NAO tolerance bands (ML). |
| **T3 fraud-proof** | 1 honest verifier | 1x + cheap disputes | optimistic single run + Merkle execution-trace commitment; challenge opens a bisection game (Truebit for VMs, Gensyn Verde two-level for ML) that pinpoints one step a referee re-runs. Best cost/assurance for long deterministic / RepOps-ML jobs. |
| **T4 attested** | hardware TEE | ~+30% | SGX/TDX + H100 remote attestation. Confidential or un-re-runnable work only; **fold into reputation, never trust standalone.** |

**Three CE-side enablers — and *only* these belong in the node/chain** (everything else stays in
the app):
1. Make `/beacon` (PoW tip height+hash) the canonical **unbiasable** seed for replica placement:
   commit the JobBid first, derive the N hosts from a *future* beacon value so neither requester
   nor colluder can grind selection. This is the only real defense against Sybil-collusion silently
   defeating K-of-N.
2. A **generic on-chain bond+slash escrow** hook (not verification-specific tx types — keep CE
   generic) so a challenger can be paid from a host's bond. This funds the jackpot that solves the
   verifier's dilemma.
3. At T2+, require **determinism**: gVisor + pinned image digest + WASM/wasi or a RepOps-style
   fixed-FP-order runtime for ML; otherwise fall back to NAO empirical tolerance bands.

**Pitfalls:** K-of-N is theater if one operator secretly runs k of the n hosts (Douceur) — beacon
placement + per-identity bonds are mandatory, not optional. Naive output-hash comparison **fails
for GPU/ML** (IEEE-754 non-associativity makes honest hosts disagree at the bit level) — pin FP
order (RepOps, ~20-30% slower) or use tolerance bands; do not ship hash-compare for ML. TEE
attestation proves code *identity*, not *correctness*, and is breakable (SGAxe/CacheOut can forge
valid quotes; Foreshadow reads enclave memory) and reintroduces Intel/NVIDIA vendor trust —
against CE's no-lighthouse invariant. Reputation-weighted sampling enables the exit scam — cap
per-host value exposure regardless of reputation and keep heartbeat pay-as-you-go.

### 4.3 Pillar 3 — Network-layer hardening (cheap, do all of it)

Concrete rust-libp2p 0.53 work for `ce-mesh`, in priority order. These are low-effort and close
N1-N5, N8, D2, D5.

1. **Wire P4 first (highest ROI, no scoring needed yet).** Add `.validate_messages()` to the
   gossipsub `ConfigBuilder` (`ce-mesh/src/lib.rs:632`) and, in the message handler, call
   `report_message_validation_result(&id, &src, MessageAcceptance::{Accept|Reject|Ignore})` using
   CE's existing block/tx validators. **Reject** only on provably-invalid (bad PoW, bad Ed25519
   sig, malformed bincode); **Ignore** on valid-but-stale. (Mis-using Reject for stale sync
   messages will graylist honest peers mid-sync — the classic footgun.)
2. **Enable peer scoring** with CE-tuned values (small-mesh-scaled from Ethereum consensus-specs):
   `decay_interval=12s`, `topic_score_cap=100`, **P4 invalid-message weight `-100`**, **P6
   IP-colocation weight `-35`, threshold `2`** (not Ethereum's 10 — on a small mesh >2 peers per
   /24 is presumptively one operator's Sybils), P7 behaviour weight `-15`. **Ship with P3/P3b
   mesh-delivery scoring OFF (`weight=0`)** until the mesh is warm (>=8 stable peers/topic, steady
   block rate) — statistical scoring on a cold mesh penalizes honest peers for the network's own
   quietness and causes partition. Thresholds: `gossip=-100, publish=-200, graylist=-400`.
3. **P5 -> economy (the bridge that imports economic Sybil resistance into the transport layer).**
   `app_specific_weight=1.0`; recompute `set_application_score(peer)` each interval from the peer's
   on-chain bond + `/history` reputation; drive slashed/revoked peers to `-300` (instantly below
   graylist, ignored mesh-wide without a hard disconnect). Minting N PeerIds is free, but earning
   positive P5 requires N bonds/histories — *this is the only network defense with unbounded Sybil
   cost.*
4. **Connection limits** (add the `libp2p-connection-limits` crate): `max_established_per_peer=2`,
   `max_pending_incoming=16`, `max_established_incoming=128`. Admission-control floor that stops
   socket-exhaustion DoS — scoring cannot, because scoring needs an established connection to act.
5. **Manual Kademlia /24 IP-diversity cap** at the `add_address` sites
   (`ce-mesh/src/lib.rs:721,733,804`): max 1 peer per /24 per k-bucket, ~3 per /24 table-wide
   (the go-ipfs 0.7 fix; rust-libp2p has no built-in filter, so hand-roll it).
6. **Replace `relay::Config::default()`** (`ce-mesh/src/lib.rs:678`): on NAT'd nodes drop the relay
   *server* entirely (keep `relay_client`); on the Hetzner relay set explicit go-libp2p-style limits
   (`MaxReservationsPerIP=4`, `MaxReservationsPerASN=16`, `ReservationTTL=1h`, `MaxCircuits=16`) and
   raise per-circuit duration/data deliberately for tunnels, metered through the existing
   `RelayReceipt` channel (also closes D2).
7. **Run >=3 independent relays/bootstrap domains** (closes N8).

**Critical pitfall specific to CE's own topology:** P6 IP-colocation and the /24 diversity cap will
**penalize Leif's own laptop + desktop** (both behind the same home NAT, both presenting the relay's
IP on circuit-relayed connections). Whitelist capability-rooted own-peers from P6/diversity, and
**skip colocation scoring entirely on `/p2p-circuit` addresses** (relayed peers present the relay's
IP, so colocation there is meaningless).

---

## 5. Checked and refuted (do not re-chase these)

The adversarial pass refuted six candidate findings. Recording them so future audits do not
re-litigate settled ground:

- **Unvalidated block difficulty in fork choice** — refuted; `try_reorg`/`append` re-derive and
  enforce expected difficulty; a low-difficulty replay chain is rejected, not adopted.
- **2-hour future-drift enables difficulty underestimation** — refuted; median-time-past + retarget
  math bound this.
- **Reorg does not validate cumulative-work consistency across state** — refuted; suffix-work is
  recomputed and only strictly-heavier chains are adopted.
- **Unsigned topics allow spoofed capacity ads (burn_proof optional)** — refuted; capacity ads are
  signed. The real issue is value-truth (E2), not signature.
- **Missing domain separation between tx sig and payer co-sig** — refuted; distinct signing-byte
  prefixes.
- **AppPubSubMsg signature lacks topic domain separator** — refuted; topic is covered and checked.

---

## 6. Prioritized roadmap

Ordered by (leverage / effort). Honest framing for the README/threat-model: *PoW gives CE Sybil
resistance over consensus weight only; network-, marketplace-, and reputation-layer Sybil
resistance comes from bonding + slashing + redundant verification, not from PoW. A young
low-difficulty chain is additionally cheap to 51% until difficulty and honest hashrate are large.
Do not treat credits as value until P0/P1 land.*

- **P0 — consensus (blocking for value):** fix C1 (difficulty-bound block production + raise
  `MIN_DIFFICULTY` + signed checkpoints/finality). N6 (sync race) and N7 (nonce persistence) ride
  along.
- **P1 — economic backbone:** Pillar 1 bond+slashing (fixes E1, E2, E3, and anchors E4). This is
  the core Sybil fix.
- **P2 — network hardening (cheap, parallelizable):** Pillar 3 steps 1-7 (fixes N1-N5, N8, D2, D5).
- **P2 — authz + DoS correctness:** D1 (bind kill to job owner — small, high-value), D3 (bound
  `pending_inbound`), D4 (cap SSE subscribers), E5 (persist channel served-state).
- **P3 — verification dial:** Pillar 2 (the three CE-side enablers, then the app-side tiers).

---

## 7. References (primary sources)

Sybil theory and consensus attacks:
- Douceur, *The Sybil Attack* (2002) — https://www.freehaven.net/anonbib/cache/sybil.pdf
- Heilman et al., *Eclipse Attacks on Bitcoin* (USENIX 2015) — https://eprint.iacr.org/2015/263 ;
  https://www.ethanheilman.com/p/eclipse/index.html
- Tran et al., *Erebus* (IEEE S&P 2020) — https://ihchoi12.github.io/assets/tran2020stealthier.pdf
- Eyal & Sirer, *Majority is Not Enough* (2014) — https://arxiv.org/abs/1311.0243
- 51%-attack costs — https://www.crypto51.app/

libp2p hardening:
- Gossipsub v1.1 spec — https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md
- Ethereum consensus-specs scoring (PR #2665) — https://github.com/ethereum/consensus-specs/pull/2665/files
- Circuit Relay v2 spec — https://github.com/libp2p/specs/blob/master/relay/circuit-v2.md ;
  go-libp2p default resources — https://github.com/libp2p/go-libp2p/blob/master/p2p/protocol/circuitv2/relay/resources.go
- IPFS DHT hardening (go-ipfs 0.7) — https://github.com/ipfs/kubo/issues/7560 ;
  https://blog.ipfs.tech/2020-10-30-dht-hardening/

Bonding / slashing:
- Filecoin collateral & slashing — https://spec.filecoin.io/systems/filecoin_mining/miner_collaterals/ ;
  https://docs.filecoin.io/storage-providers/filecoin-economics/slashing ;
  FIP-0011 — https://github.com/filecoin-project/FIPs/blob/master/FIPS/fip-0011.md
- Ethereum PoS slashing & correlation penalty — https://eth2book.info/latest/part2/incentives/slashing/ ;
  https://ethereum.org/developers/docs/consensus-mechanisms/pos/attack-and-defense/
- Akash payments / bids-and-leases — https://akash.network/docs/getting-started/intro-to-akash/payments/

Verifiable computation:
- Golem gWASM verification — https://blog.golem.network/gwasm-verification/
- Truebit — https://people.cs.uchicago.edu/~teutsch/papers/truebit.pdf
- Gensyn Verde / RepOps — https://arxiv.org/html/2502.19405v1 ;
  https://blog.gensyn.ai/verde-a-verification-system-for-machine-learning-over-untrusted-nodes/
- NAO (tolerance-band ML verification) — https://arxiv.org/html/2510.16028v1
- GPU/FP non-determinism — https://arxiv.org/html/2408.05148v3
- TEE attestation & breaks — NVIDIA HCC whitepaper; SGAxe/CacheOut — https://cacheoutattack.com/ ;
  Foreshadow — https://www.anjuna.io/blog/foreshadow

Reputation:
- EigenTrust — https://nlp.stanford.edu/pubs/eigentrust.pdf ; P2P reputation attack survey —
  https://cnitarot.github.io/papers/p2p-reputation-survey.pdf
- SybilLimit — https://nymity.ch/sybilhunting/pdf/Yu2008a.pdf

DePIN incident:
- io.net April 2024 postmortem — https://ionet.medium.com/25th-april-incident-report-176e5fb5c576
