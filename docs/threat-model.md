# CE threat model

CE is not a currency where a break costs money — it is a **compute fabric where a break costs
control of machines**. An attacker who defeats CE doesn't get "fake credits"; they get the ability
to run code on participating devices, amplified by self-replication. Security is therefore about the
whole path **mint → pay → authorize → execute → contain**, designed fail-closed and least-privilege.

> **Companion document:** [sybil-resistance.md](sybil-resistance.md) is the deep audit of Sybil
> resistance plus the network-, marketplace-, and DoS-layer findings (each adversarially verified
> against the code and cross-referenced to the literature), and the three-pillar defense design
> (bond+slashing, verification dial, libp2p hardening). The core insight there: **PoW gives CE
> Sybil resistance over consensus weight only — the peer/DHT/relay/marketplace layer gets none from
> PoW and needs its own economic defenses.** Paths C and D below summarize what that audit added to
> this model. The audit's conclusion that PoW is the wrong backbone for CE led to a consensus
> bake-off and a recommended replacement — **CE-TWLE** (VRF leader election weighted by
> `min(bond, earned-work)`, zero wasted compute) — documented in [consensus.md](consensus.md). It
> eliminates Path A's cheap-51% by removing PoW; its Phase 0 (a mandatory settlement burn that kills
> the wash-trade leak) ships on the current chain first.

## The three paths to running an attacker's code on a victim

### Path 0 — reach the node's control API directly
**Risk:** the HTTP API exposes value-moving endpoints (`/transfer`, `/capabilities/revoke`,
`/mesh-deploy`, `/mesh-kill`, `/jobs/*`, `/channels/*`, `/tunnel`, `/signals/send`).
**Defense (implemented):**
- API binds **`127.0.0.1`** by default (`--api-bind` to override; a non-loopback bind logs a warning).
- Every **mutating (non-GET) request requires a Bearer token** (`<data_dir>/api.token`, chmod 600,
  derived from the node identity; `$CE_API_TOKEN` overrides). Read-only GETs stay open.
- On the public relay: UFW denies `:8844`; nginx proxies only `/health`, `/bootstrap`, and the
  read-only SSE streams from localhost.

### Path A — forge the economy (free credits → free compute)
**Risk:** if blocks are free to produce, an attacker mints unlimited credits and buys unlimited jobs.
**Defense (implemented):** real Nakamoto PoW —
- every block must satisfy its declared **difficulty** (`has_leading_zeros`), enforced in
  `Chain::append` (the single chokepoint `try_reorg` also routes through);
- difficulty is fixed by a deterministic **retarget** (a miner can't understate it);
- **fork choice is by cumulative work**, not block count, so the heaviest chain wins and honest
  miners converge instead of each forking their own;
- **timestamp** median-time-past + future-drift bounds resist timewarp;
- **sync-before-mine** stops a fresh node forking its own chain;
- clean-break on-disk format (version-prefixed) so incompatible chains are rejected, not misread.

**What PoW does NOT defend, stated honestly:** the rules above reject *forged* (no-work) and
*understated-difficulty* blocks. They do **not** stop an attacker who does *real* work and simply
has more of it. **A majority of hashrate wins, by design** — and on a small or young network that
majority is **cheap**.

> ### CRITICAL, CONFIRMED: cheap 51% takeover — and CE makes it cheaper
> Honest nodes **self-limit** mining to one block per `mining_interval` (the pacing ticker in
> `mining_loop`). An attacker forks out that one line and mines **valid** PoW flat-out. At the low
> difficulty a small network sits at, **a single box out-produces the entire paced honest mesh**,
> builds a genuinely heavier *valid* chain, and honest nodes **correctly reorg to it** — history
> rewritten, credits minted, payments double-spent.
>
> **Demonstrated.** A 5-node paced honest mesh reached height 17 in 40s; an attacker that only
> removed the pacing line produced a *valid* 895-block chain in 22s on **one machine** (~52× the
> honest rate). On rejoin the honest nodes reorged to it (17 → 1529), adopting the attacker's
> history and the 900,000 credits it minted to itself. (Test kept private — it's an attack recipe.)
>
> The pacing floor throttles *honest* hashrate but not the attacker, so this is **cheaper than a
> normal 51%**: you don't need a majority of the hardware, only to ignore a speed limit everyone
> else obeys. Anyone who can run the (low) honest difficulty faster than the honest aggregate wins.
>
> **This is not fixed.** It is the dominant risk before there is large, decentralized honest
> hashrate. Directions (none yet implemented):
> - Remove the self-limiting pacing footgun, or make block production genuinely difficulty-bound
>   (so honest hashrate isn't throttled below an attacker's).
> - Raise `MIN_DIFFICULTY` / require meaningful work even at genesis (raises the floor cost).
> - **Checkpoints / finality** (signed checkpoints, or a finality gadget) so deep reorgs are
>   rejected regardless of work — the standard defense for young chains.
> - Don't treat credits as real money until honest hashrate is large and difficulty reflects it.
>
> Until then: **CE's economy is only as secure as its total honest hashrate, which on today's tiny
> mesh is trivially exceeded.** Do not rely on it for value.

### Path B — forge or steal authority (capabilities → exec/spawn)
**Risk:** a forged/stolen capability or a too-loose `spawn` grant runs code on a host; with
self-replication, one compromise propagates down the tree.
**Defense:**
- **Capabilities** (`ce-cap`) are signed, attenuating chains rooted at an accepted key; `authorize`
  enforces subset-attenuation, expiry, audience, and root at every link. Privilege can only shrink.
- **Mesh transport** is libp2p-Noise: the sender's NodeId is authenticated end-to-end; inbound
  Deploy/Kill RPCs require a capability **and consult on-chain revocation**.
- **Revocation** is on-chain (`RevokeCapability`) + expiry; `rdev serve` now consults the node's
  `/capabilities/revoked` set (refreshed periodically) and denies revoked chains.
- **`rdev/spawn`** (the unsandboxed host-exec edge) is default-deny: it requires the `spawn`
  ability **and** a program on `$RDEV_SPAWN_ALLOW`, runs with a **scrubbed environment**, and
  confines `cwd` to the target's home.
- **`rdev/exec`** runs in a gVisor container with no network.

### Path C — multiply identities to farm the marketplace (Sybil economics)
**Risk:** identities are free Ed25519 keypairs, so a single operator can run N of them. PoW caps
*consensus* weight per hashrate, but nothing caps *marketplace* weight per identity. Verified
findings (see [sybil-resistance.md](sybil-resistance.md) §3):
- **Sybil reward concentration** — `UptimeReward` is flat per block; N identities split a machine's
  hashrate into N reward streams. Bounded by total PoW, but uncapped per identity. (E1)
- **Unverified capacity ads** — `CellSignal` capacity values (`cpu`, `mem_mb`, `tag:gpu`) are signed
  but never checked for truth; a Sybil advertises capacity it doesn't have and wins JobBids it can't
  serve (the io.net April-2024 fake-GPU pattern). (E2)
- **Unverified heartbeat billing** — `Heartbeat.amount` carries no proof-of-work-done metric, so a
  host can still over-bill *within* a job for compute it didn't deliver. The **unconsented drain** is,
  however, closed (E3, FIXED): a `Heartbeat` must now name an OPEN `JobBid` whose `payer` equals the
  billed cell, and cumulative heartbeat cost per job is bounded by that bid's locked escrow — so a host
  can never bill a cell beyond what the cell itself escrowed via a bid it signed. The residual gap is
  metering accuracy *inside* a consented budget, not unauthorized billing. (E3)
- **Wash-traded reputation** — `JobSettle` never verifies host work, so payer+host identities owned
  by one attacker self-deal to fabricate `/history` reputation (the EigenTrust self-promotion
  problem). (E4)
- **Off-chain receipt reuse** — payment-channel `served` state is in-memory; after a host restart a
  payer replays an old receipt for free service. (E5)

**Defense (planned, not yet implemented):** a single standing **`HostBond`** that gates capacity-ad
publication and `UptimeReward` eligibility, slashable only on the three on-chain-provable fault
classes (equivocation, fake-capacity-by-`/beacon`-challenge, failed redundant verification), with
an Ethereum-style correlation multiplier so flaky hardware pays a small FaultFee while a colluding
ring loses near-100%. Plus a per-job **verification dial** (T0 interactive → T4 TEE-attested) seeded
by `/beacon` for unbiasable replica placement. Full design in sybil-resistance.md §4.1–4.2.

### Path D — network / authz / DoS holes
**Risk:** the libp2p layer has no Sybil/DoS defenses configured, and one authz check is too coarse.
Verified findings (see [sybil-resistance.md](sybil-resistance.md) §3):
- **Kill-RPC authorization is coarse** — mesh-kill checks the caller holds a "kill" capability but
  not that it owns the target job, so any "kill" cap can stop **any** job by `job_id`. Bind kill to
  the job's `payer`/owner. (D1, the most important new finding)
- **No gossipsub peer scoring / no validation feedback / no connection limits / no rate limits** —
  the entire gossipsub v1.1 Sybil/DoS layer is off; P4 can't fire because the app never reports
  validation results. (N1)
- **Four topics carry an unauthenticated in-payload `node_id`** (`ce-heights`, `ce-syncreq`,
  `ce-syncresp`, `ce-segments`) — the envelope is signed but the payload can name another node,
  enabling forged height/sync claims. (N2)
- **No Kademlia IP-diversity caps** (eclipse / routing-table poisoning), **dead `allowed_peers`**,
  **`synced`-flag race**, **CellSignal nonce replay + unbounded nonce map**, **unpaid relay window**,
  **AppRequest channel leak**, **single relay/bootstrap chokepoint**. (N3–N8, D2–D5)

**Defense (planned):** Pillar 3 in sybil-resistance.md §4.3 — wire P4 validation feedback, enable
peer scoring with P6 IP-colocation and **P5 bound to on-chain bond/reputation** (the bridge that
makes Sybil cost economic at the transport layer), add connection limits, hand-roll Kademlia /24
diversity caps, set explicit circuit-relay-v2 limits, run ≥3 independent relays. Note: P6/diversity
must whitelist capability-rooted own-peers and skip `/p2p-circuit` addrs, or it penalizes CE's own
laptop+desktop behind one NAT.

## Known residual risk / follow-ups
- **Signed-binary attestation** for replication is not yet enforced: a `sync` cap can overwrite an
  allow-listed binary's bytes, so a compromised seed could push a trojan over an allow-listed name.
  The spawn allowlist limits *which names* run; signing the bytes (org-root-signed sha256 verified
  before spawn) would close the overwrite path. Planned.
- **Per-request replay envelope** (signed nonce + freshness) is not yet added. Mitigated today by
  Noise sender-authentication and capability expiry; planned for defense-in-depth.
- **Privilege drop / rlimits** on spawned host processes (run as a non-root user, cap CPU/mem) —
  planned; run `rdev serve` as a non-root user meanwhile.
- No external audit / fuzzing yet; consensus security scales with participation.

## Test coverage
Adversarial unit + integration tests exist for: PoW rejection, understated-difficulty rejection,
timestamp rejection, work-based reorg, two-miner convergence, API token gating, capability
attenuation/expiry/audience/escalation, delegation rooted at an org key, and spawn allowlist/auth.
