# CE Platform Primitives

**What CE provides to everyone, and — just as importantly — what it deliberately does not.**

CE is a substrate, not a product. This document is the contract: the primitives every
node exposes and every app can build on, the guarantees behind them, and the boundary
that keeps CE small and interoperable.

---

## The governing rule

> **CE owns generic, node-enforced mechanism. Apps own policy.**

Two constraints fix where the line falls:

1. **The node is the enforcement point.** A device receiving a `deploy`/`exec`/`sync`
   request must decide whether to run it *inside `ce-node`*, before acting. So anything
   that must be *enforced* lives in CE — but it stays generic (keys, amounts, permissions,
   tag-selectors), with no product concepts (no company, team, reputation score, scheduler).
2. **CE is always trustless.** Consensus is proof-of-work / longest-chain. There is no
   federated quorum, no lighthouse authority, no global reputation oracle. Trust is built
   *by each participant* on top of the substrate — never granted by it.

The analogy: CE is the Linux kernel / container runtime; the schedulers, reputation
systems, and marketplaces are the Kubernetes and the Rays that run on it.

---

## The primitives

### 1. Identity
Ed25519 keypair. A **NodeId** (`[u8;32]`, 64 hex) *is* a principal — a person, a device, an
app are all just keys. Sign / verify. No accounts, no registration. (`ce-identity`)

### 2. Money — trustless credit ledger
A PoW blockchain of credit balances. Integer **base units**, never floats (floats are
non-deterministic and split consensus): `1 credit = CREDIT (10^18) base units`, amounts
`u128`, balances `i128`, `SUPPLY_CAP = 21e9 * CREDIT`. Emission: 1,000 credits/block,
halving every 210,000 blocks. Transfer credits between any two keys. (`ce-chain`)

### 3. Interaction history — the reputation substrate
The chain is an **immutable, global record of who served whom**: every `JobSettle`,
`Heartbeat`, `JobExpire`, and `Transfer` is permanent and verifiable. CE does not score
reputation — it *guarantees the facts* from which any app computes its own trust. This is
the raw material the trust economy runs on (see [Trust gradient](#the-trust-gradient)).

### 4. Placement & discovery — the atlas
Nodes advertise capacity + **capability self-tags** (`gpu`, `docker`, `linux`, `x86_64`,
`manycore`, `highmem`, …) over CEP-1 every 60s; peers cache it. `GET /atlas` returns the
map of `NodeId → {cpu, mem, running_jobs, tags, last_seen}`. This is how a client finds
hosts that *can* do the work — and the surface that grant selectors and (future) random
placement match against.

### 5. Jobs — the spot compute market
- `JobBid` — a payer offers up to `bid` credits for a workload (image/cmd/cpu/mem/duration).
  Credits are **escrowed** (locked) on bid.
- A host with capacity accepts and runs it.
- `JobSettle` — host records cost ≤ bid; **payer co-signs** (signature binds the host id, v2);
  cost moves payer → host.
- `JobExpire` — payer reclaims the lock after `EXPIRY_BLOCKS` if never settled.
- No free balance → `POST /jobs/bid` returns `402`.

### 6. Execution — sandboxed run
Run a container (cell) or one-shot command on a remote node. gVisor when available, no
network, CPU/mem limits, removed on exit. `POST /exec` (HTTP) and `RpcRequest::Exec` (mesh).
File transfer via `PUT /sync/*path` and `RpcRequest::SyncFile`. Home dir bind-mounted at
`/workspace`.

### 7. Billing for long work — heartbeats & burn-pay
- `Heartbeat` — periodic (30s) debit cell → host for a long-running cell. Pay-as-you-go:
  the cell's wallet exhausting terminates the container. Epochs strictly increase
  (replay-proof). **This is the economic lever:** you keep paying only while the work is good.
- `BurnProof` — proof that credits were spent (a referenced on-chain tx) before a CEP-1
  signal is accepted; the burn must be originated by the signal sender (no theft).

### 8. Messaging — cell & node addressing
- **CEP-1 cell signals** (`ce-protocol-1` gossip): broadcast or addressed signals between
  cells, carrying capabilities + optional payload + optional burn proof. SSE push via
  `/signals/stream`. This is how interdependent tasks talk (e.g. gradient all-reduce — the
  *workload's* sync pattern, not baked into CE).
- **Mesh RPC** (`/ce/rpc/1`, request/response): node-to-node, libp2p-noise-authenticated.
  All device-to-device features route through the mesh (relay-assisted NAT traversal),
  never direct HTTP to a stored ip:port.

### 9. Authorization — scoped capability grants
Replaces all-or-nothing trust. A trusted admin signs a `Grant` delegating a subset of its
authority: `{permissions × tag-selector × constraints × expiry}`. Enforced at both gates
(HTTP `X-CE-Grant`, mesh RPC). Generic mechanism — no org concepts. Issued by `ce grant`.
(See `docs/roadmap.md` → "Scoped capability grants".)

### 10. Fleet — personal device organization
`machines.toml` registry of trusted devices (admins) with owner **tags**. Combined with
capability self-tags from the atlas via `ce fleet ls`. Pure organizational layer.

---

## The public surface (everyone gets this)

| Layer | Surface |
|---|---|
| HTTP API | `/status` `/health` `/bootstrap` `/atlas` `/transfer` `/jobs/bid` `/jobs` `/jobs/:id` `/jobs/:id/settle` `DELETE /jobs/:id` `/signals` `/signals/send` `/signals/stream` `/blocks/stream` `/transactions/stream` `/sync/*` `/exec` `/mesh-exec` `/mesh-sync/:id/*` (amounts are decimal **strings** of base units) |
| Tx types | `Transfer` `UptimeReward` `JobBid` `JobSettle` `JobExpire` `Heartbeat` `TrustGrant` |
| Mesh RPC | `Exec` `SyncFile` `SegmentFetch` (grant rides as opaque bytes) |
| Gossip topics | `ce-transactions` `ce-blocks` `ce-heights` `ce-syncreq` `ce-syncresp` `ce-protocol-1` `ce-segments` |
| CLI | `start status balance id devices fleet grant sync exec deploy ps kill fund run` |

Full reference: `docs/api.md`, `docs/protocol.md`.

---

## The boundary — what CE deliberately does NOT provide

These are **apps**, not primitives. CE gives the substrate; these emerge on top:

| Not in CE | Why it's an app |
|---|---|
| **Work scheduler / orchestrator** (fan out N tasks, track, retry, aggregate) | Coordination logic a client runs; the node need not enforce it. See `docs/apps/scheduler.md`. |
| **Reputation scoring / trust tiers** | Subjective and per-relationship; a global score would be a trust bottleneck. CE provides the *history*; apps derive *trust*. |
| **Result verification policy** | Per-job assurance is the client's choice (watch it / redundancy / stake). CE provides random placement + pay-as-you-go; the dial is the app's. |
| **Pricing, matching, insurance, markets** | Emergent from incentives. |
| **Workflow DAGs, task sync models** | The workload's concern (over CEP-1 messaging). |
| **"Workspace for my company", teams, billing UX** | Product/policy over the grant primitive. |
| **A live bidirectional global filesystem** | An app built on sync + messaging. |

If you're tempted to add one of these to `ce-node`, ask: *does the node have to enforce it,
and is it generic?* If not, it's an app.

---

## The trust gradient

CE is trustless, so a stranger's results can't be assumed correct. Apps resolve this with a
**trust gradient** — the kind of work scales with earned trust, and verification cost falls
to zero at the tiers where you operate:

| Tier | Work | How correctness is known | Trust needed |
|---|---|---|---|
| Stranger | interactive / **visualized** (games, render, sims) | the consumer sees it; garbage is obvious | none |
| Stranger | short, deterministic | redundancy + **random independent placement**, compare | none |
| Earned | opaque, long-running (DB, training) | track record + stake | built over time |
| Owned | anything | your key / a grant | identity |

**Honesty is the profitable strategy** (repeated game + permanent memory): a scam earns one
job and forfeits the entire future stream of high-value work. Trust is **reputation capital**
— non-transferable (selling it would be Sybil-gameable), earned only by behavior, and the
thing that lets a host escape commodity pricing. New identities start as strangers (Sybil-
proof in the direction that matters); the bootstraps *up* the gradient are **emission** (earn
while building), **stake** (risk credits for provisional access), and the large supply of
commodity/visualized work for newcomers.

CE's only jobs here: keep the honest history (the chain) and make random placement +
pay-as-you-go cheap. The gradient itself lives in apps.

---

## The line: CE provides primitives, apps provide policy

CE is a substrate, not an application. The **primitives** it owns:

- **Identity** — Ed25519 sign/verify.
- **Mesh transport** — directed request/response (`AppRequest`/`AppReply`), pubsub (gossipsub),
  raw bidirectional streams (`/ce/tunnel/1` via `libp2p-stream`), NAT traversal (relay/DCUtR).
- **Content-addressed data** — blobs + chunk fetch.
- **Economy** — the ledger: balances, transfer, emission (longer-term: generic conditional
  payment/escrow rather than per-app tx types).
- **Capability verification** — the `ce-cap` crate: verify a signed, attenuating chain authorizes
  an **opaque action string**, rooted at a key. No application vocabulary lives in CE.

Everything else is an **app** built on those primitives via the SDK (`ce-rs`):

> **New device-to-device features are apps over `AppRequest` + stream + the `ce-cap` verifier +
> payment — NOT new `RpcRequest` variants, HTTP endpoints, or consensus tx types.**

`exec`/`sync`/`tunnel`/`deploy` are apps (being extracted; see the `rdev` repo). The node exposes a
small set of privileged *local* services (run-workload, fs) that apps bridge to the mesh and gate
with capabilities. The chain stays generic — resist app-specific tx types (they are forever after
launch). Litmus test: product semantics (a job, a name, a tunnel) → app; a key/byte/coin mechanism
every app would otherwise reinvent → primitive.

## Design invariants

- Integers, never floats, for anything consensus touches.
- Mesh-first: device-to-device always over libp2p, never stored ip:port HTTP.
- The enforcer authorizes before doing work (via `ce-cap`); clients are never trusted by default.
- Amounts cross JSON as strings (exceed 2^53).
- `Mesh` is `!Sync`; mining is `spawn_blocking`; Docker is optional.
- Capability actions are opaque strings; the verifier knows no app vocabulary.
- **The capability verifier (`ce-cap`) never imports app-tier reputation/policy.** Authorization is
  the signed, attenuating capability chain *alone*. Share-ratio / reputation are app-tier signals
  that bias price and priority only — they must never become an input to the hard authz path. A
  CI boundary gate fails the build if `ce-cap` ever depends on `ce-ratio`.
- **Key material never crosses the API boundary.** There is no `/key/*` HTTP route and no
  credit-/credential-minting endpoint; credits are minted only by the consensus `UptimeReward` path.
  Identity-key backup/restore is a TTY-only CLI action (`ce key backup` / `ce key restore`). CI
  boundary gates (`.github/workflows/ci.yml` → the `boundary` job) enforce both rules on every push.
