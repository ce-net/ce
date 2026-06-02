# Scheduler — the first app on CE

**A distributed task orchestrator: fan work out across the mesh, track it, collect results,
retry, aggregate.** This is CE's "Ray" / "Kubernetes" — and it is an **app**, a client that
loops over CE primitives, not part of `ce-node`. (Why: the node need not enforce orchestration;
see `docs/primitives.md` → "The boundary".)

The goal it serves: *every computer on Earth sharing compute* — a supercomputer assembled from
strangers. The scheduler is the layer that makes 1,000 untrusted hosts usable.

---

## Architecture

```
                 ┌─────────────── Scheduler (app, a CE client) ───────────────┐
                 │  control loop:  discover → place → run → collect → retry    │
   your job ───► │  per-job assurance dial   ·   trust model over chain history │
                 │  coordinator state (optionally Raft-replicated for HA)       │
                 └──────┬───────────────┬───────────────┬──────────────────────┘
                        │ /atlas        │ /jobs/bid      │ result (exec/cell signal)
                        ▼               ▼                ▼
        ┌───────── CE substrate (ce-node on every machine) ──────────┐
        │ placement · escrowed jobs · sandboxed run · heartbeats ·    │
        │ CEP-1 messaging · immutable interaction history             │
        └─────────────────────────────────────────────────────────────┘
```

A **coordinator** (one process the job owner runs, or rents) holds the live view of all tasks.
**Workers** are ordinary CE cells on hosts discovered from the atlas. Nothing here is privileged
— the coordinator is just a well-organized client.

---

## The control loop

| Step | What it does | CE primitive used |
|---|---|---|
| **Discover** | find hosts that *can* run the task (tags: `gpu`, `highmem`, …), rank by trust | `GET /atlas` + chain history |
| **Place** | submit N bids to chosen hosts; credits escrow on bid | `POST /jobs/bid` (`JobBid`) |
| **Run** | host accepts, runs the cell sandboxed | `Exec` / cell lifecycle |
| **Collect** | gather stdout/exit, or stream output via cell signals | exec result / `/signals/stream` |
| **Bill** | pay-as-you-go for long tasks; stop on bad output | `Heartbeat` / signal-pay |
| **Verify** | apply the per-job assurance dial (below) | redundancy / client check |
| **Retry / reschedule** | re-place stragglers and failures on other hosts | repeat |
| **Aggregate** | reduce results (scatter/gather, or app-defined reduce) | app logic |

For embarrassingly-parallel work this is a scatter/gather; for DAGs the coordinator walks the
dependency graph, placing a stage as its inputs complete.

---

## Verification is a per-job dial, not a subsystem

The client chooses how much assurance to buy, matched to the work (see the trust gradient in
`docs/primitives.md`):

| Dial setting | For | Cost |
|---|---|---|
| **Watch it** | interactive / visualized output (games, render, sims) | free — the consumer is the oracle |
| **Redundancy R + random placement** | short deterministic tasks | R× compute (cheap; compute is the abundant resource) |
| **Spot-check** | longer deterministic tasks | re-run a random sample / verify checkpoints |
| **Trust + stake** | opaque, long-running (DB, training) | none cryptographic — gated on earned trust |

The one rule the scheduler must honor for the redundancy path: **pick the R hosts randomly and
independently** from the atlas, so a host can't know who else is checking the same task and
collusion can't be arranged (BFT-safe under <1/3 colluding). Redundancy catches *divergence*,
not *correlated lying* — random placement is what makes the divergence assumption hold.

**Recommended workloads give direct, visualized feedback.** Opaque long-running work is allowed
but is *gated* behind trust the host has earned with this client.

---

## Trust & the economy (app-side)

- **Trust is per-relationship, derived from chain history.** The scheduler reads each candidate
  host's record (settlements completed, heartbeats honored, expiries/cut-offs) and computes *its
  own* trust score. No global reputation oracle — that would recreate a trust bottleneck.
- **Tiered placement.** Strangers get only watchable/redundant work; hosts that have served this
  client well graduate to opaque/long contracts. A single scam → permanent demotion for this
  client (and the fact is on-chain for others to weigh).
- **Honesty is the profitable equilibrium.** Cheating earns one job and forfeits the premium
  future stream. Trust is reputation capital that lets a host escape commodity pricing.
- **Stake bootstrap.** A stranger may post a slashable/visible bond to buy provisional access to
  higher-tier work before earning trust — the bridge from fungible credits to non-transferable
  reputation. (Clean form: stake-as-commitment for *perceptible* work where the payer judges;
  blind auto-slash needs a fault oracle = the verification problem again.)
- **Pricing emerges:** strangers compete on price (commodity spot); trusted providers command
  premiums (differentiated). That gap is the incentive to behave.

Trust scoring, tiers, vouching graphs, insurance, and pricing all live in this app — not CE.

---

## Coordinator high availability (where Raft actually fits)

If losing the coordinator would lose an expensive in-flight run, replicate *its* state across a
few backup coordinators with **Raft (openraft)**. This is the *only* place Raft belongs: a small
app-internal cluster replicating one orchestrator's view. It is **never** the CE ledger and never
mesh-wide. For purely independent tasks you may not need it — the coordinator can re-derive state
by re-querying `/jobs`.

---

## Interdependent tasks

When tasks must talk (distributed training all-reduce, MPI-style), they communicate **cell-to-cell
over CEP-1 signals** — the sync pattern is the *workload's*, not the scheduler's and not CE's. The
scheduler places the cohort and gives them each other's addresses; they coordinate themselves.

---

## What the scheduler needs from CE (gaps → CE roadmap)

The substrate is mostly there; a few primitives would make this app cleaner. These belong in CE
*only* if generic and node-relevant:

- **Random/independent placement helper** — atlas exists; a client-side "pick R uncorrelated hosts"
  is app logic, but a verifiable randomness beacon (e.g. block hash) helps prove non-collusion.
- ~~**Reputation read over history**~~ ✅ Done — `GET /history/:node_id` returns per-node
  `NodeStats` (jobs hosted/paid, heartbeats, earned/spent, first/last height). swarm's `run`
  already trust-tiers placement by `delivered_work()`. Richer trust models layer on top.
- **Stake / bond tx** — a lockable, conditionally-releasable collateral. Candidate CE primitive
  (extends the escrow model), but auto-slash adjudication is hard in a trustless setting — start
  with stake-as-visible-commitment.
- ~~**Mesh-routed deploy**~~ ✅ Done — `POST /mesh-deploy` / `/mesh-kill` place and stop a cell on
  a specific host over `/ce/rpc/1`, `Deploy`/`Kill` grant-enforced, host tracks the job for
  heartbeat billing. This is the directed-placement primitive the control loop's "place" step uses.

---

## MVP (v0)

1. Coordinator binary: takes a task spec + N + a tag selector + an assurance dial.
2. Discover via `/atlas`, place via `/jobs/bid` on N random matching hosts.
3. Collect results; retry failures on fresh hosts; aggregate.
4. Assurance: support **watch** (stream output) and **redundancy R + compare** first.
5. Trust: rank hosts by a simple per-relationship score scanned from chain history; tier the work.
6. No coordinator HA, no stake, no DAG yet — single coordinator, independent tasks.

Everything else (Raft HA, stake, DAGs, vouching, insurance, pricing) layers on after v0 proves
the loop.
