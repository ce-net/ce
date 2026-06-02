# CE Frontier — committed pre-launch capability roadmap

Everything CE must grow, beyond the foundation already built, to deliver the vision:
*every computer on Earth sharing compute — the world's largest throughput machine.*

This is the **committed pre-launch scope**. It is large on purpose. Each item is tagged:

- **[CE]** a node-enforced/generic primitive (lives in the substrate) · **[app]** a client/policy layer on top
- Difficulty: **Eng** (known how) · **Hard** (significant, some unknowns) · **Research** (open problem; pick narrow wins)

Ordering is by dependency, not priority — later phases assume earlier ones. The **critical path**
to a believable planet-scale launch is called out at the end.

---

## Phase A — Scale foundations (mandatory; the vision can't physically run without these)

| Item | Why | Tag | Diff |
|---|---|---|---|
| **Payment channels / off-chain micropayments** | `Heartbeat` every ~30s × millions of cells floods any single chain. Open a channel on-chain, stream signed micropayments off-chain, settle the net. Caps the signal-pay economy without it. **DONE** (`docs/payment-channels.md`): chain layer (ChannelOpen/Close/Expire + receipts), API (`/channels/*`), `ce-rs`, and `ce channel` CLI. Refinement: dispute window for bidirectional channels; `swarm` billing over a channel. | [CE] | Hard |
| **Lightweight runtimes — WASM + browser worker** | "Every computer on Earth" = phones, browsers, Docker-less laptops. Docker-only excludes ~95% of devices; a WASM sandbox + browser tab turns every web visitor into a node. **Staged (see `docs/runtime.md`): Stages 1–3 DONE** — `ce-runtime` seam, `ce-container` DockerRuntime + `ce-node` `Vec<Arc<dyn Runtime>>` registry dispatch, and the `ce-wasm` wasmtime backend (fuel+memory bounded) with a content-addressed blob store (`/blobs`), `Workload` over the mesh Deploy wire (Docker *or* Wasm), the `wasm` self-tag on every node, and `ce-rs` put_blob/mesh_deploy_wasm. A Docker-less machine can host WASM work. Refinements: WASI/args, CLI wasm-deploy, local job-manager via the registry. **Browser node = separate repo, the big remaining piece.** | [CE] | Hard |
| **Relay scaling + relay incentives** | One relay ≠ a planet. Many relays, discovered dynamically, **earning credits** for relaying; DHT tuned for millions of peers. **Economic substrate done — `docs/relay-incentives.md`:** relays advertise the `relay` service (discovery) at `--relay-price-per-min`; clients pay over a payment channel via mesh-routed `RpcRequest::RelayReceipt` (no new chain type — reuses `ChunkReceipt`); `relay_authorize` (pure, tested) verifies sig + capacity + price×minutes, a per-channel `RelayMeter` accounts it; `POST /relay/pay` / `ce-rs` `pay_relay`. The incentive sidesteps proof-of-relay (the NAT'd beneficiary pays for its own reachability). **Honest boundary:** libp2p circuit-relay v2 has no payment hook, so dropping unpaid circuits at the transport layer is the integration follow-on (v0 enforcement is advisory). | [CE] | Eng→Hard |
| **Data layer** — content-addressed, chunked, paid P2P transfer | `sync` is one-file HTTP today. Datasets, weights, inputs, and results need BitTorrent/IPFS-shaped paid distribution. **Design + status: `docs/data-layer.md`.** Stages 1–4 ✅: chunked manifests over the `/blobs` store (`ce-rs` `put_object`/`get_object`); a `FetchChunk` mesh RPC + Kademlia provider records so a node pulls chunks it lacks; **paid serving** — `ChunkReceipt` over the payment-channel primitive, a `data_price_per_byte` knob, provider-side receipt enforcement, `POST /data/fetch`; and **job integration** — `Workload` gains content-addressed `inputs`, the host stages the Wasm module + inputs from the data layer before launch (so a workload runs on a host that lacked its bytes). Open refinements: in-cell input consumption (WASI/mounts) + output publishing by CID, mesh-advertised pricing + auto-selection, swarming. Durable-storage-with-proofs is the separate storage-market item on top. | [CE]+[app] | Hard |
| **App messaging** — app-to-app comms over the mesh ✅ | The keystone for building control systems: apps need to send commands + receive telemetry between nodes, not just CE-internal RPCs. **Design + status: `docs/app-messaging.md`.** Stages 1–3 ✅: **directed messages** (`AppMessage`→`AppAck`, `/mesh/send`, `/mesh/messages[/stream]`), **pub/sub** (signed `AppPubSubMsg` on `ce-app/<topic>`, `/mesh/subscribe`+`/mesh/publish`), and **sync request/response** (`AppRequest`/`AppReply` reusing the inbound RPC correlation, `/mesh/request`+`/mesh/reply`). All sender-authenticated (CE), app-authorized. `ce-rs` covers all three. | [CE] | Eng |
| **Naming + discovery** ✅ | Address nodes by name, not 64-hex; find peers by role, not pre-shared id. **Design: `docs/naming-discovery.md`.** Naming: `TxKind::NameClaim` (consensus-enforced uniqueness, first-claim-wins, `is_valid_name`), `resolve_name`, `POST /names/claim` + `GET /names/:name`, `ce name` CLI. Discovery: a DHT service registry generalising the data-layer provider records (`service_key`, `advertise_service`/`find_service`, `node_id_from_peer_id` so finds return NodeIds), `POST /discovery/advertise` + `GET /discovery/find/:service`, `ce discover` CLI. `ce-rs` covers both. v0 refinements: name transfer/expiry/anti-squat fee; periodic ad refresh + service metadata. | [CE] | Eng |
| ~~Mesh-routed deploy (`Deploy`/`Kill` over `/ce/rpc/1`)~~ ✅ Done | Directed placement on a specific host: `RpcRequest::Deploy`/`Kill`, host tracks the job (heartbeat-billed, killable), `Deploy`/`Kill` grant-enforced, `POST /mesh-deploy`/`/mesh-kill`, `ce deploy --on <device>` / `ce kill --on <device>`. | [CE] | Eng |
| ~~Reputation read index (`history(node_id)`)~~ ✅ Done | Incremental per-node `NodeStats` cache (jobs hosted/paid, heartbeats, earned/spent, first/last height); `GET /history/:node_id`; `ce-rs` exposes `history()` and `swarm` trust-tiers placement by it. (Pruned light nodes hold only post-checkpoint history; archive nodes are complete.) | [CE] | Eng |
| Stake / bond tx | Bootstrap trust with risked credits; extends the escrow model. Start as visible commitment (auto-slash needs a fault oracle). | [CE] | Hard |
| ~~Verifiable randomness beacon (block-hash based)~~ ✅ Done | `GET /beacon` returns the PoW tip `{height, hash}` — unpredictable, globally agreed, for reproducible/auditable host selection. `ce-rs` exposes `beacon()`. (Beacon-seeded selection is verifiable-but-predictable; swarm's redundancy uses trust-ranked selection today — unpredictable-at-dispatch selection for anti-collusion is the refinement.) | [CE] | Eng |

## Phase B — Capability (what makes "supercomputer" real)

| Item | Why | Tag | Diff |
|---|---|---|---|
| **First-class GPU / accelerator support** | GPU passthrough into cells, CUDA, multi-GPU. Central to the AI/HPC use case. | [CE] | Hard |
| Verifiable capability / benchmarking | Nodes will lie about hardware ("I'm an H100"). Attested benchmarks (FLOPS, bandwidth, GPU model) feed placement. | [CE] | Hard |
| **Durable trustless storage market** | Stateful work (DBs, checkpoints) needs replicated durable storage + proof-of-storage + redundancy. Filecoin-shaped subsystem; pairs with the trust gradient. | [CE]+[app] | Research |
| Checkpoint / migrate / preempt | Long jobs on volunteer machines lose hosts; checkpoint-and-restart-elsewhere makes a flaky mesh usable for >minutes work. | [CE]+[app] | Hard |

## Phase C — Trust & verification frontier (highest leverage, hardest)

| Item | Why | Tag | Diff |
|---|---|---|---|
| **TEE / confidential-compute attestation** (SGX/SEV, GPU CC) | The biggest lever on verification: hardware proof that "this exact code ran unmodified" lets you trust opaque work *without* a track record — can collapse the earned-trust tier. | [CE] | Research |
| Verifiable computation (ZK / fraud proofs / optimistic+challenge) | General "prove the work was correct." Unsolved at general scale; target narrow, asymmetric (easy-to-verify) workloads first. | [CE]+[app] | Research |
| Reputation system + scheduler | The first apps (`docs/apps/scheduler.md`), reading the history index, computing per-relationship trust, tiering work. | [app] | Eng |

## Phase D — Safety & security (launch-blocking in their own right)

| Item | Why | Tag | Diff |
|---|---|---|---|
| Sandbox-escape hardening + **network egress control** | A cell must not DDoS, reach the host's LAN, or escape gVisor. Running strangers' code on volunteers' machines is the core attack surface. | [CE] | Hard |
| Resource-abuse limits | Prevent crypto-mining / runaway use inside cells beyond what was paid for. | [CE] | Eng |
| **Transport encryption** (TLS from identity key) | ✅ `ce-tls` crate (cert keyed by the node's Ed25519 identity + NodeId-pinned verifier) **and** the node serves the API over TLS with `ce start --tls` (opt-in). End-to-end tested: a client pinned to the node's NodeId completes the handshake; a wrong pin is rejected (MITM defense, no CA, no TOFU). The mesh (`/ce/rpc/1`) is already Noise-encrypted. **Remaining:** auto-pin the bundled CLI/`ce-rs` clients when a node runs `--tls` (today they speak plain HTTP), so `--tls` is opt-in until that lands. | [CE] | Eng |
| Mesh/API rate-limiting + DoS resistance | `MAX_TXS_PER_BLOCK` exists; the mesh and API need their own. | [CE] | Eng |
| **Abuse / illegal-use policy** | Permissionless compute attracts botnets, illegal content, "attack X for me." In real tension with trustlessness; host-side acceptance rules + egress policy + opt-outs. The thing that gets a network shut down if ignored. | [CE]+[app] | Hard |

## Phase E — Chain maturity

| Item | Why | Tag | Diff |
|---|---|---|---|
| Longest-chain reorg / fork choice | Currently first-wins; needs a real reorg in the mesh loop. | [CE] | Eng |
| Chain checkpoints | Collectively-signed tip every N blocks; freeze the prefix (Phase 1d). | [CE] | Eng |
| Throughput | Largely solved by payment channels (Phase A) moving micropayments off-chain. | [CE] | Hard |
| **PoW security revisit** | Emission is kept, but PoW still hands *ledger* control to whoever hashes most — the concern you raised. The chain-secures-money / signal-pay-secures-work split is right; the chain's own 51% resistance at scale must be confronted deliberately. | [CE] | Research |

## Phase F — Identity, recovery, UX, governance

| Item | Why | Tag | Diff |
|---|---|---|---|
| **Key recovery** (social / hardware-key) | Lose your node key → lose all credits. Essential before real value rides on it. | [CE]+[app] | Hard |
| Wallets + mobile/web clients | Onboarding for non-CLI users. | [app] | Eng |
| Human-readable node names | On-chain NameClaim (Phase 5e). | [CE] | Eng |
| **Protocol governance** | How does a *trustless* network upgrade its own rules without a central authority? Versioning + fork coordination. | [CE]+[app] | Research |

## Cross-cutting — the physics caveat

CE will be staggering at **throughput** (embarrassingly-parallel / loosely-coupled: rendering,
batch inference, parameter sweeps, Monte Carlo, search) — plausibly dwarfing any supercomputer.
It will **not** beat InfiniBand at latency-bound tightly-coupled HPC unless the scheduler does
**topology-aware co-location** (place a tightly-coupled cohort in one region/datacenter). Position
honestly: *the world's largest throughput machine*, not its fastest tightly-coupled one. Topology-
aware placement [app, using atlas locality hints — [CE]] is the bridge for the HPC cases.

---

## Critical path to a planet-scale launch

If the rest is the destination, this is the spine:

1. **Payment channels** — unlocks the micropayment economy past a few thousand cells. [CE, Hard]
2. **WASM / browser runtime** — turns billions of devices into nodes. [CE, Hard]
3. **Relay incentives + scaling** — reach beyond one box. [CE, Eng]
4. **Data layer** — get inputs/outputs/datasets to and from cells at scale. [CE, Hard]
5. **TEE attestation** — the highest-leverage bet: makes the trust gradient mostly evaporate. [CE, Research]

Plus the Phase D safety set, which is launch-blocking regardless of how far the capability work gets.

> This is the long game. Build it primitive by primitive, each one generic and node-enforced where
> it belongs and an app where it doesn't (`docs/primitives.md`), each shipped behind tests and docs.
