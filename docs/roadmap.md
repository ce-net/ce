# CE Roadmap

Current state and what needs to be built to achieve the full vision.

---

## Vision

CE is two things simultaneously:

1. **Open compute economy** — a mesh where any node can offer or consume compute, with credits as the only resource allocation mechanism. Cells (containers that implement CEP-1) earn and spend credits to stay alive on the network. A cell that nobody uses drains its wallet and dies. A cell that everyone uses accumulates credits, replicates, and thrives.

2. **Node-to-node services** — CE nodes can sync files and run commands on each other. Any node can trust any other via `machines.toml`. `ce sync` pushes files. `ce exec` runs commands inside a sandboxed container on the remote node — same gVisor/no-network isolation as compute jobs. There is no special "personal OS" mode; it is the same trust model applied to your own machines. Register the peers you own in `machines.toml` so `ce deploy` prefers them over stranger nodes when building or hosting cells.

These are the same system from two angles. The identity primitive that lets untrusted strangers transact safely is also what lets your machines authenticate each other without passwords.

---

## Current State (as of 2026-05-25)

### What's working

| Component | Status | Notes |
|---|---|---|
| `ce-identity` | ✅ Complete | Ed25519 keypair, node ID, sign/verify, benchmarks |
| `ce-chain` | ✅ Complete | Uptime emission, Transfer/UptimeReward/JobBid/JobSettle/JobExpire/TrustGrant/Heartbeat, supply cap (21B), halving schedule, credit escrow (locked_balance), tx_by_id, last_heartbeat_epoch, full validation, persistence, tests |
| `ce-mesh` | ✅ Complete | 7 gossip topics (ce-transactions/blocks/heights/syncreq/syncresp/protocol-1/segments), Kademlia DHT, chain sync, CEP-1 signal routing, relay mining |
| `ce-protocol` | ✅ Complete | CEP-1 wire format, BurnProof, CellSignal build/verify/encode/decode |
| `ce-container` | ✅ Complete | gVisor detection, CPU/memory/network limits, image pull, wait-for-exit, stop_job |
| `ce-node` | ✅ Complete | Mining loop, mesh event loop, job manager, heartbeat loop (30s), capacity broadcast (60s), atlas, signal ring buffer, tx pool, nonce replay prevention |
| HTTP API | ✅ Complete | /jobs/bid, /jobs (list), /jobs/:id, /jobs/:id/settle, /jobs/:id DELETE, /transfer, /status, /signals, /signals/send, /health, /atlas, /sync/*, /exec, /bootstrap, /mesh-exec, /mesh-sync |
| CLI | ✅ Complete | start (auto-bootstrap from ce-net.com), balance, status, id, grant, revoke, wallet (add/ls/rm), sync, exec, deploy, ps, kill, fund, run |
| Capability authorization | ✅ Complete | **The single trust primitive — `machines.toml`/`ce devices`/the v1 grant are removed.** A node honors a signed, attenuating capability chain rooted at its own key or a configured root (`<data_dir>/roots`); multi-level delegation, expiry, and on-chain `RevokeCapability` revocation. Enforced on mesh RPC and HTTP (`X-CE-Caps`). `ce grant`/`ce revoke` + a client wallet. **Spec: `docs/capabilities.md`; core: `crates/ce-node/src/capability.rs`.** (Sections below describing the old device-registry/grant-v1 model are superseded.) |
| `ce-deploy` | ✅ Complete | Hetzner provisioning, SSH deploy, E2E tests |
| Integration tests | ✅ Complete | single node mines, two nodes sync, tx pool propagates, API health/status, signal propagation, job lifecycle (requires Docker, skipped by default) |
| Chain persistence | ✅ Complete | bincode+zstd (level 3) storage (~8x smaller than JSON), O(1) tip validation, checkpoint pruning, JSON migration on first load |
| Distributed chain archive | ✅ Complete | Light node mode (`--light`, auto-prune to last 2880 blocks), archive segment distribution via `ce-segments` gossip topic, rendezvous-hash assignment of segments across peers, `SegmentFetch` RPC to retrieve historical blocks from archive nodes, oldest_block routing |
| Height re-announce on connect | ✅ Complete | On peer connect the node immediately announces its chain height so new peers trigger sync without waiting for the next ticker |

The foundation — identity, chain, mesh, protocol, containers, job economy, distributed archive — is fully implemented and tested.

### Known gaps and correctness issues

**Fork selection** — `Chain::append` uses first-wins. If two nodes mine simultaneously and then each receives the other's block, whichever arrived first stays. No longest-chain rule. Fix: in `mesh_event_loop`, on `NewBlock`, compare against current tip and replace if the incoming chain would be longer (needs a reorg function).

**`difficulty` field is vestigial** — Always 0. Kept for forward compatibility. Fine for now.

**`ce sync --watch` not yet implemented** — Directory watching (inotify/fsevents via the `notify` crate) is planned but not yet built. Use periodic `ce sync` for now.

**`.ceignore` format not yet implemented** — Sync skips a hardcoded set of default patterns (`target/`, `node_modules/`, `.git/objects/`, `*.pyc`, `__pycache__/`, `.DS_Store`). Full `.ceignore` file support (using the `ignore` crate) is planned.

**TrustGrant not broadcast on mesh** — `ce devices add` stores the admin trust relationship locally in `machines.toml`. Broadcasting a `TrustGrant` tx to the mesh (so other nodes can discover trust) is planned but not yet wired to the CLI. Note: scoped delegation between principals is already handled by capability grants (see the security model section) — they are signed and bearer-presented, needing no broadcast; only the global *revocation anchor* still wants an on-chain home.

**Transport encryption (TLS) not yet implemented** — CE auth provides authenticity and body integrity but NOT confidentiality. Plain HTTP means file contents are visible on the wire. TLS is required for production use; see security model below.

---

## Security model — sync/exec

### What the current auth scheme provides

Every sync/exec request is authenticated with the sender's Ed25519 identity key. The signature covers:

```
b"ce-auth-v1 " || METHOD || " " || PATH || " " || timestamp_le_u64 || " " || SHA256(body)
```

| Property | Mechanism |
|---|---|
| **Authenticity** | Only the holder of the private key can produce a valid signature |
| **Body integrity** | Signature commits to SHA256(body); swapping file contents invalidates it |
| **Freshness** | Timestamp must be within ±5 minutes of server time |
| **Replay prevention** | Server tracks last-accepted timestamp per sender; strictly increasing requirement |
| **Scoped authorization** | Sender is either a full-scope admin in `machines.toml`, or presents a scoped capability grant (see below). Per-action: `/sync` requires `Sync`, `/exec` requires `Exec` |

### Scoped capability grants

CE's generic delegation primitive — mechanism, not policy. A **grant** is a signed statement by
which a trusted admin (any node in the enforcing device's `machines.toml`) delegates a *subset* of
its authority to another principal:

> "I, issuer `O`, authorize subject `P` to perform `{permissions}` on any workspace whose
> capability self-tags satisfy `selector`, subject to `constraints` (expiry, resource ceilings)."

This is what replaced all-or-nothing trust. The node is the enforcement point — it must decide
whether to run an incoming exec/sync *before* acting — so verification lives in CE (`ce-node/src/grants.rs`,
enforced in both `api.rs` for HTTP and `lib.rs::handle_incoming_rpc` for mesh RPC). Products that
model organizations ("a company workspace": teams, people, sponsored billing UX) are built *on top*
by minting grants; they do not live in `ce-node`. The analogy is Bitcoin Script (protocol verifies
the spend condition) vs. wallets/exchanges (apps build the org UX), or OAuth's resource server
(infrastructure) vs. authorization server (product).

- **Permissions** (generic): `exec`, `sync` (enforced today); `deploy`, `kill`, `status` (reserved for the mesh-routed job path).
- **Selector**: matched against a device's capability self-tags — `*` / `tag=gpu` / `tag=gpu,linux`. Targeting by tag (not node id) means a grant automatically covers workspaces that later advertise the tag.
- **Constraints**: `not_after` expiry (enforced); `max_cpu` / `max_mem_mb` / `max_credits` (carried by the mechanism, enforced by the deploy path once it is mesh-routed).
- **Trust root**: a grant is accepted only if its `issuer` is already a trusted admin on the enforcing device. Your own devices are mutual full-scope admins (no grant needed) and can delegate scoped grants to others.
- **Transport**: HTTP via the `X-CE-Grant` header; mesh RPC carries it as opaque bincode bytes (keeping `ce-mesh` a pure transport).
- **CLI**: `ce grant <subject> --perm exec --select tag=gpu --expires 7d` issues a token; the subject uses it with `ce exec --grant <token>` / `ce sync --grant <token>`.
- **Revocation** (current): short `not_after` expiries, or un-trusting the issuer (invalidates every grant it signed). An on-chain `RevokeGrant` anchor keyed by `(issuer, nonce)` is the planned global mechanism.

### What SSH provides that CE currently lacks

| Property | SSH | CE current | CE target |
|---|---|---|---|
| Transport encryption | ✅ AES/ChaCha20 | ❌ plain HTTP | ✅ TLS from CE identity key |
| Server authentication | ⚠️ TOFU on first connect | n/a | ✅ cert pinned against registered NodeId |
| Client authentication | ✅ public key | ✅ Ed25519 signature | ✅ same |
| Session integrity (MITM) | ✅ MAC on all data | ✅ body-hash signature | ✅ TLS adds MAC on transport |
| Key management | Separate SSH keys | Same CE identity key | Same CE identity key |
| Trust model | TOFU (first-connect) | Explicit registry | Explicit registry |

### Path to full encryption

**Interim**: Put the API behind a TLS-terminating reverse proxy (nginx/caddy). Standard practice; zero code changes required.

**CE-native (planned)**: Derive a self-signed TLS certificate from the CE Ed25519 identity key using `rcgen`. Clients pin the certificate against the registered NodeId (the cert's embedded public key equals the node's identity). This eliminates TOFU entirely: you register the NodeId before connecting, and TLS verifies the server is who you think it is.

**Ideal**: Route sync/exec through the existing libp2p mesh connection, which uses the Noise protocol for encrypted + mutually authenticated transport. No separate TLS layer needed; encryption is free from the mesh infrastructure already in place.

---

## Phase 1 — Chain hardening

### 1a. Nonce replay prevention ✅ Done

`HashMap<NodeId, u64>` in `mesh_event_loop`; signals with `nonce <= last_seen` are dropped with a warning.

### 1b. Credit escrow for JobBid ✅ Done

`Chain::locked_balance(node)` computes credits locked in open bids (no matching `JobSettle` or `JobExpire`). `Chain::append` validates that the payer's free balance (`balance - locked_balance`) covers each new bid; settle cost must not exceed the original bid. `JobExpire { job_id, payer }` releases locked credits once `EXPIRY_BLOCKS = 1440` have elapsed with no settlement.

### 1c-ext. Chain adversarial hardening (round 2) ✅ Done

Six additional attack vectors found and addressed:

| Attack | Fix |
|---|---|
| **Cross-type double-spend (Transfer + JobBid in same block)** | `in_block_transfer` lifted out of inner scope; JobBid free-balance check now subtracts in-block transfers from the same payer |
| **Cross-type double-spend (Transfer + Heartbeat in same block)** | Heartbeat debit check now subtracts in-block transfers from the same cell |
| **Block-size bomb** | `MAX_TXS_PER_BLOCK = 1024` added; blocks exceeding this are rejected before signature verification |
| **Zero-amount transfer chain bloat** | `Transfer { amount: 0 }` now explicitly rejected |
| **UptimeReward misdirection** | Documented as intentional design (miner chooses recipient, like Bitcoin coinbase); test added |
| **Rogue host heartbeat drain** | Documented as known limitation (heartbeats not yet bid-gated); tracked for Phase 4 fix requiring bid-acceptance tx |

61 chain unit tests including 14 named adversarial scenarios.

### 1d. Chain checkpoints

Add `Checkpoint` as a block type. Every 1000 blocks, nodes collectively sign the tip hash. Once a checkpoint accumulates signatures from > 50% of known peers, it is broadcast and every node freezes that prefix as immutable.

This gives Bitcoin-level finality without PoW, scaled to mesh size.

```rust
pub struct Checkpoint {
    pub block_index: u64,
    pub block_hash: [u8; 32],
    pub signatures: Vec<(NodeId, [u8; 64])>,
}
```

---

## Phase 2 — Node-to-node services

### 2a. Machine registry ✅ Done

`~/.local/share/ce/machines.toml` (or `--data-dir` override):
```toml
[devices.desktop]
node_id = "8f3a9b..."
addr    = "192.168.1.10:8844"
```

CLI commands implemented:
```
ce grant <node-id> --can exec,sync,tunnel --expires 90d   # issue a capability token
ce revoke <nonce>                       # revoke a capability you issued (on-chain)
ce wallet add <alias> <node-id> --cap <token>   # hold a capability you were issued
ce wallet ls                            # list held capabilities
```

The chain supports `TrustGrant { grantor, grantee, label }` tx type (validated and signed by grantor). Broadcasting `TrustGrant` from the CLI is planned — currently devices are stored locally only.

### 2b. Authenticated file transfer endpoint ✅ Done

```
PUT  /sync/*path   — receive file, verify sender is in trusted devices
GET  /sync/*path   — serve file, verify requester is in trusted devices
```

Auth: requests are signed with the sender's CE identity key using `X-CE-From`, `X-CE-Timestamp`, `X-CE-Sig` headers. Receiver validates signature and checks sender against `machines.toml`.

### 2c. `.ceignore` format

Hardcoded default ignores are applied during `ce sync` (`target/`, `node_modules/`, `.git/objects/`, `*.pyc`, `__pycache__/`, `.DS_Store`). Full `.ceignore` file support via the `ignore` crate is planned.

### 2d. CLI commands ✅ Done (sync push + exec; --watch planned)

```
ce sync <src> <dst>                         # e.g. ce sync . desktop:~/code/ce  (push)
ce sync --watch <src> <dst>                 # planned: inotify/fsevents, sync on save
ce exec <machine> --image <img> <command>   # run in sandboxed container, print stdout/stderr
```

`ce exec` calls `POST /exec` with the image, command, and working directory. The remote node runs the command inside a Docker container (gVisor, no network, 1 CPU / 512 MB, home dir bind-mounted at `/workspace`). The JSON response with `stdout`, `stderr`, and `exit_code` is printed; the exit code is propagated to the shell.

### Workflow example

```bash
# Sync source to a peer you own
ce sync . desktop:~/code/ce

# Compile on that peer inside a Rust container
ce exec desktop --image rust:latest --cwd ~/code/ce cargo build --release

# Output prints to your terminal; exit code propagated
```

---

## Phase 3 — Cell economy CLI ✅ Done

### 3a. Heartbeat economy ✅ Done

`Heartbeat { cell: NodeId, host: NodeId, amount: u64, epoch: u64 }` added to `TxKind`.

The host submits a Heartbeat tx every 30 seconds for each running cell. `amount` is the bid spread evenly over 30-second intervals (`bid / (duration_secs / 30).max(1)`). If the cell's balance cannot cover the next heartbeat, the host terminates the container.

Chain validation: signed by host, cell != host, epoch strictly increasing per (cell, host) pair, cell balance sufficient. Balance effect: debit cell, credit host.

Short batch jobs still use JobBid/JobSettle; heartbeats are for long-running cells.

### 3b. `ce deploy` for cells ✅ Done

```bash
ce deploy <image> [--fund N] [--cpu N] [--mem N] [--duration N] [--cmd CMD...]
```

Submits a `JobBid` on the local node's API (default port 8844). Use `--api-port` to override.

### 3c. Cell management CLI ✅ Done

```bash
ce ps [--api-port N]                     # list all jobs on the local node
ce fund <node-id> <credits> [--api-port N]   # transfer credits to a node via POST /transfer
ce kill <job-id> [--api-port N]          # force-stop a job via DELETE /jobs/:id
ce run <cell-id> <payload-hex> [--burn-tx <tx-id>] [--api-port N]   # send a CEP-1 signal
```

### 3d. Capacity advertisement ✅ Done

Nodes broadcast available capacity as a capability-only CEP-1 signal every 60 seconds:
```
Capability { name: "cpu",    version: <cpu_cores> }
Capability { name: "mem_mb", version: <total_mem_mb> }
Capability { name: "jobs",   version: <running_job_count> }
```

Peers cache these in an in-memory atlas (updated by `mesh_event_loop`). The atlas is
exposed at `GET /atlas`. Use this to find nodes with spare capacity before calling
`ce deploy`.

**Not yet implemented**: atlas-guided host selection in `ce deploy` (currently deploys
to the local node only). The `GET /atlas` endpoint exposes the data; host selection is a
future enhancement.

---

## Phase 4 — Bootstrap and network launch (planned)

### 4a. Closed beta mode

Add `--closed-beta` flag to `ce start`. In closed-beta mode:
- Credits are non-transferable (Transfer tx type is disabled)
- New nodes must present a vouching signature from an existing node to participate

Remove closed-beta mode when the network has enough nodes that no single actor controls > 30%.

### 4b. Multi-provider deploy

Extend `ce-deploy` beyond Hetzner to support:
- Vultr
- DigitalOcean
- OVH
- Generic SSH (already partially exists)

Target: 1000 genesis nodes across 5+ providers before public launch.

### 4c. CE cell registry

The mesh is the registry. Cells that have been running for > N blocks with consistent uptime and positive balance are indexed in the atlas with their capabilities. Discovery is just a filtered atlas query.

No central registry server. No DNS. Pure mesh.

---

## Phase 5 — Zero-Config Mesh Onboarding (in progress)

The goal: `ce start` just works. No peer IDs, no multiaddrs, no config files.

Domain: **ce-net.com** (registered 2026-05-25). Relay: `178.105.145.170` (Hetzner CX23).

### 5a. Auto-bootstrap from ce-net.com ✅ Done

`ce start` with no `--bootstrap` flags automatically fetches the relay list from `https://ce-net.com/bootstrap` before starting. Falls back gracefully (mDNS still handles LAN). Override with `CE_BOOTSTRAP_URL` env var or disable with `CE_NO_AUTOBOOTSTRAP=1`.

```bash
ce start   # connects to ce-net.com automatically
```

### 5b. Bootstrap HTTP endpoint ✅ Done

`GET /bootstrap` on any node returns the multiaddrs callers can use to connect. The relay sets `CE_EXTERNAL_IP=178.105.145.170` and `CE_EXTERNAL_HOST=relay.ce-net.com`; the endpoint returns the correct public multiaddrs.

```bash
curl https://ce-net.com/bootstrap
# {"peers":["/dns4/relay.ce-net.com/tcp/4001/p2p/12D3KooW..."]}
```

### 5c. Inline device registration ✅ Done

`ce devices add <name> <node-id> --addr host:port` — no interactive prompts. Get your ID with `ce id`.

**Before:**
```
ce devices add desktop
> Node ID (64 hex chars): <manual paste>
> API address (host:port): <manual paste>
```

**After:**
```bash
# On the machine you want to add:
ce id                         # copy the "ce node id" line

# On your local machine:
ce devices add desktop <node-id> --addr 192.168.1.10:8844
```

### 5d. Relay as ce-net.com gateway (pending — needs DNS + nginx)

Set up DNS and nginx on the relay to proxy:
- `ce-net.com/bootstrap` → `localhost:8844/bootstrap`
- `ce-net.com/install` → install script

```
relay.ce-net.com.  A  178.105.145.170
```

Start relay with:
```bash
CE_EXTERNAL_IP=178.105.145.170 CE_EXTERNAL_HOST=relay.ce-net.com ce start
```

### 5e. Human-readable node names (done — see `docs/naming-discovery.md`)

On-chain `TxKind::NameClaim { name, node }`: consensus-enforced uniqueness (first claim wins),
`is_valid_name` charset, `resolve_name`, `POST /names/claim` + `GET /names/:name`, `ce name` CLI,
`ce-rs` `claim_name`/`resolve_name`. Paired with a DHT service registry (`ce discover`). v0 names
are permanent; transfer/expiry/anti-squat fee are refinements.

```bash
ce name claim mylaptop      # burns 1000 credits, name yours for 1 year
ce exec mylaptop --image rust:latest cargo build
```

Names are self-sovereign (no central authority) — stored in the chain, resolved by any node.

### 5f. Opportunity gaps (roadmap items from stakeholder review)

| Gap | Plan | Priority |
|-----|------|----------|
| No persistent storage primitive | Distributed KV or IPFS bridge as a CE job type | Medium |
| No HTTP ingress | Reverse-proxy cell routing web traffic to job containers | Medium |
| No secrets management | HashiCorp Vault integration or custom encrypted secrets job type | Low |
| CLI-only UI | Tauri dashboard: node status, job queue, atlas, credit balance | Medium |
| No FaaS ergonomics | `ce deploy --serverless` wrapper that auto-packages handlers | Low |
| TypeScript SDK is manual | Generate OpenAPI client from axum routes | Low |

---

## Phase 6 — Real-Time Push (subscription system)

The goal: no polling. Every subscriber gets pushed signals, blocks, and transactions the instant the mesh delivers them.

Currently `GET /signals` is a poll endpoint returning a static ring buffer snapshot. Internally a `tokio::sync::broadcast::Sender<CellSignal>` already fires on every validated signal — it just isn't exposed over HTTP.

### 6a. SSE streams ✅ Done

Three Server-Sent Events endpoints. Each streams newline-delimited JSON events as they arrive. Clients connect once and stay connected; the server pushes immediately.

```
GET /signals/stream        — SSE: one JSON CellSignal per event
GET /blocks/stream         — SSE: one JSON Block per event
GET /transactions/stream   — SSE: one JSON Tx per event
```

Implementation sketch (`ce-node/src/api.rs`):

```rust
// GET /signals/stream — SSE push, no polling required
async fn stream_signals(
    State(state): State<ApiState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mut rx = state.signal_tx.subscribe();   // broadcast channel already exists
    let stream = async_stream::stream! {
        loop {
            match rx.recv().await {
                Ok(sig) => {
                    let json = serde_json::to_string(&signal_view(&sig)).unwrap_or_default();
                    yield Ok(Event::default().data(json));
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    // Slow consumer — log and continue
                    warn!("SSE client lagged {n} signals");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };
    Sse::new(stream).keep_alive(KeepAlive::default())
}
```

`ApiState` must expose `signal_tx: broadcast::Sender<CellSignal>` (it is already created in `Node::start` but currently the receiver is immediately dropped and it is not threaded into `ApiState`). Wire it in.

The same pattern applies to blocks and transactions — add `block_tx` and `tx_tx` broadcast senders to `MeshEvent` processing and expose them on `ApiState`.

### 6b. WebSocket upgrade (future)

SSE is one-directional (server→client). A WebSocket variant allows bidirectional signalling: clients can also *send* from the stream. Low priority until there is a concrete use case. SSE covers 95% of cases with far less complexity.

### 6c. Filter parameters (future)

```
GET /signals/stream?from=<node-id>   — only signals from this sender
GET /signals/stream?to=<node-id>     — only signals addressed to this node
GET /blocks/stream?min_height=N      — replay from height N then stream live
```

---

## Phase 7 — Live Mesh Benchmark Suite

The goal: measure actual propagation latency, gossip fanout time, and RPC round-trip on the real ce-net network. Not synthetic — real packets, real NAT, real relay routing.

### 7a. `ce-bench` crate (planned)

New crate `crates/ce-bench`. Built as a binary (`cargo build -p ce-bench --release`) that connects to the live mesh and runs a suite of latency and throughput probes.

```
cargo run -p ce-bench -- --bootstrap /dns4/relay.ce-net.com/tcp/4001/p2p/<id> --suite all
```

**Benchmark suite:**

| Benchmark | Measures | Method |
|---|---|---|
| `gossip-signal-rtt` | Time from `POST /signals/send` until the SSE stream on a second node fires | Two nodes, one sends, other listens on SSE stream; record wall-clock delta |
| `gossip-block-rtt` | Time from mining a block until a peer reports it in `GET /status` | Node A mines, Node B polls `/status` until height bumps; record delta |
| `rpc-exec-rtt` | `/ce/rpc/1` round-trip for a trivial exec (e.g. `echo`) | `send_rpc(Exec { cmd: ["echo", "bench"] })`, record from send to recv |
| `chain-sync-speed` | Blocks/second during initial sync from 0 | Fresh node connects, time until heights match |
| `gossip-fanout` | How many hops a signal takes to saturate a 5-node mesh | Instrument signals with hop-count capability; measure saturation time |
| `tx-pool-propagation` | Time for a `Transfer` tx to appear on all peers | Broadcast tx on Node A, poll tx pool on Node B/C; record delta |

Results printed as a markdown table and optionally as JSON for CI ingestion.

### 7b. Live ce-net test harness (planned)

A separate test target that spins up two temporary nodes connected to the real ce-net bootstrap, runs the full job lifecycle, and asserts latencies are within bounds. Runs manually or from CI with `CE_LIVE_BENCH=1 cargo test -p ce-bench -- --ignored`.

```bash
# Run against the live mesh — requires network access and a funded node
CE_LIVE_BENCH=1 cargo test -p ce-bench -- --ignored --nocapture
```

This is different from the Hetzner E2E tests (which provision fresh VMs) — the live bench tests join the *existing* production mesh and measures real-world performance.

### 7c. Continuous latency tracking (future)

The relay node runs `ce-bench --daemon` which emits metrics every 5 minutes. A Prometheus scrape endpoint at `/metrics` on the relay exposes:

```
ce_gossip_signal_p50_ms
ce_gossip_signal_p99_ms
ce_rpc_exec_p50_ms
ce_rpc_exec_p99_ms
ce_connected_peers
ce_chain_height
```

Grafana dashboard at grafana.ce-net.com.

---

## Phase 8 — Multi-Bootstrap Resilience

The goal: the network boots even if the primary relay is down. A hundred bootstrap nodes should be able to go offline and the network should still be joinable.

### 8a. Multiple bootstrap domains (planned)

Maintain a fleet of bootstrap nodes across multiple domains and providers so no single point can kill discovery:

```
relay.ce-net.com       — primary (Hetzner Falkenstein)
relay-2.ce-net.com     — secondary (DigitalOcean or Vultr)
bootstrap.ce-net.io    — fallback domain (different TLD)
bootstrap.ce-network.com — fallback domain
```

The `ce start` auto-bootstrap logic already tries `CE_BOOTSTRAP_URL` then falls back to mDNS. Extend it to try a prioritised list:

```rust
const BOOTSTRAP_URLS: &[&str] = &[
    "https://relay.ce-net.com/bootstrap",
    "https://relay-2.ce-net.com/bootstrap",
    "https://bootstrap.ce-net.io/bootstrap",
];
```

The `fetch_bootstrap_peers` function in `src/main.rs` already supports a single URL override; extend to try the list in order and merge results.

### 8b. Immutable history guarantee (planned)

The distributed segment archive (done in Phase 6 of chain work) stores history across nodes. For tamper-evidence:

- Every segment is content-addressed by Sha256 of its bincode-encoded blocks.
- Segment manifests (node → held segments) are gossiped on `ce-segments`.
- Any node can re-fetch any segment from any holder and verify the hash.
- Chain checkpoints (Phase 1c) anchor segment boundaries: once a checkpoint is finalised, no segment within it can be silently rewritten.

Minimum replica target: **5 independent peers** per segment (tracked in the atlas). Segments below the threshold trigger a re-replication request on the mesh.

### 8c. One-command relay deploy (planned)

A single script that provisions a relay, deploys CE, sets up nginx, and registers it in DNS — ready to add to the bootstrap list.

```bash
# Deploy a new relay on Hetzner in one command
./scripts/deploy-relay.sh \
  --name relay-2 \
  --domain relay-2.ce-net.com \
  --hetzner-token $HETZNER_API_TOKEN \
  --ssh-key ~/.ssh/id_ed25519

# Output:
# ✅ Server created: 203.0.113.45
# ✅ CE deployed and running
# ✅ nginx configured for relay-2.ce-net.com
# ✅ Peer ID: 12D3KooW...
# Add to BOOTSTRAP_URLS and redeploy.
```

For hackers wanting to run their own relay on any provider:

```bash
# Generic SSH deploy — any Linux server
CE_SSH_HOST=1.2.3.4 CE_SSH_USER=root ./scripts/deploy-relay-ssh.sh \
  --domain myrelay.example.com
```

### 8d. ce-net.com frontend separation (planned)

`ce-net.com` root serves the marketing/dashboard frontend (Tauri web, or static HTML). Bootstrap lives on `relay.ce-net.com` — separate subdomain, no conflict. The existing `GET /bootstrap` endpoint is only exposed on the relay subdomain, not the root.

---

## Phase 9 — Human-Readable Names

On-chain `NameClaim` tx type. Nodes can claim short names, valid for a fixed period, burned from balance.

```rust
// ce-chain/src/lib.rs — add to TxKind
NameClaim {
    name: String,   // max 32 chars, [a-z0-9-] only
    node_id: NodeId,
    expires: u64,   // block height
},
NameRelease {
    name: String,
    node_id: NodeId,
},
```

Resolution is pure chain query — no DNS, no central registry.

```bash
ce name claim mylaptop   # burns 1000 credits, name valid for 210_000 blocks (~1 year)
ce name ls               # list names on chain
ce name resolve mylaptop # print node_id for name

# Use names everywhere a node_id is accepted:
ce exec mylaptop --image rust:latest cargo build
ce fund mylaptop 500
```

Cost: 1000 credits. Duration: 210,000 blocks. Name collision: first-wins per chain ordering.

---

## Implementation order

1. ~~**Fix nonce replay**~~ ✅ Done
2. ~~**Node-to-node services** (Phase 2)~~ ✅ Done (device registry, sync push, sandboxed exec; watch + .ceignore + on-chain TrustGrant broadcast planned)
3. ~~**Credit escrow / JobExpire**~~ ✅ Done
4. ~~**Heartbeat economy**~~ ✅ Done — 30s heartbeat loop, epoch replay prevention, cell wallet exhaustion terminates container
4b. ~~**Chain security hardening**~~ ✅ Done — replay attack prevention (tx deduplication), inflation attack fix (one UptimeReward per block), bid-override double-spend fix, heartbeat epoch overflow DoS fix, settlement hijacking fix (payer_sig v2 binds host identity)
5. ~~**Cell deploy CLI**~~ ✅ Done — `ce deploy`, `ce ps`, `ce kill`, `ce fund`, `ce run`, `GET /jobs`, `POST /transfer`, `GET /atlas`
6. ~~**Auto-bootstrap from ce-net.com**~~ ✅ Done — `ce start` fetches relay list automatically; `GET /bootstrap` endpoint added; inline `ce devices add <name> <id>` works
7. ~~**Chain storage optimisation**~~ ✅ Done — bincode+zstd persistence, O(1) tip validation, transparent JSON migration
8. ~~**Distributed segment archive**~~ ✅ Done — light node mode, rendezvous-hash segment assignment, `ce-segments` gossip topic, `SegmentFetch` RPC, oldest_block routing
9. **DNS + nginx for relay** — wire relay.ce-net.com → 178.105.145.170, proxy /bootstrap (30 min ops task)
10. ~~**Subscription system** (Phase 6a)~~ ✅ Done — SSE endpoints `/signals/stream`, `/blocks/stream`, `/transactions/stream`; `signal_tx`/`block_tx`/`tx_tx` broadcast channels wired through `ApiState`
11. **Live mesh benchmark suite** (Phase 7) — `ce-bench` crate, gossip latency, RPC RTT, chain sync speed
12. **Chain checkpoints** (Phase 1c) — needed before public launch
13. **Longest-chain fork selection** — reorg function in `mesh_event_loop`
14. **Multi-bootstrap resilience** (Phase 8) — multiple domains, one-command relay deploy, replica targets
15. **Human-readable names** (Phase 9) — on-chain `NameClaim`, CLI `ce name` commands
16. **Multi-provider deploy** (Phase 4b) — Vultr, DigitalOcean, OVH, generic SSH

---

## Platform model & apps

CE is a **trustless compute substrate**; products are apps built on its primitives. The
governing rule — *CE owns generic node-enforced mechanism; apps own policy* — and the full
primitive surface (identity, ledger, atlas, jobs, exec, heartbeats, CEP-1 messaging, grants,
fleet) are specified in **`docs/primitives.md`**, which also lists what CE deliberately does
*not* provide and how the **trust gradient** lets apps run untrusted compute safely.

The first app — a distributed **work scheduler** (fan out N tasks, verify per a per-job
assurance dial, gate opaque work behind earned trust, optional Raft coordinator HA) — is
specified in **`docs/apps/scheduler.md`**.

The full **committed pre-launch capability roadmap** — payment channels, WASM/browser
runtimes, relay incentives, the data layer, GPU support, durable storage, TEE attestation,
verifiable compute, safety/abuse handling, chain maturity, key recovery, governance, and the
interconnect/topology caveat — is in **`docs/frontier.md`**, tagged by CE-vs-app and difficulty,
with the critical path called out.

### Substrate gaps the scheduler surfaced (planned)

- ~~**Mesh-routed deploy**~~ ✅ Done — directed placement on a specific host over `/ce/rpc/1`
  (`RpcRequest::Deploy`/`Kill`, `Deploy`/`Kill` grant-enforced, `POST /mesh-deploy`/`/mesh-kill`,
  `ce deploy --on <device>`). The host tracks the job so it is heartbeat-billed and killable.
- ~~**Reputation read over history**~~ ✅ Done — incremental `NodeStats` cache + `GET /history/:node_id`
  (jobs hosted/paid, heartbeats, earned/spent, first/last height). `ce-rs` exposes `history()`;
  `swarm` trust-tiers placement by delivered work.
- **Stake / bond tx** — lockable, conditionally-released collateral (extends the escrow model)
  to bootstrap trust; start as visible commitment (auto-slash needs a fault oracle).
- **Verifiable randomness beacon** — e.g. block hash, to let schedulers prove non-collusive
  random host selection for the redundancy verification path.

## What CE is NOT

- Not a smart contract platform (chain rules are hardcoded, not programmable)
- Not a general-purpose cloud (no persistent storage primitive yet)
- Not an AI agent framework (CE runs whatever container you give it — if you put an agent in the container, that's the agent, not CE)
- Not Golem (GPL-3.0, Ethereum-coupled, QEMU-based — CE is MIT-licensable, native chain, Docker/gVisor)
