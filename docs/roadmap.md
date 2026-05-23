# CE Roadmap

Current state and what needs to be built to achieve the full vision.

---

## Vision

CE is two things simultaneously:

1. **Open compute economy** — a mesh where any node can offer or consume compute, with credits as the only resource allocation mechanism. Cells (containers that implement CEP-1) earn and spend credits to stay alive on the network. A cell that nobody uses drains its wallet and dies. A cell that everyone uses accumulates credits, replicates, and thrives.

2. **Node-to-node services** — CE nodes can sync files and run commands on each other. Any node can trust any other via `machines.toml`. `ce sync` pushes files. `ce exec` runs commands inside a sandboxed container on the remote node — same gVisor/no-network isolation as compute jobs. There is no special "personal OS" mode; it is the same trust model applied to your own machines. Register the peers you own in `machines.toml` so `ce deploy` prefers them over stranger nodes when building or hosting cells.

These are the same system from two angles. The identity primitive that lets untrusted strangers transact safely is also what lets your machines authenticate each other without passwords.

---

## Current State (as of 2026-05-23)

### What's working

| Component | Status | Notes |
|---|---|---|
| `ce-identity` | ✅ Complete | Ed25519 keypair, node ID, sign/verify, benchmarks |
| `ce-chain` | ✅ Complete | Uptime emission, Transfer/UptimeReward/JobBid/JobSettle/JobExpire/TrustGrant/Heartbeat, supply cap (21B), halving schedule, credit escrow (locked_balance), tx_by_id, last_heartbeat_epoch, full validation, persistence, tests |
| `ce-mesh` | ✅ Complete | 6 gossip topics, Kademlia DHT, chain sync, CEP-1 signal routing |
| `ce-protocol` | ✅ Complete | CEP-1 wire format, BurnProof, CellSignal build/verify/encode/decode |
| `ce-container` | ✅ Complete | gVisor detection, CPU/memory/network limits, image pull, wait-for-exit, stop_job |
| `ce-node` | ✅ Complete | Mining loop, mesh event loop, job manager, heartbeat loop (30s), capacity broadcast (60s), atlas, signal ring buffer, tx pool, nonce replay prevention |
| HTTP API | ✅ Complete | /jobs/bid, /jobs (list), /jobs/:id, /jobs/:id/settle, /jobs/:id DELETE, /transfer, /status, /signals, /signals/send, /health, /atlas, /sync/*, /exec |
| CLI | ✅ Complete | start, balance, status, id, devices (add/ls/revoke), sync, exec, deploy, ps, kill, fund, run |
| Device registry | ✅ Complete | machines.toml, trusted device management, CE identity auth for sync/exec |
| `ce-deploy` | ✅ Complete | Hetzner provisioning, SSH deploy, E2E tests |
| Integration tests | ✅ Complete | single node mines, two nodes sync, tx pool propagates, API health/status, signal propagation, job lifecycle (requires Docker, skipped by default) |

The foundation — identity, chain, mesh, protocol, containers, job economy — is fully implemented and tested. The system can mine blocks, earn credits, accept jobs from other nodes, run containers in gVisor, settle on-chain, route CEP-1 signals, sync files between trusted devices, and execute remote commands.

### Known gaps and correctness issues

**Fork selection** — `Chain::append` uses first-wins. If two nodes mine simultaneously and then each receives the other's block, whichever arrived first stays. No longest-chain rule. Fix: in `mesh_event_loop`, on `NewBlock`, compare against current tip and replace if the incoming chain would be longer (needs a reorg function).

**`difficulty` field is vestigial** — Always 0. Kept for forward compatibility. Fine for now.

**`ce sync --watch` not yet implemented** — Directory watching (inotify/fsevents via the `notify` crate) is planned but not yet built. Use periodic `ce sync` for now.

**`.ceignore` format not yet implemented** — Sync skips a hardcoded set of default patterns (`target/`, `node_modules/`, `.git/objects/`, `*.pyc`, `__pycache__/`, `.DS_Store`). Full `.ceignore` file support (using the `ignore` crate) is planned.

**TrustGrant not broadcast on mesh** — `ce devices add` stores the trust relationship locally in `machines.toml`. Broadcasting a `TrustGrant` tx to the mesh (so other nodes can discover trust) is planned but not yet wired to the CLI.

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
| **Explicit trust** | Sender must appear in `machines.toml` before any request is accepted |

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

### 1c. Chain checkpoints

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
addr    = "192.168.1.10:8080"
```

CLI commands implemented:
```
ce devices add <name>          # prompts for node ID and API address
ce devices ls                  # list registered devices
ce devices revoke <name>       # remove trust
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

Submits a `JobBid` on the local node's API (default port 8080). Use `--api-port` to override.

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

## Phase 4 — Bootstrap and network launch

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

## Implementation order

1. ~~**Fix nonce replay**~~ ✅ Done
2. ~~**Node-to-node services** (Phase 2)~~ ✅ Done (device registry, sync push, sandboxed exec; watch + .ceignore + on-chain TrustGrant broadcast planned)
3. ~~**Credit escrow / JobExpire**~~ ✅ Done
4. ~~**Heartbeat economy**~~ ✅ Done — 30s heartbeat loop, epoch replay prevention, cell wallet exhaustion terminates container
5. ~~**Cell deploy CLI**~~ ✅ Done — `ce deploy`, `ce ps`, `ce kill`, `ce fund`, `ce run`, `GET /jobs`, `POST /transfer`, `GET /atlas`
6. **Chain checkpoints** — needed before public launch
7. **Bootstrap / multi-provider deploy** — launch infrastructure

---

## What CE is NOT

- Not a smart contract platform (chain rules are hardcoded, not programmable)
- Not a general-purpose cloud (no persistent storage primitive yet)
- Not an AI agent framework (CE runs whatever container you give it — if you put an agent in the container, that's the agent, not CE)
- Not Golem (GPL-3.0, Ethereum-coupled, QEMU-based — CE is MIT-licensable, native chain, Docker/gVisor)
