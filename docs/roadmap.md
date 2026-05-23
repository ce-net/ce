# CE Roadmap

Current state and what needs to be built to achieve the full vision.

---

## Vision

CE is two things simultaneously:

1. **Open compute economy** — a mesh where any node can offer or consume compute, with credits as the only resource allocation mechanism. Cells (containers that implement CEP-1) earn and spend credits to stay alive on the network. A cell that nobody uses drains its wallet and dies. A cell that everyone uses accumulates credits, replicates, and thrives.

2. **Personal mesh OS** — your laptop, desktop, and servers all run CE nodes. They share the same Ed25519 identity as auth. `ce sync` moves files between your machines. `ce exec` runs commands remotely. There is no "deployment" — your machines are already one virtual computer, and the mesh makes the boundaries invisible.

These are the same system viewed from two angles. The same identity primitive that lets untrusted strangers transact safely also lets your own machines trust each other implicitly.

---

## Current State (as of 2026-05-23)

### What's working

| Component | Status | Notes |
|---|---|---|
| `ce-identity` | ✅ Complete | Ed25519 keypair, node ID, sign/verify, benchmarks |
| `ce-chain` | ✅ Complete | Uptime emission, Transfer/UptimeReward/JobBid/JobSettle, supply cap (21B), halving schedule, tx_by_id, full validation, persistence, tests |
| `ce-mesh` | ✅ Complete | 6 gossip topics, Kademlia DHT, chain sync, CEP-1 signal routing |
| `ce-protocol` | ✅ Complete | CEP-1 wire format, BurnProof, CellSignal build/verify/encode/decode |
| `ce-container` | ✅ Complete | gVisor detection, CPU/memory/network limits, image pull, wait-for-exit |
| `ce-node` | ✅ Complete | Mining loop (10s ticker), mesh event loop, job manager, signal ring buffer, tx pool |
| HTTP API | ✅ Complete | /jobs/bid, /jobs/:id, /jobs/:id/settle, /jobs/:id DELETE, /status, /signals, /signals/send, /health |
| CLI | ✅ Partial | start, balance, status, id |
| `ce-deploy` | ✅ Complete | Hetzner provisioning, SSH deploy, E2E tests |
| Integration tests | ✅ Complete | single node mines, two nodes sync, tx pool propagates, API health/status, signal propagation, job lifecycle (requires Docker, skipped by default) |

The foundation — identity, chain, mesh, protocol, containers, job economy — is fully implemented and tested. The system can mine blocks, earn credits, accept jobs from other nodes, run containers in gVisor, settle on-chain, and route CEP-1 signals across the mesh.

### Known gaps and correctness issues

**Nonce replay prevention** — CEP-1 signals carry a monotone nonce but `ce-node` doesn't track last-seen nonce per sender. Replay attacks on signals are currently possible. Fix: `HashMap<NodeId, u64>` in the mesh event loop, reject signals where `nonce <= last_seen`.

**Fork selection** — `Chain::append` uses first-wins. If two nodes mine simultaneously and then each receives the other's block, whichever arrived first stays. No longest-chain rule. Fix: in `mesh_event_loop`, on `NewBlock`, compare against current tip and replace if the incoming chain would be longer (needs a reorg function).

**JobBid credits not locked** — A payer can submit a bid, then spend those credits elsewhere before the job settles. The chain's balance check in `JobSettle` catches it at settle time (rejects the settle if balance insufficient), but the host has already done the work. Fix: track `locked_balance` per node for open bids; debit at bid time, credit back on settle or expire. Add `JobExpire` tx type with a block-height timeout.

**`difficulty` field is vestigial** — Always 0. Kept for forward compatibility. Fine for now.

---

## Phase 1 — Chain hardening

These close the correctness gaps in the existing economy before building on top.

### 1a. Nonce replay prevention

In `ce-node/src/lib.rs`, `mesh_event_loop`, add:

```rust
let mut last_nonce: HashMap<NodeId, u64> = HashMap::new();
// ... in CellSignal handler:
if let Some(&prev) = last_nonce.get(&signal.from) {
    if signal.nonce <= prev {
        warn!("dropping replay: nonce {} <= {}", signal.nonce, prev);
        continue;
    }
}
last_nonce.insert(signal.from, signal.nonce);
```

### 1b. Credit escrow for JobBid

Add `locked_balance: HashMap<NodeId, u64>` to `Chain`. When a `JobBid` is appended, lock `bid` credits from payer. When `JobSettle` is confirmed, release to host. When `JobExpire` is confirmed, release back to payer.

New tx type:
```rust
JobExpire { job_id: [u8; 32], payer: NodeId }
```

Chain validation: `JobExpire` is only valid if no `JobSettle` exists for `job_id` and current block height > bid_block + EXPIRY_BLOCKS (e.g., 144 blocks ≈ 24 hours at 10min/block, or ~1440 at 10s/block).

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

## Phase 2 — Personal mesh OS

This is the "connect your own computers" layer. Builds entirely on existing identity and mesh primitives — no new chain logic needed.

### 2a. Machine registry

`~/.ce/machines.toml`:
```toml
[devices]
desktop = "8f3a9b..."   # NodeId hex
laptop  = "2d91fc..."
server  = "a441e2..."
```

CLI commands:
```
ce devices add <name>          # trust a device (prompts for its public key)
ce devices ls                  # list registered machines with online status
ce devices revoke <name>       # remove trust, broadcast revocation
```

Devices are added by signing their NodeId with your master key. The trust relationship is broadcast on the mesh and recorded on-chain (new tx type: `TrustGrant { grantor: NodeId, grantee: NodeId, label: String }`).

### 2b. Authenticated file transfer endpoint

New endpoint in `ce-node/src/api.rs`:

```
PUT  /sync/<path>   — receive file chunks, verify sender is in trusted devices
GET  /sync/<path>   — serve file, verify requester is in trusted devices
```

Auth: standard CE identity — request is signed by the sender's node key. Receiver checks against its machine registry. No additional auth layer needed.

### 2c. `.ceignore` format

Like `.gitignore`. Patterns for paths to skip during sync. Defaults include:
```
target/
node_modules/
.git/objects/
*.pyc
__pycache__/
.DS_Store
```

Parser: use the `ignore` crate (already common in Rust ecosystem).

### 2d. CLI commands

```
ce sync <src> <dst>            # e.g. ce sync . desktop:~/code/ce
ce sync --watch <src> <dst>    # inotify/fsevents, sync on save
ce exec <machine> <command>    # run remotely, stream stdout/stderr back
```

`ce exec` connects to the target node's API, sends a signed command via a new endpoint:
```
POST /exec   { cmd: ["cargo", "build"], cwd: "~/code/ce" }
```
Response is a streaming newline-delimited stream of stdout/stderr lines.

`ce sync --watch` uses inotify on Linux (via the `notify` crate) to detect file modifications and immediately pushes diffs.

### Developer workflow this enables

```bash
# On laptop — edit a file, it auto-syncs to desktop
ce sync --watch . desktop:~/code/ce

# Compile on the desktop (your actual powerful machine)
ce exec desktop cargo build --release

# Output streams back to your laptop terminal in real time
# You never think about "which machine am I on"
```

---

## Phase 3 — Cell economy CLI

This layer makes cells (CEP-1 containers) first-class deployable units from the CLI.

### 3a. Heartbeat economy

Add `Heartbeat` tx type:
```rust
Heartbeat { cell: NodeId, host: NodeId, amount: u64, epoch: u64 }
```

The cell signs its own heartbeat every 30 seconds and pays `amount` to the host from its own wallet. If a cell's wallet reaches zero and it can't afford the next heartbeat, the host terminates the container.

This replaces the current job-lifetime model for long-running cells. Short batch jobs still use JobBid/JobSettle.

### 3b. `ce deploy` for cells

```bash
ce deploy github.com/user/ollama-cell --fund 1000
ce deploy docker:ollama/ollama --fund 500
```

Steps:
1. Find cheapest available node via mesh atlas (nodes broadcast capacity)
2. Submit `JobBid` with the cell image and initial wallet funding
3. Cell starts, registers its capabilities via capability-only CEP-1 signals
4. Returns a `CellHandle` (NodeId) you can address signals to

### 3c. Cell management CLI

```bash
ce ps                          # list your running cells, their balance, capability
ce fund <cell-id> <credits>    # top up a cell's wallet
ce kill <cell-id>              # withdraw remaining balance, terminate
ce run <cell-id> <input>       # send a signal, stream response to stdout
```

`ce run` is just:
```bash
ce signals send --to <cell-id> --payload "$(echo $input)" | ce signals receive
```

The pipe model: `ce deploy github.com/ollama-cell | ce run "what is the meaning of life"`

### 3d. Capacity advertisement

Nodes broadcast their available capacity (CPU, memory, running cell count) as a capability-only CEP-1 signal every 60 seconds. Other nodes cache this in an atlas.

The atlas is how `ce deploy` finds a host — scan the atlas for nodes with enough capacity and the lowest current load.

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

1. **Fix nonce replay** — one day, closes a security hole
2. **Personal mesh OS** (Phase 2) — this is what makes CE useful on day one for the person building it
3. **Credit escrow / JobExpire** — closes the "host did work but payer disappeared" gap
4. **Heartbeat economy** — enables long-running cells
5. **Cell deploy CLI** — completes the developer-facing product
6. **Chain checkpoints** — needed before public launch
7. **Bootstrap / multi-provider deploy** — launch infrastructure

---

## What CE is NOT

- Not a smart contract platform (chain rules are hardcoded, not programmable)
- Not a general-purpose cloud (no persistent storage primitive yet)
- Not an AI agent framework (CE runs whatever container you give it — if you put an agent in the container, that's the agent, not CE)
- Not Golem (GPL-3.0, Ethereum-coupled, QEMU-based — CE is MIT-licensable, native chain, Docker/gVisor)
