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
| `ce-chain` | ✅ Complete | Uptime emission, Transfer/UptimeReward/JobBid/JobSettle/JobExpire/TrustGrant, supply cap (21B), halving schedule, credit escrow (locked_balance), tx_by_id, full validation, persistence, tests |
| `ce-mesh` | ✅ Complete | 6 gossip topics, Kademlia DHT, chain sync, CEP-1 signal routing |
| `ce-protocol` | ✅ Complete | CEP-1 wire format, BurnProof, CellSignal build/verify/encode/decode |
| `ce-container` | ✅ Complete | gVisor detection, CPU/memory/network limits, image pull, wait-for-exit |
| `ce-node` | ✅ Complete | Mining loop (10s ticker), mesh event loop, job manager, signal ring buffer, tx pool, nonce replay prevention |
| HTTP API | ✅ Complete | /jobs/bid, /jobs/:id, /jobs/:id/settle, /jobs/:id DELETE, /status, /signals, /signals/send, /health, /sync/*, /exec |
| CLI | ✅ Complete | start, balance, status, id, devices (add/ls/revoke), sync, exec |
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

## Phase 2 — Personal mesh OS

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
ce sync <src> <dst>            # e.g. ce sync . desktop:~/code/ce  (push)
ce sync --watch <src> <dst>    # planned: inotify/fsevents, sync on save
ce exec <machine> <command>    # run remotely, print stdout/stderr
```

`ce exec` calls `POST /exec` with the command and working directory; the response is a JSON object with `stdout`, `stderr`, and `exit_code` fields. Process exit code is propagated to the shell.

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

1. ~~**Fix nonce replay**~~ ✅ Done
2. ~~**Personal mesh OS** (Phase 2)~~ ✅ Done (core: device registry, sync push, exec; watch + .ceignore + on-chain TrustGrant broadcast planned)
3. ~~**Credit escrow / JobExpire**~~ ✅ Done
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
