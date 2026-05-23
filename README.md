# CE

Pronounced "Sea". A peer-to-peer compute mesh and economy. Donate compute to the network, earn credits, spend credits on compute. Like if Bitcoin ran Docker.

Every node is assumed hostile. The honest majority wins. No trusted parties.

```
┌─────────────────────────────────────────────────────────────┐
│                          CE Node                            │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌────────────┐  ┌─────────┐  │
│  │ ce-mesh  │  │ ce-chain │  │ ce-container│  │ce-proto │  │
│  │  libp2p  │  │ uptime   │  │   Docker/   │  │  CEP-1  │  │
│  │ gossip   │  │ emission │  │   gVisor    │  │ signals │  │
│  └──────────┘  └──────────┘  └────────────┘  └─────────┘  │
│        │              │                                      │
│        └───────── ce-node (orchestrator) ───────────────────┤
│                          │                                   │
│                HTTP API :8080                               │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Build
cargo build --release

# Start a node (mines blocks, API on :8080, P2P on :4001)
./target/release/ce start

# Check status and balance
./target/release/ce status

# Join an existing network
./target/release/ce start --port 4002 --api-port 8081 \
  --bootstrap /ip4/1.2.3.4/tcp/4001/p2p/<peer-id>

# Submit a container job (node must have positive balance)
curl -X POST http://localhost:8080/jobs/bid \
  -H 'Content-Type: application/json' \
  -d '{"image":"alpine:latest","cpu_cores":1,"mem_mb":128,"duration_secs":30,"bid":100}'
```

## Architecture

### Crates

| Crate | Description |
|---|---|
| `ce-identity` | Ed25519 keypair, node ID, sign, verify |
| `ce-chain` | Blockchain, uptime emission, transactions, balance, persistence |
| `ce-mesh` | libp2p networking — Kademlia DHT + Gossipsub, chain sync |
| `ce-container` | Docker container management, gVisor isolation, resource limits |
| `ce-node` | Orchestrator: ties everything together, HTTP API, mining loop |
| `ce-protocol` | ce-protocol-1 (CEP-1) cell signaling wire format |
| `ce-deploy` | Hetzner provisioning and SSH deployment for E2E tests |

### Credit model

Nodes earn credits by staying online and mining blocks. Credits are spent to run containers on other nodes.

- Block production: every 10 seconds, the node seals a block and includes one `UptimeReward` tx for itself
- Emission starts at 1,000 credits/block, halves every 210,000 blocks, hard cap 21 billion
- Running a job debits the payer; the host earns the settlement cost
- No balance → `POST /jobs/bid` returns 402

### Transaction types

| Type | Who signs | Effect |
|---|---|---|
| `Transfer` | sender | Move credits between nodes |
| `UptimeReward` | miner | Mint credits for the block producer |
| `JobBid` | payer | Broadcast an open offer for compute; `bid` credits are locked |
| `JobSettle` | host (+ payer co-sig) | Confirm job completion, transfer cost (≤ bid) |
| `JobExpire` | payer | Reclaim locked credits after EXPIRY_BLOCKS (1440) with no settlement |
| `TrustGrant` | grantor | Record on-chain that grantor trusts grantee as a named device |
| `Heartbeat` | host | Periodic billing for a running cell: debits cell, credits host |

### Job lifecycle

```
Payer: POST /jobs/bid          → JobBid tx broadcast on mesh
Any host with capacity:        → accepts bid, pulls image, starts container
Container runs...
Container exits:               → host marks job awaiting_settlement
Payer: POST /jobs/:id/settle   → payer signs (job_id, cost)
Host:                          → builds JobSettle tx, broadcasts
Next block:                    → chain confirms, balances updated
```

Chain validation enforces: payer != host, payer_sig valid, matching JobBid in prior block, no double-settle, payer balance >= cost.

### Cell protocol (CEP-1)

Containers that implement `ce-protocol` can signal other nodes through the mesh. Every signal is Ed25519-signed and requires a `BurnProof` (on-chain tx reference) for non-empty payloads — prevents free-riding.

```
ce-protocol-1 gossip topic
  inbound:  decode → verify sig → burn-proof check against chain → expose via GET /signals
  outbound: POST /signals/send → sign → broadcast
```

### Container isolation

All containers run with:
- **Runtime**: `runsc` (gVisor) when available; falls back to runc with a logged warning
- **CPU**: cgroup v2 hard limit (`nano_cpus`)
- **Memory**: cgroup v2 hard limit
- **Network**: `none` — no direct internet; all traffic must route through CE

### Mesh

libp2p 0.53, six Gossipsub topics:

| Topic | Purpose |
|---|---|
| `ce-transactions` | Broadcast pending txs |
| `ce-blocks` | Broadcast newly mined blocks |
| `ce-heights` | Height announcements for sync triggering |
| `ce-syncreq` | Request blocks from a given height |
| `ce-syncresp` | Serve blocks to syncing nodes (up to 500/batch, 4MB max) |
| `ce-protocol-1` | CEP-1 cell signals |

## Testing

```bash
# Unit tests — no infrastructure needed
cargo test --workspace

# Local multi-node integration tests
cargo test -p ce-node -- --nocapture

# Job lifecycle test — requires Docker
cargo test -p ce-node job_lifecycle -- --ignored --nocapture

# Hetzner E2E tests — requires HETZNER_API_TOKEN, CE_SSH_KEY_NAME, CE_SSH_KEY_PATH
cargo build --release
cargo test -p ce-deploy -- --ignored --nocapture
```

See [docs/testing.md](docs/testing.md) for full test instructions.

## API Reference

See [docs/api.md](docs/api.md) for the complete reference.

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Liveness probe |
| GET | `/status` | Node ID, chain height, balance |
| POST | `/jobs/bid` | Broadcast a container job bid |
| GET | `/jobs` | List all jobs tracked by this node |
| GET | `/jobs/:id` | Job status (pending/running/awaiting_settlement/settled/failed) |
| POST | `/jobs/:id/settle` | Payer co-signs the settlement |
| DELETE | `/jobs/:id` | Force-stop a container |
| POST | `/transfer` | Transfer credits to another node |
| GET | `/signals` | Last 100 validated CEP-1 signals |
| POST | `/signals/send` | Sign and broadcast a CEP-1 signal |
| GET | `/atlas` | Peer capacity atlas from capacity advertisements |
| PUT | `/sync/*path` | Upload a file (CE identity auth, must be trusted device) |
| GET | `/sync/*path` | Download a file (CE identity auth, must be trusted device) |
| POST | `/exec` | Run a command remotely (CE identity auth, must be trusted device) |

## Data Directory

Default: `~/.local/share/ce/`

```
~/.local/share/ce/
├── identity/
│   └── node.key          # Ed25519 secret key (chmod 600)
└── chain/
    └── chain.json        # Full blockchain (JSON)
```

## CLI

```
ce start [--port 4001] [--api-port 8080] [--bootstrap <multiaddr>]
ce status
ce balance
ce id

# Node-to-node services (sync files and run sandboxed commands on trusted peers)
ce devices add <name>               # register a trusted peer (prompts for node ID + addr)
ce devices ls                       # list registered peers
ce devices revoke <name>            # remove trust
ce sync <src> <device:remote-path>  # push files to a peer
ce exec <device> --image <img> [--cwd ~/path] <command...>
                                    # run in sandboxed container on a peer

# Cell economy
ce deploy <image> [--fund N] [--cpu N] [--mem N] [--duration N]
                                    # submit a job bid on the local node
ce ps [--api-port N]                # list all jobs on this node
ce kill <job-id> [--api-port N]     # force-stop a job
ce fund <node-id> <credits>         # transfer credits to another node
ce run <cell-id> [payload-hex] [--burn-tx <tx-id>]
                                    # send a CEP-1 signal to a cell
```
