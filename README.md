# CE

Pronounced "Sea" is a compute substrate and economy which gives people the ability to donate compute to the network in order to use the network. A peer to peer supercomputer + economy. Like if bitcoin would run doom.

A Byzantine-fault-tolerant compute marketplace where credit is the only resource allocation mechanism. Every node is assumed hostile. The honest majority wins.

```
┌─────────────────────────────────────────────────────────┐
│                     CE Node                             │
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐ │
│  │ ce-mesh  │  │ ce-chain │  │ce-contain│  │ce-prot │ │
│  │ libp2p   │  │ PoW ledg │  │ Docker   │  │  CEP-1  │ │
│  │ gossip   │  │ balance  │  │ metering │  │ signal │ │
│  └──────────┘  └──────────┘  └──────────┘  └────────┘ │
│        │              │                                  │
│        └──────── ce-node (orchestrator) ────────────────┤
│                        │                                 │
│               HTTP API :8080                            │
└─────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Build
cargo build --release

# Start a node (mines immediately, API on :8080, P2P on :4001)
./target/release/ce start

# Check status
./target/release/ce status

# Join an existing network
./target/release/ce start --port 4002 --api-port 8081 \
  --bootstrap /ip4/1.2.3.4/tcp/4001/p2p/<peer-id>

# Submit a container job (payer must have positive balance)
curl -X POST http://localhost:8080/jobs/run \
  -H 'Content-Type: application/json' \
  -d '{"image":"alpine:latest","payer":"<64-hex-node-id>"}'
```

## Architecture

See [docs/architecture.md](docs/architecture.md) for the full design.

### Three components

| Component | What it does |
|---|---|
| **Mesh** (`ce-mesh`) | libp2p 0.53: Kademlia DHT + Gossipsub. Five topics: txs, blocks, heights, syncreq, syncresp. |
| **Economy** (`ce-chain`) | PoW blockchain. Two tx types: `Transfer` and `Meter`. Block reward halves every 210k blocks. |
| **Container** (`ce-container`) | Docker metering via bollard. Reads `ce.payer` label, meters CPU + memory every 10s. |

### Credit model

- Mining a block earns the block reward (starts at 1,000 credits, halves every 210,000 blocks)
- The earlier you join and the longer you run, the more credits you accumulate
- Running a job deducts credits from the payer; the host node earns them
- No credits → no jobs run → no network access

### ce-protocol-1 (CEP-1)

Containers that implement `ce-protocol` (`CellSignal`) get first-class status in the mesh:
they can signal other cells and attach burn proofs. Foreign containers run but can't communicate
through CE. See [docs/protocol.md](docs/protocol.md).

## Crates

| Crate | Description |
|---|---|
| `ce-identity` | Ed25519 keypair, node ID, signing, verification |
| `ce-chain` | Blockchain, PoW, transactions, balance, persistence |
| `ce-mesh` | libp2p networking layer (gossip, DHT, chain sync) |
| `ce-container` | Docker container management and credit metering |
| `ce-node` | Orchestrator: ties all crates together, HTTP API |
| `ce-protocol` | ce-protocol-1 (CEP-1) wire format |
| `ce-deploy` | Hetzner provisioning + SSH deployment for E2E tests |

## Testing

```bash
# Unit tests (no infrastructure needed)
cargo test --workspace

# Local multi-node integration tests
cargo test -p ce-node -- --nocapture

# Hetzner E2E tests (requires API token and SSH key)
export HETZNER_API_TOKEN=hcloud-...
export CE_SSH_KEY_NAME=my-hetzner-key
export CE_SSH_KEY_PATH=~/.ssh/id_ed25519
cargo build --release
cargo test -p ce-deploy -- --ignored --nocapture
```

See [docs/deployment.md](docs/deployment.md) for full deployment instructions.

## API Reference

See [docs/api.md](docs/api.md).

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Liveness probe |
| GET | `/status` | Node ID, chain height, balance |
| POST | `/jobs/run` | Start a container job |
| GET | `/jobs/:id` | Inspect a running job |
| DELETE | `/jobs/:id` | Stop and remove a job |

## Data Directory

Default: `~/.local/share/ce/`

```
~/.local/share/ce/
├── identity/
│   └── node.key          # Ed25519 secret key (chmod 600)
└── chain/
    └── chain.json        # Full blockchain (JSON)
```
