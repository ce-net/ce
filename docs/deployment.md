# CE — Deployment Guide

## Adding your laptop and desktop to the mesh

This is the two-step process to join your own machines to your CE network.

### Step 1: Install CE on each device

**macOS / Linux:**
```bash
curl -sSL https://raw.githubusercontent.com/ce-net/ce/main/install.sh | bash
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/ce-net/ce/main/install.ps1 | iex
```

**Homebrew (macOS / Linux):**
```bash
brew install ce-net/ce/ce
```

### Step 2: Start CE on each device

On each machine, run:
```bash
ce start
```

The node auto-joins the public mesh via `ce-net.com` bootstrap. If your devices are on the same LAN, mDNS will find them automatically — no manual peer config needed.

To verify it is running:
```bash
ce status
# prints: node ID, chain height, balance
```

### Step 3: Authorize a peer with a capability

CE's only trust primitive is the **capability** — a signed, attenuating grant from a node (or a
configured root key) to a principal. There is no device allowlist. See `docs/capabilities.md`.

**On the device you want to control remotely, get its node ID:**
```bash
ce id
# output: 7a3f9b2c...  (64 hex chars)
```

**On the machine being controlled (the resource owner), issue a capability to the controller:**
```bash
# desktop authorizes the laptop to exec/sync/tunnel on it, for 90 days
ce grant <laptop-node-id> --can exec,sync,tunnel --expires 90d
# → prints a capability token
```

**On the controller, store it under an alias (the capability wallet):**
```bash
ce wallet add desktop 7a3f9b2c... --cap <token>
ce wallet ls
```

No IP:port anywhere, on the LAN or behind NAT: device-to-device traffic (`exec`/`sync`/`deploy`/
`tunnel`) routes through the mesh over libp2p, and the relay handles NAT traversal. Each command
talks to your *local* node (`--api-port`, default 8844), which signs and forwards to the target;
the wallet supplies the capability. Revoke with `ce revoke <nonce>` (on-chain) or let it expire.

### Step 4: Use the authorized peer

```bash
# Forward a local port to the peer over the mesh (transport primitive)
ce tunnel desktop 2222:22       # then: ssh -p 2222 you@localhost

# Submit a compute job (any node with capacity picks it up)
ce deploy alpine:latest --cpu 2 --mem 512 --duration 60
```

Remote exec and file sync/mirror are the **`rdev` app** (built on CE primitives), not node commands:

```bash
rdev exec desktop --image alpine:latest -- echo hello
rdev watch ./code desktop:code      # continuous 1:1 folder mirror
```

---

## Single node (quick start)

```bash
cargo build --release
./target/release/ce start
```

Defaults: P2P on `:4001`, API on `:8844`, data in `~/.local/share/ce/`.

```bash
# Different ports
./target/release/ce start --port 5001 --api-port 9090

# Custom data directory
./target/release/ce --data-dir /data/ce-node start
```

---

## Multi-node (manual)

**Node 1 (genesis):**
```bash
./ce start --port 4001 --api-port 8844
# Note the node ID from the log: "node id: <64 hex>"
```

**Node 2 (peer):**
```bash
# Get node 1's peer ID
N1_ID=$(ssh node1 ce id)
./ce start --port 4001 --api-port 8844 \
  --bootstrap /ip4/<node1-ip>/tcp/4001/p2p/$N1_ID
```

Node 2 will discover node 1 via Kademlia and receive a height announcement, triggering chain sync.

---

## Automated Hetzner deployment

Use the shell scripts in `deploy/` for quick cluster setup, or the Rust `ce-deploy` crate for programmatic E2E testing.

### Shell scripts

```bash
# Set your environment
export HETZNER_API_TOKEN=hcloud-xxxxxxxxxx
export CE_SSH_KEY_NAME=my-key          # key name in Hetzner project
export CE_SSH_KEY_PATH=~/.ssh/id_ed25519

# Build the binary
cargo build --release

# Start a 3-node cluster
./deploy/cluster.sh 3

# Run E2E test against the cluster
./deploy/e2e_test.sh

# Tear down (or it times out and tears down automatically)
```

### Hetzner E2E test suite

```bash
cargo build --release
export HETZNER_API_TOKEN=...
export CE_SSH_KEY_NAME=...
export CE_SSH_KEY_PATH=...

# Run all E2E tests (provisions and destroys servers automatically)
cargo test -p ce-deploy -- --ignored --nocapture

# Run a single E2E test
cargo test -p ce-deploy -- --ignored three_nodes_reach_consensus --nocapture
```

---

## Server setup (manual install on Ubuntu 22.04)

```bash
# On the server
apt-get update && apt-get install -y libssl-dev

# Copy binary from your machine
scp target/release/ce root@<server-ip>:/usr/local/bin/ce
chmod +x /usr/local/bin/ce

# Start
ce start --port 4001 --api-port 8844 --bootstrap <addr>
```

### Systemd service

```ini
# /etc/systemd/system/ce.service
[Unit]
Description=CE Node
After=network.target

[Service]
ExecStart=/usr/local/bin/ce start --port 4001 --api-port 8844
Restart=always
RestartSec=5
Environment=RUST_LOG=ce=info

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable --now ce
journalctl -u ce -f
```

---

## Firewall rules

| Port | Protocol | Direction | Purpose |
|---|---|---|---|
| 4001 | TCP | Inbound | libp2p P2P (Kademlia + Gossipsub) |
| 8844 | TCP | Inbound | HTTP API |

```bash
# ufw example
ufw allow 4001/tcp
ufw allow 8844/tcp
```

---

## Monitoring

```bash
# Check node status
curl http://localhost:8844/status | jq

# Watch chain height
watch -n5 'curl -s http://localhost:8844/status | jq .height'

# Logs (if using systemd)
journalctl -u ce -f

# Or if started manually
tail -f /var/log/ce.log
```

---

## Data directory layout

```
~/.local/share/ce/
├── identity/
│   └── node.key          # 32-byte Ed25519 secret key (chmod 600)
│                         # BACK THIS UP — losing it means losing your node identity
└── chain/
    └── chain.json        # Full blockchain as JSON
                          # Size grows ~1KB per block
                          # At 6 blocks/minute: ~8MB/day
```

The chain file is rewritten on every new block. For large chains, consider keeping only the last N blocks and a checkpoint. (Not yet implemented.)

---

## Upgrading

CE has no migration system yet. To upgrade:

1. Stop the node
2. Replace the binary
3. Restart

The chain file format is backward-compatible as long as new fields are added with `#[serde(default)]`. The identity key format (raw 32-byte Ed25519) will never change.
