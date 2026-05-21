# CE — Deployment Guide

## Single node (quick start)

```bash
cargo build --release
./target/release/ce start
```

Defaults: P2P on `:4001`, API on `:8080`, data in `~/.local/share/ce/`.

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
./ce start --port 4001 --api-port 8080
# Note the node ID from the log: "node id: <64 hex>"
```

**Node 2 (peer):**
```bash
# Get node 1's peer ID
N1_ID=$(ssh node1 ce id)
./ce start --port 4001 --api-port 8080 \
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
ce start --port 4001 --api-port 8080 --bootstrap <addr>
```

### Systemd service

```ini
# /etc/systemd/system/ce.service
[Unit]
Description=CE Compute Economy Node
After=network.target

[Service]
ExecStart=/usr/local/bin/ce start --port 4001 --api-port 8080
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
| 8080 | TCP | Inbound | HTTP API |

```bash
# ufw example
ufw allow 4001/tcp
ufw allow 8080/tcp
```

---

## Monitoring

```bash
# Check node status
curl http://localhost:8080/status | jq

# Watch chain height
watch -n5 'curl -s http://localhost:8080/status | jq .height'

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
