# CE — Testing Guide

## Test layers

| Layer | Command | Infrastructure |
|---|---|---|
| Unit tests | `cargo test --workspace` | None |
| Local integration | `cargo test -p ce-node -- --nocapture` | None |
| Hetzner E2E | `cargo test -p ce-deploy -- --ignored --nocapture` | Hetzner account + SSH key |

---

## Unit tests

Run with `cargo test --workspace`. These are fast (sub-second) and test logic in isolation.

### ce-identity tests
- `generate_creates_key_file` — key file written on first run
- `reload_returns_same_node_id` — persistent identity across restarts
- `sign_and_verify_succeeds` — happy path
- `verify_rejects_tampered_message` — wrong data rejected
- `verify_rejects_wrong_key` — wrong key rejected
- `node_id_hex_is_64_chars` — format check
- `node_id_hex_roundtrips` — hex decode roundtrip

### ce-chain tests
- `try_reorg_switches_to_longer_fork` — longer competing chain replaces ours
- `try_reorg_ignores_equal_length_fork` — equal-length fork does not trigger reorg
- `try_reorg_rejects_invalid_block_in_fork` — corrupt block in fork aborts reorg
- `try_reorg_no_connection_returns_false` — orphaned blocks with no common ancestor rejected
- `hash_is_deterministic` — same input → same hash
- `hash_changes_with_nonce` — nonce affects hash
- `difficulty_1_bit` — mines to 1 leading zero bit
- `difficulty_8_bits_requires_zero_byte` — mines to 8 leading zero bits
- `genesis_structure` — genesis block shape
- `append_valid_block` — happy path
- `append_rejects_wrong_index` — index continuity
- `append_rejects_wrong_prev_hash` — chain linking
- `append_rejects_invalid_tx_sig` — tx signature validation
- `three_blocks_chain` — sequential appends
- `balance_starts_zero` — no balance before mining
- `balance_from_block_reward` — miner earns reward
- `balance_with_transfer` — transfer debit + credit
- `block_reward_halving_schedule` — halving at 210k blocks
- `tx_verify_valid` — valid sig accepted
- `tx_verify_rejects_tampered_amount` — tampered kind rejected
- `tx_id_is_stable` — deterministic ID
- `save_and_load_roundtrip` — JSON persistence
- `load_or_genesis_returns_genesis_when_missing` — missing file fallback

### ce-chain Heartbeat tests
- `heartbeat_happy_path` — host emits heartbeat, cell balance debited, epoch recorded
- `heartbeat_rejects_replay` — same or earlier epoch rejected; higher epoch accepted
- `heartbeat_rejects_insufficient_balance` — cell with zero balance cannot be billed
- `heartbeat_rejects_self_pay` — host == cell forbidden
- `heartbeat_rejects_wrong_signer` — heartbeat must be signed by the named host

### ce-protocol tests
- `roundtrip_and_verify` — build, encode, decode, verify
- `requires_burn` — flags payload-without-burn-proof

---

## Local integration tests (`crates/ce-node/tests/local_cluster.rs`)

Run with `cargo test -p ce-node -- --nocapture`. These start real Node instances in-process.

Each test allocates ports from an atomic counter starting at 14100 to avoid conflicts.

- `single_node_mines` — one node mines ≥1 block in 3 seconds
- `two_nodes_sync` — two nodes reach similar chain heights within 5 seconds
- `tx_pool_propagates` — transactions flow between nodes
- `api_health_check` — GET /health returns 200
- `api_status_endpoint` — GET /status returns valid JSON
- `api_job_bid_rejects_zero_balance` — POST /jobs/bid returns 402 when the calling node has zero balance (mine: false)
- `signal_propagates_between_nodes` — node A POSTs /signals/send with a burn_proof referencing one of its mined txs; non-mining node B sees the signal at GET /signals within 5 s of post (full CEP-1 + ce-mesh + chain-validation round trip)
- `job_lifecycle` (**ignored**, requires Docker) — full two-node job lifecycle: bid → host starts container → container exits → payer co-signs settlement → JobSettle confirmed on-chain → balances verified

---

## Hetzner E2E tests (`crates/ce-deploy/tests/e2e.rs`)

### Prerequisites

1. Hetzner Cloud account with an API token (read+write)
2. An SSH key registered in your Hetzner project
3. Build the release binary: `cargo build --release`
4. Set environment variables:

```bash
export HETZNER_API_TOKEN=hcloud-xxxxxxxxxx
export CE_SSH_KEY_NAME=my-hetzner-key-name
export CE_SSH_KEY_PATH=~/.ssh/id_ed25519
```

### Run

```bash
# All E2E tests
cargo test -p ce-deploy -- --ignored --nocapture

# Specific test
cargo test -p ce-deploy -- --ignored three_nodes_reach_consensus --nocapture
```

### Test descriptions

**`three_nodes_reach_consensus`**
- Provisions 3 `cx22` servers in Nuremberg
- Deploys CE binary to each
- Starts node 0 first, then 1 and 2 with bootstrap from node 0
- Waits for all nodes to reach height 5
- Asserts all nodes are within 2 blocks of each other
- Checks /health and /status on all nodes
- Tears down all servers

**`transaction_propagates_across_mesh`**
- 2-node cluster
- Waits for node 0 to accumulate mining balance
- Submits a job (POST /jobs/run) as payer
- Asserts 201 response
- Stops the job
- Tears down

**`late_join_node_syncs`**
- 2-node cluster builds chain to height 10
- Provisions a 3rd server
- Starts CE on it with bootstrap from node 0
- Verifies late-join node syncs to within 2 blocks
- Tears down 3rd server, then cluster

### Cost

Each `cx22` server is ~€0.007/hour. A full E2E run takes 5–15 minutes.
Three tests × three servers each × 15 min ≈ €0.01 total. Servers are always deleted at teardown.

---

## Writing new tests

### Unit test (library crate)
Add to `#[cfg(test)] mod tests` in `src/lib.rs`. Use `difficulty = 1` for any chain operations to keep them fast.

### Integration test (node crate)
Add to `crates/ce-node/tests/`. Use `alloc_ports()` for port allocation. Mark slow tests with `#[ignore]` if they take > 10s.

### E2E test (Hetzner)
Add to `crates/ce-deploy/tests/e2e.rs`. Always mark `#[ignore]`. Always call `cluster.destroy().await` in cleanup, even on failure. Use `anyhow::Result` return type and `?` for error propagation.
