# CE — Coding Standards

## Terminology (canonical glossary)

| Term | Definition |
|---|---|
| **CE** | The project. Pronounced "Sea". No acronym expansion. |
| **Node** | A running CE process. Has an identity (Ed25519 key), a local chain copy, and a mesh connection. |
| **Node ID** | The Ed25519 verifying-key bytes of a node, `[u8; 32]`, displayed as 64 hex chars. |
| **Cell** | A Docker container that implements ce-protocol-1. Gets first-class mesh status. |
| **Foreign container** | A Docker container without ce-protocol-1 support. Runs but is invisible to the protocol layer. |
| **Job** | A Docker container managed by CE (cell or foreign). Identified by `job_id` (= Docker container ID). |
| **Job ID** | The Docker container ID that CE uses as the job identifier. Single canonical value, returned as `job_id` from the API. |
| **Credit** | The unit of economic value, for display. Internally all amounts are integer **base units** — `1 credit = CREDIT (10^18) base units`, wei-style — so micropayments and decades of halvings stay representable. On-chain amounts are `u128` base units; balances are `i128` (signed, to allow temporary deficits during sync). Never floating point: float arithmetic is non-deterministic across machines and would split consensus. |
| **Base unit** | The atomic integer unit of value. `CREDIT = 10^18` base units = 1 credit (`ce_chain::CREDIT`). All `TxKind` amounts, balances, and `SUPPLY_CAP` are denominated in base units. The CLI converts to/from human credit decimals for display and input; the HTTP API carries amounts as decimal **strings** (values exceed JSON's 2^53 safe-integer limit). |
| **Balance** | A node's net credit position: mining rewards + hosting income − job spend. |
| **Block reward** | Credits earned by the miner of a block. Starts at 1,000, halves every 210,000 blocks. |
| **Payer** | The node whose balance is debited when a job runs. Identified by `NodeId`. |
| **Host** | The node running a job (and being credited). Identified by `NodeId`. |
| **Meter tx** | A `TxKind::Meter` transaction recording CPU/memory usage for one billing interval. |
| **ce-protocol-1** | The CE cell-signaling protocol, abbreviated **CEP-1**. Implemented in the `ce-protocol` crate. Gossipsub topic: `ce-protocol-1`. |
| **Burn proof** | A `BurnProof` struct proving credits were spent before a CEP-1 payload was transmitted. |
| **Chain** | The local PoW blockchain. Authoritative source of balances and transaction history. |
| **Mesh** | The libp2p networking layer. `Mesh` is the actor (not `Clone`); `MeshHandle` is the cheap clone. |

## Rust style

- `edition = "2024"` across all crates
- No `unsafe` outside of carefully justified cases (none currently exist)
- `anyhow::Result` for all fallible public functions
- `tracing::{info, warn, debug}` for logging — no `println!` in library code
- Errors returned (not panicked) at all public boundaries; `expect()` only for invariants that truly cannot fail

## Async rules

- `tokio::task::spawn_blocking` for all CPU-bound work (PoW mining)
- No `.unwrap()` across await points in production paths
- Async methods on `!Sync` types must use free functions or owned values — do not take `&self` across await if `Self: !Sync`

## Serialization

- bincode for hashing (deterministic, compact) and gossip wire format
- bincode + zstd (level 3) for disk persistence — ~8x smaller than JSON; legacy JSON files are migrated transparently on first load
- `[u8; 64]` sig fields require the local `sig_serde` module — serde supports arrays only up to [T; 32]

## Naming

- `NodeId = [u8; 32]` — always the ed25519 verifying key bytes, hex-encoded for display
- `TxKind` — the unsigned payload; `Tx` — the signed envelope
- `Block` — unsigned; validity depends on `Chain::append` which checks all rules
- `MeshHandle` — cheap clone (Arc'd channel senders); `Mesh` — the swarm actor

## Error handling

- Log at `warn!` when rejecting a peer's data (bad block, bad tx, bad gossip)
- Log at `info!` for state changes (new block, peer connected, sync applied)
- Do not panic on network inputs; discard and log

## Tests

- Unit tests in `#[cfg(test)] mod tests` at the bottom of each `src/lib.rs`
- Integration tests in `crates/*/tests/*.rs`
- Hetzner E2E tests in `crates/ce-deploy/tests/e2e.rs`, all marked `#[ignore]`
- Use `difficulty = 1` in chain unit tests to avoid slow PoW in CI
- Use `NEXT_PORT` atomic counter in local integration tests to avoid port conflicts

## Commits

- Author: Leif Rydenfalk <ledamecrydenfalk@gmail.com>
- No co-author lines
- Commit message: imperative mood, short subject, body for why not what
