# CE — Design

## Problem

Build a compute marketplace where any node can offer or consume compute, and the economy is self-enforcing with no trusted parties. Every participant is assumed hostile.

## Solution: Three layers

```
Mesh (libp2p)    →  connects nodes, propagates data
Economy (chain)  →  tracks who owns what, can't be faked
Container (Docker) → runs the actual work, metered
```

### Why blockchain?

Classic alternatives fail under the hostile-node assumption:
- Central ledger: single point of compromise
- CRDTs: can't prevent double-spend without coordination
- Signing without consensus: each node can claim any balance it wants

Bitcoin proved that honest-majority PoW works when the incentive is to be honest (attacking costs more credits than it gains).

### Credit flow

```
Time →

Node mines block:  +block_reward(height)       ← early adopter multiplier
Node hosts job:    +cost of job                 ← Meter tx credits host
Node runs job:     -cost of job                 ← Meter tx debits payer
```

The block reward halves every 210,000 blocks so early nodes accumulate disproportionately more credit for the same compute — same economic design as Bitcoin mining.

### Chain sync

On `PeerHeight` event (height > ours): broadcast `SyncReqMsg`. Any node that has the blocks responds with `SyncRespMsg` (up to 500 blocks per response). Receiver validates each block before appending.

This is gossip-based (broadcast, not unicast). Acceptable overhead for a small-to-medium mesh. Future: switch to libp2p `request_response` for large meshes.

### ce-protocol-1 (CEP-1)

First-class cells sign their signals, declare capabilities, and attach burn proofs showing they spent credits before transmitting non-trivial payloads. Foreign containers run but are invisible to the protocol layer.

## Node lifecycle

```
start
 │
 ├─ load identity (or generate)
 ├─ load chain (or start from genesis)
 ├─ connect mesh (libp2p swarm)
 ├─ announce our height to peers
 │
 ├─ [task] mining loop
 │     build block → spawn_blocking(mine) → append → broadcast → announce height
 │
 ├─ [task] mesh event loop
 │     NewTx → verify → add to pool
 │     NewBlock → validate + append → remove txs from pool
 │     PeerHeight → if behind: send sync request
 │     SyncRequest → read chain → send blocks
 │     SyncBlocks → validate + append each block
 │
 ├─ [task] container metering loop (optional)
 │     every 10s: list ce.payer-labeled containers → stats → Meter tx → broadcast
 │
 └─ [task] HTTP API
       /status /health /jobs/run /jobs/:id
```

## Security properties

| Property | Mechanism |
|---|---|
| Identity integrity | Ed25519 keys; same key seeds both chain and libp2p identity |
| Tx authenticity | Every tx signed by origin node; chain validates before accepting |
| Block integrity | SHA256 PoW; chain validates prev_hash, index, difficulty, tx sigs |
| Ledger consensus | Longest valid chain wins; honest majority > 50% required |
| Replay prevention | CellSignal carries monotone nonce per sender |
| Credit enforcement | No credits → API returns 402 before touching Docker |
