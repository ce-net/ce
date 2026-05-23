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

Node seals block:  +emission_rate(height)       ← early adopter multiplier (UptimeReward tx)
Node hosts job:    +cost of job                 ← JobSettle tx credits host
Node runs job:     -cost of job                 ← JobSettle tx debits payer
```

The uptime emission starts at 1,000 credits/block, halves every 210,000 blocks (hard cap 21B). Early nodes accumulate disproportionately more credit — same economic design as Bitcoin mining, without the hash grinding.

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
 │     10s ticker → build block with UptimeReward → seal (sign) → append → broadcast → announce height
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
| Block integrity | Ed25519 block seal; chain validates prev_hash, index, tx sigs, emission amount |
| Ledger consensus | First valid chain wins currently; honest majority > 50% required |
| Replay prevention | CellSignal carries monotone nonce per sender; Heartbeat epoch strictly increases per (cell, host) |
| Credit enforcement | No credits → API returns 402 before touching Docker; cell wallet exhaustion → host terminates container |
