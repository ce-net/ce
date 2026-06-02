# Payment channels — design

**Status: chain layer implemented** (`ChannelOpen`/`ChannelClose`/`ChannelExpire` txs, the
`channel_receipt_bytes` receipt primitive, the `open_channels` lock, validation, and tests).
**Remaining: API / SDK / CLI wiring** so apps can open channels, stream receipts, and close.
The highest-leverage item on `docs/frontier.md`: the scale unlock that lets the per-signal
economy run at planet scale.

**v0 simplification:** only the **host** closes (with the payer's highest receipt — it maximizes
its own payout, so the payer can't be underpaid), and the **payer** reclaims via `ChannelExpire`
after the timeout. This needs **no dispute window** (only one party closes-with-a-receipt). The
window described below applies once payer-side unilateral close / bidirectional channels are
added.

## Why

Billing today is one `Heartbeat` tx every ~30s per running cell. At a few thousand cells that
is already most of the chain's tx volume; at millions it is impossible — a single PoW chain
cannot ingest millions of micropayments per interval. We must move the *stream* of
micropayments **off-chain** and only touch the chain to open and close a channel.

This keeps CE trustless: payments are cryptographically enforced, not entrusted to anyone.

## Model — unidirectional payer → host channel (Lightning-lite)

Compute payment flows one way (payer funds, host earns), so a unidirectional channel is enough
and far simpler than bidirectional. Multi-hop routing is **out of scope** — channels are direct
payer↔host (you open a channel with each host you run sustained work on).

### Lifecycle

1. **Open** — `ChannelOpen { channel_id, payer, host, capacity, expiry_height }` (signed by payer).
   Locks `capacity` base units of the payer's balance on-chain (same escrow mechanism as a
   `JobBid` lock). One tx.

2. **Pay (off-chain, no tx)** — to pay for an interval of work the payer sends the host a signed
   **receipt**:
   ```
   Receipt { channel_id, cumulative: u128 }  +  payer_sig over canonical bytes
   ```
   `cumulative` is the *total* paid over the channel's life so far — **monotonic**. Each new
   receipt supersedes the prior (strictly higher `cumulative`). Receipts ride CEP-1 (or any
   transport); they never hit the chain. Millions of them cost nothing.

3. **Close / settle** — `ChannelClose { channel_id, cumulative, payer_sig }` submitted on-chain
   (normally by the host, redeeming the latest receipt). Pays `cumulative` to the host and
   returns `capacity − cumulative` to the payer. One tx. Two on-chain txs total, regardless of
   how many micropayments flowed.

4. **Timeout** — if the channel reaches `expiry_height` unclosed, the payer reclaims the full
   remaining balance (mirrors `JobExpire`).

### How it carries signal-pay

The willingness lever moves off-chain but is unchanged in spirit: each work interval the cell
(payer) signs a receipt with a higher `cumulative`; the host keeps serving while receipts keep
arriving and increasing, and **stops the instant they stall or stop growing** — exactly today's
"keep paying only if the work is good," now free and instant. `Heartbeat` becomes the in-channel
receipt cadence rather than a chain tx.

## Trustlessness — the dispute rule

The one subtlety: a unilateral close must not let either side cheat.

- A **host** could try to submit a *stale* receipt with a lower `cumulative` than it actually
  received — no gain (it only underpays itself), so ignore.
- A **host** could submit the *highest* receipt it holds — correct behavior.
- A **payer** could try to close early/unilaterally claiming a *lower* `cumulative` than it
  actually signed, to claw back credits it already promised.

Defense: **unilateral close opens a dispute window** (`DISPUTE_BLOCKS`). During the window the
counterparty may submit a *higher-`cumulative`* receipt (also payer-signed), which replaces the
pending close. After the window with no higher receipt, the highest seen `cumulative` finalizes.
Because every receipt is payer-signed and `cumulative` is monotonic, the highest payer-signed
receipt is authoritative and neither side can do better than the truth. (Watchtowers — a third
party that disputes on behalf of an offline host — are a later refinement; v0 assumes parties
come online within the window.)

## On-chain additions

New `TxKind` variants (integer base units throughout, never floats):

- `ChannelOpen { channel_id: [u8;32], payer: NodeId, host: NodeId, capacity: u128, expiry_height: u64 }`
  — signed by payer; locks `capacity` (validated against free balance like `JobBid`).
- `ChannelClose { channel_id, cumulative: u128, payer_sig: [u8;64] }` — `payer_sig` over
  `channel_close_bytes(channel_id, host, cumulative)` (host bound, v2-style). Validated: channel
  open, `cumulative ≤ capacity`, sig verifies; opens/advances the dispute window; on finalize,
  moves `cumulative` payer→host and unlocks the remainder.
- `ChannelExpire { channel_id, payer }` — payer reclaims after `expiry_height`.

Chain caches: `open_channels: channel_id → (payer, host, capacity, expiry_height, best_cumulative, close_height?)`, parallel to `open_bids`. `NodeStats` gains channel settlements toward reputation (earned/spent already cover the redeemed amount).

Off-chain (not a tx): `Receipt` + `receipt_bytes(channel_id, host, cumulative)` lives in
`ce-protocol` or `ce-identity`; carried over CEP-1 with the existing signal/burn-proof machinery.

## API / SDK / CLI surface (to add)

- `POST /channels/open`, `POST /channels/:id/close`, `GET /channels`, and a receipt-sign/-submit
  path. `ce-rs`: `channel_open`, `pay` (sign a receipt), `channel_close`, `channels`.
- The scheduler/app streams receipts per interval instead of watching `Heartbeat` txs.

## Decisions to lock before coding

- **Dispute window length** (`DISPUTE_BLOCKS`) — long enough for an offline host to come back,
  short enough that capital isn't locked forever. Start ~144 blocks (~24 min at 10s) and revisit.
- **Receipt transport** — ride CEP-1 (reuses signing/dedup) vs a dedicated direct channel. Lean CEP-1.
- **One channel per payer↔host pair**, or many concurrent? Start one; `channel_id` allows many.
- **Watchtowers** — defer.

## What this is NOT (stays an app concern)

Channel *policy* — when to open, how much to fund, receipt cadence, which host — is the
scheduler/app's call. CE provides the enforced open/pay-verify/close/dispute mechanism only.
