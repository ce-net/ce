# CE HTTP API

Base URL: `http://localhost:8844` (configurable via `--api-port`)

All request and response bodies are JSON. All responses include a `Content-Type: application/json` header.

**Credit amounts** (`bid`, `cost`, `amount`, `balance`, burn `amount`) are carried as decimal **strings** of base units, not JSON numbers — `1 credit = 10^18 base units`, and values routinely exceed JavaScript's 2^53 safe-integer limit, so a number would lose precision. Send e.g. `"bid": "1000000000000000000"` for 1 credit. Clients convert to/from human credit decimals.

**Auth.** Mutating (non-GET) requests require `Authorization: Bearer <data_dir>/api.token`. Read-only GETs are open.

**CORS.** Read-only GET and SSE endpoints send permissive CORS headers **only** for loopback origins (`http(s)://localhost`, `127.0.0.1`, `[::1]`, any port), so a browser dashboard served from `localhost` can fetch them. CORS is scoped to the `GET` method: mutating routes are never made cross-origin-reachable, and a hostile public web page cannot read this node's API from a victim's browser.

**No key endpoint (by design).** There is deliberately **no** `/key/*` HTTP route. Identity-key backup and restore are TTY-only CLI actions (`ce key backup` / `ce key restore`); key material must never cross the API boundary (a network-reachable export would let any api.token holder exfiltrate the identity). A CI boundary gate fails the build if a `/key/*` route or a credit-minting endpoint is ever added.

---

## GET /health

Liveness probe. Returns 200 if the node process is running.

**Response** `200 OK`
```
ok
```

---

## GET /status

Node status snapshot.

**Response** `200 OK`
```json
{
  "node_id": "a3f2...64 hex chars",
  "height": 1042,
  "difficulty": 4,
  "balance": "987000",
  "circulating_supply": "1042000000000000000000",
  "burned_total": "5000000000000000000",
  "bond": "0",
  "weight": "0",
  "free": "987000",
  "locked_channels": "0",
  "locked_bond": "0"
}
```

| Field | Type | Description |
|---|---|---|
| `node_id` | string | 64-hex-char Ed25519 public key (= this node's identity) |
| `height` | integer | Index of the tip block (0 = only genesis) |
| `difficulty` | integer | Vestigial PoW field, always 0 in uptime-emission model |
| `balance` | string | This node's credit balance, base units (decimal string) |
| `circulating_supply` | string | Total emitted minus total burned, base units (decimal string) |
| `burned_total` | string | Credits destroyed by the settlement burn (see below), base units (decimal string) |
| `bond` | string | This node's active host bond, base units (decimal string) |
| `weight` | string | This node's consensus weight = `min(bond, earned-work-score)`, base units (decimal string) |
| `free` | string | Spendable balance = `balance` minus all locks (bids + channels + bond), clamped at 0, base units (decimal string) |
| `locked_channels` | string | Credits locked in this node's open payment channels, base units (decimal string) |
| `locked_bond` | string | Credits locked in this node's active bond (equals `bond`), base units (decimal string) |

**Balance breakdown.** `free + locked_channels + locked_bond + (locked in open bids) == balance` once `balance` is non-negative. `free` is clamped at 0 so a transiently-negative balance during chain sync never shows a confusing negative spendable figure.

**Settlement burn.** Every `JobSettle`, `Heartbeat`, and `ChannelClose` debits the payer/cell the
full amount, credits the host `amount − burn`, and destroys the burn (`SETTLEMENT_BURN_BPS`, currently
1.00%). This is the trust-economy Sybil defence: wash-trading reputation between identities you
control costs real, unrecoverable capital per cycle. See `docs/consensus.md` and
`docs/sybil-resistance.md`.

---

## Job lifecycle overview

Jobs follow a two-step flow:

1. **Payer** calls `POST /jobs/bid` on their own node — signs and broadcasts a `JobBid` tx. The `bid` credits are locked immediately; the payer cannot double-spend them while the job is open.
2. **Any host** with capacity picks up the bid from the gossip mesh, starts the container, and marks the job `running`.
3. When the container exits the host marks the job `awaiting_settlement`.
4. **Payer** calls `POST /jobs/:id/settle` on the **host** node with their co-signature and the agreed cost (must not exceed the original `bid`).
5. Host submits the signed `JobSettle` tx; the next mined block confirms it and adjusts balances.

If no host settles within `EXPIRY_BLOCKS` (1440 blocks ≈ 24 hours at 10s/block), the payer may submit a `JobExpire` tx to reclaim the locked credits.

---

## POST /jobs/bid

Create a job bid. The **calling node** is the payer; their free balance (total minus locked bids) is checked before broadcasting. The bid amount is locked until `JobSettle` or `JobExpire` confirms.

**Request body**
```json
{
  "image": "alpine:latest",
  "cmd": ["sh", "-c", "echo hello"],
  "env": [["KEY", "value"]],
  "cpu_cores": 1,
  "mem_mb": 128,
  "duration_secs": 60,
  "bid": 500
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `image` | string | yes | Docker image to pull and run |
| `cmd` | array | no | Command override (default: image entrypoint) |
| `env` | array | no | `[[key, value], …]` environment pairs |
| `cpu_cores` | integer | yes | CPU allocation hint for resource limits |
| `mem_mb` | integer | yes | Memory limit in MiB |
| `duration_secs` | integer | yes | Maximum expected runtime |
| `bid` | integer | yes | Maximum credits the payer is willing to spend (locked at bid time) |

**Response** `201 Created`
```json
{ "job_id": "a3f2...64 hex chars" }
```

`job_id` is a 64-hex-char identifier; use it with all `/jobs/:id` routes.

**Error responses**

| Code | Meaning |
|---|---|
| 402 Payment Required | Payer's on-chain balance is ≤ 0 |

---

## GET /jobs/:id

Return the current CE-level status of a job tracked by this node.

`:id` is the 64-hex-char `job_id` returned by `POST /jobs/bid`.

**Response** `200 OK`
```json
{
  "job_id": "a3f2...",
  "status": "running",
  "container_id": "abc123def456...",
  "cost": null
}
```

| `status` | Meaning |
|---|---|
| `pending` | Bid broadcast; no host has accepted it yet |
| `running` | Container is running on this node |
| `awaiting_settlement` | Container exited; waiting for payer co-signature |
| `settled` | `JobSettle` tx submitted and broadcast |
| `failed: <reason>` | Container launch failed |

**Error:** `404 Not Found` if this node has no record of the job.

---

## POST /jobs/:id/settle

Payer co-signs the settlement. Call this on the **host** node once the job reaches
`awaiting_settlement` status. The host uses the provided signature to build and broadcast
a `JobSettle` tx.

`:id` is the 64-hex-char `job_id`.

**Request body**
```json
{
  "cost": 250,
  "payer_sig": "128 hex chars"
}
```

| Field | Type | Description |
|---|---|---|
| `cost` | integer | Agreed settlement amount in credits (must be ≤ original `bid`) |
| `payer_sig` | string | Ed25519 signature (128 hex chars) of `payer_settle_bytes(job_id, host_node_id, cost)` (v2) using the payer's identity key — the host node ID is bound into the signature to prevent settlement hijacking |

The server verifies the payer signature before storing it.

**Response** `202 Accepted` — the host will submit the `JobSettle` tx on the next poll cycle.

**Error responses**

| Code | Meaning |
|---|---|
| 400 Bad Request | Invalid `job_id` format, invalid `payer_sig` format, or signature verification failed |
| 404 Not Found | No record of this job on this node |

---

## DELETE /jobs/:id

Force-stop and remove a container. `:id` may be either a CE `job_id` (64 hex chars)
or a raw Docker container ID.

**Response** `204 No Content`

**Error:** `404 Not Found` if container doesn't exist.

---

## GET /jobs

List all jobs tracked by this node (both as payer and as host).

**Response** `200 OK`
```json
[
  {
    "job_id": "a3f2...",
    "status": "running",
    "payer": "8f3a...",
    "container_id": "abc123...",
    "cost": null,
    "bid": 1000
  }
]
```

---

## POST /transfer

Transfer credits from this node to another node. Builds a `Transfer` tx, adds it to the pool, and broadcasts it on the mesh.

**Request body**
```json
{ "to": "<64 hex chars>", "amount": 500 }
```

**Response** `201 Created`
```json
{ "tx_id": "<64 hex chars>" }
```

**Error responses**

| Code | Meaning |
|---|---|
| 400 Bad Request | Invalid `to` format or `amount == 0` |
| 402 Payment Required | Sender balance is insufficient |

---

## GET /atlas

Return the capacity atlas: the latest capacity snapshot received from each peer via CEP-1 capacity signals.

Nodes broadcast capacity every 60 seconds with capabilities `{name: "cpu", version: N}`, `{name: "mem_mb", version: N}`, `{name: "jobs", version: N}`, plus one `{name: "tag:<t>", version: 1}` entry per capability-derived self-tag. Self-tags are objective, node-reported labels describing what work the node can realistically perform — currently `linux`/`macos`/`windows`, `x86_64`/`aarch64`, and conditionally `docker`, `gpu`, `manycore` (≥16 cores), `highmem` (≥32 GB). They are distinct from owner tags in `machines.toml`. Receivers strip the `tag:` prefix and expose the set as `tags`.

**Response** `200 OK`
```json
[
  {
    "node_id": "a3f2...",
    "cpu_cores": 8,
    "mem_mb": 16384,
    "running_jobs": 3,
    "last_seen_secs": 1716470400,
    "tags": ["linux", "x86_64", "docker", "gpu"]
  }
]
```

Self-tags are advertised only while a node is mining (the capacity-broadcast loop runs under the mining gate). The `ce fleet ls` command joins these with owner tags from the local `machines.toml`.

---

## GET /history/:node_id

A node's on-chain interaction history — the **reputation substrate**. CE reports the immutable
facts; apps derive their own per-relationship trust (there is no global reputation score). Built
incrementally as blocks apply. Amounts are base-unit strings.

**Response** `200 OK`
```json
{
  "node_id": "a3f2...",
  "jobs_hosted": 12,        // jobs settled as host (work delivered + paid)
  "jobs_paid": 3,           // jobs paid for as payer
  "heartbeats_hosted": 40,  // heartbeats received hosting long-running cells
  "heartbeats_paid": 5,
  "expiries": 0,            // bids this node let expire as payer without settling
  "earned": "7200000000000000000000",
  "spent": "900000000000000000000",
  "first_height": 41,
  "last_height": 1180,
  "window_blocks": 259200,
  "recent_earned": "1200000000000000000000",
  "recent_spent": "300000000000000000000",
  "window_partial": false
}
```
A node with no interactions returns all-zero fields (`first_height: 0`). Bad node id → `400`.
Pruned light nodes hold only post-checkpoint history; query an **archive node** for the complete
record.

**Windowed slice (`window_*` / `recent_*`).** These expose a true time-windowed slice of the node's
hosting income (`recent_earned`, post-burn) and consumption (`recent_spent`, gross) over the last
`window_blocks` blocks (~30 days at 10 s/block). The cumulative `earned`/`spent` are all-time; the
recent fields are what a torrent-style **share ratio** uses to weight recent over years-old
contribution, so it computes a real windowed ratio rather than a recency proxy off `last_height`.
This is an observational read-model walked from the blocks the node holds (like `burned_total`),
**not** consensus and never part of any signed/hashed bytes. `window_partial` is `true` when the held
blocks do not cover the whole window (a pruned/short chain undercounts) — query an archive node for
the full slice.

---

## GET /transactions/:node_id

A node's confirmed transactions as an **itemized, paginated list**, newest first. Complements the
aggregate `GET /history/:node_id` (NodeStats) with the per-tx records a wallet/history view needs.

**Privacy.** This returns only **public, on-chain** facts — every settlement and transfer leg is
already world-readable to anyone holding the chain. It exposes nothing the ledger does not, for any
node (not just self), and is not a private account statement. Pruned light nodes return only
post-checkpoint transactions; query an **archive node** for the complete record.

**Query parameters**

| Param | Type | Description |
|---|---|---|
| `limit` | integer | Max items (default `100`, capped at `500`) |
| `before` | integer | Exclude transactions at block height `>= before` — the cursor for the next (older) page |

**Response** `200 OK` — a JSON array, newest first:
```json
[
  {
    "tx_id": "9f0e...64 hex",
    "height": 1180,
    "kind": "JobSettle",
    "amount": "500000000000000000000",
    "counterparty": "b1c2...64 hex",
    "direction": "in"
  }
]
```

| Field | Type | Description |
|---|---|---|
| `tx_id` | string | Content-addressed transaction id (64 hex) |
| `height` | integer | Block height the tx was confirmed at |
| `kind` | string | `Transfer`\|`UptimeReward`\|`JobBid`\|`JobSettle`\|`JobExpire`\|`Heartbeat`\|`ChannelOpen`\|`ChannelClose`\|`ChannelExpire`\|`NameClaim`\|`RevokeCapability`\|`HostBond`\|`HostUnbond`\|`SlashEquivocation` |
| `amount` | string | Value moved by the tx, base units (decimal string); `"0"` for amount-less kinds |
| `counterparty` | string? | The other party relative to the queried node (64 hex), when there is one |
| `direction` | string | `"in"` (value to this node), `"out"` (value from this node), or `"self"` |

**Pagination.** To page backwards, pass the lowest `height` you received as the next `before`. Bad
node id → `400`.

---

## GET /beacon

Verifiable public randomness from the PoW chain tip — unpredictable (it took work to find) and
globally agreed. Seed reproducible, auditable host selection from `hash` so nobody can be shown
to have cherry-picked who ran the work.

**Response** `200 OK`
```json
{ "height": 1180, "hash": "9f0e..." }
```

The tip can reorg; for high-stakes selection derive from a confirmed-depth block, not the volatile
tip. (Note: a beacon-seeded selection is *verifiable* but *predictable*; for anti-collusion in
redundancy checks, unpredictable selection at dispatch time is preferable — pick the property the
use case needs.)

---

## Payment channels

Off-chain micropayment channels (see `docs/payment-channels.md`). Only open/close touch the
chain; millions of micropayments flow as off-chain receipts. Amounts are base-unit strings.

- **`POST /channels/open`** — body `{ host, capacity, expiry_height? }`. Locks `capacity` of the
  caller's (payer's) free balance. Returns `{ channel_id }`. `402` if free balance < capacity.
- **`POST /channels/receipt`** — body `{ channel_id, host, cumulative }`. The payer signs an
  off-chain receipt; returns `{ channel_id, cumulative, payer_sig }`. No tx — hand the receipt to
  the host out of band.
- **`POST /channels/:id/close`** — body `{ cumulative, payer_sig }`. Called on the **host**;
  submits a `ChannelClose` redeeming the receipt (`cumulative` → host, remainder unlocked to payer).
- **`POST /channels/:id/expire`** — called on the **payer**; reclaims the channel after `expiry_height`.
- **`GET /channels`** — list open channels: `[{ channel_id, payer, host, capacity, expiry_height }]`.

---

## GET /signals

Returns the last 100 validated CEP-1 signals seen by this node (newest at the end).

**Response** `200 OK`
```json
[
  {
    "from": "a3f2...",
    "to": "broadcast",
    "capabilities": [{"name": "compute", "version": 1}],
    "payload_hex": "deadbeef",
    "burn_proof": {
      "tx_id": "<64 hex>",
      "amount": 1000,
      "block_height": 7,
      "block_hash": "<64 hex>"
    },
    "nonce": 0,
    "id": "<64 hex content-addressed id>"
  }
]
```

---

## GET /signals/stream

Server-Sent Events stream. Pushes every validated CEP-1 signal to the client the instant it arrives — no polling required. Each event is a JSON object with the same shape as the items returned by `GET /signals`.

Connect and keep the connection open:
```bash
curl -N http://localhost:8844/signals/stream
```

The server sends a keep-alive comment every 15 seconds on idle connections. Disconnect when done.

**Response** `text/event-stream`
```
data: {"from":"a3f2...","to":"broadcast","capabilities":[...],"payload_hex":"deadbeef","nonce":1,"id":"..."}

data: {"from":"b9c1...","to":"broadcast","capabilities":[...],"payload_hex":"","nonce":2,"id":"..."}
```

---

## GET /blocks/stream

Server-Sent Events stream. Pushes every block accepted by this node (whether locally mined or received from a peer) the instant it is appended to the chain.

```bash
curl -N http://localhost:8844/blocks/stream
```

**Response** `text/event-stream`
```
data: {"index":42,"hash":"a1b2...","prev_hash":"9f0e...","timestamp":1716634800,"miner":"a3f2...","tx_count":3,"nonce":12345}
```

| Field | Type | Description |
|---|---|---|
| `index` | integer | Block height |
| `hash` | string | 64-hex block hash |
| `prev_hash` | string | 64-hex hash of the previous block |
| `timestamp` | integer | Unix seconds when the block was sealed |
| `miner` | string | 64-hex NodeId of the block producer |
| `tx_count` | integer | Number of transactions in the block |
| `nonce` | integer | PoW nonce |

---

## GET /transactions/stream

Server-Sent Events stream. Pushes every transaction accepted from the mesh the instant it passes signature verification.

```bash
curl -N http://localhost:8844/transactions/stream
```

**Response** `text/event-stream`
```
data: {"id":"c3d4...","origin":"a3f2...","kind":"Transfer","amount":500}
```

| Field | Type | Description |
|---|---|---|
| `id` | string | 64-hex transaction ID (SHA256 of the serialised tx) |
| `origin` | string | 64-hex NodeId of the signer |
| `kind` | string | `Transfer` \| `UptimeReward` \| `JobBid` \| `JobSettle` \| `JobExpire` \| `TrustGrant` \| `Heartbeat` |
| `amount` | integer | Credit amount (0 for kinds without one) |

---

## POST /signals/send

Build a CEP-1 signal locally, sign it, and broadcast it on the `ce-protocol-1` gossip topic.

**Request body**
```json
{
  "payload_hex": "deadbeef",
  "to": "broadcast",
  "capabilities": [{"name": "compute", "version": 1}],
  "burn_tx_id_hex": "<64 hex>"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `payload_hex` | string | no | Hex-encoded payload. Empty allowed for capability-only signals. |
| `to` | string | yes | `"broadcast"` or a 64-hex-char destination NodeId. |
| `capabilities` | array | no | Capability declarations to attach. |
| `burn_tx_id_hex` | string | conditional | 64-hex-char id of an on-chain tx. Required when `payload_hex` is non-empty. |

**Response** `202 Accepted`
```json
{ "id": "<64 hex content-addressed id>", "nonce": 0 }
```

---

## Node services moved to apps

Remote **exec** and **file sync/delete** are no longer node endpoints — they're the `rdev` app,
built on the mesh `AppRequest` primitive + the `ce-cap` verifier (see github.com/ce-net/rdev and
`docs/primitives.md`). The former `/sync`, `/exec`, `/mesh-exec`, and `/mesh-sync` endpoints are
**removed**. CE keeps the **capability** primitive (issue via `ce grant`, revoke via
`POST /capabilities/revoke`; verify via `ce-cap`), the **tunnel** transport (`POST /tunnel`), and
the compute-market endpoints below.

---

## Mesh-routed placement

These let the **local** node place/stop work on a **specific remote host over the mesh**
(libp2p `/ce/rpc/1`, relay-assisted NAT traversal) — directed placement, the primitive a
scheduler uses. The local node proxies; the target enforces authorization (admin trust, or a
forwarded `grant` token covering `Deploy`/`Kill`). Amounts are decimal strings of base units.

### POST /mesh-deploy

Deploy a long-running cell on a specific host. The host tracks it (so it is heartbeat-billed
and killable) and returns a `job_id`.

**Request body**
```json
{
  "node_id": "<64 hex>",          // target host
  "image": "alpine:latest",
  "cmd": ["sleep", "30"],
  "cpu_cores": 1,
  "mem_mb": 128,
  "duration_secs": 60,
  "bid": "1000000000000000000",   // funding, base units (string)
  "hint_multiaddr": "",            // optional relay circuit dial hint
  "grant": null                    // optional scoped grant token
}
```
**Response** `200 OK` → `{ "job_id": "<64 hex>" }`. Errors: `400` bad node_id / malformed grant,
`502` host rejected (untrusted / Docker error), `504` mesh timeout.

### POST /mesh-kill

Stop a mesh-deployed job. Body: `{ "node_id": "<64 hex>", "job_id": "<64 hex>", "grant": null }`.
**Response** `204 No Content`. Errors mirror `/mesh-deploy`.

(Remote exec / file sync are the `rdev` app over `AppRequest`, not node endpoints.)

---

## Container isolation

All containers (job containers and exec containers) are launched with:

- **Runtime**: `runsc` (gVisor) when available; falls back to runc with a logged warning.
- **Network**: `none` — no direct internet access; all traffic must route through CE.
- **CPU**: cgroup v2 hard limit via `nano_cpus`. Job containers use the bid's `cpu_cores`; exec containers use 1 CPU.
- **Memory**: cgroup v2 hard limit. Job containers use `mem_mb` from the bid; exec containers use 512 MB.
- **Exec-only**: home directory bind-mounted at `/workspace:rw` so the command can read synced files. Job containers have no bind mounts.
