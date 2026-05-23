# CE HTTP API

Base URL: `http://localhost:8080` (configurable via `--api-port`)

All request and response bodies are JSON. All responses include a `Content-Type: application/json` header.

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
  "balance": 987000
}
```

| Field | Type | Description |
|---|---|---|
| `node_id` | string | 64-hex-char Ed25519 public key (= this node's identity) |
| `height` | integer | Index of the tip block (0 = only genesis) |
| `difficulty` | integer | Vestigial PoW field, always 0 in uptime-emission model |
| `balance` | integer | This node's credit balance |

---

## Job lifecycle overview

Jobs follow a two-step flow:

1. **Payer** calls `POST /jobs/bid` on their own node — signs and broadcasts a `JobBid` tx.
2. **Any host** with capacity picks up the bid from the gossip mesh, starts the container, and marks the job `running`.
3. When the container exits the host marks the job `awaiting_settlement`.
4. **Payer** calls `POST /jobs/:id/settle` on the **host** node with their co-signature and the agreed cost.
5. Host submits the signed `JobSettle` tx; the next mined block confirms it and adjusts balances.

---

## POST /jobs/bid

Create a job bid. The **calling node** is the payer; their balance is checked before broadcasting.
The bid is signed by this node's identity and gossiped to the mesh so any host can accept it.

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
| `bid` | integer | yes | Maximum credits the payer is willing to spend |

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
| `cost` | integer | Agreed settlement amount in credits (≤ original bid) |
| `payer_sig` | string | Ed25519 signature (128 hex chars) of `payer_settle_bytes(job_id, cost)` using the payer's identity key |

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

## Container isolation

Containers are launched with:

- **Runtime**: `runsc` (gVisor) when available; falls back to default runc with a logged warning.
- **CPU**: cgroup v2 limit via `nano_cpus` (1 CPU core = 1,000,000,000 nanocpus).
- **Memory**: hard cgroup v2 limit from `mem_mb`.
- **Network**: `none` — containers have no direct internet access; all traffic must route through CE.

---

## Credit metering

Once a container is running the metering loop (every 10 seconds) reads Docker stats and
can generate `Meter` transactions. Settlement cost is determined by the agreed `cost` field
in `POST /jobs/:id/settle`.

```
cost = (cpu_ms / 1000) * 10   +   (mem_mb * interval_secs / 1024) * 1
       └── 10 credits/cpu-sec     └── 1 credit/GB-second
```
