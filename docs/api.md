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
| `node_id` | string | 64-hex-char Ed25519 public key (= this node's identity in the network) |
| `height` | integer | Index of the tip block (0 = only genesis) |
| `difficulty` | integer | Current PoW difficulty (leading zero bits) |
| `balance` | integer | This node's credit balance (can be negative during initial mining) |

---

## POST /jobs/run

Start a container job. The payer must have a positive credit balance.

**Request body**
```json
{
  "image": "nginx:latest",
  "payer": "a3f2...64 hex chars",
  "env": {
    "KEY": "value"
  },
  "cmd": ["sleep", "60"]
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `image` | string | yes | Docker image to pull and run |
| `payer` | string | yes | 64-hex-char NodeId; their balance is checked before launch |
| `env` | object | no | Environment variables as key/value pairs |
| `cmd` | array | no | Command override (default: image entrypoint) |

The container is started with two labels automatically:
- `ce.payer=<payer hex>` — used by the metering loop to debit the payer
- `ce.host=<host hex>` — this node's ID, for credit routing

**Response** `201 Created`
```json
{
  "job_id": "abc123def456..."
}
```

`job_id` equals the Docker container ID and is used with all `/jobs/:id` routes.

**Error responses**

| Code | Meaning |
|---|---|
| 400 Bad Request | `payer` is not a valid 64-hex-char NodeId |
| 402 Payment Required | Payer's on-chain balance is ≤ 0 |
| 500 Internal Server Error | Docker create or start failed |

---

## GET /jobs/:id

Inspect a running or stopped job.

**Response** `200 OK`
```json
{
  "container_id": "abc123...",
  "status": "Running",
  "image": "sha256:..."
}
```

**Error:** `404 Not Found` if container doesn't exist.

---

## DELETE /jobs/:id

Force-stop and remove a container.

**Response** `204 No Content`

**Error:** `404 Not Found` if container doesn't exist.

---

## Credit metering

Once a container is running with a `ce.payer` label, the metering loop (running every 10 seconds) generates a `Meter` transaction:

```
cost = (cpu_ms / 1000) * 10   +   (mem_mb * 10 / 1024) * 1
       └── 10 credits/cpu-sec     └── 1 credit/GB-second
```

The Meter transaction is signed by the host node and broadcast to the mesh. When included in a mined block, it debits the payer and credits the host.
