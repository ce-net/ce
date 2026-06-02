# Data layer — design

**Status: Stages 1–4 done.** Content-addressed, chunked, P2P, paid object distribution — so jobs
can get their inputs (datasets, model weights, code) and return their outputs at scale, instead of
today's one-file `sync`. The frontier's reach for compute has a twin: data has to move too.

Stage 1 ✅ (in `ce-rs`): the `data` module — `Manifest` (`ce-object-v1`: chunk CIDs + sizes),
pure `chunk_object`/`reassemble`/`cid` (sha256, matches the node's `/blobs` keying), and
`CeClient::put_object`/`get_object` layering the existing blob store into whole-object upload/fetch
with per-chunk verification.

Stage 2 ✅ (in `ce-mesh` + `ce-node`): a node now pulls chunks it lacks **from the mesh**.
`RpcRequest::FetchChunk { cid }` → `RpcResponse::ChunkData` over `/ce/rpc/1` (open/unpaid, like
`SegmentFetch`); DHT **provider records** via Kademlia (`provide_chunk` on store + a startup
re-announce of all held chunks; `find_providers` completes on the first provider found, not the
query's final step); `GET /blobs/:hash` falls back to discover → fetch → **verify against the
hash** → cache + re-announce (so popular data self-replicates). Integration-tested across two
in-process nodes (`blob_fetched_across_mesh`).

Stage 3 ✅ (in `ce-chain` + `ce-mesh` + `ce-node` + `ce-rs`): **paid serving** over the existing
payment-channel primitive. `ce-chain::ChunkReceipt` (the payer's signature over the *same*
`channel_receipt_bytes` the chain validates at close) + `verify_chunk_receipt_sig`; `FetchChunk`
gains an opaque `receipt`; a node config `data_price_per_byte` (0 = free, the default). The
provider enforces payment in the `FetchChunk` handler via the pure, unit-tested
`authorize_chunk_serve` — channel must exist with this node as host, receipt cumulative must cover
`served + chunk cost` and stay within capacity, and the payer signature must verify — tracking an
in-memory per-channel high-water mark (so it's paid as it serves; the host still closes with the
highest receipt). The payer fetches via `POST /data/fetch` (signs the receipt, pulls, verifies
against the cid) / `ce-rs` `fetch_chunk_paid`. Tested: receipt accept/reject + the full
authorization decision with real signatures (unit), and a charging provider refusing a free fetch
over the real mesh (`paid_provider_refuses_free_fetch`).

Stage 4 ✅ (in `ce-runtime` + `ce-node` + `ce-rs`): **content-addressed job inputs**. `Workload`
(Docker and Wasm) gains `inputs: Vec<[u8;32]>`, and `Workload::content_deps()` lists every
content-addressed dependency (a Wasm workload's `module_hash` + all inputs). On `Deploy`, the host
**stages** each dep via `stage_blob` — fetching it from the data layer if absent — *before*
launch, so a workload runs on a host that didn't previously hold its bytes (this closes the
runtime's "host resolves the module from the data layer" loop). `mesh-deploy` / `ce-rs`
`mesh_deploy_wasm` take `inputs`. Tested: `wasm_deploy_stages_module_from_mesh` — a host with no
local copy of a WASM module stages it from a mesh provider and runs it (the deploy fails without
staging).

In-cell input *consumption* (WASI preopened dirs for Wasm, volume mounts for Docker) and **output
publishing** (capture the cell's artifact → publish to the data layer → return the output CID) are
the next refinement — they need runtime I/O (WASI/mounts) that the v0 runtimes don't yet expose.
Staging (the "host fetches inputs" half) is the distributed keystone and is done.

Decisions locked: Kademlia provider records, fixed 1 MiB chunks, per-chunk channel receipts,
scope = transfer + addressing + caching + paid serving (storage-with-proofs is the separate
market). Refinements still open: in-cell I/O + output publishing (above); mesh-advertised pricing
+ auto provider selection (the capacity signal's `u32` version field can't carry a `u128` price —
price is an out-of-band/config knob for now); paid staging (the host pays to fetch inputs, cost
folded into the job — staging uses free providers in v0); parallel multi-provider fetch (swarming);
and periodic provider-record refresh.

The good news: this is **mostly assembly of primitives CE already has**, not a new system.

## What it must do

1. **Deliver inputs** to a cell (a dataset / weights / code, possibly GBs).
2. **Return outputs** — a job produces data the client retrieves.
3. **Distribute popular data efficiently** — if 1000 hosts need the same model, don't pull it
   1000× from one source; swarm it peer-to-peer (BitTorrent-shaped).
4. **Verify everything** — content-addressing makes transfer trustless: every chunk is checked
   against its hash, so a malicious provider can't feed you wrong bytes (you detect and refetch).
5. **Be paid** — moving/serving data costs credits; bandwidth providers earn.

This is **transfer + availability + content-addressing**. Durable *storage with proofs*
(proof-of-storage, replication incentives, guaranteed persistence) is the separate
"storage market" frontier item — it builds *on* this layer; it is out of scope here.

## Object model

- **Chunk** — a content-addressed unit, `cid = sha256(bytes)`, default 1 MiB. The `/blobs`
  store already *is* a chunk store (sha256-keyed, tamper-evident); this generalizes it.
- **Object** — a logical file/dataset. Small objects are one chunk. Large objects are split into
  chunks plus a **manifest** (itself a chunk) listing `{ chunk_cids[], chunk_size, total_size }`.
  The object's CID is the manifest's hash, which anchors every chunk hash — a 1-level Merkle DAG.
  This gives **verifiable partial fetches** and **dedup** (identical chunks share a CID).
- Fetching: resolve manifest by CID → fetch chunks (in parallel, from many providers) → verify
  each against its CID → reassemble. A bad/failed chunk just refetches from another provider.

## How it reuses what exists

| Need | Reuse |
|---|---|
| Chunk storage | The `/blobs` content-addressed store (generalize: chunked + manifests) |
| **Who has chunk X?** (content routing) | **libp2p Kademlia** — providers announce provider records keyed by CID; fetchers query the DHT. CE already runs Kademlia for peer discovery. |
| Fetch a chunk from a peer | A new `FetchChunk { cid }` mesh RPC, mirroring the existing `SegmentFetch` RPC (chain-archive) — verified on receipt. Parallel across providers = swarming. |
| **Paid** serving | **Payment channels** — open a channel with a provider, stream a receipt per chunk/MB served. Pay-as-you-go bounds loss (stop paying if chunks stop verifying). |
| Provider selection / pricing | The **atlas + trust gradient** — providers advertise they serve data (+ a price/MB); requesters prefer cheap, trusted/staked providers, exactly like `swarm` host placement. |
| Trustless transfer | Content-addressing: verify every chunk's hash. Like WASM determinism, verification is *free* — you can pull from untrusted strangers and only pay for chunks that check out. |

## Job integration (the point)

`Workload` gains content-addressed I/O (additive):
- `inputs: Vec<Cid>` — the host fetches these from the data layer (paying as needed) and makes
  them available to the cell.
- The job publishes its output to the data layer and the host returns the **output CID** to the
  client (instead of, or alongside, stdout).

So a job becomes **inputs (CIDs) → compute → output (CID)** — data decoupled from placement, and
the scheduler (`swarm`) stages data to chosen hosts before dispatch.

## CE vs app

- **CE primitives (node-enforced/generic):** chunk store, manifests, DHT provider records,
  `FetchChunk` RPC, chunk verification, and the payment hook (channel receipts per chunk).
- **App/policy:** what to pin/cache/GC, pricing strategy, replication policy, staging data for a
  job, and the durable-storage market with proofs. No global index authority — routing is the DHT.

## Staged plan

- **Stage 1 ✅ — chunked objects + manifests (local).** Generalize `/blobs` into a chunk store; add
  chunking + a manifest format; `put_object`/`get_object` in `ce-rs` (chunk, store, manifest /
  resolve, fetch-local, verify, reassemble). No network yet. Fully unit-testable.
- **Stage 2 ✅ — content routing + `FetchChunk` RPC.** Announce provider records to Kademlia for
  held chunks; `FetchChunk { cid }` mesh RPC (verified); fetched chunks are cached and re-announced
  (popular data self-replicates). A node now pulls an object it doesn't have from the mesh.
  (Parallel multi-provider fetch / swarming is a refinement on top.)
- **Stage 3 ✅ — paid serving.** Per-chunk channel receipts (provider earns); a `data_price_per_byte`
  knob (0 = free); the provider verifies a receipt covering the running cost before serving.
  Free-riding bounded by small chunks + pay-as-you-go + the receipt's high-water mark. (Mesh-
  advertised pricing + cheap/trusted auto-selection is a refinement; price is config/out-of-band.)
- **Stage 4 ✅ — job integration.** `Workload` gains content-addressed `inputs`; the host stages
  every dependency (Wasm module + inputs) from the data layer before launch. In-cell consumption
  (WASI/mounts) + output publishing (return an output CID) are the next refinement.
- *(Separate, later: durable storage market — proof-of-storage, replication incentives.)*

## Hard problems (named honestly)

- **DHT at scale.** Provider records for millions of objects across millions of peers is IPFS-scale
  territory: record churn, lookup latency, hot keys. Mitigate with provider-record TTLs, caching
  popular records, and topology-aware provider preference. Real research surface.
- **Fair exchange.** Atomic "chunk for payment" is genuinely hard (someone goes first). We don't
  solve it; we *bound* it — small chunks + pay-as-you-go channel receipts + reputation mean a
  cheat costs one chunk and burns the relationship. The trust gradient again.
- **Bandwidth & locality.** Moving GBs over the public internet is slow/costly; prefer nearby
  providers (topology hints). This is a throughput layer, not low-latency — same caveat as compute.
- **Privacy.** Content-addressed data is readable by anyone with the CID + a provider. Private data
  must be **encrypted before storing** (keys shared out of band); the layer moves ciphertext.
- **Availability / GC.** Cached chunks need pinning + incentives to persist → that's the storage
  market (separate). Until then, availability follows demand (popular = replicated; cold = may
  vanish).

## Decisions to lock before building

- **Content routing:** libp2p **Kademlia provider records** (reuse, decentralized, scalable) — vs.
  a tracker/rendezvous scheme. Recommend the DHT.
- **Chunking:** **fixed 1 MiB** for v0 (simple, good-enough dedup) — vs. content-defined chunking
  (rolling hash, better dedup) later.
- **Payment granularity:** **per-chunk receipts over a payment channel** — vs. per-object upfront.
  Recommend per-chunk (bounds free-riding, rides the channel primitive).
- **Scope:** this layer is **transfer + content-addressing + caching + paid serving**; durable
  storage with proofs is a separate later layer. Confirm.
