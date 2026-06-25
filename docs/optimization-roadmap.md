# CE optimization roadmap

Performance work, prioritized. Grounded in the measured benchmark findings in
[`ce-bench/docs/network-benchmark-findings.md`](../../ce-bench/docs/network-benchmark-findings.md)
and [`ce-bench/docs/app-benchmark-findings.md`](../../ce-bench/docs/app-benchmark-findings.md).

## Done (2026-06-25)

- **F4** — `put_blob` fire-and-forget DHT announce (was the ~1s write floor; 1 MiB PUT now ~10 ms).
- **F2** — blob read/write in `spawn_blocking` (off the async runtime; kills the p99 tails).
- **Placement (data)** — `fetch_chunk_from_mesh` ranks providers by `/netgraph` RTT and races the
  nearest few in parallel (first CID-valid wins) instead of a random sequential scan.
- **F7** — self-request short-circuit (node PR #3).
- App-layer (in the app repos): D1 push-stream serve loop, D3 parallel object chunks, D5 cached open
  snapshot.

## Remaining — NOT yet implemented

### P1 — transport core (the latency/throughput ceiling)
1. **F1 — single-`Swarm` RPC serialization.** Every RPC funnels through the one libp2p `Swarm` event
   loop (`Mesh` is `!Sync`), so wire I/O serializes — that's the ~25-50 req/s ceiling and the
   per-op ~17 ms floor even at zero network distance. Directions: a dedicated RPC connection pool /
   multiple connections per peer; reduce the hop chain (HTTP handler → `cmd_tx` mpsc → swarm →
   `event_tx` mpsc → node loop → oneshot) to fewer awaits; consider splitting bulk vs control planes.
2. **QUIC-first RPC.** Prefer QUIC for the `/ce/rpc/1` substreams to avoid TCP head-of-line blocking,
   and verify/raise the concurrent-substream limits so parallel requests actually parallelize.
3. **F3 — bulk transfer off AppRequest.** Large directed-RPC payloads run ~0.5-1 MB/s. Route bulk
   bytes over dedicated libp2p streams (the `FetchChunk`/data path), chunked + parallel, rather than
   the request/reply AppRequest channel.

### P1 — data path
4. **Node `/blobs` body limit + streaming.** The `/blobs` route has a small default axum body limit
   (~2 MB); raw single-blob PUTs above it are rejected (the apparent "8 MiB RST"). Raise
   `DefaultBodyLimit` on the blob routes and stream the PUT body to disk instead of buffering it
   whole. (Apps chunk to 1 MiB so they're unaffected today; this is for raw large-blob users.)
5. **Blob GET ranges/streaming.** Serve `Range` requests and stream large blobs from disk without
   materializing the whole body in memory.
6. **Durability on write.** Pin written/fetched chunks at a replication factor (ce-pin) so bytes
   survive the uploader, instead of relying on a single provider record.

### P2 — placement & resilience
7. **Compute placement.** Atlas + `/netgraph` RTT-guided host selection in `deploy` / `ce-sched`:
   prefer low-latency, same-region, capacity-fit hosts; vendor-aware. (Data placement is done; this is
   the job-placement side.)
8. **F6 — relay/bootstrap keepalive + auto-redial.** Long-lived nodes silently lose the relay link
   (observed: laptop↔relay last-seen 7.4 h, directed traffic then "fails to dial"). Add keepalive +
   automatic redial of bootstrap/relay peers.

### P2 — app layer (tracked in the app repos, listed here for completeness)
9. **ce-drive Mirror incremental-apply (M3).** `Mirror::sync` re-bootstraps the whole tree on any
   change; apply feed deltas incrementally instead of a full snapshot refetch.
10. **Snapshot debounce.** If snapshot republish ever moves onto the write path, debounce it rather
    than per-op.

## How to validate

Use the `ce-bench` harnesses: `ce-netbench` (primitives over the real mesh), `bench-s3.js`
(ce-storage), `ce-drive-client/examples/bench_drive` (ce-drive two-node mesh). Always validate blob
perf on a **real-DHT** node — the ephemeral 2-node bench understates data-path wins (the `provide`
churns the single Swarm with no real DHT).
