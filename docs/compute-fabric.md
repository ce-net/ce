# The Compute Fabric

Status: design + phased build. Owner-facing roadmap for turning CE from a job market into a
measured, latency-aware distributed supercomputer — the substrate scientific and AI workloads
(distributed LLMs, protein folding, satellite and exoplanet analysis, genomics) build on.

This document is the canonical design. It defines **the foundational system**: a per-node resource
profile and a node-to-node network graph that every higher layer — scheduling, collective
communication, distributed inference — queries instead of guessing.

---

## 1. The principle: measure everything, keep the node thin

A scheduler can only place work well if it knows two things for the whole network:

1. **What each node can do** — CPU, GPU, memory, storage, and real throughput (the *vertices*).
2. **How far apart nodes are** — latency and bandwidth between them (the *edges*).

CE measures both, signs the measurements, and exposes them as one queryable map (the **Fabric
Map**). Today neither exists: the atlas carries only self-reported `cpu/mem/tags`, and there is no
latency measurement at all (libp2p's `ping` behaviour is not even enabled).

**Primitives-vs-apps boundary (non-negotiable).** The *node* measures **only its own network links**
— and only because latency is transport-intrinsic (libp2p `ping`); it is read-substrate like
`/atlas`, `/beacon`, and `/history`, not policy. **The node never benchmarks compute.** All
compute/GPU/storage benchmarking, graph assembly, placement, collectives, and LLM orchestration are
**apps and SDK crates** that run *on* CE. The node stays minimal; the fabric evolves without node
releases.

| Concern | Lives in | Why |
|---|---|---|
| Per-link RTT (and later bandwidth) | node (`ce-mesh`/`ce-node`) | only the transport can observe its own connections |
| Vivaldi coordinate, graph assembly | `ce-graph` SDK | pure computation over published data |
| CPU/GPU/memory/storage/tokens-per-sec benchmarking | **`ce-bench` app (runs on CE as a job)** | it *is* a workload; measure by executing real work |
| Placement, collectives, LLM serving | apps/SDK | policy and orchestration |

---

## 2. The data model

### 2.1 NodeProfile (the vertices) — measured, signed, gossiped

Every node periodically measures itself and publishes a signed `NodeProfile`. This replaces the
heuristic self-tags (`gpu-heavy`) with numbers a scheduler can compare.

```
NodeProfile {
  node_id:   NodeId,
  measured_at: u64,                 // unix seconds; signed so it cannot be backdated

  cpu:    { cores: u32, threads: u32, gflops_fp32: f32, mem_bw_gbps: f32 },
  gpus:   [ { model: String, backend: Cuda|Metal|Rocm|Vulkan, vram_mb: u32, fp16_tflops: f32 } ],
  memory: { total_mb: u32, available_mb: u32 },
  storage:{ total_gb: u32, free_gb: u32, read_mbps: u32, write_mbps: u32 },
  llm:    { ref_model: String, tokens_per_sec: f32 },   // the metric that predicts LLM serving
  runtime:{ os: String, arch: String, docker: bool, gvisor: bool, wasm: bool },
}
```

Measured values come from the **benchmark capsule** (§4). Live, fast-changing fields
(`available_mb`, `free_gb`, `running_jobs`) keep flowing through the existing 60s atlas broadcast;
the heavy `NodeProfile` is re-published only on change or on a randomized schedule.

### 2.2 Edges (the connectivity) — measured + predicted

```
LinkSample {                       // a measured edge between two peers
  a: NodeId, b: NodeId,
  rtt_ms: f32, jitter_ms: f32, loss: f32,
  bw_mbps: Option<f32>,            // bandwidth estimate (probed less often)
  measured_at: u64,
  sig_a: [u8;64], sig_b: [u8;64],  // BOTH endpoints sign — proves a real connection
}
```

Direct measurement is O(connections). For **any-pair** distance without an O(n²) matrix, each node
maintains a **Vivaldi network coordinate** nudged toward its measured RTTs. Predicted
`RTT(a,b) = ‖coord_a − coord_b‖`. Coordinates are O(1) state per node and ride the atlas; the
measured `LinkSample`s remain ground truth for immediate neighbours.

### 2.3 The Fabric Map = one substrate

```
Fabric Map = NodeProfiles (vertices, §2.1)
           + Edges: LinkSamples + Vivaldi coordinates (§2.2)
           + live capacity (running_jobs, available_mb)      — existing atlas
           + reputation (/history: delivered work, earnings)  — existing
```

This is the foundational system other work builds on. It is read through the `ce-graph` SDK (§3.4),
never by re-scraping nodes.

### 2.4 Aggregate stats — the public scoreboard

The same signed data rolls up into the network-wide numbers shown on `ce-net.com` (today the hub's
`/stats` reports only `nodes` + self-reported `cores`). The scoreboard is computed from signed
`NodeProfile`s and the netgraph — so it is *benchmarked*, not self-reported:

```
FabricStats {
  nodes: u64,            // each node counted once (deduped by NodeId)
  cpu_cores: u64,        // Σ cores
  cpu_gflops: f64,       // Σ measured CPU GFLOPS
  gpus: u64,             // Σ GPU count
  gpu_vram_mb: u64,      // Σ VRAM — the global GPU memory pool
  gpu_tflops: f64,       // Σ measured GPU FP16 TFLOPS
  tokens_per_sec: f64,   // Σ reference-model throughput (aggregate LLM serving capacity)
  storage_free_gb: u64,  // Σ free storage
  perf_score: f64,       // a single normalized headline number (display roll-up)
  mesh: { median_rtt_ms: f32, reachable_frac: f32, regions: u32 },  // network-health benchmark
}
```

- **`perf_score`** is a *display* roll-up (a weighted blend of CPU GFLOPS, GPU TFLOPS, and
  tokens/sec). It does not replace the per-node capability *vector* (§4) that placement uses —
  differentiation stays in the app; only the scoreboard collapses to a scalar.
- **Mesh is benchmarked too:** `mesh` turns the netgraph into a health score.
- **Every node counted, including browsers/phones:** browser nodes run the WASM `ce-bench` capsule
  (WebGPU where available) and publish a `NodeProfile` like any other node.
- **Exposure:** a node serves `GET /fabric/stats`; the hub serves the global `/stats` (extended from
  `nodes`+`cores` to the full `FabricStats`). The landing-page hero gauges and `network.html` read it.

---

## 3. Layer 0 — the network graph (the foundation)

| Piece | Where | Build |
|---|---|---|
| RTT capture | `ce-mesh` (node) | Enable `libp2p::ping::Behaviour`; record per-peer RTT (EWMA + jitter). |
| Coordinate | `ce-node` | Maintain a Vivaldi coordinate from ping RTTs + peers' gossiped coordinates; ride the 60s broadcast. |
| Link gossip | `ce-mesh` | New gossipsub topic `ce-netgraph` for co-signed `LinkSample`s and coordinate beacons. |
| Bandwidth probe | `ce-mesh` | Timed small transfer over a mesh stream, randomized; fills `bw_mbps`. (Fast-follow after RTT.) |
| API | `ce-node` | `GET /netgraph`; `GET /netgraph/rtt?to=<id>`; fold coordinate into `/atlas`. |
| Graph library | `ce-graph` (SDK over ce-rs + TS) | Assemble the graph; expose the query contract (§3.4). |

### 3.4 The `ce-graph` query contract (what everything else depends on)

```
predictedRtt(a, b) -> ms          measuredRtt(a, b) -> Option<ms>
bandwidth(a, b) -> Option<mbps>    kNearest(node, k) -> [NodeId]
regions() -> [[NodeId]]            shortestPath(a, b) -> [NodeId]
profile(node) -> NodeProfile       snapshot() -> FabricMap
```

Keep this surface stable. Schedulers, collectives, and the LLM router are all written against it.

---

## 4. Layer 1 — benchmarking is an app (`ce-bench`), not a node feature

Compute capability is measured by **`ce-bench`, an application that runs on CE** — dispatched like any
other job (a `ce-wasm` capsule for portable CPU/memory/storage tests; a native cell for GPU). It runs
on the host it lands on, measures it, and publishes a **signed `NodeProfile` (§2.1)** onto the mesh (a
CEP-1 signal folded into the atlas, exactly like capacity today). The node itself never benchmarks.

**Why an app: it can differentiate.** A single generic node benchmark would flatten every machine onto
one scalar. But "good at LLM serving" is a different question from "good at genomics" or "good at
rendering" — each workload stresses different hardware (VRAM + memory bandwidth vs cores vs disk IO).
As an app, `ce-bench` runs **differentiated, domain-specific probes** and reports a *vector*, not a
number; new domains add new probes without touching the node; and competing benchmark apps can
specialize (an inference bench, a simulation bench) and be chosen per workload. The differentiation
logic — the part that actually decides where work lands — evolves at app speed, not node-release speed.

The standard capsule measures: CPU GFLOPS, memory bandwidth, disk read/write, GPU FP16 TFLOPS + VRAM,
and **reference-model tokens/sec**. Trust: **randomize timing via `/beacon`** so a node cannot detect
"benchmark mode" and cheat; cross-check claimed throughput against delivered work in `/history` and
flag implausible cards (ties into `docs/sybil-resistance.md`).

See `docs/heterogeneous-compute.md` (CPU+GPU together) and `docs/guardian.md` (pre-execution screening).

---

## 5. Layer 2 — placement & the DAG engine ("graphs")

- **`ce-sched` (SDK):** takes a **computational graph** — a DAG of tasks with data dependencies
  (genomics pipelines, satellite tiling, and LLM pipeline stages are all DAGs) — and assigns tasks to
  nodes minimizing makespan + communication cost, using the Fabric Map. Chatty tasks land on
  graph-adjacent nodes; independent tasks spread for redundancy. BFT placement seeded by `/beacon`.

## 6. Layer 3 — topology-aware collectives

- **`ce-collective` (SDK):** all-reduce / broadcast / gather / scatter that build communication rings
  and trees from the netgraph. Bandwidth edges (not just latency) drive these. Required for
  distributed training and tensor-parallel inference.

## 7. Layer 4 — LLM tooling (on `ce-infer`)

- Interactive routing adds predicted RTT to the router's rank (near GPU for chat). Pipeline-parallel
  places adjacent layer-stages on lowest-RTT edges. Tensor-parallel uses `ce-collective` for
  high-bandwidth clusters. Models move as content-addressed blobs (already built).

## 8. Layer 5 — visualization

- Extend **`ce-explorer`** with a live force-directed graph: nodes by Vivaldi coordinate, edges by
  RTT/bandwidth, colored by region, sized by `NodeProfile`.

---

## 9. Trust & adversarial robustness

- **Co-signed edges** — a `LinkSample` is signed by both endpoints.
- **Vivaldi error as a lie detector** — inconsistent RTTs spike prediction error → down-weighted.
- **Randomized probes seeded by `/beacon`** — no pre-arranged probe window.
- **Reputation gating** — placement weight × delivered-work history (`/history`).
- **Benchmark cross-checks** — a card claiming throughput far above delivered work is flagged.

---

## 10. Phased roadmap

| Phase | Deliverable | Unblocks |
|---|---|---|
| **P0** | libp2p ping + per-peer RTT in `ce-mesh`; `GET /netgraph` raw endpoint | everything |
| **P1** | Vivaldi coordinates + bandwidth probe + `ce-graph` SDK + `ce-explorer` graph view | the foundation is live, complete, visible |
| **P2** | `ce-bench` capsule + signed `NodeProfile` in the atlas | real performance data |
| **P3** | `ce-sched` latency- and bandwidth-aware DAG placement | scientific pipelines + smart routing |
| **P4** | `ce-collective` topology-aware all-reduce/broadcast | distributed math |
| **P5** | `ce-infer` pipeline + tensor parallel on the fabric | distributed LLMs |

P0→P1 is the high-leverage core. Phones and browsers (mobile-auth work) become first-class measured
nodes in the same graph.
