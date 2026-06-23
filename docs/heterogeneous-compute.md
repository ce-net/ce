# Heterogeneous CPU+GPU Execution

Status: design + phased build. This document specifies **heterogeneous CPU+GPU execution** on the
compute fabric -- how a job that mixes CPU pre/post stages with GPU compute stages is scheduled,
placed, isolated, priced, and verified. It is the Layer-2 placement track of
[compute-fabric.md](compute-fabric.md) made concrete for GPUs, and it composes with the bond +
verification machinery of [sybil-resistance.md](sybil-resistance.md).

It honors the non-negotiable rule of [primitives.md](primitives.md): **CE owns generic,
node-enforced mechanism; apps own policy.** Placement, ranking, bin-packing, pipeline pinning, and
pricing are an **app** (`ce-sched`). The node gains exactly **one** new generic mechanism -- a GPU
*resource cap + isolation mode* on the job spec -- because GPU device exposure is the one thing that
genuinely mutates the host enforcement boundary and must be decided inside `ce-node` before launch.

---

## 1. Principle: the node exposes a GPU *cap*, the app does the *placement*

compute-fabric.md is explicit (line 27): *the node never benchmarks compute*, and `ce-sched` is an
SDK app (line 217). primitives.md (line 118) lists "work scheduler / orchestrator" as explicitly
**not** in CE. So the entire decision of *which host runs which task* lives in `ce-sched`, a pure
client over `ce-rs` that reads published, signed data and emits ordinary `JobBid`s. It holds zero
privileged state and adds no node RPC, no gossip topic, and no consensus tx type.

The litmus test (primitives.md:178): product semantics (a placement, a pipeline, a price) -> app; a
key/byte/coin/number mechanism every app would otherwise reinvent -> primitive. Host selection is
policy that evolves at app speed. Only the per-task **resource cap** must be node-enforced before a
container is launched -- and a cap is a generic number plus a device id, so it qualifies as a
primitive while ranking/bin-packing/pinning do not.

| Concern | Lives in | Why |
|---|---|---|
| GPU/CPU capability measurement -> signed `NodeProfile` | `ce-bench` app (compute-fabric.md sec 4) | benchmarking is a workload, never a node feature |
| netgraph distance (`predictedRtt`/`bandwidth`/`kNearest`) | `ce-graph` SDK (compute-fabric.md sec 3.4) | pure computation over published data |
| filter -> rank -> bin-pack -> pin -> replicate | **`ce-sched` SDK app** (this doc) | placement is policy |
| GPU device exposure + VRAM/isolation cap, enforced at launch | **`ce-container` (node)** -- one generic field | only the node can mutate the host enforcement boundary |
| unbiasable replica seed | reuse shipped `GET /beacon` | already a primitive |

---

## 2. Inputs `ce-sched` consumes (all already-published primitives)

`ce-sched` never re-scrapes nodes. It reads, through the `ce-graph` SDK contract
(compute-fabric.md:176):

- **The signed `NodeProfile` capability vector** (compute-fabric.md:42-83): per host,
  `cpu{cores, threads, gflops_fp32, mem_bw_gbps}`, `gpus[]{model, backend, vram_mb, fp16_tflops}`,
  `memory`, `storage`, `llm{tokens_per_sec}`, `runtime{docker, gvisor, wasm}`. This **replaces** the
  heuristic `tag:gpu` self-tag, whose untrusted-value problem is finding **E2** in
  sybil-resistance.md (a Sybil advertising `tag:gpu` + 1000 cores it cannot serve). The `tag:gpu`
  self-tag is kept only as a coarse pre-filter; the trustworthy numbers are the `NodeProfile`.
- **The netgraph**: `predictedRtt(a,b)`, `measuredRtt(a,b)`, `bandwidth(a,b)`, `kNearest(node,k)`,
  `regions()`, `profile(node)`, `snapshot()`.
- **`/history`** delivered-work reputation (the reputation substrate, primitives.md sec 3).
- **`/beacon`** verifiable randomness (PoW tip height + hash) for replica selection.
- **Live atlas capacity** (the existing 60s broadcast), extended below with residual GPU VRAM/fraction.

It extends the `NodeProfile.runtime` block (in the `ce-bench` app, gossiped as read-substrate) with
an **isolation-attestation** field so a scheduler can see whether a host can offer gVisor-GPU / MIG
isolation at all -- letting the trust gradient price a permissive-runc GPU host differently from a
MIG-partitioned host.

---

## 3. The job/DAG + resource-demand schema (`ce-sched`, app-tier)

A job is a DAG of tasks with data-dependency edges. Each task carries its hard resource demand and
the per-job verification tier (the `verify:` dial from sybil-resistance.md sec 4.2):

```
Task {
  id:        TaskId,
  cpu_cores: u32,
  mem_mb:    u64,
  gpu: Option<{
    count:           u32,
    min_vram_mb:     u32,
    min_fp16_tflops: f32,     // ranking-only; f32 is fine -- never touches consensus
    backend:         Backend, // Cuda | Metal | Rocm | Vulkan
    fractional_ok:   bool,    // may this task share a physical GPU with a co-tenant?
  }>,
  workload:  Workload,        // ce_runtime::Workload (Docker | Wasm) -- unchanged
}
Edge { from: TaskId, to: TaskId, payload_bytes: u64 }   // data dependency + transfer size
JobSpec { tasks: [Task], edges: [Edge], verify: Tier, bid_ceiling: u128 /* base units */ }
```

`bid_ceiling`, GPU-second pricing, and bond sizing are **`u128` base units** end to end; ranking
math may use `f32` for latency/TFLOPS (never consensus-touching), but every credit amount a `JobBid`
carries is a `u128` decimal string. No float arithmetic on credits -- a hard CE invariant.

---

## 4. The placement pipeline

### 4.1 Filter -- hard capability match

Drop every host whose signed `NodeProfile` lacks the required `cores` / `mem` / per-GPU `vram_mb` /
`backend` / `fp16_tflops`, or whose `runtime` cannot isolate the requested cap (see sec 6). The
legacy `tag:gpu` self-tag is consulted only as a cheap coarse pre-filter before the `NodeProfile`
numeric match -- never as the authoritative source (E2).

### 4.2 Rank -- composite cost

For each surviving host:

```
score = w_fit * fit(task, profile)
      + w_net * net_cost(task, host)        // RTT + payload_bytes/bandwidth over each in-edge
      + w_rep * rep_multiplier(history)     // delivered-work reputation, app-tier only
```

- `net_cost` prefers `measuredRtt()` for direct neighbours and falls back to `predictedRtt()`
  (Vivaldi) only beyond direct samples (compute-fabric.md:106). Hosts with high Vivaldi coordinate
  error are down-weighted (the lie-detector, compute-fabric.md sec 9), and the latency term is
  **capped** so one bad prediction cannot dominate the rank.
- `rep_multiplier` reads `/history` and is a **ranking multiplier and trust-gradient gate only**. It
  **never** gates authorization and is **never** an input to `ce-cap` (primitives.md invariant: the
  capability verifier never imports app-tier reputation). Strangers are restricted to
  redundant/visualized GPU work until they prove out.

**Owner decision:** linear vs lexicographic (hard latency budget first, then rank) combination.
Linear risks a high-reputation far host beating a near host on a latency-bound pipeline edge; a hard
latency budget for chatty edges then rank within budget is the safer default for pipelines.

### 4.3 GPU bin-pack -- Best-Fit-Decreasing on (VRAM, compute fraction)

GPU tasks are bin-packed with **VRAM as the hard dimension** and the `fp16_tflops` fraction as a soft
secondary dimension. VRAM is non-compressible: a task needing 20 GB on a 24 GB card cannot co-tenant
with another 20 GB task regardless of TFLOPS. BFD (largest task first) minimizes fragmentation and
leaves the largest contiguous VRAM holes for big future jobs.

Fractional sharing is **opt-in** (`fractional_ok`) and allowed **only** when the host's
`NodeProfile.runtime` + its `GpuLedger` (sec 5) report it can isolate co-tenants (MPS time-slice /
MIG partition) **and** the task's verify tier permits it (sec 7). The MVP advertises **one job per
physical GPU** (no co-tenancy) and treats MIG as a later isolation tier.

### 4.4 Pipeline pinning -- place the scarce stage first

GPU is the scarcest resource, so the GPU stage is placed **first**. Its CPU pre/post stages are then
drawn from `ce-graph.kNearest(gpu_host, k)` filtered to CPU-capable hosts, minimizing per-edge
`RTT * latency_weight + payload_bytes / bandwidth` (compute-fabric.md:218-220). Pulling CPU stages
toward the GPU (not vice-versa) avoids stranding a good GPU far from its data -- activations and
intermediate tensors between a GPU stage and its CPU pre/post are latency- and bandwidth-bound.

**Owner decision:** greedy stage-by-stage placement (place as inputs complete, per
`docs/apps/scheduler.md`) vs one-shot global assignment. Global gives better makespan but needs the
full DAG up front and a heavier solver. Recommend greedy for the MVP.

### 4.5 Redundant / BFT replicas -- derived from a future beacon

When the verify tier demands redundancy, `ce-sched` commits the `JobBid` first, then derives the `R`
independent replica hosts from a **future** `/beacon` value (sybil-resistance.md sec 4.2 enabler 1).
Neither the requester nor a colluder can steer or grind replica selection. This generalizes today's
"pick R random hosts" into verifiable, auditable placement and is the only real defense against
Sybil-collusion silently defeating K-of-N.

---

## 5. Host-side `GpuLedger` (worker agent, app-tier)

The host-side worker agent (the `rdev`/worker that bridges run-workload to the mesh,
primitives.md:175) keeps an in-memory `GpuLedger`: per physical GPU, the VRAM and compute fraction
already committed to running cells. It:

1. publishes **residual** free VRAM/fraction into the live 60s atlas capacity broadcast
   (compute-fabric.md:87) so `ce-sched`'s bin-packer sees current headroom; and
2. is the **authoritative truth** at accept time -- it **fail-closed rejects** an over-committing bid
   (matching the wasm aggregate-stdin cap pattern in `ce-wasm`); `ce-sched` retries the loser on the
   next-ranked host.

Atlas capacity is **advisory**; the `GpuLedger` reconciles the placement engine's view on accept.
Optionally `ce-sched` probes `GET /atlas` for the target right before bidding to shrink the race
window between two schedulers racing for the same VRAM hole.

---

## 6. The single node-side mechanism: a generic GPU cap + isolation mode

Today `ce-container::JobSpec` (`crates/ce-container/src/lib.rs:33-42`) carries only `cpu_cores` and
`mem_mb`, and `launch_job` wires `nano_cpus` / `memory` with `network_mode: "none"` and
`runtime: runsc-when-present` (lib.rs:80-95) -- **no GPU device mapping**, and gVisor silently falls
back to raw `runc` with only a log warning. To *enforce* GPU isolation the node must accept a
**generic** cap on `JobSpec` and `ce_runtime::Limits`:

```
GpuLimit {
  device_index: u32,       // which physical GPU
  vram_mb_cap:  u32,       // hard VRAM ceiling for this cell
  isolation:    Isolation, // WholeGpu | Mps | Mig | Permissive
}
```

The node then:

- **gates GPU exposure on an opaque `gpu` ability** in the `ce-cap` chain (a string; the verifier
  stays generic -- capabilities.md);
- **wires the device request** (`--gpus` / bollard device-requests) and a VRAM cap (MIG partition or
  an in-container limiter) at launch;
- **refuses raw-`runc` GPU passthrough to a non-capability (stranger) payer** unless the job spec
  explicitly opts into `isolation: Permissive` **and** the host operator has enabled it -- because
  gVisor does **not** meaningfully sandbox the CUDA/UVM ioctl surface, so a GPU job on a `runc` host
  runs against the host kernel + driver (the dominant residual risk, sec 8);
- **stamps the isolation backend that actually ran the job** into the `JobRecord` (and thus
  `/history` and the atlas) so the verify dial and the scheduler can price unsandboxed-GPU hosts as
  stranger / visualized-only.

This stays strictly a generic cap: a number, a device id, an isolation enum. **No ranking or
selection logic may live in `ce-container`** -- a CI boundary note enforces this, mirroring the
existing `ce-cap`-must-not-import-`ce-ratio` gate. All placement stays in `ce-sched`.

**Owner decision:** does `ce-container` enforce a *real* VRAM cap, or only device exposure? bollard's
`--gpus` exposes the whole device by default; a true per-cell `vram_mb_cap` needs MIG hardware
partitions or an in-container memory limiter, otherwise the cap is advisory and a co-tenant can OOM
the GPU. This choice (whole-GPU-only vs MPS vs MIG vs TEE) sets the maximum trust tier a GPU host can
reach and whether stranger GPU work is allowed at all.

---

## 7. Verification: GPU/native jobs ride the existing per-job dial

GPU and native jobs do **not** get a new trust mechanism -- they ride the existing `verify:` dial
(sybil-resistance.md sec 4.2) at a **higher default tier**, because GPU host-escape blast radius is
"control of machines":

- **WASM jobs** (`ce-wasm`) are bit-reproducible (deterministic engine config, `ce-wasm/src/lib.rs`)
  -> cheap **T1 spot-check / T3 fraud-proof**.
- **GPU/native jobs** are non-deterministic (IEEE-754 non-associativity, sybil-resistance.md:367) ->
  **T2 NAO tolerance-band redundancy** or **T4 attestation**. **Never** naive output-hash compare,
  **never** auto-slash on non-deterministic output.

The **verification-determinism guard** in `ce-sched`: refuse fractional-GPU sharing for any task
whose verify tier is T2 hash-compare (two cells time-slicing one GPU break the bit-determinism the
oracle relies on); route such tasks to whole-GPU placement or the NAO / RepOps fixed-FP path.
Fractional co-tenancy is allowed only for **T0 visualized** or **T1 spot-checked** work where
determinism is not the oracle.

GPU capability claims are treated as value only once the bond + network-hardening prerequisites land:
a capacity-proportional `HostBond` (sybil-resistance.md sec 4.1) makes faking 100x GPU cost ~100x
bond, and a `/beacon`-seeded GPU challenge (a future-beacon-selected verifier re-runs a reference
kernel) catches fake-GPU capability with a self-healing `FaultFee` (1/32 of bond), **not**
confiscation -- because a censored response is indistinguishable from a flaky card.

---

## 8. Threat model (composes with the 3 pillars, no parallel mechanism)

| Risk | Mitigation |
|---|---|
| **GPU host-escape** via the CUDA/nvidia-ioctl driver surface; gVisor does not sandbox it; `ce-container` silently falls back to `runc` | Node refuses raw-`runc` GPU passthrough to strangers; require explicit `isolation:Permissive` opt-in the operator must also enable; prefer MIG/MPS + a seccomp profile pinning the nvidia ioctl surface; record the actual isolation into `JobRecord`/`/history`/atlas so the dial prices unsandboxed-GPU hosts as stranger/visualized (T0); long-term TEE (H100 CC) at T4, **folded into reputation, never trusted standalone**. |
| **Inflated `NodeProfile` GPU numbers** (E2) select a host that cannot serve the task | Gate placement weight by `/history` delivered work; cross-check claimed `fp16_tflops` vs delivered throughput and down-rank implausible cards; require a `HostBond` to publish a GPU capacity ad. |
| **Fractional co-tenancy breaks determinism** -> honest host fails T2 hash-compare and is slashed | Refuse fractional sharing for T2 hash-compare; route to whole-GPU or NAO tolerance-band / RepOps fixed-FP. |
| **VRAM scraping / neighbour interference** between co-tenants | MVP: one job per physical GPU (exclusive device assignment). Later: MIG hardware partitions + driver-level VRAM clear; neighbour-interference detection via the `ce-bench` cross-check (delivered tokens/sec diverging from the signed `NodeProfile` is flagged in `/history`). |
| **Stale atlas capacity** lets the bin-packer over-commit a GPU two schedulers race for | `GpuLedger` is authoritative and fail-closed rejects over-commit at accept; `ce-sched` retries the loser; optional pre-bid `/atlas` probe. |
| **Beacon-seeded challenge eclipsed/ground** (N3/N6) | Derive selection from a **future** beacon (commit-then-reveal); require the response to ride a quorum of peer-confirmed tips (the N6 fix). Pillar-3 network hardening is a **prerequisite**, not optional, for treating GPU claims as value. |
| **Adding a GPU field drifts the node toward policy** | Keep the field strictly `{device_index, vram_mb_cap, isolation}` + the `gpu` ability; CI boundary note forbids any selection logic in `ce-container`. |

---

## 9. Phasing (aligned to compute-fabric.md P0..P5)

- **P2** -- `ce-bench` extends `NodeProfile` with the GPU vector + isolation-attestation field; the
  generic GPU cap + isolation mode lands in `ce-container::JobSpec`/`ce-runtime::Limits`, gated by
  the `gpu` ability, refusing raw-`runc` stranger GPU passthrough.
- **P3** -- `ce-sched`: the filter -> rank -> bin-pack -> pin -> beacon-replica pipeline; the
  host-side `GpuLedger`; the verification-determinism guard wiring GPU jobs into the verify dial.
- **P4/P5** -- collective- and inference-aware extensions (`ce-collective`, `ce-infer` pipeline /
  tensor parallel) reuse the same `NodeProfile` + netgraph + `ce-sched` placement.

The safe MVP cut (**owner decision**) is **WASM-deterministic verification + GPU advertised but
stranger-GPU refused** -- ship without native GPU host-escape exposure, defer native GPU + the
guardian behind isolation hardening and Pillar-3 network prerequisites.

---

## 10. Open decisions for the owner

1. GPU isolation commitment: whole-GPU-only (safe MVP) vs NVIDIA MPS vs MIG hard partitions vs
   full-VM (Kata/Firecracker+vfio) vs H100 confidential-compute TEE. MIG gives deterministic
   isolation suitable for T2; MPS does not. This sets the max trust tier a GPU host can reach and
   which fractional co-tenants are even legal.
2. Real VRAM cap vs device-exposure-only in `ce-container` (sec 6).
3. Linear vs lexicographic (latency-budget-first) rank combination (sec 4.2).
4. GPU-second / VRAM-GB-second pricing term: `ce-container` today prices only CPU/mem
   (`CREDITS_PER_CPU_SECOND`, lib.rs:18). A new **generic** GPU metering term is needed and must stay
   integer base units. Consider expressing the GPU premium + the guardian scan-fee as a single
   generic conditional-payment/escrow primitive (the direction in primitives.md:165) rather than
   ad-hoc `Transfer`s.
5. Greedy stage-by-stage vs one-shot global makespan minimization (sec 4.4).
