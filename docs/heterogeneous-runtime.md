# Heterogeneous GPU Runtime — host-side mechanics

Status: design + phased build. This document is the **GPU-runtime deep-dive**: the host-side
mechanics of actually *running* GPU work inside a CE cell. It is the runtime counterpart to
[heterogeneous-compute.md](heterogeneous-compute.md) (which specifies CPU+GPU *scheduling* and
*placement*) and the GPU-concrete reading of the execution seam in [runtime.md](runtime.md).

It honors the non-negotiable rule of [primitives.md](primitives.md): **CE owns generic,
node-enforced mechanism; apps own policy.** The node gains exactly **one** new generic mechanism —
a GPU *resource cap + isolation mode* on the job spec — because GPU device exposure is the one thing
that genuinely mutates the host enforcement boundary and must be decided inside `ce-node`
(`ce-container`) before a container is launched. Every selection, ranking, pricing, and bin-packing
decision stays in the `ce-sched` app (heterogeneous-compute.md sec 1). Trust tiers map to the
existing per-job `verify:` dial of [sybil-resistance.md](sybil-resistance.md) sec 4.2 — no parallel
mechanism.

---

## 0. Where we stand today

`ce-container` (`crates/ce-container/src/lib.rs`) launches cells with **no GPU awareness at all**:

- `JobSpec` carries only `cpu_cores` and `mem_mb` (lib.rs:33-42); `ce_runtime::Limits` matches
  (`crates/ce-runtime/src/lib.rs:74-78`).
- `launch_job` wires `nano_cpus` and `memory` into the bollard `HostConfig` and forces
  `network_mode: "none"` (lib.rs:80-95). There is **no `DeviceRequests`**, so even on a GPU host the
  CUDA devices are invisible inside the cell.
- `runtime` is `Some("runsc")` only when gVisor is detected, otherwise `None` (raw `runc`) with a log
  warning (`detect_runtime`, lib.rs:265-280). gVisor falls back **silently** to `runc` — acceptable
  for CPU/WASM, dangerous for GPU (sec 2, sec 7).
- Metering prices only CPU-seconds and GB-seconds (`compute_cost`, lib.rs:347-352;
  `CREDITS_PER_CPU_SECOND`, lib.rs:18). There is **no GPU-second term**.

This doc specifies exactly what `ce-container` must add, and stops there.

---

## 1. GPU passthrough into cells

### 1.1 The single node-side type

The whole node-side change is one cap on `JobSpec` and `ce_runtime::Limits` (mirrored, since the
`Runtime::launch` seam carries `Limits`, runtime.md):

```
struct GpuLimit {
  device_index: u32,        // which physical GPU on the host
  vram_mb_cap:  u32,        // hard VRAM ceiling for this cell (enforcement: sec 3)
  isolation:    Isolation,  // WholeGpu | Mps | Mig | Permissive (sec 4)
}

// JobSpec gains:    gpu: Option<GpuLimit>
// ce_runtime::Limits gains:    gpu: Option<GpuLimit>   (copy-able; today Limits is Copy, keep it so)
```

That is the entire mechanism: a device id, a number, and an isolation enum. **No ranking, no host
selection, no pricing policy in `ce-container`** — a CI boundary note enforces this, mirroring the
existing `ce-cap`-must-not-import-`ce-ratio` gate (heterogeneous-compute.md sec 6).

### 1.2 NVIDIA / CUDA on Linux (the primary path)

The host operator installs the **NVIDIA Container Toolkit** (`nvidia-container-runtime` +
`libnvidia-container`), which is what the Docker `--gpus` flag drives. In bollard this is a
`DeviceRequest` on `HostConfig`:

```rust
use bollard::models::DeviceRequest;

host_config.device_requests = Some(vec![DeviceRequest {
    driver: Some(String::new()),                 // "" selects the nvidia capability driver
    count: None,                                 // None + device_ids => explicit devices
    device_ids: Some(vec![gpu.device_index.to_string()]),
    capabilities: Some(vec![vec!["gpu".into()]]),// "compute","utility" can be appended
    options: None,
}]);
```

Under the hood the toolkit injects the device nodes (`/dev/nvidia*`, `/dev/nvidia-uvm`), the driver
libraries, and the right **device-cgroup** allow rules so the cell sees exactly the requested card
and nothing else. `device_index` becomes the value bound to `NVIDIA_VISIBLE_DEVICES`. The existing
`network_mode: "none"` stays — GPU exposure does not relax the network boundary.

### 1.3 AMD / ROCm on Linux

ROCm has no equivalent injecting runtime; passthrough is explicit device + group mapping. `ce-container`
maps `/dev/kfd` and the selected `/dev/dri/renderD<128+index>` via `HostConfig.devices`
(`bollard::models::DeviceMapping`) and adds the `video`/`render` group ids to `group_add`. The same
`device_index` selects the `renderD` node. ROCm is gated behind the same `gpu` ability and `backend:
Rocm` match in the `NodeProfile` (compute-fabric.md:53).

### 1.4 Apple Metal on macOS

Docker Desktop on macOS runs Linux containers in a VM with **no GPU passthrough** — Metal is not
reachable from inside a container. On macOS, GPU cells therefore run as a **native process runtime**
(a sibling `Runtime` impl in the seam, not Docker), sandboxed with the macOS App Sandbox / `sandbox-exec`
profile rather than gVisor. `backend: Metal` hosts advertise `runtime.docker = false` for GPU work
and are placed by `ce-sched` only for native-Metal tasks. This is a future runtime impl; the MVP
treats Metal hosts as CPU-only for container jobs.

### 1.5 The `gpu` ability gate

GPU device exposure is gated on an **opaque `gpu` ce-cap ability** (a string; the verifier stays
generic — capabilities.md). A `JobSpec` carrying `gpu: Some(..)` is rejected at launch unless the
payer's capability chain proves the `gpu` ability against the host's root. This is the same pattern
as every other host-mutating action: the node enforces a signed capability, never an allowlist.

---

## 2. gVisor + GPU: what actually works

gVisor (`runsc`) is CE's default sandbox (`detect_runtime`, lib.rs:265). For GPU the relevant piece
is gVisor's **nvproxy**: a userspace proxy that forwards a *curated subset* of the NVIDIA driver
ioctl surface from the sandboxed application to the host driver.

What nvproxy gives you:

- CUDA compute workloads (inference, training kernels) run inside `runsc` against a **filtered**
  ioctl allow-list, so the cell is not handed the raw `/dev/nvidia*` ioctl surface.
- It is pinned to **specific driver versions** — nvproxy ships per-driver ioctl ABIs and refuses
  unknown versions. The host's driver must be on gVisor's supported list, or `runsc` will not expose
  the GPU.

What nvproxy does **not** give you:

- It is **CUDA-oriented**. Graphics/Vulkan, NVENC/NVDEC in some paths, and exotic ioctls are outside
  the supported set. ROCm and Metal get nothing from nvproxy.
- It narrows but does **not eliminate** the driver attack surface. A bug in an *allowed* ioctl, or in
  the host kernel driver behind it, is still reachable. nvproxy reduces blast radius; it is not a VM
  boundary.
- gVisor's silent `runsc -> runc` fallback (lib.rs:277) means a host *without* gVisor runs GPU work
  with the **full** raw ioctl surface against the host kernel + driver. This is the dominant residual
  risk and the reason for the stranger-refusal rule in sec 7.

**Rule:** when `isolation` requires sandboxing and `detect_runtime` returns `None`, `ce-container`
must **fail closed** for GPU jobs (not silently fall back to `runc`), unless the spec explicitly
opts into `isolation: Permissive` **and** the operator has enabled permissive GPU.

---

## 3. Can `ce-container` enforce a real VRAM cap?

This is the load-bearing question, because the scheduler's bin-packer (heterogeneous-compute.md sec
4.3) treats VRAM as the **hard, non-compressible** dimension.

| Mechanism | Real cap? | Notes |
|---|---|---|
| `--gpus` / `DeviceRequest` alone | **No** | Exposes the *whole* device. A cell can allocate all VRAM; the `vram_mb_cap` is purely advisory and a co-tenant can OOM the card. |
| MIG partition (sec 4) | **Yes** | A MIG instance is a hardware slice with its own fixed VRAM. The cap is the partition size — enforced by the GPU, not by software. |
| MPS with `CUDA_MPS_PINNED_DEVICE_MEM_LIMIT` | **Soft** | MPS can set a per-client device-memory limit, but MPS clients share an address space and fault domain (sec 4); not a security boundary. |
| In-container limiter (env hint, e.g. `PYTORCH_CUDA_ALLOC_CONF`, or an LD_PRELOAD allocator shim) | **Soft / cooperative** | Caps a *cooperative* workload's allocations; a hostile workload ignores it. Useful for honest co-tenancy, useless against an adversary. |

**Conclusion (and an owner decision, sec 8):** with only `DeviceRequest`, `vram_mb_cap` is
**advisory** — `ce-container` records it and passes it as an env hint, but cannot enforce it. A
**real** per-cell VRAM cap requires **MIG hardware partitions**. Therefore: on `isolation: WholeGpu`
the cell gets the whole card and `vram_mb_cap` must equal the card's VRAM (the bin-packer already
treats it as one-job-per-GPU); a sub-card `vram_mb_cap` is honored as *enforced* only under
`isolation: Mig`. `ce-container` stamps which of the two actually happened into the `JobRecord` so
the scheduler and the verify dial never believe an unenforced cap.

---

## 4. Isolation modes and the trust tier each unlocks

The `isolation` enum is the bridge between host-side mechanics and the `verify:` dial. Each mode
caps the **maximum trust tier** a GPU host can reach for *stranger* work — co-tenancy with a hostile
neighbour needs a stronger boundary than running an owner's own job. Tiers below are the
sybil-resistance.md sec 4.2 ladder (T0 visualized .. T4 attested).

| `isolation` | Boundary | VRAM cap | Co-tenancy | Max trust tier for strangers | Verify-dial mapping |
|---|---|---|---|---|---|
| **WholeGpu** | exclusive device, gVisor/nvproxy on the ioctl surface | whole card | none (one job per GPU) | **safe MVP** | T0/T1 for strangers; T2 redundancy where determinism allows. The shipped default. |
| **Mps** (NVIDIA MPS time-slice) | shared CUDA context, shared address space + fault domain | soft only | yes (co-tenant) | **owner-trusted only** | A faulting/hostile co-tenant can crash or read the neighbour. Strangers never share via MPS. T0 owned work only. |
| **Mig** (hardware partitions) | hardware-isolated instance, own VRAM + SM slice | **hard** | yes (isolated co-tenant) | **stranger co-tenancy OK** | Deterministic, isolated VRAM -> eligible for T2 redundant K-of-N where the workload is deterministic. The first mode that makes fractional stranger work legal. |
| **Tee** (H100 Confidential Computing) | encrypted VRAM + remote attestation | hard | exclusive (CC mode) | **highest** | T4 attested. Confidential or un-re-runnable GPU work. **Folded into reputation, never trusted standalone** (sybil-resistance.md:339, 357). |
| **Permissive** (raw `runc`, full ioctl) | none | none | n/a | **refused for strangers** | Operator-opt-in escape hatch for the host's *own* trusted work. Never offered to a non-capability payer. |

### Why fractional co-tenancy is refused for hash-compare verification

GPU/native output is **non-deterministic**: IEEE-754 is non-associative, so kernel scheduling, warp
interleaving, and atomic-accumulation order make two runs of the same kernel differ in the low bits
(sybil-resistance.md:367). Two cells **time-slicing one physical GPU** (MPS, or any soft share)
perturb each other's execution order, widening that non-determinism unpredictably.

The `verify:` dial's deterministic tiers (T1 spot-check re-run, **T2 hash-compare** of redundant
replicas) rely on bit-identical output to slash on mismatch. Fractional co-tenancy breaks that
assumption: an **honest** host running a hash-compare job alongside a noisy neighbour would produce a
non-matching hash and be wrongly slashed. Therefore `ce-sched` enforces a **verification-determinism
guard** (heterogeneous-compute.md sec 7): any task at a deterministic hash-compare tier is routed to
**whole-GPU placement** (or to the NAO tolerance-band / RepOps fixed-FP path), never to a fractional
co-tenant. Fractional sharing is allowed only for **T0 visualized** or **T1 spot-checked** work where
bit-determinism is not the oracle — and even then only under `Mig` for strangers (`Mps` only for the
owner's own work). MIG's hardware partition removes the cross-tenant execution perturbation, which is
why it is the first mode that re-permits stranger co-tenancy.

---

## 5. Metering GPU-seconds (integer base units, never floats)

`compute_cost` (lib.rs:347-352) today sums CPU-seconds and GB-seconds in `u64` credits. GPU adds a
**third generic term** on the same integer footing. Money is `u128` base units end to end
(money model: `1 credit = 10^18` base units); **no float arithmetic touches a credit amount** — a
hard CE invariant. Ranking math may use `f32` TFLOPS, but a billed amount never does.

```
// New generic constants alongside CREDITS_PER_CPU_SECOND (lib.rs:18):
const BASE_UNITS_PER_GPU_SECOND:      u128 = ...;   // per exclusive physical GPU
const BASE_UNITS_PER_VRAM_GB_SECOND:  u128 = ...;   // VRAM reservation premium

// gpu_seconds and vram_gb_seconds are integers; the interval is a whole number of seconds.
let gpu_cost  = gpu_seconds      * BASE_UNITS_PER_GPU_SECOND;
let vram_cost = vram_gb_seconds  * BASE_UNITS_PER_VRAM_GB_SECOND;
let cost      = cpu_cost + mem_cost + gpu_cost + vram_cost;   // all u128 base units
```

Mechanics:

- **GPU-seconds** are reservation-based, not utilization-based: a cell holding `device_index` for the
  metering interval is billed the full interval (matching the one-job-per-GPU model). Wall-clock
  reservation, integer seconds, no fractional accrual — a partially-elapsed interval rounds down, as
  CPU metering already does (`cpu_ms / 1000`, lib.rs:348).
- Under `Mig`, the billed unit is the **partition** (its VRAM-GB and its SM fraction), still as
  integer GPU-second-equivalents derived from the partition's fixed size — never a measured float
  utilization.
- The `JobRecord` records `gpu_seconds`, `vram_gb_seconds`, and the **actual isolation backend**, so
  `/history`, the atlas, and the dial all price an unsandboxed-GPU host as stranger/visualized.
- Long-running GPU cells bill through the existing **30s heartbeat** path (heartbeat loop in
  `ce-node`); GPU terms ride the same `MeterReading` -> heartbeat tx flow as CPU/mem today
  (`MeterReading`, lib.rs:21-29). Express the GPU premium and any guardian scan-fee as a single
  generic conditional-payment/escrow primitive (primitives.md direction) rather than ad-hoc
  `Transfer`s.

`MeterReading` (lib.rs:22) gains `gpu_seconds: u64` and `vram_gb_seconds: u64` fields; the cost it
carries is widened to `u128` (the CPU/mem path should already be moving to `u128` base units per the
money model — GPU does not introduce a new float, it just adds terms).

---

## 6. End-to-end launch flow

1. `ce-sched` (app) places the GPU task and submits a `JobBid` whose workload carries `Limits.gpu =
   Some(GpuLimit { device_index, vram_mb_cap, isolation })`.
2. `ce-node` verifies the payer's capability chain proves the opaque **`gpu`** ability (sec 1.5);
   reject otherwise.
3. The host-side `GpuLedger` (heterogeneous-compute.md sec 5) **fail-closed rejects** an
   over-committing bid against current residual VRAM/fraction; `ce-sched` retries the next-ranked host.
4. `ce-container` resolves `isolation`: if it needs sandboxing and `detect_runtime` returns `None`,
   **fail closed** (no silent `runc` fallback for GPU) unless `Permissive` + operator opt-in.
5. `launch_job` builds the `HostConfig` with the `DeviceRequest`/device mapping (sec 1.2-1.3), the
   VRAM cap (MIG partition or env hint per sec 3), `network_mode: "none"`, and `runtime` per the
   resolved isolation.
6. The metering loop adds GPU-second and VRAM-GB-second terms (sec 5); heartbeats bill in `u128`.
7. On exit, the `JobRecord` stamps `{gpu_seconds, vram_gb_seconds, actual_isolation}` into
   `/history` + atlas so the verify dial and `ce-sched` price the host correctly next time.

---

## 7. Residual risk: the stranger-GPU rule

The dominant risk is **GPU host-escape** through the CUDA/NVIDIA-ioctl driver surface. gVisor's
nvproxy narrows it but does not make it a VM boundary (sec 2); a raw-`runc` GPU cell runs against the
full host kernel + driver. Blast radius is "control of the host machine."

Therefore the node **refuses raw-`runc` GPU passthrough to a stranger** (a non-capability payer)
unless the spec explicitly sets `isolation: Permissive` **and** the operator has enabled permissive
GPU. Stranger GPU work is admitted only under `WholeGpu` (gVisor/nvproxy) or stronger (`Mig`, `Tee`),
priced at the visualized/spot-checked tiers until reputation accrues, and always recorded with its
actual isolation. This composes with the three pillars (bond + slashing, the verify dial, network
hardening) — it adds **no parallel trust mechanism**. A capacity-proportional `HostBond`
(sybil-resistance.md sec 4.1) makes faking GPU capacity expensive, and a `/beacon`-seeded GPU
challenge catches fake cards with a self-healing `FaultFee` (1/32 of bond), not confiscation —
because a censored response is indistinguishable from a flaky card (sybil-resistance.md:299, 322).

The **safe MVP cut**: WASM-deterministic verification + GPU advertised but **stranger-GPU under
`WholeGpu`/gVisor only**, with `Mps`/`Mig`/`Tee` and fractional co-tenancy deferred behind isolation
hardening and the Pillar-3 network prerequisites (heterogeneous-compute.md sec 9).

---

## 8. Owner decisions

1. **Real VRAM cap vs device-exposure-only.** `DeviceRequest` alone makes `vram_mb_cap` advisory; a
   true sub-card cap needs MIG. Decision: ship `WholeGpu` (cap == card) for the MVP and treat enforced
   sub-card caps as a `Mig`-only feature. (sec 3)
2. **Isolation commitment.** WholeGpu-only (safe MVP) vs MPS vs MIG hard partitions vs full-VM
   (Kata/Firecracker + vfio) vs H100 CC TEE. This sets the max trust tier a GPU host can reach and
   whether fractional stranger co-tenancy is ever legal. MIG is the threshold for deterministic
   stranger co-tenancy; MPS never is. (sec 4)
3. **macOS/Metal as a native runtime.** Accept that Metal cannot ride Docker and add a sandboxed
   native-process `Runtime` impl, or keep Metal hosts CPU-only for the MVP. (sec 1.4)
4. **GPU pricing constants.** `BASE_UNITS_PER_GPU_SECOND` / `BASE_UNITS_PER_VRAM_GB_SECOND` values and
   whether GPU billing is reservation-based (recommended) or utilization-based. Must stay integer
   base units. (sec 5)
5. **Fail-closed strictness.** Whether a GPU job on a non-gVisor host is hard-refused for strangers
   (recommended) or merely down-priced to T0 with a loud `JobRecord` flag. (sec 2, sec 7)
