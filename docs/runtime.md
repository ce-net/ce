# Execution runtimes — design

How CE runs a unit of work, independent of *how* it runs. This is the structural seam that lets
WASM (and later, the browser) join Docker as execution backends without disturbing the consensus,
economy, or placement layers.

**Status: Stages 1–3 done.** Stage 1 ✅ `ce-runtime` seam crate. Stage 2 ✅ `ce-container`'s
`DockerRuntime` impl + `ce-node` `Vec<Arc<dyn Runtime>>` registry dispatch. Stage 3 ✅ the
`ce-wasm` backend (wasmtime, fuel-metered + memory-capped), a content-addressed blob store
(`POST/GET /blobs`), `Workload` carried over the mesh Deploy wire (so Docker *or* Wasm deploys),
the `wasm` capability self-tag (every node), and `ce-rs` `put_blob`/`mesh_deploy_wasm`. A
Docker-less machine can now host WASM work. **Refinements:** WASI/args + epoch interruption in
`ce-wasm`, a `ce` CLI for wasm deploy + blob upload, and rerouting the *local* job-manager launch
through the registry. The **browser node** remains a separate project (its own repo).

## Three separable concerns (do not conflate)

1. **Runtime abstraction** — the trait below. Small, in `ce-runtime`.
2. **WASM execution backend** — `ce-wasm` (wasmtime), so a Docker-less machine can host work.
3. **The browser node** — a CE participant in a tab. NOT "compile ce-node to wasm" (tokio-full,
   bollard, libp2p TCP/QUIC don't target `wasm32`); it's a *new slim light client* (WASM exec
   only, libp2p over WebSocket/WebTransport, light chain client, JS harness) built on the same
   protocol + `ce-rs`. Separate repo, separate design, depends on #1/#2 existing first.

## The seam: `Runtime`

```rust
pub enum Workload {
    Docker { image, cmd, env },
    // WASM modules are content-addressed: the host resolves bytes by hash (blob store / data
    // layer) and verifies sha256(bytes) == module_hash before running — tamper-proof delivery.
    Wasm { module_hash: [u8;32], entry, args },
}

#[async_trait]
pub trait Runtime: Send + Sync {
    fn tag(&self) -> &'static str;             // capability self-tag: "docker" | "wasm"
    fn can_run(&self, w: &Workload) -> bool;   // default: w.required_tag() == self.tag()
    async fn launch(&self, w: &Workload, limits: &Limits, job_id: [u8;32]) -> Result<Handle>;
    async fn stop(&self, h: &Handle) -> Result<()>;
}
```

The node holds a `Vec<Arc<dyn Runtime>>` (plugin-style registry) and dispatches a job to the first
runtime whose `can_run` returns true.

## Why this is clean, not "scrambled in"

The `Runtime` trait is the **only** new seam in `ce-node`. Everything else is payload-agnostic and
unchanged:

- **Placement** — WASM hosts advertise the `wasm` capability self-tag; atlas/fleet/`swarm`
  placement filters by tag with *zero new code*. A WASM job targets `--select wasm`.
- **Economy** — heartbeats/payment channels bill a `JobRecord`, not how it ran. WASM meters via
  wasmtime *fuel* (instruction count) + a linear-memory cap instead of cgroups; both produce a
  `Usage`. The chain, channels, reputation, and grants don't change.
- **Workload polymorphism** — `JobBid`'s payload becomes the `Workload` enum (additive; schema
  freedom while single-node). Validation is unaffected (it's about credits, not payloads).

## Bonus: WASM strengthens the trust gradient

WASM is **deterministic** (disable SIMD/threads/float-nondeterminism → bit-reproducible output)
and **capability-sandboxed** (no ambient syscalls). That makes WASM workloads ideal for `swarm
verify` redundancy — K independent hosts produce identical output — a better fit for trustless
verification than containers.

## Crate layout

```
ce-runtime/   ← Runtime trait + Workload/Limits/Usage/Handle  (tiny, no heavy deps)   [Stage 1]
ce-container/ ← Docker impl of Runtime                                                 [Stage 2]
ce-wasm/      ← wasmtime impl of Runtime (isolates the heavy wasmtime dep)             [Stage 3]
ce-node       ← holds Vec<Arc<dyn Runtime>>, dispatches by Workload, advertises tags
```

`ce-wasm` is isolated so a node without WASM doesn't pay for wasmtime, and the future browser
client can reuse its execution logic.

## Decisions (locked)

- **Dispatch:** `dyn Runtime` registry (plugin-style), not a fixed enum.
- **Module delivery:** content-addressed by hash. The data layer now closes this loop — on
  `Deploy` the host **stages** the Wasm module (and any declared inputs) from the data layer into
  its local blob store before launch (`docs/data-layer.md` Stage 4), so a workload runs on a host
  that didn't previously hold its bytes.
- **Browser node:** deferred to its own repo/design.
