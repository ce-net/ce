//! WebAssembly execution backend for CE.
//!
//! A wasmtime-based [`ce_runtime::Runtime`] so a Docker-less machine (and, later, a browser) can
//! host work. Modules are **content-addressed**: a `Workload::Wasm { module_hash, .. }` is
//! resolved from a local blob directory and its sha256 verified before running — tamper-proof.
//! Execution is **fuel-metered** (a runaway module traps when fuel runs out) and **memory-capped**
//! (linear memory limited), so an untrusted module is bounded without a container.
//!
//! Two execution modes, selected by the workload's `entry`:
//! - `entry == "_start"` → a **WASI command** (data-layer I/O): the workload's content-addressed
//!   `inputs` are concatenated onto **stdin**, the module runs, and its **stdout** is captured and
//!   published to the blob store — the host returns that **output CID**. Inputs → compute → output.
//! - any other `entry` → an exported `() -> i32` function (an exit code), no I/O — the original
//!   self-contained path.
//!
//! Either way execution is **fuel-metered** (instruction budget), **memory-capped** (linear memory
//! limited), and **wall-clock-bounded** (an epoch watchdog interrupts a module that outlives its
//! time budget — defense-in-depth on top of fuel, and platform-independent), so an untrusted module
//! is bounded without a container.
//!
//! Buffers are bounded end to end so an untrusted deploy cannot OOM the host or fill its disk:
//! module bytes ([`MAX_MODULE_BYTES`]) and aggregate stdin ([`MAX_STDIN_BYTES`]) are size-checked
//! before allocation, stdout is capped ([`MAX_STDOUT_BYTES`]) both in memory and at the disk write,
//! and an untrusted module's stderr is routed to a bounded pipe — **never** the operator's log.
//!
//! Execution is **deterministic** (engine NaN-canonicalized, threads/relaxed-SIMD off — see
//! [`engine_config`]): the pure-compute path is fully bit-reproducible, which is what makes it ideal
//! for `swarm verify` (re-run the same module + input on another host, compare output CIDs). The
//! WASI path is reproducible for modules that do not read the host clock/RNG.
//!
//! Trap delivery is configured to be **recoverable on every platform**: a runaway module that
//! exhausts its fuel (or its wall-clock deadline) returns a catchable `Err`, never aborts the host
//! process. See [`engine_config`] for the Windows-specific reason signals-based trap delivery is
//! disabled.

use anyhow::{anyhow, Context, Result};
use ce_runtime::{Handle, Limits, Runtime, Workload};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};

/// Fuel granted per CPU core. Fuel ≈ executed wasm instructions; this bounds run time. A core
/// gets a generous budget so normal compute completes, while a runaway loop still traps.
const FUEL_PER_CORE: u64 = 10_000_000_000;

/// Wall-clock ceiling for any single WASM execution, enforced by an epoch watchdog independently
/// of fuel. Fuel bounds *instructions*; this bounds *time* (e.g. a module blocked on a host call,
/// or any platform where a fuel trap is unreliable). Defense-in-depth: an untrusted module can
/// never run the host indefinitely. Generous so legitimate compute finishes well within it.
const MAX_WALL_CLOCK: Duration = Duration::from_secs(300);

/// Hard ceiling on a content-addressed **module's** byte size, enforced in [`WasmRuntime::resolve`]
/// **before** the module is fully read into host RAM. An untrusted deploy cannot make the host
/// allocate an unbounded buffer just by pointing at a huge blob. 64 MiB is far larger than any
/// real CE module yet small enough that thousands cannot exhaust host memory.
const MAX_MODULE_BYTES: u64 = 64 * 1024 * 1024;

/// Hard ceiling on the **aggregate** of all staged input blobs concatenated onto a WASI command's
/// stdin. Inputs are summed and rejected **before** any concatenation, so a large multi-input deploy
/// can never OOM the host before the module runs. 256 MiB bounds the worst case while leaving room
/// for legitimate data-layer payloads.
const MAX_STDIN_BYTES: u64 = 256 * 1024 * 1024;

/// Hard ceiling on a WASI command's captured **stdout**, which becomes the published output blob.
/// This is the single source of truth for the stdout pipe cap *and* the fail-closed guard before the
/// disk write, so an untrusted module can never write an unbounded output blob to host disk. The
/// in-memory pipe already truncates at this size; the disk-write guard rejects anything at/over it.
const MAX_STDOUT_BYTES: usize = 16 * 1024 * 1024;

/// Hard ceiling on a module's captured **stderr**. Untrusted `fd 2` is routed to a bounded in-memory
/// pipe (never the operator's log stream — that would be ambient authority and a log-injection / log-
/// flood vector), and is discarded after the run. A small cap suffices: stderr is diagnostic only and
/// never published.
const MAX_STDERR_BYTES: usize = 64 * 1024;

/// Epoch tick interval for the watchdog. Each tick increments the engine epoch; the store's epoch
/// deadline is `MAX_WALL_CLOCK / WATCHDOG_TICK` ticks, so the module is interrupted within roughly
/// one tick of the wall ceiling. Smaller = tighter bound but more wakeups.
const WATCHDOG_TICK: Duration = Duration::from_secs(1);

/// Build the wasmtime [`Config`] used for all CE execution. Centralized so every engine (runtime
/// and tests) shares the exact same trap-handling configuration.
///
/// Three settings are load-bearing for **safely** running untrusted modules across every platform:
///
/// 1. `signals_based_traps(false)` — this is the cross-platform fix for the **Windows** abort. When
///    enabled (the default), a trap (notably **fuel exhaustion** on a runaway loop) is delivered
///    through host signal/SEH machinery and a stack unwind back to the host trampoline. On Windows
///    a failure on that unwind path panics *inside* an `extern "C"` libcall, which "cannot unwind"
///    and **aborts the whole process** ("panic in a function that cannot unwind") instead of
///    returning a catchable `Err`. Disabling signals-based traps makes wasmtime emit explicit
///    in-code checks and return traps without relying on signal-handler unwinding, so a fuel/epoch
///    trap surfaces as a recoverable `Err` on every platform. The only cost is that linear-memory
///    bounds become explicit checks rather than guard pages — acceptable for CE's bounded modules.
///
/// 2. `wasm_backtrace_max_frames(None)` — never attach a WASM backtrace to errors coming out of
///    wasm. We don't need it (we log a plain trap), and not capturing it keeps the trap path free
///    of native-unwind frame walking. (This is the modern replacement for the deprecated
///    `wasm_backtrace(false)`; passing `None` disables backtrace context entirely.)
///
/// 3. `epoch_interruption(true)` — arms the wall-clock watchdog (see [`run_with_watchdog`]). This is
///    defense-in-depth on top of fuel: an untrusted module is bounded by both instruction count
///    *and* wall time, on every platform, regardless of any trap-delivery quirk.
///
/// And four settings make the **determinism** claim true, so the same module + input yields the
/// same output bytes (hence the same output CID) on every host — the prerequisite for `swarm verify`
/// cross-checking a result by re-running it elsewhere:
///
/// 4. `cranelift_nan_canonicalization(true)` — floating-point NaN bit patterns are otherwise
///    architecture-dependent; canonicalizing them makes float results bit-identical across hosts.
/// 5. threads off — shared memory + atomics admit data races and non-deterministic interleavings.
///    The wasm-threads proposal is compiled out entirely: `ce-wasm` builds wasmtime with
///    `default-features = false` (no `threads` feature), so threads are disabled at the crate level
///    and cannot be re-enabled at runtime. (Hence no `wasm_threads(false)` call — the method does
///    not even exist without the feature.)
/// 6. `wasm_relaxed_simd(false)` + `relaxed_simd_deterministic(true)` — relaxed-SIMD instructions are
///    explicitly allowed to differ per architecture. We disable the proposal entirely **and** pin the
///    deterministic lowering, so even if a module slips one in it cannot diverge across hosts.
///
/// Note: this pins the **engine**. The pure-compute path (empty linker) is then fully reproducible.
/// The WASI command path still links `clock_time_get`/`random_get` (preview1), so a module that reads
/// the clock or RNG can still observe host-specific values — bit-reproducible verification applies to
/// modules that do not call those. De-linking them is left to the capability-gated host ABI (P2).
fn engine_config() -> Config {
    let mut config = Config::new();
    config.consume_fuel(true);
    config.epoch_interruption(true);
    // See doc comment above: explicit (non-signal) trap delivery avoids the Windows "cannot unwind"
    // abort on fuel/epoch traps, surfacing them as recoverable `Err` on every platform.
    config.signals_based_traps(false);
    // Never attach a WASM backtrace to wasm errors (modern replacement for `wasm_backtrace(false)`).
    config.wasm_backtrace_max_frames(None);
    // Determinism: pin float NaN canonicalization and remove the nondeterministic feature surface so
    // the same module + input is bit-reproducible across hosts (see doc comment, points 4–6).
    // The wasm-threads proposal is already compiled out (no `threads` crate feature), so there is no
    // runtime `wasm_threads` toggle to call — threads cannot be enabled.
    config.cranelift_nan_canonicalization(true);
    config.wasm_relaxed_simd(false);
    config.relaxed_simd_deterministic(true);
    config
}

/// Run a fuel-metered WASM closure under a wall-clock watchdog.
///
/// Sets the store's epoch deadline to the number of watchdog ticks that fit in [`MAX_WALL_CLOCK`],
/// then spawns a background thread that increments the engine epoch once every [`WATCHDOG_TICK`].
/// After the budget's worth of ticks the deadline is reached and the module is interrupted (an
/// epoch trap, surfaced as a catchable `Err`, exactly like fuel exhaustion). This bounds an
/// untrusted module by wall time independently of fuel, on every platform. The watchdog thread is
/// signalled to stop and joined before returning, so it never outlives the call.
fn run_with_watchdog<T, S>(
    engine: &Engine,
    store: &mut Store<S>,
    run: impl FnOnce(&mut Store<S>) -> Result<T>,
) -> Result<T> {
    // Deadline in watchdog ticks. With one epoch bump per tick, the deadline trips at ~MAX_WALL_CLOCK.
    let deadline_ticks =
        (MAX_WALL_CLOCK.as_millis() / WATCHDOG_TICK.as_millis().max(1)).max(1) as u64;
    store.set_epoch_deadline(deadline_ticks);

    let stop = Arc::new(AtomicBool::new(false));
    let watchdog = {
        let engine = engine.clone();
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(WATCHDOG_TICK);
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                engine.increment_epoch();
            }
        })
    };

    let result = run(store);

    stop.store(true, Ordering::Relaxed);
    // The watchdog sleeps at most one tick between stop checks, so this join is bounded.
    let _ = watchdog.join();
    result
}

/// `Runtime` backend that executes WebAssembly modules via wasmtime.
pub struct WasmRuntime {
    engine: Engine,
    /// Directory of content-addressed blobs: `<blobs_dir>/<hex(sha256)>` holds module bytes.
    blobs_dir: PathBuf,
}

impl WasmRuntime {
    pub fn new(blobs_dir: PathBuf) -> Result<Self> {
        let engine =
            Engine::new(&engine_config()).map_err(anyhow::Error::from).context("wasmtime engine")?;
        Ok(Self { engine, blobs_dir })
    }

    /// Resolve a content-addressed module from the blob store, verifying its hash.
    ///
    /// The blob's on-disk size is checked against [`MAX_MODULE_BYTES`] **before** it is read into
    /// memory, so a deploy pointing at an oversized blob is rejected without allocating it (host-RAM
    /// DoS defense). This guards modules and staged inputs alike (both resolve through here).
    fn resolve(&self, module_hash: &[u8; 32]) -> Result<Vec<u8>> {
        let path = self.blobs_dir.join(hex::encode(module_hash));
        let len = std::fs::metadata(&path)
            .with_context(|| format!("blob {} not in store", hex::encode(&module_hash[..4])))?
            .len();
        if len > MAX_MODULE_BYTES {
            return Err(anyhow!(
                "blob {} is {len} bytes, exceeds {MAX_MODULE_BYTES}-byte cap",
                hex::encode(&module_hash[..4])
            ));
        }
        let bytes = std::fs::read(&path)
            .with_context(|| format!("blob {} not in store", hex::encode(&module_hash[..4])))?;
        let got: [u8; 32] = Sha256::digest(&bytes).into();
        if &got != module_hash {
            return Err(anyhow!("blob hash mismatch for {}", hex::encode(&module_hash[..4])));
        }
        Ok(bytes)
    }
}

/// Run a WASM module's exported `entry` (signature `() -> i32`), bounded by `fuel` instructions
/// and `mem_mb` of linear memory. Returns the entry's i32 result. Synchronous + CPU-bound;
/// callers run it on a blocking thread.
pub fn execute(engine: &Engine, wasm: &[u8], entry: &str, fuel: u64, mem_mb: u64) -> Result<i32> {
    let module =
        Module::new(engine, wasm).map_err(anyhow::Error::from).context("compile module")?;
    let limits = StoreLimitsBuilder::new()
        .memory_size((mem_mb as usize).saturating_mul(1024 * 1024))
        .build();
    let mut store = Store::new(engine, limits);
    store.limiter(|l: &mut StoreLimits| l);
    store.set_fuel(fuel).map_err(anyhow::Error::from).context("set fuel")?;

    // No imports — the module must be self-contained (the WASI path is `execute_command`).
    let linker: Linker<StoreLimits> = Linker::new(engine);
    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(anyhow::Error::from)
        .context("instantiate")?;
    let func = instance
        .get_typed_func::<(), i32>(&mut store, entry)
        .map_err(anyhow::Error::from)
        .with_context(|| format!("export `{entry}` with signature () -> i32"))?;
    run_with_watchdog(engine, &mut store, |store| {
        func.call(store, ()).map_err(anyhow::Error::from).context("wasm trap")
    })
}

/// Run a WASI command module (`_start`), feeding `stdin` and capturing stdout. Bounded by `fuel`
/// and `mem_mb`. Returns `(exit_code, stdout_bytes)`. This is the data-layer I/O path: stdin is the
/// concatenated inputs, stdout is the result the host publishes by CID. Synchronous + CPU-bound.
pub fn execute_command(
    engine: &Engine,
    wasm: &[u8],
    fuel: u64,
    mem_mb: u64,
    stdin: Vec<u8>,
) -> Result<(i32, Vec<u8>)> {
    use wasmtime_wasi::WasiCtxBuilder;
    use wasmtime_wasi::p1::{self, WasiP1Ctx};
    use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};

    // Store data carries both the WASI context and the memory limiter.
    struct CmdState {
        wasi: WasiP1Ctx,
        limits: StoreLimits,
    }

    let module =
        Module::new(engine, wasm).map_err(anyhow::Error::from).context("compile module")?;
    // stdout cap — bounds a runaway writer; the produced output blob can't exceed `MAX_STDOUT_BYTES`.
    let stdout = MemoryOutputPipe::new(MAX_STDOUT_BYTES);
    // stderr is routed to a SEPARATE bounded in-memory pipe and discarded after the run. It is NEVER
    // inherited onto the host's stderr/log stream: an untrusted module's fd 2 must not be able to
    // inject ANSI/log lines or flood the operator's logs (ambient authority). The cap bounds the
    // buffer; we never read it back.
    let stderr = MemoryOutputPipe::new(MAX_STDERR_BYTES);
    let wasi = WasiCtxBuilder::new()
        .stdin(MemoryInputPipe::new(stdin))
        .stdout(stdout.clone())
        .stderr(stderr)
        .build_p1();
    let limits = StoreLimitsBuilder::new()
        .memory_size((mem_mb as usize).saturating_mul(1024 * 1024))
        .build();
    let mut store = Store::new(engine, CmdState { wasi, limits });
    store.limiter(|s: &mut CmdState| &mut s.limits);
    store.set_fuel(fuel).map_err(anyhow::Error::from).context("set fuel")?;

    let mut linker: Linker<CmdState> = Linker::new(engine);
    p1::add_to_linker_sync(&mut linker, |s: &mut CmdState| &mut s.wasi)
        .map_err(anyhow::Error::from)
        .context("add wasi to linker")?;
    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(anyhow::Error::from)
        .context("instantiate")?;
    let start = instance
        .get_typed_func::<(), ()>(&mut store, "_start")
        .map_err(anyhow::Error::from)
        .context("export `_start` (WASI command)")?;
    let call = run_with_watchdog(engine, &mut store, |store| {
        Ok(start.call(store, ()))
    });
    let code = match call? {
        Ok(()) => 0,
        // A WASI command that calls proc_exit traps with I32Exit carrying the exit code.
        Err(e) => match e.downcast_ref::<wasmtime_wasi::I32Exit>() {
            Some(exit) => exit.0,
            None => return Err(anyhow::Error::from(e)).context("wasm trap"),
        },
    };
    drop(store); // drop the module's stdout handle before reading the buffer
    Ok((code, stdout.contents().to_vec()))
}

#[async_trait::async_trait]
impl Runtime for WasmRuntime {
    fn tag(&self) -> &'static str {
        "wasm"
    }

    async fn launch(
        &self,
        workload: &Workload,
        limits: &Limits,
        job_id: [u8; 32],
    ) -> Result<(Handle, Option<String>)> {
        let (module_hash, entry, inputs) = match workload {
            Workload::Wasm { module_hash, entry, inputs, .. } => (*module_hash, entry.clone(), inputs.clone()),
            other => return Err(anyhow!("wasm runtime cannot run a '{}' workload", other.required_tag())),
        };
        let wasm = self.resolve(&module_hash)?;
        let engine = self.engine.clone();
        let fuel = (limits.cpu_cores.max(1) as u64).saturating_mul(FUEL_PER_CORE);
        let mem_mb = limits.mem_mb;
        let handle = Handle(hex::encode(job_id));

        if entry != "_start" {
            // Self-contained `() -> i32` path: detached, no captured output.
            tokio::task::spawn_blocking(move || match execute(&engine, &wasm, &entry, fuel, mem_mb) {
                Ok(code) => tracing::info!("wasm job {} exited {code}", hex::encode(&job_id[..4])),
                Err(e) => tracing::warn!("wasm job {} failed: {e}", hex::encode(&job_id[..4])),
            });
            return Ok((handle, None));
        }

        // WASI command (I/O) path: concatenate the staged input blobs onto stdin, run to
        // completion, and publish stdout to the blob store — returning the output CID.
        //
        // Aggregate-stdin cap: sum the staged input sizes and reject BEFORE concatenating anything
        // into host RAM, so a large multi-input deploy can never OOM the host before the module runs.
        // (Each blob is also individually bounded by `resolve`'s `MAX_MODULE_BYTES` check.)
        let mut total_stdin: u64 = 0;
        for cid in &inputs {
            let len = std::fs::metadata(self.blobs_dir.join(hex::encode(cid)))
                .with_context(|| format!("input {} not staged in blob store", hex::encode(&cid[..4])))?
                .len();
            total_stdin = total_stdin.saturating_add(len);
            if total_stdin > MAX_STDIN_BYTES {
                return Err(anyhow!(
                    "aggregate stdin {total_stdin} bytes exceeds {MAX_STDIN_BYTES}-byte cap"
                ));
            }
        }
        let mut stdin = Vec::with_capacity(total_stdin as usize);
        for cid in &inputs {
            let bytes = self.resolve(cid).with_context(|| {
                format!("input {} not staged in blob store", hex::encode(&cid[..4]))
            })?;
            stdin.extend_from_slice(&bytes);
        }
        let (code, out) = tokio::task::spawn_blocking(move || {
            execute_command(&engine, &wasm, fuel, mem_mb, stdin)
        })
        .await
        .context("wasm command task panicked")??;
        tracing::info!("wasm command job {} exited {code} ({} bytes out)", hex::encode(&job_id[..4]), out.len());

        // Fail closed if the output somehow exceeds the cap before it ever touches disk. The stdout
        // pipe is already bounded at `MAX_STDOUT_BYTES`, so this is belt-and-suspenders: a single
        // centralized constant gates both the in-memory pipe and the disk write (output-blob quota),
        // so an untrusted module can never write an unbounded blob to the host's disk.
        if out.len() > MAX_STDOUT_BYTES {
            return Err(anyhow!(
                "wasm output {} bytes exceeds {MAX_STDOUT_BYTES}-byte cap",
                out.len()
            ));
        }
        // Publish the output to the content-addressed store (same keying as the data layer).
        let cid: [u8; 32] = Sha256::digest(&out).into();
        let hex_cid = hex::encode(cid);
        let _ = std::fs::create_dir_all(&self.blobs_dir);
        std::fs::write(self.blobs_dir.join(&hex_cid), &out).context("store output blob")?;
        Ok((handle, Some(hex_cid)))
    }

    async fn stop(&self, _handle: &Handle) -> Result<()> {
        // WASM jobs are bounded by fuel; explicit interruption (epoch deadlines) is a refinement.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> Engine {
        // Mirror the production engine exactly so tests exercise the real trap-handling config.
        Engine::new(&engine_config()).expect("wasmtime engine")
    }

    #[test]
    fn runs_module_and_returns_exit_code() {
        let wasm = wat::parse_str(r#"(module (func (export "entry") (result i32) i32.const 42))"#).unwrap();
        let code = execute(&engine(), &wasm, "entry", 1_000_000, 16).unwrap();
        assert_eq!(code, 42);
    }

    #[test]
    fn runaway_module_runs_out_of_fuel() {
        // An infinite loop traps once fuel is exhausted — a runaway module can't run forever.
        // The trap MUST come back as a recoverable `Err` on every platform (it must never abort
        // the host process). This previously aborted on Windows ("panic in a function that cannot
        // unwind") because the fuel trap was delivered through signal/SEH-based unwinding into an
        // `extern "C"` libcall; `engine_config()` now sets `signals_based_traps(false)` so traps
        // are returned via explicit checks (and disables backtrace capture), and a wall-clock epoch
        // watchdog backstops fuel regardless. Runs on all platforms to confirm the Windows fix.
        let wasm = wat::parse_str(r#"(module (func (export "entry") (result i32) (loop (br 0)) i32.const 0))"#).unwrap();
        let r = execute(&engine(), &wasm, "entry", 100_000, 16);
        assert!(r.is_err(), "infinite loop must trap on fuel exhaustion");
    }

    #[test]
    fn missing_entry_errors() {
        let wasm = wat::parse_str(r#"(module (func (export "other") (result i32) i32.const 1))"#).unwrap();
        assert!(execute(&engine(), &wasm, "entry", 1_000_000, 16).is_err());
    }

    /// A WASI command that reads up to 256 bytes from stdin and writes them back to stdout.
    const ECHO_WAT: &str = r#"(module
        (import "wasi_snapshot_preview1" "fd_read"  (func $read  (param i32 i32 i32 i32) (result i32)))
        (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
        (memory (export "memory") 1)
        (func (export "_start")
            ;; read iovec @0 -> {buf=64, len=256}; nread @8
            (i32.store (i32.const 0) (i32.const 64))
            (i32.store (i32.const 4) (i32.const 256))
            (drop (call $read (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 8)))
            ;; write iovec @16 -> {buf=64, len=nread}; nwritten @24
            (i32.store (i32.const 16) (i32.const 64))
            (i32.store (i32.const 20) (i32.load (i32.const 8)))
            (drop (call $write (i32.const 1) (i32.const 16) (i32.const 1) (i32.const 24)))))"#;

    #[test]
    fn wasi_command_echoes_stdin_to_stdout() {
        let wasm = wat::parse_str(ECHO_WAT).unwrap();
        let (code, out) =
            execute_command(&engine(), &wasm, 1_000_000_000, 16, b"ce-rocks".to_vec()).unwrap();
        assert_eq!(code, 0, "clean exit");
        assert_eq!(out, b"ce-rocks", "stdout echoes stdin (input -> output)");
    }

    #[test]
    fn blob_resolution_verifies_hash() {
        let dir = std::env::temp_dir().join(format!("ce-wasm-blobs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let wasm = wat::parse_str(r#"(module (func (export "entry") (result i32) i32.const 7))"#).unwrap();
        let hash: [u8; 32] = Sha256::digest(&wasm).into();
        std::fs::write(dir.join(hex::encode(hash)), &wasm).unwrap();

        let rt = WasmRuntime::new(dir.clone()).unwrap();
        assert_eq!(rt.resolve(&hash).unwrap(), wasm, "correct hash resolves");
        assert!(rt.resolve(&[9u8; 32]).is_err(), "unknown hash errors");
    }

    /// A WASI command that writes its whole stdin to stderr (fd 2) and exits cleanly. Used to prove
    /// the host never inherits an untrusted module's stderr.
    const STDERR_WRITER_WAT: &str = r#"(module
        (import "wasi_snapshot_preview1" "fd_read"  (func $read  (param i32 i32 i32 i32) (result i32)))
        (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
        (memory (export "memory") 1)
        (func (export "_start")
            ;; read iovec @0 -> {buf=64, len=256}; nread @8
            (i32.store (i32.const 0) (i32.const 64))
            (i32.store (i32.const 4) (i32.const 256))
            (drop (call $read (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 8)))
            ;; write iovec @16 -> {buf=64, len=nread} to fd 2 (stderr)
            (i32.store (i32.const 16) (i32.const 64))
            (i32.store (i32.const 20) (i32.load (i32.const 8)))
            (drop (call $write (i32.const 2) (i32.const 16) (i32.const 1) (i32.const 24)))))"#;

    #[test]
    fn stderr_is_not_inherited_to_host() {
        // A module that writes to stderr must run cleanly with EMPTY stdout (we route stderr to a
        // bounded, discarded pipe — never the host log). The exit code is 0 and nothing leaks into
        // the published stdout blob. If stderr were inherited this would still pass functionally, but
        // the bytes would hit the operator's log; the guarantee under test is that stdout (the only
        // captured/published surface) stays empty and the run is unaffected.
        let wasm = wat::parse_str(STDERR_WRITER_WAT).unwrap();
        let (code, out) =
            execute_command(&engine(), &wasm, 1_000_000_000, 16, b"leak-me".to_vec()).unwrap();
        assert_eq!(code, 0, "clean exit");
        assert!(out.is_empty(), "stderr output must NOT appear on captured stdout");
    }

    #[test]
    fn oversized_module_rejected_before_alloc() {
        // A blob larger than MAX_MODULE_BYTES is rejected by `resolve` on its on-disk size, before it
        // is ever read into RAM — so an oversized deploy cannot OOM the host.
        let dir = std::env::temp_dir().join(format!("ce-wasm-big-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // We can't cheaply write 64 MiB; instead point a hash at a blob and assert the size gate
        // triggers using a sparse file of the right length.
        let hash = [3u8; 32];
        let path = dir.join(hex::encode(hash));
        let f = std::fs::File::create(&path).unwrap();
        f.set_len(MAX_MODULE_BYTES + 1).unwrap();
        drop(f);
        let rt = WasmRuntime::new(dir.clone()).unwrap();
        let err = rt.resolve(&hash).unwrap_err().to_string();
        assert!(err.contains("exceeds"), "oversized module must be rejected: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_aggregate_stdin_rejected_before_alloc() {
        // Two sparse input blobs whose sizes sum past MAX_STDIN_BYTES must be rejected by `launch`
        // before any concatenation into host RAM. Each blob individually is under MAX_MODULE_BYTES,
        // so only the AGGREGATE cap can catch this.
        let dir = std::env::temp_dir().join(format!("ce-wasm-stdin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // A trivial _start module is enough; we never reach execution.
        let module = wat::parse_str(r#"(module (func (export "_start")))"#).unwrap();
        let mod_hash: [u8; 32] = Sha256::digest(&module).into();
        std::fs::write(dir.join(hex::encode(mod_hash)), &module).unwrap();

        // Each input is half of MAX_STDIN_BYTES + 1, so together they exceed the cap but each is far
        // under MAX_MODULE_BYTES would-be limit (they are < 64 MiB? no — they are 128 MiB each).
        // Use sparse files; only metadata().len() is consulted before rejection.
        let chunk = MAX_STDIN_BYTES / 2 + 1;
        let mut inputs = Vec::new();
        for i in 0..2u8 {
            let cid = [10u8 + i; 32];
            let f = std::fs::File::create(dir.join(hex::encode(cid))).unwrap();
            f.set_len(chunk).unwrap();
            drop(f);
            inputs.push(cid);
        }
        let rt = WasmRuntime::new(dir.clone()).unwrap();
        let workload = Workload::Wasm {
            module_hash: mod_hash,
            entry: "_start".into(),
            inputs,
            args: vec![],
        };
        let limits = Limits { cpu_cores: 1, mem_mb: 16 };
        let rt2 = &rt;
        let res = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async { rt2.launch(&workload, &limits, [0u8; 32]).await });
        let err = res.unwrap_err().to_string();
        assert!(err.contains("aggregate stdin"), "oversized aggregate stdin must be rejected: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn deterministic_config_yields_identical_output_cid() {
        // The same module + input must produce the same output bytes (hence the same output CID) on
        // every run, with a fresh engine each time — the property `swarm verify` relies on.
        let wasm = wat::parse_str(ECHO_WAT).unwrap();
        let run = || {
            let (_code, out) =
                execute_command(&engine(), &wasm, 1_000_000_000, 16, b"determinism".to_vec()).unwrap();
            let cid: [u8; 32] = Sha256::digest(&out).into();
            cid
        };
        let a = run();
        let b = run();
        assert_eq!(a, b, "same module + input must yield identical output CID across runs");
    }
}
