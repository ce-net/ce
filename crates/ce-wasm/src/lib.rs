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
//! is bounded without a container. WASM is deterministic, which makes it ideal for `swarm verify`.
//!
//! Trap delivery is configured to be **recoverable on every platform**: a runaway module that
//! exhausts its fuel (or its wall-clock deadline) returns a catchable `Err`, never aborts the host
//! process. See [`engine_config`] for the Windows-specific reason backtrace capture is disabled.

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

/// Epoch tick interval for the watchdog. Each tick increments the engine epoch; the store's epoch
/// deadline is `MAX_WALL_CLOCK / WATCHDOG_TICK` ticks, so the module is interrupted within roughly
/// one tick of the wall ceiling. Smaller = tighter bound but more wakeups.
const WATCHDOG_TICK: Duration = Duration::from_secs(1);

/// Build the wasmtime [`Config`] used for all CE execution. Centralized so every engine (runtime
/// and tests) shares the exact same trap-handling configuration.
///
/// Two settings are load-bearing for **safely** running untrusted modules:
///
/// 1. `wasm_backtrace(false)` — when a trap fires (notably **fuel exhaustion** on a runaway loop),
///    wasmtime delivers it from an `out_of_gas` libcall via an unwind back to the host trampoline.
///    Capturing a WASM backtrace on that path walks frames using native unwind info; on **Windows**
///    a failure there panics *inside* an `extern "C"` libcall, which "cannot unwind" and **aborts
///    the whole process** instead of returning a catchable `Err`. We don't need the backtrace
///    (we log a plain trap), so disabling its capture removes the aborting path while the trap is
///    still returned as `Err`. (See wasmtime `Config::wasm_backtrace`: disabling only drops the
///    backtrace context from the error; the trap is still surfaced.)
///
/// 2. `epoch_interruption(true)` — arms the wall-clock watchdog (see [`run_with_watchdog`]). This is
///    defense-in-depth on top of fuel: an untrusted module is bounded by both instruction count
///    *and* wall time, on every platform, regardless of any trap-delivery quirk.
fn engine_config() -> Config {
    let mut config = Config::new();
    config.consume_fuel(true);
    config.epoch_interruption(true);
    // See doc comment above: avoids the Windows "cannot unwind" abort on fuel/epoch traps.
    config.wasm_backtrace(false);
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
        let engine = Engine::new(&engine_config()).context("wasmtime engine")?;
        Ok(Self { engine, blobs_dir })
    }

    /// Resolve a content-addressed module from the blob store, verifying its hash.
    fn resolve(&self, module_hash: &[u8; 32]) -> Result<Vec<u8>> {
        let path = self.blobs_dir.join(hex::encode(module_hash));
        let bytes = std::fs::read(&path)
            .with_context(|| format!("module {} not in blob store", hex::encode(&module_hash[..4])))?;
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
    let module = Module::new(engine, wasm).context("compile module")?;
    let limits = StoreLimitsBuilder::new()
        .memory_size((mem_mb as usize).saturating_mul(1024 * 1024))
        .build();
    let mut store = Store::new(engine, limits);
    store.limiter(|l: &mut StoreLimits| l);
    store.set_fuel(fuel).context("set fuel")?;

    // No imports — the module must be self-contained (the WASI path is `execute_command`).
    let linker: Linker<StoreLimits> = Linker::new(engine);
    let instance = linker.instantiate(&mut store, &module).context("instantiate")?;
    let func = instance
        .get_typed_func::<(), i32>(&mut store, entry)
        .with_context(|| format!("export `{entry}` with signature () -> i32"))?;
    run_with_watchdog(engine, &mut store, |store| {
        func.call(store, ()).context("wasm trap")
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
    use wasmtime_wasi::pipe::{MemoryInputPipe, MemoryOutputPipe};
    use wasmtime_wasi::preview1::{self, WasiP1Ctx};
    use wasmtime_wasi::WasiCtxBuilder;

    // Store data carries both the WASI context and the memory limiter.
    struct CmdState {
        wasi: WasiP1Ctx,
        limits: StoreLimits,
    }

    let module = Module::new(engine, wasm).context("compile module")?;
    // 16 MiB stdout cap — bounds a runaway writer; the produced output blob can't exceed it.
    let stdout = MemoryOutputPipe::new(16 * 1024 * 1024);
    let wasi = WasiCtxBuilder::new()
        .stdin(MemoryInputPipe::new(stdin))
        .stdout(stdout.clone())
        .inherit_stderr()
        .build_p1();
    let limits = StoreLimitsBuilder::new()
        .memory_size((mem_mb as usize).saturating_mul(1024 * 1024))
        .build();
    let mut store = Store::new(engine, CmdState { wasi, limits });
    store.limiter(|s: &mut CmdState| &mut s.limits);
    store.set_fuel(fuel).context("set fuel")?;

    let mut linker: Linker<CmdState> = Linker::new(engine);
    preview1::add_to_linker_sync(&mut linker, |s: &mut CmdState| &mut s.wasi)
        .context("add wasi to linker")?;
    let instance = linker.instantiate(&mut store, &module).context("instantiate")?;
    let start = instance
        .get_typed_func::<(), ()>(&mut store, "_start")
        .context("export `_start` (WASI command)")?;
    let call = run_with_watchdog(engine, &mut store, |store| Ok(start.call(store, ())));
    let code = match call? {
        Ok(()) => 0,
        // A WASI command that calls proc_exit traps with I32Exit carrying the exit code.
        Err(e) => match e.downcast_ref::<wasmtime_wasi::I32Exit>() {
            Some(exit) => exit.0,
            None => return Err(e).context("wasm trap"),
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
        let mut stdin = Vec::new();
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
        // unwind") because the fuel trap captured a WASM backtrace, walking native unwind info from
        // inside an `extern "C"` libcall; `engine_config()` now disables backtrace capture
        // (`wasm_backtrace(false)`), and a wall-clock epoch watchdog backstops fuel regardless.
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
}
