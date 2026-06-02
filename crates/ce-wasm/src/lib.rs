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
//! Either way execution is **fuel-metered** and **memory-capped**, so an untrusted module is
//! bounded without a container. WASM is deterministic, which makes it ideal for `swarm verify`.

use anyhow::{anyhow, Context, Result};
use ce_runtime::{Handle, Limits, Runtime, Workload};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};

/// Fuel granted per CPU core. Fuel ≈ executed wasm instructions; this bounds run time. A core
/// gets a generous budget so normal compute completes, while a runaway loop still traps.
const FUEL_PER_CORE: u64 = 10_000_000_000;

/// `Runtime` backend that executes WebAssembly modules via wasmtime.
pub struct WasmRuntime {
    engine: Engine,
    /// Directory of content-addressed blobs: `<blobs_dir>/<hex(sha256)>` holds module bytes.
    blobs_dir: PathBuf,
}

impl WasmRuntime {
    pub fn new(blobs_dir: PathBuf) -> Result<Self> {
        let mut config = Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config).context("wasmtime engine")?;
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
    func.call(&mut store, ()).context("wasm trap")
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
    let code = match start.call(&mut store, ()) {
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
        let mut c = Config::new();
        c.consume_fuel(true);
        Engine::new(&c).unwrap()
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
