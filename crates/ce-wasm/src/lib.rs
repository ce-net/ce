//! WebAssembly execution backend for CE.
//!
//! A wasmtime-based [`ce_runtime::Runtime`] so a Docker-less machine (and, later, a browser) can
//! host work. Modules are **content-addressed**: a `Workload::Wasm { module_hash, .. }` is
//! resolved from a local blob directory and its sha256 verified before running — tamper-proof.
//! Execution is **fuel-metered** (a runaway module traps when fuel runs out) and **memory-capped**
//! (linear memory limited), so an untrusted module is bounded without a container.
//!
//! v0 runs an exported `entry` function with signature `() -> i32` (an exit code), no WASI/args
//! yet. WASM is deterministic (no ambient nondeterminism), which makes it ideal for `swarm verify`
//! redundancy — the same module on K hosts yields identical output.

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

    // No imports in v0 — the module must be self-contained (no WASI yet).
    let linker: Linker<StoreLimits> = Linker::new(engine);
    let instance = linker.instantiate(&mut store, &module).context("instantiate")?;
    let func = instance
        .get_typed_func::<(), i32>(&mut store, entry)
        .with_context(|| format!("export `{entry}` with signature () -> i32"))?;
    func.call(&mut store, ()).context("wasm trap")
}

#[async_trait::async_trait]
impl Runtime for WasmRuntime {
    fn tag(&self) -> &'static str {
        "wasm"
    }

    async fn launch(&self, workload: &Workload, limits: &Limits, job_id: [u8; 32]) -> Result<Handle> {
        let (module_hash, entry) = match workload {
            Workload::Wasm { module_hash, entry, .. } => (*module_hash, entry.clone()),
            other => return Err(anyhow!("wasm runtime cannot run a '{}' workload", other.required_tag())),
        };
        let wasm = self.resolve(&module_hash)?;
        let engine = self.engine.clone();
        let fuel = (limits.cpu_cores.max(1) as u64).saturating_mul(FUEL_PER_CORE);
        let mem_mb = limits.mem_mb;
        // Detached: WASM compute runs to completion on a blocking thread, bounded by fuel/memory.
        // (Explicit interruption via epoch deadlines is a refinement; fuel already bounds runtime.)
        tokio::task::spawn_blocking(move || match execute(&engine, &wasm, &entry, fuel, mem_mb) {
            Ok(code) => tracing::info!("wasm job {} exited {code}", hex::encode(&job_id[..4])),
            Err(e) => tracing::warn!("wasm job {} failed: {e}", hex::encode(&job_id[..4])),
        });
        Ok(Handle(hex::encode(job_id)))
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
