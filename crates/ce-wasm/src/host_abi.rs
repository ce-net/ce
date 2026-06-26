//! Capability-gated CE host ABI for WASM modules (P2).
//!
//! This is the surface through which an **untrusted** WASM module reaches CE primitives — the
//! blob store and the host log — and **only** when the job presents a signed, verified `ce-cap`
//! capability chain that grants the matching ability. There is no ambient access: a module that
//! is launched without host services *or* without a capability cannot call any of these functions
//! (their imports are simply not registered, so a module importing them fails to instantiate). The
//! pure-compute path (empty linker) and the plain-WASI path are therefore left entirely unchanged —
//! the host ABI is **opt-in** at launch time.
//!
//! ## The three host functions (module namespace `"ce"`)
//!
//! - `ce_log(ptr: i32, len: i32)` — requires ability `"ce:log"`. Reads `len` bytes of UTF-8
//!   (lossy) from guest memory at `ptr` and forwards them to the host via [`HostServices::log`].
//!   On a missing capability or out-of-bounds buffer it **traps** (there is no return value to
//!   carry an error code).
//! - `ce_blob_read(cid_ptr: i32, cid_len: i32, out_ptr: i32, out_cap: i32) -> i32` — requires
//!   ability `"ce:blob.read"`. Reads a `cid_len`-byte UTF-8 CID string from `cid_ptr`, looks the
//!   blob up via [`HostServices::blob_read`], and copies up to `out_cap` bytes into the guest
//!   buffer at `out_ptr`. Returns the number of bytes written, or a negative [error code](#errors).
//! - `ce_blob_write(ptr: i32, len: i32, out_cid_ptr: i32, out_cid_cap: i32) -> i32` — requires
//!   ability `"ce:blob.write"`. Reads `len` bytes from `ptr`, stores them via
//!   [`HostServices::blob_write`] (returning the CID hex string), and copies the CID string into
//!   the guest buffer at `out_cid_ptr` (bounded by `out_cid_cap`). Returns the number of CID bytes
//!   written, or a negative [error code](#errors).
//!
//! ## Marshalling convention (caller-owns-buffers)
//!
//! The convention is the simplest correct one: **the guest owns and sizes every buffer**. For an
//! input (`ptr`/`len`, `cid_ptr`/`cid_len`) the guest passes a pointer into its own linear memory
//! plus the exact byte length; the host reads that range. For an output (`out_ptr`/`out_cap`,
//! `out_cid_ptr`/`out_cid_cap`) the guest passes a pointer to a buffer it has reserved plus the
//! buffer's **capacity**; the host writes at most `cap` bytes and returns the count actually
//! written, so the guest learns the real length from the return value. If the host's data does not
//! fit in `cap`, the call fails with [`ERR_OUT_OF_BOUNDS`] rather than truncating silently. All
//! pointers/lengths are validated against the guest's exported `"memory"` before any copy; an
//! out-of-range range yields [`ERR_OUT_OF_BOUNDS`] (or a trap, for `ce_log`).
//!
//! <a name="errors"></a>
//! ## Error codes (negative return values)
//!
//! - [`ERR_NO_CAP`] (`-1`) — no capability, or the chain does not grant the required ability.
//! - [`ERR_OUT_OF_BOUNDS`] (`-2`) — a pointer/length (in or out) is outside guest memory, or the
//!   host result does not fit the supplied output capacity.
//! - [`ERR_NO_MEMORY`] (`-3`) — the guest does not export a `"memory"`.
//! - [`ERR_NOT_FOUND`] (`-4`) — `ce_blob_read` for a CID the host does not hold.
//!
//! ## Fuel-as-gas
//!
//! Every host call deducts a fixed [`HOST_CALL_FUEL`] from the Store's fuel before doing any work,
//! so reaching into CE primitives costs gas just like executing instructions. If the Store has
//! insufficient fuel the call traps (fuel exhaustion), exactly like a runaway compute loop.
//!
//! Mission/scale: this gate is what lets the network safely run a stranger's WASM on a
//! stranger's hardware. Designed so that across millions of donated devices a guest reaches
//! host blobs or logging only through a signed, verified ability, pooled compute stays
//! sandboxed by default and authority is carried explicitly rather than ambiently trusted.

use std::sync::Arc;

use anyhow::Result;
use ce_cap::SignedCapability;
use ce_identity::NodeId;
// wasmtime 46 has its OWN error type (not `anyhow::Error`) and deliberately does not implement
// `From<anyhow::Error>`, so `func_wrap` host functions must return `wasmtime::Result<_>` for
// `IntoFunc` to resolve (`WasmRet` is implemented for `Result<T, wasmtime::Error>`, not the anyhow
// one). Host functions below use this alias; `register` keeps `anyhow::Result` for its caller.
use wasmtime::{Caller, Error as WtError, Linker, Result as WtResult};

/// Host services a WASM module may reach through the capability-gated ABI. Kept deliberately to
/// three methods — the node supplies a concrete implementation (wired to its blob store + log).
pub trait HostServices: Send + Sync {
    /// Resolve a content-addressed blob by its CID (hex sha256). `None` if not held.
    fn blob_read(&self, cid: &str) -> Option<Vec<u8>>;
    /// Store `bytes` in the content-addressed blob store, returning the CID (hex sha256).
    fn blob_write(&self, bytes: &[u8]) -> String;
    /// Emit a diagnostic line from a module on behalf of the host.
    fn log(&self, msg: &str);
}

/// A verified `ce-cap` capability chain plus the context needed to re-check an ability on each host
/// call. The chain is expected to already verify to an accepted root (the node self-issues it); the
/// per-call [`authorize`](ce_cap::authorize) re-run is what binds each host action to a granted
/// ability string, so a module can only do what the chain explicitly permits.
#[derive(Clone)]
pub struct HostCapability {
    /// The enforcing node's id (the chain's accepted root and the requester, for a self-issued chain).
    pub node_id: NodeId,
    /// The verified chain (root-first), as produced/verified by the node.
    pub chain: Arc<Vec<SignedCapability>>,
}

impl HostCapability {
    /// Does the chain grant `ability` right now? Re-runs [`ce_cap::authorize`] with the node as both
    /// accepted root and requester (the host-ABI capability is node-self-issued). Returns `false` on
    /// any verification failure — fail-closed.
    pub fn grants(&self, ability: &str) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let never_revoked = |_: &NodeId, _: u64| false;
        ce_cap::authorize(
            &self.node_id,
            &[],
            &[],
            now,
            &self.node_id,
            ability,
            &self.chain,
            &never_revoked,
        )
        .is_ok()
    }
}

/// Ability strings checked by the three host functions.
pub const ABILITY_LOG: &str = "ce:log";
pub const ABILITY_BLOB_READ: &str = "ce:blob.read";
pub const ABILITY_BLOB_WRITE: &str = "ce:blob.write";

/// Fuel deducted per host call (fuel-as-gas). A fixed price so a module is billed for touching CE
/// primitives, not only for raw instructions. Sized well below a normal job budget so legitimate
/// host calls succeed, yet non-trivial so spamming the ABI consumes the fuel budget.
pub const HOST_CALL_FUEL: u64 = 10_000;

/// Negative return codes (see the module-level rustdoc).
pub const ERR_NO_CAP: i32 = -1;
pub const ERR_OUT_OF_BOUNDS: i32 = -2;
pub const ERR_NO_MEMORY: i32 = -3;
pub const ERR_NOT_FOUND: i32 = -4;

/// Maximum bytes a single `ce_blob_write` may store — a host-side bound so a module cannot make the
/// host buffer an unbounded blob through the ABI. Matches the spirit of the stdout cap.
const MAX_HOST_BLOB_BYTES: usize = 16 * 1024 * 1024;

/// The per-call host context carried in the wasmtime Store for the host-ABI execution path. When
/// `host`/`cap` are present the `"ce"` imports are registered and usable; the no-host paths
/// (`execute`, `execute_command`) never construct this, so they keep their original behavior.
#[derive(Clone)]
pub struct HostCtx {
    pub host: Arc<dyn HostServices>,
    pub cap: HostCapability,
}

/// wasmtime Store state for the **capability-gated host-ABI** execution path: the memory limiter,
/// the per-call [`HostCtx`] the `ce` host functions read, and — when the module is a WASI command —
/// the WASI context. The two no-host paths (`execute`, `execute_command`) use their own Store state
/// and never construct this, so they keep their original behavior unchanged. Kept concrete (not a
/// trait object behind a generic) so the `func_wrap` closures resolve `IntoFunc` without inference.
pub struct HostState {
    pub limits: wasmtime::StoreLimits,
    pub host_ctx: HostCtx,
    pub wasi: Option<wasmtime_wasi::p1::WasiP1Ctx>,
}

/// Charge [`HOST_CALL_FUEL`] from the Store. Traps (returns `Err`) on insufficient fuel, so a host
/// call that cannot pay its gas fails exactly like fuel exhaustion in compute.
fn charge_gas(caller: &mut Caller<'_, HostState>) -> WtResult<()> {
    let fuel = caller.get_fuel().unwrap_or(0);
    if fuel < HOST_CALL_FUEL {
        return Err(WtError::msg(format!("out of fuel: host call costs {HOST_CALL_FUEL}")));
    }
    caller.set_fuel(fuel - HOST_CALL_FUEL)
}

/// Fetch the guest's exported linear memory, or `None` if it exports none.
fn guest_memory(caller: &mut Caller<'_, HostState>) -> Option<wasmtime::Memory> {
    match caller.get_export("memory") {
        Some(wasmtime::Extern::Memory(m)) => Some(m),
        _ => None,
    }
}

/// Read `len` bytes from guest memory at `ptr`. Returns `None` if the range is out of bounds.
/// Takes the [`Caller`] concretely so [`wasmtime::Memory::data`] (which needs `Into<StoreContext>`)
/// resolves its store type.
fn read_guest(mem: &wasmtime::Memory, caller: &Caller<'_, HostState>, ptr: i32, len: i32) -> Option<Vec<u8>> {
    let ptr = usize::try_from(ptr).ok()?;
    let len = usize::try_from(len).ok()?;
    let data = mem.data(caller);
    let end = ptr.checked_add(len)?;
    data.get(ptr..end).map(|s| s.to_vec())
}

/// Write `bytes` into guest memory at `ptr`. Returns `false` if the range is out of bounds.
fn write_guest(mem: &wasmtime::Memory, caller: &mut Caller<'_, HostState>, ptr: i32, bytes: &[u8]) -> bool {
    let Ok(ptr) = usize::try_from(ptr) else { return false };
    let data = mem.data_mut(caller);
    let Some(end) = ptr.checked_add(bytes.len()) else { return false };
    match data.get_mut(ptr..end) {
        Some(dst) => {
            dst.copy_from_slice(bytes);
            true
        }
        None => false,
    }
}

/// ce_log(ptr, len): requires "ce:log". No return value, so a denied/invalid call traps.
fn ce_log(mut caller: Caller<'_, HostState>, ptr: i32, len: i32) -> WtResult<()> {
    charge_gas(&mut caller)?;
    if !caller.data().host_ctx.cap.grants(ABILITY_LOG) {
        return Err(WtError::msg(format!("capability does not grant {ABILITY_LOG}")));
    }
    let mem =
        guest_memory(&mut caller).ok_or_else(|| WtError::msg("guest exports no memory"))?;
    let bytes = read_guest(&mem, &caller, ptr, len)
        .ok_or_else(|| WtError::msg("ce_log buffer out of bounds"))?;
    let msg = String::from_utf8_lossy(&bytes);
    caller.data().host_ctx.host.log(&msg);
    Ok(())
}

/// ce_blob_read(cid_ptr, cid_len, out_ptr, out_cap) -> bytes_written | negative error.
fn ce_blob_read(
    mut caller: Caller<'_, HostState>,
    cid_ptr: i32,
    cid_len: i32,
    out_ptr: i32,
    out_cap: i32,
) -> WtResult<i32> {
    charge_gas(&mut caller)?;
    if !caller.data().host_ctx.cap.grants(ABILITY_BLOB_READ) {
        return Ok(ERR_NO_CAP);
    }
    let Some(mem) = guest_memory(&mut caller) else { return Ok(ERR_NO_MEMORY) };
    let Some(cid_bytes) = read_guest(&mem, &caller, cid_ptr, cid_len) else {
        return Ok(ERR_OUT_OF_BOUNDS);
    };
    let cid = String::from_utf8_lossy(&cid_bytes).into_owned();
    let Some(blob) = caller.data().host_ctx.host.blob_read(&cid) else {
        return Ok(ERR_NOT_FOUND);
    };
    let cap = match usize::try_from(out_cap) {
        Ok(c) => c,
        Err(_) => return Ok(ERR_OUT_OF_BOUNDS),
    };
    if blob.len() > cap {
        return Ok(ERR_OUT_OF_BOUNDS);
    }
    if !write_guest(&mem, &mut caller, out_ptr, &blob) {
        return Ok(ERR_OUT_OF_BOUNDS);
    }
    Ok(blob.len() as i32)
}

/// ce_blob_write(ptr, len, out_cid_ptr, out_cid_cap) -> cid_bytes_written | negative error.
fn ce_blob_write(
    mut caller: Caller<'_, HostState>,
    ptr: i32,
    len: i32,
    out_cid_ptr: i32,
    out_cid_cap: i32,
) -> WtResult<i32> {
    charge_gas(&mut caller)?;
    if !caller.data().host_ctx.cap.grants(ABILITY_BLOB_WRITE) {
        return Ok(ERR_NO_CAP);
    }
    let Some(mem) = guest_memory(&mut caller) else { return Ok(ERR_NO_MEMORY) };
    let Some(payload) = read_guest(&mem, &caller, ptr, len) else {
        return Ok(ERR_OUT_OF_BOUNDS);
    };
    if payload.len() > MAX_HOST_BLOB_BYTES {
        return Ok(ERR_OUT_OF_BOUNDS);
    }
    let cid = caller.data().host_ctx.host.blob_write(&payload);
    let cid_bytes = cid.as_bytes();
    let cap = match usize::try_from(out_cid_cap) {
        Ok(c) => c,
        Err(_) => return Ok(ERR_OUT_OF_BOUNDS),
    };
    if cid_bytes.len() > cap {
        return Ok(ERR_OUT_OF_BOUNDS);
    }
    let cid_owned = cid_bytes.to_vec();
    if !write_guest(&mem, &mut caller, out_cid_ptr, &cid_owned) {
        return Ok(ERR_OUT_OF_BOUNDS);
    }
    Ok(cid_owned.len() as i32)
}

/// Register the capability-gated `"ce"` host functions on `linker`. Only called from the host-ABI
/// execution path, so the pure-compute and plain-WASI linkers never gain these imports. The three
/// functions are passed as named `fn` items (not closures) so `IntoFunc` resolves unambiguously.
pub fn register(linker: &mut Linker<HostState>) -> Result<()> {
    linker.func_wrap("ce", "ce_log", ce_log)?;
    linker.func_wrap("ce", "ce_blob_read", ce_blob_read)?;
    linker.func_wrap("ce", "ce_blob_write", ce_blob_write)?;
    Ok(())
}
