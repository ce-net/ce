//! Phase 7 (P7) — producer-unbiasable placement beacon for committee/auditor selection.
//!
//! Governs: design `2(b)` "MANDATORY anti-grind for the PLACEMENT beacon", `2(c)`(1) anti-collusion
//! primitive, and `6` Phase 7. This is the entropy source that seeds verifier/committee/replica
//! placement for the audit dial (verification.rs). It MUST NOT be the grindable `/beacon` tip and
//! MUST NOT be mere confirmed-depth: the slot leader who PRODUCES the seed block can withhold or
//! re-roll it (Sia future-block-hash failure, red-team H4/H11). It is a SEPARATE stream from the
//! block-production VRF stream and does not change leader election (design `3` cooperation note).
//!
//! Four mandatory components (design `2(b)` 1-4):
//!  1. Mandatory Wesolowski VDF over the seed with delay `T_vdf >> slot time`, so by the time a
//!     leader could compute the resulting committee, the withholding window has closed.
//!  2. Aggregate the seed over a moving window of >=64 distinct block producers' VRF outputs
//!     (RANDAO-style XOR over LOOKBACK..LOOKBACK+W) — a single withholder controls <=1/W of entropy.
//!  3. Commit-reveal^2 among >=2 independent beacon contributors for the highest-value draws.
//!  4. Cap any single weight-holder's leadership share feeding the placement beacon.
//!
//! CRYPTO RULE (task constraint): use a VETTED VDF crate behind the `Vdf` trait below. If a real
//! Wesolowski/Pietrzak crate breaks the build (heavy C deps), the scaffold ships a clearly-marked
//! PLACEHOLDER impl with a TODO to swap the real crate — NEVER a hand-rolled VDF.

/// Number of distinct block producers' VRF outputs aggregated into the placement seed
/// (design `2(b)` 2: ">=64 distinct block producers"). Matches `ce_chain::LOOKBACK`.
pub const BEACON_WINDOW: u64 = 64;

/// A verifiable-delay-function over the aggregated seed (design `2(b)` 1, mandatory). Implementors
/// MUST back this with a vetted Wesolowski/Pietrzak crate — never a hand-rolled construction.
pub trait Vdf {
    /// Evaluate the VDF on `seed` for `delay` sequential steps, returning the output and a proof.
    fn eval(&self, seed: &[u8; 32], delay: u64) -> (Vec<u8>, Vec<u8>);
    /// Verify a VDF output + proof for `seed`/`delay` in (poly)log time.
    fn verify(&self, seed: &[u8; 32], delay: u64, output: &[u8], proof: &[u8]) -> bool;
}

/// PLACEHOLDER VDF — NOT a real verifiable delay function. It does NOT impose a sequential delay
/// and provides ZERO grinding resistance; it exists only so the scaffold compiles and the
/// placement-beacon plumbing can be wired and tested end-to-end.
///
/// TODO(P7): replace with a vetted Wesolowski VDF crate (e.g. a class-group / RSA-group impl) with
/// real `eval`/`verify`. DO NOT ship this placeholder to mainnet — it is consensus-insecure.
#[doc(hidden)]
pub struct PlaceholderVdf;

impl Vdf for PlaceholderVdf {
    fn eval(&self, seed: &[u8; 32], _delay: u64) -> (Vec<u8>, Vec<u8>) {
        // TODO(P7): real sequential squaring in a group of unknown order.
        (seed.to_vec(), Vec::new())
    }
    fn verify(&self, seed: &[u8; 32], _delay: u64, output: &[u8], _proof: &[u8]) -> bool {
        // TODO(P7): real Wesolowski verification. Placeholder accepts the identity output only.
        output == seed
    }
}

/// Aggregate a window of distinct producers' VRF outputs into a single seed (design `2(b)` 2,
/// RANDAO-style XOR). `vrf_outputs` is the >=BEACON_WINDOW most recent distinct-producer outputs.
///
/// TODO(P7): XOR-fold (or hash-to-curve aggregate) with distinct-producer enforcement.
pub fn aggregate_seed(vrf_outputs: &[[u8; 32]]) -> [u8; 32] {
    let mut acc = [0u8; 32];
    for o in vrf_outputs {
        for (a, b) in acc.iter_mut().zip(o.iter()) {
            *a ^= *b;
        }
    }
    acc // TODO(P7): enforce >=BEACON_WINDOW distinct producers + cap per-holder share.
}

/// Derive the final placement seed for a job above the value threshold: aggregate the window, then
/// run it through the mandatory VDF so the block producer cannot withhold/re-roll based on an
/// outcome it cannot yet see (design `2(b)` 1+2). Returns the VDF output used to seat committees.
///
/// TODO(P7): commit-reveal^2 (component 3) for the highest-value draws.
pub fn placement_seed<V: Vdf>(vdf: &V, vrf_outputs: &[[u8; 32]], delay: u64) -> Vec<u8> {
    let seed = aggregate_seed(vrf_outputs);
    let (output, _proof) = vdf.eval(&seed, delay);
    output // TODO(P7): also return + verify the proof on consumption.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_vdf_roundtrips_identity() {
        let v = PlaceholderVdf;
        let seed = [7u8; 32];
        let (out, proof) = v.eval(&seed, 1000);
        assert!(v.verify(&seed, 1000, &out, &proof));
    }

    #[test]
    fn aggregate_xor_is_order_independent() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(aggregate_seed(&[a, b]), aggregate_seed(&[b, a]));
    }
}
