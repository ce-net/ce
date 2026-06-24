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
//! CRYPTO RULE (task constraint): use a VETTED VDF crate behind the `Vdf` trait below. The vetted
//! POA-Network Wesolowski/Pietrzak class-group crate (`vdf 0.1`, pure-Rust, no GMP) is wired as
//! [`RealVdf`] behind the OPTIONAL `real-vdf` cargo feature; the default build ships the clearly-
//! marked, consensus-INSECURE [`PlaceholderVdf`] so the shared repo stays warning-free. NEVER a
//! hand-rolled VDF.
//!
//! ## needs-review (crypto)
//! - The VDF *core* is delegated to the vetted crate behind [`RealVdf`]; the default [`PlaceholderVdf`]
//!   is explicitly NOT a VDF. A reviewer must confirm `RealVdf`'s difficulty/parameter mapping and the
//!   discriminant size before any mainnet use (see [`RealVdf`] docs). Marked needs-review.
//! - The commit-reveal^2 helpers ([`commit`], [`reveal_ok`]) cover the binding/hiding step; the
//!   >=2-independent-contributor scheduling + slashing of a non-revealer is consensus/scheduler policy
//!   layered on top (design `2(b)` 3) and is out of this pure module's scope.

use sha2::{Digest, Sha256};

/// Number of distinct block producers' VRF outputs aggregated into the placement seed
/// (design `2(b)` 2: ">=64 distinct block producers"). Matches `ce_chain::LOOKBACK`.
pub const BEACON_WINDOW: u64 = 64;

/// The maximum number of window slots a single weight-holder (producer) may contribute to one
/// placement seed (design `2(b)` 4: "cap any single weight-holder's leadership share feeding the
/// placement beacon"). With distinct-producer enforcement this is 1 by construction; the constant
/// documents the cap and is used by [`aggregate_seed_checked`] to reject an over-represented window.
pub const MAX_SHARE_PER_PRODUCER: usize = 1;

/// A verifiable-delay-function over the aggregated seed (design `2(b)` 1, mandatory). Implementors
/// MUST back this with a vetted Wesolowski/Pietrzak crate — never a hand-rolled construction.
pub trait Vdf {
    /// Evaluate the VDF on `seed` for `delay` sequential steps, returning the output and a proof.
    fn eval(&self, seed: &[u8; 32], delay: u64) -> (Vec<u8>, Vec<u8>);
    /// Verify a VDF output + proof for `seed`/`delay` in (poly)log time.
    fn verify(&self, seed: &[u8; 32], delay: u64, output: &[u8], proof: &[u8]) -> bool;
}

/// PLACEHOLDER VDF — NOT a real verifiable delay function. It does NOT impose a sequential delay
/// and provides ZERO grinding resistance; it exists only so the default build compiles and the
/// placement-beacon plumbing can be wired and tested end-to-end WITHOUT pulling the unmaintained
/// `vdf` crate (and its `sha2 0.8` future-incompat warning) into every consensus build.
///
/// needs-review (crypto): this is consensus-INSECURE by construction. DO NOT ship to mainnet.
/// Build with `--features real-vdf` and select [`RealVdf`] for any network routing audit-seed value
/// above the trivial threshold (design `2(b)`, MANDATORY VDF).
#[doc(hidden)]
pub struct PlaceholderVdf;

impl Vdf for PlaceholderVdf {
    fn eval(&self, seed: &[u8; 32], _delay: u64) -> (Vec<u8>, Vec<u8>) {
        // Identity "output", empty proof. NOT a sequential delay. The verify side accepts only this
        // identity so the placeholder cannot be confused with a real proof on the wire.
        (seed.to_vec(), Vec::new())
    }
    fn verify(&self, seed: &[u8; 32], _delay: u64, output: &[u8], _proof: &[u8]) -> bool {
        output == seed
    }
}

/// Vetted Wesolowski VDF adapter (POA Network `vdf 0.1`, pure-Rust class-group, no GMP), gated
/// behind the OPTIONAL `real-vdf` cargo feature. This is the production VDF for the placement beacon.
///
/// needs-review (crypto): the class-group discriminant size (`int_size_bits`) and the `delay ->
/// difficulty` mapping are security parameters. The defaults here ([`RealVdf::new`] uses a 2048-bit
/// discriminant, the crate's recommended size) MUST be reviewed and pinned against the live
/// `T_vdf >> slot time` requirement (design `2(b)` 1) before mainnet. The crate is unmaintained;
/// a reviewer should confirm no known soundness break exists for the chosen parameters.
#[cfg(feature = "real-vdf")]
pub struct RealVdf {
    int_size_bits: u16,
}

#[cfg(feature = "real-vdf")]
impl RealVdf {
    /// Construct with the crate-recommended 2048-bit class-group discriminant. needs-review: pin
    /// this and the delay->difficulty mapping for the target `T_vdf`.
    pub fn new() -> Self {
        Self { int_size_bits: 2048 }
    }
}

#[cfg(feature = "real-vdf")]
impl Default for RealVdf {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "real-vdf")]
impl Vdf for RealVdf {
    fn eval(&self, seed: &[u8; 32], delay: u64) -> (Vec<u8>, Vec<u8>) {
        use vdf::{VDFParams, WesolowskiVDFParams, VDF as _};
        let vdf = WesolowskiVDFParams(self.int_size_bits).new();
        // `solve` returns the proof bytes; the crate folds the output into the proof. We carry the
        // proof as the "output" and the seed-derived solution length implicitly; `verify` re-checks
        // against the seed. An over-large/invalid difficulty yields an empty proof (caller rejects).
        match vdf.solve(seed, delay) {
            Ok(proof) => (proof.clone(), proof),
            Err(_) => (Vec::new(), Vec::new()),
        }
    }
    fn verify(&self, seed: &[u8; 32], delay: u64, _output: &[u8], proof: &[u8]) -> bool {
        use vdf::{VDFParams, WesolowskiVDFParams, VDF as _};
        let vdf = WesolowskiVDFParams(self.int_size_bits).new();
        vdf.verify(seed, delay, proof).is_ok()
    }
}

/// Aggregate a window of distinct producers' VRF outputs into a single seed (design `2(b)` 2,
/// RANDAO-style XOR). `vrf_outputs` is the >=BEACON_WINDOW most recent distinct-producer outputs.
///
/// This is the UNCHECKED fold (order-independent XOR) kept for callers that have already enforced
/// distinct producers + the window size upstream; prefer [`aggregate_seed_checked`] which enforces
/// the design's distinct-producer + window + per-holder-share invariants and fails closed.
pub fn aggregate_seed(vrf_outputs: &[[u8; 32]]) -> [u8; 32] {
    let mut acc = [0u8; 32];
    for o in vrf_outputs {
        for (a, b) in acc.iter_mut().zip(o.iter()) {
            *a ^= *b;
        }
    }
    acc
}

/// Why an aggregation was rejected (design `2(b)` 2+4: a seed that does not meet the entropy/share
/// invariants must FAIL CLOSED rather than seed a biasable committee).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregateError {
    /// Fewer than `BEACON_WINDOW` contributions (insufficient entropy; a single withholder would
    /// control too large a share).
    TooFewContributions,
    /// A producer appears more than [`MAX_SHARE_PER_PRODUCER`] times (one weight-holder over-
    /// represented; design `2(b)` 4 cap).
    ProducerOverRepresented,
}

/// Distinct-producer-enforced windowed aggregation (design `2(b)` 2+4). `contributions` pairs each
/// producer id with its VRF output. Enforces:
///  - at least `min_window` (>= [`BEACON_WINDOW`] for high-value draws) distinct contributions;
///  - no producer contributes more than [`MAX_SHARE_PER_PRODUCER`] slots (cap a single weight-
///    holder's leadership share feeding the beacon).
///
/// On success returns the XOR-folded seed (order-independent, so honest nodes agree regardless of
/// gossip arrival order). Fails CLOSED with an [`AggregateError`] otherwise — the caller MUST NOT
/// seat a committee from a rejected window.
pub fn aggregate_seed_checked(
    contributions: &[([u8; 32], [u8; 32])],
    min_window: u64,
) -> Result<[u8; 32], AggregateError> {
    use std::collections::HashMap;
    let mut counts: HashMap<[u8; 32], usize> = HashMap::new();
    for (producer, _) in contributions {
        let c = counts.entry(*producer).or_insert(0);
        *c += 1;
        if *c > MAX_SHARE_PER_PRODUCER {
            return Err(AggregateError::ProducerOverRepresented);
        }
    }
    // Distinct-producer count must meet the window (each producer counted once by the cap above).
    if (counts.len() as u64) < min_window.max(1) {
        return Err(AggregateError::TooFewContributions);
    }
    let outputs: Vec<[u8; 32]> = contributions.iter().map(|(_, o)| *o).collect();
    Ok(aggregate_seed(&outputs))
}

/// Derive the final placement seed for a job above the value threshold: aggregate the window, then
/// run it through the mandatory VDF so the block producer cannot withhold/re-roll based on an
/// outcome it cannot yet see (design `2(b)` 1+2). Returns the VDF `(output, proof)`; consumers MUST
/// re-verify the proof via [`Vdf::verify`] before seating a committee (see [`verify_placement`]).
pub fn placement_seed<V: Vdf>(
    vdf: &V,
    vrf_outputs: &[[u8; 32]],
    delay: u64,
) -> (Vec<u8>, Vec<u8>) {
    let seed = aggregate_seed(vrf_outputs);
    vdf.eval(&seed, delay)
}

/// Verify a placement-seed `(output, proof)` against the window the consumer reconstructed (design
/// `2(b)` 1: the seed is only canonical if the VDF proof checks out). Recomputes the aggregated seed
/// and verifies the VDF proof binds to it for `delay`. Returns true iff valid.
pub fn verify_placement<V: Vdf>(
    vdf: &V,
    vrf_outputs: &[[u8; 32]],
    delay: u64,
    output: &[u8],
    proof: &[u8],
) -> bool {
    let seed = aggregate_seed(vrf_outputs);
    vdf.verify(&seed, delay, output, proof)
}

// ---------------------------------------------------------------------------------------------
// Commit-reveal^2 (design `2(b)` 3) — binding + hiding for the highest-value committee draws.
// Each of >=2 independent beacon contributors COMMITs `H(salt || value)` first, then REVEALs
// `(value, salt)`; the placement seed mixes only revealed values, so no contributor can choose its
// value after seeing the others'. The scheduling of >=2 contributors and the slashing of a non-
// revealer are consensus/scheduler policy; this module provides the pure binding primitive.
// ---------------------------------------------------------------------------------------------

/// A commit-reveal commitment: `H("ce-placement-commit-v1" || salt || value)` (design `2(b)` 3).
/// SHA-256, domain-separated. Pure + deterministic.
pub fn commit(value: &[u8; 32], salt: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"ce-placement-commit-v1");
    h.update(salt);
    h.update(value);
    h.finalize().into()
}

/// Whether a `(value, salt)` reveal matches a prior `commitment` (design `2(b)` 3). Constant work,
/// pure. A mismatched reveal MUST be treated as a non-reveal (slashable per scheduler policy).
pub fn reveal_ok(commitment: &[u8; 32], value: &[u8; 32], salt: &[u8; 32]) -> bool {
    &commit(value, salt) == commitment
}

/// Mix a set of REVEALED commit-reveal values into the windowed seed (design `2(b)` 3): the highest-
/// value draw's seed is `aggregate(window) XOR fold(revealed values)`. Order-independent. The caller
/// supplies ONLY values whose reveals passed [`reveal_ok`].
pub fn mix_revealed(window_seed: [u8; 32], revealed: &[[u8; 32]]) -> [u8; 32] {
    let mut acc = window_seed;
    for v in revealed {
        for (a, b) in acc.iter_mut().zip(v.iter()) {
            *a ^= *b;
        }
    }
    acc
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
        // A tampered output is rejected even by the placeholder (it only accepts the identity).
        assert!(!v.verify(&seed, 1000, &[9u8; 32], &proof));
    }

    #[test]
    fn aggregate_xor_is_order_independent() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(aggregate_seed(&[a, b]), aggregate_seed(&[b, a]));
    }

    #[test]
    fn checked_aggregate_enforces_window_size() {
        // Fewer than the window => fail closed (insufficient entropy, design 2(b) 2).
        let few: Vec<([u8; 32], [u8; 32])> = (0..10u8).map(|i| ([i; 32], [i; 32])).collect();
        assert_eq!(
            aggregate_seed_checked(&few, BEACON_WINDOW),
            Err(AggregateError::TooFewContributions)
        );
        // Exactly the window of DISTINCT producers (64 distinct ids) => ok.
        let full: Vec<([u8; 32], [u8; 32])> = (0..BEACON_WINDOW)
            .map(|i| {
                let mut id = [0u8; 32];
                id[..8].copy_from_slice(&i.to_le_bytes());
                (id, [i as u8; 32])
            })
            .collect();
        assert!(aggregate_seed_checked(&full, BEACON_WINDOW).is_ok());
    }

    #[test]
    fn checked_aggregate_rejects_over_represented_producer() {
        // One producer contributing twice exceeds MAX_SHARE_PER_PRODUCER (design 2(b) 4 cap).
        let mut v: Vec<([u8; 32], [u8; 32])> = (0..BEACON_WINDOW)
            .map(|i| {
                let mut id = [0u8; 32];
                id[..8].copy_from_slice(&i.to_le_bytes());
                (id, [i as u8; 32])
            })
            .collect();
        // Duplicate the first producer id.
        v.push((v[0].0, [123u8; 32]));
        assert_eq!(
            aggregate_seed_checked(&v, BEACON_WINDOW),
            Err(AggregateError::ProducerOverRepresented)
        );
    }

    #[test]
    fn placement_seed_verifies_against_reconstructed_window() {
        // End-to-end with the placeholder: a consumer reconstructing the SAME window verifies the
        // VDF proof binds to it (design 2(b) 1). A DIFFERENT window must NOT verify.
        let v = PlaceholderVdf;
        let window: Vec<[u8; 32]> = (0..BEACON_WINDOW as u8).map(|i| [i; 32]).collect();
        let (out, proof) = placement_seed(&v, &window, 5_000);
        assert!(verify_placement(&v, &window, 5_000, &out, &proof));
        // Tamper the window => the aggregated seed differs => verification fails.
        let mut other = window.clone();
        other[0] = [0xFF; 32];
        assert!(!verify_placement(&v, &other, 5_000, &out, &proof));
    }

    #[test]
    fn commit_reveal_binds_value() {
        let value = [4u8; 32];
        let salt = [9u8; 32];
        let c = commit(&value, &salt);
        assert!(reveal_ok(&c, &value, &salt));
        // A different value or salt does not open the commitment (binding).
        assert!(!reveal_ok(&c, &[5u8; 32], &salt));
        assert!(!reveal_ok(&c, &value, &[8u8; 32]));
    }

    #[test]
    fn mix_revealed_is_order_independent_and_changes_seed() {
        let base = [1u8; 32];
        let a = [2u8; 32];
        let b = [3u8; 32];
        // Mixing is order-independent (XOR) so honest nodes agree.
        assert_eq!(mix_revealed(base, &[a, b]), mix_revealed(base, &[b, a]));
        // And a revealed value actually perturbs the seed (a withholder cannot leave it unchanged).
        assert_ne!(mix_revealed(base, &[a]), base);
    }
}
