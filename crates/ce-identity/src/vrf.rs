//! Phase 9 (P9) — Verifiable Random Function interface + RFC 9381 ECVRF.
//!
//! Governs: design `2(b)` ("VRF: today signature-as-VRF `SHA256(Ed25519-sig)`; harden later to RFC
//! 9381 ECVRF"), consensus.md:557, and `6` Phase 9 ("ECVRF (RFC 9381)"). This module defines a clean
//! [`Vrf`] trait and two implementations so the consensus layer can swap the VRF primitive WITHOUT
//! changing call sites:
//!
//!  - [`Ed25519AsVrf`] — the CURRENTLY-WIRED primitive: the proof is the node's 64-byte Ed25519
//!    signature over the seed; the VRF output is `SHA256(signature)`. This is what `ce-chain`'s
//!    `vrf_ticket` / `vrf_verify` and the on-chain `Block.vrf_proof: [u8; 64]` field use today. It is
//!    a usable VRF (Ed25519 sigs are deterministic per RFC 8032, so the output is deterministic,
//!    publicly verifiable, and unpredictable without the key) but is NOT RFC 9381: it lacks ECVRF's
//!    formal *full uniqueness* / *collision resistance* proofs, and a malicious signer with a
//!    nondeterministic signer could in principle produce two valid signatures over one seed.
//!
//!  - [`Ecvrf`] (feature `ecvrf`) — the RFC-9381-class hardening using the VETTED `schnorrkel` crate
//!    (sr25519 VRF as deployed in Polkadot/Substrate). Provides the *full uniqueness* guarantee the
//!    signature-as-VRF lacks: exactly one valid output per (key, input), so a leader cannot grind
//!    sibling tickets. Its proof is LARGER than 64 bytes, so adopting it on-chain is a
//!    consensus-format migration (`Block.vrf_proof` must widen) — that wiring is the integrator's
//!    consensus change, deliberately NOT done in this P9 file (which owns ce-identity only, per the
//!    module contract). The trait + this impl are the drop-in the migration will use.
//!
//! Crypto rule (task): nothing is hand-rolled. `Ed25519AsVrf` reuses `ed25519-dalek`; `Ecvrf` reuses
//! `schnorrkel`. When the `ecvrf` feature is OFF, a `#[doc(hidden)]` PLACEHOLDER preserves the trait
//! surface (clearly marked consensus-insecure) so downstream code compiles, with a TODO to enable the
//! real crate. See `Cargo.toml`.

use crate::{verify, NodeId};
use sha2::{Digest, Sha256};

/// A Verifiable Random Function: given a secret key and an input (seed), produce a pseudorandom
/// `output` plus a `proof` that anyone holding the public key can check. The defining properties:
///  - **Uniqueness** — at most one `output` verifies for a given `(public_key, input)`.
///  - **Pseudorandomness** — `output` is indistinguishable from random without the secret key.
///  - **Verifiability** — `verify` accepts iff `proof` was produced by the matching secret key.
///
/// CE uses the `output` (as a `u128` ticket via [`output_to_ticket`]) for slot leader election:
/// `lead iff ticket < threshold * weight`. The interface is intentionally byte-oriented (`Vec<u8>`
/// proof) so a 64-byte Ed25519 proof and a larger ECVRF proof share one trait.
pub trait Vrf {
    /// Produce `(output, proof)` for `input` under the implementation's bound secret key. `output` is
    /// a 32-byte pseudorandom value; `proof` is the verifier-checkable evidence.
    fn prove(&self, input: &[u8]) -> ([u8; 32], Vec<u8>);

    /// Verify `proof` for `public_key` over `input`, returning the VRF `output` on success and `None`
    /// on any failure (bad proof, wrong key, malformed bytes). MUST be deterministic and total.
    fn verify(public_key: &NodeId, input: &[u8], proof: &[u8]) -> Option<[u8; 32]>;
}

/// Map a 32-byte VRF output to a `u128` ticket (high 16 bytes, big-endian) for the eligibility
/// comparison — identical to `ce-chain::ticket_value`, kept here so a VRF consumer needs only this
/// crate. A smaller ticket means "more likely to lead".
pub fn output_to_ticket(output: &[u8; 32]) -> u128 {
    let mut b = [0u8; 16];
    b.copy_from_slice(&output[..16]);
    u128::from_be_bytes(b)
}

// ---------------------------------------------------------------------------------------------------
// Ed25519-as-VRF — the currently-wired primitive (consensus-compatible with `Block.vrf_proof`).
// ---------------------------------------------------------------------------------------------------

/// The signature-as-VRF wired in CE today (design `2(b)`): proof = the 64-byte Ed25519 signature over
/// the seed; output = `SHA256(signature)`. Backed by an [`crate::Identity`] for proving. Verification
/// is a free static method (no key material needed beyond the public `NodeId`), matching
/// `ce-chain::vrf_verify`'s signature exactly so this is a behavior-identical drop-in.
pub struct Ed25519AsVrf<'a> {
    pub identity: &'a crate::Identity,
}

impl<'a> Vrf for Ed25519AsVrf<'a> {
    fn prove(&self, input: &[u8]) -> ([u8; 32], Vec<u8>) {
        let sig = self.identity.sign(input);
        let output = Sha256::digest(sig).into();
        (output, sig.to_vec())
    }

    fn verify(public_key: &NodeId, input: &[u8], proof: &[u8]) -> Option<[u8; 32]> {
        let sig: [u8; 64] = proof.try_into().ok()?;
        verify(public_key, input, &sig).ok()?;
        Some(Sha256::digest(sig).into())
    }
}

// ---------------------------------------------------------------------------------------------------
// ECVRF (RFC 9381 class) — real impl behind feature `ecvrf`, placeholder otherwise.
// ---------------------------------------------------------------------------------------------------

#[cfg(feature = "ecvrf")]
mod ecvrf_impl {
    //! RFC-9381-class ECVRF via the vetted `schnorrkel` crate (sr25519 VRF, as shipped in
    //! Polkadot/Substrate). This gives the *full uniqueness* the signature-as-VRF lacks: exactly one
    //! valid output per (key, input), so a slot leader cannot grind sibling VRF tickets (closes the
    //! grinding gap design `2(b)`/red-team H4 flags for the placement beacon).
    //!
    //! NOTE: schnorrkel keys are sr25519 (Ristretto), NOT Ed25519 — so an `Ecvrf` public key is a
    //! *separate* 32-byte key from the node's Ed25519 `NodeId`. Adopting ECVRF on-chain therefore
    //! requires nodes to publish an sr25519 VRF key (a one-time `KeyRegister`-style tx) bound to their
    //! NodeId, and to widen `Block.vrf_proof`. That binding + migration is the integrator's consensus
    //! change; here we expose the primitive and its round-trip.

    use super::Vrf;
    use crate::NodeId;
    use schnorrkel::vrf::{VRFPreOut, VRFProof, VRF_PREOUT_LENGTH};
    use schnorrkel::{signing_context, ExpansionMode, Keypair, MiniSecretKey, PublicKey};

    /// Domain separator for CE ECVRF transcripts (RFC 9381 "suite string" analogue).
    const CE_VRF_CONTEXT: &[u8] = b"ce-twle-ecvrf-v1";

    /// An ECVRF keypair (sr25519). Derived deterministically from a 32-byte mini-secret so a node can
    /// reproduce it from stored key material.
    pub struct Ecvrf {
        keypair: Keypair,
    }

    impl Ecvrf {
        /// Build from a 32-byte mini-secret seed (deterministic).
        pub fn from_seed(seed: &[u8; 32]) -> Self {
            let mini = MiniSecretKey::from_bytes(seed).expect("32-byte mini secret");
            let keypair = mini.expand_to_keypair(ExpansionMode::Ed25519);
            Self { keypair }
        }

        /// The 32-byte sr25519 public key (the ECVRF verification key — distinct from the Ed25519
        /// NodeId).
        pub fn public_key(&self) -> [u8; 32] {
            self.keypair.public.to_bytes()
        }
    }

    impl Vrf for Ecvrf {
        fn prove(&self, input: &[u8]) -> ([u8; 32], Vec<u8>) {
            let ctx = signing_context(CE_VRF_CONTEXT);
            let (io, proof, _) = self.keypair.vrf_sign(ctx.bytes(input));
            let preout: [u8; VRF_PREOUT_LENGTH] = io.to_preout().to_bytes();
            // The trait `output` is the VRF preout (32 bytes); the `proof` we hand back is
            // `preout || proof_bytes` so `verify` is self-contained (schnorrkel's `vrf_verify` needs
            // BOTH the preout and the proof). The integrator's on-chain wire format carries the same
            // pair; this is what widens `Block.vrf_proof` beyond the current 64-byte field.
            let mut wire = Vec::with_capacity(VRF_PREOUT_LENGTH + proof.to_bytes().len());
            wire.extend_from_slice(&preout);
            wire.extend_from_slice(&proof.to_bytes());
            (preout, wire)
        }

        fn verify(public_key: &NodeId, input: &[u8], proof: &[u8]) -> Option<[u8; 32]> {
            // For ECVRF the `public_key` is the sr25519 VRF key bytes (see module note: it is NOT the
            // Ed25519 NodeId; the integrator maps NodeId -> registered VRF key before calling). The
            // `proof` arg is the `preout || proof_bytes` wire produced by `prove`.
            if proof.len() < VRF_PREOUT_LENGTH {
                return None;
            }
            let (preout_bytes, proof_bytes) = proof.split_at(VRF_PREOUT_LENGTH);
            let pk = PublicKey::from_bytes(public_key).ok()?;
            let preout = VRFPreOut::from_bytes(preout_bytes).ok()?;
            let vproof = VRFProof::from_bytes(proof_bytes).ok()?;
            let ctx = signing_context(CE_VRF_CONTEXT);
            let (io, _) = pk.vrf_verify(ctx.bytes(input), &preout, &vproof).ok()?;
            Some(io.to_preout().to_bytes())
        }
    }
}

#[cfg(feature = "ecvrf")]
pub use ecvrf_impl::Ecvrf;

/// PLACEHOLDER ECVRF used when the `ecvrf` feature is OFF (default), so the [`Vrf`] trait surface and
/// downstream code compile without pulling the schnorrkel/curve25519 stack.
///
/// CONSENSUS-INSECURE — this is `SHA256(domain || secret_seed || input)` with a symmetric "proof",
/// NOT a real VRF: it has no public verifiability (the "public key" must equal the secret to verify),
/// so it MUST NOT be used in production. It exists only to keep the type available; enable the
/// `ecvrf` feature for the real `schnorrkel`-backed impl.
///
/// TODO(P9): once the on-chain `Block.vrf_proof` widening + NodeId->sr25519-key registration land,
/// delete this placeholder and make `ecvrf` the default feature.
#[cfg(not(feature = "ecvrf"))]
#[doc(hidden)]
pub struct PlaceholderEcvrf {
    /// The 32-byte secret seed. (Insecurely also used as the "public" key in this placeholder.)
    pub seed: [u8; 32],
}

#[cfg(not(feature = "ecvrf"))]
impl PlaceholderEcvrf {
    #[doc(hidden)]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self { seed: *seed }
    }
}

#[cfg(not(feature = "ecvrf"))]
impl Vrf for PlaceholderEcvrf {
    fn prove(&self, input: &[u8]) -> ([u8; 32], Vec<u8>) {
        // INSECURE placeholder: output = H(domain || seed || input); "proof" = the seed itself.
        let mut h = Sha256::new();
        h.update(b"ce-PLACEHOLDER-ecvrf-INSECURE");
        h.update(self.seed);
        h.update(input);
        let output: [u8; 32] = h.finalize().into();
        (output, self.seed.to_vec())
    }

    fn verify(public_key: &NodeId, input: &[u8], proof: &[u8]) -> Option<[u8; 32]> {
        // INSECURE: "verify" recomputes the output from the revealed seed-as-proof. There is NO public
        // verifiability — the verifier learns the secret. Marked clearly; real ECVRF has none of this.
        let seed: [u8; 32] = proof.try_into().ok()?;
        // The placeholder cannot bind to a distinct public key; require pk == H(seed) as a token gate.
        let bound = Sha256::digest(seed);
        if bound.as_slice() != public_key.as_slice() {
            return None;
        }
        let mut h = Sha256::new();
        h.update(b"ce-PLACEHOLDER-ecvrf-INSECURE");
        h.update(seed);
        h.update(input);
        Some(h.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    fn ident() -> Identity {
        Identity::from_secret_bytes(&[7u8; 32])
    }

    #[test]
    fn ed25519_vrf_prove_verify_roundtrips() {
        let id = ident();
        let vrf = Ed25519AsVrf { identity: &id };
        let seed = b"slot-seed-42";
        let (output, proof) = vrf.prove(seed);
        let got = Ed25519AsVrf::verify(&id.node_id(), seed, &proof);
        assert_eq!(got, Some(output), "honest proof verifies and yields the same output");
    }

    #[test]
    fn ed25519_vrf_rejects_forged_proof() {
        let id = ident();
        let other = Identity::from_secret_bytes(&[9u8; 32]);
        let vrf = Ed25519AsVrf { identity: &id };
        let seed = b"slot-seed-42";
        let (_output, mut proof) = vrf.prove(seed);
        // Forge by flipping a proof byte: must fail to verify.
        proof[0] ^= 0xFF;
        assert!(Ed25519AsVrf::verify(&id.node_id(), seed, &proof).is_none());
        // A valid proof under a different key must not verify against this NodeId.
        let (_o2, proof2) = (Ed25519AsVrf { identity: &other }).prove(seed);
        assert!(Ed25519AsVrf::verify(&id.node_id(), seed, &proof2).is_none());
        // A valid proof over a DIFFERENT seed must not verify for this seed.
        let (_o3, proof3) = vrf.prove(b"other-seed");
        assert!(Ed25519AsVrf::verify(&id.node_id(), seed, &proof3).is_none());
    }

    #[test]
    fn ed25519_vrf_is_deterministic() {
        // Ed25519 (RFC 8032) is deterministic: proving twice yields the same output (uniqueness in
        // practice for an honest signer).
        let id = ident();
        let vrf = Ed25519AsVrf { identity: &id };
        let (o1, p1) = vrf.prove(b"x");
        let (o2, p2) = vrf.prove(b"x");
        assert_eq!(o1, o2);
        assert_eq!(p1, p2);
    }

    #[test]
    fn output_to_ticket_matches_chain_convention() {
        let mut out = [0u8; 32];
        out[0] = 0x01;
        // High 16 bytes big-endian → 0x0100..00 = 1 << 120.
        assert_eq!(output_to_ticket(&out), 1u128 << 120);
    }

    #[cfg(not(feature = "ecvrf"))]
    #[test]
    fn placeholder_is_marked_insecure_but_roundtrips_for_compile_coverage() {
        // The placeholder is NOT a real VRF (no public verifiability). This test only documents that
        // the trait surface is exercised; production MUST enable feature `ecvrf`.
        let seed = [3u8; 32];
        let pk: NodeId = Sha256::digest(seed).into();
        let vrf = PlaceholderEcvrf::from_seed(&seed);
        let (output, proof) = vrf.prove(b"in");
        assert_eq!(PlaceholderEcvrf::verify(&pk, b"in", &proof), Some(output));
        // Wrong "public key" gate rejects.
        assert!(PlaceholderEcvrf::verify(&[0u8; 32], b"in", &proof).is_none());
    }

    #[cfg(feature = "ecvrf")]
    #[test]
    fn ecvrf_prove_verify_roundtrips_and_rejects_forgery() {
        // Real RFC-9381-class round trip through the `Vrf` trait (schnorrkel sr25519 VRF). The wire
        // carries `preout || proof` so `verify` is self-contained.
        let vrf = Ecvrf::from_seed(&[5u8; 32]);
        let pk = vrf.public_key();
        let input = b"slot-seed-input";
        let (output, wire) = vrf.prove(input);
        // Honest proof verifies and yields the same output.
        assert_eq!(Ecvrf::verify(&pk, input, &wire), Some(output));
        // Forgery: flip a proof byte → must not verify.
        let mut bad = wire.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xFF;
        assert!(Ecvrf::verify(&pk, input, &bad).is_none(), "forged proof rejected");
        // Wrong public key → must not verify.
        let other = Ecvrf::from_seed(&[6u8; 32]);
        assert!(Ecvrf::verify(&other.public_key(), input, &wire).is_none());
        // Different input → must not verify against this proof.
        assert!(Ecvrf::verify(&pk, b"other-input", &wire).is_none());
    }
}
