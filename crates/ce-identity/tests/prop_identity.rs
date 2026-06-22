//! Property/fuzz tests for `ce-identity` — the Ed25519 signing root every other CE security
//! property rests on. The in-module unit tests cover key generation and a basic sign/verify; these
//! prove the cryptographic contract over random data and random adversarial inputs:
//!
//! * sign-then-verify succeeds for ANY message;
//! * verification fails for tampered data, a tampered signature, or the wrong key;
//! * signatures are deterministic (RFC 8032) — the same `(key, message)` always yields the same
//!   64 bytes (CE relies on this for VRF tickets and content-addressed tx ids);
//! * `verify` NEVER panics on arbitrary 32-byte "node ids" or 64-byte "signatures" from a hostile
//!   peer — it returns `Err`, never aborts the node.

use ce_identity::{Identity, NodeId, verify};
use proptest::prelude::*;
use std::sync::atomic::{AtomicU64, Ordering};

fn fresh() -> Identity {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("ce-id-prop-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    Identity::load_or_generate(&dir).unwrap()
}

proptest! {
    /// Sign then verify succeeds for any message of any length.
    #[test]
    fn sign_then_verify_roundtrips(msg in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let id = fresh();
        let sig = id.sign(&msg);
        prop_assert!(verify(&id.node_id(), &msg, &sig).is_ok());
    }

    /// Ed25519 is deterministic: signing the same message twice yields identical bytes.
    #[test]
    fn signatures_are_deterministic(msg in proptest::collection::vec(any::<u8>(), 0..256)) {
        let id = fresh();
        prop_assert_eq!(id.sign(&msg), id.sign(&msg));
    }

    /// Verification fails when the message is altered after signing (any single-byte flip).
    #[test]
    fn tampered_message_fails(
        msg in proptest::collection::vec(any::<u8>(), 1..256),
        idx in any::<usize>(),
        xor in 1u8..=255,
    ) {
        let id = fresh();
        let sig = id.sign(&msg);
        let mut tampered = msg.clone();
        let i = idx % tampered.len();
        tampered[i] ^= xor; // guaranteed change
        prop_assert!(verify(&id.node_id(), &tampered, &sig).is_err(),
            "verification accepted a tampered message");
    }

    /// Verification fails when the signature is altered (any single-byte flip).
    #[test]
    fn tampered_signature_fails(
        msg in proptest::collection::vec(any::<u8>(), 0..256),
        idx in 0usize..64,
        xor in 1u8..=255,
    ) {
        let id = fresh();
        let mut sig = id.sign(&msg);
        sig[idx] ^= xor;
        prop_assert!(verify(&id.node_id(), &msg, &sig).is_err(),
            "verification accepted a tampered signature");
    }

    /// A signature from one key never verifies under a different key.
    #[test]
    fn wrong_key_fails(msg in proptest::collection::vec(any::<u8>(), 0..256)) {
        let signer = fresh();
        let other = fresh();
        let sig = signer.sign(&msg);
        // The two keys are distinct with overwhelming probability; assert and skip the ~0 collision.
        prop_assume!(signer.node_id() != other.node_id());
        prop_assert!(verify(&other.node_id(), &msg, &sig).is_err(),
            "a signature verified under the wrong key");
    }

    /// `verify` never panics on a hostile/garbage node id or signature — it returns Err cleanly.
    /// (A node ingests these straight off the wire; a panic here would be a remote DoS.)
    #[test]
    fn verify_never_panics_on_garbage(
        node_bytes in proptest::collection::vec(any::<u8>(), 32),
        sig_bytes in proptest::collection::vec(any::<u8>(), 64),
        msg in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let mut node: NodeId = [0u8; 32];
        node.copy_from_slice(&node_bytes);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_bytes);
        // Must not panic regardless of whether `node` is a valid curve point.
        let _ = verify(&node, &msg, &sig);
    }
}

/// A persisted key reloads to the SAME identity — node id and signatures are stable across a
/// restart (the chain's whole balance/authority model assumes a node keeps its id). Deterministic.
#[test]
fn key_persists_across_reload() {
    let dir = std::env::temp_dir().join(format!("ce-id-persist-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let a = Identity::load_or_generate(&dir).unwrap();
    let id_a = a.node_id();
    let sig_a = a.sign(b"stable message");
    drop(a);

    let b = Identity::load_or_generate(&dir).unwrap();
    assert_eq!(id_a, b.node_id(), "node id changed across reload");
    assert_eq!(sig_a, b.sign(b"stable message"), "signature changed across reload");
    assert_eq!(b.secret_bytes().len(), 32);
    assert_eq!(b.node_id_hex().len(), 64);
}
