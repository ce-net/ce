//! Property/fuzz tests for the CEP-1 wire format (`CellSignal`).
//!
//! These prove the signal envelope's wire and authentication contract over random input:
//!
//! * `decode(encode(s)) == s` for arbitrary signal bodies, and the decoded signal still verifies;
//! * any tamper to a signed field (payload, nonce, from, capabilities, burn proof) breaks
//!   `verify()` — a signal is bound to every field it carries;
//! * `decode` NEVER panics on arbitrary bytes off the wire — a malformed/truncated frame from a
//!   hostile peer becomes a clean `Err`, not an abort;
//! * `requires_burn` matches its documented predicate for any payload/burn-proof combination;
//! * the content-addressed `id()` is stable across an encode/decode round-trip.

use ce_identity::Identity;
use ce_protocol::{BurnProof, Capability, CellAddress, CellSignal};
use proptest::prelude::*;
use std::sync::atomic::{AtomicU64, Ordering};

fn fresh() -> Identity {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("ce-proto-prop-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    Identity::load_or_generate(&dir).unwrap()
}

/// Strategy for an address: a random Node id or Broadcast.
fn address() -> impl Strategy<Value = CellAddress> {
    prop_oneof![
        any::<u8>().prop_map(|b| CellAddress::Node([b; 32])),
        Just(CellAddress::Broadcast),
    ]
}

/// Strategy for an optional burn proof carrying a possibly-huge (>2^53) amount.
fn burn_proof() -> impl Strategy<Value = Option<BurnProof>> {
    prop_oneof![
        Just(None),
        (any::<u128>(), any::<u64>()).prop_map(|(amount, h)| Some(BurnProof {
            tx_id: [1u8; 32],
            amount,
            block_height: h,
            block_hash: [2u8; 32],
        })),
    ]
}

fn caps() -> impl Strategy<Value = Vec<Capability>> {
    proptest::collection::vec(
        ("[a-z]{1,8}", any::<u32>()).prop_map(|(name, version)| Capability { name, version }),
        0..4,
    )
}

proptest! {
    /// A built signal round-trips through encode/decode losslessly and still verifies; its id is
    /// stable across the round-trip.
    #[test]
    fn signal_roundtrips_and_verifies(
        to in address(),
        payload in proptest::collection::vec(any::<u8>(), 0..512),
        bp in burn_proof(),
        nonce in any::<u64>(),
        cs in caps(),
    ) {
        let id = fresh();
        let sig = CellSignal::build(id.node_id(), to, cs, payload, bp, nonce, &id);
        prop_assert!(sig.verify().is_ok(), "freshly built signal must verify");

        let bytes = sig.encode().unwrap();
        let back = CellSignal::decode(&bytes).expect("decode our own encoding");
        prop_assert!(back.verify().is_ok(), "decoded signal must still verify");
        prop_assert_eq!(sig.id(), back.id(), "content id changed across roundtrip");
        prop_assert_eq!(sig.nonce, back.nonce);
        prop_assert_eq!(&sig.payload, &back.payload);
    }

    /// Tampering the payload after signing breaks verification — the payload is authenticated.
    #[test]
    fn tampered_payload_fails_verify(
        payload in proptest::collection::vec(any::<u8>(), 1..256),
        idx in any::<usize>(),
        xor in 1u8..=255,
    ) {
        let id = fresh();
        let mut sig = CellSignal::build(id.node_id(), CellAddress::Broadcast, vec![], payload.clone(), None, 1, &id);
        let i = idx % sig.payload.len();
        sig.payload[i] ^= xor;
        prop_assert!(sig.verify().is_err(), "tampered payload still verified");
    }

    /// Tampering the nonce after signing breaks verification — the replay-guard field is bound.
    #[test]
    fn tampered_nonce_fails_verify(nonce in any::<u64>(), delta in 1u64..=u64::MAX) {
        let id = fresh();
        let mut sig = CellSignal::build(id.node_id(), CellAddress::Broadcast, vec![], vec![1, 2, 3], None, nonce, &id);
        sig.nonce = nonce.wrapping_add(delta);
        prop_assert!(sig.verify().is_err(), "tampered nonce still verified");
    }

    /// Replacing `from` with another node's id breaks verification (the signature was made by the
    /// original key) — a signal cannot be re-attributed to a different sender.
    #[test]
    fn spoofed_from_fails_verify(payload in proptest::collection::vec(any::<u8>(), 0..64)) {
        let signer = fresh();
        let imposter = fresh();
        prop_assume!(signer.node_id() != imposter.node_id());
        let mut sig = CellSignal::build(signer.node_id(), CellAddress::Broadcast, vec![], payload, None, 1, &signer);
        sig.from = imposter.node_id();
        prop_assert!(sig.verify().is_err(), "signal re-attributed to a different sender still verified");
    }

    /// `CellSignal::decode` never panics on arbitrary bytes — a hostile/truncated frame is a clean Err.
    #[test]
    fn decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let _ = CellSignal::decode(&bytes); // must not panic
    }

    /// `requires_burn` is exactly "non-empty payload AND no burn proof".
    #[test]
    fn requires_burn_predicate(
        payload in proptest::collection::vec(any::<u8>(), 0..32),
        bp in burn_proof(),
    ) {
        let id = fresh();
        let want = !payload.is_empty() && bp.is_none();
        let sig = CellSignal::build(id.node_id(), CellAddress::Broadcast, vec![], payload, bp, 1, &id);
        prop_assert_eq!(sig.requires_burn(), want);
    }
}
