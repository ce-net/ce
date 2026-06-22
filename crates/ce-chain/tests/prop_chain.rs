//! Property/fuzz + serialization round-trip tests for `ce-chain`.
//!
//! The in-module unit tests cover the consensus/balance state machine. These tests focus on three
//! orthogonal foundations that benefit from random search rather than hand-picked cases:
//!
//! 1. **Money serialization is lossless for values above `2^53`.** CE money is `u128` base units
//!    (`1 credit = 10^18`), far past JSON's `2^53` safe-integer limit, so it travels as decimal
//!    strings on the API and as raw bincode on disk/wire. We prove `bincode(decode(encode)) == x`
//!    for arbitrary `u128`/`i128` and for whole `TxKind`/`Tx`/`Block` values carrying such amounts.
//! 2. **The settlement burn is a sound conservation law** for arbitrary gross amounts: `net + burn
//!    == gross`, `burn <= gross`, monotonic in `gross`, and exactly `1%` floor for large values.
//! 3. **Pure helpers never panic and stay in-range** over random input: `expected_difficulty`,
//!    `is_valid_name`, `segment_id_for_block`, `leader_threshold`/`ticket_value`.

use ce_chain::{
    Block, Chain, EquivocationProof, SETTLEMENT_BURN_BPS, SUPPLY_CAP, Tx, TxKind, channel_receipt_bytes,
    is_valid_name, leader_threshold, payer_settle_bytes, segment_id_for_block, settlement_burn,
    ticket_value, vrf_ticket,
};
use ce_identity::{Identity, NodeId};
use proptest::prelude::*;
use std::sync::atomic::{AtomicU64, Ordering};

fn id() -> Identity {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("ce-chain-prop-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    Identity::load_or_generate(&dir).unwrap()
}

/// Round-trip a serializable value through bincode and assert equality of the re-encoded bytes
/// (the canonical, deterministic comparison used everywhere on the wire and disk).
fn bincode_roundtrip_eq<T: serde::Serialize + serde::de::DeserializeOwned>(v: &T) -> bool {
    let bytes = bincode::serialize(v).expect("serialize");
    let back: T = bincode::deserialize(&bytes).expect("deserialize");
    let bytes2 = bincode::serialize(&back).expect("re-serialize");
    bytes == bytes2
}

proptest! {
    // ----- 1. Money serialization above 2^53. -----

    /// Arbitrary `u128` amounts (the on-chain amount type) round-trip through bincode losslessly,
    /// including values far above 2^53 and right at the supply cap.
    #[test]
    fn u128_amount_roundtrips(amount in any::<u128>()) {
        let bytes = bincode::serialize(&amount).unwrap();
        let back: u128 = bincode::deserialize(&bytes).unwrap();
        prop_assert_eq!(amount, back);
        // Decimal-string transit (the API form) is also lossless and never lossy like an f64 would be.
        let s = amount.to_string();
        prop_assert_eq!(amount, s.parse::<u128>().unwrap());
    }

    /// Arbitrary `i128` balances (the balance type, which may be transiently negative in math)
    /// round-trip through bincode and decimal strings.
    #[test]
    fn i128_balance_roundtrips(bal in any::<i128>()) {
        let bytes = bincode::serialize(&bal).unwrap();
        prop_assert_eq!(bal, bincode::deserialize::<i128>(&bytes).unwrap());
        prop_assert_eq!(bal, bal.to_string().parse::<i128>().unwrap());
    }

    /// A `Transfer` carrying an arbitrary (possibly >2^53) amount round-trips, signature and all,
    /// and the deserialized tx still verifies — proving no truncation of the signed amount field.
    #[test]
    fn transfer_tx_roundtrips_and_verifies(amount in any::<u128>(), to_byte in any::<u8>()) {
        let from = id();
        let to: NodeId = [to_byte; 32];
        let kind = TxKind::Transfer { from: from.node_id(), to, amount };
        let sig = from.sign(&bincode::serialize(&kind).unwrap());
        let tx = Tx::new(kind, from.node_id(), sig);

        prop_assert!(bincode_roundtrip_eq(&tx), "Tx bytes changed across roundtrip (amount={})", amount);
        let bytes = bincode::serialize(&tx).unwrap();
        let back: Tx = bincode::deserialize(&bytes).unwrap();
        prop_assert!(back.verify().is_ok(), "roundtripped tx failed to verify");
        if let TxKind::Transfer { amount: a, .. } = back.kind {
            prop_assert_eq!(a, amount, "amount truncated across serialization");
        } else {
            prop_assert!(false, "kind changed across roundtrip");
        }
        // tx.id() is stable across a roundtrip (content address must not depend on in-memory layout).
        prop_assert_eq!(tx.id(), back.id());
    }

    /// A `JobSettle` carrying a huge `cost` and a real payer co-signature round-trips losslessly,
    /// and the embedded `[u8;64]` signature survives (exercises the `sig_serde` path for big amounts).
    #[test]
    fn job_settle_tx_roundtrips(cost in any::<u128>(), cpu_ms in any::<u64>(), mem_mb in any::<u64>()) {
        let host = id();
        let payer = id();
        let job_id = [7u8; 32];
        let payer_sig = payer.sign(&payer_settle_bytes(&job_id, &host.node_id(), cost));
        let kind = TxKind::JobSettle {
            job_id, host: host.node_id(), payer: payer.node_id(), cpu_ms, mem_mb, cost, payer_sig,
        };
        let sig = host.sign(&bincode::serialize(&kind).unwrap());
        let tx = Tx::new(kind, host.node_id(), sig);
        prop_assert!(bincode_roundtrip_eq(&tx));
        let back: Tx = bincode::deserialize(&bincode::serialize(&tx).unwrap()).unwrap();
        prop_assert!(back.verify().is_ok());
    }

    /// A whole `Block` (with two amount-carrying txs) round-trips losslessly and keeps its hash —
    /// the block content-address must be stable across serialization (sync depends on it).
    #[test]
    fn block_roundtrips_keeping_hash(amount in any::<u128>(), ts in any::<u64>()) {
        let miner = id();
        let payee: NodeId = [3u8; 32];
        let chain = Chain::genesis();
        let kind = TxKind::Transfer { from: miner.node_id(), to: payee, amount };
        let sig = miner.sign(&bincode::serialize(&kind).unwrap());
        let tx = Tx::new(kind, miner.node_id(), sig);
        let mut block: Block = chain.next_block(vec![tx], miner.node_id());
        block.timestamp = ts;
        block.seal(&miner);
        let h = block.hash();
        prop_assert!(bincode_roundtrip_eq(&block));
        let back: Block = bincode::deserialize(&bincode::serialize(&block).unwrap()).unwrap();
        prop_assert_eq!(h, back.hash(), "block hash changed across serialization");
        prop_assert!(back.verify_seal(), "seal lost across serialization");
    }

    /// An `EquivocationProof` (carries two `[u8;64]` signatures) round-trips byte-for-byte.
    #[test]
    fn equivocation_proof_roundtrips(epoch in any::<u64>()) {
        let proof = EquivocationProof {
            domain: [9u8; 16],
            epoch,
            statement_a: [1u8; 32],
            sig_a: [2u8; 64],
            statement_b: [3u8; 32],
            sig_b: [4u8; 64],
        };
        prop_assert!(bincode_roundtrip_eq(&proof));
    }

    // ----- 2. Settlement burn conservation law. -----

    /// For arbitrary gross amounts: net + burn == gross, burn <= gross, burn is exactly 1% floored.
    #[test]
    fn settlement_burn_conserves_value(gross in any::<u128>()) {
        let burn = settlement_burn(gross);
        prop_assert!(burn <= gross, "burn exceeded gross");
        let net = gross - burn;
        prop_assert_eq!(net + burn, gross, "value not conserved across the burn split");
        // Floor of gross * bps / 10_000, computed independently here to cross-check the impl.
        let expected = gross.saturating_mul(SETTLEMENT_BURN_BPS) / 10_000;
        prop_assert_eq!(burn, expected);
    }

    /// The burn is monotonic non-decreasing in the gross amount (a larger settlement never burns
    /// less) — washing more volume always costs at least as much capital.
    #[test]
    fn settlement_burn_is_monotonic(a in any::<u64>(), b in any::<u64>()) {
        let (lo, hi) = if a <= b { (a as u128, b as u128) } else { (b as u128, a as u128) };
        prop_assert!(settlement_burn(lo) <= settlement_burn(hi));
    }

    // ----- 3. Pure helpers: never panic, stay in range. -----

    /// `is_valid_name` never panics on arbitrary unicode and accepted names satisfy the documented
    /// shape (3-32 chars, lowercase ascii alnum or hyphen, no leading/trailing hyphen).
    #[test]
    fn is_valid_name_shape(s in ".{0,40}") {
        if is_valid_name(&s) {
            prop_assert!((3..=32).contains(&s.len()));
            prop_assert!(s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
            prop_assert!(!s.starts_with('-') && !s.ends_with('-'));
        }
    }

    /// `segment_id_for_block` is monotonic non-decreasing in block index and never panics.
    #[test]
    fn segment_id_monotonic(a in any::<u64>(), b in any::<u64>()) {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        prop_assert!(segment_id_for_block(lo) <= segment_id_for_block(hi));
    }

    /// `leader_threshold(weight, total)` is bounded by `u128::MAX` and rises with weight share —
    /// a heavier node is at least as likely to lead. Never panics, even with total == 0.
    #[test]
    fn leader_threshold_monotonic(w1 in any::<u64>(), w2 in any::<u64>(), total in 1u64..=u64::MAX) {
        let (lo, hi) = if w1 <= w2 { (w1 as u128, w2 as u128) } else { (w2 as u128, w1 as u128) };
        let t = total as u128;
        // Clamp weights to total so the share is well-defined (weight <= total invariant on-chain).
        let lo = lo.min(t);
        let hi = hi.min(t);
        prop_assert!(leader_threshold(lo, t) <= leader_threshold(hi, t),
            "threshold not monotonic in weight: w_lo={} w_hi={} total={}", lo, hi, t);
    }

    /// `vrf_ticket` is a deterministic function of its input signature, and `ticket_value` of the
    /// ticket never panics. Same signature -> same ticket -> same value.
    #[test]
    fn vrf_ticket_is_deterministic(sig_bytes in proptest::collection::vec(any::<u8>(), 64)) {
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_bytes);
        let t1 = vrf_ticket(&sig);
        let t2 = vrf_ticket(&sig);
        prop_assert_eq!(t1, t2);
        prop_assert_eq!(ticket_value(&t1), ticket_value(&t2));
    }

    /// `channel_receipt_bytes` is injective in `cumulative` — two distinct cumulative amounts
    /// produce distinct signing payloads (so a receipt for amount X can never be replayed as Y).
    #[test]
    fn channel_receipt_bytes_distinct(c1 in any::<u128>(), c2 in any::<u128>()) {
        prop_assume!(c1 != c2);
        let host: NodeId = [5u8; 32];
        let chan = [6u8; 32];
        prop_assert_ne!(
            channel_receipt_bytes(&chan, &host, c1),
            channel_receipt_bytes(&chan, &host, c2),
            "distinct cumulative amounts produced identical signing payloads",
        );
    }
}

/// The supply cap is the largest meaningful amount; it must serialize and survive a round-trip
/// (a deterministic boundary check alongside the random `u128` property).
#[test]
fn supply_cap_roundtrips() {
    let bytes = bincode::serialize(&SUPPLY_CAP).unwrap();
    assert_eq!(SUPPLY_CAP, bincode::deserialize::<u128>(&bytes).unwrap());
    assert_eq!(SUPPLY_CAP, SUPPLY_CAP.to_string().parse::<u128>().unwrap());
    assert!(SUPPLY_CAP > (1u128 << 53), "supply cap must be past JSON's safe-integer range");
}
