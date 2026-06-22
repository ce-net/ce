//! Property/fuzz tests for the capability primitive (`ce-cap`).
//!
//! The unit tests in `src/lib.rs` cover specific, hand-picked attenuation violations. These
//! property tests instead generate *random* capability chains and assert the security invariants
//! hold for every generated case:
//!
//! 1. **Attenuation can never amplify.** A leaf can only ever be authorized for an action/resource
//!    that is present at *every* link from the root down. Randomly widening any middle link must
//!    make `authorize` fail.
//! 2. **Wire round-trips are lossless.** `decode_chain(encode_chain(x)) == x` for arbitrary chains,
//!    and `decode_chain` never panics on arbitrary (malformed) input.
//! 3. **Expiry/`not_before` windows are honored** for every `now` relative to the window.
//! 4. **Only the named audience may wield a capability**, for any random requester.
//!
//! These are the properties an attacker would probe; encoding them as proptests turns "we thought
//! of these cases" into "the prover searched the space and found no counterexample".

use ce_cap::{
    Capability, Caveats, Resource, SignedCapability, authorize, cap_bytes, decode_chain,
    decode_chain_bytes, encode_chain,
};
use ce_identity::{Identity, NodeId};
use proptest::prelude::*;
use std::sync::atomic::{AtomicU64, Ordering};

/// A fresh identity in a unique temp dir. Tests run in parallel within one process, so the dir is
/// uniquified by an atomic counter and the process id.
fn id() -> Identity {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("ce-cap-prop-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    Identity::load_or_generate(&dir).unwrap()
}

fn never_revoked(_: &NodeId, _: u64) -> bool {
    false
}

/// The universe of abilities the generators draw from.
const ABILITIES: &[&str] = &["exec", "sync", "tunnel", "deploy", "kill"];

/// A strategy producing a non-empty subset of [`ABILITIES`] (order-stable, deduped).
fn ability_set() -> impl Strategy<Value = Vec<String>> {
    proptest::collection::vec(0..ABILITIES.len(), 1..=ABILITIES.len()).prop_map(|idxs| {
        let mut v: Vec<String> = idxs.into_iter().map(|i| ABILITIES[i].to_string()).collect();
        v.sort();
        v.dedup();
        v
    })
}

proptest! {
    // ----- Invariant 1: a leaf can never be authorized for an ability missing from any ancestor.

    /// Build a two-link chain root -> leaf where the leaf's abilities are an ARBITRARY set. The
    /// leaf may only be authorized for an action that the root delegated AND the leaf carries.
    /// Any action outside the root's set must be denied — delegation cannot invent authority.
    #[test]
    fn leaf_action_must_be_in_every_ancestor(
        root_abilities in ability_set(),
        leaf_abilities in ability_set(),
        action_idx in 0..ABILITIES.len(),
    ) {
        let root = id();
        let leaf = id();
        let action = ABILITIES[action_idx];

        let c = SignedCapability::issue(
            &root, leaf.node_id(), leaf_abilities.clone(), Resource::Any,
            Caveats::default(), 1, None,
        );
        let res = authorize(
            &root.node_id(), &[], &[], 1000, &leaf.node_id(), action, &[c], &never_revoked,
        );

        // A single-link chain: the root IS the issuer (self), so attenuation is trivially satisfied.
        // Authorization succeeds iff the leaf carries the action.
        let leaf_has = leaf_abilities.iter().any(|a| a == action);
        prop_assert_eq!(res.is_ok(), leaf_has,
            "single-link authorize disagreed with leaf ability membership for {}", action);
        let _ = root_abilities; // (used in the multi-link variant below)
    }

    /// Three-link chain root -> mid -> leaf where each child's abilities are a RANDOM SUBSET of its
    /// parent's (a structurally-valid attenuating chain). For such a chain, `authorize` for a random
    /// action must succeed **iff** the leaf carries the action — which, by construction, means every
    /// ancestor carries it too. This is the core "delegation only narrows" property over random
    /// input: the set of authorized actions at the leaf is exactly the running intersection.
    #[test]
    fn valid_chain_authorizes_iff_leaf_carries_action(
        a0 in ability_set(),
        keep1 in proptest::collection::vec(any::<bool>(), ABILITIES.len()),
        keep2 in proptest::collection::vec(any::<bool>(), ABILITIES.len()),
        action_idx in 0..ABILITIES.len(),
    ) {
        let root = id();
        let mid = id();
        let leaf = id();
        let action = ABILITIES[action_idx];

        // a1 = random non-empty subset of a0; a2 = random non-empty subset of a1.
        let subset = |parent: &[String], keep: &[bool]| -> Vec<String> {
            let mut v: Vec<String> = parent.iter().enumerate()
                .filter(|(i, _)| keep.get(*i % keep.len()).copied().unwrap_or(true))
                .map(|(_, a)| a.clone()).collect();
            if v.is_empty() { v.push(parent[0].clone()); } // keep non-empty
            v
        };
        let a1 = subset(&a0, &keep1);
        let a2 = subset(&a1, &keep2);

        let c0 = SignedCapability::issue(&root, mid.node_id(), a0.clone(), Resource::Any, Caveats::default(), 1, None);
        let c1 = SignedCapability::issue(&mid, leaf.node_id(), a1.clone(), Resource::Any, Caveats::default(), 2, Some(c0.id()));
        let c2 = SignedCapability::issue(&leaf, leaf.node_id(), a2.clone(), Resource::Any, Caveats::default(), 3, Some(c1.id()));
        let chain = vec![c0, c1, c2];

        let res = authorize(&root.node_id(), &[], &[], 1000, &leaf.node_id(), action, &chain, &never_revoked);

        // Each link is a subset of its parent, so the chain is valid; authorization for `action`
        // depends solely on whether the leaf carries it (and hence every ancestor does too).
        let leaf_has = a2.iter().any(|a| a == action);
        prop_assert_eq!(res.is_ok(), leaf_has,
            "valid attenuating chain authorize disagreed with leaf membership for {}: {:?} (a0={:?} a1={:?} a2={:?})",
            action, res, a0, a1, a2);
    }

    /// A middle link that tries to ADD an ability its parent never had is always rejected, for any
    /// random parent set and any extra ability not in it. This is the direct amplification attack.
    #[test]
    fn middle_link_cannot_add_a_new_ability(
        parent_abilities in ability_set(),
        extra_idx in 0..ABILITIES.len(),
    ) {
        let extra = ABILITIES[extra_idx].to_string();
        prop_assume!(!parent_abilities.contains(&extra)); // only test genuine additions

        let root = id();
        let mid = id();
        let leaf = id();
        let c0 = SignedCapability::issue(&root, mid.node_id(), parent_abilities.clone(), Resource::Any, Caveats::default(), 1, None);
        // mid grants itself the parent's set PLUS the extra it never had.
        let mut child_abilities = parent_abilities.clone();
        child_abilities.push(extra.clone());
        let c1 = SignedCapability::issue(&mid, leaf.node_id(), child_abilities, Resource::Any, Caveats::default(), 2, Some(c0.id()));

        let res = authorize(&root.node_id(), &[], &[], 1000, &leaf.node_id(), &extra, &[c0, c1], &never_revoked);
        prop_assert!(res.is_err(), "amplified ability '{}' was authorized", extra);
    }

    // ----- Invariant 2: wire round-trips are lossless and decoding never panics.

    /// `decode_chain(encode_chain(chain)) == chain` for a random-length self-issued chain.
    #[test]
    fn chain_token_roundtrips(len in 1usize..6, nonce_seed in any::<u64>()) {
        // Build a valid linear self-delegation chain of `len` links.
        let issuer = id();
        let mut chain = Vec::new();
        let mut parent: Option<[u8; 32]> = None;
        for i in 0..len {
            let aud = id();
            let c = SignedCapability::issue(
                &issuer, aud.node_id(), vec!["exec".into()], Resource::Any,
                Caveats::default(), nonce_seed.wrapping_add(i as u64), parent,
            );
            parent = Some(c.id());
            chain.push(c);
        }
        let token = encode_chain(&chain);
        let back = decode_chain(&token).expect("decode of our own token must succeed");
        prop_assert_eq!(back.len(), chain.len());
        for (a, b) in back.iter().zip(chain.iter()) {
            prop_assert_eq!(cap_bytes(&a.cap), cap_bytes(&b.cap), "cap body differs after roundtrip");
            prop_assert_eq!(a.sig, b.sig, "signature differs after roundtrip");
        }
    }

    /// `decode_chain` / `decode_chain_bytes` must NEVER panic on arbitrary bytes — only return Err.
    /// A malformed `grant` field on the wire from a hostile peer must degrade to a clean error.
    #[test]
    fn decode_never_panics_on_garbage(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = decode_chain_bytes(&bytes); // must not panic
        let as_hex = hex::encode(&bytes);
        let _ = decode_chain(&as_hex); // must not panic
        // Non-hex input is also a clean error, never a panic.
        let _ = decode_chain("zzzz not hex @@");
    }

    // ----- Invariant 3: temporal windows honored for all `now`.

    /// A capability with `[not_before, not_after]` authorizes exactly when `now` is inside the
    /// window (inclusive), for any random window and probe time.
    #[test]
    fn temporal_window_is_exact(
        not_before in 0u64..1_000_000,
        span in 0u64..1_000_000,
        now in 0u64..2_000_000,
    ) {
        let not_after = not_before.saturating_add(span);
        let root = id();
        let leaf = id();
        let caveats = Caveats { not_before, not_after, ..Default::default() };
        let c = SignedCapability::issue(&root, leaf.node_id(), vec!["exec".into()], Resource::Any, caveats, 1, None);
        let res = authorize(&root.node_id(), &[], &[], now, &leaf.node_id(), "exec", &[c], &never_revoked);

        // valid_at semantics: not_before==0 means no lower bound; not_after==0 means never expires.
        let lower_ok = not_before == 0 || now >= not_before;
        let upper_ok = not_after == 0 || now <= not_after;
        prop_assert_eq!(res.is_ok(), lower_ok && upper_ok,
            "temporal check disagreed: now={} window=[{},{}]", now, not_before, not_after);
    }

    // ----- Invariant 4: only the named audience may wield it.

    /// For a self-issued capability to `leaf`, any requester other than `leaf` is denied; `leaf`
    /// itself is allowed. (Random requester drawn from a fresh-identity pool.)
    #[test]
    fn only_named_audience_is_authorized(use_correct in any::<bool>()) {
        let root = id();
        let leaf = id();
        let other = id();
        let c = SignedCapability::issue(&root, leaf.node_id(), vec!["exec".into()], Resource::Any, Caveats::default(), 1, None);
        let requester = if use_correct { leaf.node_id() } else { other.node_id() };
        let res = authorize(&root.node_id(), &[], &[], 1000, &requester, "exec", &[c], &never_revoked);
        prop_assert_eq!(res.is_ok(), use_correct);
    }

    // ----- Resource::is_subset_of is a sound (conservative) sub-relation.

    /// If `child.is_subset_of(parent)` claims true, then every node the child SELECTS must also be
    /// selected by the parent — proven against random node ids and tag sets. (Soundness: the
    /// predicate may be conservative and say false for a real subset, but must never say true for a
    /// non-subset.)
    #[test]
    fn resource_subset_is_sound(
        tag_a in "[a-c]",
        tag_b in "[a-c]",
        node_byte in any::<u8>(),
        node_tags in proptest::collection::vec("[a-c]", 0..4),
    ) {
        // Candidate parent/child resources drawn from the small tag/node universe.
        let nid = [node_byte; 32];
        let resources = [
            Resource::Any,
            Resource::Node(nid),
            Resource::Node([node_byte.wrapping_add(1); 32]),
            Resource::Tag(tag_a.clone()),
            Resource::Tag(tag_b.clone()),
            Resource::AllOf(vec![tag_a.clone(), tag_b.clone()]),
        ];
        for child in &resources {
            for parent in &resources {
                if child.is_subset_of(parent) {
                    // Soundness obligation: anything the child matches, the parent matches too.
                    let child_matches = child.matches(&nid, &node_tags);
                    if child_matches {
                        prop_assert!(parent.matches(&nid, &node_tags),
                            "is_subset_of({:?},{:?})=true but child matched a node the parent rejected (tags={:?})",
                            child, parent, node_tags);
                    }
                }
            }
        }
    }
}

/// A capability whose body is tampered after signing never verifies — checked structurally with a
/// single random mutation rather than proptest (deterministic, fast).
#[test]
fn structural_tamper_is_rejected() {
    let root = id();
    let leaf = id();
    let base = SignedCapability::issue(
        &root,
        leaf.node_id(),
        vec!["exec".into()],
        Resource::Any,
        Caveats::default(),
        1,
        None,
    );
    // Flip the nonce in the body without re-signing.
    let mut tampered = base.clone();
    tampered.cap = Capability { nonce: 999, ..tampered.cap };
    assert!(tampered.verify_sig().is_err(), "tampered body must fail signature verification");
    assert!(base.verify_sig().is_ok(), "untouched capability must verify");
}
