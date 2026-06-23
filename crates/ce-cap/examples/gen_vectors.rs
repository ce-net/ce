//! Generate deterministic golden vectors for the capability wire format, so the TypeScript
//! `@ce-net/cap` port can assert byte-for-byte agreement with this Rust implementation.
//!
//! Run: `cargo run -p ce-cap --example gen_vectors > ../ce-ts/cap/test/golden-vectors.json`
//! Identities are built from fixed seeds, so the output is fully reproducible across machines.

use ce_cap::{cap_bytes, cap_id, Caveats, Resource, SignedCapability};
use ce_identity::Identity;
use serde_json::json;

fn id(seed: u8) -> Identity {
    Identity::from_secret_bytes(&[seed; 32])
}

fn main() {
    let root = id(0x11);
    let mid = id(0x22);
    let leaf = id(0x33);
    let target = id(0x44);

    // (name, audience, abilities, resource, caveats, nonce) — covers every Resource variant, the
    // Caveats Option permutations, empty/multi abilities, and the u64::MAX nonce boundary.
    let cases: Vec<(&str, &Identity, Vec<String>, Resource, Caveats, u64)> = vec![
        ("any_default", &leaf, vec!["exec".into()], Resource::Any, Caveats::default(), 1),
        (
            "multi_ability",
            &leaf,
            vec!["exec".into(), "sync".into(), "tunnel".into()],
            Resource::Any,
            Caveats::default(),
            2,
        ),
        ("empty_abilities", &leaf, vec![], Resource::Any, Caveats::default(), 3),
        ("resource_node", &leaf, vec!["exec".into()], Resource::Node(target.node_id()), Caveats::default(), 4),
        ("resource_tag", &leaf, vec!["exec".into()], Resource::Tag("gpu".into()), Caveats::default(), 5),
        (
            "resource_allof",
            &leaf,
            vec!["exec".into()],
            Resource::AllOf(vec!["gpu".into(), "linux".into()]),
            Caveats::default(),
            6,
        ),
        (
            "caveats_expiry",
            &leaf,
            vec!["exec".into()],
            Resource::Any,
            Caveats { not_after: 1_000_000, ..Default::default() },
            7,
        ),
        (
            "caveats_full",
            &leaf,
            vec!["tunnel".into()],
            Resource::Any,
            Caveats {
                not_before: 100,
                not_after: 2_000_000,
                max_cpu: Some(4),
                max_mem_mb: Some(512),
                max_credits: Some(1000),
                allowed_ports: Some(vec![22, 8080]),
                path_prefix: Some("/home/user".into()),
            },
            8,
        ),
        ("nonce_max", &leaf, vec!["exec".into()], Resource::Any, Caveats::default(), u64::MAX),
    ];

    let mut single = Vec::new();
    for (name, audience, abilities, resource, caveats, nonce) in cases {
        let signed = SignedCapability::issue(&root, audience.node_id(), abilities, resource, caveats, nonce, None);
        single.push(json!({
            "name": name,
            "issuer_hex": hex::encode(signed.cap.issuer),
            "audience_hex": hex::encode(signed.cap.audience),
            "cap_bytes_hex": hex::encode(cap_bytes(&signed.cap)),
            "cap_id_hex": hex::encode(cap_id(&signed.cap)),
            "sig_hex": hex::encode(signed.sig),
            "chain_hex": ce_cap::encode_chain(std::slice::from_ref(&signed)),
        }));
    }

    // A continuity-correct two-link chain: root -> mid -> leaf.
    let c0 = SignedCapability::issue(
        &root,
        mid.node_id(),
        vec!["exec".into(), "sync".into()],
        Resource::Any,
        Caveats::default(),
        100,
        None,
    );
    let c1 = SignedCapability::issue(
        &mid,
        leaf.node_id(),
        vec!["exec".into()],
        Resource::Any,
        Caveats::default(),
        101,
        Some(c0.id()),
    );
    let two_link = ce_cap::encode_chain(&[c0, c1]);

    let out = json!({
        "seeds": { "root": "0x11", "mid": "0x22", "leaf": "0x33", "target": "0x44" },
        "node_ids": {
            "root": hex::encode(root.node_id()),
            "mid": hex::encode(mid.node_id()),
            "leaf": hex::encode(leaf.node_id()),
            "target": hex::encode(target.node_id()),
        },
        "single": single,
        "two_link_chain_hex": two_link,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
