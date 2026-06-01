//! Adversarial tests — each test models a specific attack a malicious node might attempt
//! against the CE mesh and verifies the honest node defends correctly.
//!
//! Tests here are self-contained: they spin up in-process nodes with
//! `disable_local_discovery: true` so they cannot accidentally connect to any
//! live local ce node running on the developer's machine via mDNS.

use ce_chain::{Chain, Tx, TxKind};
use ce_identity::Identity;
use ce_mesh::peer_id_from_secret;
use ce_node::{Node, NodeConfig};
use ce_protocol::{CellAddress, CellSignal};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};
use tokio::time::{Duration, sleep};

static NEXT_PORT: AtomicU16 = AtomicU16::new(15_200);

fn alloc_ports() -> (u16, u16, u16) {
    let p = NEXT_PORT.fetch_add(3, Ordering::Relaxed);
    (p, p + 1, p + 2) // (p2p, api, spare)
}

fn tmpdir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join(format!("ce-adv-{}-{label}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn tmp_identity(label: &str) -> Identity {
    let dir = tmpdir(&format!("id-{label}"));
    Identity::load_or_generate(&dir.join("identity")).unwrap()
}

async fn mining_node(label: &str, bootstrap: Option<String>) -> (Node, PathBuf, u16, u16) {
    let (p2p, api, _) = alloc_ports();
    let dir = tmpdir(label);
    let node = Node::start(NodeConfig {
        listen_port: p2p,
        bootstrap_peers: bootstrap.into_iter().collect(),
        data_dir: dir.clone(),
        api_port: api,
        mine: true,
        mining_interval_secs: 2,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();
    (node, dir, p2p, api)
}

fn bootstrap_addr(dir: &PathBuf, p2p_port: u16) -> String {
    let id = Identity::load_or_generate(&dir.join("identity")).unwrap();
    let peer_id = peer_id_from_secret(id.secret_bytes()).unwrap();
    format!("/ip4/127.0.0.1/tcp/{p2p_port}/p2p/{peer_id}")
}

// ---------------------------------------------------------------------------
// Attack 1: Invalid-signature block injection
//
// An attacker crafts a block where a transaction's payload is tampered after
// signing. Chain::append() must reject it — the signature no longer matches.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn attack_invalid_tx_signature_in_block() {
    let id = tmp_identity("inv-sig");
    let mut chain = Chain::genesis();

    // Seed: mine one real block so the chain has height 1.
    let reward_kind = TxKind::UptimeReward {
        node: id.node_id(),
        amount: Chain::emission_rate(1),
        epoch: 1,
    };
    let reward_tx = Tx::new(
        reward_kind.clone(),
        id.node_id(),
        id.sign(&bincode::serialize(&reward_kind).unwrap()),
    );
    let mut b1 = chain.next_block(vec![reward_tx], id.node_id());
    b1.seal(&id);
    assert!(chain.append(b1), "legitimate block must be accepted");

    // Build a correct transfer, then tamper the amount after signing.
    let victim = tmp_identity("victim-sig");
    let transfer_kind = TxKind::Transfer {
        from: id.node_id(),
        to: victim.node_id(),
        amount: 10,
    };
    let sig = id.sign(&bincode::serialize(&transfer_kind).unwrap());
    // Tamper: different amount — signature is now invalid for this content.
    let tampered_kind = TxKind::Transfer {
        from: id.node_id(),
        to: victim.node_id(),
        amount: 9_999_999,
    };
    let tampered_tx = Tx::new(tampered_kind, id.node_id(), sig);

    let mut bad_block = chain.next_block(vec![tampered_tx], id.node_id());
    bad_block.seal(&id);

    assert!(
        !chain.append(bad_block),
        "chain accepted a block with a tampered tx signature"
    );
    assert_eq!(chain.height(), 1, "chain height must not advance after rejected block");
}

// ---------------------------------------------------------------------------
// Attack 2: Double-spend in a single block
//
// Attacker has balance B. They pack two Transfer txs each for B into one
// block, trying to spend 2×B. The chain accumulates in-block spending so the
// second tx must cause the block to be rejected.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn attack_double_spend_single_block() {
    let attacker = tmp_identity("ds-attacker");
    let victim = tmp_identity("ds-victim");
    let mut chain = Chain::genesis();

    let reward_amount = Chain::emission_rate(1);
    let reward_kind = TxKind::UptimeReward {
        node: attacker.node_id(),
        amount: reward_amount,
        epoch: 1,
    };
    let reward_tx = Tx::new(
        reward_kind.clone(),
        attacker.node_id(),
        attacker.sign(&bincode::serialize(&reward_kind).unwrap()),
    );
    let mut b1 = chain.next_block(vec![reward_tx], attacker.node_id());
    b1.seal(&attacker);
    assert!(chain.append(b1));
    assert_eq!(chain.balance(&attacker.node_id()), reward_amount as i64);

    let make_transfer = |amount: u64| -> Tx {
        let kind = TxKind::Transfer {
            from: attacker.node_id(),
            to: victim.node_id(),
            amount,
        };
        let sig = attacker.sign(&bincode::serialize(&kind).unwrap());
        Tx::new(kind, attacker.node_id(), sig)
    };

    // Both transfers for the full balance — total would be 2× balance.
    let mut bad_block =
        chain.next_block(vec![make_transfer(reward_amount), make_transfer(reward_amount)], attacker.node_id());
    bad_block.seal(&attacker);

    assert!(!chain.append(bad_block), "chain accepted a double-spend block");
    assert_eq!(chain.height(), 1, "height must not advance after rejected double-spend");
    assert_eq!(chain.balance(&attacker.node_id()), reward_amount as i64, "balance unchanged");
}

// ---------------------------------------------------------------------------
// Attack 3: BurnProof theft
//
// Attacker node B steals the burn_proof tx_id from node A's mined block and
// uses it in a signal B sends to A. Node A must reject B's signal because
// the on-chain tx was originated by A (tx.origin == A), not by B.
//
// This tests the fix added in lib.rs: `tx.origin != signal.from → drop`.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn attack_burn_proof_theft() {
    let (node_a, dir_a, p2p_a, api_a) = mining_node("bp-a", None).await;

    // Wait for node A to mine a burnable tx.
    let mut burn_info: Option<([u8; 32], u64)> = None;
    for _ in 0..20 {
        sleep(Duration::from_secs(1)).await;
        if let Some(b) = node_a.any_burnable_tx().await {
            burn_info = Some(b);
            break;
        }
    }
    let (burn_tx_id, _burn_amount) =
        burn_info.expect("node A failed to mine a burnable tx in time");

    // Start attacker node B, bootstrapping from A so it syncs A's chain.
    let bs_a = bootstrap_addr(&dir_a, p2p_a);
    let (p2p_b, api_b, _) = alloc_ports();
    let _node_b = Node::start(NodeConfig {
        listen_port: p2p_b,
        bootstrap_peers: vec![bs_a],
        data_dir: tmpdir("bp-b"),
        api_port: api_b,
        mine: false,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();

    // Wait for B to sync at least one block from A.
    for _ in 0..15 {
        sleep(Duration::from_secs(1)).await;
        let status: serde_json::Value =
            reqwest::get(format!("http://127.0.0.1:{api_b}/status"))
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        if status["height"].as_u64().unwrap_or(0) >= 1 {
            break;
        }
    }

    // B posts to its own /signals/send with A's burn_tx_id.
    // Node B will build the signal signed by B's identity (different node_id than A).
    // When A receives this gossip signal:
    //   - tx.origin == A's node_id
    //   - signal.from == B's node_id
    //   → ownership mismatch → signal must be dropped.
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "payload_hex": hex::encode(b"stolen burn proof"),
        "to": "broadcast",
        "capabilities": [{"name": "steal", "version": 1}],
        "burn_tx_id_hex": hex::encode(burn_tx_id),
    });
    let _resp = client
        .post(format!("http://127.0.0.1:{api_b}/signals/send"))
        .json(&body)
        .send()
        .await
        .expect("POST /signals/send");

    // Give gossipsub time to propagate to A.
    sleep(Duration::from_secs(3)).await;

    // A should NOT have accepted a signal whose burn_proof was originated by A
    // but sent by B (different node_id).
    let signals_on_a: serde_json::Value =
        reqwest::get(format!("http://127.0.0.1:{api_a}/signals"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

    // B's node_id comes from its data_dir identity.
    let b_id = Identity::load_or_generate(&tmpdir("bp-b").join("identity")).unwrap();
    let b_hex = hex::encode(b_id.node_id());

    let stolen_accepted = signals_on_a
        .as_array()
        .map(|arr| arr.iter().any(|s| s["from"].as_str() == Some(&b_hex)))
        .unwrap_or(false);

    assert!(
        !stolen_accepted,
        "node A accepted a signal with a stolen burn_proof (burn-proof theft not blocked)"
    );
}

// ---------------------------------------------------------------------------
// Attack 4: Signal nonce replay
//
// An attacker saves a valid signal and rebroadcasts it verbatim. Because the
// nonce is <= the previously-accepted value the receiving node must drop it.
// This is a pure logic test of the nonce tracking used in the event loop.
// ---------------------------------------------------------------------------
#[test]
fn attack_signal_nonce_replay_detection() {
    use std::collections::HashMap;

    let sender = tmp_identity("nonce-sender");

    // Simulate the per-sender nonce tracking that runs in the mesh event loop.
    let mut last_nonce: HashMap<ce_identity::NodeId, u64> = HashMap::new();

    let make_signal = |nonce: u64| -> CellSignal {
        CellSignal::build(
            sender.node_id(),
            CellAddress::Broadcast,
            vec![],
            vec![],
            None,
            nonce,
            &sender,
        )
    };

    let passes = |last: &HashMap<_, _>, sig: &CellSignal| -> bool {
        sig.verify().is_ok()
            && last.get(&sig.from).map(|&p| sig.nonce > p).unwrap_or(true)
    };

    // First signal (nonce=5) — accepted.
    let sig5 = make_signal(5);
    assert!(passes(&last_nonce, &sig5), "fresh signal nonce=5 must pass");
    last_nonce.insert(sig5.from, sig5.nonce);

    // Exact replay (nonce=5) — rejected.
    let replay = make_signal(5);
    assert!(!passes(&last_nonce, &replay), "replay nonce=5 must be rejected");

    // Old nonce — rejected.
    let old = make_signal(3);
    assert!(!passes(&last_nonce, &old), "old nonce=3 must be rejected");

    // Fresh nonce — accepted.
    let fresh = make_signal(6);
    assert!(passes(&last_nonce, &fresh), "fresh nonce=6 must pass");
}

// ---------------------------------------------------------------------------
// Attack 5: Inflated UptimeReward — supply inflation attempt
//
// An attacker mines a block with an UptimeReward larger than the emission
// schedule allows. Chain::append() must reject it.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn attack_inflated_uptime_reward() {
    let attacker = tmp_identity("inflate");
    let mut chain = Chain::genesis();

    let legitimate = Chain::emission_rate(1);
    let inflated = legitimate + 1_000_000_000;

    let bad_kind = TxKind::UptimeReward {
        node: attacker.node_id(),
        amount: inflated,
        epoch: 1,
    };
    let bad_tx = Tx::new(
        bad_kind.clone(),
        attacker.node_id(),
        attacker.sign(&bincode::serialize(&bad_kind).unwrap()),
    );
    let mut bad_block = chain.next_block(vec![bad_tx], attacker.node_id());
    bad_block.seal(&attacker);

    assert!(
        !chain.append(bad_block),
        "chain accepted an inflated UptimeReward (emission integrity violated)"
    );
    assert_eq!(chain.total_supply(), 0, "total supply must remain 0 after rejected block");
}

// ---------------------------------------------------------------------------
// Attack 6: Job bid with zero balance (credit DoS)
//
// An attacker with no balance tries to bid for a job via the HTTP API. The
// node must reject it with 402 — no tx is queued, no escrow locked.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn attack_job_bid_zero_balance() {
    let (p2p, api, _) = alloc_ports();
    let _node = Node::start(NodeConfig {
        listen_port: p2p,
        bootstrap_peers: vec![],
        data_dir: tmpdir("overbid"),
        api_port: api,
        mine: false,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();

    sleep(Duration::from_millis(400)).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{api}/jobs/bid"))
        .json(&serde_json::json!({
            "image": "alpine:latest",
            "cpu_cores": 1,
            "mem_mb": 128,
            "duration_secs": 30,
            "bid": 1_000_000
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 402, "bid with zero balance must return 402");
}
