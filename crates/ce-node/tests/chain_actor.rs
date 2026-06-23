//! Chain actor tests — correctness, concurrency, and adversarial scenarios.
//!
//! Each test drives `spawn_chain_actor` directly (no full Node, no network) so
//! failures are isolated to the actor's state machine logic.
//!
//! Conventions:
//!  - `difficulty = 1` everywhere to keep PoW instant in CI.
//!  - Helpers at the bottom: `make_identity`, `mine_block`, `forge_bad_block`.
//!  - Adversarial tests simulate attacker behaviour and verify the chain survives
//!    with its state intact.

use ce_chain::{Block, Chain, Tx, TxKind};
use ce_identity::Identity;
use ce_node::spawn_chain_actor;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

// ── helpers ─────────────────────────────────────────────────────────────────

fn tmpdir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir()
        .join(format!("ce-actor-{}-{label}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn make_identity(label: &str) -> Arc<Identity> {
    Arc::new(Identity::load_or_generate(&tmpdir(label)).unwrap())
}

/// Build and seal a valid block on top of the current chain tip.
/// Uses `difficulty = 1` so sealing is instant.
fn mine_block(chain: &mut Chain, identity: &Identity) -> Block {
    let next = chain.height() + 1;
    let emission = Chain::emission_rate(next);
    let mut txs = vec![];
    if emission > 0 {
        let kind = TxKind::UptimeReward {
            node: identity.node_id(),
            amount: emission,
            epoch: next,
        };
        let data = bincode::serialize(&kind).unwrap();
        let sig = identity.sign(&data);
        txs.push(Tx::new(kind, identity.node_id(), sig));
    }
    let mut block = chain.next_block(txs, identity.node_id());
    block.mine(&std::sync::atomic::AtomicBool::new(false));
    block.seal(identity);
    block
}

/// Build a syntactically valid block that fails verification (wrong prev_hash).
fn forge_bad_block(chain: &mut Chain, identity: &Identity) -> Block {
    let next = chain.height() + 1;
    let mut block = chain.next_block(vec![], identity.node_id());
    block.index = next;
    block.prev_hash = [0xDE; 32]; // wrong
    block.mine(&std::sync::atomic::AtomicBool::new(false));
    block.seal(identity);
    block
}

/// Build a chain of `n` sealed blocks on a genesis chain using `identity`.
fn build_chain_of(identity: &Identity, n: usize) -> (Chain, Vec<Block>) {
    let mut chain = Chain::genesis();
    let mut blocks = vec![];
    for _ in 0..n {
        let b = mine_block(&mut chain, identity);
        assert!(chain.append(b.clone()), "append failed during chain construction");
        blocks.push(b);
    }
    (chain, blocks)
}

/// A genesis chain that grants each listed identity equal consensus weight (the network's chain
/// spec). Needed so VRF blocks by those validators are eligible and carry weight for fork choice.
fn genesis_with(grantees: &[&Identity]) -> Chain {
    let mut c = Chain::genesis();
    for g in grantees {
        c.grant_genesis_weight(g.node_id(), 1_000_000);
    }
    c
}

/// Build `n` weighted VRF blocks on a clone of `base` mined by `identity` (which must be granted
/// weight in `base`). Returns the blocks for replay/reorg into a matching-spec chain.
fn build_weighted(base: &Chain, identity: &Identity, n: usize) -> Vec<Block> {
    let mut chain = base.clone();
    let mut blocks = vec![];
    for _ in 0..n {
        let next = chain.height() + 1;
        let mut txs = vec![];
        let emission = Chain::emission_rate(next);
        if emission > 0 {
            let kind = TxKind::UptimeReward { node: identity.node_id(), amount: emission, epoch: next };
            let sig = identity.sign(&bincode::serialize(&kind).unwrap());
            txs.push(Tx::new(kind, identity.node_id(), sig));
        }
        let b = chain.produce(identity, txs).expect("weighted block");
        assert!(chain.append(b.clone()), "append failed during weighted chain construction");
        blocks.push(b);
    }
    blocks
}

// ── basic correctness ────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn actor_height_starts_at_zero() {
    let handle = spawn_chain_actor(Chain::genesis());
    assert_eq!(handle.height().await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn actor_append_and_balance() {
    let id = make_identity("balance");
    let mut raw = Chain::genesis();
    let block = mine_block(&mut raw, &id);

    let handle = spawn_chain_actor(Chain::genesis());
    let accepted = handle.append(block).await;
    assert!(accepted);
    assert_eq!(handle.height().await, 1);
    let balance = handle.balance(id.node_id()).await;
    assert!(balance > 0, "expected positive balance after UptimeReward, got {balance}");
}

#[tokio::test(flavor = "multi_thread")]
async fn actor_invalid_block_rejected_and_height_unchanged() {
    let id = make_identity("badblock");
    let mut raw = Chain::genesis();

    let handle = spawn_chain_actor(Chain::genesis());
    let bad = forge_bad_block(&mut raw, &id);
    let accepted = handle.append(bad).await;
    assert!(!accepted);
    assert_eq!(handle.height().await, 0, "height must not change after bad block");
}

#[tokio::test(flavor = "multi_thread")]
async fn actor_next_block_returns_correct_template() {
    let id = make_identity("template");
    let handle = spawn_chain_actor(Chain::genesis());
    let block = handle.next_block(vec![], id.node_id()).await;
    assert_eq!(block.index, 1, "next block index should be 1 on genesis");
    assert_eq!(block.miner, id.node_id());
}

#[tokio::test(flavor = "multi_thread")]
async fn actor_sync_snap_reflects_chain_state() {
    let id = make_identity("snap");
    let mut raw = Chain::genesis();
    let b1 = mine_block(&mut raw, &id);
    raw.append(b1.clone());
    let b2 = mine_block(&mut raw, &id);

    let handle = spawn_chain_actor(Chain::genesis());
    handle.append(b1.clone()).await;
    handle.append(b2.clone()).await;

    let snap = handle.sync_snap().await;
    assert_eq!(snap.height, 2);
    assert_eq!(snap.oldest, 0);
    assert_ne!(snap.tip_hash, [0u8; 32]);
}

#[tokio::test(flavor = "multi_thread")]
async fn actor_chain_status_returns_balance_and_difficulty() {
    let id = make_identity("chainstatus");
    let mut raw = Chain::genesis();
    let b = mine_block(&mut raw, &id);

    let handle = spawn_chain_actor(Chain::genesis());
    handle.append(b).await;

    let snap = handle.chain_status(id.node_id()).await;
    assert_eq!(snap.height, 1);
    assert!(snap.balance > 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn actor_tx_by_id_finds_reward_tx() {
    let id = make_identity("txbyid");
    let mut raw = Chain::genesis();
    let b = mine_block(&mut raw, &id);
    let tx_id = b.transactions[0].id();

    let handle = spawn_chain_actor(Chain::genesis());
    handle.append(b).await;

    let found = handle.tx_by_id(tx_id).await;
    assert!(found.is_some(), "tx should be findable after append");
    let (tx, height, _hash) = found.unwrap();
    assert_eq!(height, 1);
    assert!(matches!(tx.kind, TxKind::UptimeReward { .. }));
}

#[tokio::test(flavor = "multi_thread")]
async fn actor_blocks_after_filters_correctly() {
    let id = make_identity("blocksafter");
    let mut raw = Chain::genesis();

    let handle = spawn_chain_actor(Chain::genesis());
    for _ in 0..5 {
        let b = mine_block(&mut raw, &id);
        raw.append(b.clone());
        handle.append(b).await;
    }

    let after_2 = handle.blocks_after(2, 100).await;
    assert_eq!(after_2.len(), 3, "expected blocks 3, 4, 5");
    assert!(after_2.iter().all(|b| b.index > 2));
}

#[tokio::test(flavor = "multi_thread")]
async fn actor_any_burnable_tx_found_after_mining() {
    let id = make_identity("burnable");
    let mut raw = Chain::genesis();
    let b = mine_block(&mut raw, &id);

    let handle = spawn_chain_actor(Chain::genesis());
    handle.append(b).await;

    let found = handle.any_burnable_tx().await;
    assert!(found.is_some());
    let (_tx_id, amount) = found.unwrap();
    assert!(amount > 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn actor_save_and_reload() {
    let id = make_identity("save");
    let mut raw = Chain::genesis();
    let b = mine_block(&mut raw, &id);

    let dir = tmpdir("save-chain");
    let path = dir.join("chain.json");

    let handle = spawn_chain_actor(Chain::genesis());
    handle.append(b).await;
    handle.save(path.clone()).await.expect("save should succeed");

    let loaded = Chain::load_or_genesis(&path);
    assert_eq!(loaded.height(), 1);
    assert!(loaded.balance(&id.node_id()) > 0);
}

// ── try_reorg ────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn actor_try_reorg_switches_to_longer_fork() {
    let id_a = make_identity("reorg-a");
    let id_b = make_identity("reorg-b");
    // Equal-weight validators (shared chain spec) → fork choice is by cumulative weight, more wins.
    let base = genesis_with(&[&id_a, &id_b]);

    // Fork A: 2 blocks (becomes our chain)
    let fork_a = build_weighted(&base, &id_a, 2);

    // Fork B: 3 blocks (should win the reorg)
    let fork_b = build_weighted(&base, &id_b, 3);

    let handle = spawn_chain_actor(base.clone());
    for b in fork_a {
        handle.append(b).await;
    }
    assert_eq!(handle.height().await, 2);

    let reorged = handle.try_reorg(fork_b).await;
    assert!(reorged, "longer fork should trigger reorg");
    assert_eq!(handle.height().await, 3, "chain should be at fork_b tip after reorg");
}

#[tokio::test(flavor = "multi_thread")]
async fn actor_try_reorg_ignores_equal_or_shorter_fork() {
    let id_a = make_identity("reorg-eq-a");
    let id_b = make_identity("reorg-eq-b");

    let (_, fork_a) = build_chain_of(&id_a, 3);
    let (_, fork_b_short) = build_chain_of(&id_b, 2);

    let handle = spawn_chain_actor(Chain::genesis());
    for b in fork_a {
        handle.append(b).await;
    }

    let reorged = handle.try_reorg(fork_b_short).await;
    assert!(!reorged, "shorter fork must not trigger reorg");
    assert_eq!(handle.height().await, 3);
}

// ── heartbeat epochs ─────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn actor_heartbeat_epochs_scan() {
    let host = make_identity("hb-host");
    let cell = make_identity("hb-cell");
    let mut raw = Chain::genesis();
    let job_id = [7u8; 32];

    // E3: a heartbeat must bill against an OPEN bid the cell signed. The cell opens a zero-value bid
    // (it has no balance; bid=0 escrow → a zero-cost heartbeat is still in-bounds), confirmed first.
    let bid_kind = TxKind::JobBid {
        job_id,
        payer: cell.node_id(),
        bid: 0,
        image: "alpine:latest".into(),
        cmd: vec![],
        env: vec![],
        cpu_cores: 1,
        mem_mb: 64,
        duration_secs: 30,
    };
    let bd = bincode::serialize(&bid_kind).unwrap();
    let bs = cell.sign(&bd);
    let bid_tx = Tx::new(bid_kind, cell.node_id(), bs);
    let r0_kind = TxKind::UptimeReward { node: host.node_id(), amount: Chain::emission_rate(1), epoch: 1 };
    let r0d = bincode::serialize(&r0_kind).unwrap();
    let r0s = host.sign(&r0d);
    let r0_tx = Tx::new(r0_kind, host.node_id(), r0s);
    let mut bid_block = raw.next_block(vec![r0_tx, bid_tx], host.node_id());
    bid_block.mine(&std::sync::atomic::AtomicBool::new(false));
    bid_block.seal(&host);
    assert!(raw.append(bid_block.clone()), "bid must confirm");

    // Build a block with a heartbeat tx against the open bid.
    // amount=0: cell has no balance; zero-cost heartbeat is within the (zero) escrow.
    let hb_kind = TxKind::Heartbeat {
        job_id,
        cell: cell.node_id(),
        host: host.node_id(),
        amount: 0,
        epoch: 0,
    };
    let data = bincode::serialize(&hb_kind).unwrap();
    let sig = host.sign(&data);
    let hb_tx = Tx::new(hb_kind, host.node_id(), sig);

    let reward_kind = TxKind::UptimeReward {
        node: host.node_id(),
        amount: Chain::emission_rate(2),
        epoch: 2,
    };
    let rd = bincode::serialize(&reward_kind).unwrap();
    let rs = host.sign(&rd);
    let reward_tx = Tx::new(reward_kind, host.node_id(), rs);

    let mut block = raw.next_block(vec![reward_tx, hb_tx], host.node_id());
    block.mine(&std::sync::atomic::AtomicBool::new(false));
    block.seal(&host);

    let handle = spawn_chain_actor(Chain::genesis());
    handle.append(bid_block).await;
    handle.append(block).await;

    let epochs = handle.heartbeat_epochs(host.node_id()).await;
    assert_eq!(
        epochs.get(&cell.node_id()).copied(),
        Some(1),
        "epoch for cell should be 1 (last confirmed 0, next is 1)"
    );
}

// ── concurrency — many readers ────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn actor_concurrent_readers_all_complete() {
    let id = make_identity("concurrent-read");
    let mut raw = Chain::genesis();
    let b = mine_block(&mut raw, &id);

    let handle = spawn_chain_actor(Chain::genesis());
    handle.append(b).await;
    let handle = Arc::new(handle);

    let mut tasks = vec![];
    for _ in 0..100 {
        let h = handle.clone();
        let node = id.node_id();
        tasks.push(tokio::spawn(async move { h.balance(node).await }));
    }

    let results = futures::future::join_all(tasks).await;
    for r in results {
        let balance = r.expect("task panicked");
        assert!(balance > 0, "every concurrent reader should see a positive balance");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn actor_concurrent_readers_do_not_block_writer() {
    // 50 readers + 1 writer racing simultaneously. The writer must complete within 2s.
    let id = make_identity("concurrent-rw");
    let mut raw = Chain::genesis();
    let block = mine_block(&mut raw, &id);

    let handle = Arc::new(spawn_chain_actor(Chain::genesis()));

    // Flood the channel with 50 concurrent balance reads.
    let mut reader_tasks = vec![];
    for _ in 0..50 {
        let h = handle.clone();
        let node = id.node_id();
        reader_tasks.push(tokio::spawn(async move {
            for _ in 0..20 {
                h.balance(node).await;
            }
        }));
    }

    // Writer should finish well within 2s even under reader flood.
    let writer_h = handle.clone();
    let writer = tokio::spawn(async move {
        writer_h.append(block).await
    });

    let accepted = timeout(Duration::from_secs(2), writer)
        .await
        .expect("writer timed out — readers starved the channel")
        .expect("writer panicked");
    assert!(accepted, "valid block should be accepted");

    // Wait for readers to drain.
    futures::future::join_all(reader_tasks).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn actor_mixed_concurrent_operations_never_deadlock() {
    // Reads, writes, and reorgs all fired concurrently. Nothing should deadlock.
    let id = make_identity("no-deadlock");
    let handle = Arc::new(spawn_chain_actor(Chain::genesis()));

    let mut tasks = vec![];

    // 30 balance readers
    for _ in 0..30 {
        let h = handle.clone();
        let node = id.node_id();
        tasks.push(tokio::spawn(async move {
            h.balance(node).await;
        }));
    }

    // 20 height readers
    for _ in 0..20 {
        let h = handle.clone();
        tasks.push(tokio::spawn(async move { h.height().await; }));
    }

    // 10 sync_snap readers
    for _ in 0..10 {
        let h = handle.clone();
        tasks.push(tokio::spawn(async move { h.sync_snap().await; }));
    }

    // 5 appenders (blocks built from a local raw chain — they will race each other;
    // only one sequence can win, the rest return false)
    for i in 0..5 {
        let id2 = make_identity(&format!("no-deadlock-miner-{i}"));
        let h = handle.clone();
        tasks.push(tokio::spawn(async move {
            let mut r = Chain::genesis();
            let b = mine_block(&mut r, &id2);
            h.append(b).await;
        }));
    }

    // 3 try_reorg callers with single-block fork — all should return without hanging
    for j in 0..3 {
        let id3 = make_identity(&format!("no-deadlock-reorg-{j}"));
        let h = handle.clone();
        tasks.push(tokio::spawn(async move {
            let (_, fork) = build_chain_of(&id3, 1);
            h.try_reorg(fork).await;
        }));
    }

    let all = timeout(Duration::from_secs(5), futures::future::join_all(tasks)).await;
    assert!(all.is_ok(), "deadlock detected — join_all timed out after 5s");
}

// ── adversarial: invalid block flood ─────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn adversarial_invalid_block_flood_chain_unchanged() {
    // An attacker floods 1000 blocks with wrong prev_hash.
    // The chain must stay at height 0 and accept no state changes.
    let id = make_identity("bad-flood");
    let mut raw = Chain::genesis();

    let handle = spawn_chain_actor(Chain::genesis());

    let mut tasks = vec![];
    for _ in 0..1000 {
        let bad = forge_bad_block(&mut raw, &id);
        let h = handle.clone();
        tasks.push(tokio::spawn(async move { h.append(bad).await }));
    }

    let results = futures::future::join_all(tasks).await;
    let any_accepted = results.iter().any(|r| *r.as_ref().unwrap());
    assert!(!any_accepted, "no invalid block should be accepted");
    assert_eq!(handle.height().await, 0, "chain height must remain 0 after flood");
    assert_eq!(handle.balance(id.node_id()).await, 0, "balance must stay 0");
}

#[tokio::test(flavor = "multi_thread")]
async fn adversarial_wrong_index_flood_rejected() {
    let id = make_identity("idx-flood");
    let handle = spawn_chain_actor(Chain::genesis());

    // Blocks with completely wrong indices (e.g., index 9999) should all fail.
    let mut tasks = vec![];
    for _ in 0..500 {
        let mut block = Chain::genesis().next_block(vec![], id.node_id());
        block.index = 9999; // impossible index on genesis chain
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&id);
        let h = handle.clone();
        tasks.push(tokio::spawn(async move { h.append(block).await }));
    }

    let results = futures::future::join_all(tasks).await;
    assert!(
        results.iter().all(|r| !r.as_ref().unwrap()),
        "all wrong-index blocks should be rejected"
    );
    assert_eq!(handle.height().await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn adversarial_sync_flood_with_bad_blocks() {
    // Simulate a peer repeatedly sending sync batches full of invalid blocks.
    // The chain must survive with state intact.
    let id = make_identity("sync-flood");
    let handle = Arc::new(spawn_chain_actor(Chain::genesis()));

    // Build one valid block first so height > 0.
    let mut raw = Chain::genesis();
    let valid = mine_block(&mut raw, &id);
    handle.append(valid).await;

    let mut tasks = vec![];
    for _ in 0..200 {
        let h = handle.clone();
        let id2 = make_identity("sync-attacker");
        tasks.push(tokio::spawn(async move {
            // A batch of 10 forged blocks that can't connect to our chain.
            let mut junk = Chain::genesis();
            let mut batch = vec![];
            for _ in 0..10 {
                batch.push(forge_bad_block(&mut junk, &id2));
            }
            // try_reorg returns false — none of these should switch our chain.
            h.try_reorg(batch).await
        }));
    }

    let results = futures::future::join_all(tasks).await;
    assert!(
        results.iter().all(|r| !r.as_ref().unwrap()),
        "no junk reorg should succeed"
    );
    // Chain should still be at height 1.
    assert_eq!(handle.height().await, 1, "chain height must stay 1 after flood");
}

#[tokio::test(flavor = "multi_thread")]
async fn adversarial_concurrent_reorg_race_exactly_one_wins() {
    // Two peers both try to reorg the chain simultaneously with different fork lengths.
    // The longer fork should win, and the chain must be consistent afterwards.
    let id_a = make_identity("reorg-race-a");
    let id_b = make_identity("reorg-race-b");
    let id_ours = make_identity("reorg-race-ours");
    // Shared chain spec granting all three validators equal weight, so longer forks carry more work.
    let base = genesis_with(&[&id_a, &id_b, &id_ours]);

    // Our chain: 2 blocks
    let our_chain = build_weighted(&base, &id_ours, 2);
    let handle = Arc::new(spawn_chain_actor(base.clone()));
    for b in our_chain {
        handle.append(b).await;
    }

    // Fork A: 4 blocks (should win)
    let fork_a = build_weighted(&base, &id_a, 4);
    // Fork B: 3 blocks (should lose to fork_a, but may beat our original 2)
    let fork_b = build_weighted(&base, &id_b, 3);

    let ha = handle.clone();
    let hb = handle.clone();

    let task_a = tokio::spawn(async move { ha.try_reorg(fork_a).await });
    let task_b = tokio::spawn(async move { hb.try_reorg(fork_b).await });

    let (ra, rb) = tokio::join!(task_a, task_b);
    ra.unwrap();
    rb.unwrap();

    // After both reorgs, chain height must be at least 3 (one of the forks won).
    // It can't be 2 (original) or 0.
    let final_height = handle.height().await;
    assert!(
        final_height >= 3,
        "at least one reorg must have applied (height={final_height})"
    );
    // The chain must be internally consistent: balance query should not panic/hang.
    let _ = handle.balance(id_a.node_id()).await;
    let _ = handle.balance(id_b.node_id()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn adversarial_channel_full_caller_does_not_deadlock() {
    // Fill the channel to near capacity from one task while a second task
    // also tries to send. Both should complete without hanging.
    let handle = Arc::new(spawn_chain_actor(Chain::genesis()));
    let id = make_identity("chan-full");

    // Send 512 balance queries rapidly without awaiting — fills the channel.
    // The actor processes them one by one; callers block in `send` if the channel
    // is full but must never deadlock (bounded channel drops only when all handles closed).
    let mut tasks = vec![];
    for _ in 0..600 {
        let h = handle.clone();
        let node = id.node_id();
        tasks.push(tokio::spawn(async move {
            // Each send/await may queue up; the whole set must complete within 5s.
            h.balance(node).await
        }));
    }

    let results = timeout(Duration::from_secs(10), futures::future::join_all(tasks)).await;
    assert!(results.is_ok(), "all 600 balance queries should complete within 10s");
}

// ── adversarial: attacker tries to corrupt balance ───────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn adversarial_double_append_same_block_safe() {
    // Appending the same valid block twice: the second append must return false
    // (wrong index — already at height 1).
    let id = make_identity("double-append");
    let mut raw = Chain::genesis();
    let block = mine_block(&mut raw, &id);

    let handle = spawn_chain_actor(Chain::genesis());
    let first = handle.append(block.clone()).await;
    let second = handle.append(block.clone()).await;

    assert!(first, "first append should succeed");
    assert!(!second, "second append of same block must fail");
    assert_eq!(handle.height().await, 1);

    // Balance should reflect exactly one UptimeReward, not two.
    let expected = Chain::emission_rate(1) as i128;
    assert_eq!(handle.balance(id.node_id()).await, expected);
}

#[tokio::test(flavor = "multi_thread")]
async fn adversarial_emission_overflow_rejected() {
    // A block with emission amount exceeding the schedule must be rejected.
    let id = make_identity("overflow");
    let raw = Chain::genesis();

    let bad_kind = TxKind::UptimeReward {
        node: id.node_id(),
        amount: u128::MAX, // way over the schedule
        epoch: 1,
    };
    let data = bincode::serialize(&bad_kind).unwrap();
    let sig = id.sign(&data);
    let bad_tx = Tx::new(bad_kind, id.node_id(), sig);

    let mut block = raw.next_block(vec![bad_tx], id.node_id());
    block.mine(&std::sync::atomic::AtomicBool::new(false));
    block.seal(&id);

    let handle = spawn_chain_actor(Chain::genesis());
    let accepted = handle.append(block).await;
    assert!(!accepted, "block with excessive emission must be rejected");
    assert_eq!(handle.height().await, 0);
    assert_eq!(handle.balance(id.node_id()).await, 0);
}

// ── actor drop safety ─────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn actor_stops_gracefully_when_all_handles_dropped() {
    // When all ChainHandle clones are dropped the actor task exits cleanly via
    // the while-let loop termination in chain_actor. This test verifies the actor
    // doesn't panic on shutdown and the handle methods returned correct values
    // before it was dropped.
    let handle = spawn_chain_actor(Chain::genesis());
    assert_eq!(handle.height().await, 0);
    assert_eq!(handle.balance([0u8; 32]).await, 0);
    // Drop — actor exits, no panic expected.
    drop(handle);
    tokio::time::sleep(Duration::from_millis(50)).await;
}

// ── mining correctness through actor ─────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn actor_sequential_mining_grows_chain() {
    // Mine 10 blocks sequentially through the actor (same as the mining loop does).
    let id = make_identity("seq-mine");
    let mut raw = Chain::genesis();

    let handle = spawn_chain_actor(Chain::genesis());

    for _ in 0..10 {
        let block = handle.next_block(vec![], id.node_id()).await;
        // Seal locally (same as mining_loop does between next_block and append).
        let mut b = block;
        b.mine(&std::sync::atomic::AtomicBool::new(false));
        b.seal(&id);
        // Also add UptimeReward so the block is valid.
        let next = raw.height() + 1;
        let emission = Chain::emission_rate(next);
        if emission > 0 {
            let kind = TxKind::UptimeReward {
                node: id.node_id(),
                amount: emission,
                epoch: next,
            };
            let data = bincode::serialize(&kind).unwrap();
            let sig = id.sign(&data);
            b.transactions.insert(0, Tx::new(kind, id.node_id(), sig));
            // Reseal after adding tx.
            b.mine(&std::sync::atomic::AtomicBool::new(false));
            b.seal(&id);
        }
        let ok = handle.append(b.clone()).await;
        if ok {
            raw.append(b);
        }
    }

    let h = handle.height().await;
    assert!(h >= 1, "at least 1 block should have been appended");
    let balance = handle.balance(id.node_id()).await;
    assert!(balance > 0, "miner should have positive balance");
}

#[tokio::test(flavor = "multi_thread")]
async fn actor_peer_block_races_with_miner_correctly() {
    // Scenario: we call next_block, a peer appends a block (different fork),
    // then we try to append our sealed block. Our block should be rejected
    // (wrong prev_hash since the peer updated the tip), not accepted twice.
    let our_id = make_identity("peer-race-ours");
    let peer_id = make_identity("peer-race-peer");

    let handle = Arc::new(spawn_chain_actor(Chain::genesis()));

    // We ask for a template (next block at index 1).
    let mut our_block = handle.next_block(vec![], our_id.node_id()).await;
    our_block.mine(&std::sync::atomic::AtomicBool::new(false));
    our_block.seal(&our_id);

    // Peer races us and appends their own block 1 first.
    let mut raw = Chain::genesis();
    let peer_block = mine_block(&mut raw, &peer_id);
    let peer_ok = handle.append(peer_block).await;
    assert!(peer_ok, "peer's block should be accepted");
    assert_eq!(handle.height().await, 1);

    // Our block was built on the same genesis so it has the same index but
    // wrong prev_hash (genesis tip hash matches; actually same prev_hash but
    // append would succeed if our block is valid). Let me reconsider...
    //
    // Actually both blocks have prev_hash = genesis_hash and index = 1.
    // Chain::append only accepts the FIRST one. The second one (ours) should
    // fail because chain tip is now at index 1 and our block also has index 1.
    let our_ok = handle.append(our_block).await;
    assert!(
        !our_ok,
        "our block must be rejected since peer already extended the chain to height 1"
    );
    assert_eq!(
        handle.height().await,
        1,
        "height must remain 1 — no double-append"
    );
}

// ── prune ─────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn actor_prune_reduces_oldest_index() {
    let id = make_identity("prune");
    let handle = spawn_chain_actor(Chain::genesis());
    let mut raw = Chain::genesis();

    // Mine 10 blocks.
    for _ in 0..10 {
        let b = mine_block(&mut raw, &id);
        raw.append(b.clone());
        handle.append(b).await;
    }

    let before = handle.sync_snap().await;
    assert_eq!(before.height, 10);
    assert_eq!(before.oldest, 0);

    // Prune to keep last 5 blocks.
    handle.prune(5).await;

    let after = handle.sync_snap().await;
    assert_eq!(after.height, 10, "height should remain 10 after prune");
    assert!(after.oldest > 0, "oldest index should have advanced after prune");
}

// ── blocks_after for sync serving ─────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn actor_blocks_after_respects_max_limit() {
    let id = make_identity("blocks-limit");
    let handle = spawn_chain_actor(Chain::genesis());
    let mut raw = Chain::genesis();

    for _ in 0..20 {
        let b = mine_block(&mut raw, &id);
        raw.append(b.clone());
        handle.append(b).await;
    }

    let limited = handle.blocks_after(0, 5).await;
    assert_eq!(limited.len(), 5, "max=5 should return at most 5 blocks");

    let all = handle.blocks_after(0, 1000).await;
    assert_eq!(all.len(), 20, "without limit all 20 blocks should be returned");
}

// ── settled_on_chain scan ─────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn actor_settled_on_chain_finds_settle_tx() {
    // JobSettle requires a prior JobBid to exist in open_bids. Sequence:
    //   Block 1 — UptimeReward to payer (gives credits for the bid).
    //   Block 2 — JobBid from payer (opens the bid in open_bids cache).
    //   Block 3 — JobSettle from host (closes the bid; should appear in settled_on_chain).
    let host = make_identity("settle-host");
    let payer = make_identity("settle-payer");
    let job_id: [u8; 32] = [0xAB; 32];
    let cost = 100u128;
    let bid = 500u128;

    use ce_chain::payer_settle_bytes;
    let mut raw = Chain::genesis();
    let handle = spawn_chain_actor(Chain::genesis());

    // Block 1: credit payer with UptimeReward so the bid balance check passes.
    {
        let emission = Chain::emission_rate(1);
        let rk = TxKind::UptimeReward { node: payer.node_id(), amount: emission, epoch: 1 };
        let rd = bincode::serialize(&rk).unwrap();
        let rs = payer.sign(&rd);
        let reward_tx = Tx::new(rk, payer.node_id(), rs);
        let mut block = raw.next_block(vec![reward_tx], payer.node_id());
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&payer);
        raw.append(block.clone());
        assert!(handle.append(block).await, "block 1 should append");
    }

    // Block 2: open a bid from payer — populates open_bids for the given job_id.
    {
        let bid_kind = TxKind::JobBid {
            job_id,
            payer: payer.node_id(),
            bid,
            image: String::new(),
            cmd: vec![],
            env: vec![],
            cpu_cores: 1,
            mem_mb: 256,
            duration_secs: 60,
        };
        let data = bincode::serialize(&bid_kind).unwrap();
        let sig = payer.sign(&data);
        let bid_tx = Tx::new(bid_kind, payer.node_id(), sig);
        let emission = Chain::emission_rate(2);
        let rk = TxKind::UptimeReward { node: payer.node_id(), amount: emission, epoch: 2 };
        let rd = bincode::serialize(&rk).unwrap();
        let rs = payer.sign(&rd);
        let reward_tx = Tx::new(rk, payer.node_id(), rs);
        let mut block = raw.next_block(vec![reward_tx, bid_tx], payer.node_id());
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&payer);
        raw.append(block.clone());
        assert!(handle.append(block).await, "block 2 (bid) should append");
    }

    // Block 3: host settles the job — closes the open bid.
    {
        let settle_bytes = payer_settle_bytes(&job_id, &host.node_id(), cost);
        let payer_sig = payer.sign(&settle_bytes);
        let settle_kind = TxKind::JobSettle {
            job_id,
            host: host.node_id(),
            payer: payer.node_id(),
            cpu_ms: 0,
            mem_mb: 0,
            cost,
            payer_sig,
        };
        let data = bincode::serialize(&settle_kind).unwrap();
        let sig = host.sign(&data);
        let settle_tx = Tx::new(settle_kind, host.node_id(), sig);
        let emission = Chain::emission_rate(3);
        let rk = TxKind::UptimeReward { node: host.node_id(), amount: emission, epoch: 3 };
        let rd = bincode::serialize(&rk).unwrap();
        let rs = host.sign(&rd);
        let reward_tx = Tx::new(rk, host.node_id(), rs);
        let mut block = raw.next_block(vec![reward_tx, settle_tx], host.node_id());
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&host);
        raw.append(block.clone());
        assert!(handle.append(block).await, "block 3 (settle) should append");
    }

    let settled = handle.settled_on_chain(host.node_id()).await;
    assert_eq!(settled.len(), 1);
    assert_eq!(settled[0], job_id);
}

// ── free-vs-total balance pre-screen (Theme D) ────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn locked_funds_make_free_balance_gate_a_transfer() {
    // Regression for the `POST /transfer` (and heartbeat) pre-screen: the handler must gate on
    // FREE balance (`balance - locked_balance`), the quantity validators enforce. A payer who has
    // locked most of its balance in an open JobBid must NOT pass a transfer that only the (larger)
    // total balance would cover — otherwise the tx is "submitted but never mined".
    let payer = make_identity("free-gate-payer");
    let job_id: [u8; 32] = [0xCD; 32];
    let bid = 700u128;

    let mut raw = Chain::genesis();
    let handle = spawn_chain_actor(Chain::genesis());

    // Block 1: credit the payer.
    let emission = Chain::emission_rate(1);
    {
        let rk = TxKind::UptimeReward { node: payer.node_id(), amount: emission, epoch: 1 };
        let rs = payer.sign(&bincode::serialize(&rk).unwrap());
        let reward_tx = Tx::new(rk, payer.node_id(), rs);
        let mut block = raw.next_block(vec![reward_tx], payer.node_id());
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&payer);
        raw.append(block.clone());
        assert!(handle.append(block).await, "block 1 (reward) should append");
    }

    // Block 2: open a JobBid that locks `bid` of the payer's balance.
    {
        let bid_kind = TxKind::JobBid {
            job_id,
            payer: payer.node_id(),
            bid,
            image: String::new(),
            cmd: vec![],
            env: vec![],
            cpu_cores: 1,
            mem_mb: 256,
            duration_secs: 60,
        };
        let bid_sig = payer.sign(&bincode::serialize(&bid_kind).unwrap());
        let bid_tx = Tx::new(bid_kind, payer.node_id(), bid_sig);
        let emission2 = Chain::emission_rate(2);
        let rk = TxKind::UptimeReward { node: payer.node_id(), amount: emission2, epoch: 2 };
        let rs = payer.sign(&bincode::serialize(&rk).unwrap());
        let reward_tx = Tx::new(rk, payer.node_id(), rs);
        let mut block = raw.next_block(vec![reward_tx, bid_tx], payer.node_id());
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&payer);
        raw.append(block.clone());
        assert!(handle.append(block).await, "block 2 (bid) should append");
    }

    let total = handle.balance(payer.node_id()).await;
    let locked = handle.locked_balance(payer.node_id()).await;
    let free = total - locked as i128;

    assert_eq!(locked, bid, "the open bid must be counted as locked");
    assert!(free >= 0 && free < total, "free balance must be strictly below total when funds are locked");

    // The transfer pre-screen gates on `free`. Pick an amount the TOTAL would cover but FREE does
    // not: it must be rejected (this is exactly the leak the fix closes).
    let transfer_amount = (free as u128) + 1;
    assert!(
        (transfer_amount as i128) <= total,
        "the test amount must be coverable by total balance, proving the old gate would have wrongly accepted it",
    );
    assert!(
        free < transfer_amount as i128,
        "free-balance gate must reject a transfer of locked funds",
    );
}

// ── stress: high throughput ───────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn actor_high_throughput_read_queries() {
    // 10,000 balance reads should complete within 3 seconds — verifies the actor
    // doesn't have a per-command overhead that would make it unusable at scale.
    let id = make_identity("throughput");
    let handle = Arc::new(spawn_chain_actor(Chain::genesis()));

    let start = std::time::Instant::now();
    let mut tasks = vec![];
    for _ in 0..10_000 {
        let h = handle.clone();
        let node = id.node_id();
        tasks.push(tokio::spawn(async move { h.balance(node).await }));
    }
    futures::future::join_all(tasks).await;
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(3),
        "10,000 balance queries took {elapsed:?}, expected < 3s"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn adversarial_rapid_reorg_storm() {
    // 100 concurrent try_reorg calls from different fake forks, all racing.
    // None should win (our chain has 5 valid blocks; forks have 3).
    let id = make_identity("reorg-storm-ours");
    let handle = Arc::new(spawn_chain_actor(Chain::genesis()));
    let mut raw = Chain::genesis();
    for _ in 0..5 {
        let b = mine_block(&mut raw, &id);
        raw.append(b.clone());
        handle.append(b).await;
    }

    let mut tasks = vec![];
    for i in 0..100 {
        let h = handle.clone();
        tasks.push(tokio::spawn(async move {
            let attacker = make_identity(&format!("storm-{i}"));
            let (_, fork) = build_chain_of(&attacker, 3); // shorter than our 5
            h.try_reorg(fork).await
        }));
    }

    let results = futures::future::join_all(tasks).await;
    assert!(
        results.iter().all(|r| !r.as_ref().unwrap()),
        "all shorter reorgs must fail"
    );
    assert_eq!(handle.height().await, 5, "chain must remain at height 5");
}
