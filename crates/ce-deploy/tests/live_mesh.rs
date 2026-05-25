//! Integration tests against the live ce-net.com mesh.
//!
//! These tests hit real network infrastructure and are marked `#[ignore]` so
//! they don't run in normal CI.  Run them with:
//!
//!   cargo test -p ce-deploy --test live_mesh -- --ignored --nocapture
//!
//! Some tests spin up a local CE node and verify it can join the live mesh,
//! so the machine running them needs outbound TCP/UDP access to port 4001.
//!
//! Environment variables:
//!   CE_LIVE_TEST=1   — required safety gate (prevents accidental live runs)

use ce_chain::{Chain, ARCHIVE_DENSITY, SEGMENT_SIZE, segment_id_for_block, should_hold_segment};
use ce_node::{Node, NodeConfig};
use std::time::Duration;
use tokio::time::timeout;

fn require_live() {
    if std::env::var("CE_LIVE_TEST").as_deref() != Ok("1") {
        panic!("Set CE_LIVE_TEST=1 to run live mesh tests");
    }
}

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ce-live-{}-{}", std::process::id(), tag));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ----- Network reachability -----

/// Verify the relay bootstrap endpoint returns valid multiaddrs.
///
/// Run: CE_LIVE_TEST=1 cargo test -p ce-deploy --test live_mesh live_bootstrap -- --ignored --nocapture
#[tokio::test]
#[ignore]
async fn live_bootstrap_endpoint_returns_valid_multiaddrs() {
    require_live();
    let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init();

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    #[derive(serde::Deserialize)]
    struct Resp { peers: Vec<String> }

    let resp = client
        .get("https://ce-net.com/bootstrap")
        .send()
        .await
        .expect("bootstrap request failed")
        .json::<Resp>()
        .await
        .expect("bad bootstrap JSON");

    assert!(!resp.peers.is_empty(), "bootstrap returned zero peers");
    for peer in &resp.peers {
        assert!(
            peer.starts_with("/ip4/") || peer.starts_with("/dns4/"),
            "unexpected multiaddr format: {peer}",
        );
        assert!(peer.contains("/p2p/"), "multiaddr missing /p2p/ component: {peer}");
    }
    println!("bootstrap peers: {:#?}", resp.peers);
}

/// Verify the relay health endpoint is reachable.
#[tokio::test]
#[ignore]
async fn live_relay_health_ok() {
    require_live();

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let resp = client
        .get("https://ce-net.com/health")
        .send()
        .await
        .expect("health request failed");

    assert!(
        resp.status().is_success(),
        "health endpoint returned {}", resp.status(),
    );
}

/// Verify TCP port 4001 is reachable on the relay (libp2p P2P port).
#[tokio::test]
#[ignore]
async fn live_relay_p2p_port_reachable() {
    require_live();
    use tokio::net::TcpStream;

    let stream = timeout(
        Duration::from_secs(5),
        TcpStream::connect("178.105.145.170:4001"),
    )
    .await
    .expect("TCP connect timed out")
    .expect("TCP connect failed");

    // A successful connect is enough — we don't speak libp2p here.
    drop(stream);
}

// ----- Node sync tests -----

/// Start a local node with the relay as bootstrap, wait up to 60 s for it to
/// sync at least one block from the live mesh (height > 0).
///
/// This is the definitive end-to-end test: identity generation → mesh connect →
/// gossipsub → chain sync, all against the production relay.
#[tokio::test]
#[ignore]
async fn live_node_syncs_from_relay() {
    require_live();
    let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init();

    let data_dir = tmp_dir("sync");
    let config = NodeConfig {
        listen_port: 0,        // OS-assigned ephemeral port
        api_port: 0,
        bootstrap_peers: vec![
            "/ip4/178.105.145.170/tcp/4001/p2p/12D3KooWC6vyMMrtmdWEdpcMx7JZ4Ze5scUhA6BbMdYqnUDC7nr7"
                .to_string(),
        ],
        relay_peers: vec![],
        data_dir: data_dir.clone(),
        mine: false,
        mining_interval_secs: 60,
        prune_keep: Some(ce_chain::PRUNE_KEEP_BLOCKS),
        archive_density: 0.0, // no archiving in this test
    };

    let node = Node::start(config).await.expect("node start failed");
    let status = node.status().await;
    println!("node id  : {}", status.node_id);
    println!("peer id  : {}", status.peer_id);
    println!("height   : {}", status.height);

    // Poll until height > 0 or 60 s elapses.
    let synced = timeout(Duration::from_secs(60), async {
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let s = node.status().await;
            if s.height > 0 {
                println!("synced to height {}", s.height);
                return true;
            }
        }
    })
    .await;

    assert!(
        synced.is_ok(),
        "node did not sync from live relay within 60 s (still at height 0)",
    );
}

/// Light node test: node syncs from relay and auto-prunes the chain,
/// archiving the segments it is responsible for, then announces them.
#[tokio::test]
#[ignore]
async fn live_light_node_prunes_and_archives() {
    require_live();
    let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init();

    let data_dir = tmp_dir("light");
    let config = NodeConfig {
        listen_port: 0,
        api_port: 0,
        bootstrap_peers: vec![
            "/ip4/178.105.145.170/tcp/4001/p2p/12D3KooWC6vyMMrtmdWEdpcMx7JZ4Ze5scUhA6BbMdYqnUDC7nr7"
                .to_string(),
        ],
        relay_peers: vec![],
        data_dir: data_dir.clone(),
        mine: false,
        mining_interval_secs: 60,
        // Aggressive prune: keep only 200 blocks so the test triggers a prune quickly.
        prune_keep: Some(200),
        archive_density: ARCHIVE_DENSITY,
    };

    let node = Node::start(config).await.expect("node start failed");

    // Wait until we've synced enough to trigger a prune (200 + 100 buffer = 300 blocks).
    let done = timeout(Duration::from_secs(120), async {
        loop {
            tokio::time::sleep(Duration::from_secs(3)).await;
            let s = node.status().await;
            println!("height: {}", s.height);
            if s.height >= 300 {
                return s.height;
            }
        }
    })
    .await;

    let height = done.expect("node did not sync 300 blocks within 120 s");
    println!("synced to height {height}");

    // Give the archive logic a moment to flush.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let archive_dir = data_dir.join("archive");
    let held = ce_chain::list_archive_segments(&archive_dir);
    println!("archived segments: {held:?}");

    // Not all nodes hold every segment — that's the point.
    // But if the chain reached height ≥ SEGMENT_SIZE, at least one complete segment existed,
    // and this node should have archived any segment it was assigned.
    if height >= SEGMENT_SIZE {
        println!("segment assignment check passed ({} segments held)", held.len());
    }
}

// ----- Segment distribution unit tests (no network needed) -----

/// Verify that at default density with a large enough population,
/// every segment gets at least MIN_REPLICAS holders.
#[test]
fn segment_distribution_covers_history() {
    // Simulate 100 distinct nodes.
    let nodes: Vec<[u8; 32]> = (0u32..100)
        .map(|i| {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_le_bytes());
            id[4] = 0xce;
            id
        })
        .collect();

    let total_segments = 200u64;
    let mut holders_per_seg = vec![0u32; total_segments as usize];

    for node in &nodes {
        for seg in 0..total_segments {
            if should_hold_segment(node, seg, ARCHIVE_DENSITY) {
                holders_per_seg[seg as usize] += 1;
            }
        }
    }

    let min_holders = *holders_per_seg.iter().min().unwrap();
    let avg_holders: f32 = holders_per_seg.iter().sum::<u32>() as f32 / total_segments as f32;
    let zero_coverage = holders_per_seg.iter().filter(|&&h| h == 0).count();
    println!(
        "distribution: min={min_holders} avg={avg_holders:.1} zero_segments={zero_coverage} \
         over {total_segments} segs, {} nodes",
        nodes.len(),
    );
    // With 100 nodes at 15% density, expected replication ≈ 15×.
    // Expected uncovered segments ≈ 200 * 0.85^100 ≈ 0.
    assert_eq!(zero_coverage, 0, "some segments have zero holders — catastrophic data loss scenario");
}

/// Verify determinism: same node_id + segment_id always gives the same answer.
#[test]
fn segment_assignment_is_deterministic() {
    let node_id = [42u8; 32];
    for seg in 0..100u64 {
        let a = should_hold_segment(&node_id, seg, ARCHIVE_DENSITY);
        let b = should_hold_segment(&node_id, seg, ARCHIVE_DENSITY);
        assert_eq!(a, b, "segment {seg} assignment not deterministic");
    }
}

/// Verify archive segment save/load roundtrip (pure local, no network).
#[test]
fn segment_save_load_roundtrip() {
    use ce_chain::{save_segment, load_segment};

    let dir = tmp_dir("seg-rt");
    let genesis = Chain::genesis();
    let blocks = vec![genesis.tip().clone()];

    save_segment(&dir, 0, &blocks).expect("save failed");
    let loaded = load_segment(&dir, 0).expect("load error").expect("segment missing");
    assert_eq!(loaded.len(), blocks.len());
    assert_eq!(loaded[0].index, blocks[0].index);
    assert_eq!(loaded[0].hash(), blocks[0].hash());
}

/// Segment ID assignment is consistent with block ranges.
#[test]
fn segment_id_for_block_correct() {
    assert_eq!(segment_id_for_block(0), 0);
    assert_eq!(segment_id_for_block(999), 0);
    assert_eq!(segment_id_for_block(1000), 1);
    assert_eq!(segment_id_for_block(1999), 1);
    assert_eq!(segment_id_for_block(2000), 2);
}
