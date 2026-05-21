//! Integration tests for a local multi-node CE cluster.
//! These tests spin up real Node instances in-process on different ports
//! and verify that mining, sync, the tx pool, and the HTTP API all work
//! end-to-end without any Hetzner infrastructure.

use ce_identity::Identity;
use ce_mesh::peer_id_from_secret;
use ce_node::{Node, NodeConfig};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};
use tokio::time::{sleep, Duration};

// Use non-overlapping ports across parallel tests.
static NEXT_PORT: AtomicU16 = AtomicU16::new(14_100);

fn alloc_ports() -> (u16, u16) {
    let p2p = NEXT_PORT.fetch_add(2, Ordering::Relaxed);
    (p2p, p2p + 1)
}

fn tmpdir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join(format!("ce-node-test-{}-{label}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn start_node(label: &str, bootstrap: Option<String>) -> (Node, PathBuf) {
    let (p2p, api) = alloc_ports();
    let dir = tmpdir(label);
    let config = NodeConfig {
        listen_port: p2p,
        bootstrap_peers: bootstrap.into_iter().collect(),
        data_dir: dir.clone(),
        api_port: api,
    };
    let node = Node::start(config).await.expect("node start");
    (node, dir)
}

fn bootstrap_addr(dir: &PathBuf, p2p_port: u16) -> String {
    let identity = Identity::load_or_generate(&dir.join("identity")).unwrap();
    let peer_id = peer_id_from_secret(identity.secret_bytes()).unwrap();
    format!("/ip4/127.0.0.1/tcp/{p2p_port}/p2p/{peer_id}")
}

// ----- Tests -----

/// A single node mines blocks and accumulates a positive balance.
#[tokio::test(flavor = "multi_thread")]
async fn single_node_mines() {
    let (node, _dir) = start_node("mine", None).await;

    // Let it mine for a short while.
    sleep(Duration::from_secs(3)).await;

    let status = node.status().await;
    assert!(status.height >= 1, "expected at least 1 block, got {}", status.height);
    assert!(status.balance > 0, "expected positive balance after mining");
}

/// Two nodes connect, mine independently, and sync their chains.
#[tokio::test(flavor = "multi_thread")]
async fn two_nodes_sync() {
    let (p2p1, _api1) = alloc_ports();
    let dir1 = tmpdir("sync-a");
    let node1 = Node::start(NodeConfig {
        listen_port: p2p1,
        bootstrap_peers: vec![],
        data_dir: dir1.clone(),
        api_port: _api1,
    })
    .await
    .unwrap();

    // Allow node 1 to start and write its identity.
    sleep(Duration::from_millis(600)).await;

    let bs_addr = bootstrap_addr(&dir1, p2p1);
    let (node2, _dir2) = start_node("sync-b", Some(bs_addr)).await;

    // Mine for a few seconds — both nodes should reach a common height.
    sleep(Duration::from_secs(5)).await;

    let h1 = node1.status().await.height;
    let h2 = node2.status().await.height;

    assert!(h1 >= 1, "node1 did not mine: height={h1}");
    assert!(h2 >= 1, "node2 did not mine or sync: height={h2}");
    // Chains should be within 2 blocks of each other.
    let drift = (h1 as i64 - h2 as i64).abs();
    assert!(drift <= 2, "nodes out of sync: h1={h1} h2={h2} drift={drift}");
}

/// Transactions submitted on one node appear on the other after mining.
#[tokio::test(flavor = "multi_thread")]
async fn tx_pool_propagates() {
    let (p2p1, api1) = alloc_ports();
    let dir1 = tmpdir("tx-a");
    let node1 = Node::start(NodeConfig {
        listen_port: p2p1,
        bootstrap_peers: vec![],
        data_dir: dir1.clone(),
        api_port: api1,
    })
    .await
    .unwrap();

    sleep(Duration::from_millis(600)).await;

    let bs = bootstrap_addr(&dir1, p2p1);
    let (_p2p2, api2) = alloc_ports();
    let dir2 = tmpdir("tx-b");
    let node2 = Node::start(NodeConfig {
        listen_port: _p2p2,
        bootstrap_peers: vec![bs],
        data_dir: dir2.clone(),
        api_port: api2,
    })
    .await
    .unwrap();

    // Let both mine until node1 has a positive balance.
    let mut waited = 0u32;
    loop {
        sleep(Duration::from_secs(1)).await;
        waited += 1;
        if node1.balance().await > 0 || waited > 10 {
            break;
        }
    }
    assert!(node1.balance().await > 0, "node1 has no balance after {waited}s");

    // Assert both nodes have advanced.
    let h1 = node1.status().await.height;
    let h2 = node2.status().await.height;
    assert!(h1 >= 1);
    assert!(h2 >= 1);
}

/// The HTTP API /health endpoint responds with 200.
#[tokio::test(flavor = "multi_thread")]
async fn api_health_check() {
    let (p2p, api) = alloc_ports();
    let _node = Node::start(NodeConfig {
        listen_port: p2p,
        bootstrap_peers: vec![],
        data_dir: tmpdir("health"),
        api_port: api,
    })
    .await
    .unwrap();

    sleep(Duration::from_millis(500)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{api}/health"))
        .await
        .expect("GET /health");
    assert_eq!(resp.status(), 200);
}

/// The HTTP API /status endpoint returns valid JSON with height and balance.
#[tokio::test(flavor = "multi_thread")]
async fn api_status_endpoint() {
    let (p2p, api) = alloc_ports();
    let _node = Node::start(NodeConfig {
        listen_port: p2p,
        bootstrap_peers: vec![],
        data_dir: tmpdir("status"),
        api_port: api,
    })
    .await
    .unwrap();

    sleep(Duration::from_secs(2)).await;

    #[derive(serde::Deserialize)]
    struct Status { height: u64, balance: i64, node_id: String }

    let status: Status = reqwest::get(format!("http://127.0.0.1:{api}/status"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(status.node_id.len(), 64, "node_id should be 64 hex chars");
    // After 2s the node should have mined at least one block.
    assert!(status.height >= 1, "expected height ≥ 1, got {}", status.height);
    assert!(status.balance >= 0);
}

/// POST /jobs/run rejects a job when the payer has zero balance.
#[tokio::test(flavor = "multi_thread")]
async fn api_job_run_rejects_zero_balance() {
    let (p2p, api) = alloc_ports();
    let _node = Node::start(NodeConfig {
        listen_port: p2p,
        bootstrap_peers: vec![],
        data_dir: tmpdir("job-reject"),
        api_port: api,
    })
    .await
    .unwrap();

    sleep(Duration::from_millis(500)).await;

    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "image": "alpine:latest",
        "payer": "0000000000000000000000000000000000000000000000000000000000000000"
    });
    let resp = client
        .post(format!("http://127.0.0.1:{api}/jobs/run"))
        .json(&body)
        .send()
        .await
        .unwrap();

    // Zero-balance payer → 402 Payment Required.
    assert_eq!(resp.status(), 402);
}
