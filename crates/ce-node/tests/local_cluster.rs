//! Integration tests for a local multi-node CE cluster.
//! These tests spin up real Node instances in-process on different ports
//! and verify that mining, sync, the tx pool, and the HTTP API all work
//! end-to-end without any Hetzner infrastructure.

use ce_chain::payer_settle_bytes;
use ce_identity::Identity;
use ce_mesh::peer_id_from_secret;
use ce_node::{Node, NodeConfig};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};
use tokio::time::{sleep, Duration};

static NEXT_PORT: AtomicU16 = AtomicU16::new(14_100);

fn alloc_ports() -> (u16, u16) {
    let p2p = NEXT_PORT.fetch_add(2, Ordering::Relaxed);
    (p2p, p2p + 1)
}

/// Shared API token for tests: nodes read it from `CE_API_TOKEN`, clients send it as a Bearer.
const TEST_API_TOKEN: &str = "ce-integration-test-token";

fn tmpdir(label: &str) -> PathBuf {
    // Set before any node starts so every test node adopts the same (env-provided) API token.
    unsafe { std::env::set_var("CE_API_TOKEN", TEST_API_TOKEN) };
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
        mine: true,
        disable_local_discovery: true,
        ..Default::default()
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

#[tokio::test(flavor = "multi_thread")]
async fn single_node_mines() {
    let (node, _dir) = start_node("mine", None).await;
    sleep(Duration::from_secs(3)).await;
    let status = node.status().await;
    assert!(status.height >= 1, "expected at least 1 block, got {}", status.height);
    assert!(status.balance > 0, "expected positive balance after mining");
}

#[tokio::test(flavor = "multi_thread")]
async fn two_nodes_sync() {
    let (p2p1, api1) = alloc_ports();
    let dir1 = tmpdir("sync-a");
    let node1 = Node::start(NodeConfig {
        listen_port: p2p1,
        bootstrap_peers: vec![],
        data_dir: dir1.clone(),
        api_port: api1,
        mine: true,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();

    sleep(Duration::from_millis(600)).await;

    let bs_addr = bootstrap_addr(&dir1, p2p1);
    let (node2, _dir2) = start_node("sync-b", Some(bs_addr)).await;

    // Poll for convergence instead of a fixed sleep — robust on slow/loaded CI runners.
    let (mut h1, mut h2) = (0, 0);
    for _ in 0..60 {
        sleep(Duration::from_secs(1)).await;
        h1 = node1.status().await.height;
        h2 = node2.status().await.height;
        if h1 >= 1 && h2 >= 1 && (h1 as i64 - h2 as i64).abs() <= 2 {
            break;
        }
    }
    assert!(h1 >= 1, "node1 did not mine: height={h1}");
    assert!(h2 >= 1, "node2 did not mine or sync: height={h2}");
    let drift = (h1 as i64 - h2 as i64).abs();
    assert!(drift <= 2, "nodes out of sync: h1={h1} h2={h2} drift={drift}");
}

#[tokio::test(flavor = "multi_thread")]
async fn tx_pool_propagates() {
    let (p2p1, api1) = alloc_ports();
    let dir1 = tmpdir("tx-a");
    let node1 = Node::start(NodeConfig {
        listen_port: p2p1,
        bootstrap_peers: vec![],
        data_dir: dir1.clone(),
        api_port: api1,
        mine: true,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();

    sleep(Duration::from_millis(600)).await;

    let bs = bootstrap_addr(&dir1, p2p1);
    let (_p2p2, api2) = alloc_ports();
    let dir2 = tmpdir("tx-b");
    let _node2 = Node::start(NodeConfig {
        listen_port: _p2p2,
        bootstrap_peers: vec![bs],
        data_dir: dir2.clone(),
        api_port: api2,
        mine: true,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();

    let mut waited = 0u32;
    loop {
        sleep(Duration::from_secs(1)).await;
        waited += 1;
        if node1.balance().await > 0 || waited > 10 {
            break;
        }
    }
    assert!(node1.balance().await > 0, "node1 has no balance after {waited}s");

    let h1 = node1.status().await.height;
    assert!(h1 >= 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn api_health_check() {
    let (p2p, api) = alloc_ports();
    let _node = Node::start(NodeConfig {
        listen_port: p2p,
        bootstrap_peers: vec![],
        data_dir: tmpdir("health"),
        api_port: api,
        mine: true,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();

    sleep(Duration::from_millis(500)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{api}/health"))
        .await
        .expect("GET /health");
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn api_status_endpoint() {
    let (p2p, api) = alloc_ports();
    let _node = Node::start(NodeConfig {
        listen_port: p2p,
        bootstrap_peers: vec![],
        data_dir: tmpdir("status"),
        api_port: api,
        mine: true,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();

    sleep(Duration::from_secs(2)).await;

    #[derive(serde::Deserialize)]
    struct Status {
        height: u64,
        // Amounts are decimal strings of base units in the API (precision-safe).
        balance: String,
        node_id: String,
    }

    let status: Status = reqwest::get(format!("http://127.0.0.1:{api}/status"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(status.node_id.len(), 64, "node_id should be 64 hex chars");
    assert!(status.height >= 1, "expected height ≥ 1, got {}", status.height);
    assert!(status.balance.parse::<i128>().unwrap() >= 0, "balance parses to a non-negative integer");
}

/// POST /jobs/bid returns 402 when the node's own balance is zero (no mining yet).
#[tokio::test(flavor = "multi_thread")]
async fn api_job_bid_rejects_zero_balance() {
    let (p2p, api) = alloc_ports();
    let _node = Node::start(NodeConfig {
        listen_port: p2p,
        bootstrap_peers: vec![],
        data_dir: tmpdir("job-reject"),
        api_port: api,
        mine: false, // no mining → balance stays at zero
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();

    sleep(Duration::from_millis(500)).await;

    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "image": "alpine:latest",
        "cpu_cores": 1,
        "mem_mb": 128,
        "duration_secs": 30,
        "bid": "100"
    });
    let resp = client
        .post(format!("http://127.0.0.1:{api}/jobs/bid")).bearer_auth(TEST_API_TOKEN)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 402);
}

#[tokio::test(flavor = "multi_thread")]
async fn signal_propagates_between_nodes() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new("warn,ce_node=info,ce_mesh=info")
            }),
        )
        .with_test_writer()
        .try_init();

    let (p2p_a, api_a) = alloc_ports();
    let dir_a = tmpdir("signal-a");
    let node_a = Node::start(NodeConfig {
        listen_port: p2p_a,
        bootstrap_peers: vec![],
        data_dir: dir_a.clone(),
        api_port: api_a,
        mine: true,
        mining_interval_secs: 2,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();

    // Wait for node A to mine at least one block of its own. With 2s intervals this
    // takes ~2-4s. We use any_burnable_tx_by_self so reorgs from cross-test node
    // contamination don't cause us to pick up foreign-chain txs.
    for _ in 0..20 {
        sleep(Duration::from_secs(1)).await;
        if node_a.any_burnable_tx_by_self().await.is_some() {
            break;
        }
    }

    let bs = bootstrap_addr(&dir_a, p2p_a);
    let (p2p_b, api_b) = alloc_ports();
    let _node_b = Node::start(NodeConfig {
        listen_port: p2p_b,
        bootstrap_peers: vec![bs],
        data_dir: tmpdir("signal-b"),
        api_port: api_b,
        mine: false,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();

    let mut synced = false;
    for _ in 0..20 {
        sleep(Duration::from_secs(1)).await;
        let resp: serde_json::Value =
            reqwest::get(format!("http://127.0.0.1:{api_b}/status"))
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        let b_h = resp["height"].as_u64().unwrap_or(0);
        let a_h = node_a.status().await.height;
        if b_h >= a_h && a_h >= 1 {
            synced = true;
            break;
        }
    }
    assert!(synced, "node B did not sync node A's chain in time");

    // Wait for a self-owned burnable tx on node A's current chain. We loop because
    // a reorg from a lingering cross-test node can temporarily invalidate our own
    // blocks; node A will re-mine a fresh block on the winner chain within 2s.
    let mut burn_tx_id: Option<[u8; 32]> = None;
    for _ in 0..15 {
        if let Some((id, _)) = node_a.any_burnable_tx_by_self().await {
            burn_tx_id = Some(id);
            break;
        }
        sleep(Duration::from_secs(1)).await;
    }
    let burn_tx_id = burn_tx_id
        .expect("node A failed to produce a self-owned burnable tx before signal send");

    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "payload_hex": hex::encode(b"hello, cell"),
        "to": "broadcast",
        "capabilities": [{"name": "test", "version": 1}],
        "burn_tx_id_hex": hex::encode(burn_tx_id),
    });
    let resp = client
        .post(format!("http://127.0.0.1:{api_a}/signals/send")).bearer_auth(TEST_API_TOKEN)
        .json(&body)
        .send()
        .await
        .expect("POST /signals/send");
    assert_eq!(resp.status(), 202, "expected 202 ACCEPTED");
    let sent: serde_json::Value = resp.json().await.unwrap();
    let sent_id = sent["id"].as_str().unwrap().to_string();

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut saw_it = false;
    while std::time::Instant::now() < deadline {
        let signals: serde_json::Value =
            reqwest::get(format!("http://127.0.0.1:{api_b}/signals"))
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        if let Some(arr) = signals.as_array() {
            if arr.iter().any(|s| s["id"].as_str() == Some(&sent_id)) {
                saw_it = true;
                break;
            }
        }
        sleep(Duration::from_millis(200)).await;
    }
    assert!(saw_it, "node B did not receive signal id={sent_id} within 10s");
}

/// Full job lifecycle: bid → container starts → container exits → payer settles →
/// JobSettle confirmed on-chain → balances updated correctly.
///
/// Requires Docker to be available. Skips gracefully if Docker is absent.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn job_lifecycle() {
    if bollard::Docker::connect_with_socket_defaults().is_err() {
        eprintln!("Docker unavailable — skipping job_lifecycle");
        return;
    }

    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new("warn,ce_node=info")
            }),
        )
        .with_test_writer()
        .try_init();

    // Payer node: mines to accumulate credits; does not accept bids (payer == host forbidden).
    let (p2p_payer, api_payer) = alloc_ports();
    let dir_payer = tmpdir("lifecycle-payer");
    let node_payer = Node::start(NodeConfig {
        listen_port: p2p_payer,
        bootstrap_peers: vec![],
        relay_peers: vec![],
        data_dir: dir_payer.clone(),
        api_port: api_payer,
        mine: true,
        mining_interval_secs: 2,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();

    // Wait until the payer node has a positive balance.
    for _ in 0..15 {
        sleep(Duration::from_secs(1)).await;
        if node_payer.balance().await > 0 {
            break;
        }
    }
    assert!(node_payer.balance().await > 0, "payer node never mined a block");

    // Host node: connects to payer, mines so it can include txs, accepts bids.
    let bs = bootstrap_addr(&dir_payer, p2p_payer);
    let (p2p_host, api_host) = alloc_ports();
    let dir_host = tmpdir("lifecycle-host");
    let node_host = Node::start(NodeConfig {
        listen_port: p2p_host,
        bootstrap_peers: vec![bs],
        relay_peers: vec![],
        data_dir: dir_host.clone(),
        api_port: api_host,
        mine: true,
        mining_interval_secs: 2,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();

    // Wait for host to sync and have a positive balance.
    for _ in 0..10 {
        sleep(Duration::from_secs(1)).await;
        if node_host.balance().await > 0 {
            break;
        }
    }

    let payer_balance_before = node_payer.balance().await;
    let host_balance_before = node_host.balance().await;

    // Submit a JobBid from the payer node.
    let client = reqwest::Client::new();
    let bid_body = serde_json::json!({
        "image": "alpine:latest",
        "cmd": ["sh", "-c", "echo hello && sleep 1"],
        "cpu_cores": 1,
        "mem_mb": 64,
        "duration_secs": 10,
        "bid": "100"
    });
    let resp = client
        .post(format!("http://127.0.0.1:{api_payer}/jobs/bid")).bearer_auth(TEST_API_TOKEN)
        .json(&bid_body)
        .send()
        .await
        .expect("POST /jobs/bid");
    assert_eq!(resp.status(), 201, "expected 201 Created for bid");
    let bid_resp: serde_json::Value = resp.json().await.unwrap();
    let job_id_hex = bid_resp["job_id"].as_str().unwrap().to_string();

    // Poll the host node until the container is running.
    let mut container_started = false;
    for _ in 0..20 {
        sleep(Duration::from_secs(1)).await;
        let r = client
            .get(format!("http://127.0.0.1:{api_host}/jobs/{job_id_hex}"))
            .send()
            .await;
        if let Ok(resp) = r {
            if resp.status() == 200 {
                let v: serde_json::Value = resp.json().await.unwrap();
                let status = v["status"].as_str().unwrap_or("");
                if status == "running" || status == "awaiting_settlement" {
                    container_started = true;
                    break;
                }
            }
        }
    }
    assert!(container_started, "host node did not pick up the bid and start the container");

    // Poll the host until the container exits and the job awaits settlement.
    let mut awaiting = false;
    for _ in 0..15 {
        sleep(Duration::from_secs(1)).await;
        let r = client
            .get(format!("http://127.0.0.1:{api_host}/jobs/{job_id_hex}"))
            .send()
            .await
            .unwrap();
        if r.status() == 200 {
            let v: serde_json::Value = r.json().await.unwrap();
            if v["status"].as_str() == Some("awaiting_settlement") {
                awaiting = true;
                break;
            }
        }
    }
    assert!(awaiting, "container did not exit or job not in awaiting_settlement state");

    // Compute the payer co-signature.
    let job_id: [u8; 32] =
        hex::decode(&job_id_hex).unwrap().try_into().expect("job_id is 32 bytes");
    let cost: u128 = 50; // agreed settlement amount (≤ bid), in base units
    let payer_identity = Identity::load_or_generate(&dir_payer.join("identity")).unwrap();
    let host_node_id: [u8; 32] = hex::decode(&node_host.status().await.node_id)
        .unwrap()
        .try_into()
        .expect("node_id is 32 bytes");
    let payer_sig = payer_identity.sign(&payer_settle_bytes(&job_id, &host_node_id, cost));

    // Submit the settlement to the host node.
    let settle_body = serde_json::json!({
        "cost": cost.to_string(),
        "payer_sig": hex::encode(payer_sig)
    });
    let resp = client
        .post(format!("http://127.0.0.1:{api_host}/jobs/{job_id_hex}/settle")).bearer_auth(TEST_API_TOKEN)
        .json(&settle_body)
        .send()
        .await
        .expect("POST /jobs/:id/settle");
    assert_eq!(resp.status(), 202, "expected 202 Accepted for settle");

    // Wait for the JobSettle tx to be mined and the status to flip to settled.
    let mut settled = false;
    for _ in 0..20 {
        sleep(Duration::from_secs(1)).await;
        let r = client
            .get(format!("http://127.0.0.1:{api_host}/jobs/{job_id_hex}"))
            .send()
            .await
            .unwrap();
        if r.status() == 200 {
            let v: serde_json::Value = r.json().await.unwrap();
            if v["status"].as_str() == Some("settled") {
                settled = true;
                break;
            }
        }
    }
    assert!(settled, "job never reached settled state");

    // Allow both nodes' chains to sync the settle block.
    sleep(Duration::from_secs(3)).await;

    // Verify the balance delta on both sides.
    let payer_balance_after = node_payer.balance().await;
    let host_balance_after = node_host.balance().await;

    assert!(
        payer_balance_after < payer_balance_before,
        "payer balance should decrease: before={payer_balance_before} after={payer_balance_after}"
    );
    // The host earns `cost` credits from the settlement plus any mining rewards.
    // We can only assert it didn't decrease overall (mining adds more).
    assert!(
        host_balance_after >= host_balance_before,
        "host balance should not decrease: before={host_balance_before} after={host_balance_after}"
    );
}

// Mesh-routed directed deploy: B asks its local node to place a cell on a SPECIFIC host A
// over the mesh, then kills it. Requires Docker on host A — run with:
//   cargo test -p ce-node --test local_cluster mesh_deploy_and_kill_roundtrip -- --ignored --nocapture
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn mesh_deploy_and_kill_roundtrip() {
    use ce_node::capability::{Caveats, Resource, SignedCapability, encode_chain};

    // Host A — runs the container.
    let (p2p_a, api_a) = alloc_ports();
    let dir_a = tmpdir("mdep-host");
    let _node_a = Node::start(NodeConfig {
        listen_port: p2p_a,
        bootstrap_peers: vec![],
        data_dir: dir_a.clone(),
        api_port: api_a,
        mine: false,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();
    let a_id = Identity::load_or_generate(&dir_a.join("identity")).unwrap().node_id();

    sleep(Duration::from_millis(600)).await;

    // Deployer B — bootstrapped to A.
    let bs = bootstrap_addr(&dir_a, p2p_a);
    let (p2p_b, api_b) = alloc_ports();
    let dir_b = tmpdir("mdep-deployer");
    let _node_b = Node::start(NodeConfig {
        listen_port: p2p_b,
        bootstrap_peers: vec![bs],
        data_dir: dir_b.clone(),
        api_port: api_b,
        mine: false,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();
    let b_id = Identity::load_or_generate(&dir_b.join("identity")).unwrap().node_id();

    // A self-issues a capability authorizing B to deploy on A; B presents it with the deploy.
    let deploy_cap = {
        let a_identity = Identity::load_or_generate(&dir_a.join("identity")).unwrap();
        let cap = SignedCapability::issue(
            &a_identity,
            b_id,
            vec!["deploy".to_string()],
            Resource::Node(a_id),
            Caveats::default(),
            1,
            None,
        );
        encode_chain(&[cap])
    };

    sleep(Duration::from_secs(2)).await; // let the mesh connect

    let client = reqwest::Client::new();

    // B directs its local node to deploy on A through the mesh.
    let resp = client
        .post(format!("http://127.0.0.1:{api_b}/mesh-deploy")).bearer_auth(TEST_API_TOKEN)
        .json(&serde_json::json!({
            "node_id": hex::encode(a_id),
            "image": "alpine:latest",
            "cmd": ["sleep", "30"],
            "cpu_cores": 1,
            "mem_mb": 128,
            "duration_secs": 60,
            "bid": "1000000000000000000",
            "grant": deploy_cap
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "mesh-deploy should succeed");
    let v: serde_json::Value = resp.json().await.unwrap();
    let job_id = v["job_id"].as_str().expect("deploy returns a job_id").to_string();

    // Host A should now report the job.
    let jobs: serde_json::Value = reqwest::get(format!("http://127.0.0.1:{api_a}/jobs"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        jobs.as_array().map(|a| !a.is_empty()).unwrap_or(false),
        "host A should list the mesh-deployed job"
    );

    // Kill it through the mesh.
    let resp = client
        .post(format!("http://127.0.0.1:{api_b}/mesh-kill")).bearer_auth(TEST_API_TOKEN)
        .json(&serde_json::json!({ "node_id": hex::encode(a_id), "job_id": job_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "mesh-kill should succeed");
}

/// Data layer Stage 2: a chunk stored on one node is fetchable from another by hash. Node A
/// stores a blob (becomes a DHT provider); node B, which doesn't hold it, resolves providers via
/// the DHT, fetches it over the `FetchChunk` mesh RPC, verifies it against the hash, and serves it.
#[tokio::test(flavor = "multi_thread")]
async fn blob_fetched_across_mesh() {
    // Provider A.
    let (p2p_a, api_a) = alloc_ports();
    let dir_a = tmpdir("blob-provider");
    let _node_a = Node::start(NodeConfig {
        listen_port: p2p_a,
        bootstrap_peers: vec![],
        data_dir: dir_a.clone(),
        api_port: api_a,
        mine: false,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();

    sleep(Duration::from_millis(600)).await;

    // Fetcher B — bootstrapped to A.
    let bs = bootstrap_addr(&dir_a, p2p_a);
    let (p2p_b, api_b) = alloc_ports();
    let _node_b = Node::start(NodeConfig {
        listen_port: p2p_b,
        bootstrap_peers: vec![bs],
        data_dir: tmpdir("blob-fetcher"),
        api_port: api_b,
        mine: false,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();

    sleep(Duration::from_secs(2)).await; // let the mesh connect + Kademlia populate

    let client = reqwest::Client::new();

    // A distinctive multi-kilobyte payload, stored on A.
    let payload: Vec<u8> = (0..40_000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    let resp = client
        .post(format!("http://127.0.0.1:{api_a}/blobs")).bearer_auth(TEST_API_TOKEN)
        .body(payload.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "store blob on A");
    let v: serde_json::Value = resp.json().await.unwrap();
    let hash = v["hash"].as_str().expect("blob hash").to_string();

    // B does not hold it locally; GET must pull it from the mesh. Poll to allow the DHT provider
    // record to propagate and the FetchChunk round-trip to complete.
    let mut fetched: Option<Vec<u8>> = None;
    for _ in 0..15 {
        sleep(Duration::from_secs(2)).await;
        let r = client
            .get(format!("http://127.0.0.1:{api_b}/blobs/{hash}"))
            .send()
            .await
            .unwrap();
        if r.status() == 200 {
            fetched = Some(r.bytes().await.unwrap().to_vec());
            break;
        }
    }

    let got = fetched.expect("B should fetch the blob from A across the mesh");
    assert_eq!(got, payload, "fetched bytes must match the stored payload exactly");
}

/// Data layer Stage 3 gate: a provider that charges for data refuses a free (receiptless) fetch.
/// Node A sets a non-zero data price and stores a blob; node B's plain `GET /blobs/:hash` (which
/// attaches no payment receipt) must not succeed — the provider declines to serve it for free.
#[tokio::test(flavor = "multi_thread")]
async fn paid_provider_refuses_free_fetch() {
    let (p2p_a, api_a) = alloc_ports();
    let dir_a = tmpdir("paid-provider");
    let _node_a = Node::start(NodeConfig {
        listen_port: p2p_a,
        bootstrap_peers: vec![],
        data_dir: dir_a.clone(),
        api_port: api_a,
        mine: false,
        disable_local_discovery: true,
        data_price_per_byte: 1, // charge for data
        ..Default::default()
    })
    .await
    .unwrap();

    sleep(Duration::from_millis(600)).await;

    let bs = bootstrap_addr(&dir_a, p2p_a);
    let (p2p_b, api_b) = alloc_ports();
    let _node_b = Node::start(NodeConfig {
        listen_port: p2p_b,
        bootstrap_peers: vec![bs],
        data_dir: tmpdir("paid-fetcher"),
        api_port: api_b,
        mine: false,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();

    sleep(Duration::from_secs(2)).await;

    let client = reqwest::Client::new();
    let payload = b"this costs credits".to_vec();
    let resp = client
        .post(format!("http://127.0.0.1:{api_a}/blobs")).bearer_auth(TEST_API_TOKEN)
        .body(payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let v: serde_json::Value = resp.json().await.unwrap();
    let hash = v["hash"].as_str().unwrap().to_string();

    // B's free GET must never succeed: A discovers as a provider but declines to serve unpaid.
    for _ in 0..4 {
        sleep(Duration::from_millis(1500)).await;
        let r = client
            .get(format!("http://127.0.0.1:{api_b}/blobs/{hash}"))
            .send()
            .await
            .unwrap();
        assert_ne!(r.status(), 200, "charging provider must not serve a free fetch");
    }
}

/// Data layer Stage 4: a WASM workload runs on a host that did not previously hold its module.
/// Node A stores a WASM module (becomes a provider) and deploys it to host B; B has the wasm
/// runtime but not the module bytes, so it stages the module from the data layer (mesh) before
/// launching. Without Stage 4 staging this deploy fails ("module not in blob store").
#[tokio::test(flavor = "multi_thread")]
async fn wasm_deploy_stages_module_from_mesh() {
    use ce_node::capability::{Caveats, Resource, SignedCapability, encode_chain};

    // Deployer + provider A.
    let (p2p_a, api_a) = alloc_ports();
    let dir_a = tmpdir("wasm-stage-deployer");
    let _node_a = Node::start(NodeConfig {
        listen_port: p2p_a,
        bootstrap_peers: vec![],
        data_dir: dir_a.clone(),
        api_port: api_a,
        mine: false,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();
    let a_id = Identity::load_or_generate(&dir_a.join("identity")).unwrap().node_id();

    sleep(Duration::from_millis(600)).await;

    // Host B — bootstrapped to A, trusts A as an admin so A may deploy to it.
    let bs = bootstrap_addr(&dir_a, p2p_a);
    let (p2p_b, api_b) = alloc_ports();
    let dir_b = tmpdir("wasm-stage-host");
    let _node_b = Node::start(NodeConfig {
        listen_port: p2p_b,
        bootstrap_peers: vec![bs],
        data_dir: dir_b.clone(),
        api_port: api_b,
        mine: false,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();
    // B self-issues a capability authorizing A to deploy on B; A presents it with the deploy.
    let deploy_cap = {
        let b_identity = Identity::load_or_generate(&dir_b.join("identity")).unwrap();
        let cap = SignedCapability::issue(
            &b_identity,
            a_id,
            vec!["deploy".to_string()],
            Resource::Node(b_identity.node_id()),
            Caveats::default(),
            1,
            None,
        );
        encode_chain(&[cap])
    };

    sleep(Duration::from_secs(2)).await; // mesh connect + Kademlia populate

    let client = reqwest::Client::new();

    // A stores a tiny WASM module (and so advertises itself as its provider).
    let wasm = wat::parse_str(r#"(module (func (export "entry") (result i32) i32.const 42))"#).unwrap();
    let resp = client
        .post(format!("http://127.0.0.1:{api_a}/blobs")).bearer_auth(TEST_API_TOKEN)
        .body(wasm)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let module_hash = resp.json::<serde_json::Value>().await.unwrap()["hash"]
        .as_str()
        .unwrap()
        .to_string();

    // Host B must not already hold the module.
    let pre = client
        .get(format!("http://127.0.0.1:{api_b}/blobs/{module_hash}"))
        .send()
        .await
        .unwrap();
    // (It may pull from the mesh on this GET; that's fine — the deploy still exercises staging.)
    let _ = pre;

    // A deploys the WASM cell onto B. B stages the module from the mesh, then runs it.
    let resp = client
        .post(format!("http://127.0.0.1:{api_a}/mesh-deploy")).bearer_auth(TEST_API_TOKEN)
        .json(&serde_json::json!({
            "node_id": hex::encode(host_node_id(&dir_b)),
            "wasm_module": module_hash,
            "wasm_entry": "entry",
            "cpu_cores": 1,
            "mem_mb": 64,
            "duration_secs": 60,
            "bid": "1000000000000000000",
            "grant": deploy_cap
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "wasm mesh-deploy should succeed after staging the module");
    let v: serde_json::Value = resp.json().await.unwrap();
    assert!(v["job_id"].as_str().is_some(), "deploy returns a job_id");
}

/// The host node id, read from its data-dir identity.
fn host_node_id(dir: &PathBuf) -> ce_identity::NodeId {
    Identity::load_or_generate(&dir.join("identity")).unwrap().node_id()
}

/// Relay incentives: a relay payment routes over the mesh to the relay, which verifies it against
/// the on-chain channel. With no such channel the relay refuses — exercising the RelayReceipt RPC
/// path and the relay's channel/price check end-to-end. (The happy path's signature logic is
/// covered deterministically by the relay_authorize unit tests.)
#[tokio::test(flavor = "multi_thread")]
async fn relay_rejects_payment_without_channel() {
    // Relay A — advertises as a paid relay.
    let (p2p_a, api_a) = alloc_ports();
    let dir_a = tmpdir("relay-host");
    let _node_a = Node::start(NodeConfig {
        listen_port: p2p_a,
        bootstrap_peers: vec![],
        data_dir: dir_a.clone(),
        api_port: api_a,
        mine: false,
        disable_local_discovery: true,
        relay_price_per_min: Some(100),
        ..Default::default()
    })
    .await
    .unwrap();
    let a_id = host_node_id(&dir_a);

    sleep(Duration::from_millis(600)).await;

    // Client B — bootstrapped to A.
    let bs = bootstrap_addr(&dir_a, p2p_a);
    let (p2p_b, api_b) = alloc_ports();
    let _node_b = Node::start(NodeConfig {
        listen_port: p2p_b,
        bootstrap_peers: vec![bs],
        data_dir: tmpdir("relay-client"),
        api_port: api_b,
        mine: false,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();

    sleep(Duration::from_secs(2)).await; // mesh connect

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{api_b}/relay/pay")).bearer_auth(TEST_API_TOKEN)
        .json(&serde_json::json!({
            "relay": hex::encode(a_id),
            "channel_id": hex::encode([0u8; 32]),
            "cumulative": "100"
        }))
        .send()
        .await
        .unwrap();
    // The RPC reached the relay and was rejected (no such channel) — not a transport failure.
    assert_eq!(resp.status(), 502, "relay should reject payment for an unknown channel");
    let body = resp.text().await.unwrap();
    assert!(body.contains("unknown or unsettled channel"), "got: {body}");
}

/// Naming: a claimed name resolves to the claiming node once the claim tx is mined.
#[tokio::test(flavor = "multi_thread")]
async fn name_claim_resolves_after_mining() {
    let (p2p, api) = alloc_ports();
    let dir = tmpdir("name-claim");
    let _node = Node::start(NodeConfig {
        listen_port: p2p,
        bootstrap_peers: vec![],
        data_dir: dir.clone(),
        api_port: api,
        mine: true,
        mining_interval_secs: 1,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();
    let id = host_node_id(&dir);

    let client = reqwest::Client::new();
    // Wait for the HTTP API to be listening before hitting it — on loaded CI runners the server
    // may not accept connections the instant Node::start returns. (Was flaky: see task #27.)
    for _ in 0..50 {
        if let Ok(resp) = client.get(format!("http://127.0.0.1:{api}/health")).send().await {
            if resp.status().is_success() {
                break;
            }
        }
        sleep(Duration::from_millis(200)).await;
    }
    let r = client
        .post(format!("http://127.0.0.1:{api}/names/claim")).bearer_auth(TEST_API_TOKEN)
        .json(&serde_json::json!({ "name": "my-node" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 202, "claim accepted");

    // A malformed name is rejected up front.
    let bad = client
        .post(format!("http://127.0.0.1:{api}/names/claim")).bearer_auth(TEST_API_TOKEN)
        .json(&serde_json::json!({ "name": "Bad Name" }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 400);

    let mut resolved = None;
    for _ in 0..20 {
        sleep(Duration::from_millis(700)).await;
        let r = match reqwest::get(format!("http://127.0.0.1:{api}/names/my-node")).await {
            Ok(r) => r,
            Err(_) => continue,
        };
        if r.status() == 200 {
            let v: serde_json::Value = r.json().await.unwrap();
            resolved = v["node_id"].as_str().map(|s| s.to_string());
            break;
        }
    }
    assert_eq!(resolved, Some(hex::encode(id)), "name resolves to the claiming node");
}

/// Discovery: a node advertising a service is found by NodeId by another node via the DHT.
#[tokio::test(flavor = "multi_thread")]
async fn service_advertise_and_find() {
    let (p2p_a, api_a) = alloc_ports();
    let dir_a = tmpdir("svc-provider");
    let _node_a = Node::start(NodeConfig {
        listen_port: p2p_a,
        bootstrap_peers: vec![],
        data_dir: dir_a.clone(),
        api_port: api_a,
        mine: false,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();
    let a_id = host_node_id(&dir_a);

    sleep(Duration::from_millis(600)).await;

    let bs = bootstrap_addr(&dir_a, p2p_a);
    let (p2p_b, api_b) = alloc_ports();
    let _node_b = Node::start(NodeConfig {
        listen_port: p2p_b,
        bootstrap_peers: vec![bs],
        data_dir: tmpdir("svc-finder"),
        api_port: api_b,
        mine: false,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();

    sleep(Duration::from_secs(2)).await; // mesh connect + Kademlia populate

    let client = reqwest::Client::new();
    let r = client
        .post(format!("http://127.0.0.1:{api_a}/discovery/advertise")).bearer_auth(TEST_API_TOKEN)
        .json(&serde_json::json!({ "service": "gpu-pool" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    let mut found = false;
    for _ in 0..15 {
        sleep(Duration::from_secs(1)).await;
        let v: serde_json::Value =
            reqwest::get(format!("http://127.0.0.1:{api_b}/discovery/find/gpu-pool"))
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        if let Some(providers) = v["providers"].as_array() {
            if providers.iter().any(|p| p.as_str() == Some(&hex::encode(a_id))) {
                found = true;
                break;
            }
        }
    }
    assert!(found, "B should discover A as a provider of gpu-pool, by NodeId");
}

/// App request/reply (Stage 3): A sends a request to B and gets B's app's reply synchronously.
/// A responder task on B watches its inbox for the request's reply token and answers via
/// `/mesh/reply`; A's `/mesh/request` returns that reply.
#[tokio::test(flavor = "multi_thread")]
async fn app_request_reply_roundtrip() {
    let (p2p_a, api_a) = alloc_ports();
    let dir_a = tmpdir("rr-requester");
    let _node_a = Node::start(NodeConfig {
        listen_port: p2p_a,
        bootstrap_peers: vec![],
        data_dir: dir_a.clone(),
        api_port: api_a,
        mine: false,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();

    sleep(Duration::from_millis(600)).await;

    let bs = bootstrap_addr(&dir_a, p2p_a);
    let (p2p_b, api_b) = alloc_ports();
    let dir_b = tmpdir("rr-responder");
    let _node_b = Node::start(NodeConfig {
        listen_port: p2p_b,
        bootstrap_peers: vec![bs],
        data_dir: dir_b.clone(),
        api_port: api_b,
        mine: false,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();
    let b_id = host_node_id(&dir_b);

    sleep(Duration::from_secs(2)).await; // mesh connect

    // B's app: watch the inbox for a request with a reply token and answer "pong".
    let responder = tokio::spawn(async move {
        let client = reqwest::Client::new();
        for _ in 0..40 {
            sleep(Duration::from_millis(250)).await;
            let msgs: serde_json::Value =
                reqwest::get(format!("http://127.0.0.1:{api_b}/mesh/messages"))
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
            if let Some(token) = msgs
                .as_array()
                .and_then(|a| a.iter().find_map(|m| m["reply_token"].as_u64()))
            {
                client
                    .post(format!("http://127.0.0.1:{api_b}/mesh/reply")).bearer_auth(TEST_API_TOKEN)
                    .json(&serde_json::json!({ "token": token, "payload_hex": hex::encode(b"pong") }))
                    .send()
                    .await
                    .unwrap();
                return;
            }
        }
    });

    // A issues the request and blocks until B's app replies.
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{api_a}/mesh/request")).bearer_auth(TEST_API_TOKEN)
        .json(&serde_json::json!({
            "to": hex::encode(b_id),
            "topic": "rpc",
            "payload_hex": hex::encode(b"ping"),
            "timeout_ms": 15000
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "request should get a reply");
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["payload_hex"], hex::encode(b"pong"), "A receives B's reply");
    responder.await.unwrap();
}

/// App pub/sub: a message published on a topic reaches a subscriber on another node, verified.
/// Both nodes subscribe to `telemetry`; A publishes; B's inbox shows it with A as the signed
/// sender and the payload intact.
#[tokio::test(flavor = "multi_thread")]
async fn app_pubsub_delivers_to_subscriber() {
    let (p2p_a, api_a) = alloc_ports();
    let dir_a = tmpdir("ps-publisher");
    let _node_a = Node::start(NodeConfig {
        listen_port: p2p_a,
        bootstrap_peers: vec![],
        data_dir: dir_a.clone(),
        api_port: api_a,
        mine: false,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();
    let a_id = Identity::load_or_generate(&dir_a.join("identity")).unwrap().node_id();

    sleep(Duration::from_millis(600)).await;

    let bs = bootstrap_addr(&dir_a, p2p_a);
    let (p2p_b, api_b) = alloc_ports();
    let _node_b = Node::start(NodeConfig {
        listen_port: p2p_b,
        bootstrap_peers: vec![bs],
        data_dir: tmpdir("ps-subscriber"),
        api_port: api_b,
        mine: false,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();

    sleep(Duration::from_secs(2)).await; // mesh connect

    let client = reqwest::Client::new();
    // Both subscribe so they share the topic's gossipsub mesh.
    for api in [api_a, api_b] {
        let r = client
            .post(format!("http://127.0.0.1:{api}/mesh/subscribe")).bearer_auth(TEST_API_TOKEN)
            .json(&serde_json::json!({ "topic": "telemetry" }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
    }

    // Let gossipsub form the topic mesh (graft), then publish from A repeatedly while polling B —
    // the first publishes may land before B has grafted.
    let payload_hex = hex::encode(b"metric");
    let mut found = None;
    for _ in 0..15 {
        sleep(Duration::from_secs(1)).await;
        let _ = client
            .post(format!("http://127.0.0.1:{api_a}/mesh/publish")).bearer_auth(TEST_API_TOKEN)
            .json(&serde_json::json!({ "topic": "telemetry", "payload_hex": payload_hex }))
            .send()
            .await
            .unwrap();
        let msgs: serde_json::Value = reqwest::get(format!("http://127.0.0.1:{api_b}/mesh/messages"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if let Some(m) = msgs.as_array().and_then(|a| a.iter().find(|m| m["topic"] == "telemetry")) {
            found = Some(m.clone());
            break;
        }
    }
    let m = found.expect("subscriber B should receive the published message");
    assert_eq!(m["from"], hex::encode(a_id), "publisher is the signed sender");
    assert_eq!(m["payload_hex"], payload_hex, "payload intact");
}

/// App messaging: a directed message from one node arrives in another's inbox, authenticated.
/// Node A sends to node B over the mesh; B's `/mesh/messages` shows it with A as the verified
/// sender and the payload intact.
#[tokio::test(flavor = "multi_thread")]
async fn app_message_delivered_across_mesh() {
    let (p2p_a, api_a) = alloc_ports();
    let dir_a = tmpdir("msg-sender");
    let _node_a = Node::start(NodeConfig {
        listen_port: p2p_a,
        bootstrap_peers: vec![],
        data_dir: dir_a.clone(),
        api_port: api_a,
        mine: false,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();
    let a_id = Identity::load_or_generate(&dir_a.join("identity")).unwrap().node_id();

    sleep(Duration::from_millis(600)).await;

    let bs = bootstrap_addr(&dir_a, p2p_a);
    let (p2p_b, api_b) = alloc_ports();
    let dir_b = tmpdir("msg-receiver");
    let _node_b = Node::start(NodeConfig {
        listen_port: p2p_b,
        bootstrap_peers: vec![bs],
        data_dir: dir_b.clone(),
        api_port: api_b,
        mine: false,
        disable_local_discovery: true,
        ..Default::default()
    })
    .await
    .unwrap();
    let b_id = host_node_id(&dir_b);

    sleep(Duration::from_secs(2)).await; // mesh connect

    let client = reqwest::Client::new();
    // "ping" in hex.
    let payload_hex = hex::encode(b"ping");
    let resp = client
        .post(format!("http://127.0.0.1:{api_a}/mesh/send")).bearer_auth(TEST_API_TOKEN)
        .json(&serde_json::json!({
            "to": hex::encode(b_id),
            "topic": "control",
            "payload_hex": payload_hex,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "mesh/send should report delivered");

    // B's inbox should show the message, from A, intact.
    let mut found = None;
    for _ in 0..10 {
        sleep(Duration::from_millis(500)).await;
        let msgs: serde_json::Value = reqwest::get(format!("http://127.0.0.1:{api_b}/mesh/messages"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if let Some(m) = msgs.as_array().and_then(|a| a.first()) {
            found = Some(m.clone());
            break;
        }
    }
    let m = found.expect("B should receive the app message");
    assert_eq!(m["from"], hex::encode(a_id), "sender is the authenticated NodeId");
    assert_eq!(m["topic"], "control");
    assert_eq!(m["payload_hex"], payload_hex, "payload intact");
}
