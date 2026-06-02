//! Integration tests for the personal mesh OS layer: device auth, file sync,
//! and remote execution.
//!
//! Each test spins up a real Node in-process, registers a test device in the
//! node's machines.toml, and exercises the HTTP API with properly-signed
//! (or deliberately broken) CE auth headers.

use ce_identity::Identity;
use ce_node::grants::{Constraints, Permission, Selector, SignedGrant};
use ce_node::{auth::make_auth_headers, devices::Devices, Node, NodeConfig};
use reqwest::StatusCode;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU16, Ordering};
use tokio::time::{sleep, Duration};

// Port range reserved for this test file (14_200 – 14_300).
static NEXT_PORT: AtomicU16 = AtomicU16::new(14_200);

fn alloc_ports() -> (u16, u16) {
    let p = NEXT_PORT.fetch_add(2, Ordering::Relaxed);
    (p, p + 1)
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir()
        .join(format!("ce-sync-test-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn make_identity(tag: &str) -> Identity {
    Identity::load_or_generate(&tmpdir(tag)).unwrap()
}

/// Start a non-mining node and wait for the API to come up.
async fn start_node(tag: &str) -> (Node, PathBuf, u16) {
    let (p2p, api) = alloc_ports();
    let dir = tmpdir(tag);
    let node = Node::start(NodeConfig {
        listen_port: p2p,
        bootstrap_peers: vec![],
        data_dir: dir.clone(),
        api_port: api,
        mine: false,
        ..Default::default()
    })
    .await
    .expect("node start");
    sleep(Duration::from_millis(400)).await;
    (node, dir, api)
}

/// Register `client_id` as a trusted device in `server_dir/machines.toml`.
fn register_device(server_dir: &Path, client_id: &Identity) {
    let path = server_dir.join("machines.toml");
    let mut devices = Devices::load_or_empty(&path);
    devices.add("test-client", client_id.node_id(), "127.0.0.1:0");
    devices.save(&path).unwrap();
}

/// Build a reqwest client with CE auth headers for the given request.
fn add_auth(
    builder: reqwest::RequestBuilder,
    identity: &Identity,
    method: &str,
    path: &str,
    body: &[u8],
) -> reqwest::RequestBuilder {
    let headers = make_auth_headers(identity, method, path, body);
    let mut b = builder;
    for (k, v) in headers {
        b = b.header(k, v);
    }
    b
}

// ─────────────────────────────────────────────────────────────────────────────
// Device auth unit-level checks (via HTTP so we test the full path)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn sync_put_no_auth_returns_401() {
    let (_node, _dir, api) = start_node("no-auth").await;
    let client = reqwest::Client::new();
    let resp = client
        .put(format!("http://127.0.0.1:{api}/sync/tmp/ce-test-no-auth.txt"))
        .body(b"hello".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_put_unknown_device_returns_403() {
    let (_node, _dir, api) = start_node("unknown-device").await;
    // Client identity is NOT registered in machines.toml.
    let client_id = make_identity("unknown-client");
    let body = b"secret data";
    let path = "/sync/tmp/ce-test-unknown.txt";
    let req = add_auth(
        reqwest::Client::new().put(format!("http://127.0.0.1:{api}{path}")).body(body.to_vec()),
        &client_id,
        "PUT",
        path,
        body,
    );
    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "unregistered device must get 403");
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_put_bad_signature_returns_401() {
    let (_node, server_dir, api) = start_node("bad-sig").await;
    let client_id = make_identity("bad-sig-client");
    register_device(&server_dir, &client_id);

    let body = b"legitimate body";
    let path = "/sync/tmp/ce-test-badsig.txt";

    // Build valid headers but corrupt the signature.
    let mut headers = make_auth_headers(&client_id, "PUT", path, body);
    for (k, v) in headers.iter_mut() {
        if k == "X-CE-Sig" {
            // Flip the first byte of the signature hex.
            let mut chars: Vec<char> = v.chars().collect();
            chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
            *v = chars.into_iter().collect();
        }
    }

    let mut req = reqwest::Client::new().put(format!("http://127.0.0.1:{api}{path}")).body(body.to_vec());
    for (k, v) in &headers {
        req = req.header(k, v);
    }
    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "bad signature must get 401");
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_put_tampered_body_returns_401() {
    let (_node, server_dir, api) = start_node("tampered").await;
    let client_id = make_identity("tampered-client");
    register_device(&server_dir, &client_id);

    let original_body = b"original file content";
    let tampered_body = b"attacker replaced this";
    let path = "/sync/tmp/ce-test-tampered.txt";

    // Sign the ORIGINAL body but send the TAMPERED body.
    let req = add_auth(
        reqwest::Client::new()
            .put(format!("http://127.0.0.1:{api}{path}"))
            .body(tampered_body.to_vec()),
        &client_id,
        "PUT",
        path,
        original_body, // sign original — body hash mismatch
    );
    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "tampered body must be rejected");
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_put_stale_timestamp_returns_401() {
    let (_node, server_dir, api) = start_node("stale-ts").await;
    let client_id = make_identity("stale-ts-client");
    register_device(&server_dir, &client_id);

    let body = b"data";
    let path = "/sync/tmp/ce-test-stale.txt";

    // Build a timestamp 10 minutes in the past.
    let old_ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        - 10 * 60 * 1000;

    let auth_bytes = ce_node::auth::auth_bytes("PUT", path, old_ts_ms, body);
    let sig = client_id.sign(&auth_bytes);

    let resp = reqwest::Client::new()
        .put(format!("http://127.0.0.1:{api}{path}"))
        .body(body.to_vec())
        .header("X-CE-From", hex::encode(client_id.node_id()))
        .header("X-CE-Timestamp", old_ts_ms.to_string())
        .header("X-CE-Sig", hex::encode(sig))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "stale timestamp must be rejected");
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_put_replay_returns_401() {
    let (_node, server_dir, api) = start_node("replay").await;
    let client_id = make_identity("replay-client");
    register_device(&server_dir, &client_id);

    let body = b"file content";
    let path = "/sync/tmp/ce-test-replay.txt";

    // First request — should succeed or fail only on traversal/fs issues, but not on auth.
    let headers = make_auth_headers(&client_id, "PUT", path, body);
    let mut req1 = reqwest::Client::new()
        .put(format!("http://127.0.0.1:{api}{path}"))
        .body(body.to_vec());
    for (k, v) in &headers {
        req1 = req1.header(k, v);
    }
    let resp1 = req1.send().await.unwrap();
    // Auth should pass (may fail on FS write if path is outside home, that's OK).
    assert_ne!(
        resp1.status(),
        StatusCode::UNAUTHORIZED,
        "first request must not fail auth"
    );

    // Replay the SAME request (same timestamp, same signature).
    let mut req2 = reqwest::Client::new()
        .put(format!("http://127.0.0.1:{api}{path}"))
        .body(body.to_vec());
    for (k, v) in &headers {
        req2 = req2.header(k, v);
    }
    let resp2 = req2.send().await.unwrap();
    assert_eq!(resp2.status(), StatusCode::UNAUTHORIZED, "replayed request must be rejected");
}

// ─────────────────────────────────────────────────────────────────────────────
// File sync roundtrip
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn sync_put_and_get_roundtrip() {
    let (_node, server_dir, api) = start_node("roundtrip").await;
    let client_id = make_identity("roundtrip-client");
    register_device(&server_dir, &client_id);

    // Use a path relative to the server process's home directory.
    // We write to a predictable temp location that definitely exists.
    let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    let rel = "ce-sync-roundtrip-test/hello.txt";
    let api_path = format!("/sync/{rel}");
    let content = b"hello from CE sync test";

    // --- PUT ---
    let put_req = add_auth(
        reqwest::Client::new()
            .put(format!("http://127.0.0.1:{api}{api_path}"))
            .body(content.to_vec()),
        &client_id,
        "PUT",
        &api_path,
        content,
    );
    let put_resp = put_req.send().await.unwrap();
    assert_eq!(put_resp.status(), StatusCode::NO_CONTENT, "PUT must return 204");

    // Verify the file actually landed on disk.
    let on_disk = std::fs::read(home.join(rel)).expect("file must exist on disk after PUT");
    assert_eq!(on_disk, content);

    // --- GET ---
    let get_req = add_auth(
        reqwest::Client::new().get(format!("http://127.0.0.1:{api}{api_path}")),
        &client_id,
        "GET",
        &api_path,
        b"", // no body for GET
    );
    let get_resp = get_req.send().await.unwrap();
    assert_eq!(get_resp.status(), StatusCode::OK, "GET must return 200");
    let returned = get_resp.bytes().await.unwrap();
    assert_eq!(returned.as_ref(), content, "GET must return the exact bytes that were PUT");

    // Clean up.
    let _ = std::fs::remove_file(home.join(rel));
    let _ = std::fs::remove_dir(home.join("ce-sync-roundtrip-test"));
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_get_missing_file_returns_404() {
    let (_node, server_dir, api) = start_node("get-404").await;
    let client_id = make_identity("get-404-client");
    register_device(&server_dir, &client_id);

    let api_path = "/sync/ce-nonexistent-file-xyz.bin";
    let get_req = add_auth(
        reqwest::Client::new().get(format!("http://127.0.0.1:{api}{api_path}")),
        &client_id,
        "GET",
        api_path,
        b"",
    );
    let resp = get_req.send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_put_path_traversal_rejected() {
    let (_node, server_dir, api) = start_node("traversal").await;
    let client_id = make_identity("traversal-client");
    register_device(&server_dir, &client_id);

    // Attempt to write above the home directory via ../
    // URL-encode the dots to bypass naive prefix checks.
    let api_path = "/sync/../../../tmp/evil.txt";
    let body = b"evil content";

    let req = add_auth(
        reqwest::Client::new()
            .put(format!("http://127.0.0.1:{api}{api_path}"))
            .body(body.to_vec()),
        &client_id,
        "PUT",
        api_path,
        body,
    );
    let resp = req.send().await.unwrap();
    // Any 4xx is acceptable (400 Bad Request or 404).
    assert!(resp.status().is_client_error(), "path traversal must be rejected with 4xx");
}

// ─────────────────────────────────────────────────────────────────────────────
// Remote exec
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn exec_no_auth_returns_401() {
    let (_node, _dir, api) = start_node("exec-no-auth").await;
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{api}/exec"))
        .json(&serde_json::json!({ "cmd": ["echo", "hello"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_unknown_device_returns_403() {
    let (_node, _dir, api) = start_node("exec-403").await;
    let client_id = make_identity("exec-403-client"); // not registered

    let body = serde_json::to_vec(&serde_json::json!({ "cmd": ["echo", "hi"] })).unwrap();
    let req = add_auth(
        reqwest::Client::new()
            .post(format!("http://127.0.0.1:{api}/exec"))
            .body(body.clone())
            .header("content-type", "application/json"),
        &client_id,
        "POST",
        "/exec",
        &body,
    );
    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// Execution tests require Docker. Run with: cargo test -p ce-node exec -- --ignored --nocapture

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn exec_runs_echo_and_returns_stdout() {
    let (_node, server_dir, api) = start_node("exec-echo").await;
    let client_id = make_identity("exec-echo-client");
    register_device(&server_dir, &client_id);

    let body = serde_json::to_vec(&serde_json::json!({
        "image": "alpine:latest",
        "cmd": ["echo", "hello-from-ce"],
    })).unwrap();
    let req = add_auth(
        reqwest::Client::new()
            .post(format!("http://127.0.0.1:{api}/exec"))
            .body(body.clone())
            .header("content-type", "application/json"),
        &client_id,
        "POST",
        "/exec",
        &body,
    );
    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let result: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(result["exit_code"].as_i64(), Some(0), "echo should exit 0");
    let stdout = result["stdout"].as_str().unwrap_or("");
    assert!(stdout.contains("hello-from-ce"), "stdout must contain the echoed string: got {stdout:?}");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn exec_captures_exit_code() {
    let (_node, server_dir, api) = start_node("exec-exit").await;
    let client_id = make_identity("exec-exit-client");
    register_device(&server_dir, &client_id);

    let body = serde_json::to_vec(&serde_json::json!({
        "image": "alpine:latest",
        "cmd": ["sh", "-c", "exit 42"],
    })).unwrap();
    let req = add_auth(
        reqwest::Client::new()
            .post(format!("http://127.0.0.1:{api}/exec"))
            .body(body.clone())
            .header("content-type", "application/json"),
        &client_id,
        "POST",
        "/exec",
        &body,
    );
    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let result: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        result["exit_code"].as_i64(),
        Some(42),
        "exit code 42 must be propagated"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn exec_captures_stderr() {
    let (_node, server_dir, api) = start_node("exec-stderr").await;
    let client_id = make_identity("exec-stderr-client");
    register_device(&server_dir, &client_id);

    let body = serde_json::to_vec(&serde_json::json!({
        "image": "alpine:latest",
        "cmd": ["sh", "-c", "echo error-output >&2"],
    })).unwrap();
    let req = add_auth(
        reqwest::Client::new()
            .post(format!("http://127.0.0.1:{api}/exec"))
            .body(body.clone())
            .header("content-type", "application/json"),
        &client_id,
        "POST",
        "/exec",
        &body,
    );
    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let result: serde_json::Value = resp.json().await.unwrap();
    let stderr = result["stderr"].as_str().unwrap_or("");
    assert!(stderr.contains("error-output"), "stderr must be captured: got {stderr:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_tampered_body_returns_401() {
    let (_node, server_dir, api) = start_node("exec-tampered").await;
    let client_id = make_identity("exec-tampered-client");
    register_device(&server_dir, &client_id);

    let original = serde_json::to_vec(&serde_json::json!({ "cmd": ["echo", "safe"] })).unwrap();
    let tampered = serde_json::to_vec(&serde_json::json!({ "cmd": ["rm", "-rf", "/"] })).unwrap();

    // Sign original body, send tampered body.
    let req = add_auth(
        reqwest::Client::new()
            .post(format!("http://127.0.0.1:{api}/exec"))
            .body(tampered)
            .header("content-type", "application/json"),
        &client_id,
        "POST",
        "/exec",
        &original, // sign the safe body
    );
    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "tampered exec body must be rejected");
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_empty_cmd_returns_400() {
    let (_node, server_dir, api) = start_node("exec-empty").await;
    let client_id = make_identity("exec-empty-client");
    register_device(&server_dir, &client_id);

    let body = serde_json::to_vec(&serde_json::json!({ "image": "alpine:latest", "cmd": [] })).unwrap();
    let req = add_auth(
        reqwest::Client::new()
            .post(format!("http://127.0.0.1:{api}/exec"))
            .body(body.clone())
            .header("content-type", "application/json"),
        &client_id,
        "POST",
        "/exec",
        &body,
    );
    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ─────────────────────────────────────────────────────────────────────────────
// Scoped capability grants (HTTP enforcement path)
// ─────────────────────────────────────────────────────────────────────────────

/// Register `admin` as a trusted admin, then issue a grant from it to `subject`.
/// `subject` itself is NOT registered — its only authority is the grant.
fn issue_grant(
    admin: &Identity,
    subject: &Identity,
    perms: Vec<Permission>,
    selector: Selector,
) -> SignedGrant {
    SignedGrant::issue(
        admin,
        subject.node_id(),
        perms,
        selector,
        Constraints::default(), // no expiry
        1,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_with_valid_grant_passes_auth() {
    let (_node, server_dir, api) = start_node("grant-ok").await;
    let admin = make_identity("grant-ok-admin");
    register_device(&server_dir, &admin);
    let subject = make_identity("grant-ok-subject"); // NOT registered

    // Admin grants the subject exec on any workspace.
    let token = issue_grant(&admin, &subject, vec![Permission::Exec], Selector::Any).encode();

    let body = serde_json::to_vec(&serde_json::json!({
        "image": "alpine:latest",
        "cmd": ["echo", "hi"],
    }))
    .unwrap();
    let req = add_auth(
        reqwest::Client::new()
            .post(format!("http://127.0.0.1:{api}/exec"))
            .body(body.clone())
            .header("content-type", "application/json")
            .header("X-CE-Grant", &token),
        &subject,
        "POST",
        "/exec",
        &body,
    );
    let resp = req.send().await.unwrap();
    // The grant must clear authorization. What happens next depends on Docker
    // availability (200 with output, or 503 without), but it must NOT be denied.
    assert_ne!(resp.status(), StatusCode::FORBIDDEN, "valid grant must not be denied");
    assert_ne!(resp.status(), StatusCode::UNAUTHORIZED, "valid grant must clear auth");
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_with_grant_lacking_permission_returns_403() {
    let (_node, server_dir, api) = start_node("grant-noperm").await;
    let admin = make_identity("grant-noperm-admin");
    register_device(&server_dir, &admin);
    let subject = make_identity("grant-noperm-subject");

    // Grant covers Sync, but the request is Exec.
    let token = issue_grant(&admin, &subject, vec![Permission::Sync], Selector::Any).encode();

    let body = serde_json::to_vec(&serde_json::json!({ "image": "alpine:latest", "cmd": ["echo", "hi"] })).unwrap();
    let req = add_auth(
        reqwest::Client::new()
            .post(format!("http://127.0.0.1:{api}/exec"))
            .body(body.clone())
            .header("content-type", "application/json")
            .header("X-CE-Grant", &token),
        &subject,
        "POST",
        "/exec",
        &body,
    );
    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "grant without exec permission must be denied");
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_grant_from_untrusted_issuer_returns_403() {
    let (_node, server_dir, api) = start_node("grant-badissuer").await;
    let admin = make_identity("grant-badissuer-admin");
    register_device(&server_dir, &admin);
    let subject = make_identity("grant-badissuer-subject");
    let rogue = make_identity("grant-badissuer-rogue"); // NOT a trusted admin

    // A rogue (untrusted) key signs a grant — must be rejected even though it is well-formed.
    let token = issue_grant(&rogue, &subject, vec![Permission::Exec], Selector::Any).encode();

    let body = serde_json::to_vec(&serde_json::json!({ "image": "alpine:latest", "cmd": ["echo", "hi"] })).unwrap();
    let req = add_auth(
        reqwest::Client::new()
            .post(format!("http://127.0.0.1:{api}/exec"))
            .body(body.clone())
            .header("content-type", "application/json")
            .header("X-CE-Grant", &token),
        &subject,
        "POST",
        "/exec",
        &body,
    );
    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "grant from untrusted issuer must be denied");
}

// ─────────────────────────────────────────────────────────────────────────────
// Mesh-routed deploy/kill — request validation (single node; no peer/Docker needed,
// the checks below all happen before any mesh send)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn mesh_deploy_bad_node_id_returns_400() {
    let (_node, _dir, api) = start_node("mdeploy-badid").await;
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{api}/mesh-deploy"))
        .json(&serde_json::json!({
            "node_id": "not-hex",
            "image": "alpine:latest",
            "cpu_cores": 1, "mem_mb": 128, "duration_secs": 30,
            "bid": "100"
        }))
        .send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn mesh_deploy_malformed_grant_returns_400() {
    let (_node, _dir, api) = start_node("mdeploy-badgrant").await;
    // Valid (real) target node id, but a garbage grant token — rejected before any send.
    let target = make_identity("mdeploy-target");
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{api}/mesh-deploy"))
        .json(&serde_json::json!({
            "node_id": hex::encode(target.node_id()),
            "image": "alpine:latest",
            "cpu_cores": 1, "mem_mb": 128, "duration_secs": 30,
            "bid": "100",
            "grant": "not-a-valid-grant-token"
        }))
        .send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn mesh_kill_bad_node_id_returns_400() {
    let (_node, _dir, api) = start_node("mkill-badid").await;
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{api}/mesh-kill"))
        .json(&serde_json::json!({ "node_id": "xyz", "job_id": "00" }))
        .send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ─────────────────────────────────────────────────────────────────────────────
// Payment channels
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn channels_empty_on_fresh_node() {
    let (_node, _dir, api) = start_node("chan-empty").await;
    let v: serde_json::Value =
        reqwest::get(format!("http://127.0.0.1:{api}/channels")).await.unwrap().json().await.unwrap();
    assert_eq!(v.as_array().map(|a| a.len()), Some(0));
}

#[tokio::test(flavor = "multi_thread")]
async fn channel_open_zero_balance_returns_402() {
    let (_node, _dir, api) = start_node("chan-402").await;
    let host = make_identity("chan-402-host");
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{api}/channels/open"))
        .json(&serde_json::json!({ "host": hex::encode(host.node_id()), "capacity": "1000" }))
        .send()
        .await
        .unwrap();
    // A non-mining test node has no free balance to lock.
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
}

#[tokio::test(flavor = "multi_thread")]
async fn channel_receipt_signs() {
    let (_node, _dir, api) = start_node("chan-receipt").await;
    let host = make_identity("chan-receipt-host");
    let resp: serde_json::Value = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{api}/channels/receipt"))
        .json(&serde_json::json!({
            "channel_id": hex::encode([1u8; 32]),
            "host": hex::encode(host.node_id()),
            "cumulative": "100"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sig = resp["payer_sig"].as_str().unwrap_or("");
    assert_eq!(sig.len(), 128, "receipt signature is 128 hex chars");
    assert_eq!(resp["cumulative"].as_str(), Some("100"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Reputation read (GET /history/:node_id)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn history_unknown_node_returns_zeros() {
    let (_node, _dir, api) = start_node("history-zero").await;
    let stranger = make_identity("history-stranger");
    let v: serde_json::Value = reqwest::get(format!(
        "http://127.0.0.1:{api}/history/{}",
        hex::encode(stranger.node_id())
    ))
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(v["jobs_hosted"].as_u64(), Some(0));
    assert_eq!(v["earned"].as_str(), Some("0"), "amounts are base-unit strings");
    assert_eq!(v["first_height"].as_u64(), Some(0), "a stranger has no recorded interactions");
}

#[tokio::test(flavor = "multi_thread")]
async fn beacon_returns_height_and_hash() {
    let (_node, _dir, api) = start_node("beacon").await;
    let v: serde_json::Value =
        reqwest::get(format!("http://127.0.0.1:{api}/beacon")).await.unwrap().json().await.unwrap();
    assert!(v["height"].as_u64().is_some(), "beacon has a height");
    let hash = v["hash"].as_str().unwrap_or("");
    assert_eq!(hash.len(), 64, "beacon hash is 64 hex chars");
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[tokio::test(flavor = "multi_thread")]
async fn history_bad_node_id_returns_400() {
    let (_node, _dir, api) = start_node("history-bad").await;
    let resp = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{api}/history/not-hex"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ─────────────────────────────────────────────────────────────────────────────
// Auth module unit-level integration check
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn different_methods_produce_different_signatures() {
    // Two requests with same path/body/ts but different methods must not
    // be interchangeable (a GET auth header must not satisfy a PUT endpoint).
    let (_node, server_dir, api) = start_node("method-mismatch").await;
    let client_id = make_identity("method-mismatch-client");
    register_device(&server_dir, &client_id);

    let body = b"some content";
    let path = "/sync/tmp/ce-method-mismatch.txt";

    // Build headers for GET but send as PUT.
    let req = add_auth(
        reqwest::Client::new()
            .put(format!("http://127.0.0.1:{api}{path}"))
            .body(body.to_vec()),
        &client_id,
        "GET",    // sign as GET …
        path,
        body,
    );
    let resp = req.send().await.unwrap();
    // The server checks method "PUT" against a signature built for "GET" — must reject.
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "signature for GET must not satisfy a PUT request"
    );
}
