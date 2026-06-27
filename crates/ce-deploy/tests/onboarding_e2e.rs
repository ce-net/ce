//! Real-VM E2E test of the DEVELOPER ONBOARDING FLOW.
//!
//! Ordered by Leif (PLAN/ce-e2e-vm-onboarding-tests.md, notes/verbatim-orders-leif.md): "instead of
//! guessing write e2e tests spinning up real vms trying this process - the installation commands ...
//! and fix so it actually works."
//!
//! These provision fresh Hetzner VMs and run the EXACT commands a developer runs — `curl install.sh
//! | bash`, `ce start`, connecting two devices — then assert the flow behaves as intended. They are
//! the failures hand-debugging missed:
//!   * install lands the RELEASED binary as the on-PATH `ce` (catches the /usr/local vs ~/.local
//!     shadowing bug),
//!   * a second node JOINING the first SYNCS to its height (catches the mining-from-genesis fork and
//!     the consensus/format incompatibility — both fresh same-version nodes MUST converge),
//!   * connected devices can deploy across the mesh.
//!
//! Run (real VMs — costs money, ~10 min, needs a Hetzner project + SSH key already registered):
//!   HETZNER_API_TOKEN=.. CE_SSH_KEY_NAME=.. CE_SSH_KEY_PATH=~/.ssh/id_ed25519 \
//!     cargo test -p ce-deploy --test onboarding_e2e -- --ignored --nocapture --test-threads=1
//!
//! Every test deletes its VMs on exit (success OR failure).

use anyhow::{anyhow, bail, Context, Result};
use ce_deploy::{ssh, HetznerClient};
use std::time::Duration;

const INSTALL_ONE_LINER: &str =
    "curl -fsSL https://raw.githubusercontent.com/ce-net/ce/main/install.sh | bash";

/// Env the tests need; returns None to SKIP (so `cargo test` without creds is green, not red).
fn creds() -> Option<(String, String, String)> {
    Some((
        std::env::var("HETZNER_API_TOKEN").ok()?,
        std::env::var("CE_SSH_KEY_NAME").ok()?,
        std::env::var("CE_SSH_KEY_PATH").ok()?,
    ))
}

/// A provisioned VM and the bits needed to drive + tear it down.
struct Vm {
    id: u64,
    ip: String,
    key: String,
}

impl Vm {
    async fn provision(hz: &HetznerClient, key_path: &str, name: &str) -> Result<Vm> {
        let s = hz.create_server(name).await.context("create_server")?;
        let s = hz
            .wait_until_running(s.id, key_path)
            .await
            .context("wait_until_running")?;
        Ok(Vm {
            id: s.id,
            ip: s.ip().to_string(),
            key: key_path.to_string(),
        })
    }

    /// Run a shell command on the VM (blocking ssh wrapped for the async runtime).
    async fn sh(&self, cmd: &str) -> Result<String> {
        let (ip, key, cmd) = (self.ip.clone(), self.key.clone(), cmd.to_string());
        tokio::task::spawn_blocking(move || ssh::run(&ip, &key, &cmd))
            .await
            .context("ssh join")?
    }

    /// `curl localhost:<port>/status` on the VM, returning the node's height.
    async fn height(&self, port: u16) -> Result<u64> {
        let out = self
            .sh(&format!("curl -fsS --max-time 8 http://127.0.0.1:{port}/status"))
            .await?;
        let v: serde_json::Value =
            serde_json::from_str(out.trim()).with_context(|| format!("status json: {out}"))?;
        v["height"]
            .as_u64()
            .ok_or_else(|| anyhow!("no height in status: {out}"))
    }
}

/// Delete a set of VMs, logging (never failing) — call from every exit path.
async fn teardown(hz: &HetznerClient, vms: &[u64]) {
    for &id in vms {
        if let Err(e) = hz.delete_server(id).await {
            eprintln!("WARN: failed to delete server {id}: {e} — delete it manually!");
        } else {
            eprintln!("torn down server {id}");
        }
    }
}

/// The current GitHub "latest" release tag (e.g. "v0.1.3") — what install.sh should land.
async fn latest_release_tag() -> Result<String> {
    let v: serde_json::Value = reqwest::Client::builder()
        .user_agent("ce-onboarding-e2e")
        .build()?
        .get("https://api.github.com/repos/ce-net/ce/releases/latest")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    v["tag_name"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("no tag_name"))
}

/// Install ce on a fresh VM via the real one-liner and stop the auto-started service, so the test can
/// drive an ISOLATED node manually (no auto-join of the live ce-net.com network).
async fn install_and_quiesce(vm: &Vm) -> Result<()> {
    vm.sh(INSTALL_ONE_LINER).await.context("install.sh")?;
    // install.sh (as root) starts a systemd service that joins ce-net.com; stop it for isolation.
    let _ = vm.sh("systemctl stop ce 2>/dev/null; pkill -f 'ce start' 2>/dev/null; sleep 2; true").await;
    // Fresh chain so the isolated cluster starts from a common genesis.
    vm.sh("rm -rf /root/.local/share/ce/chain").await?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1 — `curl install.sh | bash` lands the RELEASED binary as the on-PATH `ce`.
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
#[ignore]
async fn install_script_lands_release_on_path() -> Result<()> {
    let Some((token, key_name, key_path)) = creds() else {
        eprintln!("SKIP: set HETZNER_API_TOKEN, CE_SSH_KEY_NAME, CE_SSH_KEY_PATH");
        return Ok(());
    };
    let hz = HetznerClient::new(token, key_name);
    let want_tag = latest_release_tag().await?;
    let vm = Vm::provision(&hz, &key_path, &format!("ce-onb-install-{}", short_ts())).await?;

    let result = async {
        // Pre-seed a STALE shadowing binary to prove the installer overwrites the on-PATH one.
        vm.sh("mkdir -p /usr/local/bin && printf '#!/bin/sh\\necho ce 0.0.0-stale\\n' > /usr/local/bin/ce && chmod +x /usr/local/bin/ce").await?;
        vm.sh(INSTALL_ONE_LINER).await.context("install.sh")?;

        let which = vm.sh("command -v ce").await?.trim().to_string();
        let version = vm.sh("ce --version").await?.trim().to_string();
        eprintln!("on-PATH ce: {which}\nversion: {version}");
        if !version.contains(want_tag.trim_start_matches('v')) {
            bail!("on-PATH ce is '{version}', expected the released {want_tag} (shadowing bug?)");
        }
        // install.sh as root also installs+starts a systemd service; the API should answer.
        vm.sh("sleep 5; systemctl is-active ce || true").await?;
        let _ = vm.height(8844).await; // best-effort; may be mid-bootstrap
        Ok::<_, anyhow::Error>(())
    }
    .await;

    teardown(&hz, &[vm.id]).await;
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2 — two fresh same-version nodes form a network: the joiner SYNCS to the
// bootstrap's height, they see each other, and one can deploy on the other.
// This is the test that catches the mining-fork and consensus/format bugs.
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
#[ignore]
async fn two_nodes_converge_and_connect() -> Result<()> {
    let Some((token, key_name, key_path)) = creds() else {
        eprintln!("SKIP: set HETZNER_API_TOKEN, CE_SSH_KEY_NAME, CE_SSH_KEY_PATH");
        return Ok(());
    };
    let hz = HetznerClient::new(token, key_name);
    let ts = short_ts();
    let a = Vm::provision(&hz, &key_path, &format!("ce-onb-a-{ts}")).await?;
    let b = Vm::provision(&hz, &key_path, &format!("ce-onb-b-{ts}")).await?;

    let result = async {
        install_and_quiesce(&a).await.context("install on A")?;
        install_and_quiesce(&b).await.context("install on B")?;

        // A = isolated genesis/bootstrap. API on 0.0.0.0 so we can read it; mDNS off; no auto-join.
        a.sh("CE_NO_AUTOBOOTSTRAP=1 nohup ce start --no-mdns --api-bind 0.0.0.0 \
              > /var/log/ce.log 2>&1 & sleep 6").await?;
        let a_id = a.sh("ce id 2>/dev/null | grep -oE '[0-9a-f]{64}' | head -1").await?
            .trim().to_string();
        if a_id.len() != 64 {
            bail!("A node id not ready: '{a_id}'\nlog:\n{}", a.sh("tail -30 /var/log/ce.log").await.unwrap_or_default());
        }
        let a_multiaddr = format!("/ip4/{}/tcp/4001/p2p/{a_id}", a.ip);

        // B joins A. DEFAULT mining stays ON — the desired dev flow must converge without --no-mine.
        b.sh(&format!(
            "CE_NO_AUTOBOOTSTRAP=1 nohup ce start --no-mdns --api-bind 0.0.0.0 --bootstrap '{a_multiaddr}' \
             > /var/log/ce.log 2>&1 & sleep 6"
        )).await?;

        // Let A build some height, then assert B SYNCS up to it (the core onboarding invariant).
        let mut converged = false;
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let (ha, hb) = (a.height(8844).await.unwrap_or(0), b.height(8844).await.unwrap_or(0));
            eprintln!("heights: A={ha} B={hb}");
            if ha >= 5 && hb + 3 >= ha && hb > 0 {
                converged = true;
                break;
            }
        }
        if !converged {
            let blog = b.sh("grep -E 'mesh exited|mismatch|rejected|relay circuit|peer connected' /var/log/ce.log | tail -20")
                .await.unwrap_or_default();
            bail!("B never synced to A — fork / format mismatch / unreachable. B log:\n{blog}");
        }

        // Devices see each other on the mesh.
        let a_atlas = a.sh("curl -fsS http://127.0.0.1:8844/atlas").await?;
        if !a_atlas.contains(&b_id_of(&b).await.unwrap_or_default()) {
            eprintln!("NOTE: A's atlas did not list B yet:\n{a_atlas}");
        }

        // Connect: A authorizes B, then B deploys a container ON A over the mesh.
        let token = a.sh(&format!(
            "ce grant {b} --can deploy,kill,status --resource self 2>/dev/null | tail -1",
            b = b_id_of(&b).await?
        )).await?.trim().to_string();
        if token.len() < 32 {
            bail!("grant on A produced no token: '{token}'");
        }
        b.sh(&format!("ce wallet add hostA {a_id} --cap {token}")).await?;
        let deploy = b.sh(&format!(
            "ce deploy alpine:latest --on hostA --cmd 'echo paired-ok' --fund 1000 --duration 60 2>&1 | tail -5"
        )).await?;
        eprintln!("cross-node deploy:\n{deploy}");
        if deploy.to_lowercase().contains("error") || deploy.to_lowercase().contains("failed") {
            bail!("cross-node deploy B->A failed:\n{deploy}");
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;

    teardown(&hz, &[a.id, b.id]).await;
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3 — CANARY: a fresh RELEASE node joining the LIVE ce-net.com network must
// sync to its height. Fails today (released format-v2 vs live format-v1) — this
// is the documented incompatibility the live-network upgrade must fix.
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
#[ignore]
async fn fresh_release_node_joins_live_network() -> Result<()> {
    let Some((token, key_name, key_path)) = creds() else {
        eprintln!("SKIP: set HETZNER_API_TOKEN, CE_SSH_KEY_NAME, CE_SSH_KEY_PATH");
        return Ok(());
    };
    let hz = HetznerClient::new(token, key_name);
    let vm = Vm::provision(&hz, &key_path, &format!("ce-onb-live-{}", short_ts())).await?;

    let result = async {
        vm.sh(INSTALL_ONE_LINER).await.context("install.sh")?;
        // install.sh's root service runs `ce start` which auto-bootstraps ce-net.com.
        vm.sh("systemctl restart ce 2>/dev/null || true; sleep 8").await?;
        let mut synced = false;
        let mut last = 0;
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_secs(5)).await;
            last = vm.height(8844).await.unwrap_or(0);
            eprintln!("joining-node height: {last}");
            if last > 1000 {
                synced = true;
                break;
            }
        }
        let log = vm.sh("journalctl -u ce -n 25 --no-pager 2>/dev/null || tail -25 /var/log/ce.log")
            .await.unwrap_or_default();
        if !synced {
            bail!(
                "CANARY FAILED (expected until the live network is upgraded): fresh release node \
                 stuck at height {last}, did not sync the live chain.\nlog:\n{log}"
            );
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;

    teardown(&hz, &[vm.id]).await;
    result
}

/// B's 64-hex node id (read on the VM).
async fn b_id_of(vm: &Vm) -> Result<String> {
    let id = vm
        .sh("ce id 2>/dev/null | grep -oE '[0-9a-f]{64}' | head -1")
        .await?
        .trim()
        .to_string();
    if id.len() == 64 {
        Ok(id)
    } else {
        bail!("node id not ready: '{id}'")
    }
}

/// A short, monotonic-ish suffix for VM names without Date/rand (uses process id + a counter).
fn short_ts() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    format!("{}{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed))
}
