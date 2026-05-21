use anyhow::{anyhow, Result};
use std::process::{Command, Output};
use tokio::time::{sleep, Duration};

const SSH_OPTS: &[&str] = &[
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=10",
    "-o", "BatchMode=yes",
    "-o", "LogLevel=ERROR",
];

fn ssh_args(ip: &str, key: &str) -> Vec<String> {
    let mut args: Vec<String> = SSH_OPTS.iter().map(|s| s.to_string()).collect();
    args.push("-i".into());
    args.push(key.into());
    args.push(format!("root@{ip}"));
    args
}

fn check(output: Output, context: &str) -> Result<String> {
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(anyhow!("{context}: {stderr}"))
    }
}

/// Run a single command on a remote host.
pub fn run(ip: &str, key: &str, cmd: &str) -> Result<String> {
    let mut args = ssh_args(ip, key);
    args.push(cmd.into());
    let out = Command::new("ssh").args(&args).output()?;
    check(out, &format!("ssh {ip} {cmd}"))
}

/// Copy a local file to a remote host.
pub fn copy(ip: &str, key: &str, local: &str, remote: &str) -> Result<()> {
    let dest = format!("root@{ip}:{remote}");
    let mut args: Vec<String> = SSH_OPTS.iter().map(|s| s.to_string()).collect();
    args.extend(["-i".into(), key.into(), local.into(), dest]);
    let out = Command::new("scp").args(&args).output()?;
    check(out, &format!("scp {local} → {ip}:{remote}")).map(|_| ())
}

/// Probe SSH connectivity — retries for up to 30 seconds.
pub async fn probe(ip: &str, key: &str) -> Result<()> {
    for attempt in 0..10 {
        if attempt > 0 {
            sleep(Duration::from_secs(3)).await;
        }
        let mut args = ssh_args(ip, key);
        args.push("true".into());
        if let Ok(out) = Command::new("ssh").args(&args).output() {
            if out.status.success() {
                return Ok(());
            }
        }
    }
    Err(anyhow!("SSH probe timed out for {ip}"))
}

/// Install required system packages on a fresh Ubuntu 22.04 server.
/// Installs libssl (CE runtime dep) and Docker (for job execution).
pub fn provision(ip: &str, key: &str) -> Result<()> {
    // Wait for cloud-init to finish (it holds the apt lock during first-boot setup).
    run(ip, key, "cloud-init status --wait 2>/dev/null || sleep 30")?;
    // Belt-and-suspenders: also wait for the dpkg lock itself.
    run(ip, key, "until ! fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do sleep 2; done")?;
    run(ip, key, "DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y libssl-dev docker.io")?;
    run(ip, key, "systemctl enable --now docker")?;
    Ok(())
}

/// Upload the CE binary and make it executable.
pub fn deploy_binary(ip: &str, key: &str, local_binary: &str) -> Result<()> {
    copy(ip, key, local_binary, "/usr/local/bin/ce")?;
    run(ip, key, "chmod +x /usr/local/bin/ce")?;
    Ok(())
}

/// Start a CE node in the background. Returns the node's hex ID.
pub fn start_node(
    ip: &str,
    key: &str,
    p2p_port: u16,
    api_port: u16,
    bootstrap: Option<&str>,
) -> Result<String> {
    // Kill any existing CE process.
    let _ = run(ip, key, "pkill -f '/usr/local/bin/ce' || true");

    let bootstrap_arg = bootstrap
        .map(|b| format!("--bootstrap '{b}'"))
        .unwrap_or_default();

    let cmd = format!(
        "nohup /usr/local/bin/ce start --port {p2p_port} --api-port {api_port} {bootstrap_arg} \
         > /var/log/ce.log 2>&1 &"
    );
    run(ip, key, &cmd)?;

    // Give CE a moment to write its identity.
    std::thread::sleep(std::time::Duration::from_secs(2));

    let node_id = run(ip, key, "/usr/local/bin/ce id")?;
    Ok(node_id)
}

/// Stop the CE node process.
pub fn stop_node(ip: &str, key: &str) -> Result<()> {
    let _ = run(ip, key, "pkill -f '/usr/local/bin/ce' || true");
    Ok(())
}

/// Read the CE log from the remote server.
pub fn read_log(ip: &str, key: &str) -> Result<String> {
    run(ip, key, "cat /var/log/ce.log 2>/dev/null || echo ''")
}
