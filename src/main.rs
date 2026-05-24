use anyhow::{anyhow, Result};
use ce_chain::Chain;
use ce_identity::Identity;
use ce_node::{auth::make_auth_headers, devices::Devices, Node, NodeConfig};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use std::net::IpAddr;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

/// Return non-loopback IPv4 addresses on this host. Used to print bootstrap multiaddrs.
fn local_ip_addrs() -> Result<Vec<IpAddr>> {
    use std::net::UdpSocket;
    // UDP connect trick: bind to any addr, check what local IP the OS picks for an external dest.
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    let addr = socket.local_addr()?;
    Ok(vec![addr.ip()])
}

#[derive(Parser)]
#[command(name = "ce", about = "CE node")]
struct Cli {
    #[arg(long, help = "Override data directory (default: ~/.local/share/ce)")]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the CE node: mine, meter, mesh, and HTTP API.
    Start {
        #[arg(short, long, default_value = "4001")]
        port: u16,
        #[arg(long, default_value = "8080")]
        api_port: u16,
        /// Bootstrap peer multiaddrs: /ip4/1.2.3.4/tcp/4001/p2p/<peer-id>
        #[arg(short, long)]
        bootstrap: Vec<String>,
        /// Relay node multiaddrs for NAT traversal: /ip4/1.2.3.4/tcp/4001/p2p/<peer-id>
        /// The node connects to each relay and listens on its circuit address,
        /// becoming reachable from the internet even behind NAT.
        #[arg(long)]
        relay: Vec<String>,
    },
    /// Show this node's credit balance.
    Balance,
    /// Show node status (id, chain height, difficulty, balance).
    Status,
    /// Print this node's ID.
    Id,
    /// Manage trusted devices (personal mesh OS).
    Devices {
        #[command(subcommand)]
        command: DevicesCommands,
    },
    /// Sync files to a remote device.
    ///
    /// Destination format: <device-name>:<remote-path>
    /// Example: ce sync . desktop:~/code/ce
    Sync {
        src: String,
        dst: String,
    },
    /// Execute a command on a remote CE node inside a sandboxed container.
    ///
    /// The node's home directory is bind-mounted at /workspace inside the container.
    /// Example: ce exec desktop --image rust:latest cargo build --release
    Exec {
        machine: String,
        /// Docker image to run the command in (e.g. rust:latest, alpine:latest).
        #[arg(long, short = 'i')]
        image: String,
        /// Working directory (relative to ~/). Defaults to ~/workspace.
        #[arg(long)]
        cwd: Option<String>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Deploy a cell (container job) on the local node.
    ///
    /// Example: ce deploy alpine:latest --fund 1000 --duration 300
    Deploy {
        /// Docker image to run.
        image: String,
        #[arg(long, default_value = "1000")]
        fund: u64,
        #[arg(long, default_value = "1")]
        cpu: u32,
        #[arg(long, default_value = "128")]
        mem: u64,
        #[arg(long, default_value = "300")]
        duration: u64,
        /// Command override for the container.
        #[arg(short, long)]
        cmd: Vec<String>,
        #[arg(long, default_value = "8080")]
        api_port: u16,
    },
    /// List jobs on this node (or a remote device).
    ///
    /// Example: ce ps
    Ps {
        #[arg(long, default_value = "8080")]
        api_port: u16,
    },
    /// Force-stop a job by CE job ID.
    ///
    /// Example: ce kill <job-id>
    Kill {
        job_id: String,
        #[arg(long, default_value = "8080")]
        api_port: u16,
    },
    /// Transfer credits to another node.
    ///
    /// Example: ce fund <node-id> 500
    Fund {
        /// Recipient NodeId (64 hex chars).
        to: String,
        amount: u64,
        #[arg(long, default_value = "8080")]
        api_port: u16,
    },
    /// Send a CEP-1 signal to a cell and print the response.
    ///
    /// Example: ce run <cell-id> deadbeef
    Run {
        /// Destination NodeId (64 hex chars) or "broadcast".
        cell: String,
        /// Payload as hex string. Requires a burn_tx_id if non-empty.
        #[arg(default_value = "")]
        payload_hex: String,
        #[arg(long)]
        burn_tx: Option<String>,
        #[arg(long, default_value = "8080")]
        api_port: u16,
    },
}

#[derive(Subcommand)]
enum DevicesCommands {
    /// Add a trusted device. Prompts for node ID and API address.
    Add {
        /// Friendly name for the device (e.g. "desktop", "laptop").
        name: String,
    },
    /// List all registered devices.
    Ls,
    /// Revoke trust for a device.
    Revoke {
        /// Device name to remove.
        name: String,
    },
}

fn data_dir(override_path: Option<PathBuf>) -> PathBuf {
    override_path.unwrap_or_else(|| {
        ProjectDirs::from("", "", "ce")
            .map(|d| d.data_dir().to_owned())
            .unwrap_or_else(|| PathBuf::from(".ce"))
    })
}

fn devices_path(data_dir: &PathBuf) -> PathBuf {
    data_dir.join("machines.toml")
}


/// Default paths to skip during sync.
fn should_ignore(rel: &std::path::Path) -> bool {
    let s = rel.to_string_lossy();
    let ignore_dirs = ["target/", "node_modules/", ".git/objects/", "__pycache__/"];
    let ignore_names = [".DS_Store"];
    let ignore_exts = [".pyc"];

    for d in &ignore_dirs {
        if s.starts_with(d) || s.contains(&format!("/{d}")) {
            return true;
        }
    }
    if let Some(name) = rel.file_name() {
        for n in &ignore_names {
            if name == *n {
                return true;
            }
        }
    }
    for ext in &ignore_exts {
        if s.ends_with(ext) {
            return true;
        }
    }
    false
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("ce=info".parse()?))
        .init();

    let cli = Cli::parse();
    let data_dir = data_dir(cli.data_dir);

    match cli.command {
        Commands::Start { port, api_port, bootstrap, relay } => {
            // CE_BOOTSTRAP_PEERS: colon-separated list of bootstrap multiaddrs.
            // Useful for Docker/systemd deployments where CLI flags are inconvenient.
            let mut bootstrap_peers = bootstrap;
            if let Ok(env_peers) = std::env::var("CE_BOOTSTRAP_PEERS") {
                for peer in env_peers.split(':').map(str::trim).filter(|s| !s.is_empty()) {
                    bootstrap_peers.push(peer.to_string());
                }
            }
            // CE_RELAY_PEERS: colon-separated list of relay multiaddrs.
            let mut relay_peers = relay;
            if let Ok(env_relays) = std::env::var("CE_RELAY_PEERS") {
                for peer in env_relays.split(':').map(str::trim).filter(|s| !s.is_empty()) {
                    relay_peers.push(peer.to_string());
                }
            }

            let config = NodeConfig {
                listen_port: port,
                bootstrap_peers,
                relay_peers,
                data_dir,
                api_port,
                mine: true,
                ..Default::default()
            };
            let node = Node::start(config).await?;
            let status = node.status().await;
            println!("CE node running");
            println!("  node id  : {}", status.node_id);
            println!("  peer id  : {}", status.peer_id);
            println!("  height   : {}", status.height);
            println!("  balance  : {}", status.balance);
            println!("  p2p port : {}", status.listen_port);
            println!("  api port : {}", status.api_port);
            println!();
            println!("Bootstrap multiaddrs (share with other nodes via --bootstrap):");
            // Try common interface IPs; mDNS handles LAN automatically.
            if let Ok(addrs) = local_ip_addrs() {
                for ip in &addrs {
                    println!("  /ip4/{ip}/tcp/{port}/p2p/{}", status.peer_id);
                }
            } else {
                println!("  /ip4/<your-ip>/tcp/{port}/p2p/{}", status.peer_id);
            }
            println!();
            println!("Press Ctrl-C to stop.");
            tokio::signal::ctrl_c().await?;
            println!("Shutting down.");
        }

        Commands::Balance => {
            let identity_dir = data_dir.join("identity");
            let chain_path = data_dir.join("chain").join("chain.json");
            let identity = Identity::load_or_generate(&identity_dir)?;
            let chain = Chain::load_or_genesis(&chain_path);
            println!("{}", chain.balance(&identity.node_id()));
        }

        Commands::Status => {
            let identity_dir = data_dir.join("identity");
            let chain_path = data_dir.join("chain").join("chain.json");
            let identity = Identity::load_or_generate(&identity_dir)?;
            let chain = Chain::load_or_genesis(&chain_path);
            println!("node id   : {}", identity.node_id_hex());
            println!("height    : {}", chain.height());
            println!("difficulty: {}", chain.difficulty);
            println!("balance   : {}", chain.balance(&identity.node_id()));
        }

        Commands::Id => {
            let identity_dir = data_dir.join("identity");
            let identity = Identity::load_or_generate(&identity_dir)?;
            println!("ce node id : {}", identity.node_id_hex());
            let peer_id = ce_node::peer_id_from_identity(&identity)?;
            println!("libp2p id  : {peer_id}");
        }

        Commands::Devices { command } => {
            let path = devices_path(&data_dir);
            match command {
                DevicesCommands::Add { name } => {
                    use std::io::{BufRead, Write};
                    print!("Node ID (64 hex chars): ");
                    std::io::stdout().flush()?;
                    let mut node_id_hex = String::new();
                    std::io::stdin().lock().read_line(&mut node_id_hex)?;
                    let node_id_hex = node_id_hex.trim();

                    let bytes = hex::decode(node_id_hex)
                        .map_err(|_| anyhow!("node ID must be 64 hex chars"))?;
                    let node_id: [u8; 32] = bytes
                        .try_into()
                        .map_err(|_| anyhow!("node ID must be exactly 32 bytes"))?;

                    print!("API address (host:port, e.g. 192.168.1.10:8080): ");
                    std::io::stdout().flush()?;
                    let mut addr = String::new();
                    std::io::stdin().lock().read_line(&mut addr)?;
                    let addr = addr.trim();

                    let mut devices = Devices::load_or_empty(&path);
                    devices.add(&name, node_id, addr);
                    devices.save(&path)?;
                    println!("Added device '{name}'.");
                }
                DevicesCommands::Ls => {
                    let devices = Devices::load_or_empty(&path);
                    let list = devices.list();
                    if list.is_empty() {
                        println!("No devices registered. Use `ce devices add <name>`.");
                    } else {
                        for (name, node_id, addr) in &list {
                            println!("{name:<16}  {}  {addr}", hex::encode(node_id));
                        }
                    }
                }
                DevicesCommands::Revoke { name } => {
                    let mut devices = Devices::load_or_empty(&path);
                    if devices.remove(&name) {
                        devices.save(&path)?;
                        println!("Revoked device '{name}'.");
                    } else {
                        println!("Device '{name}' not found.");
                    }
                }
            }
        }

        Commands::Sync { src, dst } => {
            // Parse destination: "device:path"
            let (device_name, remote_path) = dst
                .split_once(':')
                .ok_or_else(|| anyhow!("dst must be in <device>:<path> format, e.g. desktop:~/code/ce"))?;

            let identity_dir = data_dir.join("identity");
            let identity = Identity::load_or_generate(&identity_dir)?;

            let dev_path = devices_path(&data_dir);
            let devices = Devices::load_or_empty(&dev_path);
            let (_, addr) = devices.get(device_name)?;

            let src_path = std::path::Path::new(&src);
            let client = reqwest::Client::new();
            let mut synced = 0usize;
            let mut skipped = 0usize;

            for entry in walkdir::WalkDir::new(src_path)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
            {
                let rel = entry.path().strip_prefix(src_path).unwrap_or(entry.path());
                if should_ignore(rel) {
                    skipped += 1;
                    continue;
                }

                // Build the remote path: remote_path/relative
                let remote_path_expanded = if remote_path.starts_with('~') {
                    remote_path.trim_start_matches("~/").trim_start_matches('~').to_string()
                } else {
                    remote_path.to_string()
                };
                let remote_file = format!("{}/{}", remote_path_expanded.trim_end_matches('/'), rel.display());
                let api_path = format!("/sync/{remote_file}");
                let url = format!("http://{addr}{api_path}");

                let file_bytes = std::fs::read(entry.path())?;
                let auth = make_auth_headers(&identity, "PUT", &api_path, &file_bytes);
                let mut req = client.put(&url).body(file_bytes);
                for (k, v) in &auth {
                    req = req.header(k, v);
                }

                let resp = req.send().await?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    eprintln!("WARN: {} → {status}: {body}", rel.display());
                } else {
                    synced += 1;
                }
            }

            println!("Synced {synced} files to {device_name}:{remote_path} ({skipped} ignored).");
        }

        Commands::Exec { machine, image, cwd, command } => {
            if command.is_empty() {
                return Err(anyhow!("specify a command to run, e.g. ce exec desktop --image rust:latest cargo build"));
            }

            let identity_dir = data_dir.join("identity");
            let identity = Identity::load_or_generate(&identity_dir)?;

            let dev_path = devices_path(&data_dir);
            let devices = Devices::load_or_empty(&dev_path);
            let (_, addr) = devices.get(&machine)?;

            let url = format!("http://{addr}/exec");
            let mut body = serde_json::json!({ "image": image, "cmd": command });
            if let Some(c) = cwd {
                body["cwd"] = serde_json::Value::String(c);
            }
            let body_bytes = serde_json::to_vec(&body)?;
            let auth = make_auth_headers(&identity, "POST", "/exec", &body_bytes);
            let client = reqwest::Client::new();
            let mut req = client.post(&url).body(body_bytes).header("content-type", "application/json");
            for (k, v) in &auth {
                req = req.header(k, v);
            }

            let resp = req.send().await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(anyhow!("exec failed ({status}): {text}"));
            }

            let result: serde_json::Value = resp.json().await?;
            let stdout = result["stdout"].as_str().unwrap_or("");
            let stderr = result["stderr"].as_str().unwrap_or("");
            let exit_code = result["exit_code"].as_i64().unwrap_or(-1);

            if !stdout.is_empty() {
                print!("{stdout}");
            }
            if !stderr.is_empty() {
                eprint!("{stderr}");
            }
            if exit_code != 0 {
                std::process::exit(exit_code as i32);
            }
        }

        Commands::Deploy { image, fund, cpu, mem, duration, cmd, api_port } => {
            let url = format!("http://127.0.0.1:{api_port}/jobs/bid");
            let body = serde_json::json!({
                "image": image,
                "cmd": cmd,
                "cpu_cores": cpu,
                "mem_mb": mem,
                "duration_secs": duration,
                "bid": fund,
            });
            let client = reqwest::Client::new();
            let resp = client.post(&url).json(&body).send().await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(anyhow!("deploy failed ({status}): {text}"));
            }
            let result: serde_json::Value = resp.json().await?;
            println!("job_id: {}", result["job_id"].as_str().unwrap_or("?"));
        }

        Commands::Ps { api_port } => {
            let url = format!("http://127.0.0.1:{api_port}/jobs");
            let client = reqwest::Client::new();
            let resp = client.get(&url).send().await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(anyhow!("ps failed ({status}): {text}"));
            }
            let jobs: serde_json::Value = resp.json().await?;
            let jobs = jobs.as_array().map(|v| v.as_slice()).unwrap_or(&[]);
            if jobs.is_empty() {
                println!("No jobs.");
            } else {
                println!("{:<66}  {:<22}  {:<8}  payer", "JOB ID", "STATUS", "BID");
                for job in jobs {
                    let id     = job["job_id"].as_str().unwrap_or("?");
                    let status = job["status"].as_str().unwrap_or("?");
                    let bid    = job["bid"].as_u64().unwrap_or(0);
                    let payer  = job["payer"].as_str().unwrap_or("?");
                    println!("{id:<66}  {status:<22}  {bid:<8}  {payer}");
                }
            }
        }

        Commands::Kill { job_id, api_port } => {
            let url = format!("http://127.0.0.1:{api_port}/jobs/{job_id}");
            let client = reqwest::Client::new();
            let resp = client.delete(&url).send().await?;
            if resp.status().is_success() {
                println!("Job {job_id} stopped.");
            } else {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(anyhow!("kill failed ({status}): {text}"));
            }
        }

        Commands::Fund { to, amount, api_port } => {
            let url = format!("http://127.0.0.1:{api_port}/transfer");
            let body = serde_json::json!({ "to": to, "amount": amount });
            let client = reqwest::Client::new();
            let resp = client.post(&url).json(&body).send().await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(anyhow!("fund failed ({status}): {text}"));
            }
            let result: serde_json::Value = resp.json().await?;
            println!("tx_id: {}", result["tx_id"].as_str().unwrap_or("?"));
        }

        Commands::Run { cell, payload_hex, burn_tx, api_port } => {
            let url = format!("http://127.0.0.1:{api_port}/signals/send");
            let mut body = serde_json::json!({
                "to": cell,
                "payload_hex": payload_hex,
                "capabilities": [],
            });
            if let Some(burn) = burn_tx {
                body["burn_tx_id_hex"] = serde_json::Value::String(burn);
            }
            let client = reqwest::Client::new();
            let resp = client.post(&url).json(&body).send().await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(anyhow!("run failed ({status}): {text}"));
            }
            let result: serde_json::Value = resp.json().await?;
            println!("signal id: {}", result["id"].as_str().unwrap_or("?"));
            println!("nonce    : {}", result["nonce"].as_u64().unwrap_or(0));
        }
    }

    Ok(())
}
