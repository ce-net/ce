use anyhow::{anyhow, Result};
use ce_chain::Chain;
use ce_identity::Identity;
use ce_node::{devices::Devices, Node, NodeConfig};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing_subscriber::EnvFilter;

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
    /// Execute a command on a remote device and stream its output.
    ///
    /// Example: ce exec desktop cargo build --release
    Exec {
        machine: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
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

/// Build CE identity auth headers for a request.
/// Signs: b"ce-auth-v1" SP method SP path SP timestamp_le_u64
fn auth_headers(identity: &Identity, method: &str, path: &str) -> Result<Vec<(String, String)>> {
    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let mut buf = Vec::new();
    buf.extend_from_slice(b"ce-auth-v1 ");
    buf.extend_from_slice(method.as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(path.as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(&ts_ms.to_le_bytes());

    let sig = identity.sign(&buf);

    Ok(vec![
        ("X-CE-From".to_string(), hex::encode(identity.node_id())),
        ("X-CE-Timestamp".to_string(), ts_ms.to_string()),
        ("X-CE-Sig".to_string(), hex::encode(sig)),
    ])
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
        Commands::Start { port, api_port, bootstrap } => {
            let config = NodeConfig {
                listen_port: port,
                bootstrap_peers: bootstrap,
                data_dir,
                api_port,
                mine: true,
                ..Default::default()
            };
            let node = Node::start(config).await?;
            let status = node.status().await;
            println!("CE node running");
            println!("  node id  : {}", status.node_id);
            println!("  height   : {}", status.height);
            println!("  balance  : {}", status.balance);
            println!("  p2p port : {}", status.listen_port);
            println!("  api port : {}", status.api_port);
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
            println!("{}", identity.node_id_hex());
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
                let headers = auth_headers(&identity, "PUT", &api_path)?;
                let mut req = client.put(&url).body(file_bytes);
                for (k, v) in &headers {
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

        Commands::Exec { machine, command } => {
            if command.is_empty() {
                return Err(anyhow!("specify a command to run, e.g. ce exec desktop cargo build"));
            }

            let identity_dir = data_dir.join("identity");
            let identity = Identity::load_or_generate(&identity_dir)?;

            let dev_path = devices_path(&data_dir);
            let devices = Devices::load_or_empty(&dev_path);
            let (_, addr) = devices.get(&machine)?;

            let url = format!("http://{addr}/exec");
            let api_path = "/exec";
            let headers = auth_headers(&identity, "POST", api_path)?;

            let body = serde_json::json!({ "cmd": command });
            let client = reqwest::Client::new();
            let mut req = client.post(&url).json(&body);
            for (k, v) in &headers {
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
    }

    Ok(())
}
