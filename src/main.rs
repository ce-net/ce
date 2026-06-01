use anyhow::{anyhow, Result};
use ce_chain::Chain;
use ce_identity::Identity;
use ce_node::{auth::make_auth_headers, devices::Devices, Node, NodeConfig};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

/// Fetch bootstrap peer multiaddrs from the ce-net.com relay or CE_BOOTSTRAP_URL override.
/// Returns an empty vec on any error so startup is never blocked.
async fn fetch_bootstrap_peers() -> Vec<String> {
    let url = std::env::var("CE_BOOTSTRAP_URL")
        .unwrap_or_else(|_| "https://ce-net.com/bootstrap".to_string());

    let client = match reqwest::Client::builder().timeout(Duration::from_secs(10)).build() {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    #[derive(serde::Deserialize)]
    struct BootstrapResp {
        peers: Vec<String>,
    }

    match client.get(&url).send().await {
        Ok(resp) => resp.json::<BootstrapResp>().await.map(|b| b.peers).unwrap_or_default(),
        Err(_) => vec![],
    }
}

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
#[command(name = "ce", about = "CE node", version)]
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
        #[arg(long, default_value = "8844")]
        api_port: u16,
        /// Bootstrap peer multiaddrs: /ip4/1.2.3.4/tcp/4001/p2p/<peer-id>
        #[arg(short, long)]
        bootstrap: Vec<String>,
        /// Relay node multiaddrs for NAT traversal: /ip4/1.2.3.4/tcp/4001/p2p/<peer-id>
        /// The node connects to each relay and listens on its circuit address,
        /// becoming reachable from the internet even behind NAT.
        #[arg(long)]
        relay: Vec<String>,
        /// Disable block mining. Node will still sync, relay, and serve jobs.
        #[arg(long)]
        no_mine: bool,
        /// Run as a light node: auto-prune chain to the last 2880 blocks after each sync.
        /// Archive nodes (relay, desktop) should omit this flag.
        #[arg(long)]
        light: bool,
    },
    /// Show this node's credit balance.
    Balance,
    /// Show node status (id, chain height, difficulty, balance).
    Status,
    /// Print this node's ID.
    Id,
    /// Manage trusted devices (personal mesh OS).
    ///
    /// Quick add: ce devices add desktop <node-id> --addr 192.168.1.10:8844
    Devices {
        #[command(subcommand)]
        command: DevicesCommands,
    },
    /// View and organize your device fleet by tag.
    ///
    /// Combines owner tags (from machines.toml) with capability self-tags a node
    /// advertises on the mesh (gpu, docker, linux, ...), read from the local node's atlas.
    /// Example: ce fleet ls --select gpu
    Fleet {
        #[command(subcommand)]
        command: FleetCommands,
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
        #[arg(long, default_value = "8844")]
        api_port: u16,
    },
    /// List jobs on this node (or a remote device).
    ///
    /// Example: ce ps
    Ps {
        #[arg(long, default_value = "8844")]
        api_port: u16,
    },
    /// Force-stop a job by CE job ID.
    ///
    /// Example: ce kill <job-id>
    Kill {
        job_id: String,
        #[arg(long, default_value = "8844")]
        api_port: u16,
    },
    /// Install CE as a background service that starts automatically on login.
    ///
    /// macOS: installs a LaunchAgent (~/.local/share/ce/ce.log for logs).
    /// Linux: installs a systemd user service (journalctl --user -u ce -f for logs).
    ///
    /// Run `ce install-service` once — CE will start now and on every login.
    InstallService {
        /// Run as a light node (auto-prune chain). Recommended for laptops.
        #[arg(long, default_value = "true")]
        light: bool,
        /// Disable mining. Node will still sync and relay but not earn credits.
        #[arg(long)]
        no_mine: bool,
    },
    /// Remove the background service installed by `ce install-service`.
    UninstallService,
    /// Show CE node logs (works on macOS and Linux).
    Logs {
        /// Number of recent lines to show (then follow).
        #[arg(short, long, default_value = "50")]
        lines: usize,
    },
    /// Transfer credits to another node.
    ///
    /// Example: ce fund <node-id> 500
    Fund {
        /// Recipient NodeId (64 hex chars).
        to: String,
        amount: u64,
        #[arg(long, default_value = "8844")]
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
        #[arg(long, default_value = "8844")]
        api_port: u16,
    },
}

#[derive(Subcommand)]
enum DevicesCommands {
    /// Add a trusted device.
    ///
    /// Quick usage: ce devices add desktop <node-id> --addr 192.168.1.10:8844
    /// Get the node ID on the target machine with: ce id
    Add {
        /// Friendly name for the device (e.g. "desktop", "laptop").
        name: String,
        /// Node ID (64 hex chars). Run `ce id` on the target machine to get it.
        /// If omitted, you will be prompted interactively.
        node_id: Option<String>,
        /// API address (host:port). If omitted, you will be prompted interactively.
        #[arg(long)]
        addr: Option<String>,
        /// Owner tag to attach (repeatable): --tag build --tag home
        #[arg(long = "tag")]
        tags: Vec<String>,
    },
    /// List all registered devices.
    Ls,
    /// Revoke trust for a device.
    Revoke {
        /// Device name to remove.
        name: String,
    },
}

#[derive(Subcommand)]
enum FleetCommands {
    /// List devices with their owner tags and live capability self-tags.
    Ls {
        /// Only show devices carrying this tag (matches owner tags or mesh self-tags).
        #[arg(long)]
        select: Option<String>,
        /// Local node API port to read the atlas from.
        #[arg(long, default_value = "8844")]
        api_port: u16,
    },
    /// Attach one or more owner tags to a device.
    ///
    /// Example: ce fleet tag desktop build gpu
    Tag {
        /// Device name.
        name: String,
        /// Tags to add.
        #[arg(required = true)]
        tags: Vec<String>,
    },
    /// Remove one or more owner tags from a device.
    Untag {
        /// Device name.
        name: String,
        /// Tags to remove.
        #[arg(required = true)]
        tags: Vec<String>,
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

// ----- Service install/uninstall -----

fn install_service(light: bool, no_mine: bool) -> Result<()> {
    let bin = std::env::current_exe()
        .map_err(|e| anyhow!("cannot determine binary path: {e}"))?;
    let bin = bin.to_string_lossy();

    let mut args = vec!["start".to_string()];
    if light   { args.push("--light".into()); }
    if no_mine { args.push("--no-mine".into()); }

    #[cfg(target_os = "macos")]
    {
        let log_dir = dirs_next::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
            .join(".local").join("share").join("ce");
        std::fs::create_dir_all(&log_dir)?;
        let log = log_dir.join("ce.log").to_string_lossy().into_owned();

        let plist_dir = dirs_next::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
            .join("Library").join("LaunchAgents");
        std::fs::create_dir_all(&plist_dir)?;
        let plist_path = plist_dir.join("com.ce-net.ce.plist");

        let arg_xml: String = args.iter()
            .map(|a| format!("        <string>{a}</string>\n"))
            .collect();

        let plist = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ce-net.ce</string>
    <key>ProgramArguments</key>
    <array>
        <string>{bin}</string>
{arg_xml}    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>StandardOutPath</key>
    <string>{log}</string>
    <key>StandardErrorPath</key>
    <string>{log}</string>
</dict>
</plist>
"#
        );

        std::fs::write(&plist_path, &plist)?;
        println!("Wrote {}", plist_path.display());

        // Unload first (idempotent — fails silently if not loaded).
        let _ = std::process::Command::new("launchctl")
            .args(["unload", &plist_path.to_string_lossy()])
            .output();
        let out = std::process::Command::new("launchctl")
            .args(["load", "-w", &plist_path.to_string_lossy()])
            .output()
            .map_err(|e| anyhow!("launchctl load: {e}"))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(anyhow!("launchctl load failed: {err}"));
        }

        println!("CE service installed and started.");
        println!();
        println!("  Logs : tail -f {log}");
        println!("  Stop : launchctl unload ~/Library/LaunchAgents/com.ce-net.ce.plist");
        println!("  Remove: ce uninstall-service");
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        let unit_dir = dirs_next::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
            .join(".config").join("systemd").join("user");
        std::fs::create_dir_all(&unit_dir)?;
        let unit_path = unit_dir.join("ce.service");

        let exec_start = std::iter::once(bin.as_ref())
            .chain(args.iter().map(|s| s.as_str()))
            .collect::<Vec<_>>()
            .join(" ");

        let unit = format!(
            "[Unit]\nDescription=CE — global compute mesh node\nAfter=network.target\n\n\
             [Service]\nExecStart={exec_start}\nRestart=on-failure\nRestartSec=10\n\n\
             [Install]\nWantedBy=default.target\n"
        );

        std::fs::write(&unit_path, &unit)?;
        println!("Wrote {}", unit_path.display());

        for subcmd in &["daemon-reload", "--now enable ce"] {
            let out = std::process::Command::new("systemctl")
                .args(std::iter::once("--user").chain(subcmd.split_whitespace()))
                .output()
                .map_err(|e| anyhow!("systemctl: {e}"))?;
            if !out.status.success() {
                let err = String::from_utf8_lossy(&out.stderr);
                return Err(anyhow!("systemctl --user {subcmd}: {err}"));
            }
        }

        println!("CE service installed and started.");
        println!();
        println!("  Logs : journalctl --user -u ce -f");
        println!("  Stop : systemctl --user stop ce");
        println!("  Remove: ce uninstall-service");
        return Ok(());
    }

    #[allow(unreachable_code)]
    Err(anyhow!("install-service is not supported on this platform. Start manually with: ce start"))
}

fn uninstall_service() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let plist_path = dirs_next::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
            .join("Library").join("LaunchAgents").join("com.ce-net.ce.plist");
        if plist_path.exists() {
            let _ = std::process::Command::new("launchctl")
                .args(["unload", &plist_path.to_string_lossy()])
                .output();
            std::fs::remove_file(&plist_path)?;
            println!("CE service stopped and removed.");
        } else {
            println!("No CE service found (already uninstalled).");
        }
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "disable", "--now", "ce"])
            .output();
        let unit_path = dirs_next::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
            .join(".config").join("systemd").join("user").join("ce.service");
        if unit_path.exists() {
            std::fs::remove_file(&unit_path)?;
            let _ = std::process::Command::new("systemctl")
                .args(["--user", "daemon-reload"])
                .output();
        }
        println!("CE service stopped and removed.");
        return Ok(());
    }

    #[allow(unreachable_code)]
    Err(anyhow!("uninstall-service is not supported on this platform"))
}

fn show_logs(lines: usize) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let log = dirs_next::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
            .join(".local").join("share").join("ce").join("ce.log");
        if !log.exists() {
            println!("No log file yet. Is the service running? Try: ce install-service");
            return Ok(());
        }
        // Use `tail -n N -f` to show last N lines then follow.
        let status = std::process::Command::new("tail")
            .args(["-n", &lines.to_string(), "-f", &log.to_string_lossy()])
            .status()
            .map_err(|e| anyhow!("tail: {e}"))?;
        std::process::exit(status.code().unwrap_or(0));
    }

    #[cfg(target_os = "linux")]
    {
        let status = std::process::Command::new("journalctl")
            .args(["--user", "-u", "ce", "-n", &lines.to_string(), "-f"])
            .status()
            .map_err(|e| anyhow!("journalctl: {e}"))?;
        std::process::exit(status.code().unwrap_or(0));
    }

    #[allow(unreachable_code)]
    Err(anyhow!("logs not supported on this platform"))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("ce=info".parse()?))
        .init();

    let cli = Cli::parse();
    let data_dir = data_dir(cli.data_dir);

    match cli.command {
        Commands::Start { port, api_port, bootstrap, relay, no_mine, light } => {
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
            // Auto-bootstrap from ce-net.com when no peers are configured.
            // Override with CE_BOOTSTRAP_URL or CE_NO_AUTOBOOTSTRAP=1 to disable.
            if bootstrap_peers.is_empty() && std::env::var("CE_NO_AUTOBOOTSTRAP").is_err() {
                let auto = fetch_bootstrap_peers().await;
                if !auto.is_empty() {
                    println!("Connecting to ce-net.com mesh ({} relay peers)...", auto.len());
                    bootstrap_peers.extend(auto);
                }
            }

            let config = NodeConfig {
                listen_port: port,
                bootstrap_peers,
                relay_peers,
                data_dir,
                api_port,
                mine: !no_mine,
                prune_keep: if light { Some(ce_chain::PRUNE_KEEP_BLOCKS) } else { None },
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

        Commands::InstallService { light, no_mine } => {
            install_service(light, no_mine)?;
        }

        Commands::UninstallService => {
            uninstall_service()?;
        }

        Commands::Logs { lines } => {
            show_logs(lines)?;
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
                DevicesCommands::Add { name, node_id, addr, tags } => {
                    use std::io::{BufRead, Write};

                    let node_id_hex = match node_id {
                        Some(id) => id,
                        None => {
                            print!("Node ID (64 hex chars): ");
                            std::io::stdout().flush()?;
                            let mut s = String::new();
                            std::io::stdin().lock().read_line(&mut s)?;
                            s.trim().to_string()
                        }
                    };

                    let bytes = hex::decode(&node_id_hex)
                        .map_err(|_| anyhow!("node ID must be 64 hex chars"))?;
                    let node_id: [u8; 32] = bytes
                        .try_into()
                        .map_err(|_| anyhow!("node ID must be exactly 32 bytes"))?;

                    let addr_str = match addr {
                        Some(a) => a,
                        None => {
                            print!("API address (host:port, e.g. 192.168.1.10:8844): ");
                            std::io::stdout().flush()?;
                            let mut s = String::new();
                            std::io::stdin().lock().read_line(&mut s)?;
                            s.trim().to_string()
                        }
                    };

                    let mut devices = Devices::load_or_empty(&path);
                    devices.add(&name, node_id, &addr_str);
                    if !tags.is_empty() {
                        devices.add_tags(&name, &tags)?;
                    }
                    devices.save(&path)?;
                    println!("Added device '{name}'.");
                }
                DevicesCommands::Ls => {
                    let devices = Devices::load_or_empty(&path);
                    let list = devices.entries();
                    if list.is_empty() {
                        println!("No devices registered. Use `ce devices add <name>`.");
                    } else {
                        for (name, node_id, addr, tags) in &list {
                            let tag_str =
                                if tags.is_empty() { String::new() } else { format!("  [{}]", tags.join(", ")) };
                            println!("{name:<16}  {}  {addr}{tag_str}", hex::encode(node_id));
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

        Commands::Fleet { command } => {
            let path = devices_path(&data_dir);
            match command {
                FleetCommands::Tag { name, tags } => {
                    let mut devices = Devices::load_or_empty(&path);
                    devices.add_tags(&name, &tags)?;
                    devices.save(&path)?;
                    println!("Tagged '{name}' with [{}].", tags.join(", "));
                }
                FleetCommands::Untag { name, tags } => {
                    let mut devices = Devices::load_or_empty(&path);
                    devices.remove_tags(&name, &tags)?;
                    devices.save(&path)?;
                    println!("Removed [{}] from '{name}'.", tags.join(", "));
                }
                FleetCommands::Ls { select, api_port } => {
                    let devices = Devices::load_or_empty(&path);
                    let entries = devices.entries();
                    if entries.is_empty() {
                        println!("No devices registered. Use `ce devices add <name>`.");
                        return Ok(());
                    }

                    // Best-effort: read live capability self-tags from the local node's atlas.
                    // node_id (hex) -> self-tags. Empty if the node is not running.
                    let mut self_tags: std::collections::HashMap<String, Vec<String>> =
                        std::collections::HashMap::new();
                    let url = format!("http://127.0.0.1:{api_port}/atlas");
                    match reqwest::Client::new().get(&url).send().await {
                        Ok(resp) if resp.status().is_success() => {
                            if let Ok(atlas) = resp.json::<serde_json::Value>().await {
                                for e in atlas.as_array().map(|v| v.as_slice()).unwrap_or(&[]) {
                                    if let Some(id) = e["node_id"].as_str() {
                                        let tags = e["tags"]
                                            .as_array()
                                            .map(|a| {
                                                a.iter()
                                                    .filter_map(|t| t.as_str().map(String::from))
                                                    .collect()
                                            })
                                            .unwrap_or_default();
                                        self_tags.insert(id.to_string(), tags);
                                    }
                                }
                            }
                        }
                        _ => {
                            eprintln!(
                                "note: local node not reachable on :{api_port} — showing owner tags only \
                                 (capability self-tags need a running `ce start`)."
                            );
                        }
                    }

                    println!("{:<16}  {:<16}  {:<24}  capabilities", "NAME", "NODE", "OWNER TAGS");
                    for (name, node_id, _addr, owner_tags) in &entries {
                        let id_hex = hex::encode(node_id);
                        let caps = self_tags.get(&id_hex).cloned().unwrap_or_default();

                        // --select matches either an owner tag or a capability self-tag.
                        if let Some(sel) = &select {
                            let hit = owner_tags.iter().any(|t| t == sel) || caps.iter().any(|t| t == sel);
                            if !hit {
                                continue;
                            }
                        }

                        let owners = if owner_tags.is_empty() { "-".into() } else { owner_tags.join(", ") };
                        let cap_str = if caps.is_empty() { "-".into() } else { caps.join(", ") };
                        println!("{name:<16}  {:<16}  {owners:<24}  {cap_str}", &id_hex[..16]);
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
