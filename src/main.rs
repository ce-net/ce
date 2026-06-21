use anyhow::{anyhow, Result};
use ce_chain::{Chain, CREDIT};
use ce_identity::Identity;
use ce_cap::{self as capability, Caveats, Resource, SignedCapability};
use ce_node::{Node, NodeConfig};
use serde::{Deserialize, Serialize};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

mod keybackup;

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
        /// Address the HTTP API binds to. Default 127.0.0.1 (loopback only). Use 0.0.0.0 to expose
        /// on all interfaces — only safe behind a firewall; the api.token still gates write ops.
        #[arg(long, default_value = "127.0.0.1")]
        api_bind: String,
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
        /// Serve the HTTP API over TLS (cert keyed by this node's identity; clients pin the NodeId).
        #[arg(long)]
        tls: bool,
        /// Advertise this node as a relay charging this many base units per minute (0 = free,
        /// discoverable relay). Omit to not advertise as a relay. Clients open a payment channel
        /// and stream receipts to stay paid-up.
        #[arg(long)]
        relay_price_per_min: Option<u128>,
        /// Ephemeral / in-memory chain: keep the chain in RAM and skip per-block disk persistence.
        /// Still syncs and gossips with normal nodes; snapshot to disk on demand with POST
        /// /chain/save. Useful for throwaway / test fleets (saves disk I/O).
        #[arg(long)]
        ephemeral: bool,
        /// Disable mDNS local peer discovery (isolate this node from others on the LAN). Use for
        /// isolated local test meshes so they can't cross-link with a live node.
        #[arg(long)]
        no_mdns: bool,
    },
    /// Show this node's credit balance.
    Balance,
    /// Show node status (id, chain height, difficulty, balance).
    Status,
    /// Print this node's ID.
    Id,
    /// Back up or restore this node's identity key (TTY-only; never over HTTP).
    ///
    /// Losing <data_dir>/identity/node.key permanently loses this node's funds and name. `ce key
    /// backup` writes a transcribable mnemonic and/or an encrypted keystore; `ce key restore`
    /// rebuilds node.key from either. These run only in an interactive terminal and never expose key
    /// material on the network — there is deliberately no HTTP /key route.
    Key {
        #[command(subcommand)]
        command: KeyCommands,
    },
    /// Manage your wallet: credits (money) and capabilities (authority).
    ///
    /// Credit half — money over the node HTTP API: `balance` (free/locked breakdown), `history`
    /// (itemized tx list), `send` (transfer credits), `watch` (live tx tail).
    /// Capability half — held authority tokens: `add`/`ls`/`rm` store capabilities others issued
    /// you, so `ce tunnel`/`ce deploy <alias>` auto-attach them. (Remote exec/sync are the `rdev`
    /// app, which has its own wallet.) See PLAN/06-token-management.md for the full split.
    Wallet {
        #[command(subcommand)]
        command: WalletCommands,
    },
    /// Manage off-chain payment channels (stream micropayments, settle on close).
    Channel {
        #[command(subcommand)]
        command: ChannelCommands,
    },
    /// Claim and resolve human-readable node names (on-chain, first claim wins).
    Name {
        #[command(subcommand)]
        command: NameCommands,
    },
    /// Advertise and discover named services across the mesh (DHT).
    Discover {
        #[command(subcommand)]
        command: DiscoverCommands,
    },
    /// Issue a capability token authorizing another principal (a node) on your resources.
    ///
    /// Self-issued: signed by THIS node's identity, so any node that accepts this node as a root
    /// (its own resources by default) honors it. Hand the printed token to the audience; they store
    /// it with `ce wallet add` (or the rdev app's wallet) and the relevant command attaches it.
    /// See docs/capabilities.md.
    ///
    /// Example: ce grant <node-id> --can exec,sync,tunnel --port 22 --expires 90d
    Grant {
        /// Audience node ID (64 hex chars) — the principal being authorized. Get it via `ce id`.
        subject: String,
        /// Abilities (comma-separated or repeatable): exec,sync,delete,tunnel,deploy,kill,status.
        #[arg(long = "can", required = true, value_delimiter = ',')]
        can: Vec<String>,
        /// Resource: `self` (this node, default), `any`/`*`, `tag=gpu`, `tag=gpu,linux`, or `node=<hex>`.
        #[arg(long, default_value = "self")]
        resource: String,
        /// Expiry as a duration from now (e.g. 7d, 24h, 30m, 3600s). Omit for no expiry.
        #[arg(long)]
        expires: Option<String>,
        /// Tunnel: allowed remote port (repeatable). Omit for any port.
        #[arg(long = "port")]
        ports: Vec<u16>,
        /// Sync/delete: confine writes to this path prefix (relative to the target's home).
        #[arg(long)]
        path: Option<String>,
        /// Max CPU cores a deploy under this capability may request.
        #[arg(long)]
        max_cpu: Option<u32>,
        /// Max memory (MB) a deploy under this capability may request.
        #[arg(long)]
        max_mem_mb: Option<u32>,
        /// Max credits the audience may spend under this capability.
        #[arg(long)]
        max_credits: Option<u64>,
    },
    /// Revoke a capability you issued, by its nonce (submits an on-chain RevokeCapability tx).
    Revoke {
        /// The nonce of a capability this node issued.
        nonce: u64,
        #[arg(long, default_value = "8844")]
        api_port: u16,
    },
    // Remote exec and file sync are apps now — see the `rdev` app (`rdev exec`, `rdev push`,
    // `rdev watch`). CE keeps only the transport/economy/capability primitives below.
    /// Forward a local TCP port to a remote port on a peer over the CE mesh (TCP-over-libp2p).
    ///
    /// Needs a `tunnel` capability for the target. The forward runs in your local node and stays up
    /// while `ce start` runs. Example: ce tunnel desktop 2222:22  then  ssh -p 2222 you@localhost
    Tunnel {
        /// Target: a wallet alias or a 64-hex node id.
        target: String,
        /// Port mapping `<local>:<remote>` (e.g. 2222:22).
        ports: String,
        /// Capability token override (else the wallet entry for the target is used).
        #[arg(long)]
        grant: Option<String>,
        /// Relay circuit multiaddr dial hint.
        #[arg(long)]
        hint: Option<String>,
        #[arg(long, default_value = "8844")]
        api_port: u16,
    },
    /// Deploy a cell (container job) on the local node.
    ///
    /// Example: ce deploy alpine:latest --fund 1000 --duration 300
    Deploy {
        /// Docker image to run.
        image: String,
        /// Place on a SPECIFIC remote device (by name) via the mesh, instead of broadcasting
        /// a local bid. Directed placement — what a scheduler uses.
        #[arg(long)]
        on: Option<String>,
        /// Credits to fund the job with (decimal allowed, e.g. 1000 or 1.5).
        #[arg(long, default_value = "1000")]
        fund: String,
        #[arg(long, default_value = "1")]
        cpu: u32,
        #[arg(long, default_value = "128")]
        mem: u64,
        #[arg(long, default_value = "300")]
        duration: u64,
        /// Command override for the container.
        #[arg(short, long)]
        cmd: Vec<String>,
        /// Scoped grant token (from `ce grant`) when deploying on a host you don't fully own.
        #[arg(long)]
        grant: Option<String>,
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
        /// Kill a job running on a SPECIFIC remote device (by name) via the mesh.
        #[arg(long)]
        on: Option<String>,
        /// Scoped grant token, if killing on a host you don't fully own.
        #[arg(long)]
        grant: Option<String>,
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
        /// Credits to transfer (decimal allowed, e.g. 500 or 0.25).
        amount: String,
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
enum WalletCommands {
    // ----- credit wallet (money: balance / history / send / live tail) -----
    //
    // These operate on this node's CREDITS via the local HTTP API (direct reqwest). They
    // are distinct from the capability-wallet subcommands below (`add`/`ls`/`rm`), which manage
    // signed authority tokens — see `ce wallet cap`-style docs and PLAN/06-token-management.md.
    /// Show this node's credit balance breakdown (total / free / locked-in-channels / locked-in-bond).
    Balance {
        #[arg(long, default_value = "8844")]
        api_port: u16,
    },
    /// Show itemized credit transaction history (newest first), paginated.
    ///
    /// Example: ce wallet history --limit 20
    History {
        /// Node id whose history to show (default: this node).
        #[arg(long)]
        node: Option<String>,
        /// Max items to show (node caps at 500).
        #[arg(long, default_value = "50")]
        limit: u32,
        /// Only show txs strictly below this block height (cursor for older pages).
        #[arg(long)]
        before: Option<u64>,
        #[arg(long, default_value = "8844")]
        api_port: u16,
    },
    /// Send credits to another node (alias of `ce fund`).
    ///
    /// Example: ce wallet send <node-id> 500
    Send {
        /// Recipient NodeId (64 hex chars).
        to: String,
        /// Credits to send (decimal allowed, e.g. 500 or 0.25).
        amount: String,
        #[arg(long, default_value = "8844")]
        api_port: u16,
    },
    /// Live-tail confirmed credit transactions touching this node (SSE; Ctrl-C to stop).
    Watch {
        #[arg(long, default_value = "8844")]
        api_port: u16,
    },

    // ----- capability wallet (authority: held capability tokens) -----
    /// Store (or replace) a capability you were issued, under a friendly alias.
    ///
    /// Example: ce wallet add desktop <desktop-node-id> --cap <token-from-ce-grant>
    Add {
        /// Friendly alias (e.g. "desktop", "laptop").
        alias: String,
        /// The target node's ID (64 hex chars) this capability applies to.
        node_id: String,
        /// The capability token printed by `ce grant` on the target.
        #[arg(long)]
        cap: String,
    },
    /// List wallet entries.
    Ls,
    /// Remove a wallet entry.
    Rm {
        /// Alias to remove.
        alias: String,
    },
}

#[derive(Subcommand)]
enum KeyCommands {
    /// Back up this node's identity key as a mnemonic and/or an encrypted keystore file.
    ///
    /// By default prints the CE mnemonic to the terminal (write it down OFFLINE). Add
    /// `--out <file>` to also write an encrypted keystore (you will be prompted for a passphrase).
    Backup {
        /// Print the 33-word CE mnemonic to the terminal (default true if no --out is given).
        #[arg(long)]
        mnemonic: bool,
        /// Also write an encrypted keystore JSON to this path (prompts for a passphrase).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Restore node.key from a mnemonic or an encrypted keystore file.
    ///
    /// Refuses to overwrite an existing node.key unless --force (it shows the current node id first
    /// so you don't silently destroy a funded identity).
    Restore {
        /// Restore from a 33-word CE mnemonic (you will be prompted to type it).
        #[arg(long)]
        mnemonic: bool,
        /// Restore from an encrypted keystore JSON written by `ce key backup --out`.
        #[arg(long, value_name = "FILE")]
        r#in: Option<PathBuf>,
        /// Overwrite an existing node.key (destroys the current identity — be sure).
        #[arg(long)]
        force: bool,
    },
    /// Print this node's id and a short fingerprint (verify a backup without exposing the secret).
    Fingerprint,
}

#[derive(Subcommand)]
enum NameCommands {
    /// Claim a unique name for this node (3-32 chars: a-z, 0-9, hyphen). Takes effect once mined.
    Claim {
        name: String,
        #[arg(long, default_value = "8844")]
        api_port: u16,
    },
    /// Resolve a name to its owner's NodeId.
    Resolve {
        name: String,
        #[arg(long, default_value = "8844")]
        api_port: u16,
    },
}

#[derive(Subcommand)]
enum DiscoverCommands {
    /// Advertise that this node provides a named service (re-run periodically; records expire).
    Advertise {
        service: String,
        #[arg(long, default_value = "8844")]
        api_port: u16,
    },
    /// Find the NodeIds advertising a named service.
    Find {
        service: String,
        #[arg(long, default_value = "8844")]
        api_port: u16,
    },
}

#[derive(Subcommand)]
enum ChannelCommands {
    /// Open a channel paying a host, locking `capacity` credits.
    ///
    /// Example: ce channel open <host-node-id> --capacity 1000
    Open {
        /// Host NodeId (64 hex) this channel pays.
        host: String,
        /// Credits to lock as the channel's capacity (decimal allowed).
        #[arg(long)]
        capacity: String,
        /// Block height after which the payer may reclaim. 0 = node default (~24h).
        #[arg(long, default_value = "0")]
        expiry_height: u64,
        #[arg(long, default_value = "8844")]
        api_port: u16,
    },
    /// List open channels.
    Ls {
        #[arg(long, default_value = "8844")]
        api_port: u16,
    },
    /// Sign an off-chain receipt for `cumulative` total paid; give the output to the host.
    Receipt {
        channel_id: String,
        /// Host NodeId (64 hex) the channel pays.
        #[arg(long)]
        host: String,
        /// Cumulative total paid so far over the channel (decimal credits).
        #[arg(long)]
        cumulative: String,
        #[arg(long, default_value = "8844")]
        api_port: u16,
    },
    /// Close a channel by redeeming a receipt (run on the host).
    Close {
        channel_id: String,
        #[arg(long)]
        cumulative: String,
        /// The payer's receipt signature (128 hex).
        #[arg(long)]
        sig: String,
        #[arg(long, default_value = "8844")]
        api_port: u16,
    },
    /// Reclaim a channel after its expiry (run as the payer).
    Expire {
        channel_id: String,
        #[arg(long, default_value = "8844")]
        api_port: u16,
    },
}

/// Format base units as a human credit string, trimming trailing fractional zeros.
/// 1 credit = `CREDIT` (10^18) base units.
fn format_credits(base: i128) -> String {
    let sign = if base < 0 { "-" } else { "" };
    let v = base.unsigned_abs();
    let whole = v / CREDIT;
    let frac = v % CREDIT;
    if frac == 0 {
        format!("{sign}{whole}")
    } else {
        let frac_str = format!("{frac:018}");
        format!("{sign}{whole}.{}", frac_str.trim_end_matches('0'))
    }
}

/// Parse a human credit string (e.g. "1000", "1.5", "0.000001") into base units.
/// Accepts up to 18 decimal places.
fn parse_credits(s: &str) -> Result<u128> {
    let s = s.trim();
    let (whole_str, frac_str) = s.split_once('.').unwrap_or((s, ""));
    if frac_str.len() > 18 {
        return Err(anyhow!("amount '{s}' has more than 18 decimal places"));
    }
    let whole: u128 = if whole_str.is_empty() {
        0
    } else {
        whole_str.parse().map_err(|_| anyhow!("invalid amount '{s}'"))?
    };
    // Right-pad the fractional part to 18 digits so "5" means 0.5, not 0.000…5.
    let frac: u128 = format!("{frac_str:0<18}").parse().map_err(|_| anyhow!("invalid amount '{s}'"))?;
    whole
        .checked_mul(CREDIT)
        .and_then(|w| w.checked_add(frac))
        .ok_or_else(|| anyhow!("amount '{s}' is too large"))
}

/// Parse a human duration into seconds: `7d`, `24h`, `30m`, `3600s`, or a bare number (seconds).
fn parse_duration_secs(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('d') => (&s[..s.len() - 1], 86_400),
        Some('h') => (&s[..s.len() - 1], 3_600),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('s') => (&s[..s.len() - 1], 1),
        _ => (s, 1),
    };
    let v: u64 = num
        .trim()
        .parse()
        .map_err(|_| anyhow!("bad duration '{s}' (use e.g. 7d, 24h, 30m, 3600s)"))?;
    Ok(v * mult)
}

fn data_dir(override_path: Option<PathBuf>) -> PathBuf {
    override_path.unwrap_or_else(|| {
        ProjectDirs::from("", "", "ce")
            .map(|d| d.data_dir().to_owned())
            .unwrap_or_else(|| PathBuf::from(".ce"))
    })
}

/// Read the node's API token from `<data_dir>/api.token` (written by the running node). Empty if
/// absent — read-only commands don't need it; write commands then get a 401 with guidance.
fn read_api_token(data_dir: &std::path::Path) -> String {
    std::fs::read_to_string(data_dir.join("api.token"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// A reqwest client that sends `Authorization: Bearer <token>` on every request, so mutating API
/// calls are accepted by the node's auth middleware. Read-only calls work with an empty token too.
fn api_client(token: &str) -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    if let Ok(v) = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")) {
        headers.insert(reqwest::header::AUTHORIZATION, v);
    }
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// Base URL of the local node's HTTP API. The credit-wallet CLI subtree
/// (`ce wallet balance|history|send|watch`) talks to it directly with [`api_client`].
fn api_base(api_port: u16) -> String {
    format!("http://127.0.0.1:{api_port}")
}

// ----- Capability wallet -----
//
// The wallet is a local, client-side keychain of capabilities this node has been issued, keyed by a
// friendly alias. It is NOT a trust store — holding a capability grants nothing on its own; the
// issuing node decides what it authorizes. `ce exec`/`ce sync <alias>` auto-attach the held token.

#[derive(Default, Serialize, Deserialize)]
struct Wallet {
    #[serde(default)]
    entries: std::collections::BTreeMap<String, WalletEntry>,
}

#[derive(Clone, Serialize, Deserialize)]
struct WalletEntry {
    /// Target node id (64 hex) this capability applies to.
    node_id: String,
    /// The capability token (hex), as printed by `ce grant`.
    cap: String,
}

fn wallet_path(data_dir: &PathBuf) -> PathBuf {
    data_dir.join("wallet.toml")
}

fn load_wallet(data_dir: &PathBuf) -> Wallet {
    match std::fs::read_to_string(wallet_path(data_dir)) {
        Ok(s) => toml::from_str(&s).unwrap_or_default(),
        Err(_) => Wallet::default(),
    }
}

fn save_wallet(data_dir: &PathBuf, w: &Wallet) -> Result<()> {
    std::fs::write(wallet_path(data_dir), toml::to_string_pretty(w)?)?;
    Ok(())
}

/// Resolve a target (a 64-hex node id, or a wallet alias) to (node_id_hex, capability token).
/// A raw node id resolves with no token (you must pass `--cap` or hold it some other way).
fn resolve_target(data_dir: &PathBuf, target: &str) -> Result<(String, Option<String>)> {
    if target.len() == 64 && target.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok((target.to_string(), None));
    }
    let wallet = load_wallet(data_dir);
    match wallet.entries.get(target) {
        Some(e) => Ok((e.node_id.clone(), Some(e.cap.clone()))),
        None => Err(anyhow!(
            "unknown target '{target}': not a 64-hex node id and not a wallet alias (see `ce wallet ls`)"
        )),
    }
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
    // API token the running node wrote to <data_dir>/api.token; attached to every API call so
    // mutating requests pass the node's auth middleware. Empty if the node hasn't run yet.
    let api_token = read_api_token(&data_dir);

    match cli.command {
        Commands::Start { port, api_port, api_bind, bootstrap, relay, no_mine, light, tls, relay_price_per_min, ephemeral, no_mdns } => {
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
                    // The ce-net.com bootstrap peers are public relays. Unless relays were given
                    // explicitly, register them as relays too: a node behind NAT then reserves a
                    // circuit and becomes reachable from `ce start` alone — no `--relay` needed.
                    // (A publicly-reachable node just logs a harmless self-dial warning.)
                    if relay_peers.is_empty() {
                        relay_peers.extend(auto.iter().cloned());
                    }
                    bootstrap_peers.extend(auto);
                }
            }

            let config = NodeConfig {
                listen_port: port,
                bootstrap_peers,
                relay_peers,
                data_dir,
                api_port,
                api_bind,
                mine: !no_mine,
                prune_keep: if light { Some(ce_chain::PRUNE_KEEP_BLOCKS) } else { None },
                tls,
                relay_price_per_min,
                ephemeral,
                disable_local_discovery: no_mdns,
                ..Default::default()
            };
            let node = Node::start(config).await?;
            let status = node.status().await;
            println!("CE node running");
            println!("  node id  : {}", status.node_id);
            println!("  peer id  : {}", status.peer_id);
            println!("  height   : {}", status.height);
            println!("  balance  : {} credits", format_credits(status.balance));
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
            println!("{} credits", format_credits(chain.balance(&identity.node_id())));
        }

        Commands::Status => {
            let identity_dir = data_dir.join("identity");
            let chain_path = data_dir.join("chain").join("chain.json");
            let identity = Identity::load_or_generate(&identity_dir)?;
            let chain = Chain::load_or_genesis(&chain_path);
            println!("node id   : {}", identity.node_id_hex());
            println!("height    : {}", chain.height());
            println!("difficulty: {}", chain.difficulty);
            println!("balance   : {} credits", format_credits(chain.balance(&identity.node_id())));
        }

        Commands::Id => {
            let identity_dir = data_dir.join("identity");
            let identity = Identity::load_or_generate(&identity_dir)?;
            println!("ce node id : {}", identity.node_id_hex());
            let peer_id = ce_node::peer_id_from_identity(&identity)?;
            println!("libp2p id  : {peer_id}");
        }

        Commands::Key { command } => {
            let identity_dir = data_dir.join("identity");
            match command {
                KeyCommands::Backup { mnemonic, out } => {
                    keybackup::require_tty()?;
                    keybackup::print_banner("BACKUP");
                    // Load the existing identity (or generate one if this is a fresh node).
                    let identity = Identity::load_or_generate(&identity_dir)?;
                    let seed = identity.secret_bytes();
                    let node_id_hex = identity.node_id_hex();
                    println!("node id : {node_id_hex}");

                    // Default to printing the mnemonic when no keystore output was requested.
                    let want_mnemonic = mnemonic || out.is_none();
                    if want_mnemonic {
                        if !keybackup::confirm(
                            "Display the secret mnemonic on this terminal now?",
                        )? {
                            println!("Aborted — no mnemonic shown.");
                        } else {
                            let phrase = keybackup::seed_to_mnemonic(&seed);
                            println!();
                            println!("--- BEGIN CE MNEMONIC (33 words — write down OFFLINE) ---");
                            println!("{phrase}");
                            println!("--- END CE MNEMONIC ---");
                            println!();
                            println!(
                                "Note: this is a CE-specific mnemonic — it re-imports only into \
                                 `ce key restore`, not other wallets."
                            );
                        }
                    }

                    if let Some(path) = out {
                        let pass = keybackup::prompt_passphrase("Choose a keystore passphrase")?;
                        let confirm = keybackup::prompt_passphrase("Confirm passphrase")?;
                        if pass != confirm {
                            return Err(anyhow!("passphrases do not match — aborting"));
                        }
                        let ks = keybackup::encrypt_keystore(&seed, &node_id_hex, &pass)?;
                        let json = serde_json::to_string_pretty(&ks)?;
                        std::fs::write(&path, json)?;
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
                        }
                        println!("Encrypted keystore written to {}", path.display());
                    }
                }

                KeyCommands::Restore { mnemonic, r#in, force } => {
                    keybackup::require_tty()?;
                    keybackup::print_banner("RESTORE");
                    // Warn loudly if we are about to clobber a funded identity.
                    let key_path = identity_dir.join("node.key");
                    if key_path.exists() {
                        let current = Identity::load_or_generate(&identity_dir)?;
                        println!("current node id : {}", current.node_id_hex());
                        if !force {
                            return Err(anyhow!(
                                "{} already exists — re-run with --force to overwrite the current \
                                 identity (this destroys it)",
                                key_path.display()
                            ));
                        }
                        if !keybackup::confirm(
                            "OVERWRITE the current identity above? This is irreversible.",
                        )? {
                            println!("Aborted — identity unchanged.");
                            return Ok(());
                        }
                    }

                    let seed = if let Some(path) = r#in {
                        let json = std::fs::read_to_string(&path)?;
                        let ks: keybackup::Keystore = serde_json::from_str(&json)
                            .map_err(|_| anyhow!("not a valid CE keystore file"))?;
                        println!("keystore node id : {}", ks.node_id);
                        let pass = keybackup::prompt_passphrase("Keystore passphrase")?;
                        keybackup::decrypt_keystore(&ks, &pass)?
                    } else if mnemonic {
                        let phrase = keybackup::prompt_passphrase(
                            "Type the 33-word CE mnemonic (space-separated)",
                        )?;
                        keybackup::mnemonic_to_seed(&phrase)?
                    } else {
                        return Err(anyhow!(
                            "specify a source: --mnemonic or --in <keystore-file>"
                        ));
                    };

                    keybackup::write_node_key(&identity_dir, &seed, force)?;
                    let restored = Identity::load_or_generate(&identity_dir)?;
                    println!("Restored identity. node id : {}", restored.node_id_hex());
                }

                KeyCommands::Fingerprint => {
                    let identity = Identity::load_or_generate(&identity_dir)?;
                    let id_hex = identity.node_id_hex();
                    println!("node id     : {id_hex}");
                    // Short fingerprint: first 4 / last 4 of the node id, for at-a-glance verification.
                    println!("fingerprint : {}…{}", &id_hex[..8], &id_hex[id_hex.len() - 8..]);
                }
            }
        }

        Commands::Wallet { command } => match command {
            // ----- credit wallet -----
            WalletCommands::Balance { api_port } => {
                // GET /status → total/free/locked_channels/locked_bond/bond, all decimal base-unit
                // strings. Parse with parse_credits (string of base units → base units).
                let client = api_client(&api_token);
                let resp = client
                    .get(format!("{}/status", api_base(api_port)))
                    .send()
                    .await
                    .map_err(|e| anyhow!("could not read balance (is `ce start` running?): {e}"))?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let text = resp.text().await.unwrap_or_default();
                    return Err(anyhow!("could not read balance ({status}): {text}"));
                }
                let s: serde_json::Value = resp.json().await?;
                let base_field = |key: &str| -> i128 {
                    s[key].as_str().and_then(|v| v.parse::<i128>().ok()).unwrap_or(0)
                };
                let total = base_field("balance");
                let locked_channels = base_field("locked_channels");
                let locked_bond = base_field("locked_bond");
                let bond = base_field("bond");
                // `free` may be absent on older nodes; derive a spendable estimate then.
                let free = s["free"]
                    .as_str()
                    .and_then(|v| v.parse::<i128>().ok())
                    .unwrap_or_else(|| (total - locked_channels - locked_bond).max(0));
                println!("total  : {} credits", format_credits(total));
                println!("free   : {} credits", format_credits(free));
                println!(
                    "locked : {} credits  (channels {} · bond {})",
                    format_credits(locked_channels + locked_bond),
                    format_credits(locked_channels),
                    format_credits(locked_bond),
                );
                println!("bond   : {} credits", format_credits(bond));
            }
            WalletCommands::History { node, limit, before, api_port } => {
                // Default to this node's own id (loaded locally — no API round-trip needed).
                let node_id = match node {
                    Some(n) => n,
                    None => {
                        let identity = Identity::load_or_generate(&data_dir.join("identity"))?;
                        identity.node_id_hex()
                    }
                };
                // GET /transactions/:node_id?limit=&before= → array of { height, kind, amount,
                // counterparty, direction }; amount is a decimal base-unit string.
                let mut url = format!("{}/transactions/{node_id}?limit={limit}", api_base(api_port));
                if let Some(b) = before {
                    url.push_str(&format!("&before={b}"));
                }
                let client = api_client(&api_token);
                let resp = client
                    .get(&url)
                    .send()
                    .await
                    .map_err(|e| anyhow!("could not read history (is `ce start` running?): {e}"))?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let text = resp.text().await.unwrap_or_default();
                    return Err(anyhow!("could not read history ({status}): {text}"));
                }
                let txs: Vec<serde_json::Value> = resp.json().await?;
                if txs.is_empty() {
                    println!("No transactions found for {}.", &node_id[..node_id.len().min(16)]);
                } else {
                    println!("{:>8}  {:<14}  {:<4}  {:>16}  counterparty", "HEIGHT", "KIND", "DIR", "AMOUNT");
                    for t in &txs {
                        let height = t["height"].as_u64().unwrap_or(0);
                        let kind = t["kind"].as_str().unwrap_or("?");
                        let dir = t["direction"].as_str().unwrap_or("self");
                        let cp = t["counterparty"]
                            .as_str()
                            .map(|c| c[..c.len().min(16)].to_string())
                            .unwrap_or_else(|| "—".to_string());
                        let amount = t["amount"].as_str().and_then(|v| v.parse::<i128>().ok()).unwrap_or(0);
                        let amt = if amount == 0 {
                            "—".to_string()
                        } else {
                            format_credits(amount)
                        };
                        println!("{height:>8}  {kind:<14}  {dir:<4}  {amt:>16}  {cp}");
                    }
                    // Pagination hint: oldest height returned is the cursor for the next page.
                    if let Some(oldest) = txs.last().filter(|_| txs.len() as u32 >= limit) {
                        let oldest_height = oldest["height"].as_u64().unwrap_or(0);
                        println!(
                            "\nLoad older: ce wallet history --node {node_id} --before {oldest_height} --limit {limit}"
                        );
                    }
                }
            }
            WalletCommands::Send { to, amount, api_port } => {
                if to.len() != 64 || !to.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(anyhow!("recipient node id must be 64 hex chars"));
                }
                // POST /transfer { to, amount } — amount is a decimal base-unit string. Returns tx_id.
                let amount_base = parse_credits(&amount)?.to_string();
                let body = serde_json::json!({ "to": to, "amount": amount_base });
                let client = api_client(&api_token);
                let resp = client
                    .post(format!("{}/transfer", api_base(api_port)))
                    .json(&body)
                    .send()
                    .await
                    .map_err(|e| anyhow!("transfer failed: {e}"))?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let text = resp.text().await.unwrap_or_default();
                    return Err(anyhow!("transfer failed ({status}): {text}"));
                }
                let result: serde_json::Value = resp.json().await?;
                println!("Sent {amount} credits to {}.", &to[..16]);
                println!("tx_id: {}", result["tx_id"].as_str().unwrap_or("?"));
            }
            WalletCommands::Watch { api_port } => {
                use futures_util::StreamExt;
                let identity = Identity::load_or_generate(&data_dir.join("identity"))?;
                let self_id = identity.node_id_hex();
                // GET /transactions/stream is a Server-Sent Events stream of { id, origin, kind,
                // amount } frames (amount is a decimal base-unit string). We enrich each frame to a
                // wallet-relative view client-side: a tx whose `origin` is us is outbound (no
                // counterparty shown), otherwise inbound from `origin`.
                let client = api_client(&api_token);
                let resp = client
                    .get(format!("{}/transactions/stream", api_base(api_port)))
                    .send()
                    .await
                    .map_err(|e| anyhow!("could not open tx stream (is `ce start` running?): {e}"))?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let text = resp.text().await.unwrap_or_default();
                    return Err(anyhow!("could not open tx stream ({status}): {text}"));
                }
                println!("Watching credit transactions for {} … (Ctrl-C to stop)", &self_id[..16]);
                println!("{:<14}  {:<4}  {:>16}  counterparty", "KIND", "DIR", "AMOUNT");
                // Minimal SSE parser: accumulate bytes, split on lines, handle `data: <json>` frames.
                let mut stream = resp.bytes_stream();
                let mut buf = String::new();
                while let Some(chunk) = stream.next().await {
                    let chunk = match chunk {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("stream error: {e}");
                            break;
                        }
                    };
                    buf.push_str(&String::from_utf8_lossy(&chunk));
                    // Process every complete line; keep the trailing partial line in `buf`.
                    while let Some(nl) = buf.find('\n') {
                        let line = buf[..nl].trim_end_matches('\r').to_string();
                        buf.drain(..=nl);
                        let payload = match line.strip_prefix("data:") {
                            Some(p) => p.trim(),
                            None => continue, // ignore comments, `event:`, keep-alives, blank lines
                        };
                        let ev: serde_json::Value = match serde_json::from_str(payload) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };
                        let origin = ev["origin"].as_str().unwrap_or("");
                        let kind = ev["kind"].as_str().unwrap_or("?");
                        let (dir, cp) = if origin == self_id {
                            ("out", "—".to_string())
                        } else {
                            ("in", origin[..origin.len().min(16)].to_string())
                        };
                        let amount = ev["amount"].as_str().and_then(|v| v.parse::<i128>().ok()).unwrap_or(0);
                        let amt = if amount == 0 {
                            "—".to_string()
                        } else {
                            format_credits(amount)
                        };
                        println!("{kind:<14}  {dir:<4}  {amt:>16}  {cp}");
                    }
                }
            }

            // ----- capability wallet -----
            WalletCommands::Add { alias, node_id, cap } => {
                if node_id.len() != 64 || !node_id.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(anyhow!("node_id must be 64 hex chars"));
                }
                capability::decode_chain(&cap).map_err(|_| anyhow!("invalid capability token"))?;
                let mut w = load_wallet(&data_dir);
                w.entries.insert(alias.clone(), WalletEntry { node_id, cap });
                save_wallet(&data_dir, &w)?;
                println!("Added wallet entry '{alias}'.");
            }
            WalletCommands::Ls => {
                let w = load_wallet(&data_dir);
                if w.entries.is_empty() {
                    println!("Wallet is empty. Add one with `ce wallet add <alias> <node-id> --cap <token>`.");
                } else {
                    for (alias, e) in &w.entries {
                        println!("{alias:<16}  {}", &e.node_id[..e.node_id.len().min(16)]);
                    }
                }
            }
            WalletCommands::Rm { alias } => {
                let mut w = load_wallet(&data_dir);
                if w.entries.remove(&alias).is_some() {
                    save_wallet(&data_dir, &w)?;
                    println!("Removed '{alias}'.");
                } else {
                    println!("No such wallet entry '{alias}'.");
                }
            }
        },

        Commands::Channel { command } => {
            let client = api_client(&api_token);
            match command {
                ChannelCommands::Open { host, capacity, expiry_height, api_port } => {
                    let cap = parse_credits(&capacity)?.to_string();
                    let body = serde_json::json!({ "host": host, "capacity": cap, "expiry_height": expiry_height });
                    let resp = client.post(format!("http://127.0.0.1:{api_port}/channels/open")).json(&body).send().await?;
                    if !resp.status().is_success() {
                        let s = resp.status();
                        return Err(anyhow!("open failed ({s}): {}", resp.text().await.unwrap_or_default()));
                    }
                    let v: serde_json::Value = resp.json().await?;
                    println!("channel_id: {}", v["channel_id"].as_str().unwrap_or("?"));
                }
                ChannelCommands::Ls { api_port } => {
                    let resp = client.get(format!("http://127.0.0.1:{api_port}/channels")).send().await?;
                    let chans: serde_json::Value = resp.json().await?;
                    let chans = chans.as_array().map(|v| v.as_slice()).unwrap_or(&[]);
                    if chans.is_empty() {
                        println!("No open channels.");
                    } else {
                        println!("{:<66}  {:<16}  {:<16}  {:>12}  expiry", "CHANNEL", "PAYER", "HOST", "CAPACITY");
                        for c in chans {
                            let cap = c["capacity"].as_str().and_then(|s| s.parse::<u128>().ok()).map(|b| format_credits(b as i128)).unwrap_or_else(|| "?".into());
                            println!(
                                "{:<66}  {:<16}  {:<16}  {cap:>12}  {}",
                                c["channel_id"].as_str().unwrap_or("?"),
                                &c["payer"].as_str().unwrap_or("?")[..16.min(c["payer"].as_str().unwrap_or("?").len())],
                                &c["host"].as_str().unwrap_or("?")[..16.min(c["host"].as_str().unwrap_or("?").len())],
                                c["expiry_height"].as_u64().unwrap_or(0),
                            );
                        }
                    }
                }
                ChannelCommands::Receipt { channel_id, host, cumulative, api_port } => {
                    let cum = parse_credits(&cumulative)?.to_string();
                    let body = serde_json::json!({ "channel_id": channel_id, "host": host, "cumulative": cum });
                    let resp = client.post(format!("http://127.0.0.1:{api_port}/channels/receipt")).json(&body).send().await?;
                    if !resp.status().is_success() {
                        let s = resp.status();
                        return Err(anyhow!("receipt failed ({s}): {}", resp.text().await.unwrap_or_default()));
                    }
                    let v: serde_json::Value = resp.json().await?;
                    // Print what the host needs to redeem this receipt.
                    println!("cumulative: {cumulative}");
                    println!("sig:        {}", v["payer_sig"].as_str().unwrap_or("?"));
                    println!("\nGive these to the host: ce channel close {channel_id} --cumulative {cumulative} --sig <sig>");
                }
                ChannelCommands::Close { channel_id, cumulative, sig, api_port } => {
                    let cum = parse_credits(&cumulative)?.to_string();
                    let body = serde_json::json!({ "cumulative": cum, "payer_sig": sig });
                    let resp = client.post(format!("http://127.0.0.1:{api_port}/channels/{channel_id}/close")).json(&body).send().await?;
                    if !resp.status().is_success() {
                        let s = resp.status();
                        return Err(anyhow!("close failed ({s}): {}", resp.text().await.unwrap_or_default()));
                    }
                    println!("Channel {channel_id} close submitted.");
                }
                ChannelCommands::Expire { channel_id, api_port } => {
                    let resp = client.post(format!("http://127.0.0.1:{api_port}/channels/{channel_id}/expire")).send().await?;
                    if !resp.status().is_success() {
                        let s = resp.status();
                        return Err(anyhow!("expire failed ({s}): {}", resp.text().await.unwrap_or_default()));
                    }
                    println!("Channel {channel_id} expire submitted.");
                }
            }
        }

        Commands::Name { command } => {
            let client = api_client(&api_token);
            match command {
                NameCommands::Claim { name, api_port } => {
                    let body = serde_json::json!({ "name": name });
                    let resp = client.post(format!("http://127.0.0.1:{api_port}/names/claim")).json(&body).send().await?;
                    if !resp.status().is_success() {
                        let s = resp.status();
                        return Err(anyhow!("claim failed ({s}): {}", resp.text().await.unwrap_or_default()));
                    }
                    println!("Name '{name}' claim submitted — resolves once mined.");
                }
                NameCommands::Resolve { name, api_port } => {
                    let resp = client.get(format!("http://127.0.0.1:{api_port}/names/{name}")).send().await?;
                    if resp.status().as_u16() == 404 {
                        println!("'{name}' is not claimed.");
                    } else if resp.status().is_success() {
                        let v: serde_json::Value = resp.json().await?;
                        println!("{}", v["node_id"].as_str().unwrap_or("?"));
                    } else {
                        let s = resp.status();
                        return Err(anyhow!("resolve failed ({s}): {}", resp.text().await.unwrap_or_default()));
                    }
                }
            }
        }

        Commands::Discover { command } => {
            let client = api_client(&api_token);
            match command {
                DiscoverCommands::Advertise { service, api_port } => {
                    let body = serde_json::json!({ "service": service });
                    let resp = client.post(format!("http://127.0.0.1:{api_port}/discovery/advertise")).json(&body).send().await?;
                    if !resp.status().is_success() {
                        let s = resp.status();
                        return Err(anyhow!("advertise failed ({s}): {}", resp.text().await.unwrap_or_default()));
                    }
                    println!("Advertising service '{service}'.");
                }
                DiscoverCommands::Find { service, api_port } => {
                    let resp = client.get(format!("http://127.0.0.1:{api_port}/discovery/find/{service}")).send().await?;
                    if !resp.status().is_success() {
                        let s = resp.status();
                        return Err(anyhow!("find failed ({s}): {}", resp.text().await.unwrap_or_default()));
                    }
                    let v: serde_json::Value = resp.json().await?;
                    let providers = v["providers"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);
                    if providers.is_empty() {
                        println!("No providers found for '{service}'.");
                    } else {
                        for p in providers {
                            println!("{}", p.as_str().unwrap_or("?"));
                        }
                    }
                }
            }
        }

        Commands::Grant { subject, can, resource, expires, ports, path, max_cpu, max_mem_mb, max_credits } => {
            let bytes = hex::decode(&subject).map_err(|_| anyhow!("subject must be 64 hex chars"))?;
            let audience: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow!("subject must be exactly 32 bytes (64 hex chars)"))?;

            let abilities: Vec<String> = can.iter().map(|a| a.trim().to_ascii_lowercase()).collect();
            let identity = Identity::load_or_generate(&data_dir.join("identity"))?;

            // Resolve the resource matcher: `self` = this node, `any`/`*` = Any, `node=<hex>`, else tags.
            let res = match resource.as_str() {
                "self" => Resource::Node(identity.node_id()),
                "*" | "any" => Resource::Any,
                s if s.starts_with("node=") => {
                    let b = hex::decode(&s[5..]).map_err(|_| anyhow!("node= must be 64 hex chars"))?;
                    let id: [u8; 32] = b.try_into().map_err(|_| anyhow!("node= must be 32 bytes"))?;
                    Resource::Node(id)
                }
                s => {
                    let body = s.strip_prefix("tag=").unwrap_or(s);
                    let parts: Vec<String> =
                        body.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect();
                    match parts.len() {
                        0 => Resource::Any,
                        1 => Resource::Tag(parts.into_iter().next().unwrap()),
                        _ => Resource::AllOf(parts),
                    }
                }
            };

            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
            let not_after = match &expires {
                Some(d) => now + parse_duration_secs(d)?,
                None => {
                    eprintln!("warning: capability has no --expires; it never expires (revoke with `ce revoke <nonce>`)");
                    0
                }
            };
            let caveats = Caveats {
                not_before: 0,
                not_after,
                max_cpu,
                max_mem_mb,
                max_credits,
                allowed_ports: if ports.is_empty() { None } else { Some(ports) },
                path_prefix: path,
            };
            // Nonce names this capability for revocation; current time is unique enough per issuer.
            let nonce = now;
            let cap = SignedCapability::issue(&identity, audience, abilities, res, caveats, nonce, None);
            let token = capability::encode_chain(&[cap]);

            eprintln!("Capability issued by {}", identity.node_id_hex());
            eprintln!("  audience: {subject}");
            eprintln!("  can:      {}", can.join(", "));
            eprintln!("  resource: {resource}");
            eprintln!("  nonce:    {nonce}  (revoke with: ce revoke {nonce})");
            eprintln!(
                "  expires:  {}",
                if not_after == 0 { "never".to_string() } else { format!("{not_after} (unix seconds)") }
            );
            eprintln!("\nToken (give to the audience; they run: ce wallet add <alias> {subject} --cap <token>):");
            println!("{token}");
        }
        Commands::Revoke { nonce, api_port } => {
            let url = format!("http://127.0.0.1:{api_port}/capabilities/revoke");
            let client = api_client(&api_token);
            let resp = client.post(&url).json(&serde_json::json!({ "nonce": nonce })).send().await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(anyhow!("revoke failed ({status}): {text}"));
            }
            let v: serde_json::Value = resp.json().await?;
            println!("revoked nonce {nonce} (tx {})", v["tx_id"].as_str().unwrap_or("?"));
        }

        Commands::Tunnel { target, ports, grant, hint, api_port } => {
            let (local, remote) = ports
                .split_once(':')
                .ok_or_else(|| anyhow!("ports must be <local>:<remote>, e.g. 2222:22"))?;
            let local: u16 = local.parse().map_err(|_| anyhow!("bad local port"))?;
            let remote: u16 = remote.parse().map_err(|_| anyhow!("bad remote port"))?;

            let (node_id_hex, wallet_cap) = resolve_target(&data_dir, &target)?;
            let cap = grant.or(wallet_cap);

            let url = format!("http://127.0.0.1:{api_port}/tunnel");
            let body = serde_json::json!({
                "node_id": node_id_hex,
                "local_port": local,
                "remote_port": remote,
                "caps": cap,
                "hint": hint,
            });
            let client = api_client(&api_token);
            let resp = client.post(&url).json(&body).send().await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(anyhow!("tunnel failed ({status}): {text}"));
            }
            println!(
                "Tunnel up: localhost:{local} -> {target}:{remote} over CE.\n\
                 It runs inside your local node (keep `ce start` running). e.g. ssh -p {local} <user>@localhost"
            );
        }

        Commands::Deploy { image, on, fund, cpu, mem, duration, cmd, grant, api_port } => {
            // Amounts cross JSON as decimal strings of base units (precision-safe).
            let bid_base = parse_credits(&fund)?.to_string();
            let client = api_client(&api_token);

            let (url, body) = match &on {
                // Directed placement: route through the local node's mesh proxy to a specific host.
                Some(device) => {
                    let (node_id_hex, wallet_cap) = resolve_target(&data_dir, device)?;
                    let cap = grant.clone().or(wallet_cap);
                    (
                        format!("http://127.0.0.1:{api_port}/mesh-deploy"),
                        serde_json::json!({
                            "node_id": node_id_hex,
                            "image": image,
                            "cmd": cmd,
                            "cpu_cores": cpu,
                            "mem_mb": mem,
                            "duration_secs": duration,
                            "bid": bid_base,
                            "grant": cap,
                        }),
                    )
                }
                // Open placement: broadcast a local bid; whoever has capacity accepts.
                None => (
                    format!("http://127.0.0.1:{api_port}/jobs/bid"),
                    serde_json::json!({
                        "image": image,
                        "cmd": cmd,
                        "cpu_cores": cpu,
                        "mem_mb": mem,
                        "duration_secs": duration,
                        "bid": bid_base,
                    }),
                ),
            };

            let resp = client.post(&url).json(&body).send().await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(anyhow!("deploy failed ({status}): {text}"));
            }
            let result: serde_json::Value = resp.json().await?;
            let job_id = result["job_id"].as_str().unwrap_or("?");
            match &on {
                Some(device) => println!("job_id: {job_id}  (deployed on {device})"),
                None => println!("job_id: {job_id}"),
            }
        }

        Commands::Ps { api_port } => {
            let url = format!("http://127.0.0.1:{api_port}/jobs");
            let client = api_client(&api_token);
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
                println!("{:<66}  {:<22}  {:<12}  payer", "JOB ID", "STATUS", "BID");
                for job in jobs {
                    let id     = job["job_id"].as_str().unwrap_or("?");
                    let status = job["status"].as_str().unwrap_or("?");
                    // bid arrives as a decimal string of base units; show it in credits.
                    let bid = job["bid"]
                        .as_str()
                        .and_then(|s| s.parse::<u128>().ok())
                        .map(|b| format_credits(b as i128))
                        .unwrap_or_else(|| "?".into());
                    let payer  = job["payer"].as_str().unwrap_or("?");
                    println!("{id:<66}  {status:<22}  {bid:<12}  {payer}");
                }
            }
        }

        Commands::Kill { job_id, on, grant, api_port } => {
            let client = api_client(&api_token);
            let resp = match &on {
                // Directed: route through the local mesh proxy to a specific host.
                Some(device) => {
                    let (node_id_hex, wallet_cap) = resolve_target(&data_dir, device)?;
                    let cap = grant.clone().or(wallet_cap);
                    let body = serde_json::json!({
                        "node_id": node_id_hex,
                        "job_id": job_id,
                        "grant": cap,
                    });
                    client.post(format!("http://127.0.0.1:{api_port}/mesh-kill")).json(&body).send().await?
                }
                // Local job.
                None => {
                    client.delete(format!("http://127.0.0.1:{api_port}/jobs/{job_id}")).send().await?
                }
            };
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
            let amount_base = parse_credits(&amount)?.to_string();
            let body = serde_json::json!({ "to": to, "amount": amount_base });
            let client = api_client(&api_token);
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
            let client = api_client(&api_token);
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

#[cfg(test)]
mod credit_tests {
    use super::{format_credits, parse_credits};
    use ce_chain::CREDIT;

    #[test]
    fn parse_whole_and_fractional_credits() {
        assert_eq!(parse_credits("1000").unwrap(), 1_000 * CREDIT);
        assert_eq!(parse_credits("1").unwrap(), CREDIT);
        assert_eq!(parse_credits("0.5").unwrap(), CREDIT / 2);
        assert_eq!(parse_credits("1.5").unwrap(), CREDIT + CREDIT / 2);
        // 18 decimal places = smallest base unit.
        assert_eq!(parse_credits("0.000000000000000001").unwrap(), 1);
        assert_eq!(parse_credits(".25").unwrap(), CREDIT / 4);
    }

    #[test]
    fn parse_rejects_too_many_decimals() {
        assert!(parse_credits("0.0000000000000000001").is_err()); // 19 places
        assert!(parse_credits("abc").is_err());
    }

    #[test]
    fn format_trims_and_round_trips() {
        assert_eq!(format_credits((1_000 * CREDIT) as i128), "1000");
        assert_eq!(format_credits(CREDIT as i128), "1");
        assert_eq!(format_credits((CREDIT / 2) as i128), "0.5");
        assert_eq!(format_credits(1), "0.000000000000000001");
        assert_eq!(format_credits(-(CREDIT as i128)), "-1");
        assert_eq!(format_credits(0), "0");
    }

    #[test]
    fn round_trip_random_values() {
        for credits in ["0", "1", "42", "1000000", "0.123456789012345678", "21000000000"] {
            let base = parse_credits(credits).unwrap();
            assert_eq!(format_credits(base as i128), credits, "round-trip {credits}");
        }
    }
}
