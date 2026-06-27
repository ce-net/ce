//! `ce` — the single root binary every device runs to join the network.
//!
//! This is the CLI entry point and command surface for the whole system: one `clap` dispatcher over
//! `ce start` (run the node: mine, meter, mesh, HTTP API), plus `status`/`id`/`balance`, identity
//! `key` backup/restore, the `wallet` (credits + held capabilities), payment `channel`s, on-chain
//! `name` claims, mesh service `discover`, and `grant` (issue capability tokens). On launch it
//! auto-fetches bootstrap peers from ce-net.com so a node finds the mesh with zero configuration.
//! Everything a participant does — from owning an identity to spending credits to authorizing
//! others — flows through subcommands defined here.
//!
//! It is deliberately the ONLY root binary: apps (rdev, ce-expose, and the rest) build on the
//! primitives this node exposes rather than shipping their own daemons, so onboarding a machine is
//! one install of one program. That is the on-ramp at scale — for the supercomputer to be open and
//! participant-owned, joining has to be a single command anyone can run on a phone, laptop, or
//! server. Designed so that, across millions of heterogeneous devices, this same binary and the same
//! `ce start` is the universal front door into the pooled compute, economy, and mesh.

use anyhow::{anyhow, Context, Result};
use ce_chain::{Chain, CREDIT};
use ce_identity::Identity;
use ce_cap::{self as capability, Caveats, Resource, SignedCapability};
use ce_node::{Node, NodeConfig};
use serde::{Deserialize, Serialize};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use std::net::IpAddr;
use std::path::PathBuf;
use sha2::{Digest, Sha256};
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
#[command(name = "ce", about = "CE node", version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("CE_GIT_HASH"), ", ", env!("CE_BUILD_DATE"), ")"))]
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
    /// Update the `ce` binary in place to the latest GitHub release (self-update).
    ///
    /// Downloads the release asset for this platform, verifies it runs, and atomically replaces
    /// the running binary (using sudo only if its directory needs it). Run `ce update --restart`
    /// to also restart the background service afterwards.
    Update {
        /// Reinstall even if already on the latest version.
        #[arg(long)]
        force: bool,
        /// Restart the ce background service after updating (if one is installed).
        #[arg(long)]
        restart: bool,
    },
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
    /// Install, run, and supervise any app or system through `ce` — the only host binary.
    ///
    /// Apps (CE-native, arbitrary legacy software, or whole systems) are described by a
    /// `ceapp.toml` in the ce-hub registry and installed into the single ce-owned store.
    /// See PLAN/ce-app-package-runtime.md.
    App {
        #[command(subcommand)]
        command: AppCommands,
    },
}

/// `ce app ...` — the universal app & system manager.
#[derive(Subcommand)]
enum AppCommands {
    /// Resolve an app + its dependency graph and install it (records + launcher shim).
    ///
    /// Without `--yes` this is a dry run: it prints the resolved plan and required
    /// services/capabilities, and changes nothing. `--on` places the install on the
    /// mesh (default `self`); non-local placements ship to the target node's agent.
    Install {
        /// App name as published to the registry.
        name: String,
        /// Placement: self | node=<id> | tag=a,b | fleet=<name> | nearest.
        #[arg(long, default_value = "self")]
        on: String,
        /// ce-hub registry origin to resolve manifests from.
        #[arg(long, default_value = "https://ce-net.com")]
        registry: String,
        /// Apply the plan (write install records + shims) instead of a dry run.
        #[arg(long)]
        yes: bool,
        /// Trust-on-first-use: record an unknown publisher and proceed (instead of refusing).
        #[arg(long)]
        tofu: bool,
        /// Allow installing an unsigned app (no publisher signature). Not recommended.
        #[arg(long)]
        allow_unsigned: bool,
    },
    /// Re-fetch an installed app from the registry, picking up a republished binary (new content
    /// digest, same version). Unlike `install`, this does NOT skip an already-installed app.
    Update {
        /// App to update; omit to update every installed app.
        name: Option<String>,
        #[arg(long, default_value = "https://ce-net.com")]
        registry: String,
    },
    /// Show an app's manifest and resolved install plan from the registry.
    Info {
        name: String,
        #[arg(long, default_value = "https://ce-net.com")]
        registry: String,
    },
    /// List apps installed locally through `ce`.
    Ls,
    /// List running app instances across the whole mesh (from ce-hub).
    Ps {
        /// Only show instances of this app.
        #[arg(long)]
        app: Option<String>,
        /// ce-hub origin holding the global instance registry.
        #[arg(long, default_value = "https://ce-net.com")]
        hub: String,
    },
    /// Remove an installed app (record + artifacts + launcher shim).
    Uninstall {
        name: String,
    },
    /// Run an installed app in its sandbox (one-shot). Args after `--` go to the app.
    Run {
        name: String,
        /// Placement: self | node=<id> | tag=a,b | fleet=<name> | nearest.
        #[arg(long, default_value = "self")]
        on: String,
        /// Arguments passed through to the app (after `--`).
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// Manage long-running app daemons supervised by the single `ce` service.
    Daemon {
        #[command(subcommand)]
        command: DaemonCommands,
    },
    /// Stop a (possibly remote) app instance deployed via `--on`, by its job id.
    Kill {
        /// The job id printed by `ce app install/run --on <placement>`.
        job_id: String,
        /// Node the instance runs on: node=<id> or a wallet alias.
        #[arg(long)]
        on: String,
    },
    /// The app-facing control API: apps ensure their own deps + install securely.
    Ctl {
        #[command(subcommand)]
        command: CtlCommands,
    },
    /// Sign a `ceapp.toml` and publish it (manifest + signature) to the registry.
    Publish {
        /// Path to the ceapp.toml to publish (omit when using --repo).
        path: Option<String>,
        /// Also write the signed manifest + sidecar into this local dir (a servable registry).
        #[arg(long)]
        out: Option<String>,
        /// ce-hub origin to upload the manifest + signature to (best-effort).
        #[arg(long)]
        registry: Option<String>,
        /// Discover and publish EVERY `ceapp.toml` under this directory — one repo, many ceapps (§8.3).
        #[arg(long)]
        repo: Option<String>,
    },
    /// Manage the set of publisher keys this node trusts for installs.
    Trust {
        #[command(subcommand)]
        command: TrustCommands,
    },
}

/// `ce app trust ...` — publisher trust management (the install gate).
#[derive(Subcommand)]
enum TrustCommands {
    /// Trust a publisher node id for future installs.
    Add { publisher: String },
    /// Stop trusting a publisher.
    Rm { publisher: String },
    /// List trusted publishers.
    Ls,
}

/// `ce app ctl ...` — the per-instance, capability-scoped app-facing control API.
#[derive(Subcommand)]
enum CtlCommands {
    /// Mint a per-instance token whose authority is derived from an installed app's
    /// manifest `[deps]` (declared deps + capabilities). Hand it to the app as
    /// `CE_INSTANCE_TOKEN`.
    Token {
        /// The installed app the token authorizes.
        app: String,
    },
    /// Serve the CtlAPI on a unix socket. Apps connected to it can ensure declared
    /// dependencies and install — each request gated by the caller's token.
    Serve {
        /// Unix socket path to bind (injected into sandboxes as CE_CTL_SOCK).
        #[arg(long, default_value = "/tmp/ce-ctl.sock")]
        sock: String,
        /// ce-hub registry origin used to resolve dependencies.
        #[arg(long, default_value = "https://ce-net.com")]
        registry: String,
        /// ce-hub origin for the instance registry.
        #[arg(long, default_value = "https://ce-net.com")]
        hub: String,
    },
}

/// `ce app daemon ...` — the single supervisor that replaces per-app plists.
#[derive(Subcommand)]
enum DaemonCommands {
    /// Mark a daemon app to be kept running by the ce supervisor.
    Enable { name: String },
    /// Stop supervising a daemon app.
    Disable { name: String },
    /// List enabled daemons.
    Ls,
    /// Run the supervisor: start + keep enabled daemons running, register them to ce-hub.
    Run {
        /// ce-hub origin holding the global instance registry.
        #[arg(long, default_value = "https://ce-net.com")]
        hub: String,
        /// Do a single reconcile pass (start missing daemons + register) and exit.
        #[arg(long)]
        once: bool,
        /// Reconcile interval in seconds for the supervision loop.
        #[arg(long, default_value = "5")]
        interval: u64,
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
        /// Enrol this device in one or more ORGANIZATIONS (repeatable) — for `--on org=<x>`.
        #[arg(long = "org")]
        orgs: Vec<String>,
        /// Put this device in one or more named WORKSPACES (repeatable) — for `--on workspace=<x>`.
        /// (The `personal` workspace is implicitly every paired device.)
        #[arg(long = "workspace")]
        workspaces: Vec<String>,
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
    /// Organizations this device is enrolled in (multi-membership) — for `--on org=<x>`. A device can be
    /// in several (your personal org AND your company's). Empty = personal only.
    #[serde(default)]
    orgs: Vec<String>,
    /// Workspaces this device belongs to — for `--on workspace=<x>`. The implicit `personal` workspace is
    /// every paired device, so it need not be listed here; add named workspaces (e.g. `acme/backend`).
    #[serde(default)]
    workspaces: Vec<String>,
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

/// Install CE as the ONE OS service (launchd/systemd) running `ce start`. Because `ce start` now also
/// runs the app supervisor in-process, this single unit hosts the node + every installed app daemon —
/// there are no per-app plists and no separate supervisor unit. This is the only service a machine in the
/// "shared computer" needs.
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

/// Self-update: download the latest GitHub release for this platform and atomically replace the
/// running `ce` binary. Shells out to `tar`/`sudo` from the environment — no extra crates.
async fn self_update(force: bool, restart: bool) -> Result<()> {
    const REPO: &str = "ce-net/ce";
    let current = env!("CARGO_PKG_VERSION");
    let asset = update_asset_name()?;

    let client = reqwest::Client::builder()
        .user_agent(concat!("ce/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(60))
        .build()?;
    let rel: serde_json::Value = client
        .get(format!("https://api.github.com/repos/{REPO}/releases/latest"))
        .send()
        .await
        .context("fetching latest release")?
        .error_for_status()
        .context("GitHub releases API")?
        .json()
        .await
        .context("decoding release JSON")?;
    let tag = rel["tag_name"]
        .as_str()
        .context("latest release has no tag_name")?;
    let latest = tag.trim_start_matches('v');

    if latest == current && !force {
        println!("ce is already up to date (v{current}).");
        return Ok(());
    }
    println!("Updating ce v{current} -> {tag} ...");

    let ext = if cfg!(windows) { "zip" } else { "tar.gz" };
    let url = format!("https://github.com/{REPO}/releases/download/{tag}/{asset}.{ext}");
    let bytes = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("downloading {url}"))?
        .error_for_status()
        .with_context(|| format!("downloading {url}"))?
        .bytes()
        .await
        .context("reading release bytes")?;

    let tmp = std::env::temp_dir().join(format!("ce-update-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).context("creating temp dir")?;
    let archive = tmp.join(format!("ce.{ext}"));
    std::fs::write(&archive, &bytes).context("writing archive")?;

    // `tar` extracts both .tar.gz and .zip on macOS/Linux and Windows 10+.
    let ok = std::process::Command::new("tar")
        .arg("-xf")
        .arg(&archive)
        .arg("-C")
        .arg(&tmp)
        .status()
        .context("running tar")?
        .success();
    if !ok {
        anyhow::bail!("failed to extract {}", archive.display());
    }

    let bin_name = if cfg!(windows) { "ce.exe" } else { "ce" };
    let new_bin = tmp.join(bin_name);
    if !new_bin.exists() {
        anyhow::bail!("release archive did not contain {bin_name}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&new_bin, std::fs::Permissions::from_mode(0o755))
            .context("chmod new binary")?;
    }

    // Verify the downloaded binary actually runs before we swap it in.
    let out = std::process::Command::new(&new_bin)
        .arg("--version")
        .output()
        .context("running the downloaded binary")?;
    if !out.status.success() {
        anyhow::bail!("downloaded binary failed its --version check");
    }

    let exe = std::env::current_exe().context("resolving current executable")?;
    replace_binary(&new_bin, &exe)?;
    let _ = std::fs::remove_dir_all(&tmp);

    println!(
        "Updated: {} is now {}",
        exe.display(),
        String::from_utf8_lossy(&out.stdout).trim()
    );

    if restart {
        restart_service();
    } else {
        println!("Restart your node to run the new version (or re-run with --restart).");
    }
    Ok(())
}

/// The release asset base name for this platform (no extension).
fn update_asset_name() -> Result<&'static str> {
    Ok(match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "ce-linux-amd64",
        ("linux", "aarch64") => "ce-linux-arm64",
        ("macos", "x86_64") => "ce-macos-amd64",
        ("macos", "aarch64") => "ce-macos-arm64",
        ("windows", "x86_64") => "ce-windows-amd64",
        (os, arch) => anyhow::bail!("no prebuilt release for {os}-{arch}; build from source"),
    })
}

/// Replace `dst` with `src`, atomically when possible; escalate with sudo if the dir needs it.
fn replace_binary(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    let dir = dst.parent().unwrap_or_else(|| std::path::Path::new("."));
    let staged = dir.join(".ce-update.tmp");
    if std::fs::copy(src, &staged).is_ok() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755));
        }
        // Same directory => same filesystem => atomic rename over the running binary (allowed on
        // Unix even while executing).
        return std::fs::rename(&staged, dst)
            .with_context(|| format!("replacing {}", dst.display()));
    }
    // No write permission to the install dir: fall back to sudo on Unix.
    #[cfg(unix)]
    {
        let ok = std::process::Command::new("sudo")
            .arg("install")
            .arg("-m")
            .arg("755")
            .arg(src)
            .arg(dst)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return Ok(());
        }
    }
    anyhow::bail!(
        "cannot write {} — try `sudo ce update`, or re-run the installer",
        dst.display()
    )
}

/// Best-effort restart of the ce background service (systemd user, then system).
fn restart_service() {
    let attempts: &[(&str, &[&str])] = &[
        ("systemctl", &["--user", "restart", "ce"]),
        ("systemctl", &["restart", "ce"]),
    ];
    for (cmd, args) in attempts {
        if let Ok(s) = std::process::Command::new(cmd).args(*args).status() {
            if s.success() {
                println!("Restarted the ce service ({cmd} {}).", args.join(" "));
                return;
            }
        }
    }
    println!("Could not auto-restart the service; restart your node manually.");
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

            // Keep a copy of the data dir for the in-process app supervisor (config moves `data_dir`).
            let sup_data = data_dir.clone();
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
            // ONE OS SERVICE: the node ALSO runs the app supervisor in-process, so every installed app
            // daemon (rdev, clip, …) is hosted under this single `ce` service. There is no separate
            // per-app plist and no separate supervisor unit — `ce install-service` (which runs `ce start`)
            // is the one launchd/systemd service the whole "shared computer" needs on a machine. The
            // supervisor reconciles enabled daemons every 5s, so `ce app daemon enable <x>` is picked up
            // live. Opt out with CE_NO_APP_SUPERVISOR=1 (e.g. a minimal node that hosts no apps).
            if std::env::var("CE_NO_APP_SUPERVISOR").is_err() {
                let hub = std::env::var("CE_APP_HUB").unwrap_or_else(|_| "https://ce-net.com".to_string());
                tokio::spawn(async move {
                    let store = ce_appmgr::Store::new(&sup_data);
                    if let Err(e) = store.ensure() {
                        eprintln!("app supervisor: store init failed: {e}");
                        return;
                    }
                    if let Err(e) = run_supervisor(&store, &sup_data, &hub, false, 5).await {
                        eprintln!("app supervisor exited: {e}");
                    }
                });
                println!("App supervisor running in-process (one service hosts the node + all app daemons).");
            }
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

        Commands::Update { force, restart } => {
            self_update(force, restart).await?;
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
            WalletCommands::Add { alias, node_id, cap, orgs, workspaces } => {
                if node_id.len() != 64 || !node_id.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(anyhow!("node_id must be 64 hex chars"));
                }
                capability::decode_chain(&cap).map_err(|_| anyhow!("invalid capability token"))?;
                let mut w = load_wallet(&data_dir);
                w.entries.insert(alias.clone(), WalletEntry { node_id, cap, orgs, workspaces });
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
        Commands::App { command } => app_command(command, &data_dir).await?,
    }

    Ok(())
}

// ===== ce app — universal app & system manager =====

/// The launcher-shim / entrypoint name for an app: the native binary name when the
/// app ships a native binary, otherwise the app name itself (oci/wasm/recipe).
fn app_shim_name(m: &ce_appmgr::AppManifest) -> String {
    m.native
        .as_ref()
        .map(|n| n.bin.clone())
        .unwrap_or_else(|| m.app.name.clone())
}

/// Print the non-app requirements a resolved plan carries (services, capabilities,
/// host features). Shared by `info` and `install`.
fn print_plan_requirements(plan: &ce_appmgr::Plan) {
    if !plan.services.is_empty() {
        println!("  services    : {}", plan.services.iter().cloned().collect::<Vec<_>>().join(", "));
    }
    if !plan.capabilities.is_empty() {
        println!("  capabilities: {}", plan.capabilities.iter().cloned().collect::<Vec<_>>().join(", "));
    }
    if !plan.system.is_empty() {
        let sys: Vec<String> = plan.system.iter().map(|(k, v)| format!("{k}={v}")).collect();
        println!("  system      : {}", sys.join(", "));
    }
}

async fn app_command(cmd: AppCommands, data_dir: &std::path::Path) -> Result<()> {
    let store = ce_appmgr::Store::new(data_dir);
    match cmd {
        AppCommands::Info { name, registry } => {
            let reg = ce_appmgr::HubRegistry::new(registry);
            let plan = ce_appmgr::resolve(&reg, &name).await?;
            // The root app is the last item in install order.
            let root = plan
                .items
                .last()
                .ok_or_else(|| anyhow!("empty plan for '{name}'"))?;
            let m = &root.manifest;
            println!("{} {}", m.app.name, m.app.version);
            if !m.app.summary.is_empty() {
                println!("  {}", m.app.summary);
            }
            println!("  runtime     : {:?}", m.app.runtime);
            let target = ce_appmgr::host_target();
            match m.app.runtime {
                ce_appmgr::Runtime::Native => match m.native_digest(&target) {
                    Some(d) => println!("  artifact    : {target} -> {d}"),
                    None => println!("  artifact    : (no native build for {target})"),
                },
                ce_appmgr::Runtime::Oci => {
                    if let Some(o) = &m.oci {
                        println!("  image       : {}", o.image);
                    }
                }
                ce_appmgr::Runtime::Wasm => {
                    if let Some(w) = &m.wasm {
                        println!("  artifact    : {} (portable)", w.artifact);
                    }
                }
                ce_appmgr::Runtime::Recipe => {
                    if let Some(r) = &m.recipe {
                        println!("  source      : {}", r.source);
                    }
                }
            }
            println!("  sandbox     : {:?} / net={}", m.sandbox.tier, m.sandbox.net);
            if m.is_daemon() {
                println!("  daemon      : yes (supervised by the ce service)");
            }
            print_plan_requirements(&plan);
            if plan.items.len() > 1 {
                println!("  install order: {}", plan.order().join(" -> "));
            }
        }

        AppCommands::Install { name, on, registry, yes, tofu, allow_unsigned } => {
            // SOURCE = a local working tree (./path or a ceapp.toml): install straight from disk — no
            // registry round-trip, no publisher gate (it's your own tree). The most-wanted dev source
            // (§4.1): build locally, `ce app install ./myapp`, and it's live + supervised here at once.
            if is_local_source(&name) {
                let _ = (tofu, allow_unsigned);
                let placement = ce_appmgr::Placement::parse(&on)?;
                if !placement.is_local() {
                    return Err(anyhow!(
                        "local-source install is `--on self` for now; `ce app publish` it to install on \
                         other nodes/orgs/workspaces"
                    ));
                }
                return install_from_path(&name, &store, yes).await;
            }
            // SOURCE = a scheme URI (§4.1/§8.3): install ANY system, not just published ceapps. `oci:` is
            // the universal "install any container/system" path (e.g. `ce app install oci:postgres:16`).
            if let Some(image) = name.strip_prefix("oci:") {
                let _ = (tofu, allow_unsigned, &registry);
                let placement = ce_appmgr::Placement::parse(&on)?;
                if !placement.is_local() {
                    return Err(anyhow!("oci: source installs `--on self` for now"));
                }
                return install_oci_uri(image, &store).await;
            }
            if name.starts_with("git:") || name.starts_with("blob:") {
                return Err(anyhow!(
                    "source '{name}' is recognised but not wired yet: `git:` builds via the recipe tier and \
                     `blob:` fetches by CID — both land after the recipe/blob build path. Use a published \
                     name, `./path`, or `oci:` for now."
                ));
            }
            let placement = ce_appmgr::Placement::parse(&on)?;
            // Publisher trust gate: verify the app's signature and that its publisher
            // is trusted (or trust-on-first-use) before any install side effect.
            verify_publisher(&registry, &name, data_dir, tofu, allow_unsigned).await?;
            if !placement.is_local() {
                // Global install over the mesh. Resolve once to learn the runtime, then place:
                //  - oci apps ship as a sandboxed job via /mesh-deploy;
                //  - native/wasm apps install + supervise on the host via /mesh-app-install
                //    (the capability-authed remote appmgr agent — the `app:install` ability).
                // `fleet=mine` fans out to this host plus every paired device in the wallet, so a
                // single command installs across all your devices.
                let reg = ce_appmgr::HubRegistry::new(&registry);
                let plan = ce_appmgr::resolve(&reg, &name).await?;
                let root = plan.items.last().ok_or_else(|| anyhow!("empty plan for '{name}'"))?;
                let runtime = root.manifest.app.runtime;
                let version = root.manifest.app.version.to_string();
                let image = if runtime == ce_appmgr::Runtime::Oci {
                    Some(oci_image_or_err(&root.manifest)?)
                } else {
                    None
                };
                if !yes {
                    println!("Would install '{name}' {version} ({runtime:?}) on {placement}. Re-run with --yes.");
                    return Ok(());
                }
                if let Some(members) = fleet_targets(data_dir, &placement)? {
                    // Fan out: this host first (a normal local install), then every paired device.
                    println!("fleet install '{name}' {version} -> this host + {} device(s)", members.len());
                    install_local(&name, &registry, &store, false).await?;
                    // A fleet install is turnkey: enable the daemon on this host too (the remote
                    // legs enable it on their hosts), so e.g. `clip` runs everywhere after one
                    // command. The single supervisor (`ce app daemon run`) starts it.
                    if root.manifest.is_daemon() {
                        store.set_daemon_enabled(&name, true)?;
                    }
                    let mut ok = 1usize;
                    let mut failed = 0usize;
                    for member in &members {
                        let target = ce_appmgr::Placement::Node(member.clone());
                        match remote_install_one(&name, &registry, &version, image.clone(), &target, data_dir).await {
                            Ok(()) => ok += 1,
                            Err(e) => {
                                eprintln!("  {member}: {e}");
                                failed += 1;
                            }
                        }
                    }
                    println!("fleet install: {ok} ok, {failed} failed (this host + {} device(s))", members.len());
                    return Ok(());
                }
                return remote_install_one(&name, &registry, &version, image, &placement, data_dir).await;
            }
            let reg = ce_appmgr::HubRegistry::new(&registry);
            let plan = ce_appmgr::resolve(&reg, &name).await?;
            println!("Plan for '{name}' (on {placement}):");
            for item in &plan.items {
                let m = &item.manifest;
                let marker = if store.is_installed(&m.app.name) { " (already installed)" } else { "" };
                println!("  - {} {} [{:?}]{marker}", m.app.name, m.app.version, m.app.runtime);
            }
            print_plan_requirements(&plan);

            if !yes {
                println!("\nDry run. Re-run with --yes to install.");
                return Ok(());
            }
            install_local(&name, &registry, &store, false).await?;
        }

        AppCommands::Update { name, registry } => {
            let targets: Vec<String> = match name {
                Some(n) => vec![n],
                None => store.list()?.into_iter().map(|a| a.manifest.app.name).collect(),
            };
            if targets.is_empty() {
                println!("No apps installed to update.");
                return Ok(());
            }
            for n in &targets {
                println!("Updating {n}...");
                if let Err(e) = install_local(n, &registry, &store, true).await {
                    eprintln!("  update '{n}' failed: {e}");
                }
            }
        }

        AppCommands::Ls => {
            let apps = store.list()?;
            if apps.is_empty() {
                println!("No apps installed. Try: ce app install <name>");
                return Ok(());
            }
            for a in apps {
                let kind = if a.manifest.is_daemon() { "daemon" } else { "cli" };
                println!(
                    "{:<20} {:<10} {:<7} {:?}",
                    a.manifest.app.name, a.manifest.app.version, kind, a.manifest.app.runtime
                );
            }
        }

        AppCommands::Ps { app, hub } => {
            let hub = ce_appmgr::HubInstances::new(hub);
            let filter = ce_appmgr::InstanceFilter { app, ..Default::default() };
            let instances = hub.list(&filter).await?;
            if instances.is_empty() {
                println!("No running instances.");
                return Ok(());
            }
            println!("{:<24} {:<14} {:<10} {:<10} NODE", "INSTANCE", "APP", "VERSION", "HEALTH");
            for i in instances {
                let node_short: String = i.node_id.chars().take(12).collect();
                println!(
                    "{:<24} {:<14} {:<10} {:<10} {node_short}",
                    i.id, i.app, i.version, format!("{:?}", i.health)
                );
            }
        }

        AppCommands::Uninstall { name } => {
            let Some(rec) = store.get(&name)? else {
                println!("'{name}' is not installed.");
                return Ok(());
            };
            #[cfg(unix)]
            store.remove_shim(&app_shim_name(&rec.manifest))?;
            store.remove(&name)?;
            println!("Uninstalled {name}.");
        }

        AppCommands::Run { name, on, args } => {
            let placement = ce_appmgr::Placement::parse(&on)?;
            let Some(rec) = store.get(&name)? else {
                return Err(anyhow!("'{name}' is not installed. Run: ce app install {name}"));
            };
            let version = rec.manifest.app.version.to_string();
            if !placement.is_local() {
                // Global run: ship the (already-installed) app's image to the target
                // node over mesh-deploy.
                let image = oci_image_or_err(&rec.manifest)?;
                return mesh_deploy_oci(&name, &version, &image, &placement, data_dir).await;
            }
            let plan = ce_appmgr::plan_run(&store, &rec, args)?;
            run_app(&name, &version, plan, data_dir).await?;
        }

        AppCommands::Daemon { command } => match command {
            DaemonCommands::Enable { name } => {
                let Some(rec) = store.get(&name)? else {
                    return Err(anyhow!("'{name}' is not installed. Run: ce app install {name}"));
                };
                if !rec.manifest.is_daemon() {
                    return Err(anyhow!("'{name}' is a one-shot app (no [daemon]); use `ce app run`"));
                }
                store.set_daemon_enabled(&name, true)?;
                println!("Enabled daemon '{name}'. The running `ce` node supervises it in-process — it \
                          starts within a few seconds (or on next `ce start`). No separate service.");
            }
            DaemonCommands::Disable { name } => {
                store.set_daemon_enabled(&name, false)?;
                println!("Disabled daemon '{name}'.");
            }
            DaemonCommands::Ls => {
                let daemons = ce_appmgr::enabled_daemons(&store)?;
                if daemons.is_empty() {
                    println!("No daemons enabled. Enable one: ce app daemon enable <name>");
                    return Ok(());
                }
                for a in daemons {
                    let policy = ce_appmgr::daemon_policy(&a.manifest);
                    let restart = policy.map(|p| format!("{:?}", p.restart)).unwrap_or_default();
                    println!(
                        "{:<20} {:<10} {:?}  restart={restart}",
                        a.manifest.app.name, a.manifest.app.version, a.manifest.app.runtime
                    );
                }
            }
            DaemonCommands::Run { hub, once, interval } => {
                run_supervisor(&store, data_dir, &hub, once, interval).await?;
            }
        },

        AppCommands::Kill { job_id, on } => {
            let placement = ce_appmgr::Placement::parse(&on)?;
            let node = match &placement {
                ce_appmgr::Placement::Node(id) => id.clone(),
                other => {
                    return Err(anyhow!(
                        "`ce app kill` needs the node the instance runs on: --on node=<id> (got '{other}')"
                    ));
                }
            };
            let (node_id_hex, cap) = resolve_target(&data_dir.to_path_buf(), &node)?;
            let api_token = read_api_token(data_dir);
            let client = api_client(&api_token);
            let body = serde_json::json!({ "node_id": node_id_hex, "job_id": job_id, "grant": cap });
            let resp = client
                .post("http://127.0.0.1:8844/mesh-kill")
                .json(&body)
                .send()
                .await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(anyhow!("kill failed ({status}): {text}"));
            }
            println!("killed job {job_id} on node={node_id_hex}");
        }

        AppCommands::Ctl { command } => match command {
            CtlCommands::Token { app } => {
                let Some(rec) = store.get(&app)? else {
                    return Err(anyhow!("'{app}' is not installed. Run: ce app install {app}"));
                };
                let identity = Identity::load_or_generate(&data_dir.join("identity"))?;
                let token = mint_ctl_token(&identity, &app);
                let caller = caller_context_for(&rec.manifest, &app);
                write_ctl_token(data_dir, &token, &caller)?;
                println!("CE_INSTANCE_TOKEN={token}");
                println!("authorizes app '{app}': deps={:?} caps={:?}", caller.declared_deps, caller.capabilities);
            }
            CtlCommands::Serve { sock, registry, hub } => {
                ctl_serve(&store, data_dir, &sock, &registry, &hub).await?;
            }
        },

        AppCommands::Publish { path, out, registry, repo } => {
            if let Some(dir) = repo {
                // One repo, many ceapps: publish every ceapp.toml under <dir> (skipping build/target dirs).
                let manifests = discover_ceapps(std::path::Path::new(&dir))?;
                if manifests.is_empty() {
                    return Err(anyhow!("no ceapp.toml found under {dir}"));
                }
                println!("Publishing {} ceapp(s) from {dir}:", manifests.len());
                for mp in &manifests {
                    app_publish(data_dir, &mp.to_string_lossy(), out.as_deref(), registry.as_deref()).await?;
                }
            } else if let Some(path) = path {
                app_publish(data_dir, &path, out.as_deref(), registry.as_deref()).await?;
            } else {
                return Err(anyhow!("give a ceapp.toml path or --repo <dir>"));
            }
        }

        AppCommands::Trust { command } => match command {
            TrustCommands::Add { publisher } => {
                let pub_id = publisher.trim().to_lowercase();
                if pub_id.len() != 64 || !pub_id.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(anyhow!("publisher must be a 64-hex node id"));
                }
                let mut set = load_trusted_publishers(data_dir);
                if set.insert(pub_id.clone()) {
                    save_trusted_publishers(data_dir, &set)?;
                    println!("Trusting publisher {pub_id}");
                } else {
                    println!("Already trusting {pub_id}");
                }
            }
            TrustCommands::Rm { publisher } => {
                let pub_id = publisher.trim().to_lowercase();
                let mut set = load_trusted_publishers(data_dir);
                if set.remove(&pub_id) {
                    save_trusted_publishers(data_dir, &set)?;
                    println!("No longer trusting {pub_id}");
                } else {
                    println!("{pub_id} was not trusted");
                }
            }
            TrustCommands::Ls => {
                let set = load_trusted_publishers(data_dir);
                if set.is_empty() {
                    println!("No trusted publishers. Add one: ce app trust add <publisher-id>");
                } else {
                    for p in set {
                        println!("{p}");
                    }
                }
            }
        },
    }
    Ok(())
}

// ===== M7: publish + manifest signing + trust =====

fn trusted_publishers_path(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("trusted-publishers")
}

/// The set of publisher node ids this node trusts for installs (one 64-hex id/line).
fn load_trusted_publishers(data_dir: &std::path::Path) -> std::collections::BTreeSet<String> {
    std::fs::read_to_string(trusted_publishers_path(data_dir))
        .map(|s| {
            s.lines()
                .map(|l| l.trim().to_lowercase())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect()
        })
        .unwrap_or_default()
}

fn save_trusted_publishers(
    data_dir: &std::path::Path,
    set: &std::collections::BTreeSet<String>,
) -> Result<()> {
    std::fs::create_dir_all(data_dir)?;
    let body: String = set.iter().map(|p| format!("{p}\n")).collect();
    std::fs::write(trusted_publishers_path(data_dir), body)?;
    Ok(())
}

/// Find every `ceapp.toml` under `dir` (recursive), skipping build/vcs/dependency dirs. This is how one
/// repo holds MANY ceapps (§8.3): a `core` app + one per platform integration, each its own manifest.
fn discover_ceapps(dir: &std::path::Path) -> Result<Vec<std::path::PathBuf>> {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for entry in rd.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                if matches!(name.as_ref(), "target" | ".git" | "node_modules" | ".cargo-shared" | "dist" | "build") {
                    continue;
                }
                walk(&path, out);
            } else if name == "ceapp.toml" {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, &mut out);
    out.sort();
    Ok(out)
}

/// Sign a `ceapp.toml` with this node's identity and publish the manifest + a
/// detached signature sidecar (to a local dir and/or a ce-hub origin).
async fn app_publish(
    data_dir: &std::path::Path,
    path: &str,
    out: Option<&str>,
    registry: Option<&str>,
) -> Result<()> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {path}"))?;
    let manifest = ce_appmgr::AppManifest::parse(&String::from_utf8_lossy(&bytes))
        .with_context(|| format!("parsing {path}"))?;
    let name = manifest.app.name.clone();

    let identity = Identity::load_or_generate(&data_dir.join("identity"))?;
    let publisher = identity.node_id_hex();
    let signature = hex::encode(identity.sign(&bytes));
    let sig = ce_appmgr::SignatureSidecar { publisher: publisher.clone(), signature };
    let sig_json = serde_json::to_vec_pretty(&sig)?;

    println!("publishing '{name}' signed by {publisher}");

    if let Some(dir) = out {
        let app_dir = std::path::Path::new(dir).join("apps").join(&name);
        std::fs::create_dir_all(&app_dir)?;
        std::fs::write(app_dir.join("ceapp.toml"), &bytes)?;
        std::fs::write(app_dir.join("ceapp.sig"), &sig_json)?;
        println!("  wrote {}", app_dir.join("ceapp.toml").display());
        println!("  wrote {}", app_dir.join("ceapp.sig").display());
    }

    if let Some(hub) = registry {
        let hub = hub.trim_end_matches('/');
        let client = reqwest::Client::new();
        for (suffix, body, ctype) in [
            ("ceapp.toml", bytes.clone(), "text/plain"),
            ("ceapp.sig", sig_json.clone(), "application/json"),
        ] {
            let rel = format!("/apps/{name}/{suffix}");
            let url = format!("{hub}{rel}");
            // Signed write (ce-hub scheme): the hub records this identity as the app
            // owner on first publish and 403s any later write from a different identity.
            // Canonical = "PUT\n<path>\n<ts>\n<nonce>\n<sha256(body)hex>".
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
                .to_string();
            let mut nh = Sha256::new();
            nh.update(identity.secret_bytes());
            nh.update(ts.as_bytes());
            nh.update(suffix.as_bytes());
            nh.update(&body);
            let nonce = hex::encode(nh.finalize());
            let body_hex = hex::encode(Sha256::digest(&body));
            let canon = format!("PUT\n{rel}\n{ts}\n{nonce}\n{body_hex}");
            let sig = hex::encode(identity.sign(canon.as_bytes()));
            let resp = client
                .put(&url)
                .header("content-type", ctype)
                .header("x-ce-id", &publisher)
                .header("x-ce-ts", &ts)
                .header("x-ce-nonce", &nonce)
                .header("x-ce-sig", &sig)
                .body(body)
                .send()
                .await;
            match resp {
                Ok(r) if r.status().is_success() => println!("  uploaded {url} (signed)"),
                Ok(r) => println!("  note: {url} -> {} (owned by another identity?)", r.status()),
                Err(e) => println!("  note: upload to {url} failed: {e}"),
            }
        }
    }

    if out.is_none() && registry.is_none() {
        println!("  (no --out or --registry; nothing written. Re-run with one.)");
    }
    Ok(())
}

/// Verify an app's publisher signature and trust before install. Refuses an
/// untrusted publisher unless `tofu` (record + proceed), and an unsigned app unless
/// `allow_unsigned`.
async fn verify_publisher(
    registry: &str,
    name: &str,
    data_dir: &std::path::Path,
    tofu: bool,
    allow_unsigned: bool,
) -> Result<()> {
    let reg = ce_appmgr::HubRegistry::new(registry);
    let raw = reg.fetch_raw(name).await?;
    let sig = reg.fetch_signature(name).await?;

    let Some(sig) = sig else {
        if allow_unsigned {
            eprintln!("warning: installing UNSIGNED app '{name}' (--allow-unsigned)");
            return Ok(());
        }
        return Err(anyhow!(
            "app '{name}' is unsigned — refuse by default. Re-run with --allow-unsigned to override, \
             or ask the publisher to `ce app publish` a signed manifest."
        ));
    };

    // Verify the Ed25519 signature over the exact manifest bytes.
    let pub_id = sig.publisher.to_lowercase();
    let node_id: [u8; 32] = hex::decode(&pub_id)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("signature publisher is not a 64-hex node id"))?;
    let sig_bytes: [u8; 64] = hex::decode(&sig.signature)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("signature is not 128 hex chars"))?;
    ce_identity::verify(&node_id, raw.as_bytes(), &sig_bytes)
        .map_err(|e| anyhow!("signature verification FAILED for '{name}': {e}"))?;

    // Trust check.
    let mut trusted = load_trusted_publishers(data_dir);
    if trusted.contains(&pub_id) {
        return Ok(());
    }
    if tofu {
        trusted.insert(pub_id.clone());
        save_trusted_publishers(data_dir, &trusted)?;
        eprintln!("trust-on-first-use: now trusting publisher {pub_id}");
        return Ok(());
    }
    Err(anyhow!(
        "publisher {pub_id} of '{name}' is not trusted. Trust it with `ce app trust add {pub_id}`, \
         or re-run install with --tofu to trust-on-first-use."
    ))
}

// ===== app-facing CtlAPI (M6): transport + security gates =====

/// Derive a [`ce_appmgr::CallerContext`] from an app's manifest: declared deps are
/// the app dependencies + required services; capabilities are the manifest's.
fn caller_context_for(m: &ce_appmgr::AppManifest, app: &str) -> ce_appmgr::CallerContext {
    let mut declared: Vec<String> = m
        .deps
        .apps
        .iter()
        .filter_map(|d| ce_appmgr::DepSpec::parse(d).ok().map(|s| s.name))
        .collect();
    declared.extend(m.deps.services.iter().cloned());
    ce_appmgr::CallerContext {
        instance_id: ce_appmgr::InstanceRecord::make_id("local", app, 0),
        app: app.to_string(),
        capabilities: m.deps.capabilities.clone(),
        declared_deps: declared,
    }
}

/// An unguessable per-instance token bound to the node's secret key, so tokens
/// can't be forged by another process.
fn mint_ctl_token(identity: &Identity, app: &str) -> String {
    let mut h = Sha256::new();
    h.update(identity.secret_bytes());
    h.update(app.as_bytes());
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    h.update(nanos.to_le_bytes());
    hex::encode(h.finalize())
}

fn ctl_tokens_dir(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("ctl").join("tokens")
}

/// Persist token -> CallerContext so `ctl serve` can authenticate the caller.
fn write_ctl_token(
    data_dir: &std::path::Path,
    token: &str,
    caller: &ce_appmgr::CallerContext,
) -> Result<()> {
    let dir = ctl_tokens_dir(data_dir);
    std::fs::create_dir_all(&dir)?;
    let body = serde_json::json!({
        "app": caller.app,
        "instance_id": caller.instance_id,
        "capabilities": caller.capabilities,
        "declared_deps": caller.declared_deps,
    });
    std::fs::write(dir.join(format!("{token}.json")), serde_json::to_vec_pretty(&body)?)?;
    Ok(())
}

/// Resolve a token to its [`ce_appmgr::CallerContext`], or `None` if unknown.
fn resolve_ctl_caller(data_dir: &std::path::Path, token: &str) -> Option<ce_appmgr::CallerContext> {
    // Reject path tricks in the token before using it as a filename.
    if token.is_empty() || !token.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    let p = ctl_tokens_dir(data_dir).join(format!("{token}.json"));
    let s = std::fs::read_to_string(p).ok()?;
    let v: serde_json::Value = serde_json::from_str(&s).ok()?;
    Some(ce_appmgr::CallerContext {
        instance_id: v["instance_id"].as_str().unwrap_or_default().to_string(),
        app: v["app"].as_str().unwrap_or_default().to_string(),
        capabilities: v["capabilities"]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        declared_deps: v["declared_deps"]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default(),
    })
}

/// Serve the CtlAPI on a unix socket: one JSON `CtlEnvelope` per line in, one
/// `CtlResponse` per line out. Every request is gated by the caller's token before
/// any side effect. Unix only — the transport is a unix domain socket.
#[cfg(not(unix))]
async fn ctl_serve(
    _store: &ce_appmgr::Store,
    _data_dir: &std::path::Path,
    _sock: &str,
    _registry: &str,
    _hub: &str,
) -> Result<()> {
    Err(anyhow!(
        "the app-facing CtlAPI uses a unix domain socket and is not available on this platform"
    ))
}

#[cfg(unix)]
async fn ctl_serve(
    store: &ce_appmgr::Store,
    data_dir: &std::path::Path,
    sock: &str,
    registry: &str,
    hub: &str,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let _ = std::fs::remove_file(sock); // clear a stale socket
    let listener = tokio::net::UnixListener::bind(sock)
        .with_context(|| format!("binding CtlAPI socket {sock}"))?;
    println!("CtlAPI listening on {sock} (CE_CTL_SOCK)");

    loop {
        let (stream, _) = listener.accept().await?;
        let (read_half, mut write_half) = stream.into_split();
        let mut lines = BufReader::new(read_half).lines();
        let store = store.clone();
        let data_dir = data_dir.to_path_buf();
        let registry = registry.to_string();
        let hub = hub.to_string();
        // Handle each connection inline (low concurrency expected per instance).
        while let Ok(Some(line)) = lines.next_line().await {
            if line.trim().is_empty() {
                continue;
            }
            let resp = handle_ctl_line(&store, &data_dir, &registry, &hub, &line).await;
            let mut out = serde_json::to_string(&resp).unwrap_or_else(|e| {
                serde_json::to_string(&ce_appmgr::CtlResponse::Error { message: e.to_string() })
                    .unwrap_or_default()
            });
            out.push('\n');
            if write_half.write_all(out.as_bytes()).await.is_err() {
                break;
            }
        }
    }
}

/// Decode one envelope, authenticate, run the security gates, then dispatch. Pure
/// enough to unit-test the gate decisions via the returned `CtlResponse`.
async fn handle_ctl_line(
    store: &ce_appmgr::Store,
    data_dir: &std::path::Path,
    registry: &str,
    hub: &str,
    line: &str,
) -> ce_appmgr::CtlResponse {
    use ce_appmgr::{ControlPlane, CtlRequest, CtlResponse, DenyReason};
    let env: ce_appmgr::CtlEnvelope = match serde_json::from_str(line) {
        Ok(e) => e,
        Err(e) => return CtlResponse::Error { message: format!("bad request: {e}") },
    };
    let Some(caller) = resolve_ctl_caller(data_dir, &env.token) else {
        return CtlResponse::Error { message: "invalid or unknown instance token".into() };
    };
    let agent = AgentControlPlane {
        store: store.clone(),
        data_dir: data_dir.to_path_buf(),
        registry: registry.to_string(),
        hub: hub.to_string(),
    };
    match env.request {
        CtlRequest::EnsureDep(req) => {
            // Gate 1: the dep must be declared in the manifest. Gate 2: a capability
            // permitting it (ce-cap). ce-gov policy is an additional hook (TODO wire).
            if let Err(reason) = ce_appmgr::precheck_declared(&caller, &req.name) {
                return CtlResponse::Denied { reason };
            }
            if !caller_may_provision(&caller) {
                return CtlResponse::Denied { reason: DenyReason::CapabilityDenied };
            }
            if let Some(reason) = ce_gov_denies("ensure_dep", &req.name, &caller).await {
                return CtlResponse::Denied { reason };
            }
            match agent.ensure_dep(&caller, req).await {
                Ok(handle) => CtlResponse::ok(&handle),
                Err(e) => CtlResponse::Error { message: e.to_string() },
            }
        }
        CtlRequest::Install(req) => {
            if let Err(reason) = ce_appmgr::precheck_declared(&caller, &req.name) {
                return CtlResponse::Denied { reason };
            }
            if !caller_may_provision(&caller) {
                return CtlResponse::Denied { reason: DenyReason::CapabilityDenied };
            }
            if let Some(reason) = ce_gov_denies("install", &req.name, &caller).await {
                return CtlResponse::Denied { reason };
            }
            match agent.install(&caller, req).await {
                Ok(()) => CtlResponse::ok(&serde_json::json!({ "installed": true })),
                Err(e) => CtlResponse::Error { message: e.to_string() },
            }
        }
        CtlRequest::Instances(q) => match agent.instances(&caller, q).await {
            Ok(list) => CtlResponse::ok(&list),
            Err(e) => CtlResponse::Error { message: e.to_string() },
        },
    }
}

/// Capability gate for provisioning ops: the instance must hold an ability that
/// lets it install/spawn. (ce-cap chain verification is layered on when instances
/// carry a real attenuated capability; here we check the declared abilities.)
fn caller_may_provision(caller: &ce_appmgr::CallerContext) -> bool {
    caller
        .capabilities
        .iter()
        .any(|c| matches!(c.as_str(), "install" | "exec" | "deploy" | "sync"))
}

/// ce-gov policy gate (M12). When `CE_GOV_URL` is configured, every provisioning
/// request (ensure_dep/install) is submitted to ce-gov for a pre-run policy
/// decision and DENIED if ce-gov rejects it (fail-closed). When unconfigured,
/// ce-gov is opt-in and the gate allows. Returns `Some(reason)` to deny.
async fn ce_gov_denies(
    op: &str,
    target: &str,
    caller: &ce_appmgr::CallerContext,
) -> Option<ce_appmgr::DenyReason> {
    let Ok(base) = std::env::var("CE_GOV_URL") else {
        return None; // ce-gov not configured — opt-in, allow.
    };
    let url = format!("{}/policy/scan", base.trim_end_matches('/'));
    let body = serde_json::json!({
        "op": op,
        "target": target,
        "caller_app": caller.app,
        "caller_caps": caller.capabilities,
    });
    match reqwest::Client::new().post(&url).json(&body).send().await {
        Ok(resp) => {
            let v: serde_json::Value = resp.json().await.unwrap_or_else(|_| serde_json::json!({}));
            // ce-gov returns { "allow": bool, "reason": "..." }. Anything not an
            // explicit allow is a policy denial (fail-closed).
            if v["allow"].as_bool() == Some(true) {
                None
            } else {
                Some(ce_appmgr::DenyReason::PolicyDenied)
            }
        }
        // ce-gov configured but unreachable: fail closed — a policy gate that
        // silently disappears when the judge is down is not a gate.
        Err(_) => Some(ce_appmgr::DenyReason::PolicyDenied),
    }
}

/// The agent's [`ce_appmgr::ControlPlane`] implementation: resolves, installs, and
/// runs declared dependencies on behalf of a managed app, and answers instance
/// queries from ce-hub. The security gates run in [`handle_ctl_line`] before these.
struct AgentControlPlane {
    store: ce_appmgr::Store,
    data_dir: PathBuf,
    registry: String,
    hub: String,
}

impl ce_appmgr::ControlPlane for AgentControlPlane {
    async fn ensure_dep(
        &self,
        _caller: &ce_appmgr::CallerContext,
        req: ce_appmgr::EnsureDepRequest,
    ) -> Result<ce_appmgr::DepHandle> {
        let identity = Identity::load_or_generate(&self.data_dir.join("identity"))?;
        let node_hex = identity.node_id_hex();
        let instance_id = ce_appmgr::InstanceRecord::make_id(&node_hex, &req.name, 0);

        // Already installed? Treat as satisfied (idempotent ensure).
        if let Some(rec) = self.store.get(&req.name)? {
            return Ok(ce_appmgr::DepHandle {
                name: req.name.clone(),
                instance_id,
                endpoint: dep_endpoint(&rec.manifest),
                created: false,
            });
        }

        // Resolve + materialize + record locally (declared, so authorized).
        let reg = ce_appmgr::HubRegistry::new(&self.registry);
        let plan = ce_appmgr::resolve(&reg, &req.name).await?;
        self.store.ensure()?;
        let blobs = ce_appmgr::BlobClient::new(&self.registry);
        let target = ce_appmgr::host_target();
        let mut manifest = None;
        for item in &plan.items {
            let m = &item.manifest;
            if self.store.is_installed(&m.app.name) {
                if m.app.name == req.name {
                    manifest = Some(m.clone());
                }
                continue;
            }
            let materialized = ce_appmgr::materialize(&self.store, &blobs, m, &target).await?;
            let rec = ce_appmgr::InstalledApp {
                manifest: m.clone(),
                target: target.clone(),
                digest: materialized.digest().map(str::to_string),
            };
            self.store.record(&rec)?;
            if m.app.name == req.name {
                manifest = Some(m.clone());
            }
        }
        let manifest = manifest
            .ok_or_else(|| anyhow!("resolved plan did not contain '{}'", req.name))?;
        let endpoint = dep_endpoint(&manifest);
        Ok(ce_appmgr::DepHandle { name: req.name, instance_id, endpoint, created: true })
    }

    async fn install(
        &self,
        _caller: &ce_appmgr::CallerContext,
        req: ce_appmgr::InstallRequest,
    ) -> Result<()> {
        let reg = ce_appmgr::HubRegistry::new(&self.registry);
        let plan = ce_appmgr::resolve(&reg, &req.name).await?;
        self.store.ensure()?;
        let blobs = ce_appmgr::BlobClient::new(&self.registry);
        let target = ce_appmgr::host_target();
        for item in &plan.items {
            let m = &item.manifest;
            if self.store.is_installed(&m.app.name) {
                continue;
            }
            let materialized = ce_appmgr::materialize(&self.store, &blobs, m, &target).await?;
            let rec = ce_appmgr::InstalledApp {
                manifest: m.clone(),
                target: target.clone(),
                digest: materialized.digest().map(str::to_string),
            };
            self.store.record(&rec)?;
        }
        Ok(())
    }

    async fn instances(
        &self,
        _caller: &ce_appmgr::CallerContext,
        query: ce_appmgr::InstancesQuery,
    ) -> Result<Vec<ce_appmgr::InstanceRecord>> {
        let hub = ce_appmgr::HubInstances::new(&self.hub);
        let filter = ce_appmgr::InstanceFilter { app: query.app, ..Default::default() };
        hub.list(&filter).await
    }
}

/// A best-effort connection endpoint for a dependency: the first oci port on
/// loopback, else a marker the app can resolve via its own discovery.
fn dep_endpoint(m: &ce_appmgr::AppManifest) -> String {
    if let Some(o) = &m.oci {
        if let Some(port) = o.ports.first() {
            return format!("127.0.0.1:{}", port.split('/').next().unwrap_or(port));
        }
    }
    format!("ce-app://{}", m.app.name)
}

/// Resolve a tag/fleet/nearest placement to a concrete node id by querying the
/// local node's `/atlas` and ranking candidates by free capacity (cpu*100 + mem,
/// penalized by running jobs). `tag=a,b` requires all tags; `fleet=<name>` treats
/// the fleet name as a required tag; `nearest` ranks the whole atlas.
async fn resolve_placement_node(placement: &ce_appmgr::Placement, api_token: &str) -> Result<String> {
    let required: Vec<String> = match placement {
        ce_appmgr::Placement::Tag(tags) => tags.clone(),
        ce_appmgr::Placement::Fleet(name) => vec![name.clone()],
        // A capability is just an atlas tag (node-intrinsic like `gpu`/`wasm`, or app-provided like
        // `http-ingress`) — pick the best node advertising it.
        ce_appmgr::Placement::Capability(c) => vec![c.clone()],
        ce_appmgr::Placement::Nearest => Vec::new(),
        _ => Vec::new(),
    };
    let client = api_client(api_token);
    let resp = client
        .get("http://127.0.0.1:8844/atlas")
        .send()
        .await
        .context("querying /atlas for placement")?;
    if !resp.status().is_success() {
        return Err(anyhow!("/atlas returned {}", resp.status()));
    }
    let entries: serde_json::Value = resp.json().await.context("decoding /atlas")?;
    let arr = entries.as_array().cloned().unwrap_or_default();
    // (node_id, score) candidates that satisfy the required tags.
    let mut cands: Vec<(String, i64)> = Vec::new();
    for e in &arr {
        let Some(id) = e["node_id"].as_str() else { continue };
        let cap = &e["capacity"];
        let cpu = cap["cpu_cores"].as_u64().unwrap_or(0) as i64;
        let mem = cap["mem_mb"].as_u64().unwrap_or(0) as i64;
        let jobs = cap["running_jobs"].as_u64().unwrap_or(0) as i64;
        let tags: Vec<&str> = cap["tags"]
            .as_array()
            .map(|a| a.iter().filter_map(|t| t.as_str()).collect())
            .unwrap_or_default();
        if !required.iter().all(|r| tags.iter().any(|t| t == r)) {
            continue;
        }
        // Higher is better: free capacity, penalized by current load.
        let score = cpu * 100 + mem - jobs * 50;
        cands.push((id.to_string(), score));
    }
    cands.sort_by(|a, b| b.1.cmp(&a.1));
    cands
        .into_iter()
        .next()
        .map(|(id, _)| id)
        .ok_or_else(|| anyhow!("no atlas node satisfies placement '{placement}' (need tags {required:?})"))
}

/// Install an app on THIS host: resolve, materialize + sha256-verify each artifact, record, and
/// write launcher shims. Does not enable daemons (local install is deliberate; use `ce app daemon
/// enable`). Shared by the local install path and the local leg of a `fleet=mine` fan-out.
async fn install_local(name: &str, registry: &str, store: &ce_appmgr::Store, force: bool) -> Result<()> {
    let reg = ce_appmgr::HubRegistry::new(registry);
    let plan = ce_appmgr::resolve(&reg, name).await?;
    store.ensure()?;
    // Blobs are content-addressed in the same ce-hub origin that serves manifests.
    let blobs = ce_appmgr::BlobClient::new(registry);
    let target = ce_appmgr::host_target();
    for item in &plan.items {
        let m = &item.manifest;
        // `force` (from `ce app update`) re-materializes even when already installed: materialize only
        // refetches a content tier whose on-disk hash != the manifest digest, so a republished binary
        // (new digest, same version) is picked up. Without force, an installed app is left as-is.
        if !force && store.is_installed(&m.app.name) {
            continue;
        }
        // Materialize first (fetch + sha256-verify content-addressed tiers, resolve the oci image)
        // so a bad/missing artifact fails before we record anything.
        let materialized = ce_appmgr::materialize(store, &blobs, m, &target).await?;
        let rec = ce_appmgr::InstalledApp {
            manifest: m.clone(),
            target: target.clone(),
            digest: materialized.digest().map(str::to_string),
        };
        store.record(&rec)?;
        #[cfg(unix)]
        let shim_suffix = {
            let shim = app_shim_name(m);
            let path = store.write_shim(&shim, &m.app.name)?;
            format!(" -> shim {}", path.display())
        };
        #[cfg(not(unix))]
        let shim_suffix = String::from(" (shims: unix only for now)");
        let what = match &materialized {
            ce_appmgr::Materialized::Native { bin_path, .. } => format!("native {}", bin_path.display()),
            ce_appmgr::Materialized::Wasm { module_path, .. } => format!("wasm {}", module_path.display()),
            ce_appmgr::Materialized::Oci { image } => format!("oci {image} (pulled on first run)"),
            ce_appmgr::Materialized::Recipe { source } => format!("recipe {source} (built on first run)"),
        };
        println!("installed {} {} [{what}]{shim_suffix}", m.app.name, m.app.version);
    }
    println!("Installed {name}. Ensure {} is on PATH.", store.bin_dir().display());
    Ok(())
}

/// Is this install SOURCE a local working tree (vs a registry app name)? (§4.1)
fn is_local_source(s: &str) -> bool {
    s == "."
        || s.starts_with("./")
        || s.starts_with("../")
        || s.starts_with('/')
        || s.starts_with('~')
        || s.ends_with("ceapp.toml")
        || std::path::Path::new(s).join("ceapp.toml").is_file()
}

/// Ask cargo where it builds this repo — honours `CARGO_TARGET_DIR`, a `.cargo/config.toml` `target-dir`
/// (incl. a global one), and workspace layout. None if there's no Cargo.toml or cargo isn't available.
fn cargo_target_dir(repo: &std::path::Path) -> Option<std::path::PathBuf> {
    if !repo.join("Cargo.toml").is_file() {
        return None;
    }
    let out = std::process::Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(repo)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    v.get("target_directory")?.as_str().map(std::path::PathBuf::from)
}

/// Install a native ceapp straight from a local working tree (§4.1): read its `ceapp.toml`, take the
/// locally-built binary, place it in the store, record + shim it, and (if a daemon) enable it so the
/// in-process supervisor starts it. No registry, no blob fetch, no publish loop — the dev inner loop.
async fn install_from_path(src: &str, store: &ce_appmgr::Store, _yes: bool) -> Result<()> {
    let p = std::path::Path::new(src);
    let manifest_path = if p.is_dir() || p.join("ceapp.toml").is_file() {
        p.join("ceapp.toml")
    } else {
        p.to_path_buf()
    };
    let manifest_path = std::fs::canonicalize(&manifest_path)
        .map_err(|e| anyhow!("no ceapp.toml at {}: {e}", manifest_path.display()))?;
    let toml = std::fs::read_to_string(&manifest_path)?;
    let m = ce_appmgr::AppManifest::parse(&toml)?;
    let repo = manifest_path.parent().unwrap_or(std::path::Path::new("/")).to_path_buf();
    store.ensure()?;

    // Only native is wired for local install today; oci/wasm/recipe resolve through their own tiers.
    let native = m.native.as_ref().ok_or_else(|| {
        anyhow!("local install supports `[native]` apps; '{}' is {:?}", m.app.name, m.app.runtime)
    })?;
    let bin = native.bin.clone();
    // Find the locally-built release binary. The authoritative source is `cargo metadata` (it honours
    // CARGO_TARGET_DIR, a `.cargo/config.toml` `target-dir`, and workspace layout — e.g. this machine
    // points every build at a shared `~/ce-net/.cargo-shared`). Fall back to the conventional locations
    // for non-cargo trees.
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Some(td) = cargo_target_dir(&repo) {
        candidates.push(td.join("release").join(&bin));
    }
    candidates.push(repo.join("target/release").join(&bin));
    if let Some(w) = repo.parent() {
        candidates.push(w.join(".cargo-shared/release").join(&bin));
    }
    candidates.push(repo.join(".cargo-shared/release").join(&bin));
    let built = candidates.iter().find(|c| c.is_file()).cloned().ok_or_else(|| {
        anyhow!("no local build of '{bin}' — run `cargo build --release` first (looked in {candidates:?})")
    })?;
    let bytes = std::fs::read(built)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hex::encode(hasher.finalize());

    let version = m.app.version.to_string();
    let vdir = store.version_dir(&m.app.name, &version);
    std::fs::create_dir_all(&vdir)?;
    let dest = vdir.join(&bin);
    std::fs::write(&dest, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))?;
    }

    let rec = ce_appmgr::InstalledApp { manifest: m.clone(), target: ce_appmgr::host_target(), digest: Some(digest) };
    store.record(&rec)?;
    if m.is_daemon() {
        store.set_daemon_enabled(&m.app.name, true)?; // the in-process supervisor (ce start) starts it
    }
    #[cfg(unix)]
    {
        let shim = app_shim_name(&m);
        store.write_shim(&shim, &m.app.name)?;
    }
    println!(
        "installed {} {} from {} [native {}]{}",
        m.app.name,
        version,
        manifest_path.display(),
        dest.display(),
        if m.is_daemon() { " + enabled (supervised by `ce start`)" } else { "" }
    );
    println!("Ensure {} is on PATH.", store.bin_dir().display());
    Ok(())
}

/// Derive an app name from an OCI image ref: `postgres:16` -> `postgres`, `ghcr.io/foo/bar:1.2` -> `bar`.
fn oci_app_name(image: &str) -> String {
    let no_digest = image.split('@').next().unwrap_or(image);
    let no_tag = no_digest.rsplit_once(':').map(|(a, _)| a).unwrap_or(no_digest);
    no_tag.rsplit('/').next().unwrap_or(no_tag).to_string()
}

/// Install ANY container/system as a ceapp from an `oci:<image>` source (§8.3 — "homebrew for the mesh").
/// Synthesizes a minimal oci manifest and records it; the image is pulled lazily by ce-container on first
/// run. No publish loop needed — this is how a legacy system becomes a ceapp you can run anywhere.
async fn install_oci_uri(image: &str, store: &ce_appmgr::Store) -> Result<()> {
    store.ensure()?;
    let name = oci_app_name(image);
    if name.is_empty() {
        return Err(anyhow!("could not derive an app name from oci image '{image}'"));
    }
    let toml = format!(
        "[app]\nname = \"{name}\"\nversion = \"0.0.0\"\nruntime = \"oci\"\n\n[oci]\nimage = \"{image}\"\n"
    );
    let m = ce_appmgr::AppManifest::parse(&toml)?;
    let rec =
        ce_appmgr::InstalledApp { manifest: m.clone(), target: ce_appmgr::host_target(), digest: None };
    store.record(&rec)?;
    #[cfg(unix)]
    {
        let shim = app_shim_name(&m);
        store.write_shim(&shim, &m.app.name)?;
    }
    println!("installed {name} [oci {image}] (image pulled on first run). Run it: ce app run {name}");
    println!("Ensure {} is on PATH.", store.bin_dir().display());
    Ok(())
}

/// The concrete targets a fan-out placement expands to. `fleet=mine` = every paired device in the
/// wallet (each already holds an owner-rooted capability for that device), installed alongside this
/// host. Returns `None` for placements that resolve to a single node (`node=`/`tag=`/`nearest`/other
/// fleets), which install on exactly one target.
fn fleet_targets(
    data_dir: &std::path::Path,
    placement: &ce_appmgr::Placement,
) -> Result<Option<Vec<String>>> {
    // These placements fan out to a SET of devices (this host + the matching paired devices), unlike
    // node/tag/capability/nearest which pick a single best node.
    match placement {
        ce_appmgr::Placement::Fleet(name) if name == "mine" => {
            let wallet = load_wallet(&data_dir.to_path_buf());
            let members: Vec<String> = wallet.entries.keys().cloned().collect();
            if members.is_empty() {
                return Err(anyhow!(
                    "fleet=mine is empty: no paired devices in the wallet (add one with `ce wallet add`)"
                ));
            }
            Ok(Some(members))
        }
        // `workspace=personal` is every paired device (the default personal scope); a named workspace is
        // the devices tagged with it.
        ce_appmgr::Placement::Workspace(ws) => {
            let wallet = load_wallet(&data_dir.to_path_buf());
            let members: Vec<String> = if ws == "personal" {
                wallet.entries.keys().cloned().collect()
            } else {
                wallet.entries.iter().filter(|(_, e)| e.workspaces.contains(ws)).map(|(k, _)| k.clone()).collect()
            };
            if members.is_empty() {
                return Err(anyhow!("workspace '{ws}' has no devices (enrol one, or `ce wallet add`)"));
            }
            Ok(Some(members))
        }
        // Every paired device enrolled in the org.
        ce_appmgr::Placement::Org(org) => {
            let wallet = load_wallet(&data_dir.to_path_buf());
            let members: Vec<String> =
                wallet.entries.iter().filter(|(_, e)| e.orgs.contains(org)).map(|(k, _)| k.clone()).collect();
            if members.is_empty() {
                return Err(anyhow!("org '{org}' has no enrolled devices in your wallet"));
            }
            Ok(Some(members))
        }
        _ => Ok(None),
    }
}

/// Install one app on one remote target: oci apps ship as a job via `mesh_deploy_oci`; native/wasm
/// apps install + supervise on the host via the remote appmgr agent (`/mesh-app-install`).
async fn remote_install_one(
    name: &str,
    registry: &str,
    version: &str,
    image: Option<String>,
    placement: &ce_appmgr::Placement,
    data_dir: &std::path::Path,
) -> Result<()> {
    match image {
        Some(img) => mesh_deploy_oci(name, version, &img, placement, data_dir).await,
        None => mesh_app_install_one(name, registry, placement, data_dir).await,
    }
}

/// Ship a native/wasm ceapp install to a target node via `/mesh-app-install` (capability-authed).
/// The target runs the appmgr install flow and enables any declared daemon; the local node only
/// packages and forwards the request with the wallet's capability for that device.
async fn mesh_app_install_one(
    name: &str,
    registry: &str,
    placement: &ce_appmgr::Placement,
    data_dir: &std::path::Path,
) -> Result<()> {
    let target = match placement {
        ce_appmgr::Placement::Node(id) => id.clone(),
        ce_appmgr::Placement::Local => {
            return Err(anyhow!("internal: local placement reached mesh_app_install_one"));
        }
        other => resolve_placement_node(other, &read_api_token(data_dir)).await?,
    };
    let (node_id_hex, cap) = resolve_target(&data_dir.to_path_buf(), &target)?;
    let api_token = read_api_token(data_dir);
    let client = api_client(&api_token);
    let body = serde_json::json!({
        "node_id": node_id_hex,
        "registry": registry,
        "app": name,
        "grant": cap,
    });
    let resp = client
        .post("http://127.0.0.1:8844/mesh-app-install")
        .json(&body)
        .send()
        .await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(anyhow!("mesh-app-install failed ({status}): {text}"));
    }
    let result: serde_json::Value = resp.json().await?;
    let ver = result["version"].as_str().unwrap_or("?");
    println!("installed {name} {ver} on node={node_id_hex} (native, via remote appmgr)");
    Ok(())
}

/// The oci image for a manifest, or a clear error for tiers that can't yet be
/// placed on the mesh (native/wasm global install needs the remote agent path).
fn oci_image_or_err(m: &ce_appmgr::AppManifest) -> Result<String> {
    if m.app.runtime != ce_appmgr::Runtime::Oci {
        return Err(anyhow!(
            "global placement currently supports oci apps (postgres, ffmpeg, ...); \
             '{}' is {:?} — install it locally with --on self, or publish an oci build",
            m.app.name,
            m.app.runtime
        ));
    }
    m.oci
        .as_ref()
        .map(|o| o.image.clone())
        .ok_or_else(|| anyhow!("oci manifest missing [oci].image"))
}

/// Ship an oci app to a target node via the node's `/mesh-deploy` primitive
/// (capability-authed), then register the instance in ce-hub. Only explicit
/// `node=<id>` placement is wired; tag/fleet/nearest need atlas-based selection.
async fn mesh_deploy_oci(
    app_name: &str,
    version: &str,
    image: &str,
    placement: &ce_appmgr::Placement,
    data_dir: &std::path::Path,
) -> Result<()> {
    let target = match placement {
        ce_appmgr::Placement::Node(id) => id.clone(),
        ce_appmgr::Placement::Local => {
            return Err(anyhow!("internal: local placement reached mesh_deploy_oci"));
        }
        // tag/fleet/nearest: pick a node from the live atlas.
        other => resolve_placement_node(other, &read_api_token(data_dir)).await?,
    };
    let (node_id_hex, cap) = resolve_target(&data_dir.to_path_buf(), &target)?;
    let api_token = read_api_token(data_dir);
    let client = api_client(&api_token);
    // Conservative default envelope; a 1-credit bid keeps the directed deploy cheap.
    let bid = parse_credits("1")?.to_string();
    let body = serde_json::json!({
        "node_id": node_id_hex,
        "image": image,
        "cmd": Vec::<String>::new(),
        "cpu_cores": ce_appmgr::run::DEFAULT_CPU_CORES,
        "mem_mb": ce_appmgr::run::DEFAULT_MEM_MB,
        "duration_secs": 3600u64,
        "bid": bid,
        "grant": cap,
    });
    let resp = client
        .post("http://127.0.0.1:8844/mesh-deploy")
        .json(&body)
        .send()
        .await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(anyhow!("mesh-deploy failed ({status}): {text}"));
    }
    let result: serde_json::Value = resp.json().await?;
    let job_id = result["job_id"].as_str().unwrap_or("?");
    println!("deployed {app_name} {version} on node={node_id_hex} (oci {image}, job {job_id})");

    // Best-effort: record the remote instance in ce-hub's global registry.
    let hub = ce_appmgr::HubInstances::new("https://ce-net.com");
    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let rec = ce_appmgr::InstanceRecord {
        id: ce_appmgr::InstanceRecord::make_id(&node_id_hex, app_name, 0),
        app: app_name.to_string(),
        version: version.to_string(),
        node_id: node_id_hex.clone(),
        runtime: ce_appmgr::Runtime::Oci,
        placement: placement.clone(),
        health: ce_appmgr::Health::Starting,
        started_unix: started,
        metrics: serde_json::Value::Null,
    };
    if let Err(e) = hub.register(&rec).await {
        eprintln!("note: ce-hub registration for the remote instance failed (continuing): {e}");
    }
    Ok(())
}

/// The single supervisor: keep every enabled daemon running and registered in
/// ce-hub's global instance registry. Replaces per-app launchd/systemd plists.
///
/// Native daemons are spawned as host processes and restarted per their policy;
/// oci daemons are launched (detached) via ce-container. ce-hub registration is
/// best-effort — a missing hub logs a warning but never stops supervision.
async fn run_supervisor(
    store: &ce_appmgr::Store,
    data_dir: &std::path::Path,
    hub_url: &str,
    once: bool,
    interval: u64,
) -> Result<()> {
    use std::collections::HashMap;
    let hub = ce_appmgr::HubInstances::new(hub_url);
    let identity = Identity::load_or_generate(&data_dir.join("identity"))?;
    let node_hex = identity.node_id_hex();

    // Native children we own, keyed by app name. (oci daemons are tracked by Docker.)
    let mut children: HashMap<String, std::process::Child> = HashMap::new();

    loop {
        let daemons = ce_appmgr::enabled_daemons(store)?;
        // CAPABILITY ADVERTISEMENT: publish the union of supervised apps' `[app].provides` to a file the
        // node reads each capacity broadcast, so this node's atlas tags include app-provided capabilities
        // (e.g. ce-serve installed -> `http-ingress`). That's how capability-routed placement finds it —
        // no hardcoding of any specific app/edge in the node.
        {
            let mut provided: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
            for app in &daemons {
                for c in &app.manifest.app.provides {
                    provided.insert(c.clone());
                }
            }
            let body: String = provided.into_iter().map(|c| format!("{c}\n")).collect();
            let _ = std::fs::write(data_dir.join("extra-capabilities"), body);
        }
        for app in &daemons {
            let name = app.manifest.app.name.clone();
            let version = app.manifest.app.version.to_string();
            let policy = ce_appmgr::daemon_policy(&app.manifest);

            // Phase 1: classify a tracked native child without holding the borrow
            // across the `children.remove`/await below.
            enum Reap {
                Running,
                Exited(i32),
                WaitErr,
                Untracked,
            }
            let reap = match children.get_mut(&name) {
                Some(child) => match child.try_wait() {
                    Ok(Some(status)) => Reap::Exited(status.code().unwrap_or(1)),
                    Ok(None) => Reap::Running,
                    Err(e) => {
                        eprintln!("daemon '{name}': wait failed: {e}");
                        Reap::WaitErr
                    }
                },
                None => Reap::Untracked,
            };
            let iid = ce_appmgr::InstanceRecord::make_id(&node_hex, &name, 0);
            match reap {
                Reap::Running => {
                    let _ = hub
                        .heartbeat(&iid, ce_appmgr::Health::Healthy, serde_json::json!({}))
                        .await;
                    continue;
                }
                Reap::WaitErr => continue,
                Reap::Exited(code) => {
                    children.remove(&name);
                    let _ = hub
                        .heartbeat(
                            &iid,
                            ce_appmgr::Health::Unhealthy,
                            serde_json::json!({ "exit_code": code }),
                        )
                        .await;
                    let restart = policy
                        .as_ref()
                        .map(|p| p.restart.should_restart(code))
                        .unwrap_or(false);
                    if !restart {
                        println!("daemon '{name}' exited ({code}); not restarting");
                        continue;
                    }
                    println!("daemon '{name}' exited ({code}); restarting");
                }
                Reap::Untracked => {}
            }

            // Not running — start it with the manifest's [daemon].args (e.g. `agent`), so a
            // multi-command native binary launches in daemon mode, not its bare CLI mode.
            let plan = ce_appmgr::plan_run(store, app, ce_appmgr::daemon_args(&app.manifest))?;
            match plan {
                ce_appmgr::RunPlan::Native { bin, args } => {
                    if !bin.exists() {
                        eprintln!("daemon '{name}': artifact missing at {}", bin.display());
                        continue;
                    }
                    // SCOPED IDENTITY, not env config: mint this daemon's per-instance capability (its
                    // authority derived from the manifest `[deps]`) and hand it over as CE_INSTANCE_TOKEN.
                    // The app uses that token to read its config + secrets from ce-iam WITHIN ITS SCOPE —
                    // config/secrets never live in plaintext env or in the published manifest.
                    let token = mint_ctl_token(&identity, &name);
                    let caller = caller_context_for(&app.manifest, &name);
                    let _ = write_ctl_token(data_dir, &token, &caller);
                    // If the manifest declares `[daemon].secrets`, launch the daemon THROUGH
                    // `ce-iam secret use --ns app:<name> <names> -- <bin> <args>`, so ce-iam injects those
                    // values (from its scoped vault) as env at spawn. The values live in ce-iam, never in
                    // the manifest, on disk, or in a stored env. No secrets declared -> spawn directly.
                    let secrets = ce_appmgr::daemon_secrets(&app.manifest);
                    let mut cmd = if secrets.is_empty() {
                        let mut c = std::process::Command::new(&bin);
                        c.args(&args);
                        c
                    } else {
                        let mut c = std::process::Command::new("ce-iam");
                        c.arg("secret").arg("use").arg("--ns").arg(format!("app:{name}"));
                        for s in &secrets {
                            c.arg(s);
                        }
                        c.arg("--").arg(&bin).args(&args);
                        c
                    };
                    cmd.env("CE_INSTANCE_TOKEN", &token);
                    match cmd.spawn() {
                        Ok(child) => {
                            children.insert(name.clone(), child);
                            register_instance(&hub, &node_hex, &name, &version, "native").await;
                            println!("started daemon '{name}' (native)");
                        }
                        Err(e) => eprintln!("daemon '{name}': spawn failed: {e}"),
                    }
                }
                ce_appmgr::RunPlan::Oci { image, cmd, env, cpu_cores, mem_mb, daemon: _, .. } => {
                    let node_id = identity.node_id();
                    match ce_container::ContainerManager::new(node_id).await {
                        Ok(cm) => {
                            let job_id: [u8; 32] =
                                Sha256::digest(format!("{name}:{version}").as_bytes()).into();
                            let spec = ce_container::JobSpec {
                                job_id,
                                image: image.clone(),
                                cmd,
                                env,
                                cpu_cores,
                                mem_mb,
                                payer: node_id,
                            };
                            match cm.launch_job(&spec).await {
                                Ok(cid) => {
                                    register_instance(&hub, &node_hex, &name, &version, "oci").await;
                                    println!("started daemon '{name}' (oci {image}, container {cid})");
                                }
                                Err(e) => eprintln!("daemon '{name}': launch failed: {e}"),
                            }
                        }
                        Err(e) => eprintln!("daemon '{name}': Docker unavailable: {e}"),
                    }
                }
                other => {
                    eprintln!("daemon '{name}': unsupported runtime for supervision: {other:?}");
                }
            }
        }

        if once {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
    }
    Ok(())
}

/// Register a started instance with ce-hub's global registry (best-effort).
async fn register_instance(
    hub: &ce_appmgr::HubInstances,
    node_hex: &str,
    name: &str,
    version: &str,
    runtime: &str,
) {
    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let runtime = match runtime {
        "oci" => ce_appmgr::Runtime::Oci,
        "wasm" => ce_appmgr::Runtime::Wasm,
        "recipe" => ce_appmgr::Runtime::Recipe,
        _ => ce_appmgr::Runtime::Native,
    };
    let rec = ce_appmgr::InstanceRecord {
        id: ce_appmgr::InstanceRecord::make_id(node_hex, name, 0),
        app: name.to_string(),
        version: version.to_string(),
        node_id: node_hex.to_string(),
        runtime,
        placement: ce_appmgr::Placement::Local,
        health: ce_appmgr::Health::Starting,
        started_unix: started,
        metrics: serde_json::Value::Null,
    };
    if let Err(e) = hub.register(&rec).await {
        eprintln!("warning: ce-hub registration for '{name}' failed (continuing): {e}");
    }
}

/// Execute a [`ce_appmgr::RunPlan`] in the appropriate runtime. Native spawns a host
/// process; oci runs in a sandboxed (gVisor when available) container via
/// `ce-container`; wasm/recipe are deferred. Propagates the child's exit code.
async fn run_app(
    name: &str,
    version: &str,
    plan: ce_appmgr::RunPlan,
    data_dir: &std::path::Path,
) -> Result<()> {
    use ce_appmgr::RunPlan;
    match plan {
        RunPlan::Native { bin, args } => {
            if !bin.exists() {
                return Err(anyhow!(
                    "artifact for '{name}' is missing at {} — reinstall: ce app install {name}",
                    bin.display()
                ));
            }
            // Spawn the materialized binary, inheriting stdio, and propagate its exit.
            let status = std::process::Command::new(&bin)
                .args(&args)
                .status()
                .with_context(|| format!("spawning {}", bin.display()))?;
            std::process::exit(status.code().unwrap_or(1));
        }
        RunPlan::Oci { image, cmd, env, cpu_cores, mem_mb, gvisor: _, daemon, net: _ } => {
            // ce-container detects and prefers gVisor itself; net/fs profile
            // enforcement is layered on with the sandbox-hardening milestone.
            let identity = Identity::load_or_generate(&data_dir.join("identity"))?;
            let node_id = identity.node_id();
            let cm = ce_container::ContainerManager::new(node_id)
                .await
                .context("Docker is not available — oci apps need a running Docker (gVisor recommended)")?;
            if daemon {
                // Long-running system: launch detached. job_id is derived from the
                // app coordinates so a re-run targets the same logical instance.
                let job_id: [u8; 32] =
                    Sha256::digest(format!("{name}:{version}").as_bytes()).into();
                let spec = ce_container::JobSpec {
                    job_id,
                    image: image.clone(),
                    cmd,
                    env,
                    cpu_cores,
                    mem_mb,
                    payer: node_id,
                };
                let cid = cm.launch_job(&spec).await?;
                println!("started {name} {version} (oci {image}, container {cid})");
            } else {
                // One-shot CLI: run, stream output, propagate exit.
                let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("/"));
                let spec = ce_container::ExecSpec { image, cmd, cwd: None };
                let (out, err, code) =
                    ce_container::exec_in_container(&cm.docker, &spec, &home).await?;
                print!("{out}");
                eprint!("{err}");
                std::process::exit(code as i32);
            }
            Ok(())
        }
        RunPlan::Wasm { module, args } => {
            if !module.exists() {
                return Err(anyhow!(
                    "wasm module for '{name}' is missing at {} — reinstall: ce app install {name}",
                    module.display()
                ));
            }
            let wasm = std::fs::read(&module)
                .with_context(|| format!("reading wasm module {}", module.display()))?;
            // Args reach the module on stdin (one per line); ce-wasm runs the WASI command
            // fuel- and memory-bounded. Run on a blocking thread (CPU-bound).
            let engine = ce_wasm::new_engine()?;
            let stdin = args.join("\n").into_bytes();
            let (code, out) = tokio::task::spawn_blocking(move || {
                ce_wasm::execute_command(&engine, &wasm, 10_000_000_000, 512, stdin)
            })
            .await
            .context("wasm execution task")??;
            use std::io::Write;
            let _ = std::io::stdout().write_all(&out);
            std::process::exit(code);
        }
        RunPlan::Recipe { source } => Err(anyhow!(
            "recipe apps build on the relay and promote to a native artifact — \
             run path pending (source {source})"
        )),
    }
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
