mod api;
pub mod chain_actor;

/// Re-export the capability verifier so node consumers can use `ce_node::capability::*`
/// (the canonical home is the standalone `ce-cap` crate, also usable by apps).
pub use ce_cap as capability;

pub use chain_actor::{ChainHandle, ChainStatusSnap, SyncSnap, spawn_chain_actor};

/// Derive the libp2p PeerId string from a CE identity (same Ed25519 key, different encoding).
pub fn peer_id_from_identity(identity: &ce_identity::Identity) -> anyhow::Result<String> {
    ce_mesh::peer_id_from_secret(identity.secret_bytes()).map(|p| p.to_string())
}

use anyhow::Result;
use bollard::Docker;
use ce_chain::{Block, Chain, ChunkReceipt, Tx, TxKind, verify_chunk_receipt_sig};
use ce_container::{ContainerManager, JobSpec};
use ce_runtime::Runtime;
use ce_identity::{Identity, NodeId};
use ce_mesh::{Mesh, MeshEvent, MeshHandle, RpcRequest, RpcResponse, peer_id_from_node_id};
use ce_protocol::{CellSignal, Capability};
use directories::ProjectDirs;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, mpsc, Mutex};
use tracing::{debug, info, warn};

/// Max number of recently-validated signals retained for GET /signals.
const SIGNAL_RING_CAPACITY: usize = 100;

/// Must match MAX_BLOCKS_PER_SYNC in ce-mesh. Used when serving sync responses.
const MAX_BLOCKS_PER_SYNC: usize = 10_000;

pub(crate) type SignalRing = Arc<Mutex<VecDeque<CellSignal>>>;

/// Capacity snapshot cached from incoming peer capacity signals.
#[derive(Debug, Clone, Serialize)]
pub struct PeerCapacity {
    pub cpu_cores: u32,
    pub mem_mb: u32,
    pub running_jobs: u32,
    pub last_seen_secs: u64,
    /// Capability-derived self-tags the node advertises (e.g. "gpu", "docker",
    /// "linux", "x86_64", "manycore", "highmem"). These describe what work the
    /// node can realistically perform and let any peer select hosts by capability.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Atlas: maps NodeId → latest capacity snapshot. Updated from incoming CEP-1 capacity signals.
pub(crate) type Atlas = Arc<Mutex<HashMap<NodeId, PeerCapacity>>>;

/// A smoothed round-trip-time edge to one peer — the ground-truth edges of the network graph
/// (see `docs/compute-fabric.md`). Higher layers (the `ce-graph` SDK) build Vivaldi coordinates and
/// topology on top; the node only carries this transport-intrinsic measurement.
#[derive(Debug, Clone, Serialize)]
pub struct RttStat {
    /// Smoothed round-trip time in milliseconds (EWMA over samples).
    pub rtt_ms: f64,
    /// Number of samples folded into the estimate.
    pub samples: u64,
    /// Unix seconds of the most recent sample.
    pub last_seen_secs: u64,
}

/// NetGraph: maps a connected peer (libp2p PeerId, hex string) → its latest smoothed RTT. The thin,
/// transport-intrinsic latency primitive; coordinate embedding and graph assembly live in apps/SDK.
pub(crate) type NetGraph = Arc<Mutex<HashMap<String, RttStat>>>;

fn push_signal(ring: &mut VecDeque<CellSignal>, sig: CellSignal) {
    if ring.len() >= SIGNAL_RING_CAPACITY {
        ring.pop_front();
    }
    ring.push_back(sig);
}

// ----- Pending TX pool -----

#[derive(Clone)]
pub(crate) struct TxPool(Arc<Mutex<HashMap<[u8; 32], Tx>>>);

impl TxPool {
    fn new() -> Self {
        TxPool(Arc::new(Mutex::new(HashMap::new())))
    }

    pub(crate) async fn add(&self, tx: Tx) {
        self.0.lock().await.insert(tx.id(), tx);
    }

    async fn drain(&self, max: usize) -> Vec<Tx> {
        let mut map = self.0.lock().await;
        let keys: Vec<[u8; 32]> = map.keys().copied().take(max).collect();
        keys.into_iter().filter_map(|k| map.remove(&k)).collect()
    }

    async fn remove_included(&self, block: &Block) {
        let mut map = self.0.lock().await;
        for tx in &block.transactions {
            map.remove(&tx.id());
        }
    }
}

// ----- Job lifecycle tracking -----

#[derive(Debug, Clone, PartialEq)]
pub enum CeJobStatus {
    /// Bid broadcast; no host has accepted yet.
    Pending,
    /// Container is running on this node.
    Running,
    /// Container exited; waiting for payer to co-sign the settlement.
    AwaitingSettlement,
    /// JobSettle tx submitted to pool and broadcast.
    Settled,
    /// Unrecoverable error (e.g., image pull failed).
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct JobRecord {
    pub job_id: [u8; 32],
    pub payer: NodeId,
    /// Docker container ID assigned when the container starts.
    pub container_id: Option<String>,
    pub status: CeJobStatus,
    /// Payer co-signature over payer_settle_bytes(job_id, cost), supplied via POST /jobs/:id/settle.
    pub payer_sig: Option<[u8; 64]>,
    /// Agreed settlement cost, set alongside payer_sig.
    pub cost: Option<u128>,
    /// Original bid amount from the JobBid tx. Used for heartbeat rate calculation.
    pub bid: u128,
    /// Expected job duration in seconds. Used for heartbeat rate calculation.
    pub duration_secs: u64,
}

/// Shared job store: maps CE job_id ([u8;32]) → job record.
pub(crate) type JobStore = Arc<Mutex<HashMap<[u8; 32], JobRecord>>>;

/// Provider-side data-layer accounting: channel_id → cumulative value already served on it.
/// Each priced chunk requires a receipt whose cumulative exceeds this by at least the chunk's
/// cost; the new cumulative is then recorded. In-memory (resets on restart, which can only
/// under-charge, never over-charge); the host still closes the channel with the highest receipt.
pub(crate) type DataServedLedger = Arc<Mutex<HashMap<[u8; 32], u128>>>;

/// A directed application message received from a mesh peer (app-messaging inbox item). `from` is
/// the Noise-authenticated sender, so the app can trust who sent it; `payload` is opaque to CE.
#[derive(Debug, Clone, Serialize)]
pub struct AppMessage {
    /// Authenticated sender NodeId (hex).
    pub from: String,
    /// App-chosen topic namespace.
    pub topic: String,
    /// Opaque payload, hex-encoded for JSON transport.
    pub payload_hex: String,
    /// Unix seconds when this node received it.
    pub received_at: u64,
    /// Set when this is a request expecting a reply (Stage 3): pass it to `/mesh/reply` to answer.
    /// `None` for fire-and-forget messages and pub/sub.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_token: Option<u64>,
}

/// Bounded ring of recently-received app messages (best-effort snapshot for `GET /mesh/messages`).
/// Apps consume the SSE stream to avoid missing messages; this is for polling/debugging.
pub(crate) type AppInbox = Arc<Mutex<VecDeque<AppMessage>>>;

/// Relay-side per-channel accounting: channel_id → (first_receipt_secs, paid_cumulative). A relay
/// charges per minute of relay time; a receipt must cover `price * minutes_elapsed`. In-memory
/// (resets on restart, which can only under-charge); the relay closes the channel to collect.
#[derive(Debug, Clone, Default)]
pub struct RelayAccount {
    pub first_receipt_secs: u64,
    pub paid_cumulative: u128,
}
pub(crate) type RelayMeter = Arc<Mutex<HashMap<[u8; 32], RelayAccount>>>;

const APP_INBOX_CAPACITY: usize = 200;

// ----- Node config -----

pub struct NodeConfig {
    pub listen_port: u16,
    pub bootstrap_peers: Vec<String>,
    /// Circuit relay nodes (multiaddrs with /p2p/<peer-id>). On connect, the node
    /// listens on their circuit address to become reachable through NAT.
    pub relay_peers: Vec<String>,
    pub data_dir: PathBuf,
    pub api_port: u16,
    /// Address the HTTP API binds to. Defaults to `127.0.0.1` (loopback only). `0.0.0.0` exposes
    /// it on all interfaces and is only safe behind a firewall (the api.token still gates writes).
    pub api_bind: String,
    /// Disable the mining loop. Tests that need a non-mining observer set this to `false`.
    pub mine: bool,
    /// Mining loop interval in seconds. Default 10; set lower in tests for speed.
    pub mining_interval_secs: u64,
    /// How many recent blocks to keep after pruning. `None` = archive (never prune).
    /// Light nodes set this to `PRUNE_KEEP_BLOCKS`. Relay and desktops use `None`.
    pub prune_keep: Option<u64>,
    /// Fraction of history segments to volunteer to hold in local archive (0.0–1.0).
    /// Light nodes use ARCHIVE_DENSITY (~0.15); archive nodes should set 1.0.
    /// Together across all nodes this achieves distributed redundancy of the full history.
    pub archive_density: f64,
    /// Disable mDNS local peer discovery. Set to true in tests to prevent in-process
    /// nodes from connecting to any live local ce node via multicast.
    pub disable_local_discovery: bool,
    /// Serve the HTTP API over TLS (cert keyed by the node identity; clients pin the NodeId).
    pub tls: bool,
    /// Price (base units) charged per byte served from the data layer. `0` = free/open serving
    /// (the default). When non-zero, a `FetchChunk` must carry a payment-channel receipt whose
    /// cumulative covers the running cost, or the provider refuses to serve.
    pub data_price_per_byte: u128,
    /// If set, this node advertises itself as a relay charging this many base units per minute
    /// (`0` = a free, discoverable relay). `None` (default) = not advertised as a relay. Clients
    /// open a payment channel with the relay and stream `RelayReceipt`s to stay paid-up.
    pub relay_price_per_min: Option<u128>,
    /// Ephemeral / in-memory chain: skip per-block disk persistence (the chain lives in RAM). The
    /// node still syncs and gossips with persisting nodes (same protocol); snapshot to disk on
    /// demand via `POST /chain/save`. Saves disk I/O for throwaway / test fleets.
    pub ephemeral: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            listen_port: 0,
            bootstrap_peers: vec![],
            relay_peers: vec![],
            data_dir: Self::default_data_dir(),
            api_port: 0,
            api_bind: "127.0.0.1".to_string(),
            mine: true,
            mining_interval_secs: 10,
            prune_keep: None,
            archive_density: ce_chain::ARCHIVE_DENSITY,
            disable_local_discovery: false,
            tls: false,
            data_price_per_byte: 0,
            relay_price_per_min: None,
            ephemeral: false,
        }
    }
}

impl NodeConfig {
    pub fn default_data_dir() -> PathBuf {
        ProjectDirs::from("", "", "ce")
            .map(|d| d.data_dir().to_owned())
            .unwrap_or_else(|| PathBuf::from(".ce"))
    }
}

// ----- Node -----

pub struct Node {
    identity: Arc<Identity>,
    chain: ChainHandle,
    #[allow(dead_code)]
    mesh_handle: MeshHandle,
    #[allow(dead_code)]
    signals: SignalRing,
    #[allow(dead_code)]
    atlas: Atlas,
    config: NodeConfig,
}

impl Node {
    pub async fn start(config: NodeConfig) -> Result<Self> {
        std::fs::create_dir_all(&config.data_dir)?;
        let identity_dir = config.data_dir.join("identity");
        let chain_path = config.data_dir.join("chain").join("chain.json");

        let identity = Arc::new(Identity::load_or_generate(&identity_dir)?);
        info!("node id: {}", identity.node_id_hex());

        let raw_chain = Chain::load_or_genesis(&chain_path);
        info!("chain height: {}", raw_chain.height());

        let chain = spawn_chain_actor(raw_chain);

        let docker = Docker::connect_with_socket_defaults().ok();
        let docker_available = docker.is_some();
        if docker.is_none() {
            warn!("Docker unavailable — exec RPCs and job routes will be disabled");
        }

        // Execution-runtime registry (ce-runtime seam). Today: Docker. ce-wasm plugs in here.
        // The node dispatches each job to the first runtime that can run its Workload.
        let mut runtimes: Vec<Arc<dyn Runtime>> = Vec::new();
        if docker_available {
            match ce_container::DockerRuntime::new(identity.node_id()).await {
                Ok(rt) => runtimes.push(Arc::new(rt)),
                Err(e) => warn!("docker runtime init: {e}"),
            }
        }
        // WASM runs everywhere (no external daemon), so every node offers it. Modules are
        // resolved from the content-addressed blob store under the data dir.
        let blobs_dir = config.data_dir.join("blobs");
        let _ = std::fs::create_dir_all(&blobs_dir);
        match ce_wasm::WasmRuntime::new(blobs_dir) {
            Ok(rt) => runtimes.push(Arc::new(rt)),
            Err(e) => warn!("wasm runtime init: {e}"),
        }

        // Pre-execution screening seam (ce-guard). No ce-guardian app is wired yet, so default to a
        // logged pass-through: deploys keep working and the chokepoint is in place. A production node
        // configures a real screener (the fail-closed DenyAllGuardian is the conservative default).
        let guardian: Arc<dyn ce_guard::Guardian> = Arc::new(ce_guard::AllowAllGuardian);
        warn!("guardian: no screener configured — passing all workloads (wire the ce-guardian app)");

        // Capability self-tags, computed once and shared by the capacity broadcast (what we
        // advertise) and both auth enforcement points (what grant selectors match against),
        // so the advertised set and the enforced set can never diverge.
        let self_tags = capability_tags(docker_available, num_cpus() as u32, available_mem_mb());

        let (mesh, mesh_handle, mesh_rx, tunnel_control) = if config.disable_local_discovery {
            Mesh::new_isolated(identity.secret_bytes())?
        } else {
            Mesh::new(identity.secret_bytes())?
        };

        let mut mesh = mesh;
        for peer in &config.bootstrap_peers {
            if let Err(e) = mesh.add_bootstrap(peer) {
                warn!("bootstrap {peer}: {e}");
            }
        }
        for relay in &config.relay_peers {
            if let Err(e) = mesh.add_relay(relay) {
                warn!("relay {relay}: {e}");
            }
        }

        let pool = TxPool::new();
        let signals: SignalRing =
            Arc::new(Mutex::new(VecDeque::with_capacity(SIGNAL_RING_CAPACITY)));
        let (signal_tx, _signal_rx0) = broadcast::channel::<CellSignal>(64);
        let (block_tx, _block_rx0) = broadcast::channel::<Block>(32);
        let (tx_tx, _tx_rx0) = broadcast::channel::<Tx>(256);
        let app_inbox: AppInbox = Arc::new(Mutex::new(VecDeque::with_capacity(APP_INBOX_CAPACITY)));
        let (app_msg_tx, _app_rx0) = broadcast::channel::<AppMessage>(128);
        let send_nonce = Arc::new(AtomicU64::new(0));
        let job_store: JobStore = Arc::new(Mutex::new(HashMap::new()));
        let atlas: Atlas = Arc::new(Mutex::new(HashMap::new()));
        let netgraph: NetGraph = Arc::new(Mutex::new(HashMap::new()));

        let (bid_notify_tx, bid_notify_rx) = mpsc::channel::<Tx>(64);
        let (settle_notify_tx, settle_notify_rx) = mpsc::channel::<()>(16);

        let node = Self {
            identity: identity.clone(),
            chain: chain.clone(),
            mesh_handle: mesh_handle.clone(),
            signals: signals.clone(),
            atlas: atlas.clone(),
            config,
        };

        let listen_port = node.config.listen_port;
        tokio::spawn(async move {
            if let Err(e) = mesh.run(listen_port).await {
                warn!("mesh exited: {e}");
            }
        });

        {
            let snap = chain.sync_snap().await;
            let _ = mesh_handle
                .announce_height(identity.node_id(), snap.height, snap.tip_hash, snap.oldest)
                .await;
        }

        // Re-announce every locally-held chunk as a DHT provider record. Provider records expire,
        // so this runs on each startup; new chunks are announced as they are stored (put_blob).
        {
            let handle = mesh_handle.clone();
            let blobs_dir = node.config.data_dir.join("blobs");
            tokio::spawn(async move {
                let entries = match std::fs::read_dir(&blobs_dir) {
                    Ok(e) => e,
                    Err(_) => return,
                };
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let Some(name) = name.to_str() else { continue };
                    let mut cid = [0u8; 32];
                    if name.len() == 64 && hex::decode_to_slice(name, &mut cid).is_ok() {
                        let _ = handle.provide_chunk(cid).await;
                    }
                }
            });
        }

        // Shared "caught up with the network" flag: set by the mesh loop, read by the mining loop
        // so a fresh node syncs the canonical chain before mining instead of forking its own.
        // A node with NO bootstrap peers is solo — nothing to sync from — so it may mine at once.
        // A node WITH bootstrap peers waits until it has caught up (or the grace elapses if those
        // peers turn out to be unreachable / not ahead).
        let synced = Arc::new(std::sync::atomic::AtomicBool::new(
            node.config.bootstrap_peers.is_empty(),
        ));

        // Ephemeral mode keeps the chain in RAM: the background loops skip per-block disk saves.
        let persist = !node.config.ephemeral;

        if node.config.mine {
            let chain2 = chain.clone();
            let identity2 = identity.clone();
            let handle2 = mesh_handle.clone();
            let chain_path2 = node.config.data_dir.join("chain").join("chain.json");
            let pool2 = pool.clone();
            let interval = node.config.mining_interval_secs;
            let block_tx2 = block_tx.clone();
            let synced2 = synced.clone();
            tokio::spawn(async move {
                mining_loop(chain2, identity2, handle2, chain_path2, persist, pool2, interval, block_tx2, synced2)
                    .await;
            });
        }

        {
            let chain2 = chain.clone();
            let chain_path2 = node.config.data_dir.join("chain").join("chain.json");
            let handle2 = mesh_handle.clone();
            let node_id = identity.node_id();
            let pool2 = pool.clone();
            let signals2 = signals.clone();
            let signal_tx2 = signal_tx.clone();
            let block_tx3 = block_tx.clone();
            let tx_tx3 = tx_tx.clone();
            let atlas2 = atlas.clone();
            let netgraph2 = netgraph.clone();
            let data_dir2 = node.config.data_dir.clone();
            let docker2 = docker.clone();
            let prune_keep = node.config.prune_keep;
            let archive_density = node.config.archive_density;
            let archive_dir2 = node.config.data_dir.join("archive");
            let disable_local_discovery = node.config.disable_local_discovery;
            let self_tags2 = self_tags.clone();
            let accepted_roots2 = load_accepted_roots(&node.config.data_dir);
            let job_store_m = job_store.clone();
            let runtimes_m = runtimes.clone();
            let guardian_m = guardian.clone();
            let data_price = node.config.data_price_per_byte;
            let data_served: DataServedLedger = Arc::new(Mutex::new(HashMap::new()));
            let app_inbox2 = app_inbox.clone();
            let app_msg_tx2 = app_msg_tx.clone();
            let relay_price = node.config.relay_price_per_min;
            let relay_meter: RelayMeter = Arc::new(Mutex::new(HashMap::new()));
            tokio::spawn(async move {
                mesh_event_loop(
                    chain2,
                    mesh_rx,
                    chain_path2,
                    handle2,
                    node_id,
                    pool2,
                    signals2,
                    signal_tx2,
                    block_tx3,
                    tx_tx3,
                    bid_notify_tx,
                    atlas2,
                    netgraph2,
                    data_dir2,
                    docker2,
                    prune_keep,
                    archive_density,
                    archive_dir2,
                    disable_local_discovery,
                    self_tags2,
                    accepted_roots2,
                    job_store_m,
                    runtimes_m,
                    guardian_m,
                    data_price,
                    data_served,
                    app_inbox2,
                    app_msg_tx2,
                    relay_price,
                    relay_meter,
                    synced.clone(),
                    persist,
                )
                .await;
            });
        }

        {
            let chain2 = chain.clone();
            let identity2 = identity.clone();
            let handle2 = mesh_handle.clone();
            let chain_path2 = node.config.data_dir.join("chain").join("chain.json");
            let pool2 = pool.clone();
            let js = job_store.clone();
            tokio::spawn(async move {
                job_manager_loop(
                    chain2,
                    identity2,
                    handle2,
                    chain_path2,
                    persist,
                    pool2,
                    js,
                    bid_notify_rx,
                    settle_notify_rx,
                )
                .await;
            });
        }

        if node.config.mine {
            let identity2 = identity.clone();
            let handle2 = mesh_handle.clone();
            let job_store2 = job_store.clone();
            let send_nonce2 = send_nonce.clone();
            let self_tags2 = self_tags.clone();
            tokio::spawn(async move {
                capacity_broadcast_loop(identity2, handle2, job_store2, send_nonce2, self_tags2)
                    .await;
            });
        }

        // Tunnel: accept inbound /ce/tunnel/1 streams and splice them to local TCP, gated by a
        // `tunnel` capability (with optional allowed-ports caveat). Driven via the cloned control.
        {
            let control = tunnel_control.clone();
            let host = identity.node_id();
            let roots = Arc::new(load_accepted_roots(&node.config.data_dir));
            let tags = Arc::new(self_tags.clone());
            let chain_t = chain.clone();
            tokio::spawn(async move {
                tunnel_accept_loop(control, host, roots, tags, chain_t).await;
            });
        }

        {
            let chain2 = chain.clone();
            let identity2 = identity.clone();
            let mesh_handle2 = mesh_handle.clone();
            let signals2 = signals.clone();
            let api_port = node.config.api_port;
            let api_bind = node.config.api_bind.clone();
            let p2p_port = node.config.listen_port;
            let send_nonce2 = send_nonce.clone();
            let js = job_store.clone();
            let pool2 = pool.clone();
            let data_dir2 = node.config.data_dir.clone();
            let atlas3 = atlas.clone();
            let netgraph3 = netgraph.clone();
            let docker3 = docker.clone();
            let tunnel_control2 = tunnel_control.clone();
            let tls_seed = if node.config.tls { Some(identity.secret_bytes()) } else { None };
            tokio::spawn(async move {
                if let Err(e) = api::start(
                    chain2,
                    identity2,
                    mesh_handle2,
                    signals2,
                    signal_tx,
                    block_tx,
                    tx_tx,
                    send_nonce2,
                    api_port,
                    api_bind,
                    p2p_port,
                    js,
                    pool2,
                    settle_notify_tx,
                    data_dir2,
                    atlas3,
                    netgraph3,
                    docker3,
                    tls_seed,
                    app_inbox,
                    app_msg_tx,
                    tunnel_control2,
                )
                .await
                {
                    warn!("API server: {e}");
                }
            });
        }

        Ok(node)
    }

    pub async fn balance(&self) -> i128 {
        self.chain.balance(self.identity.node_id()).await
    }

    pub async fn any_burnable_tx(&self) -> Option<([u8; 32], u128)> {
        self.chain.any_burnable_tx().await
    }

    pub async fn any_burnable_tx_by_self(&self) -> Option<([u8; 32], u128)> {
        self.chain.any_burnable_tx_by_origin(self.identity.node_id()).await
    }

    pub async fn status(&self) -> NodeStatus {
        let snap = self.chain.sync_snap().await;
        let balance = self.chain.balance(self.identity.node_id()).await;
        let difficulty = self.chain.difficulty().await;
        let peer_id = ce_mesh::peer_id_from_secret(self.identity.secret_bytes())
            .map(|p| p.to_string())
            .unwrap_or_else(|_| "unknown".into());
        NodeStatus {
            node_id: self.identity.node_id_hex(),
            peer_id,
            height: snap.height,
            difficulty,
            balance,
            listen_port: self.config.listen_port,
            api_port: self.config.api_port,
        }
    }
}

#[derive(Debug)]
pub struct NodeStatus {
    pub node_id: String,
    /// libp2p PeerId derived from the node's Ed25519 key. Use this in bootstrap multiaddrs:
    /// /ip4/<ip>/tcp/<port>/p2p/<peer_id>
    pub peer_id: String,
    pub height: u64,
    pub difficulty: u8,
    pub balance: i128,
    pub listen_port: u16,
    pub api_port: u16,
}

// ----- Mining loop -----

async fn mining_loop(
    chain: ChainHandle,
    identity: Arc<Identity>,
    mesh_handle: MeshHandle,
    chain_path: PathBuf,
    persist: bool,
    pool: TxPool,
    poll_secs: u64,
    block_tx: broadcast::Sender<Block>,
    synced: Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::atomic::{AtomicBool, Ordering};
    let poll = std::time::Duration::from_secs(poll_secs.clamp(1, 5));
    // Pacing floor: at most one block attempt per interval. PoW dominates timing at real network
    // difficulty; this just stops a node from storming blocks while difficulty is still trivially
    // low (bootstrap / tests). The first tick fires immediately so a solo node mines right away.
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(poll_secs.max(1)));
    loop {
        ticker.tick().await;

        // Sync-before-mine: don't build on a stale tip while peers are ahead, or we'd fork our own
        // chain. The mesh loop flips `synced` once no known peer is higher (with a startup grace).
        if !synced.load(Ordering::Relaxed) {
            tokio::time::sleep(poll).await;
            continue;
        }

        let mut pending = pool.drain(100).await;

        // Build UptimeReward tx for this block's emission.
        let current_height = chain.height().await;
        let next_index = current_height + 1;
        let emission = Chain::emission_rate(next_index);
        if emission > 0 {
            let kind = TxKind::UptimeReward {
                node: identity.node_id(),
                amount: emission,
                epoch: next_index,
            };
            let data = bincode::serialize(&kind).expect("serialize UptimeReward");
            let sig = identity.sign(&data);
            pending.insert(0, Tx::new(kind, identity.node_id(), sig));
        }

        let block = chain.next_block(pending, identity.node_id()).await;

        // Proof-of-work search runs on a blocking thread (CPU-bound — never block the executor).
        // A watcher aborts the search if the chain tip advances (a peer's block arrived), so we
        // don't waste work mining a now-stale block.
        let abort = Arc::new(AtomicBool::new(false));
        let abort_w = abort.clone();
        let chain_w = chain.clone();
        let watcher = tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                if chain_w.height().await != current_height {
                    abort_w.store(true, Ordering::Relaxed);
                    break;
                }
            }
        });
        let id2 = identity.clone();
        let mined = tokio::task::spawn_blocking(move || {
            let mut b = block;
            if b.mine(&abort) {
                b.seal(&id2);
                Some(b)
            } else {
                None
            }
        })
        .await
        .ok()
        .flatten();
        watcher.abort();

        let Some(block) = mined else {
            continue; // tip advanced mid-search; rebuild on the new tip next round
        };
        info!("mined block {} (difficulty {} bits)", block.index, block.difficulty);

        if chain.append(block.clone()).await {
            pool.remove_included(&block).await;
            if persist {
                if let Err(e) = chain.save(chain_path.clone()).await {
                    warn!("save chain: {e}");
                }
            }
            let _ = block_tx.send(block.clone());
            let _ = mesh_handle.broadcast_block(&block).await;
            let snap = chain.sync_snap().await;
            let _ = mesh_handle
                .announce_height(identity.node_id(), snap.height, snap.tip_hash, snap.oldest)
                .await;
        } else {
            // Lost the race (tip moved between search and append). Brief backoff, then retry.
            tokio::time::sleep(poll).await;
        }
    }
}

// ----- Mesh event loop -----

#[allow(clippy::too_many_arguments)]
/// Load the node's accepted capability **root keys** from `<data_dir>/roots` — one 64-hex node id
/// per line (`#` comments allowed). These are the org/CA anchors a node honors in addition to its
/// own identity (which is always implicitly accepted). Missing file → empty, so self-issued
/// capabilities still work with zero config. See `docs/capabilities.md`.
pub fn load_accepted_roots(data_dir: &Path) -> Vec<NodeId> {
    let path = data_dir.join("roots");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .filter_map(|h| hex::decode(h).ok().and_then(|b| b.try_into().ok()))
        .collect()
}

// ----- TCP tunnel (TCP-over-libp2p) -----

/// Accept inbound `/ce/tunnel/1` streams and splice each to a local TCP port. Each stream begins
/// with a header — `remote_port: u16 BE`, `caps_len: u32 BE`, then the capability chain bytes — and
/// is authorized by a `tunnel` capability before any bytes are forwarded. Runs as its own task via
/// a cloned stream control (the swarm is `!Sync`).
async fn tunnel_accept_loop(
    mut control: ce_mesh::StreamControl,
    host_node_id: NodeId,
    accepted_roots: Arc<Vec<NodeId>>,
    self_tags: Arc<Vec<String>>,
    chain: ChainHandle,
) {
    use futures::StreamExt;
    let mut incoming = match control.accept(ce_mesh::TUNNEL_PROTOCOL) {
        Ok(i) => i,
        Err(e) => {
            warn!("tunnel: cannot register accept handler: {e}");
            return;
        }
    };
    while let Some((peer, stream)) = incoming.next().await {
        let roots = accepted_roots.clone();
        let tags = self_tags.clone();
        let chain = chain.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_tunnel_stream(peer, stream, host_node_id, &roots, &tags, &chain).await
            {
                debug!("tunnel stream rejected/closed: {e}");
            }
        });
    }
}

async fn handle_tunnel_stream(
    peer: ce_mesh::CePeerId,
    stream: ce_mesh::MeshStream,
    host_node_id: NodeId,
    accepted_roots: &[NodeId],
    self_tags: &[String],
    chain: &ChainHandle,
) -> anyhow::Result<()> {
    use tokio::io::AsyncReadExt;
    use tokio_util::compat::FuturesAsyncReadCompatExt;

    let mut s = stream.compat();

    // Header: remote_port (u16 BE), caps_len (u32 BE), then the capability chain bytes.
    let mut hdr = [0u8; 6];
    s.read_exact(&mut hdr).await?;
    let port = u16::from_be_bytes([hdr[0], hdr[1]]);
    let caps_len = u32::from_be_bytes([hdr[2], hdr[3], hdr[4], hdr[5]]) as usize;
    if caps_len > 64 * 1024 {
        anyhow::bail!("capability header too large");
    }
    let mut caps_bytes = vec![0u8; caps_len];
    s.read_exact(&mut caps_bytes).await?;

    // Authorize: a `tunnel` capability rooted at us / a configured root, with the requested port
    // within any allowed-ports caveat.
    let requester = ce_mesh::node_id_from_peer_id(&peer)
        .ok_or_else(|| anyhow::anyhow!("peer id is not a CE node id"))?;
    let caps = ce_cap::decode_chain_bytes(&caps_bytes)?;
    let mut revoked: std::collections::HashSet<(NodeId, u64)> = std::collections::HashSet::new();
    for link in &caps {
        if chain.is_revoked(link.cap.issuer, link.cap.nonce).await {
            revoked.insert((link.cap.issuer, link.cap.nonce));
        }
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let is_revoked = |i: &NodeId, n: u64| revoked.contains(&(*i, n));
    ce_cap::authorize(
        &host_node_id,
        accepted_roots,
        self_tags,
        now,
        &requester,
        "tunnel",
        &caps,
        &is_revoked,
    )
    .map_err(|e| anyhow::anyhow!("tunnel denied: {e}"))?;
    if let Some(leaf) = caps.last() {
        if let Some(allowed) = &leaf.cap.caveats.allowed_ports {
            if !allowed.contains(&port) {
                anyhow::bail!("tunnel to port {port} not permitted by capability");
            }
        }
    }

    // Splice to the local TCP service.
    let mut upstream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    info!("tunnel: {} -> 127.0.0.1:{port}", hex::encode(&requester[..4]));
    tokio::io::copy_bidirectional(&mut s, &mut upstream).await?;
    Ok(())
}

async fn mesh_event_loop(
    chain: ChainHandle,
    mut rx: mpsc::Receiver<MeshEvent>,
    chain_path: PathBuf,
    mesh_handle: MeshHandle,
    our_node_id: NodeId,
    pool: TxPool,
    signals: SignalRing,
    signal_tx: broadcast::Sender<CellSignal>,
    block_tx: broadcast::Sender<Block>,
    tx_tx: broadcast::Sender<Tx>,
    bid_notify_tx: mpsc::Sender<Tx>,
    atlas: Atlas,
    netgraph: NetGraph,
    data_dir: PathBuf,
    docker: Option<Docker>,
    prune_keep: Option<u64>,
    archive_density: f64,
    archive_dir: PathBuf,
    disable_local_discovery: bool,
    self_tags: Vec<String>,
    accepted_roots: Vec<NodeId>,
    job_store: JobStore,
    runtimes: Vec<Arc<dyn Runtime>>,
    guardian: Arc<dyn ce_guard::Guardian>,
    data_price_per_byte: u128,
    data_served: DataServedLedger,
    app_inbox: AppInbox,
    app_msg_tx: broadcast::Sender<AppMessage>,
    relay_price_per_min: Option<u128>,
    relay_meter: RelayMeter,
    synced: Arc<std::sync::atomic::AtomicBool>,
    persist: bool,
) {
    use std::sync::atomic::Ordering as SyncedOrdering;
    let mut sync_ticks: u32 = 0;
    let mut last_nonce: HashMap<NodeId, u64> = HashMap::new();
    let mut peer_heights: HashMap<NodeId, u64> = HashMap::new();
    let mut peer_oldest: HashMap<NodeId, u64> = HashMap::new();
    let mut peer_segments: HashMap<NodeId, Vec<u64>> = HashMap::new();

    {
        let held = ce_chain::list_archive_segments(&archive_dir);
        if !held.is_empty() {
            let _ = mesh_handle.announce_segments(our_node_id, held).await;
        }
        // Advertise as a relay so clients can discover us (provider records expire — re-advertised
        // on the segment ticker below).
        if relay_price_per_min.is_some() {
            let _ = mesh_handle.advertise_service("relay").await;
        }
    }

    let mut segment_announce_ticker =
        tokio::time::interval(std::time::Duration::from_secs(300));
    // Drives both sync-request retries (when behind) and the "caught up → may mine" signal.
    // Kept short so a solo node starts mining within a couple of seconds while a joining node
    // still has time to learn it is behind (via PeerHeight) before the grace elapses.
    let mut sync_retry_ticker =
        tokio::time::interval(std::time::Duration::from_secs(2));

    loop {
        let event = tokio::select! {
            _ = segment_announce_ticker.tick() => {
                let held = ce_chain::list_archive_segments(&archive_dir);
                let _ = mesh_handle.announce_segments(our_node_id, held).await;
                if relay_price_per_min.is_some() {
                    let _ = mesh_handle.advertise_service("relay").await;
                }
                continue;
            }
            _ = sync_retry_ticker.tick() => {
                sync_ticks += 1;
                let our_height = chain.height().await;
                let best = peer_heights.values().copied().max().unwrap_or(0);
                if best > our_height {
                    debug!("sync retry: we={our_height}, best peer={best}");
                    let _ = mesh_handle.send_sync_request(our_node_id, our_height).await;
                    synced.store(false, SyncedOrdering::Relaxed);
                } else if sync_ticks >= 2 || !peer_heights.is_empty() {
                    // Caught up with a known peer, or the startup grace (~15s) elapsed with no peer
                    // ahead — safe to mine on our tip without forking the network chain.
                    synced.store(true, SyncedOrdering::Relaxed);
                }
                continue;
            }
            maybe = rx.recv() => match maybe {
                Some(e) => e,
                None => break,
            }
        };

        match event {
            MeshEvent::NewBlock(block) => {
                if chain.append(block.clone()).await {
                    info!("accepted block {} from mesh", block.index);
                    pool.remove_included(&block).await;
                    if persist {
                        if let Err(e) = chain.save(chain_path.clone()).await {
                            warn!("save chain: {e}");
                        }
                    }
                    let _ = block_tx.send(block.clone());
                } else {
                    warn!(
                        "rejected block {} from mesh (index/hash/diff mismatch)",
                        block.index
                    );
                }
            }
            MeshEvent::NewTx(tx) => {
                match tx.verify() {
                    Ok(()) => {
                        if matches!(tx.kind, TxKind::JobBid { .. }) {
                            let _ = bid_notify_tx.send(tx.clone()).await;
                        }
                        let _ = tx_tx.send(tx.clone());
                        pool.add(tx).await;
                    }
                    Err(e) => warn!("invalid tx from mesh: {e}"),
                }
            }
            MeshEvent::PeerHeight { node_id, height, tip_hash, oldest_block } => {
                let snap = chain.sync_snap().await;
                // Isolation mode: when running in an isolated test environment
                // (disable_local_discovery=true), silently discard announcements from peers
                // claiming a height more than 500 blocks ahead while we are on a fresh chain
                // (height < 200). This prevents live ce nodes discovered via mDNS from
                // triggering wasteful sync loops against an unrelated production chain.
                // We do NOT add such peers to peer_heights so the retry ticker ignores them.
                if disable_local_discovery && snap.height < 200 && height > snap.height + 500 {
                    debug!(
                        "isolation: ignoring height {} from peer {} (we are at {})",
                        height,
                        hex::encode(&node_id[..4]),
                        snap.height,
                    );
                    continue;
                }
                peer_heights.insert(node_id, height);
                peer_oldest.insert(node_id, oldest_block);
                // If no known peer is ahead of us, we're caught up — allow mining immediately
                // (don't wait for the 15s grace tick).
                if peer_heights.values().copied().max().unwrap_or(0) <= snap.height {
                    synced.store(true, SyncedOrdering::Relaxed);
                }
                if height > snap.height {
                    let from = if tip_hash != snap.tip_hash && snap.height > 0 {
                        0
                    } else {
                        snap.height
                    };
                    let peer_can_serve = oldest_block <= from;
                    if !peer_can_serve && from > 0 {
                        debug!(
                            "peer {} is pruned (oldest {}), skipping sync request from {}",
                            hex::encode(&node_id[..4]),
                            oldest_block,
                            from,
                        );
                    } else {
                        info!(
                            "peer {} is at height {}, we're at {} — requesting sync from {}",
                            hex::encode(&node_id[..4]),
                            height,
                            snap.height,
                            from,
                        );
                        let _ = mesh_handle.send_sync_request(our_node_id, from).await;
                    }
                }
            }
            MeshEvent::SyncRequest { from_node, from_height } => {
                let blocks = chain.blocks_after(from_height, MAX_BLOCKS_PER_SYNC).await;
                if !blocks.is_empty() {
                    info!(
                        "serving {} blocks from height {} to {}",
                        blocks.len(),
                        from_height,
                        blocks.last().unwrap().index
                    );
                    let _ = mesh_handle.send_sync_response(from_node, blocks).await;
                }
            }
            MeshEvent::SyncBlocks { for_node, blocks } => {
                if for_node != our_node_id {
                    continue;
                }
                let height_before = chain.height().await;
                let max_candidate = blocks.iter().map(|b| b.index).max().unwrap_or(0);
                info!("sync response: {} blocks, candidate tip {}", blocks.len(), max_candidate);

                let mut applied = 0u64;
                for block in blocks.clone() {
                    if chain.append(block).await {
                        applied += 1;
                    }
                }

                if applied == 0 && chain.try_reorg(blocks).await {
                    let new_height = chain.height().await;
                    info!(
                        "reorg: switched to longer chain at height {} (was {})",
                        new_height, height_before
                    );
                    applied = new_height.saturating_sub(height_before);
                }

                if applied > 0 {
                    let new_height = chain.height().await;
                    info!("sync applied {applied} blocks, now at height {new_height}");

                    if let Some(keep) = prune_keep {
                        if new_height > keep + 100 {
                            if archive_density > 0.0 {
                                if let Some(top_seg) =
                                    chain.highest_complete_segment().await
                                {
                                    let snap = chain.sync_snap().await;
                                    let oldest_live_seg =
                                        ce_chain::segment_id_for_block(snap.oldest);
                                    for seg_id in oldest_live_seg..=top_seg {
                                        if ce_chain::should_hold_segment(
                                            &our_node_id,
                                            seg_id,
                                            archive_density,
                                        ) {
                                            let seg_path = archive_dir
                                                .join(format!("segment_{seg_id}.bin"));
                                            if !seg_path.exists() {
                                                if let Some(seg_blocks) =
                                                    chain.export_segment(seg_id).await
                                                {
                                                    if let Err(e) = ce_chain::save_segment(
                                                        &archive_dir,
                                                        seg_id,
                                                        &seg_blocks,
                                                    ) {
                                                        warn!("archive segment {seg_id}: {e}");
                                                    } else {
                                                        info!(
                                                            "archived segment {seg_id} ({} blocks)",
                                                            seg_blocks.len()
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            chain.prune(keep).await;
                            let snap = chain.sync_snap().await;
                            info!("pruned to height {}..{} (light mode)", snap.oldest, snap.height);
                            let held = ce_chain::list_archive_segments(&archive_dir);
                            let _ = mesh_handle.announce_segments(our_node_id, held).await;
                        }
                    }

                    if persist {
                        if let Err(e) = chain.save(chain_path.clone()).await {
                            warn!("save chain after sync: {e}");
                        }
                    }
                    let snap = chain.sync_snap().await;
                    let _ = mesh_handle
                        .announce_height(our_node_id, snap.height, snap.tip_hash, snap.oldest)
                        .await;
                } else {
                    let our_height = chain.height().await;
                    let best_peer_height = peer_heights.values().copied().max().unwrap_or(0);
                    if best_peer_height > our_height {
                        warn!(
                            "sync blocks didn't apply (our height {our_height}, \
                             best peer {best_peer_height}, candidate tip {max_candidate}); \
                             requesting full resync"
                        );
                        let _ = mesh_handle.send_sync_request(our_node_id, 0).await;
                    }
                }
            }
            MeshEvent::PeerSegments { node_id, held_segments } => {
                debug!(
                    "peer {} holds {} archive segments",
                    hex::encode(&node_id[..4]),
                    held_segments.len(),
                );
                peer_segments.insert(node_id, held_segments);
            }
            MeshEvent::AppGossip { from, topic, payload } => {
                // A verified app pub/sub message — deliver it to the local app via the same inbox
                // + stream as directed messages (the app filters by topic).
                let msg = AppMessage {
                    from: hex::encode(from),
                    topic,
                    payload_hex: hex::encode(&payload),
                    received_at: now_secs(),
                    reply_token: None,
                };
                {
                    let mut ring = app_inbox.lock().await;
                    if ring.len() >= APP_INBOX_CAPACITY {
                        ring.pop_front();
                    }
                    ring.push_back(msg.clone());
                }
                let _ = app_msg_tx.send(msg);
            }
            MeshEvent::PeerConnected(peer) => {
                info!("peer connected: {peer}");
                let snap = chain.sync_snap().await;
                let _ = mesh_handle
                    .announce_height(our_node_id, snap.height, snap.tip_hash, snap.oldest)
                    .await;
                let held = ce_chain::list_archive_segments(&archive_dir);
                if !held.is_empty() {
                    let _ = mesh_handle.announce_segments(our_node_id, held).await;
                }
            }
            MeshEvent::PeerDisconnected(peer) => info!("peer disconnected: {peer}"),
            MeshEvent::Rtt { peer, rtt_ms } => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                let mut g = netgraph.lock().await;
                let e = g.entry(peer.to_string()).or_insert(RttStat {
                    rtt_ms,
                    samples: 0,
                    last_seen_secs: now,
                });
                // EWMA (alpha = 0.2); the first sample seeds the estimate directly.
                e.rtt_ms = if e.samples == 0 { rtt_ms } else { e.rtt_ms * 0.8 + rtt_ms * 0.2 };
                e.samples += 1;
                e.last_seen_secs = now;
            }
            MeshEvent::IncomingRpc { from_peer, correlation_id, request } => {
                if let RpcRequest::SegmentFetch { segment_id, .. } = &request {
                    let seg_id = *segment_id;
                    let chain2 = chain.clone();
                    let adir = archive_dir.clone();
                    let handle = mesh_handle.clone();
                    tokio::spawn(async move {
                        let blocks = chain2.export_segment(seg_id).await;
                        let blocks = if let Some(b) = blocks {
                            Some(b)
                        } else {
                            ce_chain::load_segment(&adir, seg_id).ok().flatten()
                        };
                        let resp = match blocks {
                            Some(b) => RpcResponse::SegmentData { segment_id: seg_id, blocks: b },
                            None => {
                                RpcResponse::Error(format!("segment {seg_id} not available"))
                            }
                        };
                        let _ = handle.respond_rpc(correlation_id, resp).await;
                    });
                } else if let RpcRequest::FetchChunk { cid, receipt, .. } = &request {
                    // Serve a content-addressed chunk from the local blob store. Free when
                    // data_price_per_byte == 0 (open, like SegmentFetch); otherwise the request
                    // must carry a payment-channel receipt covering the running cost (Stage 3).
                    let cid = *cid;
                    let receipt = receipt.clone();
                    let blobs_dir = data_dir.join("blobs");
                    let handle = mesh_handle.clone();
                    let price = data_price_per_byte;
                    let chain2 = chain.clone();
                    let ledger = data_served.clone();
                    let host = our_node_id;
                    tokio::spawn(async move {
                        let resp = match std::fs::read(blobs_dir.join(hex::encode(cid))) {
                            Ok(bytes) if price == 0 => RpcResponse::ChunkData { cid, bytes },
                            Ok(bytes) => {
                                let parsed = receipt
                                    .as_ref()
                                    .and_then(|b| bincode::deserialize::<ChunkReceipt>(b).ok());
                                let channel = match &parsed {
                                    Some(r) => chain2
                                        .list_channels()
                                        .await
                                        .into_iter()
                                        .find(|(id, ..)| id == &r.channel_id)
                                        .map(|(_, payer, h, cap, _)| (payer, h, cap)),
                                    None => None,
                                };
                                let mut guard = ledger.lock().await;
                                let key = parsed.as_ref().map(|r| r.channel_id).unwrap_or_default();
                                let served = guard.get(&key).copied().unwrap_or(0);
                                match authorize_chunk_serve(
                                    price,
                                    bytes.len(),
                                    &host,
                                    parsed.as_ref(),
                                    channel,
                                    served,
                                ) {
                                    Ok(new_cumulative) => {
                                        guard.insert(key, new_cumulative);
                                        drop(guard);
                                        RpcResponse::ChunkData { cid, bytes }
                                    }
                                    Err(reason) => {
                                        RpcResponse::Error(format!("payment required: {reason}"))
                                    }
                                }
                            }
                            Err(_) => RpcResponse::Error(format!(
                                "chunk {} not held",
                                hex::encode(&cid[..4])
                            )),
                        };
                        let _ = handle.respond_rpc(correlation_id, resp).await;
                    });
                } else if let RpcRequest::AppMessage { from_node, topic, payload } = &request {
                    // Authenticate the sender (Noise PeerId must match the claimed NodeId), then
                    // enqueue + fan out so the local app can consume it. CE authenticates; the
                    // app authorizes (it inspects `from` and decides what to honor).
                    let authentic = ce_mesh::peer_id_from_node_id(from_node)
                        .map(|p| p == from_peer)
                        .unwrap_or(false);
                    let resp = if authentic {
                        let msg = AppMessage {
                            from: hex::encode(from_node),
                            topic: topic.clone(),
                            payload_hex: hex::encode(payload),
                            received_at: now_secs(),
                            reply_token: None,
                        };
                        {
                            let mut ring = app_inbox.lock().await;
                            if ring.len() >= APP_INBOX_CAPACITY {
                                ring.pop_front();
                            }
                            ring.push_back(msg.clone());
                        }
                        let _ = app_msg_tx.send(msg);
                        RpcResponse::AppAck
                    } else {
                        warn!("app message: from_node/from_peer mismatch — dropping");
                        RpcResponse::Error("sender identity mismatch".into())
                    };
                    let _ = mesh_handle.respond_rpc(correlation_id, resp).await;
                } else if let RpcRequest::AppRequest { from_node, topic, payload } = &request {
                    // Sync request/response (Stage 3): authenticate, surface to the app tagged with
                    // the reply token (= this RPC's correlation id), and DO NOT respond yet — the
                    // app answers via `/mesh/reply`, which sends `AppReply` back over this channel.
                    let authentic = ce_mesh::peer_id_from_node_id(from_node)
                        .map(|p| p == from_peer)
                        .unwrap_or(false);
                    if authentic {
                        let msg = AppMessage {
                            from: hex::encode(from_node),
                            topic: topic.clone(),
                            payload_hex: hex::encode(payload),
                            received_at: now_secs(),
                            reply_token: Some(correlation_id),
                        };
                        {
                            let mut ring = app_inbox.lock().await;
                            if ring.len() >= APP_INBOX_CAPACITY {
                                ring.pop_front();
                            }
                            ring.push_back(msg.clone());
                        }
                        let _ = app_msg_tx.send(msg);
                        // No respond_rpc here — the app replies later via /mesh/reply.
                    } else {
                        warn!("app request: from_node/from_peer mismatch — dropping");
                        let _ = mesh_handle
                            .respond_rpc(correlation_id, RpcResponse::Error("sender identity mismatch".into()))
                            .await;
                    }
                } else if let RpcRequest::RelayReceipt { from_node, channel_id, cumulative, payer_sig } = &request {
                    // A client paying us for relay service. Verify the receipt against the on-chain
                    // channel (we must be the host) and our per-minute price, then record it.
                    let channel_id = *channel_id;
                    let cumulative = *cumulative;
                    let payer = *from_node;
                    let sig_vec = payer_sig.clone();
                    let price = relay_price_per_min;
                    let chain2 = chain.clone();
                    let meter = relay_meter.clone();
                    let relay_id = our_node_id;
                    let handle = mesh_handle.clone();
                    tokio::spawn(async move {
                        let resp = relay_record_receipt(
                            &chain2, &meter, price, relay_id, payer, channel_id, cumulative, sig_vec,
                        )
                        .await;
                        let _ = handle.respond_rpc(correlation_id, resp).await;
                    });
                } else {
                    handle_incoming_rpc(
                        from_peer,
                        correlation_id,
                        request,
                        &data_dir,
                        docker.clone(),
                        mesh_handle.clone(),
                        &self_tags,
                        &runtimes,
                        &guardian,
                        job_store.clone(),
                        our_node_id,
                        chain.clone(),
                        &accepted_roots,
                    )
                    .await;
                }
            }
            MeshEvent::CellSignal(signal) => {
                if let Some(&prev) = last_nonce.get(&signal.from) {
                    if signal.nonce <= prev {
                        warn!(
                            "dropping replay from {}: nonce {} <= last {}",
                            hex::encode(&signal.from[..4]),
                            signal.nonce,
                            prev,
                        );
                        continue;
                    }
                }

                // Anti-spam: payload-bearing signals require a burn proof, except the node's own.
                if signal.requires_burn() && signal.from != our_node_id {
                    warn!(
                        "dropping ce-protocol-1 signal from {}: payload without burn_proof",
                        hex::encode(&signal.from[..4]),
                    );
                    continue;
                }
                if let Some(burn) = &signal.burn_proof {
                    let lookup = chain.tx_by_id(burn.tx_id).await;
                    let Some((tx, _height, _hash)) = lookup else {
                        warn!(
                            "dropping signal: burn_proof tx {} not found on chain",
                            hex::encode(&burn.tx_id[..4]),
                        );
                        continue;
                    };
                    if tx_burn_amount(&tx) != Some(burn.amount) {
                        warn!(
                            "dropping signal: burn_proof amount {} does not match on-chain tx",
                            burn.amount,
                        );
                        continue;
                    }
                    // Prevent burn-proof theft: the tx must have been originated by the
                    // signal sender. Without this check, any node could copy a tx_id from
                    // a legitimate signal it observed and send free-riding signals.
                    if tx.origin != signal.from {
                        warn!(
                            "dropping signal: burn_proof tx {} not owned by sender {}",
                            hex::encode(&burn.tx_id[..4]),
                            hex::encode(&signal.from[..4]),
                        );
                        continue;
                    }
                }
                last_nonce.insert(signal.from, signal.nonce);

                if let Some(cap) = parse_capacity_signal(&signal) {
                    atlas.lock().await.insert(signal.from, cap);
                }

                {
                    let mut ring = signals.lock().await;
                    push_signal(&mut ring, signal.clone());
                }
                let _ = signal_tx.send(signal);
            }
        }
    }
}

// ----- Relay payment authorization -----

/// Decide whether a relay should accept a payment receipt for relay service. Pure + unit-testable.
/// The relay charges `price_per_min` per minute; `minutes_elapsed` is how long this channel has
/// been relaying (at least 1 — the first minute is charged up front). A valid receipt must cover
/// `price * minutes`, stay within capacity, name this relay as host, and carry a valid payer
/// signature. Returns the cumulative to record (the high-water mark), or a refusal reason.
fn relay_authorize(
    price_per_min: u128,
    minutes_elapsed: u64,
    capacity: u128,
    payer: &NodeId,
    relay: &NodeId,
    receipt: &ChunkReceipt,
) -> Result<u128, String> {
    if !verify_chunk_receipt_sig(payer, relay, receipt) {
        return Err("invalid receipt signature".into());
    }
    if receipt.cumulative > capacity {
        return Err("receipt cumulative exceeds channel capacity".into());
    }
    let required = price_per_min.saturating_mul(minutes_elapsed.max(1) as u128);
    if receipt.cumulative < required {
        return Err("receipt does not cover the relay time used".into());
    }
    Ok(receipt.cumulative)
}

/// Verify and record an incoming relay payment receipt against the on-chain channel and our price.
#[allow(clippy::too_many_arguments)]
async fn relay_record_receipt(
    chain: &ChainHandle,
    meter: &RelayMeter,
    price: Option<u128>,
    relay: NodeId,
    payer: NodeId,
    channel_id: [u8; 32],
    cumulative: u128,
    payer_sig: Vec<u8>,
) -> RpcResponse {
    let Some(price_per_min) = price else {
        return RpcResponse::Error("this node is not a relay".into());
    };
    let sig: [u8; 64] = match payer_sig.as_slice().try_into() {
        Ok(s) => s,
        Err(_) => return RpcResponse::Error("bad signature length".into()),
    };
    // The channel must exist on-chain with us as host and the sender as payer.
    let chan = chain
        .list_channels()
        .await
        .into_iter()
        .find(|(id, ..)| id == &channel_id)
        .map(|(_, p, h, cap, _)| (p, h, cap));
    let Some((chan_payer, chan_host, capacity)) = chan else {
        return RpcResponse::Error("unknown or unsettled channel".into());
    };
    if chan_host != relay || chan_payer != payer {
        return RpcResponse::Error("channel not hosted by this relay for this payer".into());
    }
    let receipt = ChunkReceipt { channel_id, cumulative, payer_sig: sig };
    let now = now_secs();
    let mut guard = meter.lock().await;
    let acct = guard
        .entry(channel_id)
        .or_insert_with(|| RelayAccount { first_receipt_secs: now, paid_cumulative: 0 });
    let minutes = (now.saturating_sub(acct.first_receipt_secs) / 60) + 1;
    match relay_authorize(price_per_min, minutes, capacity, &payer, &relay, &receipt) {
        Ok(new_cum) => {
            acct.paid_cumulative = acct.paid_cumulative.max(new_cum);
            RpcResponse::RelayAck
        }
        Err(reason) => RpcResponse::Error(format!("relay payment rejected: {reason}")),
    }
}

// ----- Data-layer chunk payment authorization -----

/// Decide whether to serve a priced chunk, given the attached receipt and channel state. Pure and
/// deterministic so it can be unit-tested with real signatures. Returns the new cumulative value
/// to record for the channel on success, or a human reason on refusal.
///
/// - `price_per_byte == 0` → always free (returns `served` unchanged).
/// - otherwise a receipt is required; the channel must exist with this node as host; the receipt's
///   cumulative must cover `served + chunk cost`, stay within capacity, and carry a valid payer
///   signature. The returned cumulative becomes the new high-water mark for the channel.
fn authorize_chunk_serve(
    price_per_byte: u128,
    chunk_len: usize,
    host: &NodeId,
    receipt: Option<&ChunkReceipt>,
    channel: Option<(NodeId, NodeId, u128)>, // (payer, host, capacity) from the chain
    served: u128,
) -> Result<u128, String> {
    if price_per_byte == 0 {
        return Ok(served);
    }
    let cost = price_per_byte.saturating_mul(chunk_len as u128);
    let receipt = receipt.ok_or("no receipt (provider charges for data)")?;
    let (payer, chan_host, capacity) = channel.ok_or("unknown or unsettled channel")?;
    if &chan_host != host {
        return Err("channel is not hosted by this node".into());
    }
    let owed = served.saturating_add(cost);
    if receipt.cumulative < owed {
        return Err("receipt cumulative does not cover the chunk cost".into());
    }
    if receipt.cumulative > capacity {
        return Err("receipt cumulative exceeds channel capacity".into());
    }
    if !verify_chunk_receipt_sig(&payer, host, receipt) {
        return Err("invalid receipt signature".into());
    }
    Ok(receipt.cumulative)
}

/// Ensure a content-addressed blob is present in the local store, fetching it from the data layer
/// (free providers) if absent. Used to stage a workload's module + inputs before launch (Stage 4).
/// Verifies fetched bytes against `cid`; errors if no provider serves it (e.g. it requires payment).
async fn stage_blob(
    data_dir: &Path,
    mesh_handle: &MeshHandle,
    host_id: NodeId,
    cid: [u8; 32],
) -> Result<()> {
    let dir = data_dir.join("blobs");
    let path = dir.join(hex::encode(cid));
    if path.exists() {
        return Ok(());
    }
    let providers = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        mesh_handle.find_providers(cid),
    )
    .await
    .map_err(|_| anyhow::anyhow!("provider lookup timed out for {}", hex::encode(&cid[..4])))??;
    for peer in providers {
        let req = RpcRequest::FetchChunk { from_node: host_id, cid, receipt: None };
        if let Ok(RpcResponse::ChunkData { bytes, .. }) = mesh_handle.send_rpc(peer, req).await {
            let got: [u8; 32] = Sha256::digest(&bytes).into();
            if got != cid {
                continue;
            }
            std::fs::create_dir_all(&dir)?;
            std::fs::write(&path, &bytes)?;
            let _ = mesh_handle.provide_chunk(cid).await;
            return Ok(());
        }
    }
    anyhow::bail!(
        "no provider served {} (it may require payment)",
        hex::encode(&cid[..4])
    )
}

/// Enforce a deploy request against the leaf capability's resource ceilings. Each `Some(limit)` is
/// a hard ceiling the request may not exceed; `None` means unlimited. Returns the rejection reason
/// when any caveat is violated. Mirrors the `allowed_ports` enforcement done for tunnels: ce-cap
/// authenticates and attenuates the `max_*` caveats but leaves their enforcement to the action that
/// consumes the resources, which for deploy is here.
fn deploy_within_caveats(
    caveats: &ce_cap::Caveats,
    cpu_cores: u32,
    mem_mb: u64,
    bid: u128,
) -> Result<(), String> {
    if let Some(max) = caveats.max_cpu {
        if cpu_cores > max {
            return Err(format!("deploy cpu_cores {cpu_cores} exceeds capability max_cpu {max}"));
        }
    }
    if let Some(max) = caveats.max_mem_mb {
        if mem_mb > u64::from(max) {
            return Err(format!("deploy mem_mb {mem_mb} exceeds capability max_mem_mb {max}"));
        }
    }
    if let Some(max) = caveats.max_credits {
        if bid > u128::from(max) {
            return Err(format!("deploy bid {bid} exceeds capability max_credits {max}"));
        }
    }
    Ok(())
}

// ----- Incoming mesh RPC handler -----

#[allow(clippy::too_many_arguments)]
async fn handle_incoming_rpc(
    from_peer: ce_mesh::CePeerId,
    correlation_id: u64,
    request: RpcRequest,
    data_dir: &Path,
    _docker: Option<Docker>,
    mesh_handle: MeshHandle,
    self_tags: &[String],
    runtimes: &[Arc<dyn Runtime>],
    guardian: &Arc<dyn ce_guard::Guardian>,
    job_store: JobStore,
    host_node_id: NodeId,
    chain: ChainHandle,
    accepted_roots: &[NodeId],
) {
    use ce_cap as capability;

    // Reject helper: send an Error response and stop.
    let reject = |msg: String| {
        let handle = mesh_handle.clone();
        tokio::spawn(async move {
            let _ = handle.respond_rpc(correlation_id, RpcResponse::Error(msg)).await;
        });
    };

    let from_node = request.from_node();

    // 1. libp2p-noise authentication: the claimed NodeId must own the connecting PeerId.
    match peer_id_from_node_id(&from_node) {
        Ok(expected) if expected == from_peer => {}
        Ok(_) => {
            warn!("rpc: from_node/from_peer mismatch — dropping");
            reject("sender identity mismatch".into());
            return;
        }
        Err(e) => {
            warn!("rpc: invalid from_node: {e}");
            reject("invalid sender identity".into());
            return;
        }
    }

    // 2. Capability authorization. The action this RPC performs and the capability chain it carries
    //    (the `grant` field now transports bincode(Vec<SignedCapability>), root-first).
    // Action names are opaque to the capability verifier; the node defines its own vocabulary.
    let (action, chain_bytes): (&str, Option<Vec<u8>>) = match &request {
        RpcRequest::Deploy { grant, .. } => ("deploy", grant.clone()),
        RpcRequest::Kill { grant, .. } => ("kill", grant.clone()),
        _ => unreachable!("non-action RPCs are handled in the event loop"),
    };
    let caps = match chain_bytes.as_deref().map(capability::decode_chain_bytes) {
        Some(Ok(c)) => c,
        Some(Err(_)) => {
            reject("malformed capability".into());
            return;
        }
        None => {
            reject("no capability presented".into());
            return;
        }
    };
    // The chain actor is async, so pre-resolve on-chain revocation for each link.
    let mut revoked: std::collections::HashSet<(NodeId, u64)> = std::collections::HashSet::new();
    for link in &caps {
        if chain.is_revoked(link.cap.issuer, link.cap.nonce).await {
            revoked.insert((link.cap.issuer, link.cap.nonce));
        }
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let is_revoked = |issuer: &NodeId, nonce: u64| revoked.contains(&(*issuer, nonce));
    if let Err(reason) = capability::authorize(
        &host_node_id,
        accepted_roots,
        self_tags,
        now,
        &from_node,
        action,
        &caps,
        &is_revoked,
    ) {
        warn!("rpc: denied {action} from {}: {reason}", hex::encode(&from_node[..4]));
        reject(reason);
        return;
    }

    match request {
        RpcRequest::SegmentFetch { .. } => unreachable!("SegmentFetch handled in event loop"),
        RpcRequest::FetchChunk { .. } => unreachable!("FetchChunk handled in event loop"),
        RpcRequest::AppMessage { .. } => unreachable!("AppMessage handled in event loop"),
        RpcRequest::AppRequest { .. } => unreachable!("AppRequest handled in event loop"),
        RpcRequest::RelayReceipt { .. } => unreachable!("RelayReceipt handled in event loop"),
        RpcRequest::Deploy { workload, cpu_cores, mem_mb, duration_secs, bid, .. } => {
            // Enforce the leaf capability's resource ceilings. ce-cap leaves `max_*` caveats for
            // "whichever action consumes them" (mirrors the `allowed_ports` enforcement for tunnel
            // above): deploy consumes cpu/mem/credits, so a request exceeding any `Some(limit)` is
            // rejected. `None` means unlimited.
            if let Some(leaf) = caps.last() {
                if let Err(reason) = deploy_within_caveats(&leaf.cap.caveats, cpu_cores, mem_mb, bid) {
                    reject(reason);
                    return;
                }
            }
            // Decode the polymorphic workload (Docker | Wasm) and dispatch through the runtime
            // registry — the first runtime whose can_run matches its required tag.
            let workload: ce_runtime::Workload = match bincode::deserialize(&workload) {
                Ok(w) => w,
                Err(_) => {
                    reject("malformed workload".into());
                    return;
                }
            };
            let limits = ce_runtime::Limits { cpu_cores, mem_mb };
            let Some(runtime) = runtimes.iter().find(|r| r.can_run(&workload)).cloned() else {
                reject(format!("no runtime for a '{}' workload on this node", workload.required_tag()));
                return;
            };
            let payer = from_node; // the deployer funds and is billed for the cell
            let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
            let job_id: [u8; 32] =
                Sha256::digest(bincode::serialize(&(ts as u64, payer, workload.required_tag())).unwrap_or_default())
                    .into();
            let deps = workload.content_deps();

            // Pre-execution screening (ce-guard): refuse disallowed workloads before anything is
            // staged or launched. The seam is content-free; banned-category policy lives in the
            // ce-guardian app. A Deny ends the deploy here.
            let guard_req = ce_guard::GuardRequest {
                required_tag: workload.required_tag().to_string(),
                artifact: match &workload {
                    ce_runtime::Workload::Docker { image, .. } => {
                        ce_guard::ArtifactRef::Docker { image: image.clone(), digest: None }
                    }
                    ce_runtime::Workload::Wasm { module_hash, .. } => {
                        ce_guard::ArtifactRef::Wasm { module_hash: *module_hash }
                    }
                },
                cmd_entry_args: match &workload {
                    ce_runtime::Workload::Docker { cmd, .. } => cmd.clone(),
                    ce_runtime::Workload::Wasm { entry, args, .. } => {
                        let mut a = vec![entry.clone()];
                        a.extend(args.iter().cloned());
                        a
                    }
                },
                env_keys: match &workload {
                    ce_runtime::Workload::Docker { env, .. } => {
                        env.iter().map(|(k, _)| k.clone()).collect()
                    }
                    ce_runtime::Workload::Wasm { .. } => vec![],
                },
                inputs: deps.clone(),
                limits: ce_guard::Limits { cpu_cores, mem_mb, gpus: 0 },
                payer: from_node,
                job_id,
                cap_chain: chain_bytes.clone().unwrap_or_default(),
            };
            if let ce_guard::GuardVerdict::Deny { reason, categories } =
                guardian.screen(&guard_req).await
            {
                warn!("guardian denied job {}: {reason} {categories:?}", hex::encode(&job_id[..4]));
                reject(format!("workload denied by guardian: {reason}"));
                return;
            }

            let stage_dir = data_dir.to_path_buf();
            let host_id = host_node_id;
            tokio::spawn(async move {
                // Stage 4: stage every content-addressed dependency (the Wasm module + declared
                // inputs) into the local blob store before launch — fetching from the data layer
                // if absent — so a workload runs on a host that didn't previously hold its bytes.
                for cid in deps {
                    if let Err(e) = stage_blob(&stage_dir, &mesh_handle, host_id, cid).await {
                        let _ = mesh_handle
                            .respond_rpc(correlation_id, RpcResponse::Error(format!("staging failed: {e}")))
                            .await;
                        return;
                    }
                }
                let resp = match runtime.launch(&workload, &limits, job_id).await {
                    Ok((handle, output)) => {
                        // Track it so the heartbeat loop bills it and `ps`/Kill can find it.
                        // Wallet exhaustion will terminate it (existing mechanism).
                        job_store.lock().await.insert(
                            job_id,
                            JobRecord {
                                job_id,
                                payer,
                                container_id: Some(handle.0),
                                status: CeJobStatus::Running,
                                payer_sig: None,
                                cost: None,
                                bid,
                                duration_secs,
                            },
                        );
                        info!("mesh deploy: launched job {} for {}", hex::encode(&job_id[..4]), hex::encode(&payer[..4]));
                        RpcResponse::Deployed { job_id: hex::encode(job_id), output }
                    }
                    Err(e) => RpcResponse::Error(format!("deploy failed: {e}")),
                };
                let _ = mesh_handle.respond_rpc(correlation_id, resp).await;
            });
        }
        RpcRequest::Kill { job_id, .. } => {
            // Containers are stopped via the Docker runtime. (Stage 3: JobRecord tracks the
            // runtime tag so multi-backend kills route correctly.)
            let Some(runtime) = runtimes.iter().find(|r| r.tag() == "docker").cloned() else {
                reject("no runtime available to stop a job on this node".into());
                return;
            };
            tokio::spawn(async move {
                // Resolve the 64-hex job id to a tracked container handle.
                let container = match hex::decode(&job_id).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()) {
                    Some(id) => job_store.lock().await.get(&id).and_then(|r| r.container_id.clone()),
                    None => None,
                };
                let resp = match container {
                    Some(cid) => match runtime.stop(&ce_runtime::Handle(cid)).await {
                        Ok(()) => RpcResponse::Killed,
                        Err(e) => RpcResponse::Error(format!("kill failed: {e}")),
                    },
                    None => RpcResponse::Error("unknown job id on this host".into()),
                };
                let _ = mesh_handle.respond_rpc(correlation_id, resp).await;
            });
        }
    }
}

// ----- Job manager loop -----

#[allow(clippy::too_many_arguments)]
async fn job_manager_loop(
    chain: ChainHandle,
    identity: Arc<Identity>,
    mesh_handle: MeshHandle,
    chain_path: PathBuf,
    persist: bool,
    pool: TxPool,
    job_store: JobStore,
    mut bid_rx: mpsc::Receiver<Tx>,
    mut settle_notify_rx: mpsc::Receiver<()>,
) {
    let manager = match ContainerManager::new(identity.node_id()).await {
        Ok(m) => m,
        Err(e) => {
            warn!("job_manager: Docker unavailable ({e}), job acceptance disabled");
            return;
        }
    };

    let (completion_tx, mut completion_rx) = mpsc::channel::<([u8; 32], i64)>(32);
    let mut settle_ticker = tokio::time::interval(std::time::Duration::from_secs(5));
    let mut heartbeat_ticker = tokio::time::interval(std::time::Duration::from_secs(30));
    heartbeat_ticker.tick().await;

    let mut heartbeat_epochs: HashMap<NodeId, u64> =
        chain.heartbeat_epochs(identity.node_id()).await;

    loop {
        tokio::select! {
            Some(tx) = bid_rx.recv() => {
                handle_incoming_bid(
                    tx,
                    &identity,
                    &manager,
                    &job_store,
                    &completion_tx,
                ).await;
            }
            Some((job_id, _exit_code)) = completion_rx.recv() => {
                let mut store = job_store.lock().await;
                if let Some(r) = store.get_mut(&job_id) {
                    r.status = CeJobStatus::AwaitingSettlement;
                    info!(
                        "container exited for job {}, awaiting settlement",
                        hex::encode(&job_id)
                    );
                }
            }
            _ = settle_notify_rx.recv() => {}
            _ = settle_ticker.tick() => {}
            _ = heartbeat_ticker.tick() => {
                let to_terminate = emit_heartbeats(
                    &chain,
                    &identity,
                    &mesh_handle,
                    &pool,
                    &job_store,
                    &mut heartbeat_epochs,
                ).await;
                for (job_id, cid) in to_terminate {
                    if let Some(cid) = cid {
                        let mgr = manager.clone();
                        tokio::spawn(async move {
                            let _ = mgr.stop_job(&cid).await;
                        });
                    }
                    let mut store = job_store.lock().await;
                    if let Some(r) = store.get_mut(&job_id) {
                        r.status = CeJobStatus::Failed("cell wallet exhausted".into());
                    }
                }
            }
        }

        submit_pending_settles(
            &chain,
            &identity,
            &mesh_handle,
            &chain_path,
            persist,
            &pool,
            &job_store,
        )
        .await;
    }
}

async fn handle_incoming_bid(
    tx: Tx,
    identity: &Identity,
    manager: &ContainerManager,
    job_store: &JobStore,
    completion_tx: &mpsc::Sender<([u8; 32], i64)>,
) {
    let TxKind::JobBid {
        job_id,
        payer,
        image,
        cmd,
        env,
        cpu_cores,
        mem_mb,
        bid,
        duration_secs,
        ..
    } = &tx.kind
    else {
        return;
    };
    let (bid, duration_secs) = (*bid, *duration_secs);

    if payer == &identity.node_id() {
        return;
    }

    {
        let store = job_store.lock().await;
        if store.contains_key(job_id) {
            return;
        }
    }

    let spec = JobSpec {
        job_id: *job_id,
        image: image.clone(),
        cmd: cmd.clone(),
        env: env.clone(),
        cpu_cores: *cpu_cores,
        mem_mb: *mem_mb,
        payer: *payer,
    };

    match manager.launch_job(&spec).await {
        Ok(container_id) => {
            info!(
                "accepted bid {}, container {}",
                hex::encode(job_id),
                &container_id[..12]
            );
            {
                let mut store = job_store.lock().await;
                store.insert(
                    *job_id,
                    JobRecord {
                        job_id: *job_id,
                        payer: *payer,
                        container_id: Some(container_id.clone()),
                        status: CeJobStatus::Running,
                        payer_sig: None,
                        cost: None,
                        bid,
                        duration_secs,
                    },
                );
            }
            let mgr = manager.clone();
            let cid = container_id;
            let jid = *job_id;
            let done_tx = completion_tx.clone();
            tokio::spawn(async move {
                let code = mgr.wait_for_exit(&cid).await.unwrap_or(-1);
                let _ = done_tx.send((jid, code)).await;
            });
        }
        Err(e) => {
            warn!("launch_job {}: {e}", hex::encode(job_id));
            let mut store = job_store.lock().await;
            store.insert(
                *job_id,
                JobRecord {
                    job_id: *job_id,
                    payer: *payer,
                    container_id: None,
                    status: CeJobStatus::Failed(e.to_string()),
                    payer_sig: None,
                    cost: None,
                    bid,
                    duration_secs,
                },
            );
        }
    }
}

async fn submit_pending_settles(
    chain: &ChainHandle,
    identity: &Identity,
    mesh_handle: &MeshHandle,
    chain_path: &PathBuf,
    persist: bool,
    pool: &TxPool,
    job_store: &JobStore,
) {
    let ready: Vec<([u8; 32], NodeId, u128, [u8; 64])> = {
        let store = job_store.lock().await;
        store
            .values()
            .filter(|r| {
                matches!(r.status, CeJobStatus::AwaitingSettlement)
                    && r.payer_sig.is_some()
                    && r.cost.is_some()
            })
            .map(|r| (r.job_id, r.payer, r.cost.unwrap(), r.payer_sig.unwrap()))
            .collect()
    };

    for (job_id, payer, cost, payer_sig) in ready {
        let kind = TxKind::JobSettle {
            job_id,
            host: identity.node_id(),
            payer,
            cpu_ms: 0,
            mem_mb: 0,
            cost,
            payer_sig,
        };
        let data = bincode::serialize(&kind).expect("serialize JobSettle");
        let sig = identity.sign(&data);
        let settle_tx = Tx::new(kind, identity.node_id(), sig);

        pool.add(settle_tx.clone()).await;
        let _ = mesh_handle.broadcast_tx(&settle_tx).await;
        info!("submitted JobSettle tx for job {}", hex::encode(&job_id));

        let mut store = job_store.lock().await;
        if let Some(r) = store.get_mut(&job_id) {
            r.status = CeJobStatus::Settled;
        }
    }

    let settled_on_chain = chain.settled_on_chain(identity.node_id()).await;
    if !settled_on_chain.is_empty() {
        if persist {
            let _ = chain.save(chain_path.clone()).await;
        }
        let mut store = job_store.lock().await;
        for job_id in settled_on_chain {
            if let Some(r) = store.get_mut(&job_id) {
                if !matches!(r.status, CeJobStatus::Settled) {
                    r.status = CeJobStatus::Settled;
                }
            }
        }
    }
}

async fn emit_heartbeats(
    chain: &ChainHandle,
    identity: &Identity,
    mesh_handle: &MeshHandle,
    pool: &TxPool,
    job_store: &JobStore,
    heartbeat_epochs: &mut HashMap<NodeId, u64>,
) -> Vec<([u8; 32], Option<String>)> {
    let running: Vec<(NodeId, u128, u64, [u8; 32], Option<String>)> = {
        let store = job_store.lock().await;
        store
            .values()
            .filter(|r| matches!(r.status, CeJobStatus::Running))
            .map(|r| (r.payer, r.bid, r.duration_secs, r.job_id, r.container_id.clone()))
            .collect()
    };

    let mut to_terminate: Vec<([u8; 32], Option<String>)> = Vec::new();

    for (cell, bid, duration_secs, job_id, container_id) in running {
        let intervals = (duration_secs / 30).max(1) as u128;
        let amount = bid / intervals;
        if amount == 0 {
            continue;
        }

        // Gate on FREE balance (total minus funds locked by open bids/channels/bond), which is
        // exactly what validators require when they append the Heartbeat. Screening on total
        // balance would let a payer lock its funds so the host keeps broadcasting heartbeats that
        // validators silently reject — the job runs but the host is never paid (free-compute leak).
        let cell_balance = chain.balance(cell).await - chain.locked_balance(cell).await as i128;
        if cell_balance < amount as i128 {
            info!(
                "cell {} insufficient free balance ({cell_balance}) for heartbeat {amount}, \
                 terminating job {}",
                hex::encode(&cell[..4]),
                hex::encode(&job_id),
            );
            to_terminate.push((job_id, container_id));
            continue;
        }

        let epoch = {
            let e = heartbeat_epochs.entry(cell).or_insert(0);
            let current = *e;
            *e += 1;
            current
        };

        let kind = TxKind::Heartbeat { job_id, cell, host: identity.node_id(), amount, epoch };
        let data = bincode::serialize(&kind).expect("serialize Heartbeat");
        let sig = identity.sign(&data);
        let tx = Tx::new(kind, identity.node_id(), sig);

        pool.add(tx.clone()).await;
        let _ = mesh_handle.broadcast_tx(&tx).await;
        info!(
            "heartbeat epoch {epoch} for cell {} job {}",
            hex::encode(&cell[..4]),
            hex::encode(&job_id),
        );
    }

    to_terminate
}

async fn capacity_broadcast_loop(
    identity: Arc<Identity>,
    mesh_handle: MeshHandle,
    job_store: JobStore,
    send_nonce: Arc<AtomicU64>,
    self_tags: Vec<String>,
) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
    ticker.tick().await;

    let cpu_cores = num_cpus() as u32;
    let mem_mb = available_mem_mb();
    info!("node self-tags: {}", self_tags.join(", "));

    loop {
        ticker.tick().await;

        let running_jobs = {
            let store = job_store.lock().await;
            store.values().filter(|r| matches!(r.status, CeJobStatus::Running)).count() as u32
        };

        let mut capabilities = vec![
            Capability { name: "cpu".into(), version: cpu_cores },
            Capability { name: "mem_mb".into(), version: mem_mb },
            Capability { name: "jobs".into(), version: running_jobs },
        ];
        // Advertise self-tags as `tag:<name>` capabilities. This rides the existing
        // CEP-1 capability list — no wire-format change — and peers strip the prefix.
        for t in &self_tags {
            capabilities.push(Capability { name: format!("tag:{t}"), version: 1 });
        }

        let nonce = send_nonce.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let signal = CellSignal::build(
            identity.node_id(),
            ce_protocol::CellAddress::Broadcast,
            capabilities,
            vec![],
            None,
            nonce,
            &identity,
        );

        if let Err(e) = mesh_handle.broadcast_signal(&signal).await {
            warn!("capacity broadcast: {e}");
        } else {
            info!("broadcast capacity: {cpu_cores} cpu, {mem_mb} mb, {running_jobs} jobs");
        }
    }
}

fn parse_capacity_signal(signal: &CellSignal) -> Option<PeerCapacity> {
    let mut cpu = None;
    let mut mem = None;
    let mut jobs = None;
    let mut tags = Vec::new();
    for cap in &signal.capabilities {
        match cap.name.as_str() {
            "cpu"    => cpu  = Some(cap.version),
            "mem_mb" => mem  = Some(cap.version),
            "jobs"   => jobs = Some(cap.version),
            other => {
                if let Some(t) = other.strip_prefix("tag:") {
                    tags.push(t.to_string());
                }
            }
        }
    }
    let (cpu_cores, mem_mb) = cpu.zip(mem)?;
    let last_seen_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Some(PeerCapacity { cpu_cores, mem_mb, running_jobs: jobs.unwrap_or(0), last_seen_secs, tags })
}

/// Capability-derived tags this node advertises so any peer can select hosts by
/// what they can realistically do. Objective and self-reported — distinct from the
/// owner-assigned tags in machines.toml. Additive: new tags can be introduced without
/// breaking older nodes, which simply ignore tags they do not recognize.
fn capability_tags(docker_available: bool, cpu_cores: u32, mem_mb: u32) -> Vec<String> {
    let mut tags = vec![
        std::env::consts::OS.to_string(),   // "linux" | "macos" | "windows"
        std::env::consts::ARCH.to_string(), // "x86_64" | "aarch64" | ...
    ];
    if docker_available {
        tags.push("docker".into());
    }
    // Every node can run WebAssembly (wasmtime is built in — no external daemon).
    tags.push("wasm".into());
    if has_gpu() {
        tags.push("gpu".into());
    }
    if cpu_cores >= 16 {
        tags.push("manycore".into());
    }
    if mem_mb >= 32_768 {
        tags.push("highmem".into());
    }
    tags
}

/// Best-effort NVIDIA GPU detection. Linux-only for now (checks the driver node);
/// other platforms report no GPU until detection is added.
fn has_gpu() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new("/proc/driver/nvidia/version").exists()
            || std::path::Path::new("/dev/nvidia0").exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

fn num_cpus() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

/// Unix seconds now (saturating to 0 before the epoch).
fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn available_mem_mb() -> u32 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/meminfo") {
            for line in s.lines() {
                if line.starts_with("MemTotal:") {
                    if let Some(kb_str) = line.split_whitespace().nth(1) {
                        if let Ok(kb) = kb_str.parse::<u64>() {
                            return (kb / 1024).min(u32::MAX as u64) as u32;
                        }
                    }
                }
            }
        }
    }
    4096
}

fn tx_burn_amount(tx: &Tx) -> Option<u128> {
    match &tx.kind {
        TxKind::Transfer { amount, .. } => Some(*amount),
        TxKind::UptimeReward { amount, .. } => Some(*amount),
        TxKind::JobBid { bid, .. } => Some(*bid),
        TxKind::JobSettle { cost, .. } => Some(*cost),
        TxKind::Heartbeat { amount, .. } => Some(*amount),
        TxKind::HostBond { amount, .. } => Some(*amount),
        TxKind::JobExpire { .. }
        | TxKind::ChannelOpen { .. }
        | TxKind::ChannelClose { .. }
        | TxKind::ChannelExpire { .. }
        | TxKind::NameClaim { .. }
        | TxKind::RevokeCapability { .. }
        | TxKind::HostUnbond { .. }
        | TxKind::SlashEquivocation { .. } => None,
    }
}

#[cfg(test)]
mod capability_tag_tests {
    use super::*;
    use ce_protocol::CellAddress;

    #[test]
    fn capability_tags_reflect_resources() {
        // Always reports OS and ARCH.
        let base = capability_tags(false, 1, 1024);
        assert!(base.contains(&std::env::consts::OS.to_string()));
        assert!(base.contains(&std::env::consts::ARCH.to_string()));
        assert!(!base.contains(&"docker".to_string()));
        assert!(!base.contains(&"manycore".to_string()));
        assert!(!base.contains(&"highmem".to_string()));

        let big = capability_tags(true, 32, 65_536);
        assert!(big.contains(&"docker".to_string()));
        assert!(big.contains(&"manycore".to_string()));
        assert!(big.contains(&"highmem".to_string()));
    }

    #[test]
    fn self_tags_round_trip_through_capacity_signal() {
        let dir = std::env::temp_dir().join(format!("ce-captag-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let identity = Identity::load_or_generate(&dir).unwrap();

        let mut caps = vec![
            Capability { name: "cpu".into(), version: 8 },
            Capability { name: "mem_mb".into(), version: 16_384 },
            Capability { name: "jobs".into(), version: 2 },
        ];
        for t in ["gpu", "linux", "docker"] {
            caps.push(Capability { name: format!("tag:{t}"), version: 1 });
        }

        let signal = CellSignal::build(
            identity.node_id(),
            CellAddress::Broadcast,
            caps,
            vec![],
            None,
            0,
            &identity,
        );

        let parsed = parse_capacity_signal(&signal).expect("capacity parses");
        assert_eq!(parsed.cpu_cores, 8);
        assert_eq!(parsed.mem_mb, 16_384);
        assert_eq!(parsed.running_jobs, 2);
        assert_eq!(parsed.tags, vec!["gpu".to_string(), "linux".to_string(), "docker".to_string()]);
    }

    #[test]
    fn deploy_caveats_reject_over_limit_and_accept_in_limit() {
        // A deploy cap scoped to small ceilings must reject a job that exceeds any of them, and
        // accept one within all of them (regression for H1: caveats were authenticated but never
        // enforced at the Deploy consumption point).
        let cv = ce_cap::Caveats {
            max_cpu: Some(2),
            max_mem_mb: Some(512),
            max_credits: Some(100),
            ..Default::default()
        };

        // Over each ceiling individually → rejected.
        assert!(deploy_within_caveats(&cv, 64, 256, 50).is_err(), "cpu over the ceiling must reject");
        assert!(deploy_within_caveats(&cv, 2, 256_000, 50).is_err(), "mem over the ceiling must reject");
        assert!(deploy_within_caveats(&cv, 2, 256, 1_000).is_err(), "bid over the ceiling must reject");

        // Exactly at every ceiling → accepted (ceilings are inclusive).
        assert!(deploy_within_caveats(&cv, 2, 512, 100).is_ok(), "an at-limit deploy must be accepted");
        // Comfortably within → accepted.
        assert!(deploy_within_caveats(&cv, 1, 256, 50).is_ok(), "an in-limit deploy must be accepted");

        // No ceilings (all None) → anything is accepted.
        let unlimited = ce_cap::Caveats::default();
        assert!(deploy_within_caveats(&unlimited, u32::MAX, u64::MAX, u128::MAX).is_ok());
    }
}

#[cfg(test)]
mod chunk_payment_tests {
    use super::*;
    use ce_chain::channel_receipt_bytes;
    use ce_identity::Identity;

    fn ident(seed: &str) -> Identity {
        let dir = std::env::temp_dir().join(format!("ce-pay-{seed}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Identity::load_or_generate(&dir).unwrap()
    }

    fn receipt(payer: &Identity, host: &NodeId, channel_id: [u8; 32], cumulative: u128) -> ChunkReceipt {
        let payer_sig = payer.sign(&channel_receipt_bytes(&channel_id, host, cumulative));
        ChunkReceipt { channel_id, cumulative, payer_sig }
    }

    #[test]
    fn free_serving_needs_no_receipt() {
        let host = ident("free-host").node_id();
        assert_eq!(authorize_chunk_serve(0, 1024, &host, None, None, 0), Ok(0));
    }

    #[test]
    fn priced_serving_requires_a_receipt() {
        let host = ident("ph").node_id();
        let e = authorize_chunk_serve(10, 100, &host, None, None, 0).unwrap_err();
        assert!(e.contains("no receipt"), "{e}");
    }

    #[test]
    fn valid_receipt_authorizes_and_advances_cumulative() {
        let payer = ident("ok-payer");
        let host = ident("ok-host");
        let host_id = host.node_id();
        let channel_id = [3u8; 32];
        let capacity = 1_000_000u128;
        // Price 10/byte, 1000-byte chunk => cost 10_000. Receipt covers it.
        let r = receipt(&payer, &host_id, channel_id, 10_000);
        let chan = Some((payer.node_id(), host_id, capacity));
        let new_cum = authorize_chunk_serve(10, 1000, &host_id, Some(&r), chan, 0).unwrap();
        assert_eq!(new_cum, 10_000, "records the receipt's cumulative as served");
    }

    #[test]
    fn rejects_insufficient_capacity_or_coverage_or_wrong_host_or_bad_sig() {
        let payer = ident("bad-payer");
        let host = ident("bad-host");
        let other = ident("bad-other");
        let host_id = host.node_id();
        let channel_id = [4u8; 32];

        // Cumulative below cost (cost = 10 * 1000 = 10_000, already served 5_000 => owed 15_000).
        let low = receipt(&payer, &host_id, channel_id, 12_000);
        let chan = Some((payer.node_id(), host_id, 1_000_000));
        assert!(authorize_chunk_serve(10, 1000, &host_id, Some(&low), chan, 5_000)
            .unwrap_err()
            .contains("does not cover"));

        // Cumulative beyond channel capacity.
        let over = receipt(&payer, &host_id, channel_id, 50_000);
        let small = Some((payer.node_id(), host_id, 20_000));
        assert!(authorize_chunk_serve(10, 1000, &host_id, Some(&over), small, 0)
            .unwrap_err()
            .contains("capacity"));

        // Channel hosted by someone else.
        let r = receipt(&payer, &host_id, channel_id, 10_000);
        let foreign = Some((payer.node_id(), other.node_id(), 1_000_000));
        assert!(authorize_chunk_serve(10, 1000, &host_id, Some(&r), foreign, 0)
            .unwrap_err()
            .contains("not hosted"));

        // Signature by the wrong key (other signs but channel payer is `payer`).
        let forged = receipt(&other, &host_id, channel_id, 10_000);
        let chan2 = Some((payer.node_id(), host_id, 1_000_000));
        assert!(authorize_chunk_serve(10, 1000, &host_id, Some(&forged), chan2, 0)
            .unwrap_err()
            .contains("signature"));
    }

    #[test]
    fn relay_free_accepts_any_valid_receipt() {
        let payer = ident("rl-free-p");
        let relay = ident("rl-free-h");
        let r = receipt(&payer, &relay.node_id(), [1u8; 32], 0);
        assert_eq!(relay_authorize(0, 5, 1_000, &payer.node_id(), &relay.node_id(), &r), Ok(0));
    }

    #[test]
    fn relay_priced_requires_time_coverage() {
        let payer = ident("rl-p");
        let relay = ident("rl-h");
        let other = ident("rl-o");
        let relay_id = relay.node_id();
        let chan = [2u8; 32];

        // Price 100/min over 3 minutes => required 300; a covering receipt is accepted.
        let ok = receipt(&payer, &relay_id, chan, 300);
        assert_eq!(relay_authorize(100, 3, 10_000, &payer.node_id(), &relay_id, &ok), Ok(300));

        // Below the time-based requirement.
        let low = receipt(&payer, &relay_id, chan, 200);
        assert!(relay_authorize(100, 3, 10_000, &payer.node_id(), &relay_id, &low)
            .unwrap_err()
            .contains("does not cover"));

        // Beyond channel capacity.
        let over = receipt(&payer, &relay_id, chan, 5_000);
        assert!(relay_authorize(100, 3, 1_000, &payer.node_id(), &relay_id, &over)
            .unwrap_err()
            .contains("capacity"));

        // Signed by the wrong key.
        let forged = receipt(&other, &relay_id, chan, 300);
        assert!(relay_authorize(100, 3, 10_000, &payer.node_id(), &relay_id, &forged)
            .unwrap_err()
            .contains("signature"));
    }
}
