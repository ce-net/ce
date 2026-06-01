mod api;
pub mod auth;
pub mod chain_actor;
pub mod devices;
pub mod grants;

pub use chain_actor::{ChainHandle, ChainStatusSnap, SyncSnap, spawn_chain_actor};

/// Derive the libp2p PeerId string from a CE identity (same Ed25519 key, different encoding).
pub fn peer_id_from_identity(identity: &ce_identity::Identity) -> anyhow::Result<String> {
    ce_mesh::peer_id_from_secret(identity.secret_bytes()).map(|p| p.to_string())
}

use anyhow::Result;
use bollard::Docker;
use ce_chain::{Block, Chain, Tx, TxKind};
use ce_container::{ContainerManager, ExecSpec, JobSpec, exec_in_container};
use ce_identity::{Identity, NodeId};
use ce_mesh::{Mesh, MeshEvent, MeshHandle, RpcRequest, RpcResponse, peer_id_from_node_id};
use ce_protocol::{CellSignal, Capability};
use directories::ProjectDirs;
use serde::Serialize;
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
    pub cost: Option<u64>,
    /// Original bid amount from the JobBid tx. Used for heartbeat rate calculation.
    pub bid: u64,
    /// Expected job duration in seconds. Used for heartbeat rate calculation.
    pub duration_secs: u64,
}

/// Shared job store: maps CE job_id ([u8;32]) → job record.
pub(crate) type JobStore = Arc<Mutex<HashMap<[u8; 32], JobRecord>>>;

// ----- Node config -----

pub struct NodeConfig {
    pub listen_port: u16,
    pub bootstrap_peers: Vec<String>,
    /// Circuit relay nodes (multiaddrs with /p2p/<peer-id>). On connect, the node
    /// listens on their circuit address to become reachable through NAT.
    pub relay_peers: Vec<String>,
    pub data_dir: PathBuf,
    pub api_port: u16,
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
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            listen_port: 0,
            bootstrap_peers: vec![],
            relay_peers: vec![],
            data_dir: Self::default_data_dir(),
            api_port: 0,
            mine: true,
            mining_interval_secs: 10,
            prune_keep: None,
            archive_density: ce_chain::ARCHIVE_DENSITY,
            disable_local_discovery: false,
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

        // Capability self-tags, computed once and shared by the capacity broadcast (what we
        // advertise) and both auth enforcement points (what grant selectors match against),
        // so the advertised set and the enforced set can never diverge.
        let self_tags = capability_tags(docker_available, num_cpus() as u32, available_mem_mb());

        let (mesh, mesh_handle, mesh_rx) = if config.disable_local_discovery {
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
        let send_nonce = Arc::new(AtomicU64::new(0));
        let job_store: JobStore = Arc::new(Mutex::new(HashMap::new()));
        let atlas: Atlas = Arc::new(Mutex::new(HashMap::new()));

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

        if node.config.mine {
            let chain2 = chain.clone();
            let identity2 = identity.clone();
            let handle2 = mesh_handle.clone();
            let chain_path2 = node.config.data_dir.join("chain").join("chain.json");
            let pool2 = pool.clone();
            let interval = node.config.mining_interval_secs;
            let block_tx2 = block_tx.clone();
            tokio::spawn(async move {
                mining_loop(chain2, identity2, handle2, chain_path2, pool2, interval, block_tx2)
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
            let data_dir2 = node.config.data_dir.clone();
            let docker2 = docker.clone();
            let prune_keep = node.config.prune_keep;
            let archive_density = node.config.archive_density;
            let archive_dir2 = node.config.data_dir.join("archive");
            let disable_local_discovery = node.config.disable_local_discovery;
            let self_tags2 = self_tags.clone();
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
                    data_dir2,
                    docker2,
                    prune_keep,
                    archive_density,
                    archive_dir2,
                    disable_local_discovery,
                    self_tags2,
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

        {
            let chain2 = chain.clone();
            let identity2 = identity.clone();
            let mesh_handle2 = mesh_handle.clone();
            let signals2 = signals.clone();
            let api_port = node.config.api_port;
            let p2p_port = node.config.listen_port;
            let send_nonce2 = send_nonce.clone();
            let js = job_store.clone();
            let pool2 = pool.clone();
            let data_dir2 = node.config.data_dir.clone();
            let atlas3 = atlas.clone();
            let docker3 = docker.clone();
            let self_tags3 = self_tags.clone();
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
                    p2p_port,
                    js,
                    pool2,
                    settle_notify_tx,
                    data_dir2,
                    atlas3,
                    docker3,
                    self_tags3,
                )
                .await
                {
                    warn!("API server: {e}");
                }
            });
        }

        Ok(node)
    }

    pub async fn balance(&self) -> i64 {
        self.chain.balance(self.identity.node_id()).await
    }

    pub async fn any_burnable_tx(&self) -> Option<([u8; 32], u64)> {
        self.chain.any_burnable_tx().await
    }

    pub async fn any_burnable_tx_by_self(&self) -> Option<([u8; 32], u64)> {
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
    pub balance: i64,
    pub listen_port: u16,
    pub api_port: u16,
}

// ----- Mining loop -----

async fn mining_loop(
    chain: ChainHandle,
    identity: Arc<Identity>,
    mesh_handle: MeshHandle,
    chain_path: PathBuf,
    pool: TxPool,
    interval_secs: u64,
    block_tx: broadcast::Sender<Block>,
) {
    let mut ticker =
        tokio::time::interval(std::time::Duration::from_secs(interval_secs));
    loop {
        ticker.tick().await;

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

        let mut block = chain.next_block(pending, identity.node_id()).await;
        block.seal(&identity);
        info!("sealed block {}", block.index);

        if chain.append(block.clone()).await {
            pool.remove_included(&block).await;
            if let Err(e) = chain.save(chain_path.clone()).await {
                warn!("save chain: {e}");
            }
            let _ = block_tx.send(block.clone());
        }

        let _ = mesh_handle.broadcast_block(&block).await;
        let snap = chain.sync_snap().await;
        let _ = mesh_handle
            .announce_height(identity.node_id(), snap.height, snap.tip_hash, snap.oldest)
            .await;
    }
}

// ----- Mesh event loop -----

#[allow(clippy::too_many_arguments)]
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
    data_dir: PathBuf,
    docker: Option<Docker>,
    prune_keep: Option<u64>,
    archive_density: f64,
    archive_dir: PathBuf,
    disable_local_discovery: bool,
    self_tags: Vec<String>,
) {
    let mut last_nonce: HashMap<NodeId, u64> = HashMap::new();
    let mut peer_heights: HashMap<NodeId, u64> = HashMap::new();
    let mut peer_oldest: HashMap<NodeId, u64> = HashMap::new();
    let mut peer_segments: HashMap<NodeId, Vec<u64>> = HashMap::new();

    {
        let held = ce_chain::list_archive_segments(&archive_dir);
        if !held.is_empty() {
            let _ = mesh_handle.announce_segments(our_node_id, held).await;
        }
    }

    let mut segment_announce_ticker =
        tokio::time::interval(std::time::Duration::from_secs(300));
    let mut sync_retry_ticker =
        tokio::time::interval(std::time::Duration::from_secs(15));

    loop {
        let event = tokio::select! {
            _ = segment_announce_ticker.tick() => {
                let held = ce_chain::list_archive_segments(&archive_dir);
                let _ = mesh_handle.announce_segments(our_node_id, held).await;
                continue;
            }
            _ = sync_retry_ticker.tick() => {
                let our_height = chain.height().await;
                let best = peer_heights.values().copied().max().unwrap_or(0);
                if best > our_height {
                    debug!("sync retry: we={our_height}, best peer={best}");
                    let _ = mesh_handle.send_sync_request(our_node_id, our_height).await;
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
                    if let Err(e) = chain.save(chain_path.clone()).await {
                        warn!("save chain: {e}");
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

                    if let Err(e) = chain.save(chain_path.clone()).await {
                        warn!("save chain after sync: {e}");
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
                } else {
                    handle_incoming_rpc(
                        from_peer,
                        correlation_id,
                        request,
                        &data_dir,
                        docker.clone(),
                        mesh_handle.clone(),
                        &self_tags,
                    );
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

                let sender_is_trusted = {
                    let path = data_dir.join("machines.toml");
                    crate::devices::Devices::load_or_empty(&path).is_trusted(&signal.from)
                };
                if signal.requires_burn() && !sender_is_trusted {
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

// ----- Incoming mesh RPC handler -----

fn handle_incoming_rpc(
    from_peer: ce_mesh::CePeerId,
    correlation_id: u64,
    request: RpcRequest,
    data_dir: &Path,
    docker: Option<Docker>,
    mesh_handle: MeshHandle,
    self_tags: &[String],
) {
    use crate::grants::{authorize, Permission, SignedGrant};

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

    // 2. Scoped authorization: the action this RPC performs, and any grant it carries.
    let (action, grant_bytes): (Permission, Option<Vec<u8>>) = match &request {
        RpcRequest::Exec { grant, .. } => (Permission::Exec, grant.clone()),
        RpcRequest::SyncFile { grant, .. } => (Permission::Sync, grant.clone()),
        RpcRequest::SegmentFetch { .. } => unreachable!("SegmentFetch handled in event loop"),
    };
    let grant = match grant_bytes.as_deref().map(bincode::deserialize::<SignedGrant>) {
        Some(Ok(g)) => Some(g),
        Some(Err(_)) => {
            reject("malformed grant".into());
            return;
        }
        None => None,
    };
    let devices = crate::devices::Devices::load_or_empty(&data_dir.join("machines.toml"));
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    if let Err(reason) = authorize(&devices, self_tags, now, &from_node, action, grant.as_ref()) {
        warn!("rpc: denied {} from {}: {reason}", action.as_str(), hex::encode(&from_node[..4]));
        reject(reason);
        return;
    }

    match request {
        RpcRequest::Exec { image, cmd, cwd, .. } => {
            let Some(docker) = docker else {
                tokio::spawn(async move {
                    let _ = mesh_handle
                        .respond_rpc(
                            correlation_id,
                            RpcResponse::Error("Docker not available on this node".into()),
                        )
                        .await;
                });
                return;
            };
            tokio::spawn(async move {
                let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
                let spec = ExecSpec { image, cmd, cwd };
                let resp = match exec_in_container(&docker, &spec, &home).await {
                    Ok((stdout, stderr, exit_code)) => RpcResponse::ExecResult {
                        stdout,
                        stderr,
                        exit_code: exit_code as i32,
                    },
                    Err(e) => RpcResponse::Error(format!("exec failed: {e}")),
                };
                let _ = mesh_handle.respond_rpc(correlation_id, resp).await;
            });
        }
        RpcRequest::SegmentFetch { .. } => unreachable!("SegmentFetch handled in event loop"),
        RpcRequest::SyncFile { path, data, .. } => {
            let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
            let home_canon = home.canonicalize().unwrap_or(home.clone());

            let resp = (|| -> RpcResponse {
                if path.contains("..") {
                    return RpcResponse::Error("path traversal not allowed".into());
                }
                let target = home.join(&path);
                let canonical = match target.parent() {
                    Some(p) => {
                        let _ = std::fs::create_dir_all(p);
                        match p.canonicalize().ok().map(|cp| {
                            cp.join(target.file_name().unwrap_or_default())
                        }) {
                            Some(c) => c,
                            None => {
                                return RpcResponse::Error("cannot resolve target path".into())
                            }
                        }
                    }
                    None => return RpcResponse::Error("invalid path".into()),
                };
                if !canonical.starts_with(&home_canon) {
                    return RpcResponse::Error("path traversal not allowed".into());
                }
                match std::fs::write(&canonical, &data) {
                    Ok(()) => {
                        info!("mesh sync: wrote {} ({} bytes)", canonical.display(), data.len());
                        RpcResponse::SyncAck
                    }
                    Err(e) => RpcResponse::Error(format!("write failed: {e}")),
                }
            })();

            tokio::spawn(async move {
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
    pool: &TxPool,
    job_store: &JobStore,
) {
    let ready: Vec<([u8; 32], NodeId, u64, [u8; 64])> = {
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
        let _ = chain.save(chain_path.clone()).await;
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
    let running: Vec<(NodeId, u64, u64, [u8; 32], Option<String>)> = {
        let store = job_store.lock().await;
        store
            .values()
            .filter(|r| matches!(r.status, CeJobStatus::Running))
            .map(|r| (r.payer, r.bid, r.duration_secs, r.job_id, r.container_id.clone()))
            .collect()
    };

    let mut to_terminate: Vec<([u8; 32], Option<String>)> = Vec::new();

    for (cell, bid, duration_secs, job_id, container_id) in running {
        let intervals = (duration_secs / 30).max(1);
        let amount = bid / intervals;
        if amount == 0 {
            continue;
        }

        let cell_balance = chain.balance(cell).await;
        if cell_balance < amount as i64 {
            info!(
                "cell {} insufficient balance ({cell_balance}) for heartbeat {amount}, \
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

        let kind = TxKind::Heartbeat { cell, host: identity.node_id(), amount, epoch };
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

fn tx_burn_amount(tx: &Tx) -> Option<u64> {
    match &tx.kind {
        TxKind::Transfer { amount, .. } => Some(*amount),
        TxKind::UptimeReward { amount, .. } => Some(*amount),
        TxKind::JobBid { bid, .. } => Some(*bid),
        TxKind::JobSettle { cost, .. } => Some(*cost),
        TxKind::Heartbeat { amount, .. } => Some(*amount),
        TxKind::JobExpire { .. } | TxKind::TrustGrant { .. } => None,
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
}
