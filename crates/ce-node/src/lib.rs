mod api;
pub mod auth;
pub mod devices;

use anyhow::Result;
use ce_chain::{Block, Chain, Tx, TxKind};
use ce_container::{ContainerManager, JobSpec};
use ce_identity::{Identity, NodeId};
use ce_mesh::{Mesh, MeshEvent, MeshHandle};
use ce_protocol::{CellSignal, Capability};
use directories::ProjectDirs;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, mpsc, Mutex};
use tracing::{info, warn};

/// Max number of recently-validated signals retained for GET /signals.
const SIGNAL_RING_CAPACITY: usize = 100;

pub(crate) type SignalRing = Arc<Mutex<VecDeque<CellSignal>>>;

/// Capacity snapshot cached from incoming peer capacity signals.
#[derive(Debug, Clone, Serialize)]
pub struct PeerCapacity {
    pub cpu_cores: u32,
    pub mem_mb: u32,
    pub running_jobs: u32,
    pub last_seen_secs: u64,
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
    chain: Arc<Mutex<Chain>>,
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

        let chain = Arc::new(Mutex::new(Chain::load_or_genesis(&chain_path)));
        {
            let c = chain.lock().await;
            info!("chain height: {}", c.height());
        }

        let (mesh, mesh_handle, mesh_rx) = Mesh::new(identity.secret_bytes())?;

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
        let send_nonce = Arc::new(AtomicU64::new(0));
        let job_store: JobStore = Arc::new(Mutex::new(HashMap::new()));
        let atlas: Atlas = Arc::new(Mutex::new(HashMap::new()));

        // Channel: mesh event loop → job manager for incoming JobBid txs.
        let (bid_notify_tx, bid_notify_rx) = mpsc::channel::<Tx>(64);
        // Channel: settle API endpoint → job manager to trigger immediate settle check.
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
            let c = chain.lock().await;
            let h = c.height();
            let tip = c.tip_hash();
            let _ = mesh_handle.announce_height(identity.node_id(), h, tip).await;
        }

        if node.config.mine {
            let chain = chain.clone();
            let identity = identity.clone();
            let handle = mesh_handle.clone();
            let chain_path2 = node.config.data_dir.join("chain").join("chain.json");
            let pool = pool.clone();
            let interval = node.config.mining_interval_secs;
            tokio::spawn(async move {
                mining_loop(chain, identity, handle, chain_path2, pool, interval).await;
            });
        }

        {
            let chain = chain.clone();
            let chain_path2 = node.config.data_dir.join("chain").join("chain.json");
            let handle = mesh_handle.clone();
            let node_id = identity.node_id();
            let pool = pool.clone();
            let signals = signals.clone();
            let signal_tx = signal_tx.clone();
            let atlas2 = atlas.clone();
            tokio::spawn(async move {
                mesh_event_loop(
                    chain,
                    mesh_rx,
                    chain_path2,
                    handle,
                    node_id,
                    pool,
                    signals,
                    signal_tx,
                    bid_notify_tx,
                    atlas2,
                )
                .await;
            });
        }

        {
            let chain = chain.clone();
            let identity = identity.clone();
            let handle = mesh_handle.clone();
            let chain_path2 = node.config.data_dir.join("chain").join("chain.json");
            let pool = pool.clone();
            let js = job_store.clone();
            tokio::spawn(async move {
                job_manager_loop(
                    chain,
                    identity,
                    handle,
                    chain_path2,
                    pool,
                    js,
                    bid_notify_rx,
                    settle_notify_rx,
                )
                .await;
            });
        }

        // Capacity broadcast: every 60s announce CPU/memory/job capacity as a CEP-1 signal.
        if node.config.mine {
            let identity2 = identity.clone();
            let handle2 = mesh_handle.clone();
            let job_store2 = job_store.clone();
            let send_nonce2 = send_nonce.clone();
            tokio::spawn(async move {
                capacity_broadcast_loop(identity2, handle2, job_store2, send_nonce2).await;
            });
        }

        {
            let chain = chain.clone();
            let identity = identity.clone();
            let mesh_handle = mesh_handle.clone();
            let signals = signals.clone();
            let api_port = node.config.api_port;
            let send_nonce = send_nonce.clone();
            let js = job_store.clone();
            let pool = pool.clone();
            let data_dir = node.config.data_dir.clone();
            let atlas3 = atlas.clone();
            tokio::spawn(async move {
                if let Err(e) = api::start(
                    chain,
                    identity,
                    mesh_handle,
                    signals,
                    send_nonce,
                    api_port,
                    js,
                    pool,
                    settle_notify_tx,
                    data_dir,
                    atlas3,
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
        self.chain.lock().await.balance(&self.identity.node_id())
    }

    pub async fn any_burnable_tx(&self) -> Option<([u8; 32], u64)> {
        let chain = self.chain.lock().await;
        for block in &chain.blocks {
            for tx in &block.transactions {
                if let Some(amt) = tx_burn_amount(tx) {
                    return Some((tx.id(), amt));
                }
            }
        }
        None
    }

    pub async fn status(&self) -> NodeStatus {
        let chain = self.chain.lock().await;
        NodeStatus {
            node_id: self.identity.node_id_hex(),
            height: chain.height(),
            difficulty: chain.difficulty,
            balance: chain.balance(&self.identity.node_id()),
            listen_port: self.config.listen_port,
            api_port: self.config.api_port,
        }
    }
}

#[derive(Debug)]
pub struct NodeStatus {
    pub node_id: String,
    pub height: u64,
    pub difficulty: u8,
    pub balance: i64,
    pub listen_port: u16,
    pub api_port: u16,
}

// ----- Mining loop -----

async fn mining_loop(
    chain: Arc<Mutex<Chain>>,
    identity: Arc<Identity>,
    mesh_handle: MeshHandle,
    chain_path: PathBuf,
    pool: TxPool,
    interval_secs: u64,
) {
    let mut ticker =
        tokio::time::interval(std::time::Duration::from_secs(interval_secs));
    loop {
        ticker.tick().await;

        let mut pending = pool.drain(100).await;

        let mut block = {
            let c = chain.lock().await;
            let next_index = c.tip().index + 1;
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
            c.next_block(pending, identity.node_id())
        };

        block.seal(&identity);

        info!("sealed block {}", block.index);

        let (height, tip_hash) = {
            let mut c = chain.lock().await;
            if c.append(block.clone()) {
                pool.remove_included(&block).await;
                if let Err(e) = c.save(&chain_path) {
                    warn!("save chain: {e}");
                }
            }
            (c.height(), c.tip_hash())
        };

        let _ = mesh_handle.broadcast_block(&block).await;
        let _ = mesh_handle.announce_height(identity.node_id(), height, tip_hash).await;
    }
}

// ----- Mesh event loop -----

#[allow(clippy::too_many_arguments)]
async fn mesh_event_loop(
    chain: Arc<Mutex<Chain>>,
    mut rx: mpsc::Receiver<MeshEvent>,
    chain_path: PathBuf,
    mesh_handle: MeshHandle,
    our_node_id: NodeId,
    pool: TxPool,
    signals: SignalRing,
    signal_tx: broadcast::Sender<CellSignal>,
    bid_notify_tx: mpsc::Sender<Tx>,
    atlas: Atlas,
) {
    // Tracks the highest accepted nonce per sender to prevent replays.
    let mut last_nonce: HashMap<NodeId, u64> = HashMap::new();

    while let Some(event) = rx.recv().await {
        match event {
            MeshEvent::NewBlock(block) => {
                let mut c = chain.lock().await;
                if c.append(block.clone()) {
                    info!("accepted block {} from mesh", block.index);
                    pool.remove_included(&block).await;
                    if let Err(e) = c.save(&chain_path) {
                        warn!("save chain: {e}");
                    }
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
                        // Forward JobBid txs to the job manager before pooling.
                        if matches!(tx.kind, TxKind::JobBid { .. }) {
                            let _ = bid_notify_tx.send(tx.clone()).await;
                        }
                        pool.add(tx).await;
                    }
                    Err(e) => warn!("invalid tx from mesh: {e}"),
                }
            }
            MeshEvent::PeerHeight { node_id, height, tip_hash: _ } => {
                let our_height = chain.lock().await.height();
                if height > our_height {
                    info!(
                        "peer {} is at height {}, we're at {} — requesting sync",
                        hex::encode(&node_id[..4]),
                        height,
                        our_height
                    );
                    let _ = mesh_handle.send_sync_request(our_node_id, our_height).await;
                }
            }
            MeshEvent::SyncRequest { from_node, from_height } => {
                let blocks: Vec<Block> = {
                    let c = chain.lock().await;
                    c.blocks
                        .iter()
                        .filter(|b| b.index > from_height)
                        .take(500)
                        .cloned()
                        .collect()
                };
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
                let mut applied = 0u64;
                let mut c = chain.lock().await;
                for block in blocks {
                    if c.append(block) {
                        applied += 1;
                    }
                }
                if applied > 0 {
                    info!("sync applied {applied} blocks, now at height {}", c.height());
                    if let Err(e) = c.save(&chain_path) {
                        warn!("save chain after sync: {e}");
                    }
                }
            }
            MeshEvent::PeerConnected(peer) => info!("peer connected: {peer}"),
            MeshEvent::PeerDisconnected(peer) => info!("peer disconnected: {peer}"),
            MeshEvent::CellSignal(signal) => {
                // Reject replays: nonce must strictly increase per sender.
                // Only enforced once we've seen at least one signal from them.
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

                if signal.requires_burn() {
                    warn!(
                        "dropping ce-protocol-1 signal from {}: payload without burn_proof",
                        hex::encode(&signal.from[..4]),
                    );
                    continue;
                }
                if let Some(burn) = &signal.burn_proof {
                    let lookup = {
                        let c = chain.lock().await;
                        c.tx_by_id(&burn.tx_id)
                    };
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
                }
                last_nonce.insert(signal.from, signal.nonce);

                // Update atlas if this is a capacity advertisement.
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

// ----- Job manager loop -----

#[allow(clippy::too_many_arguments)]
async fn job_manager_loop(
    chain: Arc<Mutex<Chain>>,
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

    // Per-container tasks send (job_id, exit_code) when the container exits.
    let (completion_tx, mut completion_rx) = mpsc::channel::<([u8; 32], i64)>(32);
    let mut settle_ticker = tokio::time::interval(std::time::Duration::from_secs(5));
    let mut heartbeat_ticker = tokio::time::interval(std::time::Duration::from_secs(30));
    // Skip the first (immediate) tick so the heartbeat fires 30s after start.
    heartbeat_ticker.tick().await;

    // Initialize heartbeat epoch counters from chain state (survives restarts).
    let mut heartbeat_epochs: HashMap<NodeId, u64> = {
        let c = chain.lock().await;
        let host_id = identity.node_id();
        let mut epochs: HashMap<NodeId, u64> = HashMap::new();
        for block in &c.blocks {
            for tx in &block.transactions {
                if let ce_chain::TxKind::Heartbeat { cell, host, epoch, .. } = &tx.kind {
                    if host == &host_id {
                        let e = epochs.entry(*cell).or_insert(0);
                        if *epoch >= *e {
                            *e = *epoch + 1;
                        }
                    }
                }
            }
        }
        epochs
    };

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

        // Submit settle txs for any jobs that now have a payer signature.
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

/// Accept a JobBid from the mesh: pull the image, start the container, record the job.
async fn handle_incoming_bid(
    tx: Tx,
    identity: &Identity,
    manager: &ContainerManager,
    job_store: &JobStore,
    completion_tx: &mpsc::Sender<([u8; 32], i64)>,
) {
    let TxKind::JobBid { job_id, payer, image, cmd, env, cpu_cores, mem_mb, bid, duration_secs, .. } = &tx.kind
    else {
        return;
    };
    let (bid, duration_secs) = (*bid, *duration_secs);

    // Never accept our own bids; chain would reject the settle (payer == host).
    if payer == &identity.node_id() {
        return;
    }

    // Skip if already accepted (duplicate gossip).
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
            // Spawn a task that waits for the container to exit, then notifies.
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

/// Build and submit JobSettle txs for jobs in AwaitingSettlement state that have a payer_sig.
async fn submit_pending_settles(
    chain: &Arc<Mutex<Chain>>,
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

        // Update status immediately; the chain confirms later.
        let mut store = job_store.lock().await;
        if let Some(r) = store.get_mut(&job_id) {
            r.status = CeJobStatus::Settled;
        }
    }

    // Also mark as Settled any jobs for which we find a confirmed JobSettle on-chain.
    let settled_on_chain: Vec<[u8; 32]> = {
        let c = chain.lock().await;
        c.blocks
            .iter()
            .flat_map(|b| &b.transactions)
            .filter_map(|tx| {
                if let TxKind::JobSettle { job_id, host, .. } = &tx.kind {
                    if host == &identity.node_id() { Some(*job_id) } else { None }
                } else {
                    None
                }
            })
            .collect()
    };
    if !settled_on_chain.is_empty() {
        let _ = chain.lock().await.save(chain_path);
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

/// Emit Heartbeat txs for all Running jobs. Returns (job_id, container_id) pairs
/// for cells whose balance is too low to afford the next heartbeat.
async fn emit_heartbeats(
    chain: &Arc<Mutex<Chain>>,
    identity: &Identity,
    mesh_handle: &MeshHandle,
    pool: &TxPool,
    job_store: &JobStore,
    heartbeat_epochs: &mut HashMap<NodeId, u64>,
) -> Vec<([u8; 32], Option<String>)> {
    // Snapshot running jobs: (payer, bid, duration_secs, job_id, container_id)
    let running: Vec<(NodeId, u64, u64, [u8; 32], Option<String>)> = {
        let store = job_store.lock().await;
        store.values()
            .filter(|r| matches!(r.status, CeJobStatus::Running))
            .map(|r| (r.payer, r.bid, r.duration_secs, r.job_id, r.container_id.clone()))
            .collect()
    };

    let mut to_terminate: Vec<([u8; 32], Option<String>)> = Vec::new();

    for (cell, bid, duration_secs, job_id, container_id) in running {
        // Heartbeat rate: spread the bid evenly over 30-second intervals.
        let intervals = (duration_secs / 30).max(1);
        let amount = bid / intervals;
        if amount == 0 {
            continue;
        }

        let cell_balance = chain.lock().await.balance(&cell);
        if cell_balance < amount as i64 {
            info!(
                "cell {} insufficient balance ({cell_balance}) for heartbeat {amount}, terminating job {}",
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

/// Broadcast this node's available capacity as a capability-only CEP-1 signal every 60 seconds.
/// Capabilities encode cpu_cores / mem_mb / running_jobs so peers can build an atlas.
async fn capacity_broadcast_loop(
    identity: Arc<Identity>,
    mesh_handle: MeshHandle,
    job_store: JobStore,
    send_nonce: Arc<AtomicU64>,
) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
    // Skip immediate first tick.
    ticker.tick().await;

    // Read available system resources once (approximation; accurate values need sysinfo).
    let cpu_cores = num_cpus() as u32;
    let mem_mb = available_mem_mb();

    loop {
        ticker.tick().await;

        let running_jobs = {
            let store = job_store.lock().await;
            store.values().filter(|r| matches!(r.status, CeJobStatus::Running)).count() as u32
        };

        let capabilities = vec![
            Capability { name: "cpu".into(), version: cpu_cores },
            Capability { name: "mem_mb".into(), version: mem_mb },
            Capability { name: "jobs".into(), version: running_jobs },
        ];

        let nonce = send_nonce.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let signal = CellSignal::build(
            identity.node_id(),
            ce_protocol::CellAddress::Broadcast,
            capabilities,
            vec![],   // empty payload — no burn proof required
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

/// Extract a PeerCapacity from an incoming capacity advertisement signal.
/// Returns None if the signal is not a capacity advertisement.
fn parse_capacity_signal(signal: &CellSignal) -> Option<PeerCapacity> {
    let mut cpu = None;
    let mut mem = None;
    let mut jobs = None;
    for cap in &signal.capabilities {
        match cap.name.as_str() {
            "cpu"    => cpu  = Some(cap.version),
            "mem_mb" => mem  = Some(cap.version),
            "jobs"   => jobs = Some(cap.version),
            _ => {}
        }
    }
    let (cpu_cores, mem_mb) = cpu.zip(mem)?;
    let last_seen_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Some(PeerCapacity { cpu_cores, mem_mb, running_jobs: jobs.unwrap_or(0), last_seen_secs })
}

fn num_cpus() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

fn available_mem_mb() -> u32 {
    // Best-effort: read /proc/meminfo on Linux; fall back to 4096.
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
        // JobExpire and TrustGrant carry no burnable credit amount.
        TxKind::JobExpire { .. } | TxKind::TrustGrant { .. } => None,
    }
}
