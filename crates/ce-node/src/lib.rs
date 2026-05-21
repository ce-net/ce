mod api;

use anyhow::Result;
use ce_chain::{Block, Chain, Tx};
use ce_container::{meter_reading_to_tx_kind, ContainerManager, MeterReading};
use ce_identity::{NodeId, Identity};
use ce_mesh::{Mesh, MeshEvent, MeshHandle};
use directories::ProjectDirs;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};

// ----- Pending TX pool -----

#[derive(Clone)]
struct TxPool(Arc<Mutex<HashMap<[u8; 32], Tx>>>);

impl TxPool {
    fn new() -> Self {
        TxPool(Arc::new(Mutex::new(HashMap::new())))
    }

    async fn add(&self, tx: Tx) {
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

// ----- Node config -----

pub struct NodeConfig {
    pub listen_port: u16,
    pub bootstrap_peers: Vec<String>,
    pub data_dir: PathBuf,
    pub api_port: u16,
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

        let pool = TxPool::new();

        let node = Self {
            identity: identity.clone(),
            chain: chain.clone(),
            mesh_handle: mesh_handle.clone(),
            config,
        };

        // Spawn mesh run loop.
        let listen_port = node.config.listen_port;
        tokio::spawn(async move {
            if let Err(e) = mesh.run(listen_port).await {
                warn!("mesh exited: {e}");
            }
        });

        // Announce our initial chain height so joining peers can sync from us.
        {
            let c = chain.lock().await;
            let h = c.height();
            let tip = c.tip_hash();
            let _ = mesh_handle.announce_height(identity.node_id(), h, tip).await;
        }

        // Spawn mining loop.
        {
            let chain = chain.clone();
            let identity = identity.clone();
            let handle = mesh_handle.clone();
            let chain_path = node.config.data_dir.join("chain").join("chain.json");
            let pool = pool.clone();
            tokio::spawn(async move {
                mining_loop(chain, identity, handle, chain_path, pool).await;
            });
        }

        // Spawn mesh event handler.
        {
            let chain = chain.clone();
            let chain_path = node.config.data_dir.join("chain").join("chain.json");
            let handle = mesh_handle.clone();
            let node_id = identity.node_id();
            let pool = pool.clone();
            tokio::spawn(async move {
                mesh_event_loop(chain, mesh_rx, chain_path, handle, node_id, pool).await;
            });
        }

        // Spawn container metering (silently skipped if Docker is unavailable).
        {
            let identity = identity.clone();
            let handle = mesh_handle.clone();
            tokio::spawn(async move {
                start_metering(identity, handle).await;
            });
        }

        // Spawn HTTP API server.
        {
            let chain = chain.clone();
            let host = identity.node_id();
            let api_port = node.config.api_port;
            tokio::spawn(async move {
                if let Err(e) = api::start(chain, host, api_port).await {
                    warn!("API server: {e}");
                }
            });
        }

        Ok(node)
    }

    pub async fn balance(&self) -> i64 {
        self.chain.lock().await.balance(&self.identity.node_id())
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
) {
    loop {
        let (mut block, difficulty) = {
            let c = chain.lock().await;
            let pending = pool.drain(100).await; // drain up to 100 pending txs
            // Release the lock before calling pool.drain — can't hold across await.
            // Actually pool.drain takes its own lock so this is fine; re-acquire chain.
            let b = c.next_block(pending, identity.node_id());
            (b, c.difficulty)
        };

        let mined = tokio::task::spawn_blocking(move || {
            block.mine(difficulty);
            block
        })
        .await
        .expect("mining task panicked");

        info!("mined block {} (nonce={})", mined.index, mined.nonce);

        let (height, tip_hash) = {
            let mut c = chain.lock().await;
            if c.append(mined.clone()) {
                pool.remove_included(&mined).await;
                if let Err(e) = c.save(&chain_path) {
                    warn!("save chain: {e}");
                }
            }
            (c.height(), c.tip_hash())
        };

        let _ = mesh_handle.broadcast_block(&mined).await;
        let _ = mesh_handle.announce_height(identity.node_id(), height, tip_hash).await;
    }
}

// ----- Mesh event loop -----

async fn mesh_event_loop(
    chain: Arc<Mutex<Chain>>,
    mut rx: mpsc::Receiver<MeshEvent>,
    chain_path: PathBuf,
    mesh_handle: MeshHandle,
    our_node_id: NodeId,
    pool: TxPool,
) {
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
                    warn!("rejected block {} from mesh (index/hash/diff mismatch)", block.index);
                }
            }
            MeshEvent::NewTx(tx) => {
                match tx.verify() {
                    Ok(()) => pool.add(tx).await,
                    Err(e) => warn!("invalid tx from mesh: {e}"),
                }
            }
            MeshEvent::PeerHeight { node_id, height, tip_hash: _ } => {
                let our_height = chain.lock().await.height();
                if height > our_height {
                    info!("peer {} is at height {}, we're at {} — requesting sync", hex::encode(&node_id[..4]), height, our_height);
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
                    info!("serving {} blocks from height {} to {}", blocks.len(), from_height, blocks.last().unwrap().index);
                    let _ = mesh_handle.send_sync_response(from_node, blocks).await;
                }
            }
            MeshEvent::SyncBlocks { for_node, blocks } => {
                if for_node != our_node_id {
                    continue; // not for us
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
        }
    }
}

// ----- Container metering -----

async fn start_metering(identity: Arc<Identity>, mesh_handle: MeshHandle) {
    let (reading_tx, mut reading_rx) = mpsc::channel::<MeterReading>(64);
    let host = identity.node_id();

    let manager = match ContainerManager::new(host) {
        Ok(m) => m,
        Err(e) => {
            warn!("Docker unavailable, metering disabled: {e}");
            return;
        }
    };

    tokio::spawn(async move {
        if let Err(e) = manager.run(reading_tx).await {
            warn!("container manager: {e}");
        }
    });

    while let Some(reading) = reading_rx.recv().await {
        let kind = meter_reading_to_tx_kind(&reading);
        let data = match bincode::serialize(&kind) {
            Ok(d) => d,
            Err(e) => { warn!("serialize meter tx: {e}"); continue; }
        };
        let sig = identity.sign(&data);
        let tx = Tx::new(kind, host, sig);
        if let Err(e) = mesh_handle.broadcast_tx(&tx).await {
            warn!("broadcast meter tx: {e}");
        }
    }
}
