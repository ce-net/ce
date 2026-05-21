use anyhow::{anyhow, Result};
use ce_chain::{Block, Tx};
use ce_identity::NodeId;
use libp2p::{
    futures::StreamExt,
    gossipsub, identify, kad,
    noise, swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, SwarmBuilder,
};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use serde::{Deserialize, Serialize};

pub use ce_identity::NodeId as CeNodeId;
pub use libp2p::PeerId as CePeerId;

/// Compute the libp2p PeerId from a CE node's 32-byte secret key.
/// Useful in tests to compute bootstrap multiaddrs before a node starts.
pub fn peer_id_from_secret(secret: [u8; 32]) -> anyhow::Result<libp2p::PeerId> {
    let sec = libp2p::identity::ed25519::SecretKey::try_from_bytes(secret)?;
    let kp = libp2p::identity::Keypair::from(libp2p::identity::ed25519::Keypair::from(sec));
    Ok(kp.public().to_peer_id())
}

// ----- Wire types for sync protocol -----

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HeightAnnounce {
    node_id: NodeId,
    height: u64,
    tip_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncReqMsg {
    from_node: NodeId,
    from_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncRespMsg {
    for_node: NodeId,
    blocks: Vec<Block>,
}

const MAX_BLOCKS_PER_SYNC: usize = 500;

// ----- Command channel -----

enum MeshCommand {
    PublishTx(Vec<u8>),
    PublishBlock(Vec<u8>),
    AnnounceHeight { node_id: NodeId, height: u64, tip_hash: [u8; 32] },
    SendSyncRequest { from_node: NodeId, from_height: u64 },
    SendSyncResponse { for_node: NodeId, blocks: Vec<Block> },
}

// ----- Public event type -----

#[derive(Debug)]
pub enum MeshEvent {
    NewTx(Tx),
    NewBlock(Block),
    PeerConnected(PeerId),
    PeerDisconnected(PeerId),
    /// A peer announced their chain height — node uses this to decide if it needs to sync.
    PeerHeight { node_id: NodeId, height: u64, tip_hash: [u8; 32] },
    /// A peer is requesting blocks from `from_height` onward — node should call send_sync_response.
    SyncRequest { from_node: NodeId, from_height: u64 },
    /// Incoming block batch from a sync response, addressed to `for_node`.
    SyncBlocks { for_node: NodeId, blocks: Vec<Block> },
}

// ----- Topic names -----

const TOPIC_TXS: &str = "ce-transactions";
const TOPIC_BLOCKS: &str = "ce-blocks";
const TOPIC_HEIGHTS: &str = "ce-heights";
const TOPIC_SYNCREQ: &str = "ce-syncreq";
const TOPIC_SYNCRESP: &str = "ce-syncresp";

// ----- Network behaviour -----

#[derive(NetworkBehaviour)]
struct CeBehaviour {
    gossipsub: gossipsub::Behaviour,
    kademlia: kad::Behaviour<kad::store::MemoryStore>,
    identify: identify::Behaviour,
}

// ----- Topic hash bundle (passed to free handler fn) -----

struct Topics {
    tx: gossipsub::TopicHash,
    block: gossipsub::TopicHash,
    heights: gossipsub::TopicHash,
    syncreq: gossipsub::TopicHash,
    syncresp: gossipsub::TopicHash,
}

// ----- Handle returned to callers -----

#[derive(Clone)]
pub struct MeshHandle {
    cmd_tx: mpsc::Sender<MeshCommand>,
}

impl MeshHandle {
    pub async fn broadcast_tx(&self, tx: &Tx) -> Result<()> {
        let bytes = bincode::serialize(tx)?;
        self.send(MeshCommand::PublishTx(bytes)).await
    }

    pub async fn broadcast_block(&self, block: &Block) -> Result<()> {
        let bytes = bincode::serialize(block)?;
        self.send(MeshCommand::PublishBlock(bytes)).await
    }

    pub async fn announce_height(&self, node_id: NodeId, height: u64, tip_hash: [u8; 32]) -> Result<()> {
        self.send(MeshCommand::AnnounceHeight { node_id, height, tip_hash }).await
    }

    pub async fn send_sync_request(&self, from_node: NodeId, from_height: u64) -> Result<()> {
        self.send(MeshCommand::SendSyncRequest { from_node, from_height }).await
    }

    pub async fn send_sync_response(&self, for_node: NodeId, blocks: Vec<Block>) -> Result<()> {
        self.send(MeshCommand::SendSyncResponse { for_node, blocks }).await
    }

    async fn send(&self, cmd: MeshCommand) -> Result<()> {
        self.cmd_tx.send(cmd).await.map_err(|_| anyhow!("mesh actor gone"))
    }
}

// ----- Main mesh struct -----

pub struct Mesh {
    swarm: libp2p::Swarm<CeBehaviour>,
    tx_topic: gossipsub::IdentTopic,
    block_topic: gossipsub::IdentTopic,
    heights_topic: gossipsub::IdentTopic,
    syncreq_topic: gossipsub::IdentTopic,
    syncresp_topic: gossipsub::IdentTopic,
    cmd_rx: mpsc::Receiver<MeshCommand>,
    event_tx: mpsc::Sender<MeshEvent>,
}

impl Mesh {
    pub fn new(
        secret_key_bytes: [u8; 32],
    ) -> Result<(Self, MeshHandle, mpsc::Receiver<MeshEvent>)> {
        let ed_secret = libp2p::identity::ed25519::SecretKey::try_from_bytes(secret_key_bytes)?;
        let ed_kp = libp2p::identity::ed25519::Keypair::from(ed_secret);
        let keypair = libp2p::identity::Keypair::from(ed_kp);

        let tx_topic = gossipsub::IdentTopic::new(TOPIC_TXS);
        let block_topic = gossipsub::IdentTopic::new(TOPIC_BLOCKS);
        let heights_topic = gossipsub::IdentTopic::new(TOPIC_HEIGHTS);
        let syncreq_topic = gossipsub::IdentTopic::new(TOPIC_SYNCREQ);
        let syncresp_topic = gossipsub::IdentTopic::new(TOPIC_SYNCRESP);

        let swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|key| {
                let message_id_fn = |msg: &gossipsub::Message| {
                    let hash = Sha256::digest(&msg.data);
                    gossipsub::MessageId::from(hash.to_vec())
                };

                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(1))
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .message_id_fn(message_id_fn)
                    // Sync responses can be large — allow up to 4MB per message.
                    .max_transmit_size(4 * 1024 * 1024)
                    .build()
                    .expect("valid gossipsub config");

                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )
                .expect("valid gossipsub");

                let peer_id = key.public().to_peer_id();
                let mut kademlia = kad::Behaviour::new(
                    peer_id,
                    kad::store::MemoryStore::new(peer_id),
                );
                kademlia.set_mode(Some(kad::Mode::Server));

                let identify = identify::Behaviour::new(identify::Config::new(
                    "/ce/1.0.0".to_string(),
                    key.public(),
                ));

                Ok(CeBehaviour { gossipsub, kademlia, identify })
            })?
            .build();

        let (cmd_tx, cmd_rx) = mpsc::channel(128);
        let (event_tx, event_rx) = mpsc::channel(256);

        let mesh = Self {
            swarm,
            tx_topic,
            block_topic,
            heights_topic,
            syncreq_topic,
            syncresp_topic,
            cmd_rx,
            event_tx,
        };

        let handle = MeshHandle { cmd_tx };
        Ok((mesh, handle, event_rx))
    }

    pub fn add_bootstrap(&mut self, addr: &str) -> Result<()> {
        let ma: Multiaddr = addr.parse()?;
        let peer_id = peer_id_from_multiaddr(&ma)?;
        self.swarm.behaviour_mut().kademlia.add_address(&peer_id, ma.clone());
        self.swarm.dial(ma)?;
        Ok(())
    }

    pub async fn run(mut self, listen_port: u16) -> Result<()> {
        let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{listen_port}").parse()?;
        self.swarm.listen_on(listen_addr)?;

        for topic in [
            &self.tx_topic,
            &self.block_topic,
            &self.heights_topic,
            &self.syncreq_topic,
            &self.syncresp_topic,
        ] {
            self.swarm.behaviour_mut().gossipsub.subscribe(topic)?;
        }

        let topics = Topics {
            tx: self.tx_topic.hash(),
            block: self.block_topic.hash(),
            heights: self.heights_topic.hash(),
            syncreq: self.syncreq_topic.hash(),
            syncresp: self.syncresp_topic.hash(),
        };

        loop {
            tokio::select! {
                Some(cmd) = self.cmd_rx.recv() => {
                    self.handle_command(cmd);
                }
                event = self.swarm.next() => {
                    let Some(event) = event else { break };
                    let mesh_event = handle_swarm_event(
                        event,
                        &topics,
                        self.swarm.behaviour_mut(),
                    );
                    if let Some(ev) = mesh_event {
                        let _ = self.event_tx.send(ev).await;
                    }
                }
            }
        }
        Ok(())
    }

    fn handle_command(&mut self, cmd: MeshCommand) {
        match cmd {
            MeshCommand::PublishTx(bytes) => {
                if let Err(e) = self.swarm.behaviour_mut().gossipsub
                    .publish(self.tx_topic.clone(), bytes)
                {
                    debug!("publish tx: {e}");
                }
            }
            MeshCommand::PublishBlock(bytes) => {
                if let Err(e) = self.swarm.behaviour_mut().gossipsub
                    .publish(self.block_topic.clone(), bytes)
                {
                    debug!("publish block: {e}");
                }
            }
            MeshCommand::AnnounceHeight { node_id, height, tip_hash } => {
                let msg = HeightAnnounce { node_id, height, tip_hash };
                if let Ok(bytes) = bincode::serialize(&msg) {
                    let _ = self.swarm.behaviour_mut().gossipsub
                        .publish(self.heights_topic.clone(), bytes);
                }
            }
            MeshCommand::SendSyncRequest { from_node, from_height } => {
                let msg = SyncReqMsg { from_node, from_height };
                if let Ok(bytes) = bincode::serialize(&msg) {
                    let _ = self.swarm.behaviour_mut().gossipsub
                        .publish(self.syncreq_topic.clone(), bytes);
                }
            }
            MeshCommand::SendSyncResponse { for_node, blocks } => {
                // Chunk into batches to stay under max_transmit_size.
                for chunk in blocks.chunks(MAX_BLOCKS_PER_SYNC) {
                    let msg = SyncRespMsg { for_node, blocks: chunk.to_vec() };
                    if let Ok(bytes) = bincode::serialize(&msg) {
                        let _ = self.swarm.behaviour_mut().gossipsub
                            .publish(self.syncresp_topic.clone(), bytes);
                    }
                }
            }
        }
    }
}

fn handle_swarm_event(
    event: SwarmEvent<CeBehaviourEvent>,
    topics: &Topics,
    behaviour: &mut CeBehaviour,
) -> Option<MeshEvent> {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            info!("listening on {address}");
            None
        }
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            Some(MeshEvent::PeerConnected(peer_id))
        }
        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            Some(MeshEvent::PeerDisconnected(peer_id))
        }
        SwarmEvent::Behaviour(CeBehaviourEvent::Gossipsub(
            gossipsub::Event::Message { message, .. },
        )) => {
            decode_gossip(message, topics)
        }
        SwarmEvent::Behaviour(CeBehaviourEvent::Identify(
            identify::Event::Received { peer_id, info },
        )) => {
            for addr in info.listen_addrs {
                behaviour.kademlia.add_address(&peer_id, addr);
            }
            None
        }
        SwarmEvent::Behaviour(CeBehaviourEvent::Kademlia(
            kad::Event::RoutingUpdated { peer, .. },
        )) => {
            debug!("kademlia routing updated: {peer}");
            None
        }
        _ => None,
    }
}

fn decode_gossip(message: gossipsub::Message, topics: &Topics) -> Option<MeshEvent> {
    let t = &message.topic;
    if t == &topics.tx {
        match bincode::deserialize::<Tx>(&message.data) {
            Ok(tx) => Some(MeshEvent::NewTx(tx)),
            Err(e) => { warn!("bad tx gossip: {e}"); None }
        }
    } else if t == &topics.block {
        match bincode::deserialize::<Block>(&message.data) {
            Ok(block) => Some(MeshEvent::NewBlock(block)),
            Err(e) => { warn!("bad block gossip: {e}"); None }
        }
    } else if t == &topics.heights {
        match bincode::deserialize::<HeightAnnounce>(&message.data) {
            Ok(a) => Some(MeshEvent::PeerHeight {
                node_id: a.node_id,
                height: a.height,
                tip_hash: a.tip_hash,
            }),
            Err(e) => { warn!("bad height announce: {e}"); None }
        }
    } else if t == &topics.syncreq {
        match bincode::deserialize::<SyncReqMsg>(&message.data) {
            Ok(r) => Some(MeshEvent::SyncRequest {
                from_node: r.from_node,
                from_height: r.from_height,
            }),
            Err(e) => { warn!("bad syncreq: {e}"); None }
        }
    } else if t == &topics.syncresp {
        match bincode::deserialize::<SyncRespMsg>(&message.data) {
            Ok(r) => Some(MeshEvent::SyncBlocks {
                for_node: r.for_node,
                blocks: r.blocks,
            }),
            Err(e) => { warn!("bad syncresp: {e}"); None }
        }
    } else {
        None
    }
}

fn peer_id_from_multiaddr(ma: &Multiaddr) -> Result<PeerId> {
    use libp2p::multiaddr::Protocol;
    for proto in ma.iter() {
        if let Protocol::P2p(peer_id) = proto {
            return Ok(peer_id);
        }
    }
    Err(anyhow!("multiaddr {ma} has no /p2p/<peer-id> component"))
}
