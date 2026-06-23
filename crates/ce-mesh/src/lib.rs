use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ce_chain::{Block, Tx};
use ce_identity::NodeId;
use ce_protocol::{CellSignal, GOSSIP_TOPIC as PROTOCOL_TOPIC};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use libp2p::{
    autonat, dcutr,
    futures::StreamExt,
    gossipsub, identify, kad, mdns,
    noise, ping, relay, request_response,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, SwarmBuilder,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};
use serde::{Deserialize, Serialize};

/// Vivaldi network coordinates — predicted RTT between any two nodes without an O(n^2) probe matrix.
/// Pure + transport-free; the node updates the local coordinate from measured ping RTTs and carries
/// it in the atlas so the `ce-graph` SDK can assemble global topology. See `docs/compute-fabric.md`.
pub mod vivaldi;

pub use ce_identity::NodeId as CeNodeId;
pub use libp2p::PeerId as CePeerId;

/// Compute the libp2p PeerId from a CE node's 32-byte secret key.
pub fn peer_id_from_secret(secret: [u8; 32]) -> anyhow::Result<libp2p::PeerId> {
    let sec = libp2p::identity::ed25519::SecretKey::try_from_bytes(secret)?;
    let kp = libp2p::identity::ed25519::Keypair::from(sec);
    let kp = libp2p::identity::Keypair::from(kp);
    Ok(kp.public().to_peer_id())
}

/// Compute the libp2p PeerId from a CE node's 32-byte public key (NodeId).
///
/// CE NodeId IS the Ed25519 public key. libp2p PeerId is derived from the same key,
/// so this conversion is deterministic and lossless. Used to verify that the sender
/// of an incoming mesh RPC actually controls the claimed CE NodeId.
pub fn peer_id_from_node_id(node_id: &NodeId) -> Result<PeerId> {
    let pk = libp2p::identity::ed25519::PublicKey::try_from_bytes(node_id)
        .map_err(|e| anyhow!("invalid node_id as ed25519 public key: {e}"))?;
    let pk = libp2p::identity::PublicKey::from(pk);
    Ok(pk.to_peer_id())
}

/// Recover a CE NodeId from a libp2p PeerId. Ed25519 PeerIds embed the public key via an identity
/// multihash (the key is small enough to inline), so the NodeId is recoverable. Returns `None` if
/// the PeerId doesn't inline an ed25519 key. The inverse of [`peer_id_from_node_id`].
pub fn node_id_from_peer_id(peer: &PeerId) -> Option<NodeId> {
    let mh = peer.as_ref(); // &Multihash — identity-coded for inlined keys
    if mh.code() != 0 {
        return None;
    }
    let pk = libp2p::identity::PublicKey::try_decode_protobuf(mh.digest()).ok()?;
    pk.try_into_ed25519().ok().map(|k| k.to_bytes())
}

/// Derive the DHT key for a named service advertisement. Domain-separated from chunk cids
/// (`sha256(content)`) so the two never collide in the shared provider-record keyspace.
pub fn service_key(service: &str) -> [u8; 32] {
    Sha256::digest(format!("ce-svc/{service}").as_bytes()).into()
}

// ----- Wire types for chain sync -----

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HeightAnnounce {
    node_id: NodeId,
    height: u64,
    tip_hash: [u8; 32],
    /// Oldest block index this node can serve (0 = full archive).
    oldest_block: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncReqMsg {
    from_node: NodeId,
    from_height: u64,
    // Unique nonce prevents gossipsub content-hash dedup from swallowing repeated requests.
    nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncRespMsg {
    for_node: NodeId,
    blocks: Vec<Block>,
}

// Large enough to cover the full chain in a single batch so try_reorg always
// has enough history to find a common ancestor and produce a longer fork.
const MAX_BLOCKS_PER_SYNC: usize = 10_000;

// ----- Mesh RPC protocol (/ce/rpc/1) -----
//
// Device-to-device exec and file sync travel over this request-response protocol.
// The transport layer (noise) authenticates the sender's identity; no separate
// signature is needed. See docs/architecture.md for the full security model.

/// Request payload for the /ce/rpc/1 protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RpcRequest {
    // exec / file-sync / file-delete used to live here as bespoke node RPCs. They are apps now
    // (run processes / touch the filesystem) and live in the `rdev` app over `AppRequest` + the
    // `ce-cap` verifier. CE keeps only transport/economy/data RPCs below.
    /// Fetch a historical archive segment from a peer's local archive.
    /// The peer replies with SegmentData if it holds the segment, or Error otherwise.
    SegmentFetch {
        from_node: NodeId,
        segment_id: u64,
    },
    /// Deploy a long-running cell (detached container) on a specific remote host.
    /// Directed placement — unlike a broadcast JobBid, this targets one host. The host
    /// tracks the job so it is heartbeat-billed and killable; replies with `Deployed`.
    /// `bid` is the funding (base units) the deployer commits; billing draws it down.
    Deploy {
        from_node: NodeId,
        /// The workload to run, as bincode of `ce_runtime::Workload` (Docker or Wasm). Opaque to
        /// the transport; the receiving node decodes and dispatches it to a matching runtime.
        workload: Vec<u8>,
        cpu_cores: u32,
        mem_mb: u64,
        duration_secs: u64,
        bid: u128,
        /// Optional scoped grant (bincode of `SignedGrant`); opaque to transport. See `Exec`.
        grant: Option<Vec<u8>>,
    },
    /// Stop a job previously deployed on a remote host. `job_id` is the 64-hex id returned
    /// by `Deployed`. Replies with `Killed`.
    Kill {
        from_node: NodeId,
        job_id: String,
        grant: Option<Vec<u8>>,
    },
    /// Fetch a content-addressed chunk (data-layer blob) from a peer that holds it. `cid` is the
    /// sha256 of the bytes; the caller verifies `sha256(reply) == cid` on receipt, so a wrong or
    /// tampered reply is detected and discarded. Open/unpaid in v0 — like `SegmentFetch`, serving
    /// content-addressed data to anyone; per-chunk payment over channels arrives in a later stage.
    FetchChunk {
        from_node: NodeId,
        cid: [u8; 32],
        /// Optional payment-channel receipt (bincode of `ce_chain::ChunkReceipt`), opaque to the
        /// transport. Required when the provider charges for data; `None` for free/open serving.
        receipt: Option<Vec<u8>>,
    },
    /// A directed application message (the app-messaging primitive). `topic` is an app-chosen
    /// namespace and `payload` is opaque to CE. The receiver verifies `from_node` against the
    /// Noise PeerId, then surfaces it to the local app (inbox + SSE). Replies with `AppAck`.
    AppMessage {
        from_node: NodeId,
        topic: String,
        payload: Vec<u8>,
    },
    /// A directed application request expecting a reply (sync request/response, Stage 3). The
    /// receiving node surfaces it to its app tagged with a reply token and holds the response
    /// channel open until the app answers via `/mesh/reply`, which sends back `AppReply`.
    AppRequest {
        from_node: NodeId,
        topic: String,
        payload: Vec<u8>,
    },
    /// Pay a relay for relay service: a payment-channel receipt (the relay is the channel `host`,
    /// the sender the `payer`). The relay verifies it against the on-chain channel and its price,
    /// records the payment, and marks the payer paid-up. `payer_sig` is the 64-byte signature over
    /// `channel_receipt_bytes(channel_id, relay, cumulative)`, as a Vec to avoid serde array limits.
    RelayReceipt {
        from_node: NodeId,
        channel_id: [u8; 32],
        cumulative: u128,
        payer_sig: Vec<u8>,
    },
}

impl RpcRequest {
    pub fn from_node(&self) -> NodeId {
        match self {
            Self::SegmentFetch { from_node, .. }
            | Self::Deploy { from_node, .. }
            | Self::Kill { from_node, .. }
            | Self::FetchChunk { from_node, .. }
            | Self::AppMessage { from_node, .. }
            | Self::AppRequest { from_node, .. }
            | Self::RelayReceipt { from_node, .. } => *from_node,
        }
    }
}

/// Response payload for the /ce/rpc/1 protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RpcResponse {
    ExecResult { stdout: String, stderr: String, exit_code: i32 },
    SyncAck,
    /// Blocks for the requested archive segment.
    SegmentData { segment_id: u64, blocks: Vec<Block> },
    /// A cell was deployed; `job_id` is the 64-hex id to track/kill it. `output` is the output CID
    /// (hex) when the workload ran to completion and produced a captured artifact (a WASI command's
    /// stdout); `None` for detached/streaming cells.
    Deployed { job_id: String, output: Option<String> },
    /// A deployed cell was stopped.
    Killed,
    /// The requested content-addressed chunk's bytes. The caller verifies `sha256(bytes) == cid`.
    ChunkData { cid: [u8; 32], bytes: Vec<u8> },
    /// The receiving node enqueued a directed `AppMessage` for the local app.
    AppAck,
    /// The app's reply to an `AppRequest`.
    AppReply { payload: Vec<u8> },
    /// The relay accepted and recorded a `RelayReceipt`.
    RelayAck,
    /// The remote node rejected the request (trust failure, Docker error, etc.).
    Error(String),
}

// 256 MB hard cap per RPC message (covers large file syncs; exec output is bounded separately).
const MAX_RPC_BYTES: usize = 256 * 1024 * 1024;

/// Length-prefixed bincode codec for /ce/rpc/1.
#[derive(Clone)]
pub struct CeRpcCodec;

#[async_trait]
impl request_response::Codec for CeRpcCodec {
    type Protocol = &'static str;
    type Request = RpcRequest;
    type Response = RpcResponse;

    async fn read_request<T>(&mut self, _: &&'static str, io: &mut T)
        -> std::io::Result<Self::Request>
    where T: futures::AsyncRead + Unpin + Send
    {
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_RPC_BYTES {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "rpc request too large"));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        bincode::deserialize(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }

    async fn read_response<T>(&mut self, _: &&'static str, io: &mut T)
        -> std::io::Result<Self::Response>
    where T: futures::AsyncRead + Unpin + Send
    {
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_RPC_BYTES {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "rpc response too large"));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        bincode::deserialize(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }

    async fn write_request<T>(&mut self, _: &&'static str, io: &mut T, req: Self::Request)
        -> std::io::Result<()>
    where T: futures::AsyncWrite + Unpin + Send
    {
        let buf = bincode::serialize(&req)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        io.write_all(&(buf.len() as u32).to_be_bytes()).await?;
        io.write_all(&buf).await
    }

    async fn write_response<T>(&mut self, _: &&'static str, io: &mut T, res: Self::Response)
        -> std::io::Result<()>
    where T: futures::AsyncWrite + Unpin + Send
    {
        let buf = bincode::serialize(&res)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        io.write_all(&(buf.len() as u32).to_be_bytes()).await?;
        io.write_all(&buf).await
    }
}

// ----- Segment manifest wire type -----

/// Broadcast on `ce-segments` topic: advertises which archive segments a node holds.
/// Sent on startup and whenever the local segment set changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SegmentManifest {
    node_id: NodeId,
    /// Sorted list of segment IDs this node holds in its archive.
    held_segments: Vec<u64>,
}

// ----- App pub/sub wire type -----

/// Gossip topics for app pub/sub are namespaced under this prefix, so they never collide with
/// CE-internal topics and the receiver can recognise them generically.
pub const APP_TOPIC_PREFIX: &str = "ce-app/";

/// A published application message (app pub/sub, Stage 2). Broadcast on `ce-app/<topic>`. Signed
/// by the publisher so any receiver verifies authorship (gossip is relayed, not point-to-point
/// authenticated). `nonce` keeps otherwise-identical publishes unique so gossipsub doesn't dedup
/// them. The 64-byte signature travels as a `Vec<u8>` to avoid serde's array-size limit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppPubSubMsg {
    pub from: NodeId,
    pub topic: String,
    pub payload: Vec<u8>,
    pub nonce: u64,
    pub sig: Vec<u8>,
}

/// Canonical bytes the publisher signs for an app pub/sub message: domain-separated over the
/// topic, payload, and nonce.
pub fn app_pubsub_bytes(topic: &str, payload: &[u8], nonce: u64) -> Vec<u8> {
    bincode::serialize(&(b"ce-app-pubsub-v1", topic, payload, nonce)).unwrap_or_default()
}

// ----- Command channel -----

enum MeshCommand {
    PublishTx(Vec<u8>),
    PublishBlock(Vec<u8>),
    AnnounceHeight { node_id: NodeId, height: u64, tip_hash: [u8; 32], oldest_block: u64 },
    AnnounceSegments { node_id: NodeId, held_segments: Vec<u64> },
    SendSyncRequest { from_node: NodeId, from_height: u64 },
    SendSyncResponse { for_node: NodeId, blocks: Vec<Block> },
    PublishSignal(Vec<u8>),
    /// Dial a multiaddr to add a peer as a swarm connection hint.
    Dial(String),
    /// Send an RPC request to a specific peer; reply is delivered via `reply_tx`.
    SendRpc {
        peer_id: PeerId,
        request: RpcRequest,
        reply_tx: oneshot::Sender<RpcResponse>,
    },
    /// Deliver a response for an incoming RPC identified by `correlation_id`.
    RespondRpc {
        correlation_id: u64,
        response: RpcResponse,
    },
    /// Announce to the DHT that this node holds the chunk keyed by `key` (a sha256), so peers
    /// querying for it discover us as a provider.
    ProvideChunk { key: [u8; 32] },
    /// Query the DHT for peers providing the chunk keyed by `key`. The accumulated provider set
    /// is delivered via `reply_tx` once the Kademlia query completes.
    FindProviders {
        key: [u8; 32],
        reply_tx: oneshot::Sender<Vec<PeerId>>,
    },
    /// Subscribe this node's gossipsub to an app pub/sub topic (`ce-app/<topic>`).
    SubscribeApp { topic: String },
    /// Publish pre-signed `AppPubSubMsg` bytes to an app pub/sub topic (`ce-app/<topic>`).
    PublishApp { topic: String, data: Vec<u8> },
}

// ----- Public event type -----

#[derive(Debug)]
pub enum MeshEvent {
    NewTx(Tx),
    NewBlock(Block),
    PeerConnected(PeerId),
    PeerDisconnected(PeerId),
    /// A round-trip-time sample to a connected peer, in milliseconds. The ground-truth edge of the
    /// network graph; the node accumulates these per peer (see `docs/compute-fabric.md`).
    Rtt { peer: PeerId, rtt_ms: f64 },
    PeerHeight { node_id: NodeId, height: u64, tip_hash: [u8; 32], oldest_block: u64 },
    /// A peer broadcast their archive segment manifest.
    PeerSegments { node_id: NodeId, held_segments: Vec<u64> },
    /// A verified app pub/sub message arrived on a subscribed `ce-app/<topic>` topic.
    AppGossip { from: NodeId, topic: String, payload: Vec<u8> },
    SyncRequest { from_node: NodeId, from_height: u64 },
    SyncBlocks { for_node: NodeId, blocks: Vec<Block> },
    CellSignal(CellSignal),
    /// An incoming RPC request from a mesh peer.
    ///
    /// The receiver MUST call `MeshHandle::respond_rpc(correlation_id, response)` exactly
    /// once, even on error. Not responding leaks the `ResponseChannel` and may stall the
    /// remote caller until the request-response timeout fires (10 min).
    IncomingRpc {
        /// Noise-authenticated sender identity. Cannot be spoofed.
        from_peer: PeerId,
        /// Opaque ID for delivering the response via `MeshHandle::respond_rpc`.
        correlation_id: u64,
        request: RpcRequest,
    },
}

// ----- Topic names -----

const TOPIC_TXS: &str = "ce-transactions";
const TOPIC_BLOCKS: &str = "ce-blocks";
const TOPIC_HEIGHTS: &str = "ce-heights";
const TOPIC_SYNCREQ: &str = "ce-syncreq";
const TOPIC_SYNCRESP: &str = "ce-syncresp";
const TOPIC_PROTOCOL: &str = PROTOCOL_TOPIC;
const TOPIC_SEGMENTS: &str = "ce-segments";

// ----- Network behaviour -----

#[derive(NetworkBehaviour)]
struct CeBehaviour {
    gossipsub: gossipsub::Behaviour,
    kademlia: kad::Behaviour<kad::store::MemoryStore>,
    identify: identify::Behaviour,
    mdns: mdns::tokio::Behaviour,
    autonat: autonat::Behaviour,
    dcutr: dcutr::Behaviour,
    /// Periodic RTT probes to connected peers — the ground-truth edges of the network graph
    /// (see `docs/compute-fabric.md`). RTT samples are forwarded to the node as [`MeshEvent::Rtt`].
    ping: ping::Behaviour,
    relay_client: relay::client::Behaviour,
    relay_server: relay::Behaviour,
    /// /ce/rpc/1 — device-to-device exec and file sync, relay-routed.
    rpc: request_response::Behaviour<CeRpcCodec>,
    /// /ce/tunnel/1 — raw bidirectional byte streams (TCP-over-libp2p), relay-routed. Driven
    /// entirely through the cloned [`libp2p_stream::Control`] handed to the node; emits no events.
    stream: libp2p_stream::Behaviour,
}

/// The libp2p protocol for CE TCP tunnels. The node forwards a local TCP port to a remote port
/// over this protocol; authorization is a `tunnel` capability checked on the receiving node.
pub const TUNNEL_PROTOCOL: libp2p::StreamProtocol = libp2p::StreamProtocol::new("/ce/tunnel/1");

/// Cloneable handle to open/accept tunnel streams (re-exported so the node can drive tunnels from
/// tasks without touching the `!Sync` swarm).
pub use libp2p_stream::Control as StreamControl;

/// A raw bidirectional byte stream (re-exported so the node can splice tunnels without a direct
/// libp2p dependency). Implements `futures::{AsyncRead, AsyncWrite}`.
pub use libp2p::Stream as MeshStream;

// ----- Topic hash bundle -----

struct Topics {
    tx: gossipsub::TopicHash,
    block: gossipsub::TopicHash,
    heights: gossipsub::TopicHash,
    syncreq: gossipsub::TopicHash,
    syncresp: gossipsub::TopicHash,
    protocol: gossipsub::TopicHash,
    segments: gossipsub::TopicHash,
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

    pub async fn announce_height(
        &self,
        node_id: NodeId,
        height: u64,
        tip_hash: [u8; 32],
        oldest_block: u64,
    ) -> Result<()> {
        self.send(MeshCommand::AnnounceHeight { node_id, height, tip_hash, oldest_block }).await
    }

    pub async fn send_sync_request(&self, from_node: NodeId, from_height: u64) -> Result<()> {
        self.send(MeshCommand::SendSyncRequest { from_node, from_height }).await
    }

    pub async fn send_sync_response(&self, for_node: NodeId, blocks: Vec<Block>) -> Result<()> {
        self.send(MeshCommand::SendSyncResponse { for_node, blocks }).await
    }

    pub async fn broadcast_signal(&self, signal: &CellSignal) -> Result<()> {
        let bytes = signal.encode()?;
        self.send(MeshCommand::PublishSignal(bytes)).await
    }

    /// Broadcast which archive segments this node holds (via `ce-segments` topic).
    pub async fn announce_segments(&self, node_id: NodeId, held_segments: Vec<u64>) -> Result<()> {
        self.send(MeshCommand::AnnounceSegments { node_id, held_segments }).await
    }

    /// Add a dial hint so the swarm can find and connect to a peer.
    /// The `addr` is a libp2p multiaddr, e.g. a relay circuit address.
    /// Silently ignores invalid multiaddrs (logs a warning instead).
    pub async fn dial(&self, addr: String) -> Result<()> {
        self.send(MeshCommand::Dial(addr)).await
    }

    /// Send an RPC request to `peer_id` and await the response.
    ///
    /// The peer must be reachable via the swarm (direct or relay-routed).
    /// Exec RPCs may take up to 10 minutes; the request-response timeout is set accordingly.
    pub async fn send_rpc(&self, peer_id: PeerId, request: RpcRequest) -> Result<RpcResponse> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send(MeshCommand::SendRpc { peer_id, request, reply_tx }).await?;
        reply_rx.await.map_err(|_| anyhow!("mesh rpc: actor dropped before response"))
    }

    /// Deliver a response for an incoming RPC. `correlation_id` comes from `MeshEvent::IncomingRpc`.
    pub async fn respond_rpc(&self, correlation_id: u64, response: RpcResponse) -> Result<()> {
        self.send(MeshCommand::RespondRpc { correlation_id, response }).await
    }

    /// Announce that this node provides the content-addressed chunk `cid` (a DHT provider record).
    /// Call it whenever a chunk is stored locally; provider records expire, so re-announce held
    /// chunks periodically / on startup.
    pub async fn provide_chunk(&self, cid: [u8; 32]) -> Result<()> {
        self.send(MeshCommand::ProvideChunk { key: cid }).await
    }

    /// Find peers advertising the chunk `cid` via the DHT. Returns the providers discovered by the
    /// time the Kademlia query completes (possibly empty). The caller then `send_rpc`s a
    /// `FetchChunk` to one of them and verifies the bytes against `cid`.
    pub async fn find_providers(&self, cid: [u8; 32]) -> Result<Vec<PeerId>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send(MeshCommand::FindProviders { key: cid, reply_tx }).await?;
        reply_rx.await.map_err(|_| anyhow!("find_providers: actor dropped before response"))
    }

    /// Subscribe to an app pub/sub topic so this node receives its messages (`ce-app/<topic>`).
    pub async fn subscribe_app(&self, topic: &str) -> Result<()> {
        self.send(MeshCommand::SubscribeApp { topic: topic.to_string() }).await
    }

    /// Publish pre-signed `AppPubSubMsg` bytes to an app pub/sub topic (`ce-app/<topic>`).
    pub async fn publish_app(&self, topic: &str, data: Vec<u8>) -> Result<()> {
        self.send(MeshCommand::PublishApp { topic: topic.to_string(), data }).await
    }

    /// Advertise that this node provides a named service, discoverable via the DHT (reuses the
    /// provider-record machinery with a service-derived key). Re-advertise periodically: provider
    /// records expire.
    pub async fn advertise_service(&self, service: &str) -> Result<()> {
        self.send(MeshCommand::ProvideChunk { key: service_key(service) }).await
    }

    /// Find the NodeIds of nodes advertising a named service via the DHT. PeerIds that don't
    /// inline an ed25519 key are skipped.
    pub async fn find_service(&self, service: &str) -> Result<Vec<NodeId>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send(MeshCommand::FindProviders { key: service_key(service), reply_tx }).await?;
        let peers = reply_rx.await.map_err(|_| anyhow!("find_service: actor dropped before response"))?;
        Ok(peers.iter().filter_map(node_id_from_peer_id).collect())
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
    protocol_topic: gossipsub::IdentTopic,
    segments_topic: gossipsub::IdentTopic,
    cmd_rx: mpsc::Receiver<MeshCommand>,
    event_tx: mpsc::Sender<MeshEvent>,
    /// Relay nodes: peer_id → full multiaddr. On connect, listen on the circuit addr.
    relay_peers: HashMap<PeerId, Multiaddr>,
    /// Pending outbound RPC calls: libp2p request ID → oneshot sender for the response.
    pending_outbound: HashMap<request_response::OutboundRequestId, oneshot::Sender<RpcResponse>>,
    /// Pending inbound RPC calls: correlation_id → libp2p response channel.
    pending_inbound: HashMap<u64, request_response::ResponseChannel<RpcResponse>>,
    next_inbound_id: u64,
    /// In-flight DHT provider lookups: kad query id → (reply sender, providers seen so far).
    /// Completed and drained when the query's final progress step arrives.
    pending_providers:
        HashMap<kad::QueryId, (oneshot::Sender<Vec<PeerId>>, std::collections::HashSet<PeerId>)>,
    /// Monotonic counter for sync request nonces — prevents gossipsub from deduplicating
    /// identical requests (same from_node + from_height) sent on repeated sync intervals.
    sync_nonce: u64,
    /// When true, mDNS-discovered local peers are ignored and any peer that connects
    /// which is NOT in `allowed_peers` is immediately disconnected. Set in tests to
    /// prevent in-process test nodes from connecting to any live local ce node.
    disable_local_discovery: bool,
    /// Peers explicitly permitted when `disable_local_discovery` is true.
    /// Populated from bootstrap and relay addresses. Empty = allow all (production mode).
    allowed_peers: std::collections::HashSet<PeerId>,
}

impl Mesh {
    pub fn new(
        secret_key_bytes: [u8; 32],
    ) -> Result<(Self, MeshHandle, mpsc::Receiver<MeshEvent>, StreamControl)> {
        Self::new_inner(secret_key_bytes, false)
    }

    /// Like `new`, but disables mDNS peer discovery. Use in tests to prevent
    /// test nodes from connecting to live local nodes via multicast.
    pub fn new_isolated(
        secret_key_bytes: [u8; 32],
    ) -> Result<(Self, MeshHandle, mpsc::Receiver<MeshEvent>, StreamControl)> {
        Self::new_inner(secret_key_bytes, true)
    }

    fn new_inner(
        secret_key_bytes: [u8; 32],
        disable_local_discovery: bool,
    ) -> Result<(Self, MeshHandle, mpsc::Receiver<MeshEvent>, StreamControl)> {
        let ed_secret = libp2p::identity::ed25519::SecretKey::try_from_bytes(secret_key_bytes)?;
        let ed_kp = libp2p::identity::ed25519::Keypair::from(ed_secret);
        let keypair = libp2p::identity::Keypair::from(ed_kp);

        let tx_topic = gossipsub::IdentTopic::new(TOPIC_TXS);
        let block_topic = gossipsub::IdentTopic::new(TOPIC_BLOCKS);
        let heights_topic = gossipsub::IdentTopic::new(TOPIC_HEIGHTS);
        let syncreq_topic = gossipsub::IdentTopic::new(TOPIC_SYNCREQ);
        let syncresp_topic = gossipsub::IdentTopic::new(TOPIC_SYNCRESP);
        let protocol_topic = gossipsub::IdentTopic::new(TOPIC_PROTOCOL);
        let segments_topic = gossipsub::IdentTopic::new(TOPIC_SEGMENTS);

        let swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_quic()
            .with_relay_client(noise::Config::new, yamux::Config::default)?
            .with_behaviour(|key, relay_client| {
                let peer_id = key.public().to_peer_id();

                let message_id_fn = |msg: &gossipsub::Message| {
                    let hash = Sha256::digest(&msg.data);
                    gossipsub::MessageId::from(hash.to_vec())
                };
                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(1))
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .message_id_fn(message_id_fn)
                    .max_transmit_size(4 * 1024 * 1024)
                    .build()
                    .expect("valid gossipsub config");
                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )
                .expect("valid gossipsub");

                let mut kademlia = kad::Behaviour::new(
                    peer_id,
                    kad::store::MemoryStore::new(peer_id),
                );
                kademlia.set_mode(Some(kad::Mode::Server));

                let identify = identify::Behaviour::new(identify::Config::new(
                    "/ce/1.0.0".to_string(),
                    key.public(),
                ));

                let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)?;
                let autonat = autonat::Behaviour::new(peer_id, autonat::Config::default());
                let dcutr = dcutr::Behaviour::new(peer_id);
                let ping = ping::Behaviour::new(ping::Config::new());

                // /ce/rpc/1 — exec and sync between trusted devices.
                // 10-minute timeout: exec may run a full cargo build or similar long task.
                let rpc_cfg = request_response::Config::default()
                    .with_request_timeout(Duration::from_secs(600));
                let rpc = request_response::Behaviour::with_codec(
                    CeRpcCodec,
                    std::iter::once(("/ce/rpc/1", request_response::ProtocolSupport::Full)),
                    rpc_cfg,
                );

                Ok(CeBehaviour {
                    gossipsub,
                    kademlia,
                    identify,
                    mdns,
                    autonat,
                    dcutr,
                    ping,
                    relay_client,
                    relay_server: relay::Behaviour::new(peer_id, relay::Config::default()),
                    rpc,
                    stream: libp2p_stream::Behaviour::new(),
                })
            })?
            .build();

        // Clone a control handle out before the swarm is moved into the event loop; tunnels are
        // driven from spawned tasks via this handle (the swarm itself is !Sync).
        let stream_control = swarm.behaviour().stream.new_control();

        let (cmd_tx, cmd_rx) = mpsc::channel(128);
        let (event_tx, event_rx) = mpsc::channel(256);

        let mesh = Self {
            swarm,
            tx_topic,
            block_topic,
            heights_topic,
            syncreq_topic,
            syncresp_topic,
            protocol_topic,
            segments_topic,
            cmd_rx,
            event_tx,
            relay_peers: HashMap::new(),
            pending_outbound: HashMap::new(),
            pending_inbound: HashMap::new(),
            next_inbound_id: 0,
            pending_providers: HashMap::new(),
            sync_nonce: 0,
            disable_local_discovery,
            allowed_peers: std::collections::HashSet::new(),
        };

        let handle = MeshHandle { cmd_tx };
        Ok((mesh, handle, event_rx, stream_control))
    }

    pub fn add_bootstrap(&mut self, addr: &str) -> Result<()> {
        let ma: Multiaddr = addr.parse()?;
        let peer_id = peer_id_from_multiaddr(&ma)?;
        self.allowed_peers.insert(peer_id);
        self.swarm.behaviour_mut().kademlia.add_address(&peer_id, ma.clone());
        self.swarm.dial(ma)?;
        Ok(())
    }

    /// Register a relay node. After connecting, we will listen on its circuit address,
    /// making this node reachable even behind NAT.
    pub fn add_relay(&mut self, addr: &str) -> Result<()> {
        let ma: Multiaddr = addr.parse()?;
        let peer_id = peer_id_from_multiaddr(&ma)?;
        self.allowed_peers.insert(peer_id);
        self.relay_peers.insert(peer_id, ma.clone());
        self.swarm.behaviour_mut().kademlia.add_address(&peer_id, ma.clone());
        self.swarm.dial(ma)?;
        Ok(())
    }

    pub async fn run(mut self, listen_port: u16) -> Result<()> {
        let tcp_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{listen_port}").parse()?;
        self.swarm.listen_on(tcp_addr)?;

        let quic_addr: Multiaddr = format!("/ip4/0.0.0.0/udp/{listen_port}/quic-v1").parse()?;
        if let Err(e) = self.swarm.listen_on(quic_addr) {
            debug!("QUIC listen: {e}");
        }

        for topic in [
            &self.tx_topic,
            &self.block_topic,
            &self.heights_topic,
            &self.syncreq_topic,
            &self.syncresp_topic,
            &self.protocol_topic,
            &self.segments_topic,
        ] {
            self.swarm.behaviour_mut().gossipsub.subscribe(topic)?;
        }

        let topics = Topics {
            tx: self.tx_topic.hash(),
            block: self.block_topic.hash(),
            heights: self.heights_topic.hash(),
            syncreq: self.syncreq_topic.hash(),
            syncresp: self.syncresp_topic.hash(),
            protocol: self.protocol_topic.hash(),
            segments: self.segments_topic.hash(),
        };

        loop {
            tokio::select! {
                Some(cmd) = self.cmd_rx.recv() => {
                    self.handle_command(cmd);
                }
                event = self.swarm.next() => {
                    let Some(event) = event else { break };
                    self.handle_event(event, &topics).await;
                }
            }
        }
        Ok(())
    }

    async fn handle_event(&mut self, event: SwarmEvent<CeBehaviourEvent>, topics: &Topics) {
        // Relay: when we connect to a registered relay, start listening on its circuit.
        if let SwarmEvent::ConnectionEstablished { ref peer_id, .. } = event {
            if let Some(relay_ma) = self.relay_peers.get(peer_id).cloned() {
                let circuit: Multiaddr = format!("{relay_ma}/p2p-circuit").parse()
                    .expect("valid circuit multiaddr");
                match self.swarm.listen_on(circuit) {
                    Ok(_) => info!("relay circuit listening via {peer_id}"),
                    Err(e) => warn!("relay circuit listen error: {e}"),
                }
            }
        }

        match event {
            // mDNS: dial discovered local peers and add them to kademlia.
            SwarmEvent::Behaviour(CeBehaviourEvent::Mdns(
                mdns::Event::Discovered(peers)
            )) => {
                if !self.disable_local_discovery {
                    for (peer_id, addr) in peers {
                        info!("mDNS discovered {peer_id} at {addr}");
                        self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                        let _ = self.swarm.dial(peer_id);
                    }
                }
            }

            // AutoNAT: log NAT status changes.
            SwarmEvent::Behaviour(CeBehaviourEvent::Autonat(
                autonat::Event::StatusChanged { old, new }
            )) => {
                info!("NAT status: {old:?} → {new:?}");
            }

            // DCUtR: log hole-punch outcomes.
            SwarmEvent::Behaviour(CeBehaviourEvent::Dcutr(ref ev)) => {
                debug!("DCUtR: {ev:?}");
            }

            // /ce/rpc/1 — device exec/sync protocol.
            SwarmEvent::Behaviour(CeBehaviourEvent::Rpc(rpc_event)) => {
                self.handle_rpc_event(rpc_event).await;
            }

            // Kademlia query results — completes `find_providers` lookups (data layer).
            SwarmEvent::Behaviour(CeBehaviourEvent::Kademlia(
                kad::Event::OutboundQueryProgressed { id, result, step, .. }
            )) => {
                self.handle_kad_query(id, result, step.last);
            }

            // Everything else: decode and forward to the node.
            other => {
                if let Some(ev) = decode_swarm_event(other, topics, self.swarm.behaviour_mut()) {
                    let _ = self.event_tx.send(ev).await;
                }
            }
        }
    }

    async fn handle_rpc_event(
        &mut self,
        event: request_response::Event<RpcRequest, RpcResponse>,
    ) {
        use request_response::{Event, Message};
        match event {
            Event::Message { peer, message } => match message {
                Message::Request { request, channel, .. } => {
                    let id = self.next_inbound_id;
                    self.next_inbound_id += 1;
                    self.pending_inbound.insert(id, channel);
                    let _ = self.event_tx.send(MeshEvent::IncomingRpc {
                        from_peer: peer,
                        correlation_id: id,
                        request,
                    }).await;
                }
                Message::Response { request_id, response } => {
                    if let Some(tx) = self.pending_outbound.remove(&request_id) {
                        let _ = tx.send(response);
                    }
                }
            },
            Event::OutboundFailure { request_id, error, .. } => {
                warn!("rpc outbound failure: {error}");
                if let Some(tx) = self.pending_outbound.remove(&request_id) {
                    let _ = tx.send(RpcResponse::Error(format!("outbound failure: {error}")));
                }
            }
            Event::InboundFailure { peer, error, .. } => {
                warn!("rpc inbound failure from {peer}: {error}");
            }
            Event::ResponseSent { .. } => {}
        }
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
            MeshCommand::AnnounceHeight { node_id, height, tip_hash, oldest_block } => {
                let msg = HeightAnnounce { node_id, height, tip_hash, oldest_block };
                if let Ok(bytes) = bincode::serialize(&msg) {
                    let _ = self.swarm.behaviour_mut().gossipsub
                        .publish(self.heights_topic.clone(), bytes);
                }
            }
            MeshCommand::AnnounceSegments { node_id, held_segments } => {
                let msg = SegmentManifest { node_id, held_segments };
                if let Ok(bytes) = bincode::serialize(&msg) {
                    let _ = self.swarm.behaviour_mut().gossipsub
                        .publish(self.segments_topic.clone(), bytes);
                }
            }
            MeshCommand::SendSyncRequest { from_node, from_height } => {
                self.sync_nonce += 1;
                let msg = SyncReqMsg { from_node, from_height, nonce: self.sync_nonce };
                if let Ok(bytes) = bincode::serialize(&msg) {
                    if let Err(e) = self.swarm.behaviour_mut().gossipsub
                        .publish(self.syncreq_topic.clone(), bytes)
                    {
                        debug!("sync request publish: {e}");
                    }
                }
            }
            MeshCommand::SendSyncResponse { for_node, blocks } => {
                for chunk in blocks.chunks(MAX_BLOCKS_PER_SYNC) {
                    let msg = SyncRespMsg { for_node, blocks: chunk.to_vec() };
                    if let Ok(bytes) = bincode::serialize(&msg) {
                        if let Err(e) = self.swarm.behaviour_mut().gossipsub
                            .publish(self.syncresp_topic.clone(), bytes)
                        {
                            debug!("sync response publish: {e}");
                        }
                    }
                }
            }
            MeshCommand::PublishSignal(bytes) => {
                if let Err(e) = self.swarm.behaviour_mut().gossipsub
                    .publish(self.protocol_topic.clone(), bytes)
                {
                    debug!("publish signal: {e}");
                }
            }
            MeshCommand::Dial(addr) => {
                match addr.parse::<Multiaddr>() {
                    Ok(ma) => {
                        if let Err(e) = self.swarm.dial(ma) {
                            debug!("dial {addr}: {e}");
                        }
                    }
                    Err(e) => warn!("dial: bad multiaddr {addr}: {e}"),
                }
            }
            MeshCommand::SendRpc { peer_id, request, reply_tx } => {
                let req_id = self.swarm.behaviour_mut().rpc
                    .send_request(&peer_id, request);
                self.pending_outbound.insert(req_id, reply_tx);
            }
            MeshCommand::RespondRpc { correlation_id, response } => {
                if let Some(channel) = self.pending_inbound.remove(&correlation_id) {
                    if let Err(_) = self.swarm.behaviour_mut().rpc
                        .send_response(channel, response)
                    {
                        warn!("rpc: failed to send response for correlation_id {correlation_id} (channel closed)");
                    }
                } else {
                    warn!("rpc: no pending inbound for correlation_id {correlation_id}");
                }
            }
            MeshCommand::ProvideChunk { key } => {
                let record_key = kad::RecordKey::new(&key);
                if let Err(e) = self.swarm.behaviour_mut().kademlia.start_providing(record_key) {
                    debug!("start_providing {:02x?}: {e}", &key[..4]);
                }
            }
            MeshCommand::FindProviders { key, reply_tx } => {
                let record_key = kad::RecordKey::new(&key);
                let qid = self.swarm.behaviour_mut().kademlia.get_providers(record_key);
                self.pending_providers.insert(qid, (reply_tx, std::collections::HashSet::new()));
            }
            MeshCommand::SubscribeApp { topic } => {
                let t = gossipsub::IdentTopic::new(format!("{APP_TOPIC_PREFIX}{topic}"));
                if let Err(e) = self.swarm.behaviour_mut().gossipsub.subscribe(&t) {
                    debug!("subscribe app topic {topic}: {e}");
                }
            }
            MeshCommand::PublishApp { topic, data } => {
                let t = gossipsub::IdentTopic::new(format!("{APP_TOPIC_PREFIX}{topic}"));
                if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(t, data) {
                    debug!("publish app topic {topic}: {e}");
                }
            }
        }
    }

    /// Accumulate providers from a Kademlia `GetProviders` query and complete the pending
    /// `find_providers` call when the query's final progress step arrives.
    fn handle_kad_query(&mut self, id: kad::QueryId, result: kad::QueryResult, last: bool) {
        if let kad::QueryResult::GetProviders(res) = result {
            // Complete as soon as any provider is found — one is enough to attempt a fetch, and
            // waiting for the query's final step can take tens of seconds. Otherwise wait for the
            // last step (which may carry no providers, i.e. nobody has it).
            let mut done = last;
            if let Some((_, acc)) = self.pending_providers.get_mut(&id) {
                if let Ok(kad::GetProvidersOk::FoundProviders { providers, .. }) = &res {
                    acc.extend(providers.iter().copied());
                    if !acc.is_empty() {
                        done = true;
                    }
                }
            }
            if done {
                if let Some((tx, acc)) = self.pending_providers.remove(&id) {
                    let _ = tx.send(acc.into_iter().collect());
                }
            }
        }
    }
}

fn decode_swarm_event(
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
        SwarmEvent::Behaviour(CeBehaviourEvent::Ping(
            ping::Event { peer, result: Ok(rtt), .. },
        )) => {
            Some(MeshEvent::Rtt { peer, rtt_ms: rtt.as_secs_f64() * 1000.0 })
        }
        SwarmEvent::Behaviour(CeBehaviourEvent::RelayClient(ev)) => {
            debug!("relay client: {ev:?}");
            None
        }
        SwarmEvent::Behaviour(CeBehaviourEvent::RelayServer(ev)) => {
            debug!("relay server: {ev:?}");
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
                oldest_block: a.oldest_block,
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
    } else if t == &topics.protocol {
        match CellSignal::decode(&message.data) {
            Ok(signal) => match signal.verify() {
                Ok(()) => Some(MeshEvent::CellSignal(signal)),
                Err(e) => { warn!("ce-protocol-1 signal failed sig check: {e}"); None }
            },
            Err(e) => { warn!("bad ce-protocol-1 gossip: {e}"); None }
        }
    } else if t == &topics.segments {
        match bincode::deserialize::<SegmentManifest>(&message.data) {
            Ok(m) => Some(MeshEvent::PeerSegments {
                node_id: m.node_id,
                held_segments: m.held_segments,
            }),
            Err(e) => { warn!("bad segment manifest: {e}"); None }
        }
    } else if let Some(app_topic) = t.as_str().strip_prefix(APP_TOPIC_PREFIX) {
        // App pub/sub: verify the publisher's signature before delivering (gossip is relayed,
        // so per-message authorship must be proven by the signature, not the transport).
        match bincode::deserialize::<AppPubSubMsg>(&message.data) {
            Ok(m) => {
                let sig: [u8; 64] = match m.sig.as_slice().try_into() {
                    Ok(s) => s,
                    Err(_) => { warn!("app pubsub: bad signature length"); return None; }
                };
                let signed = app_pubsub_bytes(&m.topic, &m.payload, m.nonce);
                if m.topic == app_topic && ce_identity::verify(&m.from, &signed, &sig).is_ok() {
                    Some(MeshEvent::AppGossip { from: m.from, topic: m.topic, payload: m.payload })
                } else {
                    warn!("app pubsub: signature/topic mismatch — dropping");
                    None
                }
            }
            Err(e) => { warn!("bad app pubsub message: {e}"); None }
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

#[cfg(test)]
mod conversion_tests {
    use super::*;

    #[test]
    fn node_id_peer_id_roundtrip() {
        // A node id (ed25519 pubkey) ↔ libp2p PeerId must round-trip both directions, since the
        // node addresses peers by CE node id and the mesh authenticates by PeerId.
        let peer = peer_id_from_secret([7u8; 32]).unwrap();
        let node_id = node_id_from_peer_id(&peer).expect("ed25519 peer carries an inlined key");
        let peer2 = peer_id_from_node_id(&node_id).unwrap();
        assert_eq!(peer, peer2, "node_id -> peer_id -> node_id is stable");
        assert_eq!(node_id_from_peer_id(&peer2), Some(node_id));
    }

    #[test]
    fn distinct_secrets_give_distinct_ids() {
        let a = node_id_from_peer_id(&peer_id_from_secret([1u8; 32]).unwrap()).unwrap();
        let b = node_id_from_peer_id(&peer_id_from_secret([2u8; 32]).unwrap()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn tunnel_protocol_is_stable() {
        assert_eq!(TUNNEL_PROTOCOL.as_ref(), "/ce/tunnel/1");
    }

    #[test]
    fn rpc_from_node_is_extractable() {
        let n = [3u8; 32];
        let req = RpcRequest::Deploy {
            from_node: n,
            workload: vec![],
            cpu_cores: 1,
            mem_mb: 1,
            duration_secs: 1,
            bid: 0,
            grant: None,
        };
        assert_eq!(req.from_node(), n);
        let app = RpcRequest::AppMessage { from_node: n, topic: "t".into(), payload: vec![] };
        assert_eq!(app.from_node(), n);
    }
}
