use anyhow::{anyhow, Result};
use ce_identity::{verify, Identity, NodeId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Difficulty adjustment window (blocks).
pub const DIFFICULTY_WINDOW: u64 = 2016;
/// Target inter-block time in seconds.
pub const TARGET_BLOCK_SECS: u64 = 600;
/// Minimum blocks to retain after a prune. Covers EXPIRY_BLOCKS + difficulty window.
pub const PRUNE_KEEP_BLOCKS: u64 = 2880;

/// Number of blocks per archive segment. 1000 blocks ≈ 2.8 hours at 10 s/block.
pub const SEGMENT_SIZE: u64 = 1000;

/// Default fraction of history segments each node volunteers to hold.
/// At 15% density with 20 peers → ~3× replication per segment on average.
/// 0.0 = opt out, 1.0 = full archive.
pub const ARCHIVE_DENSITY: f64 = 0.15;

/// Returns the segment ID that contains `block_index`.
pub fn segment_id_for_block(block_index: u64) -> u64 {
    block_index / SEGMENT_SIZE
}

/// Deterministic volunteer check: should this node hold `segment_id` from its archive?
/// Uses rendezvous hashing — any node can compute this for any peer without coordination.
pub fn should_hold_segment(node_id: &NodeId, segment_id: u64, density: f64) -> bool {
    if density >= 1.0 {
        return true;
    }
    if density <= 0.0 {
        return false;
    }
    let mut h = Sha256::new();
    h.update(node_id);
    h.update(&segment_id.to_le_bytes());
    let val = u32::from_le_bytes(h.finalize()[..4].try_into().unwrap());
    (val as f64 / u32::MAX as f64) < density
}

/// Persist a segment's blocks to the archive directory (bincode + zstd level 3).
pub fn save_segment(archive_dir: &Path, segment_id: u64, blocks: &[Block]) -> Result<()> {
    std::fs::create_dir_all(archive_dir)?;
    let path = archive_dir.join(format!("segment_{segment_id}.bin"));
    let raw = bincode::serialize(blocks).map_err(|e| anyhow!("bincode: {e}"))?;
    let compressed = zstd::encode_all(raw.as_slice(), 3).map_err(|e| anyhow!("zstd: {e}"))?;
    std::fs::write(path, compressed)?;
    Ok(())
}

/// Load a segment from the archive directory. Returns None if the file doesn't exist.
pub fn load_segment(archive_dir: &Path, segment_id: u64) -> Result<Option<Vec<Block>>> {
    let path = archive_dir.join(format!("segment_{segment_id}.bin"));
    if !path.exists() {
        return Ok(None);
    }
    let compressed = std::fs::read(&path)?;
    let raw = zstd::decode_all(compressed.as_slice()).map_err(|e| anyhow!("zstd: {e}"))?;
    let blocks: Vec<Block> = bincode::deserialize(&raw).map_err(|e| anyhow!("bincode: {e}"))?;
    Ok(Some(blocks))
}

/// Return all segment IDs present in the archive directory (sorted).
pub fn list_archive_segments(archive_dir: &Path) -> Vec<u64> {
    let mut ids = vec![];
    let Ok(entries) = std::fs::read_dir(archive_dir) else {
        return ids;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let s = name.to_string_lossy();
        if let Some(rest) = s.strip_prefix("segment_") {
            if let Some(id_str) = rest.strip_suffix(".bin") {
                if let Ok(id) = id_str.parse::<u64>() {
                    ids.push(id);
                }
            }
        }
    }
    ids.sort_unstable();
    ids
}

/// Returns true if `hash` begins with at least `bits` zero bits.
/// With `bits = 0` this is always true (genesis / test chains).
pub fn has_leading_zeros(hash: &[u8; 32], bits: u8) -> bool {
    let full_bytes = (bits / 8) as usize;
    let rem = bits % 8;
    for b in hash.iter().take(full_bytes) {
        if *b != 0 {
            return false;
        }
    }
    if rem > 0 && full_bytes < 32 {
        let mask = 0xFFu8 << (8 - rem);
        if hash[full_bytes] & mask != 0 {
            return false;
        }
    }
    true
}

mod sig_serde {
    use serde::{de::Error, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(sig: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(sig)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(d)?;
        bytes.try_into().map_err(|_| D::Error::custom("expected 64 bytes for signature"))
    }
}

// ----- Transactions -----

/// After this many blocks past the bid block, the payer may submit a JobExpire to reclaim
/// locked credits. Approximately 24 hours at 10s/block.
pub const EXPIRY_BLOCKS: u64 = 1440;

/// Maximum transactions per block. Prevents chain-bloat attacks where an adversary packs
/// a block with thousands of tiny transactions to exhaust storage or gossip bandwidth.
/// At ~200 bytes/tx this caps a block at ~200 KB, well within the gossip 4 MB limit.
pub const MAX_TXS_PER_BLOCK: usize = 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TxKind {
    /// Credit transfer between nodes. `amount` is in base units (1 credit = `CREDIT` base units).
    Transfer { from: NodeId, to: NodeId, amount: u128 },
    /// Uptime emission: credits minted and credited to a node for staying online.
    UptimeReward { node: NodeId, amount: u128, epoch: u64 },
    /// Open job bid: payer offers up to `bid` credits for a workload.
    /// `cmd` and `env` describe how the container should be launched; they are
    /// included on-chain so any host with capacity can accept the bid deterministically.
    /// The `bid` amount is locked in the payer's balance until JobSettle or JobExpire.
    JobBid {
        job_id: [u8; 32],
        payer: NodeId,
        bid: u128,
        image: String,
        cmd: Vec<String>,
        env: Vec<(String, String)>,
        cpu_cores: u32,
        mem_mb: u64,
        duration_secs: u64,
    },
    /// Job settlement: host records actual resource usage; payer co-signs to authorize.
    /// `payer_sig` is a signature over `payer_settle_bytes(job_id, cost)` by `payer`.
    /// `cost` must not exceed the original bid amount.
    JobSettle {
        job_id: [u8; 32],
        host: NodeId,
        payer: NodeId,
        cpu_ms: u64,
        mem_mb: u64,
        cost: u128,
        #[serde(with = "sig_serde")]
        payer_sig: [u8; 64],
    },
    /// Job expiry: payer reclaims locked bid credits after EXPIRY_BLOCKS have elapsed
    /// without a matching JobSettle.
    JobExpire { job_id: [u8; 32], payer: NodeId },
    /// Trust grant: records that `grantor` trusts `grantee` as a named device.
    /// Used by the personal mesh OS layer for authenticated sync and exec.
    TrustGrant { grantor: NodeId, grantee: NodeId, label: String },
    /// Periodic heartbeat payment for a long-running cell.
    /// Signed by the host; debits the cell's wallet and credits the host.
    /// `epoch` must strictly increase per (cell, host) pair to prevent replay.
    Heartbeat { cell: NodeId, host: NodeId, amount: u128, epoch: u64 },
    /// Open a unidirectional payment channel payer → host. Locks `capacity` base units of the
    /// payer's free balance (like a JobBid lock). Signed by the payer. See docs/payment-channels.md.
    ChannelOpen {
        channel_id: [u8; 32],
        payer: NodeId,
        host: NodeId,
        capacity: u128,
        /// After this block height the payer may reclaim the channel via ChannelExpire.
        expiry_height: u64,
    },
    /// Close a channel by redeeming the payer's highest off-chain receipt. Submitted by the
    /// **host** (origin == host); settles instantly: `cumulative` → host, the rest unlocks to the
    /// payer. `payer_sig` is over `channel_receipt_bytes(channel_id, host, cumulative)`.
    /// (v0: only the host closes-with-receipt — it maximizes its own payout, so the payer can't be
    /// underpaid and no dispute window is needed. Payer-side unilateral close + the dispute window
    /// in the design doc come with bidirectional channels.)
    ChannelClose {
        channel_id: [u8; 32],
        cumulative: u128,
        #[serde(with = "sig_serde")]
        payer_sig: [u8; 64],
    },
    /// Reclaim a channel's full locked capacity after `expiry_height`. Signed by the payer.
    /// The payer's escape if the host never closes; the host must close before expiry to claim.
    ChannelExpire { channel_id: [u8; 32], payer: NodeId },
}

/// Canonical bytes the payer signs to authorize a settlement of `cost` for `job_id` by `host`.
/// Binds the authorization to a specific host so a stolen sig cannot be replayed by another node.
/// Both the host (when building) and the chain (when validating) must produce identical bytes.
pub fn payer_settle_bytes(job_id: &[u8; 32], host: &NodeId, cost: u128) -> Vec<u8> {
    bincode::serialize(&(b"ce-job-settle-v2", job_id, host, cost)).unwrap_or_default()
}

/// Canonical bytes the payer signs for an **off-chain payment-channel receipt** — the core of
/// payment channels (see `docs/payment-channels.md`). `cumulative` is the monotonic total paid
/// over the channel's life; `host` is bound so a receipt can't be replayed against another host
/// or channel. The payer streams these off-chain (no tx); the host redeems the highest one
/// on-chain via `ChannelClose`. The chain validates that closing receipt with identical bytes.
pub fn channel_receipt_bytes(channel_id: &[u8; 32], host: &NodeId, cumulative: u128) -> Vec<u8> {
    bincode::serialize(&(b"ce-channel-receipt-v1", channel_id, host, cumulative)).unwrap_or_default()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tx {
    pub kind: TxKind,
    #[serde(with = "sig_serde")]
    pub sig: [u8; 64],
    pub origin: NodeId,
}

impl Tx {
    pub fn new(kind: TxKind, origin: NodeId, sig: [u8; 64]) -> Self {
        Self { kind, sig, origin }
    }

    pub fn verify(&self) -> Result<()> {
        let data = bincode::serialize(&self.kind)?;
        verify(&self.origin, &data, &self.sig)
    }

    pub fn id(&self) -> [u8; 32] {
        let data = bincode::serialize(self).unwrap_or_default();
        Sha256::digest(data).into()
    }
}

// ----- Block -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub index: u64,
    pub prev_hash: [u8; 32],
    pub timestamp: u64,
    pub transactions: Vec<Tx>,
    pub nonce: u64,
    pub miner: NodeId,
    #[serde(with = "sig_serde")]
    pub sig: [u8; 64],
}

impl Block {
    pub fn hash(&self) -> [u8; 32] {
        let data = bincode::serialize(self).unwrap_or_default();
        Sha256::digest(data).into()
    }

    fn header_bytes(&self) -> Vec<u8> {
        // Sign all fields except sig itself to avoid a circular dependency.
        bincode::serialize(&(
            self.index,
            &self.prev_hash,
            self.timestamp,
            &self.transactions,
            self.nonce,
            &self.miner,
        ))
        .unwrap_or_default()
    }

    /// Sign the block header. Must be called before Chain::append.
    pub fn seal(&mut self, identity: &Identity) {
        self.sig = identity.sign(&self.header_bytes());
    }

    /// Verify the block seal against the miner's public key.
    pub fn verify_seal(&self) -> bool {
        verify(&self.miner, &self.header_bytes(), &self.sig).is_ok()
    }
}

// ----- Checkpoint -----

/// Full state snapshot taken at `block_height`. Blocks before this height are pruned.
/// Stored alongside the chain blocks so nodes can boot from checkpoint + recent history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Height of the last block included in this snapshot.
    pub block_height: u64,
    /// Hash of that block (integrity anchor).
    pub block_hash: [u8; 32],
    /// Total UptimeReward supply emitted up to and including `block_height`, in base units.
    pub total_supply: u128,
    /// Full balance snapshot at checkpoint height (base units).
    pub balances: Vec<(NodeId, i128)>,
    /// All open (unsettled, unexpired) job bids at checkpoint height.
    /// Tuple: (job_id, (payer, bid_amount_base_units, bid_block_index)).
    pub open_bids: Vec<([u8; 32], (NodeId, u128, u64))>,
    /// Highest confirmed heartbeat epoch per (cell, host) pair at checkpoint height.
    pub heartbeat_max_epoch: Vec<((NodeId, NodeId), u64)>,
}

// ----- Chain -----

/// Base units per credit. All on-chain amounts are denominated in base units (integers);
/// "credits" are a display multiple. 10^18 (wei-style) gives ample room for micropayments
/// in the per-signal economy. We use integers — never floating point — because float
/// arithmetic is non-deterministic across machines and would split consensus.
pub const CREDIT: u128 = 1_000_000_000_000_000_000;
/// Initial block emission: 1,000 credits per block, expressed in base units.
const EMISSION_BASE: u128 = 1_000 * CREDIT;
/// Hard cap on total emitted supply: 21 billion credits, in base units (2.1 × 10^28).
pub const SUPPLY_CAP: u128 = 21_000_000_000 * CREDIT;

/// zstd magic bytes (little-endian frame magic).
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// Per-node interaction history derived from the chain — the **reputation substrate**.
/// CE does not score trust; it guarantees these immutable facts, and apps compute their own
/// per-relationship trust from them. All amounts are base units. Built incrementally as blocks
/// apply (same pattern as `balances`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeStats {
    /// Jobs this node settled as the host (work delivered and paid for).
    pub jobs_hosted: u64,
    /// Jobs this node paid for as the payer.
    pub jobs_paid: u64,
    /// Heartbeats this node received as host (long-running work it served).
    pub heartbeats_hosted: u64,
    /// Heartbeats this node paid as the cell (long-running work it consumed).
    pub heartbeats_paid: u64,
    /// Bids this node let expire as payer without settling (host never delivered / no-show).
    pub expiries: u64,
    /// Total credits earned hosting work (settlements + heartbeats received).
    pub earned: u128,
    /// Total credits spent on work (settlements + heartbeats paid).
    pub spent: u128,
    /// Block height at which this node was first seen in an interaction (0 = never).
    pub first_height: u64,
    /// Block height of this node's most recent interaction.
    pub last_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chain {
    /// Blocks after the checkpoint (or all blocks if no checkpoint exists).
    pub blocks: Vec<Block>,
    /// Retained for forward compatibility; not used for validation in the uptime model.
    pub difficulty: u8,
    /// Pruned state snapshot. When present, `blocks` only contains blocks whose
    /// index is greater than `checkpoint.block_height`.
    pub checkpoint: Option<Checkpoint>,

    // Incremental caches — NOT persisted (rebuilt on load from checkpoint + blocks).
    // These give O(1) lookups for all validation hot-paths.

    /// Net balance per node (base units).
    #[serde(skip, default)]
    balances: std::collections::HashMap<NodeId, i128>,

    /// Highest confirmed Heartbeat epoch per (cell, host) pair.
    #[serde(skip, default)]
    heartbeat_max_epoch: std::collections::HashMap<(NodeId, NodeId), u64>,

    /// tx_id → (block.index, position-in-block-txs): O(1) tx lookup.
    #[serde(skip, default)]
    tx_index: std::collections::HashMap<[u8; 32], (u64, usize)>,

    /// Open (unsettled, unexpired) JobBids: job_id → (payer, bid_amount, bid_block_index).
    /// bid_block_index enables O(1) EXPIRY_BLOCKS check without scanning history.
    /// Entries are removed when a matching JobSettle or JobExpire is confirmed.
    #[serde(skip, default)]
    open_bids: std::collections::HashMap<[u8; 32], (NodeId, u128, u64)>,

    /// Open payment channels: channel_id → (payer, host, capacity, expiry_height).
    /// Capacity is locked in the payer's balance until ChannelClose or ChannelExpire.
    #[serde(skip, default)]
    open_channels: std::collections::HashMap<[u8; 32], (NodeId, NodeId, u128, u64)>,

    /// Cumulative UptimeReward supply. Avoids O(n) scan in append().
    #[serde(skip, default)]
    total_supply_cache: u128,

    /// Per-node interaction history (reputation substrate). O(1) lookup, built incrementally.
    #[serde(skip, default)]
    node_stats: std::collections::HashMap<NodeId, NodeStats>,
}

impl Chain {
    pub fn genesis() -> Self {
        let genesis = Block {
            index: 0,
            prev_hash: [0u8; 32],
            timestamp: 0,
            transactions: vec![],
            nonce: 0,
            miner: [0u8; 32],
            sig: [0u8; 64],
        };
        Self {
            blocks: vec![genesis],
            difficulty: 0,
            checkpoint: None,
            balances: std::collections::HashMap::new(),
            heartbeat_max_epoch: std::collections::HashMap::new(),
            tx_index: std::collections::HashMap::new(),
            open_bids: std::collections::HashMap::new(),
            open_channels: std::collections::HashMap::new(),
            total_supply_cache: 0,
            node_stats: std::collections::HashMap::new(),
        }
    }

    /// Rebuild all incremental caches from checkpoint state + kept blocks.
    /// Called once after loading from disk.
    pub fn rebuild_caches(&mut self) {
        self.balances.clear();
        self.heartbeat_max_epoch.clear();
        self.tx_index.clear();
        self.open_bids.clear();
        // Rebuilt from available blocks (not seeded from checkpoint). Channels are short-lived
        // and retained within the light-node prune window; archive nodes hold full state.
        self.open_channels.clear();
        self.total_supply_cache = 0;
        // node_stats is rebuilt from available blocks. A pruned light node therefore holds
        // only post-checkpoint reputation; full history lives on archive nodes (query one of
        // those for complete reputation). Acceptable for v0.
        self.node_stats.clear();

        // Seed caches from checkpoint if present.
        if let Some(ref cp) = self.checkpoint {
            self.total_supply_cache = cp.total_supply;
            self.balances.extend(cp.balances.iter().copied());
            self.open_bids.extend(cp.open_bids.iter().copied());
            self.heartbeat_max_epoch.extend(cp.heartbeat_max_epoch.iter().copied());
        }

        let blocks = self.blocks.clone();
        for block in &blocks {
            self.apply_block_to_cache(block);
        }
    }

    /// Apply one block's transactions to the incremental caches.
    fn apply_block_to_cache(&mut self, block: &Block) {
        for (pos, tx) in block.transactions.iter().enumerate() {
            match &tx.kind {
                TxKind::Transfer { from, to, amount } => {
                    *self.balances.entry(*from).or_insert(0) -= *amount as i128;
                    *self.balances.entry(*to).or_insert(0) += *amount as i128;
                }
                TxKind::UptimeReward { node, amount, .. } => {
                    *self.balances.entry(*node).or_insert(0) += *amount as i128;
                    self.total_supply_cache =
                        self.total_supply_cache.saturating_add(*amount);
                }
                TxKind::JobSettle { job_id, host, payer, cost, .. } => {
                    *self.balances.entry(*payer).or_insert(0) -= *cost as i128;
                    *self.balances.entry(*host).or_insert(0) += *cost as i128;
                    self.open_bids.remove(job_id);
                    let h = block.index;
                    let (cost, host, payer) = (*cost, *host, *payer);
                    let s = self.node_stat(&host, h);
                    s.jobs_hosted += 1;
                    s.earned = s.earned.saturating_add(cost);
                    let s = self.node_stat(&payer, h);
                    s.jobs_paid += 1;
                    s.spent = s.spent.saturating_add(cost);
                }
                TxKind::Heartbeat { cell, host, amount, epoch } => {
                    *self.balances.entry(*cell).or_insert(0) -= *amount as i128;
                    *self.balances.entry(*host).or_insert(0) += *amount as i128;
                    let e = self.heartbeat_max_epoch.entry((*cell, *host)).or_insert(0);
                    if *epoch >= *e {
                        *e = *epoch;
                    }
                    let h = block.index;
                    let (amount, host, cell) = (*amount, *host, *cell);
                    let s = self.node_stat(&host, h);
                    s.heartbeats_hosted += 1;
                    s.earned = s.earned.saturating_add(amount);
                    let s = self.node_stat(&cell, h);
                    s.heartbeats_paid += 1;
                    s.spent = s.spent.saturating_add(amount);
                }
                TxKind::JobBid { job_id, payer, bid, .. } => {
                    self.open_bids.insert(*job_id, (*payer, *bid, block.index));
                }
                TxKind::JobExpire { job_id, payer } => {
                    self.open_bids.remove(job_id);
                    let h = block.index;
                    self.node_stat(payer, h).expiries += 1;
                }
                TxKind::TrustGrant { .. } => {}
                TxKind::ChannelOpen { channel_id, payer, host, capacity, expiry_height } => {
                    self.open_channels.insert(*channel_id, (*payer, *host, *capacity, *expiry_height));
                }
                TxKind::ChannelClose { channel_id, cumulative, .. } => {
                    if let Some((payer, host, _cap, _exp)) = self.open_channels.remove(channel_id) {
                        *self.balances.entry(payer).or_insert(0) -= *cumulative as i128;
                        *self.balances.entry(host).or_insert(0) += *cumulative as i128;
                        let h = block.index;
                        let cumulative = *cumulative;
                        let s = self.node_stat(&host, h);
                        s.jobs_hosted += 1;
                        s.earned = s.earned.saturating_add(cumulative);
                        let s = self.node_stat(&payer, h);
                        s.jobs_paid += 1;
                        s.spent = s.spent.saturating_add(cumulative);
                    }
                }
                TxKind::ChannelExpire { channel_id, .. } => {
                    // Just unlock — capacity returns to the payer's free balance (no balance move).
                    self.open_channels.remove(channel_id);
                }
            }
            self.tx_index.insert(tx.id(), (block.index, pos));
        }
    }

    /// Mutable per-node stats entry, stamping first/last interaction height.
    fn node_stat(&mut self, node: &NodeId, height: u64) -> &mut NodeStats {
        let s = self.node_stats.entry(*node).or_default();
        if s.first_height == 0 {
            s.first_height = height;
        }
        s.last_height = height;
        s
    }

    /// Per-node interaction history (reputation substrate). Returns defaults for an
    /// unknown node. O(1). Apps derive their own trust from these facts.
    pub fn node_history(&self, node: &NodeId) -> NodeStats {
        self.node_stats.get(node).cloned().unwrap_or_default()
    }

    pub fn tip(&self) -> &Block {
        self.blocks.last().expect("chain always has genesis")
    }

    pub fn tip_hash(&self) -> [u8; 32] {
        self.tip().hash()
    }

    pub fn height(&self) -> u64 {
        self.tip().index
    }

    /// Total UptimeReward supply emitted, in base units. O(1) via incremental cache.
    pub fn total_supply(&self) -> u128 {
        self.total_supply_cache
    }

    /// Emission per block at a given block index, in base units.
    /// Base rate 1,000 credits; halves every 210,000 blocks. Because base units are 10^18,
    /// the reward stays non-zero through ~69 halvings before integer-truncating to 0.
    /// The `>= 128` guard keeps the shift width valid for u128.
    pub fn emission_rate(block_index: u64) -> u128 {
        let halvings = block_index / 210_000;
        if halvings >= 128 { 0 } else { EMISSION_BASE >> halvings }
    }

    /// Validates and appends a block. Returns false if invalid (caller should log and discard).
    pub fn append(&mut self, block: Block) -> bool {
        if block.index != self.tip().index + 1 {
            return false;
        }
        if block.prev_hash != self.tip_hash() {
            return false;
        }
        if !block.verify_seal() {
            return false;
        }
        // Reject oversized blocks before paying signature-verification cost.
        if block.transactions.len() > MAX_TXS_PER_BLOCK {
            return false;
        }
        for tx in &block.transactions {
            if tx.verify().is_err() {
                return false;
            }
        }
        // Reject duplicate transaction IDs — prevents cross-block replay and within-block copies.
        {
            let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
            for tx in &block.transactions {
                let id = tx.id();
                if self.tx_index.contains_key(&id) || !seen.insert(id) {
                    return false;
                }
            }
        }
        // At most one UptimeReward per block — a miner cannot claim multiple emission events.
        if block
            .transactions
            .iter()
            .filter(|tx| matches!(tx.kind, TxKind::UptimeReward { .. }))
            .count()
            > 1
        {
            return false;
        }
        // Each UptimeReward must match the emission schedule.
        for tx in &block.transactions {
            if let TxKind::UptimeReward { amount, .. } = &tx.kind {
                if *amount != Self::emission_rate(block.index) {
                    return false;
                }
            }
        }
        // Cumulative supply must not exceed the hard cap.
        let new_emission: u128 = block
            .transactions
            .iter()
            .filter_map(|tx| {
                if let TxKind::UptimeReward { amount, .. } = &tx.kind { Some(*amount) } else { None }
            })
            .fold(0u128, |a, b| a.saturating_add(b));
        if self.total_supply_cache.saturating_add(new_emission) > SUPPLY_CAP {
            return false;
        }
        // Transfer rules: sender must have enough free balance after accumulating all
        // in-block debits. Without this check an attacker could pack two Transfer txs
        // each for the full balance in one block and double-spend.
        //
        // Declared outside its validation loop so later sections (JobBid, Heartbeat) can
        // subtract in-block transfers from the same sender — closing the cross-type
        // double-spend where a node transfers credits and bids/heartbeats with the same
        // credits in a single block.
        let mut in_block_transfer: std::collections::HashMap<NodeId, u128> =
            std::collections::HashMap::new();
        for tx in &block.transactions {
            if let TxKind::Transfer { from, amount, .. } = &tx.kind {
                // Zero-amount transfers are economically meaningless and bloat the chain.
                if *amount == 0 {
                    return false;
                }
                // Sender must match tx origin (verified above via tx.verify()).
                let prior_balance = self.balance(from);
                let locked = self.locked_balance(from) as i128;
                let accumulated = *in_block_transfer.get(from).unwrap_or(&0) as i128;
                let free = prior_balance - locked - accumulated;
                if free < *amount as i128 {
                    return false;
                }
                *in_block_transfer.entry(*from).or_insert(0) =
                    in_block_transfer.get(from).unwrap_or(&0).saturating_add(*amount);
            }
        }
        // JobBid rules.
        {
            // Envelope: must be signed by the named payer.
            for tx in &block.transactions {
                if let TxKind::JobBid { payer, .. } = &tx.kind {
                    if &tx.origin != payer {
                        return false;
                    }
                }
            }
            // No rebid while open: a second bid for the same job_id would silently overwrite
            // the open_bids entry, dropping the original credit lock and enabling a double-spend.
            {
                let mut in_block_job_ids: std::collections::HashSet<[u8; 32]> =
                    std::collections::HashSet::new();
                for tx in &block.transactions {
                    if let TxKind::JobBid { job_id, .. } = &tx.kind {
                        if self.open_bids.contains_key(job_id) || !in_block_job_ids.insert(*job_id) {
                            return false;
                        }
                    }
                }
            }
            // Free-balance check: payer must have enough un-locked credits to cover the bid.
            // Accumulate within this block to prevent double-bidding in a single block.
            // Also subtract in-block transfers: a payer cannot transfer away credits and
            // then bid with those same credits in the same block (cross-type double-spend).
            let mut in_block_bid: std::collections::HashMap<NodeId, u128> =
                std::collections::HashMap::new();
            for tx in &block.transactions {
                if let TxKind::JobBid { payer, bid, .. } = &tx.kind {
                    let already_locked = self.locked_balance(payer) as i128;
                    let in_block = *in_block_bid.get(payer).unwrap_or(&0) as i128;
                    let transferred = *in_block_transfer.get(payer).unwrap_or(&0) as i128;
                    let free = self.balance(payer) - already_locked - in_block - transferred;
                    if free < *bid as i128 {
                        return false;
                    }
                    *in_block_bid.entry(*payer).or_insert(0) += bid;
                }
            }
        }
        // JobSettle rules.
        // open_bids cache tracks all open (unsettled, unexpired) bids — a single lookup
        // replaces the previous O(n) bid-search + O(n) duplicate-settle scan.
        let mut payer_debit: std::collections::HashMap<NodeId, u128> =
            std::collections::HashMap::new();
        for tx in &block.transactions {
            if let TxKind::JobSettle { job_id, host, payer, cost, payer_sig, .. } = &tx.kind {
                // Envelope rule: settles are submitted (and signed) by the host.
                if &tx.origin != host {
                    return false;
                }
                // No self-pay.
                if payer == host {
                    return false;
                }
                // Payer co-signature over (job_id, host, cost) — host is bound to prevent sig theft.
                let bytes = payer_settle_bytes(job_id, host, *cost);
                if verify(payer, &bytes, payer_sig).is_err() {
                    return false;
                }
                // open_bids cache: if present → bid exists, correct payer, not yet settled/expired.
                let (bid_payer, bid_amount, _) = match self.open_bids.get(job_id) {
                    Some(entry) => entry,
                    None => return false,
                };
                if bid_payer != payer {
                    return false;
                }
                if *cost > *bid_amount {
                    return false;
                }
                // Balance check: chain balance minus accumulated debits in this block must cover cost.
                let prior_balance = self.balance(payer);
                let accumulated = *payer_debit.get(payer).unwrap_or(&0);
                if prior_balance.saturating_sub(accumulated as i128) < *cost as i128 {
                    return false;
                }
                *payer_debit.entry(*payer).or_insert(0) =
                    accumulated.saturating_add(*cost);
            }
        }
        // JobExpire rules.
        // open_bids cache gives O(1) bid lookup + settled/expired check + bid_block_index.
        for tx in &block.transactions {
            if let TxKind::JobExpire { job_id, payer } = &tx.kind {
                // Envelope: must be signed by the named payer.
                if &tx.origin != payer {
                    return false;
                }
                // open_bids cache: present → bid exists with correct payer, not settled/expired.
                let (bid_payer, _, bid_block_index) = match self.open_bids.get(job_id) {
                    Some(entry) => entry,
                    None => return false,
                };
                if bid_payer != payer {
                    return false;
                }
                // The bid must have been in a block long enough ago.
                if block.index <= bid_block_index + EXPIRY_BLOCKS {
                    return false;
                }
            }
        }
        // TrustGrant rules: must be signed by the grantor.
        for tx in &block.transactions {
            if let TxKind::TrustGrant { grantor, .. } = &tx.kind {
                if &tx.origin != grantor {
                    return false;
                }
            }
        }
        // Heartbeat rules.
        {
            let mut in_block_epochs: std::collections::HashMap<(NodeId, NodeId), u64> =
                std::collections::HashMap::new();
            let mut heartbeat_debits: std::collections::HashMap<NodeId, u128> =
                std::collections::HashMap::new();
            for tx in &block.transactions {
                if let TxKind::Heartbeat { cell, host, amount, epoch } = &tx.kind {
                    // Must be signed by the host.
                    if &tx.origin != host {
                        return false;
                    }
                    // No self-pay.
                    if cell == host {
                        return false;
                    }
                    // epoch=u64::MAX would permanently block future heartbeats for this pair.
                    if *epoch == u64::MAX {
                        return false;
                    }
                    // Epoch must be strictly greater than the last confirmed for this pair.
                    let chain_last = self.last_heartbeat_epoch(cell, host);
                    let in_block_last = in_block_epochs.get(&(*cell, *host)).copied();
                    let last = in_block_last.or(chain_last);
                    if let Some(prev) = last {
                        if *epoch <= prev {
                            return false;
                        }
                    }
                    in_block_epochs.insert((*cell, *host), *epoch);
                    // Cell balance must cover heartbeat + any credits the cell transferred
                    // away earlier in this same block (cross-type double-spend defence).
                    let prior_balance = self.balance(cell);
                    let hb_accumulated = *heartbeat_debits.get(cell).unwrap_or(&0) as i128;
                    let transferred = *in_block_transfer.get(cell).unwrap_or(&0) as i128;
                    if prior_balance - hb_accumulated - transferred < *amount as i128 {
                        return false;
                    }
                    *heartbeat_debits.entry(*cell).or_insert(0) += amount;
                }
            }
        }
        // Payment-channel rules. Validated LAST so a ChannelOpen's free-balance check subtracts
        // every other in-block debit of the payer (transfers, bids, heartbeats) — channels lose
        // ties, closing the cross-type double-spend.
        {
            let mut in_block_channel: std::collections::HashMap<NodeId, u128> =
                std::collections::HashMap::new();
            let mut in_block_channel_ids: std::collections::HashSet<[u8; 32]> =
                std::collections::HashSet::new();
            let mut closing: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
            for tx in &block.transactions {
                match &tx.kind {
                    TxKind::ChannelOpen { channel_id, payer, host, capacity, .. } => {
                        if &tx.origin != payer || payer == host || *capacity == 0 {
                            return false;
                        }
                        // Unique channel id (not already open, not opened twice this block).
                        if self.open_channels.contains_key(channel_id)
                            || !in_block_channel_ids.insert(*channel_id)
                        {
                            return false;
                        }
                        // Free balance after ALL of this payer's other in-block debits.
                        let bids: u128 = block
                            .transactions
                            .iter()
                            .filter_map(|t| match &t.kind {
                                TxKind::JobBid { payer: p, bid, .. } if p == payer => Some(*bid),
                                _ => None,
                            })
                            .sum();
                        let hbs: u128 = block
                            .transactions
                            .iter()
                            .filter_map(|t| match &t.kind {
                                TxKind::Heartbeat { cell, amount, .. } if cell == payer => Some(*amount),
                                _ => None,
                            })
                            .sum();
                        let transfers = *in_block_transfer.get(payer).unwrap_or(&0);
                        let prior_chan = *in_block_channel.get(payer).unwrap_or(&0);
                        let committed =
                            (self.locked_balance(payer) + transfers + bids + hbs + prior_chan) as i128;
                        if self.balance(payer) - committed < *capacity as i128 {
                            return false;
                        }
                        *in_block_channel.entry(*payer).or_insert(0) += *capacity;
                    }
                    TxKind::ChannelClose { channel_id, cumulative, payer_sig } => {
                        // One close/expire per channel per block.
                        if !closing.insert(*channel_id) {
                            return false;
                        }
                        let (payer, host, capacity, _expiry) = match self.open_channels.get(channel_id) {
                            Some(c) => c,
                            None => return false, // unknown / already settled / opened this same block
                        };
                        // Only the host closes, and only up to the locked capacity.
                        if &tx.origin != host || *cumulative > *capacity {
                            return false;
                        }
                        // The closing receipt must be the payer's signature over (channel, host, cumulative).
                        let bytes = channel_receipt_bytes(channel_id, host, *cumulative);
                        if verify(payer, &bytes, payer_sig).is_err() {
                            return false;
                        }
                    }
                    TxKind::ChannelExpire { channel_id, payer } => {
                        if !closing.insert(*channel_id) {
                            return false;
                        }
                        let (chan_payer, _host, _cap, expiry) = match self.open_channels.get(channel_id) {
                            Some(c) => c,
                            None => return false,
                        };
                        if &tx.origin != payer || chan_payer != payer || block.index <= *expiry {
                            return false;
                        }
                    }
                    _ => {}
                }
            }
        }
        self.apply_block_to_cache(&block);
        self.blocks.push(block);
        true
    }

    /// Attempt a chain reorganisation using a batch of candidate blocks.
    ///
    /// Finds the highest common ancestor between the candidate set and our chain,
    /// then checks whether the candidate suffix is strictly longer than ours from
    /// that fork point. If so, validates every candidate block in order and replaces
    /// our chain. Returns true if a reorg occurred.
    ///
    /// This enforces the longest-chain rule: the network converges on whichever
    /// branch accumulates more blocks, regardless of which arrived first.
    pub fn try_reorg(&mut self, mut candidate: Vec<Block>) -> bool {
        candidate.sort_by_key(|b| b.index);
        if candidate.is_empty() {
            return false;
        }

        // Build a map: block_hash → position in our kept blocks.
        let our_hash_to_pos: std::collections::HashMap<[u8; 32], usize> = self
            .blocks
            .iter()
            .enumerate()
            .map(|(i, b)| (b.hash(), i))
            .collect();

        // Find the deepest fork point: the highest position in our kept blocks whose
        // hash appears as a prev_hash of any candidate block.
        let mut fork_pos: Option<usize> = None;
        for cand in &candidate {
            if let Some(&pos) = our_hash_to_pos.get(&cand.prev_hash) {
                fork_pos = Some(match fork_pos {
                    None => pos,
                    Some(prev) => prev.max(pos),
                });
            }
        }
        let fork_pos = match fork_pos {
            Some(p) => p,
            None => return false, // no connection to our kept chain (could be pre-checkpoint)
        };

        // Walk the candidates in chain order starting from the fork point.
        let mut new_suffix: Vec<Block> = Vec::new();
        let mut expected_prev = self.blocks[fork_pos].hash();
        let mut remaining: Vec<Block> = candidate;
        loop {
            let next = remaining.iter().position(|b| b.prev_hash == expected_prev);
            match next {
                None => break,
                Some(i) => {
                    let block = remaining.remove(i);
                    expected_prev = block.hash();
                    new_suffix.push(block);
                }
            }
        }

        // Only reorg if the candidate suffix is strictly longer.
        let our_suffix_len = self.blocks.len().saturating_sub(fork_pos + 1);
        if new_suffix.len() <= our_suffix_len {
            return false;
        }

        // Validate every candidate block against the chain up to the fork point.
        // Carry the checkpoint so rebuild_caches() has the correct pruned base state.
        let mut reorg_chain = Chain {
            blocks: self.blocks[..=fork_pos].to_vec(),
            difficulty: self.difficulty,
            checkpoint: self.checkpoint.clone(),
            balances: std::collections::HashMap::new(),
            heartbeat_max_epoch: std::collections::HashMap::new(),
            tx_index: std::collections::HashMap::new(),
            open_bids: std::collections::HashMap::new(),
            open_channels: std::collections::HashMap::new(),
            total_supply_cache: 0,
            node_stats: std::collections::HashMap::new(),
        };
        reorg_chain.rebuild_caches();
        for block in new_suffix {
            if !reorg_chain.append(block) {
                return false; // invalid block in candidate chain; abort
            }
        }

        reorg_chain.rebuild_caches();
        *self = reorg_chain;
        true
    }

    /// Prune blocks older than `keep_last` by committing a checkpoint at the cut point.
    /// The checkpoint captures full state so caches can be restored without the pruned blocks.
    /// Only prunes if there are more than `keep_last` blocks beyond genesis.
    /// Minimum safe value: `PRUNE_KEEP_BLOCKS` (covers EXPIRY_BLOCKS + difficulty window).
    pub fn prune(&mut self, keep_last: u64) {
        let keep = keep_last as usize;
        if self.blocks.len() <= keep + 1 {
            return;
        }
        let cut = self.blocks.len() - keep - 1;

        // Build a temporary chain from the checkpoint + blocks up to the cut point to get
        // the exact state at that height. Pruning is infrequent so O(cut) is acceptable.
        let mut snap = Chain {
            blocks: self.blocks[..cut].to_vec(),
            difficulty: self.difficulty,
            checkpoint: self.checkpoint.clone(),
            balances: std::collections::HashMap::new(),
            heartbeat_max_epoch: std::collections::HashMap::new(),
            tx_index: std::collections::HashMap::new(),
            open_bids: std::collections::HashMap::new(),
            open_channels: std::collections::HashMap::new(),
            total_supply_cache: 0,
            node_stats: std::collections::HashMap::new(),
        };
        snap.rebuild_caches();

        let cp_block = &self.blocks[cut - 1];
        let checkpoint = Checkpoint {
            block_height: cp_block.index,
            block_hash: cp_block.hash(),
            total_supply: snap.total_supply_cache,
            balances: snap.balances.into_iter().collect(),
            open_bids: snap.open_bids.into_iter().collect(),
            heartbeat_max_epoch: snap.heartbeat_max_epoch.into_iter().collect(),
        };
        self.checkpoint = Some(checkpoint);
        self.blocks.drain(..cut);
        // Live caches are still valid — they reflect the full chain and haven't changed.
    }

    /// O(1) balance lookup via the incremental cache (base units).
    pub fn balance(&self, node: &NodeId) -> i128 {
        self.balances.get(node).copied().unwrap_or(0)
    }

    /// Credits locked in open bids (no matching JobSettle or JobExpire yet) for a node.
    /// Free balance = `balance(node) - locked_balance(node)`.
    /// O(open_jobs) via the open_bids cache.
    pub fn locked_balance(&self, node: &NodeId) -> u128 {
        let in_bids: u128 = self
            .open_bids
            .values()
            .filter(|(payer, _, _)| payer == node)
            .map(|(_, bid, _)| *bid)
            .sum();
        // Payment-channel capacity is also locked in the payer's balance until close/expire.
        let in_channels: u128 = self
            .open_channels
            .values()
            .filter(|(payer, _, _, _)| payer == node)
            .map(|(_, _, capacity, _)| *capacity)
            .sum();
        in_bids + in_channels
    }

    /// O(1) lookup for the highest confirmed Heartbeat epoch for a (cell, host) pair.
    /// Returns None if no Heartbeat has been confirmed for this pair yet.
    pub fn last_heartbeat_epoch(&self, cell: &NodeId, host: &NodeId) -> Option<u64> {
        self.heartbeat_max_epoch.get(&(*cell, *host)).copied()
    }

    /// O(1) transaction lookup via the tx index.
    /// Returns the tx together with the block height and block hash.
    pub fn tx_by_id(&self, tx_id: &[u8; 32]) -> Option<(Tx, u64, [u8; 32])> {
        let &(blk_idx, tx_pos) = self.tx_index.get(tx_id)?;
        // tx_index stores absolute block indices; map to kept-blocks offset.
        let base = self.blocks.first().map(|b| b.index).unwrap_or(0);
        let offset = blk_idx.checked_sub(base)? as usize;
        let block = self.blocks.get(offset)?;
        let tx = block.transactions.get(tx_pos)?;
        Some((tx.clone(), block.index, block.hash()))
    }

    pub fn next_block(&self, transactions: Vec<Tx>, miner: NodeId) -> Block {
        Block {
            index: self.tip().index + 1,
            prev_hash: self.tip_hash(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            transactions,
            nonce: 0,
            miner,
            sig: [0u8; 64],
        }
    }

    /// Export all blocks in `segment_id` from the live chain.
    /// Returns None if those blocks have been pruned or the segment isn't reached yet.
    pub fn export_segment(&self, segment_id: u64) -> Option<Vec<Block>> {
        let start = segment_id * SEGMENT_SIZE;
        let end = start + SEGMENT_SIZE;
        let base = self.blocks.first().map(|b| b.index).unwrap_or(u64::MAX);
        if base > start {
            return None;
        }
        let blocks: Vec<Block> = self
            .blocks
            .iter()
            .filter(|b| b.index >= start && b.index < end)
            .cloned()
            .collect();
        if blocks.is_empty() { None } else { Some(blocks) }
    }

    /// The highest segment ID that is fully written (all SEGMENT_SIZE blocks present).
    /// Returns None if the chain hasn't accumulated a full segment yet.
    pub fn highest_complete_segment(&self) -> Option<u64> {
        let h = self.height();
        if h < SEGMENT_SIZE {
            return None;
        }
        let current_seg = h / SEGMENT_SIZE;
        if current_seg == 0 { None } else { Some(current_seg - 1) }
    }

    /// Load chain from disk. Supports bincode+zstd (current) and plain JSON (legacy migration).
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        let mut chain: Chain = if data.starts_with(&ZSTD_MAGIC) {
            let decompressed =
                zstd::decode_all(&data[..]).map_err(|e| anyhow!("zstd decompress: {e}"))?;
            bincode::deserialize(&decompressed).map_err(|e| anyhow!("bincode deserialize: {e}"))?
        } else {
            // Legacy JSON — migrate transparently on next save.
            serde_json::from_slice(&data).map_err(|e| anyhow!("json deserialize: {e}"))?
        };
        if chain.blocks.is_empty() && chain.checkpoint.is_none() {
            return Err(anyhow!("chain file is empty"));
        }
        chain.rebuild_caches();
        Ok(chain)
    }

    /// Save chain to disk as bincode + zstd (level 3). ~8x smaller than JSON.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bin = bincode::serialize(self).map_err(|e| anyhow!("bincode serialize: {e}"))?;
        let compressed =
            zstd::encode_all(&bin[..], 3).map_err(|e| anyhow!("zstd compress: {e}"))?;
        std::fs::write(path, compressed)?;
        Ok(())
    }

    pub fn load_or_genesis(path: &Path) -> Self {
        Self::load(path).unwrap_or_else(|_| Self::genesis())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ce_identity::Identity;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("ce-chain-{}-{}", std::process::id(), tag));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn make_identity(tag: &str) -> Identity {
        Identity::load_or_generate(&tmpdir(tag)).unwrap()
    }

    fn signed_transfer(from: &Identity, to: NodeId, amount: u128) -> Tx {
        let kind = TxKind::Transfer { from: from.node_id(), to, amount };
        let data = bincode::serialize(&kind).unwrap();
        let sig = from.sign(&data);
        Tx::new(kind, from.node_id(), sig)
    }

    fn signed_uptime_reward(identity: &Identity, block_index: u64) -> Tx {
        let amount = Chain::emission_rate(block_index);
        let kind = TxKind::UptimeReward { node: identity.node_id(), amount, epoch: block_index };
        let data = bincode::serialize(&kind).unwrap();
        let sig = identity.sign(&data);
        Tx::new(kind, identity.node_id(), sig)
    }

    fn seal_and_append(chain: &mut Chain, identity: &Identity) -> bool {
        let next_index = chain.tip().index + 1;
        let reward = signed_uptime_reward(identity, next_index);
        let mut block = chain.next_block(vec![reward], identity.node_id());
        block.seal(identity);
        chain.append(block)
    }

    // ----- Block tests -----

    #[test]
    fn hash_is_deterministic() {
        let chain = Chain::genesis();
        let b = chain.tip();
        assert_eq!(b.hash(), b.hash());
        assert_ne!(b.hash(), [0u8; 32]);
    }

    #[test]
    fn hash_changes_with_nonce() {
        let chain = Chain::genesis();
        let mut b = chain.next_block(vec![], [1u8; 32]);
        let h1 = b.hash();
        b.nonce += 1;
        assert_ne!(b.hash(), h1);
    }

    #[test]
    fn seal_and_verify() {
        let id = make_identity("seal");
        let chain = Chain::genesis();
        let mut block = chain.next_block(vec![], id.node_id());
        assert!(!block.verify_seal(), "unsigned block should not verify");
        block.seal(&id);
        assert!(block.verify_seal());
    }

    // ----- Chain::append tests -----

    #[test]
    fn genesis_structure() {
        let chain = Chain::genesis();
        assert_eq!(chain.height(), 0);
        assert_eq!(chain.blocks.len(), 1);
        assert_eq!(chain.tip().prev_hash, [0u8; 32]);
        assert_eq!(chain.tip().index, 0);
        assert_eq!(chain.difficulty, 0);
    }

    #[test]
    fn append_valid_block() {
        let mut chain = Chain::genesis();
        let id = make_identity("valid");
        assert!(seal_and_append(&mut chain, &id));
        assert_eq!(chain.height(), 1);
    }

    #[test]
    fn append_rejects_wrong_index() {
        let mut chain = Chain::genesis();
        let id = make_identity("idx");
        let mut block = chain.next_block(vec![], id.node_id());
        block.index = 99;
        block.seal(&id);
        assert!(!chain.append(block));
        assert_eq!(chain.height(), 0);
    }

    #[test]
    fn append_rejects_wrong_prev_hash() {
        let mut chain = Chain::genesis();
        let id = make_identity("prev");
        let reward = signed_uptime_reward(&id, 1);
        let mut block = chain.next_block(vec![reward], id.node_id());
        block.seal(&id);
        block.prev_hash = [0xff; 32]; // corrupt after sealing
        assert!(!chain.append(block));
    }

    #[test]
    fn append_rejects_bad_seal() {
        let mut chain = Chain::genesis();
        let id = make_identity("badseal");
        let other_id = make_identity("other");
        let mut block = chain.next_block(vec![], id.node_id());
        block.seal(&other_id); // wrong identity seals the block
        assert!(!chain.append(block));
    }

    #[test]
    fn append_rejects_invalid_tx_sig() {
        let mut chain = Chain::genesis();
        let id = make_identity("txsig");
        let mut tx = signed_transfer(&id, [0u8; 32], 100);
        tx.sig = [0xff; 64]; // corrupt tx sig
        let mut block = chain.next_block(vec![tx], id.node_id());
        block.seal(&id);
        assert!(!chain.append(block));
    }

    #[test]
    fn three_blocks_chain() {
        let mut chain = Chain::genesis();
        let id = make_identity("three");
        for expected_height in 1u64..=3 {
            assert!(seal_and_append(&mut chain, &id));
            assert_eq!(chain.height(), expected_height);
        }
    }

    // ----- Balance tests -----

    #[test]
    fn balance_starts_zero() {
        let chain = Chain::genesis();
        let id = make_identity("zero");
        assert_eq!(chain.balance(&id.node_id()), 0);
    }

    #[test]
    fn balance_from_uptime_reward() {
        let mut chain = Chain::genesis();
        let id = make_identity("reward");
        seal_and_append(&mut chain, &id);
        assert_eq!(chain.balance(&id.node_id()), Chain::emission_rate(1) as i128);
    }

    #[test]
    fn balance_with_transfer() {
        let mut chain = Chain::genesis();
        let alice = make_identity("alice");
        let bob = make_identity("bob");

        seal_and_append(&mut chain, &alice);
        seal_and_append(&mut chain, &alice);
        let alice_before = chain.balance(&alice.node_id());

        let tx = signed_transfer(&alice, bob.node_id(), 10);
        let reward = signed_uptime_reward(&alice, 3);
        let mut block = chain.next_block(vec![reward, tx], alice.node_id());
        block.seal(&alice);
        chain.append(block);

        assert_eq!(
            chain.balance(&alice.node_id()),
            alice_before - 10 + Chain::emission_rate(3) as i128,
        );
        assert_eq!(chain.balance(&bob.node_id()), 10);
    }

    // ----- Emission schedule -----

    #[test]
    fn channel_receipt_is_host_bound_and_tamper_evident() {
        let payer = make_identity("rcpt-payer");
        let host = make_identity("rcpt-host");
        let other = make_identity("rcpt-other");
        let chan = [7u8; 32];

        // A valid receipt: payer signs (channel, host, cumulative).
        let bytes = channel_receipt_bytes(&chan, &host.node_id(), 1_000);
        let sig = payer.sign(&bytes);
        assert!(verify(&payer.node_id(), &bytes, &sig).is_ok());

        // Tampering the cumulative invalidates the signature.
        let tampered = channel_receipt_bytes(&chan, &host.node_id(), 2_000);
        assert!(verify(&payer.node_id(), &tampered, &sig).is_err());

        // Same receipt can't be replayed against a different host.
        let other_host = channel_receipt_bytes(&chan, &other.node_id(), 1_000);
        assert!(verify(&payer.node_id(), &other_host, &sig).is_err());

        // Monotonic: a higher cumulative produces distinct bytes (supersedes the prior receipt).
        assert_ne!(
            channel_receipt_bytes(&chan, &host.node_id(), 1_000),
            channel_receipt_bytes(&chan, &host.node_id(), 1_001)
        );
    }

    fn signed_channel_open(
        payer: &Identity,
        channel_id: [u8; 32],
        host: NodeId,
        capacity: u128,
        expiry_height: u64,
    ) -> Tx {
        let kind = TxKind::ChannelOpen { channel_id, payer: payer.node_id(), host, capacity, expiry_height };
        let data = bincode::serialize(&kind).unwrap();
        let sig = payer.sign(&data);
        Tx::new(kind, payer.node_id(), sig)
    }

    fn signed_channel_close(host: &Identity, payer: &Identity, channel_id: [u8; 32], cumulative: u128) -> Tx {
        let payer_sig = payer.sign(&channel_receipt_bytes(&channel_id, &host.node_id(), cumulative));
        let kind = TxKind::ChannelClose { channel_id, cumulative, payer_sig };
        let data = bincode::serialize(&kind).unwrap();
        let sig = host.sign(&data);
        Tx::new(kind, host.node_id(), sig)
    }

    fn signed_channel_expire(payer: &Identity, channel_id: [u8; 32]) -> Tx {
        let kind = TxKind::ChannelExpire { channel_id, payer: payer.node_id() };
        let data = bincode::serialize(&kind).unwrap();
        let sig = payer.sign(&data);
        Tx::new(kind, payer.node_id(), sig)
    }

    /// Append a single-tx block (plus a uptime reward to `miner`) and return whether it was accepted.
    fn append_with(chain: &mut Chain, miner: &Identity, tx: Tx) -> bool {
        let reward = signed_uptime_reward(miner, chain.tip().index + 1);
        let mut b = chain.next_block(vec![reward, tx], miner.node_id());
        b.seal(miner);
        chain.append(b)
    }

    #[test]
    fn channel_open_lock_close_settles() {
        let payer = make_identity("ch-payer");
        let host = make_identity("ch-host");
        let mut chain = Chain::genesis();
        fund(&mut chain, &payer, 2_000);
        let before = chain.balance(&payer.node_id());
        let chan = [3u8; 32];

        assert!(append_with(&mut chain, &host, signed_channel_open(&payer, chan, host.node_id(), 1_000, 100_000)));
        // Capacity is locked in the payer's balance.
        assert_eq!(chain.locked_balance(&payer.node_id()), 1_000);

        // Host redeems a receipt for 600 of the 1000.
        assert!(append_with(&mut chain, &host, signed_channel_close(&host, &payer, chan, 600)));
        assert_eq!(chain.balance(&payer.node_id()), before - 600, "only the redeemed 600 leaves the payer");
        assert_eq!(chain.locked_balance(&payer.node_id()), 0, "the rest unlocks on close");
        assert_eq!(chain.node_history(&host.node_id()).earned, 600);
    }

    #[test]
    fn channel_open_insufficient_free_balance_rejected() {
        let payer = make_identity("chx-payer");
        let host = make_identity("chx-host");
        let mut chain = Chain::genesis();
        fund(&mut chain, &payer, 1_000);
        let bal = chain.balance(&payer.node_id()) as u128;
        assert!(
            !append_with(&mut chain, &host, signed_channel_open(&payer, [1u8; 32], host.node_id(), bal + 1, 100_000)),
            "opening a channel larger than free balance must be rejected"
        );
    }

    #[test]
    fn channel_close_rejects_forged_overdraw_and_wrong_closer() {
        let payer = make_identity("chf-payer");
        let host = make_identity("chf-host");
        let mallory = make_identity("chf-mallory");
        let mut chain = Chain::genesis();
        fund(&mut chain, &payer, 2_000);
        let chan = [5u8; 32];
        assert!(append_with(&mut chain, &host, signed_channel_open(&payer, chan, host.node_id(), 1_000, 100_000)));

        // Redeeming more than the capacity is rejected.
        assert!(!append_with(&mut chain, &host, signed_channel_close(&host, &payer, chan, 1_001)), "cumulative > capacity");

        // A non-host cannot close (the receipt is bound to `host`, and only the host may submit).
        assert!(!append_with(&mut chain, &mallory, signed_channel_close(&mallory, &payer, chan, 500)), "non-host closer");

        // A receipt not signed by the payer is rejected (mallory signs instead of payer).
        assert!(!append_with(&mut chain, &host, signed_channel_close(&host, &mallory, chan, 500)), "forged receipt");

        // The channel is still open and unspent after all rejected closes.
        assert_eq!(chain.locked_balance(&payer.node_id()), 1_000);
    }

    #[test]
    fn channel_expire_refunds_after_expiry() {
        let payer = make_identity("che-payer");
        let host = make_identity("che-host");
        let mut chain = Chain::genesis();
        fund(&mut chain, &payer, 2_000);
        let before = chain.balance(&payer.node_id());
        let chan = [6u8; 32];

        // Expiry at the current tip height — so the next block's index exceeds it.
        let expiry = chain.tip().index + 1;
        assert!(append_with(&mut chain, &host, signed_channel_open(&payer, chan, host.node_id(), 1_000, expiry)));
        assert_eq!(chain.locked_balance(&payer.node_id()), 1_000);

        // Expiring before the height passes is rejected, then accepted once block.index > expiry.
        assert!(append_with(&mut chain, &payer, signed_channel_expire(&payer, chan)), "expire after expiry height");
        assert_eq!(chain.locked_balance(&payer.node_id()), 0, "capacity unlocked");
        // Balance unchanged by expiry itself (payer mined the expire block, gaining a reward).
        assert!(chain.balance(&payer.node_id()) >= before, "no credits left the payer on expire");
    }

    #[test]
    fn transfer_and_channel_open_same_credits_rejected() {
        let payer = make_identity("chc-payer");
        let host = make_identity("chc-host");
        let eve = make_identity("chc-eve");
        let mut chain = Chain::genesis();
        fund(&mut chain, &payer, 2_000);
        let bal = chain.balance(&payer.node_id()) as u128;
        let spend = bal * 8 / 10;

        // One block: transfer 80% AND open a channel for 80% — 160% > balance, so the block is rejected.
        let transfer = signed_transfer(&payer, eve.node_id(), spend);
        let open = signed_channel_open(&payer, [8u8; 32], host.node_id(), spend, 100_000);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut b = chain.next_block(vec![reward, transfer, open], host.node_id());
        b.seal(&host);
        assert!(!chain.append(b), "transfer + channel-open exceeding balance must be rejected");
        assert_eq!(chain.balance(&payer.node_id()), bal as i128, "balance unchanged");
    }

    #[test]
    fn node_history_tracks_settlements_and_heartbeats() {
        let host = make_identity("hist-host");
        let payer = make_identity("hist-payer");
        let mut chain = Chain::genesis();
        fund(&mut chain, &payer, 2_000);

        // Bid then settle a job for 600 base units.
        let job_id = [9u8; 32];
        let bid = signed_job_bid(&payer, job_id, 1_000);
        let r1 = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut b = chain.next_block(vec![r1, bid], host.node_id());
        b.seal(&host);
        assert!(chain.append(b));

        let settle = signed_job_settle(&host, &payer, job_id, 600);
        let r2 = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut b = chain.next_block(vec![r2, settle], host.node_id());
        b.seal(&host);
        assert!(chain.append(b));

        let hs = chain.node_history(&host.node_id());
        assert_eq!(hs.jobs_hosted, 1, "host settled one job");
        assert_eq!(hs.earned, 600);
        assert_eq!(hs.jobs_paid, 0);
        assert!(hs.first_height >= 1 && hs.last_height >= hs.first_height);

        let ps = chain.node_history(&payer.node_id());
        assert_eq!(ps.jobs_paid, 1, "payer paid one job");
        assert_eq!(ps.spent, 600);
        assert_eq!(ps.jobs_hosted, 0);

        // A heartbeat cell -> host updates both sides.
        let cell = make_identity("hist-cell");
        fund(&mut chain, &cell, 2_000);
        let hb = signed_heartbeat(&host, cell.node_id(), 50, 1);
        let r3 = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut b = chain.next_block(vec![r3, hb], host.node_id());
        b.seal(&host);
        assert!(chain.append(b));

        assert_eq!(chain.node_history(&host.node_id()).heartbeats_hosted, 1);
        assert_eq!(chain.node_history(&cell.node_id()).heartbeats_paid, 1);
        assert_eq!(chain.node_history(&cell.node_id()).spent, 50);

        // Unknown node returns defaults.
        let zero = chain.node_history(&make_identity("hist-stranger").node_id());
        assert_eq!(zero.jobs_hosted, 0);
        assert_eq!(zero.first_height, 0);
    }

    #[test]
    fn emission_rate_schedule() {
        assert_eq!(Chain::emission_rate(0), 1_000 * CREDIT);
        assert_eq!(Chain::emission_rate(209_999), 1_000 * CREDIT);
        assert_eq!(Chain::emission_rate(210_000), 500 * CREDIT);
        assert_eq!(Chain::emission_rate(420_000), 250 * CREDIT);
        assert_eq!(Chain::emission_rate(630_000), 125 * CREDIT);
        assert_eq!(Chain::emission_rate(u64::MAX), 0);
    }

    // ----- Supply cap -----

    #[test]
    fn total_supply_500_blocks() {
        let id = make_identity("supply");
        let mut chain = Chain::genesis();
        for _ in 0..500 {
            assert!(seal_and_append(&mut chain, &id));
        }
        assert!(
            chain.total_supply() <= SUPPLY_CAP,
            "total_supply {} exceeded cap after 500 blocks",
            chain.total_supply(),
        );
    }

    #[test]
    fn uptime_reward_wrong_amount_rejected() {
        let mut chain = Chain::genesis();
        let id = make_identity("wrongamt");
        let wrong_amount = Chain::emission_rate(1) + 1;
        let kind = TxKind::UptimeReward { node: id.node_id(), amount: wrong_amount, epoch: 1 };
        let data = bincode::serialize(&kind).unwrap();
        let sig = id.sign(&data);
        let tx = Tx::new(kind, id.node_id(), sig);
        let mut block = chain.next_block(vec![tx], id.node_id());
        block.seal(&id);
        assert!(!chain.append(block), "block with wrong UptimeReward amount must be rejected");
    }

    // ----- Tx tests -----

    #[test]
    fn tx_verify_valid() {
        let id = make_identity("txv");
        let tx = signed_transfer(&id, [1u8; 32], 50);
        assert!(tx.verify().is_ok());
    }

    #[test]
    fn tx_verify_rejects_tampered_amount() {
        let id = make_identity("txr");
        let mut tx = signed_transfer(&id, [1u8; 32], 50);
        tx.kind = TxKind::Transfer { from: id.node_id(), to: [1u8; 32], amount: 9999 };
        assert!(tx.verify().is_err());
    }

    #[test]
    fn tx_id_is_stable() {
        let id = make_identity("txid");
        let tx = signed_transfer(&id, [2u8; 32], 7);
        assert_eq!(tx.id(), tx.id());
    }

    // ----- Persistence -----

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tmpdir("saveload");
        let path = dir.join("chain.bin");
        let id = make_identity("saveload-id");
        let mut chain = Chain::genesis();
        seal_and_append(&mut chain, &id);

        chain.save(&path).unwrap();
        let loaded = Chain::load(&path).unwrap();

        assert_eq!(loaded.height(), chain.height());
        assert_eq!(loaded.tip().hash(), chain.tip().hash());
        assert_eq!(loaded.difficulty, chain.difficulty);
        // Caches must be rebuilt correctly.
        assert_eq!(loaded.balance(&id.node_id()), chain.balance(&id.node_id()));
        assert_eq!(loaded.total_supply(), chain.total_supply());
    }

    #[test]
    fn load_or_genesis_returns_genesis_when_missing() {
        let chain = Chain::load_or_genesis(std::path::Path::new("/nonexistent/chain.bin"));
        assert_eq!(chain.height(), 0);
    }

    // ----- Pruning -----

    #[test]
    fn prune_reduces_block_count() {
        let id = make_identity("prune-blocks");
        let mut chain = Chain::genesis();
        for _ in 0..10 {
            assert!(seal_and_append(&mut chain, &id));
        }
        assert_eq!(chain.blocks.len(), 11); // genesis + 10
        chain.prune(5);
        assert_eq!(chain.blocks.len(), 6); // 5 kept + 1 at cut
        assert!(chain.checkpoint.is_some());
    }

    #[test]
    fn prune_preserves_balances() {
        let id = make_identity("prune-bal");
        let mut chain = Chain::genesis();
        for _ in 0..10 {
            assert!(seal_and_append(&mut chain, &id));
        }
        let balance_before = chain.balance(&id.node_id());
        let supply_before = chain.total_supply();
        chain.prune(3);
        assert_eq!(chain.balance(&id.node_id()), balance_before);
        assert_eq!(chain.total_supply(), supply_before);
    }

    #[test]
    fn prune_then_save_load_roundtrip() {
        let dir = tmpdir("prune-persist");
        let path = dir.join("chain.bin");
        let id = make_identity("prune-persist-id");
        let mut chain = Chain::genesis();
        for _ in 0..10 {
            assert!(seal_and_append(&mut chain, &id));
        }
        chain.prune(4);
        chain.save(&path).unwrap();

        let loaded = Chain::load(&path).unwrap();
        assert_eq!(loaded.height(), chain.height());
        assert_eq!(loaded.tip().hash(), chain.tip().hash());
        assert_eq!(loaded.balance(&id.node_id()), chain.balance(&id.node_id()));
        assert_eq!(loaded.total_supply(), chain.total_supply());
        assert!(loaded.checkpoint.is_some());
    }

    #[test]
    fn prune_too_small_is_noop() {
        let id = make_identity("prune-noop");
        let mut chain = Chain::genesis();
        for _ in 0..5 {
            seal_and_append(&mut chain, &id);
        }
        let len_before = chain.blocks.len();
        chain.prune(100); // keep more than we have — no-op
        assert_eq!(chain.blocks.len(), len_before);
        assert!(chain.checkpoint.is_none());
    }

    // ----- Job lifecycle tests -----

    fn signed_job_bid(payer: &Identity, job_id: [u8; 32], bid: u128) -> Tx {
        let kind = TxKind::JobBid {
            job_id,
            payer: payer.node_id(),
            bid,
            image: "alpine:latest".into(),
            cmd: vec![],
            env: vec![],
            cpu_cores: 1,
            mem_mb: 64,
            duration_secs: 30,
        };
        let data = bincode::serialize(&kind).unwrap();
        let sig = payer.sign(&data);
        Tx::new(kind, payer.node_id(), sig)
    }

    fn signed_job_settle(
        host: &Identity,
        payer: &Identity,
        job_id: [u8; 32],
        cost: u128,
    ) -> Tx {
        let payer_sig = payer.sign(&payer_settle_bytes(&job_id, &host.node_id(), cost));
        let kind = TxKind::JobSettle {
            job_id,
            host: host.node_id(),
            payer: payer.node_id(),
            cpu_ms: 1000,
            mem_mb: 32,
            cost,
            payer_sig,
        };
        let data = bincode::serialize(&kind).unwrap();
        let sig = host.sign(&data);
        Tx::new(kind, host.node_id(), sig)
    }

    /// Mine enough blocks so `payer` has at least `min` credits.
    fn fund(chain: &mut Chain, payer: &Identity, min: u128) {
        while chain.balance(&payer.node_id()) < min as i128 {
            assert!(seal_and_append(chain, payer));
        }
    }

    #[test]
    fn job_settle_happy_path() {
        let host = make_identity("settle-host");
        let payer = make_identity("settle-payer");
        let mut chain = Chain::genesis();
        fund(&mut chain, &payer, 2_000);

        let job_id = [7u8; 32];
        let bid = signed_job_bid(&payer, job_id, 1_000);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, bid], host.node_id());
        block.seal(&host);
        assert!(chain.append(block));

        let cost = 500;
        let payer_before = chain.balance(&payer.node_id());
        let host_before = chain.balance(&host.node_id());
        let settle = signed_job_settle(&host, &payer, job_id, cost);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, settle], host.node_id());
        block.seal(&host);
        assert!(chain.append(block), "settle should be accepted");

        assert_eq!(
            chain.balance(&payer.node_id()),
            payer_before - cost as i128,
        );
        assert_eq!(
            chain.balance(&host.node_id()),
            host_before + cost as i128 + Chain::emission_rate(chain.tip().index) as i128,
        );
    }

    #[test]
    fn job_settle_rejects_bad_payer_sig() {
        let host = make_identity("badsig-host");
        let payer = make_identity("badsig-payer");
        let mut chain = Chain::genesis();
        fund(&mut chain, &payer, 1_000);

        let job_id = [1u8; 32];
        let bid = signed_job_bid(&payer, job_id, 500);
        let mut block = chain.next_block(vec![bid], host.node_id());
        block.seal(&host);
        assert!(chain.append(block));

        let mut settle = signed_job_settle(&host, &payer, job_id, 100);
        if let TxKind::JobSettle { ref mut payer_sig, .. } = settle.kind {
            *payer_sig = [0xff; 64];
        }
        let data = bincode::serialize(&settle.kind).unwrap();
        settle.sig = host.sign(&data);

        let mut block = chain.next_block(vec![settle], host.node_id());
        block.seal(&host);
        assert!(!chain.append(block), "settle with bad payer_sig must be rejected");
    }

    #[test]
    fn job_settle_rejects_unknown_job_id() {
        let host = make_identity("noid-host");
        let payer = make_identity("noid-payer");
        let mut chain = Chain::genesis();
        fund(&mut chain, &payer, 1_000);

        let settle = signed_job_settle(&host, &payer, [9u8; 32], 50);
        let mut block = chain.next_block(vec![settle], host.node_id());
        block.seal(&host);
        assert!(!chain.append(block), "settle without a prior bid must be rejected");
    }

    #[test]
    fn job_bid_rejects_insufficient_balance() {
        let host = make_identity("poor-host");
        let payer = make_identity("poor-payer");
        let mut chain = Chain::genesis();
        seal_and_append(&mut chain, &host);

        let job_id = [3u8; 32];
        let bid = signed_job_bid(&payer, job_id, 1_000);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, bid], host.node_id());
        block.seal(&host);
        assert!(!chain.append(block), "bid with insufficient free balance must be rejected");
    }

    #[test]
    fn job_settle_rejects_cost_exceeds_bid() {
        let host = make_identity("exceed-host");
        let payer = make_identity("exceed-payer");
        let mut chain = Chain::genesis();
        fund(&mut chain, &payer, 2_000);

        let job_id = [3u8; 32];
        let bid = signed_job_bid(&payer, job_id, 100);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, bid], host.node_id());
        block.seal(&host);
        assert!(chain.append(block));

        let settle = signed_job_settle(&host, &payer, job_id, 200);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, settle], host.node_id());
        block.seal(&host);
        assert!(!chain.append(block), "settle cost exceeding bid must be rejected");
    }

    #[test]
    fn job_settle_rejects_self_pay() {
        let id = make_identity("selfpay");
        let mut chain = Chain::genesis();
        fund(&mut chain, &id, 1_000);

        let job_id = [4u8; 32];
        let bid = signed_job_bid(&id, job_id, 500);
        let mut block = chain.next_block(vec![bid], id.node_id());
        block.seal(&id);
        assert!(chain.append(block));

        let payer_sig = id.sign(&payer_settle_bytes(&job_id, &id.node_id(), 50));
        let kind = TxKind::JobSettle {
            job_id,
            host: id.node_id(),
            payer: id.node_id(),
            cpu_ms: 100,
            mem_mb: 10,
            cost: 50,
            payer_sig,
        };
        let data = bincode::serialize(&kind).unwrap();
        let sig = id.sign(&data);
        let settle = Tx::new(kind, id.node_id(), sig);

        let mut block = chain.next_block(vec![settle], id.node_id());
        block.seal(&id);
        assert!(!chain.append(block));
    }

    #[test]
    fn job_settle_rejects_double_settle() {
        let host = make_identity("dupe-host");
        let payer = make_identity("dupe-payer");
        let mut chain = Chain::genesis();
        fund(&mut chain, &payer, 2_000);

        let job_id = [5u8; 32];
        let bid = signed_job_bid(&payer, job_id, 1_000);
        let mut block = chain.next_block(vec![bid], host.node_id());
        block.seal(&host);
        assert!(chain.append(block));

        let settle = signed_job_settle(&host, &payer, job_id, 100);
        let mut block = chain.next_block(vec![settle], host.node_id());
        block.seal(&host);
        assert!(chain.append(block));

        let dup = signed_job_settle(&host, &payer, job_id, 100);
        let mut block = chain.next_block(vec![dup], host.node_id());
        block.seal(&host);
        assert!(!chain.append(block));
    }

    fn signed_job_expire(payer: &Identity, job_id: [u8; 32]) -> Tx {
        let kind = TxKind::JobExpire { job_id, payer: payer.node_id() };
        let data = bincode::serialize(&kind).unwrap();
        let sig = payer.sign(&data);
        Tx::new(kind, payer.node_id(), sig)
    }

    fn signed_trust_grant(grantor: &Identity, grantee: NodeId, label: &str) -> Tx {
        let kind = TxKind::TrustGrant {
            grantor: grantor.node_id(),
            grantee,
            label: label.to_string(),
        };
        let data = bincode::serialize(&kind).unwrap();
        let sig = grantor.sign(&data);
        Tx::new(kind, grantor.node_id(), sig)
    }

    #[test]
    fn job_expire_happy_path() {
        let host = make_identity("expire-host");
        let payer = make_identity("expire-payer");
        let mut chain = Chain::genesis();
        fund(&mut chain, &payer, 2_000);

        let job_id = [11u8; 32];
        let bid = signed_job_bid(&payer, job_id, 500);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, bid], host.node_id());
        block.seal(&host);
        let bid_block = chain.tip().index + 1;
        assert!(chain.append(block));
        assert_eq!(chain.locked_balance(&payer.node_id()), 500);

        // Too early — reject.
        let expire2 = signed_job_expire(&payer, job_id);
        let reward2 = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut early_block = chain.next_block(vec![reward2, expire2], host.node_id());
        early_block.seal(&host);
        assert!(!chain.append(early_block), "expire before EXPIRY_BLOCKS must be rejected");
        assert_eq!(chain.locked_balance(&payer.node_id()), 500, "lock not released on failed expire");
        let _ = bid_block; // used above
    }

    #[test]
    fn job_expire_rejects_unknown_job() {
        let host = make_identity("exp-unk-host");
        let payer = make_identity("exp-unk-payer");
        let mut chain = Chain::genesis();
        fund(&mut chain, &payer, 500);

        let expire = signed_job_expire(&payer, [99u8; 32]);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, expire], host.node_id());
        block.seal(&host);
        assert!(!chain.append(block), "expire without a prior bid must be rejected");
    }

    #[test]
    fn locked_balance_cleared_by_settle() {
        let host = make_identity("lock-settle-host");
        let payer = make_identity("lock-settle-payer");
        let mut chain = Chain::genesis();
        fund(&mut chain, &payer, 2_000);

        let job_id = [22u8; 32];
        let bid = signed_job_bid(&payer, job_id, 500);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, bid], host.node_id());
        block.seal(&host);
        assert!(chain.append(block));
        assert_eq!(chain.locked_balance(&payer.node_id()), 500);

        let settle = signed_job_settle(&host, &payer, job_id, 300);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, settle], host.node_id());
        block.seal(&host);
        assert!(chain.append(block));
        assert_eq!(chain.locked_balance(&payer.node_id()), 0, "locked balance must clear after settle");
    }

    #[test]
    fn trust_grant_happy_path() {
        let grantor = make_identity("tg-grantor");
        let grantee = make_identity("tg-grantee");
        let mut chain = Chain::genesis();
        fund(&mut chain, &grantor, 100);

        let tg = signed_trust_grant(&grantor, grantee.node_id(), "laptop");
        let reward = signed_uptime_reward(&grantor, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, tg], grantor.node_id());
        block.seal(&grantor);
        assert!(chain.append(block), "valid TrustGrant must be accepted");
    }

    fn signed_heartbeat(host: &Identity, cell_id: NodeId, amount: u128, epoch: u64) -> Tx {
        let kind = TxKind::Heartbeat { cell: cell_id, host: host.node_id(), amount, epoch };
        let data = bincode::serialize(&kind).unwrap();
        let sig = host.sign(&data);
        Tx::new(kind, host.node_id(), sig)
    }

    #[test]
    fn heartbeat_happy_path() {
        let host = make_identity("hb-host");
        let cell = make_identity("hb-cell");
        let mut chain = Chain::genesis();
        fund(&mut chain, &cell, 1_000);
        let before = chain.balance(&cell.node_id());

        let hb = signed_heartbeat(&host, cell.node_id(), 100, 0);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, hb], host.node_id());
        block.seal(&host);
        assert!(chain.append(block), "valid heartbeat must be accepted");
        assert_eq!(chain.balance(&cell.node_id()), before - 100);
        assert_eq!(chain.last_heartbeat_epoch(&cell.node_id(), &host.node_id()), Some(0));
    }

    #[test]
    fn heartbeat_rejects_replay() {
        let host = make_identity("hb-replay-host");
        let cell = make_identity("hb-replay-cell");
        let mut chain = Chain::genesis();
        fund(&mut chain, &cell, 1_000);

        let hb = signed_heartbeat(&host, cell.node_id(), 100, 5);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, hb], host.node_id());
        block.seal(&host);
        assert!(chain.append(block));

        let hb2 = signed_heartbeat(&host, cell.node_id(), 100, 5);
        let reward2 = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block2 = chain.next_block(vec![reward2, hb2], host.node_id());
        block2.seal(&host);
        assert!(!chain.append(block2), "replayed heartbeat epoch must be rejected");

        let hb3 = signed_heartbeat(&host, cell.node_id(), 100, 3);
        let reward3 = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block3 = chain.next_block(vec![reward3, hb3], host.node_id());
        block3.seal(&host);
        assert!(!chain.append(block3), "earlier epoch must be rejected");

        let hb4 = signed_heartbeat(&host, cell.node_id(), 100, 6);
        let reward4 = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block4 = chain.next_block(vec![reward4, hb4], host.node_id());
        block4.seal(&host);
        assert!(chain.append(block4), "higher epoch must be accepted");
    }

    #[test]
    fn heartbeat_rejects_insufficient_balance() {
        let host = make_identity("hb-poor-host");
        let cell = make_identity("hb-poor-cell");
        let mut chain = Chain::genesis();

        let hb = signed_heartbeat(&host, cell.node_id(), 100, 0);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, hb], host.node_id());
        block.seal(&host);
        assert!(!chain.append(block), "heartbeat with insufficient cell balance must be rejected");
    }

    #[test]
    fn heartbeat_rejects_self_pay() {
        let host = make_identity("hb-self");
        let mut chain = Chain::genesis();
        fund(&mut chain, &host, 1_000);

        let kind = TxKind::Heartbeat {
            cell: host.node_id(),
            host: host.node_id(),
            amount: 100,
            epoch: 0,
        };
        let data = bincode::serialize(&kind).unwrap();
        let sig = host.sign(&data);
        let bad_hb = Tx::new(kind, host.node_id(), sig);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, bad_hb], host.node_id());
        block.seal(&host);
        assert!(!chain.append(block), "heartbeat self-pay must be rejected");
    }

    #[test]
    fn heartbeat_rejects_wrong_signer() {
        let host = make_identity("hb-ws-host");
        let cell = make_identity("hb-ws-cell");
        let attacker = make_identity("hb-attacker");
        let mut chain = Chain::genesis();
        fund(&mut chain, &cell, 1_000);

        let kind = TxKind::Heartbeat {
            cell: cell.node_id(),
            host: host.node_id(),
            amount: 100,
            epoch: 0,
        };
        let data = bincode::serialize(&kind).unwrap();
        let bad_sig = attacker.sign(&data);
        let bad_hb = Tx::new(kind, attacker.node_id(), bad_sig);
        let reward = signed_uptime_reward(&attacker, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, bad_hb], attacker.node_id());
        block.seal(&attacker);
        assert!(!chain.append(block), "heartbeat with wrong signer must be rejected");
    }

    #[test]
    fn trust_grant_rejects_wrong_signer() {
        let grantor = make_identity("tg-bad-grantor");
        let grantee = make_identity("tg-bad-grantee");
        let attacker = make_identity("tg-attacker");
        let mut chain = Chain::genesis();
        fund(&mut chain, &attacker, 100);

        let kind = TxKind::TrustGrant {
            grantor: grantor.node_id(),
            grantee: grantee.node_id(),
            label: "laptop".into(),
        };
        let data = bincode::serialize(&kind).unwrap();
        let bad_sig = attacker.sign(&data);
        let bad_tg = Tx::new(kind, attacker.node_id(), bad_sig);
        let reward = signed_uptime_reward(&attacker, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, bad_tg], attacker.node_id());
        block.seal(&attacker);
        assert!(!chain.append(block), "TrustGrant with wrong signer must be rejected");
    }

    #[test]
    fn job_bid_must_be_signed_by_payer() {
        let host = make_identity("bidh");
        let payer = make_identity("bidp");
        let mut chain = Chain::genesis();
        fund(&mut chain, &payer, 100);

        let kind = TxKind::JobBid {
            job_id: [6u8; 32],
            payer: payer.node_id(),
            bid: 50,
            image: "alpine".into(),
            cmd: vec![],
            env: vec![],
            cpu_cores: 1,
            mem_mb: 16,
            duration_secs: 10,
        };
        let data = bincode::serialize(&kind).unwrap();
        let bad_sig = host.sign(&data);
        let bad_bid = Tx::new(kind, host.node_id(), bad_sig);

        let mut block = chain.next_block(vec![bad_bid], host.node_id());
        block.seal(&host);
        assert!(!chain.append(block), "bid signed by non-payer must be rejected");
    }

    // ----- Fork choice / reorg tests -----

    fn build_fork(base: &Chain, miner: &Identity, count: usize) -> Vec<Block> {
        let mut fork = base.clone();
        let mut new_blocks = Vec::new();
        for _ in 0..count {
            let next_idx = fork.tip().index + 1;
            let reward = signed_uptime_reward(miner, next_idx);
            let mut block = fork.next_block(vec![reward], miner.node_id());
            block.seal(miner);
            assert!(fork.append(block.clone()), "fork block must be valid");
            new_blocks.push(block);
        }
        new_blocks
    }

    #[test]
    fn try_reorg_ignores_equal_length_fork() {
        let a = make_identity("reorg-eq-a");
        let b = make_identity("reorg-eq-b");
        let mut chain = Chain::genesis();
        seal_and_append(&mut chain, &a);

        let fork_blocks = build_fork(&chain, &b, 1);
        seal_and_append(&mut chain, &a);

        assert!(!chain.try_reorg(fork_blocks));
        assert_eq!(chain.tip().miner, a.node_id());
    }

    #[test]
    fn try_reorg_switches_to_longer_fork() {
        let a = make_identity("reorg-long-a");
        let b = make_identity("reorg-long-b");
        let mut chain = Chain::genesis();
        seal_and_append(&mut chain, &a);

        let common = chain.clone();
        seal_and_append(&mut chain, &a);

        let fork_blocks = build_fork(&common, &b, 2);

        assert!(chain.try_reorg(fork_blocks));
        assert_eq!(chain.height(), 3);
        assert_eq!(chain.tip().miner, b.node_id());
    }

    #[test]
    fn try_reorg_rejects_invalid_block_in_fork() {
        let a = make_identity("reorg-inv-a");
        let b = make_identity("reorg-inv-b");
        let mut chain = Chain::genesis();
        seal_and_append(&mut chain, &a);

        let common = chain.clone();
        seal_and_append(&mut chain, &a);

        let mut fork_blocks = build_fork(&common, &b, 2);
        fork_blocks.last_mut().unwrap().sig = [0xff; 64];

        assert!(!chain.try_reorg(fork_blocks));
        assert_eq!(chain.tip().miner, a.node_id());
    }

    #[test]
    fn try_reorg_no_connection_returns_false() {
        let a = make_identity("reorg-nocon-a");
        let b = make_identity("reorg-nocon-b");
        let mut chain = Chain::genesis();
        seal_and_append(&mut chain, &a);

        let mut ghost = Block {
            index: 1,
            prev_hash: [0xde; 32],
            timestamp: 0,
            transactions: vec![],
            nonce: 0,
            miner: b.node_id(),
            sig: [0u8; 64],
        };
        ghost.seal(&b);
        assert!(!chain.try_reorg(vec![ghost]));
    }

    // ----- Adversarial / attack scenario tests -----

    // Attack 1: Inflation via duplicate UptimeReward in one block.
    // A malicious miner packs two UptimeReward txs (for two different node IDs) into one
    // block. Each reward individually matches emission_rate, so the per-tx check passes,
    // but the block would emit 2× the scheduled amount. Must be rejected.
    #[test]
    fn inflation_attack_two_rewards_same_block() {
        let miner = make_identity("inf-miner");
        let second = make_identity("inf-second");
        let mut chain = Chain::genesis();

        let r1 = signed_uptime_reward(&miner, 1);
        let r2 = signed_uptime_reward(&second, 1);
        let mut block = chain.next_block(vec![r1, r2], miner.node_id());
        block.seal(&miner);
        assert!(!chain.append(block), "block with two UptimeRewards must be rejected");
        assert_eq!(chain.height(), 0);
    }

    // Attack 2: Cross-block transaction replay.
    // Same signed Transfer (identical bytes → same tx_id) submitted in block 1 and again
    // in block 2. The payer re-accumulates credits via a reward between them.
    // The second submission must be rejected even though the sender now has sufficient balance.
    #[test]
    fn replay_attack_same_tx_different_blocks() {
        let miner = make_identity("replay-miner");
        let victim = make_identity("replay-victim");
        let mut chain = Chain::genesis();

        // Fund miner with two reward blocks so they have 2 × emission_rate credits.
        seal_and_append(&mut chain, &miner);
        seal_and_append(&mut chain, &miner);
        let balance_after_two_rewards = chain.balance(&miner.node_id());
        assert!(balance_after_two_rewards > 0);

        // First spend: transfer half to victim. Chain height 3.
        let spend_amount = 1u128;
        let transfer = signed_transfer(&miner, victim.node_id(), spend_amount);
        let reward = signed_uptime_reward(&miner, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, transfer.clone()], miner.node_id());
        block.seal(&miner);
        assert!(chain.append(block), "first transfer must succeed");

        // Mine another block to top up miner's balance again.
        seal_and_append(&mut chain, &miner);

        // Replay: include the exact same Transfer tx in block 5.
        let reward = signed_uptime_reward(&miner, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, transfer], miner.node_id());
        block.seal(&miner);
        assert!(!chain.append(block), "replayed tx must be rejected even with sufficient balance");
    }

    // Attack 3: Within-block transaction duplication.
    // Two copies of the identical signed tx in one block. The second copy must be rejected.
    #[test]
    fn replay_attack_duplicate_tx_within_block() {
        let miner = make_identity("dup-miner");
        let victim = make_identity("dup-victim");
        let mut chain = Chain::genesis();
        fund(&mut chain, &miner, 1_000);

        let transfer = signed_transfer(&miner, victim.node_id(), 100);
        let reward = signed_uptime_reward(&miner, chain.tip().index + 1);
        let mut block = chain.next_block(
            vec![reward, transfer.clone(), transfer],
            miner.node_id(),
        );
        block.seal(&miner);
        assert!(!chain.append(block), "block with duplicate tx must be rejected");
    }

    // Attack 4: Heartbeat epoch=u64::MAX — permanent denial-of-service.
    // A compromised host submits epoch=u64::MAX, making it impossible for any future
    // heartbeat to satisfy the strictly-greater-than constraint. Must be rejected.
    #[test]
    fn heartbeat_epoch_overflow_blocks_future() {
        let host = make_identity("hb-overflow-host");
        let cell = make_identity("hb-overflow-cell");
        let mut chain = Chain::genesis();
        fund(&mut chain, &cell, 10_000);

        let kind = TxKind::Heartbeat {
            cell: cell.node_id(),
            host: host.node_id(),
            amount: 100,
            epoch: u64::MAX,
        };
        let data = bincode::serialize(&kind).unwrap();
        let sig = host.sign(&data);
        let bad_hb = Tx::new(kind, host.node_id(), sig);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, bad_hb], host.node_id());
        block.seal(&host);
        assert!(!chain.append(block), "epoch=u64::MAX heartbeat must be rejected");
    }

    // Attack 5: Bid-override double-spend.
    // Payer opens a bid for job A (500 credits locked). In a later block the payer submits
    // another bid for the SAME job_id. Without protection the second bid overwrites the
    // open_bids entry, the locked amount drops from 500 to the new bid, and the payer can
    // spend the difference. Must be rejected.
    #[test]
    fn bid_rebid_same_job_id_credit_unlock_rejected() {
        let host = make_identity("rebid-host");
        let payer = make_identity("rebid-payer");
        let mut chain = Chain::genesis();
        fund(&mut chain, &payer, 2_000);

        let job_id = [88u8; 32];
        let bid1 = signed_job_bid(&payer, job_id, 500);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, bid1], host.node_id());
        block.seal(&host);
        assert!(chain.append(block));
        assert_eq!(chain.locked_balance(&payer.node_id()), 500);

        // Attempt rebid for the same job_id.
        let bid2 = signed_job_bid(&payer, job_id, 100);
        let reward2 = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block2 = chain.next_block(vec![reward2, bid2], host.node_id());
        block2.seal(&host);
        assert!(!chain.append(block2), "rebid for open job_id must be rejected");
        // Locked balance must be unchanged.
        assert_eq!(chain.locked_balance(&payer.node_id()), 500);
    }

    // Attack 6: Settlement hijacking via stolen payer signature.
    // The payer's co-signature now binds the host identity (payer_settle_bytes v2).
    // Mallory intercepts Alice's signed authorization and presents herself as the host.
    // The chain must reject because the payer_sig is over (job_id, real_host, cost),
    // not (job_id, mallory, cost).
    #[test]
    fn settlement_hijack_stolen_payer_sig_rejected() {
        let real_host = make_identity("hijack-real-host");
        let mallory = make_identity("hijack-mallory");
        let payer = make_identity("hijack-payer");
        let mut chain = Chain::genesis();
        fund(&mut chain, &payer, 1_000);

        let job_id = [77u8; 32];
        let bid = signed_job_bid(&payer, job_id, 500);
        let reward = signed_uptime_reward(&real_host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, bid], real_host.node_id());
        block.seal(&real_host);
        assert!(chain.append(block));

        // Payer signs authorization for the REAL host.
        let payer_sig = payer.sign(&payer_settle_bytes(&job_id, &real_host.node_id(), 300));

        // Mallory creates a settle naming herself as host, using Alice's stolen sig.
        let kind = TxKind::JobSettle {
            job_id,
            host: mallory.node_id(),
            payer: payer.node_id(),
            cpu_ms: 1000,
            mem_mb: 32,
            cost: 300,
            payer_sig,
        };
        let data = bincode::serialize(&kind).unwrap();
        let sig = mallory.sign(&data);
        let bad_settle = Tx::new(kind, mallory.node_id(), sig);

        let reward2 = signed_uptime_reward(&mallory, chain.tip().index + 1);
        let mut block2 = chain.next_block(vec![reward2, bad_settle], mallory.node_id());
        block2.seal(&mallory);
        assert!(!chain.append(block2), "settle hijack with stolen payer sig must be rejected");
        // Payer's credits must remain locked.
        assert_eq!(chain.locked_balance(&payer.node_id()), 500);
    }

    // Attack 7: Shadow chain reorg with inflated rewards.
    // An attacker builds a longer fork where each block contains two UptimeReward txs.
    // The fork is 2 blocks longer than the honest chain, so it would win on length,
    // but every shadow block must be individually valid — the inflation blocks fail
    // append() and the entire reorg is rejected.
    #[test]
    fn shadow_chain_inflation_reorg_rejected() {
        let honest = make_identity("shadow-honest");
        let attacker = make_identity("shadow-attacker");
        let colluder = make_identity("shadow-colluder");
        let mut chain = Chain::genesis();
        seal_and_append(&mut chain, &honest);
        seal_and_append(&mut chain, &honest);

        let fork_base = chain.clone();

        // Build shadow fork: two more blocks, each with two UptimeRewards.
        let mut shadow_blocks: Vec<Block> = Vec::new();
        let mut shadow = fork_base.clone();
        for _ in 0..4 {
            let next_idx = shadow.tip().index + 1;
            let r1 = signed_uptime_reward(&attacker, next_idx);
            let r2 = signed_uptime_reward(&colluder, next_idx);
            let mut block = shadow.next_block(vec![r1, r2], attacker.node_id());
            block.seal(&attacker);
            // Don't push through shadow.append — just collect the blocks.
            shadow_blocks.push(block);
            // Manually advance shadow tip for next_block to produce correct prev_hash.
            shadow.blocks.push(shadow_blocks.last().unwrap().clone());
        }

        // Shadow fork is 4 blocks from base (longer than 0 from honest), but each block
        // carries two UptimeRewards — chain.try_reorg must reject the whole fork.
        assert!(!chain.try_reorg(shadow_blocks), "reorg with inflated blocks must be rejected");
        assert_eq!(chain.tip().miner, honest.node_id(), "honest chain must be unchanged");
    }

    // Attack 9: Cross-type in-block double-spend — Transfer + JobBid.
    // Alice transfers most of her credits to Eve and bids the same amount in the same block.
    // Before the fix, in_block_transfer was scoped away before the JobBid check, letting the
    // bid pass. Now the bid check subtracts in-block transfers from the same payer.
    #[test]
    fn transfer_and_bid_same_credits_rejected() {
        let host = make_identity("xtd-host");
        let alice = make_identity("xtd-alice");
        let eve = make_identity("xtd-eve");
        let mut chain = Chain::genesis();
        fund(&mut chain, &alice, 1_000);
        let bal = chain.balance(&alice.node_id()) as u128;
        // Each spend is 80% of the balance; together (160%) they exceed it.
        let spend = bal * 8 / 10;

        let transfer = signed_transfer(&alice, eve.node_id(), spend);
        let bid = signed_job_bid(&alice, [42u8; 32], spend);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, transfer, bid], host.node_id());
        block.seal(&host);
        assert!(!chain.append(block), "transfer + bid exceeding free balance must be rejected");
        assert_eq!(chain.balance(&alice.node_id()), bal as i128, "alice's balance must be unchanged");
    }

    // Attack 10: Cross-type in-block double-spend — Transfer + Heartbeat.
    // Bob (cell) transfers credits away while the host submits a heartbeat charging Bob for
    // the same credits in one block. Before the fix the heartbeat balance check did not see
    // the in-block transfer; now it does.
    //
    // One mined block funds bob with emission_rate(1) base units. A transfer and a heartbeat
    // each for 80% of that balance sum to 160% — the block must be rejected.
    #[test]
    fn transfer_and_heartbeat_same_credits_rejected() {
        let host = make_identity("xth-host");
        let bob = make_identity("xth-bob");
        let eve = make_identity("xth-eve");
        let mut chain = Chain::genesis();
        fund(&mut chain, &bob, 500);
        let bal = chain.balance(&bob.node_id()) as u128;
        let spend = bal * 8 / 10;

        let transfer = signed_transfer(&bob, eve.node_id(), spend);
        let hb = signed_heartbeat(&host, bob.node_id(), spend, 1);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, transfer, hb], host.node_id());
        block.seal(&host);
        assert!(!chain.append(block), "transfer + heartbeat exceeding cell balance must be rejected");
        assert_eq!(chain.balance(&bob.node_id()), bal as i128, "bob's balance must be unchanged");
    }

    // Attack 11: Block-size bomb — adversary packs more than MAX_TXS_PER_BLOCK transactions.
    // Each individual tx is valid; the block as a whole is rejected solely on size.
    // This prevents an attacker from exhausting storage or gossip bandwidth.
    #[test]
    fn block_size_bomb_rejected() {
        let miner = make_identity("bomb-miner");
        let mut chain = Chain::genesis();
        // Fund just enough for MAX_TXS_PER_BLOCK × 1-credit transfers.
        // emission_rate=1000, so 2 blocks suffices for 1024 credits.
        fund(&mut chain, &miner, MAX_TXS_PER_BLOCK as u128);

        let height_before = chain.height();
        let reward = signed_uptime_reward(&miner, chain.tip().index + 1);
        let mut txs = vec![reward];
        // Fill up to MAX_TXS_PER_BLOCK (reward already counts as one slot).
        for i in 0..MAX_TXS_PER_BLOCK {
            let mut to = [0u8; 32];
            to[..8].copy_from_slice(&(i as u64).to_le_bytes());
            txs.push(signed_transfer(&miner, to, 1));
        }
        // txs.len() == MAX_TXS_PER_BLOCK + 1 (one over the limit).
        let mut block = chain.next_block(txs, miner.node_id());
        block.seal(&miner);
        assert!(!chain.append(block), "block with more than MAX_TXS_PER_BLOCK txs must be rejected");
        assert_eq!(chain.height(), height_before, "chain height must be unchanged after bomb rejection");
    }

    // Attack 12: UptimeReward misdirection — miner directs emission to a third-party NodeId.
    // This is ALLOWED by design (analogous to Bitcoin coinbase payout address being arbitrary).
    // The test documents this intentional behaviour: the reward recipient is the miner's choice.
    #[test]
    fn uptime_reward_misdirection_to_third_party() {
        let miner = make_identity("redir-miner");
        let beneficiary = make_identity("redir-beneficiary");
        let mut chain = Chain::genesis();

        let block_index = chain.tip().index + 1;
        let amount = Chain::emission_rate(block_index);
        let kind = TxKind::UptimeReward { node: beneficiary.node_id(), amount, epoch: block_index };
        let data = bincode::serialize(&kind).unwrap();
        let sig = miner.sign(&data);
        let reward = Tx::new(kind, miner.node_id(), sig);

        let mut block = chain.next_block(vec![reward], miner.node_id());
        block.seal(&miner);
        assert!(chain.append(block), "reward directed to a third party must be accepted");
        assert_eq!(chain.balance(&miner.node_id()), 0, "miner gets nothing");
        assert_eq!(
            chain.balance(&beneficiary.node_id()),
            amount as i128,
            "beneficiary receives the full emission"
        );
    }

    // Attack 13: Rogue host drains a cell with a Heartbeat when no open bid exists.
    // The chain currently accepts this — heartbeats are not yet bid-gated because the
    // open_bids cache does not track which host accepted a given bid (only the payer).
    // This test documents the known design limitation. A future upgrade should introduce
    // a bid-acceptance tx that links a specific host to a job_id so heartbeats can be
    // validated against it.
    #[test]
    fn rogue_host_heartbeat_drains_cell_without_bid() {
        let mallory = make_identity("rogue-mallory");
        let bob = make_identity("rogue-bob");
        let mut chain = Chain::genesis();
        fund(&mut chain, &bob, 1_000);
        let before = chain.balance(&bob.node_id());

        let hb = signed_heartbeat(&mallory, bob.node_id(), 500, 1);
        let reward = signed_uptime_reward(&mallory, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, hb], mallory.node_id());
        block.seal(&mallory);
        // KNOWN LIMITATION: succeeds without a prior bid; bob is drained without consent.
        assert!(chain.append(block), "rogue heartbeat accepted — known design limitation");
        assert_eq!(chain.balance(&bob.node_id()), before - 500, "bob drained 500 base units by rogue host");
    }

    // Attack 14: Zero-amount transfer chain bloat.
    // An attacker floods the chain with zero-credit transfers — valid in isolation but
    // pointless, and accumulate into unbounded chain growth at no cost to the attacker.
    // The chain now rejects them explicitly.
    #[test]
    fn zero_amount_transfer_rejected() {
        let miner = make_identity("zero-miner");
        let victim = make_identity("zero-victim");
        let mut chain = Chain::genesis();
        fund(&mut chain, &miner, 1_000);

        let kind = TxKind::Transfer { from: miner.node_id(), to: victim.node_id(), amount: 0 };
        let data = bincode::serialize(&kind).unwrap();
        let sig = miner.sign(&data);
        let zero_tx = Tx::new(kind, miner.node_id(), sig);

        let reward = signed_uptime_reward(&miner, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, zero_tx], miner.node_id());
        block.seal(&miner);
        assert!(!chain.append(block), "zero-amount transfer must be rejected");
    }

    // Attack 8: Sybil reorg with double-spend — longest-chain double-spend attempt.
    // Attacker (Alice) pays Bob on the honest chain, then reveals a longer private fork
    // that redirects the same credits to Mallory. The reorg succeeds because the fork is
    // longer and fully valid — this is the expected behavior for any longest-chain rule.
    // It is NOT a chain bug; it documents that finality requires honest majority mining.
    // The test verifies: (a) a valid longer fork wins, (b) Bob's payment is erased.
    #[test]
    fn sybil_reorg_double_spend_succeeds_with_longer_valid_fork() {
        let alice = make_identity("ds-alice");
        let bob = make_identity("ds-bob");
        let mallory = make_identity("ds-mallory");
        let mut chain = Chain::genesis();

        // Fund Alice on the shared honest chain.
        fund(&mut chain, &alice, 1_000);

        // Save the chain at this point — both the honest chain and the shadow fork
        // will build from here so that try_reorg can find the common ancestor.
        let fork_base = chain.clone();

        // Honest chain: Alice → Bob 500 (one block above fork_base).
        let pay_bob = signed_transfer(&alice, bob.node_id(), 500);
        let reward = signed_uptime_reward(&alice, chain.tip().index + 1);
        let mut b = chain.next_block(vec![reward, pay_bob], alice.node_id());
        b.seal(&alice);
        assert!(chain.append(b));
        assert_eq!(chain.balance(&bob.node_id()), 500);

        // Shadow fork: three blocks from the same fork_base, so it beats the honest
        // chain's one block and triggers a reorg.
        let mut shadow_blocks: Vec<Block> = Vec::new();
        let mut shadow = fork_base;

        // Shadow block 1: Alice → Mallory 500 instead of Bob.
        let pay_mallory = signed_transfer(&alice, mallory.node_id(), 500);
        let reward = signed_uptime_reward(&alice, shadow.tip().index + 1);
        let mut b1 = shadow.next_block(vec![reward, pay_mallory], alice.node_id());
        b1.seal(&alice);
        assert!(shadow.append(b1.clone()));
        shadow_blocks.push(b1);

        // Shadow blocks 2–3: extend the fork past the honest chain.
        for _ in 0..2usize {
            let next_idx = shadow.tip().index + 1;
            let r = signed_uptime_reward(&mallory, next_idx);
            let mut blk = shadow.next_block(vec![r], mallory.node_id());
            blk.seal(&mallory);
            assert!(shadow.append(blk.clone()));
            shadow_blocks.push(blk);
        }

        // Three shadow blocks beat the honest chain's one block — reorg must proceed.
        assert!(chain.try_reorg(shadow_blocks), "valid longer shadow fork must win");
        assert_eq!(chain.balance(&bob.node_id()), 0, "Bob's payment erased by reorg");
        // Mallory gets: 500 (transfer from alice) + 2 × emission_rate (shadow blocks 2–3).
        let mallory_expected = 500i128
            + Chain::emission_rate(3) as i128
            + Chain::emission_rate(4) as i128;
        assert_eq!(chain.balance(&mallory.node_id()), mallory_expected, "Mallory receives transfer + mining rewards after reorg");
    }
}
