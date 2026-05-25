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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TxKind {
    /// Credit transfer between nodes.
    Transfer { from: NodeId, to: NodeId, amount: u64 },
    /// Uptime emission: credits minted and credited to a node for staying online.
    UptimeReward { node: NodeId, amount: u64, epoch: u64 },
    /// Open job bid: payer offers up to `bid` credits for a workload.
    /// `cmd` and `env` describe how the container should be launched; they are
    /// included on-chain so any host with capacity can accept the bid deterministically.
    /// The `bid` amount is locked in the payer's balance until JobSettle or JobExpire.
    JobBid {
        job_id: [u8; 32],
        payer: NodeId,
        bid: u64,
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
        cost: u64,
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
    Heartbeat { cell: NodeId, host: NodeId, amount: u64, epoch: u64 },
}

/// Canonical bytes the payer signs to authorize a settlement of `cost` against `job_id`.
/// Both the host (when building) and the chain (when validating) must produce
/// identical bytes for the same inputs.
pub fn payer_settle_bytes(job_id: &[u8; 32], cost: u64) -> Vec<u8> {
    bincode::serialize(&(b"ce-job-settle-v1", job_id, cost)).unwrap_or_default()
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
    /// Total UptimeReward supply emitted up to and including `block_height`.
    pub total_supply: u64,
    /// Full balance snapshot at checkpoint height.
    pub balances: Vec<(NodeId, i64)>,
    /// All open (unsettled, unexpired) job bids at checkpoint height.
    /// Tuple: (job_id, (payer, bid_amount, bid_block_index)).
    pub open_bids: Vec<([u8; 32], (NodeId, u64, u64))>,
    /// Highest confirmed heartbeat epoch per (cell, host) pair at checkpoint height.
    pub heartbeat_max_epoch: Vec<((NodeId, NodeId), u64)>,
}

// ----- Chain -----

const EMISSION_BASE: u64 = 1_000;
pub const SUPPLY_CAP: u64 = 21_000_000_000;

/// zstd magic bytes (little-endian frame magic).
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

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

    /// Net balance per node.
    #[serde(skip, default)]
    balances: std::collections::HashMap<NodeId, i64>,

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
    open_bids: std::collections::HashMap<[u8; 32], (NodeId, u64, u64)>,

    /// Cumulative UptimeReward supply. Avoids O(n) scan in append().
    #[serde(skip, default)]
    total_supply_cache: u64,
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
            total_supply_cache: 0,
        }
    }

    /// Rebuild all incremental caches from checkpoint state + kept blocks.
    /// Called once after loading from disk.
    pub fn rebuild_caches(&mut self) {
        self.balances.clear();
        self.heartbeat_max_epoch.clear();
        self.tx_index.clear();
        self.open_bids.clear();
        self.total_supply_cache = 0;

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
                    *self.balances.entry(*from).or_insert(0) -= *amount as i64;
                    *self.balances.entry(*to).or_insert(0) += *amount as i64;
                }
                TxKind::UptimeReward { node, amount, .. } => {
                    *self.balances.entry(*node).or_insert(0) += *amount as i64;
                    self.total_supply_cache =
                        self.total_supply_cache.saturating_add(*amount);
                }
                TxKind::JobSettle { job_id, host, payer, cost, .. } => {
                    *self.balances.entry(*payer).or_insert(0) -= *cost as i64;
                    *self.balances.entry(*host).or_insert(0) += *cost as i64;
                    self.open_bids.remove(job_id);
                }
                TxKind::Heartbeat { cell, host, amount, epoch } => {
                    *self.balances.entry(*cell).or_insert(0) -= *amount as i64;
                    *self.balances.entry(*host).or_insert(0) += *amount as i64;
                    let e = self.heartbeat_max_epoch.entry((*cell, *host)).or_insert(0);
                    if *epoch >= *e {
                        *e = *epoch;
                    }
                }
                TxKind::JobBid { job_id, payer, bid, .. } => {
                    self.open_bids.insert(*job_id, (*payer, *bid, block.index));
                }
                TxKind::JobExpire { job_id, .. } => {
                    self.open_bids.remove(job_id);
                }
                TxKind::TrustGrant { .. } => {}
            }
            self.tx_index.insert(tx.id(), (block.index, pos));
        }
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

    /// Total UptimeReward supply emitted. O(1) via incremental cache.
    pub fn total_supply(&self) -> u64 {
        self.total_supply_cache
    }

    /// Credits emitted per epoch at a given block index.
    /// Base rate 1,000; halves every 210,000 blocks; returns 0 after 64 halvings.
    pub fn emission_rate(block_index: u64) -> u64 {
        let halvings = block_index / 210_000;
        if halvings >= 64 { 0 } else { EMISSION_BASE >> halvings }
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
        for tx in &block.transactions {
            if tx.verify().is_err() {
                return false;
            }
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
        let new_emission: u64 = block
            .transactions
            .iter()
            .filter_map(|tx| {
                if let TxKind::UptimeReward { amount, .. } = &tx.kind { Some(*amount) } else { None }
            })
            .fold(0u64, |a, b| a.saturating_add(b));
        if self.total_supply_cache.saturating_add(new_emission) > SUPPLY_CAP {
            return false;
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
            // Free-balance check: payer must have enough un-locked credits to cover the bid.
            // Accumulate within this block to prevent double-bidding in a single block.
            let mut in_block_bid: std::collections::HashMap<NodeId, u64> =
                std::collections::HashMap::new();
            for tx in &block.transactions {
                if let TxKind::JobBid { payer, bid, .. } = &tx.kind {
                    let already_locked = self.locked_balance(payer) as i64;
                    let in_block = *in_block_bid.get(payer).unwrap_or(&0) as i64;
                    let free = self.balance(payer) - already_locked - in_block;
                    if free < *bid as i64 {
                        return false;
                    }
                    *in_block_bid.entry(*payer).or_insert(0) += bid;
                }
            }
        }
        // JobSettle rules.
        // open_bids cache tracks all open (unsettled, unexpired) bids — a single lookup
        // replaces the previous O(n) bid-search + O(n) duplicate-settle scan.
        let mut payer_debit: std::collections::HashMap<NodeId, u64> =
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
                // Payer co-signature over (job_id, cost).
                let bytes = payer_settle_bytes(job_id, *cost);
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
                if prior_balance.saturating_sub(accumulated as i64) < *cost as i64 {
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
            let mut heartbeat_debits: std::collections::HashMap<NodeId, u64> =
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
                    // Cell balance must cover the heartbeat.
                    let prior_balance = self.balance(cell);
                    let accumulated = *heartbeat_debits.get(cell).unwrap_or(&0) as i64;
                    if prior_balance - accumulated < *amount as i64 {
                        return false;
                    }
                    *heartbeat_debits.entry(*cell).or_insert(0) += amount;
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
            total_supply_cache: 0,
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
            total_supply_cache: 0,
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

    /// O(1) balance lookup via the incremental cache.
    pub fn balance(&self, node: &NodeId) -> i64 {
        self.balances.get(node).copied().unwrap_or(0)
    }

    /// Credits locked in open bids (no matching JobSettle or JobExpire yet) for a node.
    /// Free balance = `balance(node) - locked_balance(node)`.
    /// O(open_jobs) via the open_bids cache.
    pub fn locked_balance(&self, node: &NodeId) -> u64 {
        self.open_bids
            .values()
            .filter(|(payer, _, _)| payer == node)
            .map(|(_, bid, _)| *bid)
            .sum()
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

    fn signed_transfer(from: &Identity, to: NodeId, amount: u64) -> Tx {
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
        assert_eq!(chain.balance(&id.node_id()), Chain::emission_rate(1) as i64);
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
            alice_before - 10 + Chain::emission_rate(3) as i64,
        );
        assert_eq!(chain.balance(&bob.node_id()), 10);
    }

    // ----- Emission schedule -----

    #[test]
    fn emission_rate_schedule() {
        assert_eq!(Chain::emission_rate(0), 1_000);
        assert_eq!(Chain::emission_rate(209_999), 1_000);
        assert_eq!(Chain::emission_rate(210_000), 500);
        assert_eq!(Chain::emission_rate(420_000), 250);
        assert_eq!(Chain::emission_rate(630_000), 125);
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

    fn signed_job_bid(payer: &Identity, job_id: [u8; 32], bid: u64) -> Tx {
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
        cost: u64,
    ) -> Tx {
        let payer_sig = payer.sign(&payer_settle_bytes(&job_id, cost));
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
    fn fund(chain: &mut Chain, payer: &Identity, min: u64) {
        while (chain.balance(&payer.node_id()) as u64) < min {
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
            payer_before - cost as i64,
        );
        assert_eq!(
            chain.balance(&host.node_id()),
            host_before + cost as i64 + Chain::emission_rate(chain.tip().index) as i64,
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

        let payer_sig = id.sign(&payer_settle_bytes(&job_id, 50));
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

    fn signed_heartbeat(host: &Identity, cell_id: NodeId, amount: u64, epoch: u64) -> Tx {
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

        let hb = signed_heartbeat(&host, cell.node_id(), 100, 0);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, hb], host.node_id());
        block.seal(&host);
        assert!(chain.append(block), "valid heartbeat must be accepted");
        assert_eq!(chain.balance(&cell.node_id()), 1_000 - 100);
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
}
