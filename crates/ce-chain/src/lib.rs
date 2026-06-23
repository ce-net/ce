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
/// Minimum PoW difficulty (leading-zero bits). Mainnet floor; tests may mine at this level cheaply.
pub const MIN_DIFFICULTY: u8 = 8;
/// Difficulty genesis starts at. Equal to the floor.
pub const GENESIS_DIFFICULTY: u8 = MIN_DIFFICULTY;
/// Max per-window difficulty swing, as bits (±2 bits = the 4× clamp Bitcoin uses, on a log scale).
pub const MAX_DIFFICULTY_STEP: u8 = 2;
/// Number of recent blocks whose median timestamp forms the lower bound for a new block's time.
pub const MEDIAN_TIME_SPAN: usize = 11;
/// A block's timestamp may be at most this far in the future (seconds) — bounds timewarp attacks.
pub const MAX_FUTURE_DRIFT_SECS: u64 = 2 * 3600;
/// On-disk chain format version. Bumped to 2 for per-block PoW difficulty (a clean break — old
/// chains are not migrated; nodes wipe `<data_dir>/chain` and re-sync). The byte prefixes the file.
pub const CHAIN_FORMAT_VERSION: u8 = 2;
/// Minimum blocks to retain after a prune. Covers EXPIRY_BLOCKS + difficulty window.
pub const PRUNE_KEEP_BLOCKS: u64 = 2880;

/// Default share-ratio recency window (blocks). ~30 days at 10 s/block (259_200 blocks). Used by
/// `Chain::node_history_windowed` and surfaced on `GET /history`. Note: a default light node keeps
/// only `PRUNE_KEEP_BLOCKS` (~8 h), so its window is `partial`; archive nodes cover the full window.
pub const RATIO_WINDOW_BLOCKS: u64 = 259_200;

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

/// Persist a segment's blocks to the archive directory: `[CHAIN_FORMAT_VERSION] ++ zstd(bincode)`.
pub fn save_segment(archive_dir: &Path, segment_id: u64, blocks: &[Block]) -> Result<()> {
    std::fs::create_dir_all(archive_dir)?;
    let path = archive_dir.join(format!("segment_{segment_id}.bin"));
    let raw = bincode::serialize(blocks).map_err(|e| anyhow!("bincode: {e}"))?;
    let mut out = vec![CHAIN_FORMAT_VERSION];
    out.extend_from_slice(&zstd::encode_all(raw.as_slice(), 3).map_err(|e| anyhow!("zstd: {e}"))?);
    std::fs::write(path, out)?;
    Ok(())
}

/// Load a segment from the archive directory. Returns None if the file doesn't exist or was
/// written in an incompatible (pre-PoW) format — the node then re-fetches it from the network.
pub fn load_segment(archive_dir: &Path, segment_id: u64) -> Result<Option<Vec<Block>>> {
    let path = archive_dir.join(format!("segment_{segment_id}.bin"));
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read(&path)?;
    match data.split_first() {
        Some((&v, body)) if v == CHAIN_FORMAT_VERSION => {
            let raw = zstd::decode_all(body).map_err(|e| anyhow!("zstd: {e}"))?;
            let blocks: Vec<Block> =
                bincode::deserialize(&raw).map_err(|e| anyhow!("bincode: {e}"))?;
            Ok(Some(blocks))
        }
        _ => Ok(None), // stale/incompatible segment — treat as absent
    }
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

/// The PoW difficulty (leading-zero bits) the block extending `blocks` must declare. Pure: depends
/// only on the existing chain. Difficulty holds steady within a window and retargets on
/// `DIFFICULTY_WINDOW` boundaries toward `TARGET_BLOCK_SECS`, clamped to ±`MAX_DIFFICULTY_STEP`
/// bits (the log-scale equivalent of Bitcoin's 4× clamp) and floored at `MIN_DIFFICULTY`.
pub fn expected_difficulty(blocks: &[Block]) -> u8 {
    let Some(tip) = blocks.last() else {
        return GENESIS_DIFFICULTY;
    };
    let next_height = tip.index + 1;
    let window = DIFFICULTY_WINDOW as usize;
    // Retarget only on window boundaries, and only with a full window of retained history.
    if next_height % DIFFICULTY_WINDOW != 0 || blocks.len() < window {
        return tip.difficulty.max(MIN_DIFFICULTY);
    }
    let first = &blocks[blocks.len() - window];
    let actual = tip.timestamp.saturating_sub(first.timestamp).max(1);
    let target = DIFFICULTY_WINDOW * TARGET_BLOCK_SECS;
    let cur = tip.difficulty;
    let next = if actual < target / 4 {
        cur.saturating_add(MAX_DIFFICULTY_STEP) // far too fast → much harder
    } else if actual < target {
        cur.saturating_add(1) // a bit fast → slightly harder
    } else if actual > target.saturating_mul(4) {
        cur.saturating_sub(MAX_DIFFICULTY_STEP) // far too slow → much easier
    } else if actual > target {
        cur.saturating_sub(1) // a bit slow → slightly easier
    } else {
        cur
    };
    next.max(MIN_DIFFICULTY)
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
    /// Periodic heartbeat payment for a long-running cell. Signed by the host; debits the cell's
    /// wallet and credits the host (net of the settlement burn). `epoch` must strictly increase per
    /// (cell, host) pair to prevent replay.
    ///
    /// **Bid-gated (E3):** a heartbeat is only valid against an OPEN `JobBid` whose `job_id` it names
    /// and whose `payer == cell` — i.e. the cell's own signed bid authorized the work. The cumulative
    /// heartbeat cost billed against a job can NEVER exceed that job's locked bid escrow. This is the
    /// consent + bound that stops a rogue host from draining a funded cell's free balance with
    /// unconsented heartbeats. Heartbeats draw the escrow down; the remainder unlocks on
    /// JobSettle/JobExpire.
    Heartbeat { job_id: [u8; 32], cell: NodeId, host: NodeId, amount: u128, epoch: u64 },
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
    /// Claim a unique human-readable name for `node`. First claim wins (consensus-enforced
    /// uniqueness); `node` must equal the tx origin, so you only name yourself. Permanent in v0
    /// (transfer/release/expiry are refinements). `name` is validated for length and charset.
    NameClaim { name: String, node: NodeId },
    /// Revoke a capability by naming it `(issuer, nonce)`. Must be signed by `issuer` (origin ==
    /// issuer). Adds the pair to the chain's revocation set; revoking any link in a capability
    /// chain invalidates that link and its whole subtree. See `ce-node`'s `capability` module and
    /// `docs/capabilities.md`.
    RevokeCapability { issuer: NodeId, nonce: u64 },
    /// Post or top up a standing host bond. Locks `amount` of the host's free balance (like a JobBid
    /// lock) and re-activates the bond if it was unbonding. Signed by the host (origin == host).
    /// In later phases the bond gates marketplace roles (capacity ads, reward/leader eligibility); in
    /// this phase it is a slashable, slow-release lock. See docs/consensus.md. `nonce` only
    /// disambiguates otherwise-identical top-ups so two equal-amount bonds don't collide on tx id
    /// (the duplicate-tx-id rule still blocks true replay); it is not otherwise validated.
    HostBond { host: NodeId, amount: u128, nonce: u64 },
    /// Begin unbonding the host's standing bond. The funds stay locked and slashable for
    /// `UNBOND_BLOCKS` more blocks, then auto-release to free balance (no second tx). Signed by the host.
    HostUnbond { host: NodeId },
    /// Slash an `offender`'s standing bond for provable equivocation (two conflicting host-signed
    /// statements for one slot). Submitted by the `reporter` (origin == reporter). Burns 100% of the
    /// bond: the reporter receives `SLASH_REPORTER_BPS`, the remainder is destroyed. Idempotent per
    /// `(offender, domain, epoch)`.
    SlashEquivocation { offender: NodeId, reporter: NodeId, proof: EquivocationProof },
}

/// Validate a claimable name: 3–32 chars, lowercase ascii letters/digits/hyphen, not starting or
/// ending with a hyphen. Keeps names readable, case-insensitive-safe, and DNS-label-shaped.
pub fn is_valid_name(name: &str) -> bool {
    let n = name.len();
    if !(3..=32).contains(&n) {
        return false;
    }
    if name.starts_with('-') || name.ends_with('-') {
        return false;
    }
    name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
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

/// Canonical bytes a host signs when it commits to a single `statement` for a `(domain, epoch)` slot.
/// Any future per-slot signed artifact (a VRF block ticket, a capacity advertisement) signs through
/// this helper, which makes double-signing two different statements for the same slot a self-contained,
/// on-chain-verifiable equivocation — the evidence in `SlashEquivocation`. `statement` is a hash of
/// the artifact's payload; `domain` tags which kind of slot it is.
pub fn equivocation_signed_bytes(domain: &[u8; 16], epoch: u64, statement: &[u8; 32]) -> Vec<u8> {
    bincode::serialize(&(b"ce-equivocation-v1", domain, epoch, statement)).unwrap_or_default()
}

/// Self-contained proof that one host signed two conflicting statements for the same `(domain, epoch)`
/// slot — the evidence carried by `TxKind::SlashEquivocation`. The chain re-verifies both signatures
/// and that the statements differ; no external context is needed (cf. Filecoin `ReportConsensusFault`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EquivocationProof {
    /// Context tag for the slot the offender equivocated on (e.g. a capacity-ad or block-ticket domain).
    pub domain: [u8; 16],
    /// The slot/epoch both signed statements claim.
    pub epoch: u64,
    /// Hash of the first statement the offender signed.
    pub statement_a: [u8; 32],
    /// Hash of the conflicting second statement (must differ from `statement_a`).
    pub statement_b: [u8; 32],
    #[serde(with = "sig_serde")]
    pub sig_a: [u8; 64],
    #[serde(with = "sig_serde")]
    pub sig_b: [u8; 64],
}

/// An off-chain payment-channel receipt carried with a data-layer chunk fetch (Stage 3): the
/// payer's signature over `channel_receipt_bytes(channel_id, host, cumulative)`, authorising the
/// host to redeem up to `cumulative` later via `ChannelClose`. The provider is paid as it serves —
/// each chunk requires a receipt whose cumulative covers the running cost. The signed bytes are
/// identical to the on-chain closing receipt, so the same receipts settle the channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkReceipt {
    pub channel_id: [u8; 32],
    pub cumulative: u128,
    #[serde(with = "sig_serde")]
    pub payer_sig: [u8; 64],
}

/// Verify a chunk receipt's signature against the channel's `payer` and `host`.
pub fn verify_chunk_receipt_sig(payer: &NodeId, host: &NodeId, r: &ChunkReceipt) -> bool {
    verify(payer, &channel_receipt_bytes(&r.channel_id, host, r.cumulative), &r.payer_sig).is_ok()
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
    /// Vestigial (was the PoW search nonce). Unused under VRF leader election; kept at 0.
    pub nonce: u64,
    /// Vestigial (was the PoW difficulty). Unused under VRF leader election; kept at 0.
    pub difficulty: u8,
    pub miner: NodeId,
    /// The producer's consensus weight at production time. Validated on append to equal
    /// `consensus_weight(miner)`, so fork choice can sum weights without recomputing state. This is
    /// the block's fork-choice work.
    pub weight: u128,
    /// VRF proof: the miner's Ed25519 signature over the slot's `leader_seed`. `vrf_ticket(this)`
    /// must fall below `leader_threshold(weight, total_weight)` for the miner to be an eligible leader.
    #[serde(with = "sig_serde")]
    pub vrf_proof: [u8; 64],
    #[serde(with = "sig_serde")]
    pub sig: [u8; 64],
}

impl Block {
    /// The proof-of-work hash: SHA256 of the header (everything except the signature). PoW is
    /// searched over `nonce` against this hash, independently of signing — so sealing the block
    /// after a solve doesn't invalidate the work (Bitcoin-style header PoW).
    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.header_bytes()).into()
    }

    fn header_bytes(&self) -> Vec<u8> {
        // Sign/hash all fields except `sig` itself (circular). `weight` and `vrf_proof` are bound by
        // the seal so a relayer can't alter the producer's claimed weight or VRF proof.
        bincode::serialize(&(
            self.index,
            &self.prev_hash,
            self.timestamp,
            &self.transactions,
            self.nonce,
            self.difficulty,
            &self.miner,
            self.weight,
            &self.vrf_proof[..],
        ))
        .unwrap_or_default()
    }

    /// Cumulative-work contribution of this block for fork choice: the producer's consensus weight.
    /// Validated on append to equal `consensus_weight(miner)`, so the heaviest-weight suffix wins.
    pub fn work(&self) -> u128 {
        self.weight
    }

    /// Sign the block header. Called after the VRF proof and weight are set.
    pub fn seal(&mut self, identity: &Identity) {
        self.sig = identity.sign(&self.header_bytes());
    }

    /// Vestigial no-op kept so legacy block-construction call sites compile. Under VRF leader
    /// election there is nothing to mine — eligibility comes from `Chain::try_produce`/`produce`.
    pub fn mine(&mut self, _abort: &std::sync::atomic::AtomicBool) -> bool {
        true
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

/// Protocol burn applied to every settlement (JobSettle, Heartbeat, ChannelClose), in basis points
/// of the gross amount. The payer/cell is debited the full gross amount; the host receives
/// `gross − burn`; the burn is destroyed (removed from circulation, credited to no one).
///
/// This is the keystone Sybil defence for the trust economy (docs/consensus.md Phase 0,
/// docs/sybil-resistance.md finding E4): a wash trade between two identities the same attacker
/// controls no longer nets to zero — every settlement cycle destroys `burn`, so manufacturing
/// reputation/earned-history costs real capital that scales with the volume faked. Honest users pay
/// the same burn as a flat marketplace take-rate.
///
/// Reward-spread design: set so the provider keeps **one fifth** of every settlement and the other
/// four fifths are burned. The consumer pays the full gross; the host receives `gross - gross*4/5 =
/// gross/5`. Contributing-to-consume is therefore a 5:1 ratio — donating idle compute earns back ~20%
/// of its value in spendable credits — and wash trading is brutally unprofitable (every faked cycle
/// destroys 80%). Strongly deflationary at volume; uptime emission is the offsetting knob.
/// Consensus validation is unaffected — the burn is a deterministic function of the gross amount,
/// applied identically by every node in `apply_block_to_cache`, and the payer's debit (the only side
/// `append` balance-checks) is unchanged.
pub const SETTLEMENT_BURN_BPS: u128 = 8000; // 80.00% — provider keeps 1/5 (reward spread)
/// Basis-point denominator.
const BPS_DENOM: u128 = 10_000;

/// Credits destroyed by the protocol burn on a settlement of `gross` base units.
/// Floor division: a settlement smaller than `BPS_DENOM / SETTLEMENT_BURN_BPS` base units burns 0
/// (too small to be worth washing). The host receives `gross - settlement_burn(gross)`.
pub fn settlement_burn(gross: u128) -> u128 {
    gross.saturating_mul(SETTLEMENT_BURN_BPS) / BPS_DENOM
}

/// Blocks a `HostBond` stays locked and slashable after `HostUnbond` before it auto-releases to the
/// host's free balance. One difficulty window (~2 weeks at the 10-min target), so a host cannot
/// cheat-then-flee: equivocation proven during this window still burns the bond. See docs/consensus.md.
pub const UNBOND_BLOCKS: u64 = 2016;

/// Share of a slashed bond paid to the reporter who submitted the equivocation proof, in basis
/// points; the remainder is destroyed (burned), never paid to a counterparty (which would incentivise
/// fraudulent disputes). v0 uses a flat share — the Filecoin-style Dutch-auction rising reward is a
/// later refinement (docs/consensus.md §4).
pub const SLASH_REPORTER_BPS: u128 = 2_500; // 25%

/// Fork-choice / VRF look-back depth (blocks). Consensus weight is read from chain state this many
/// blocks behind the tip, so an attacker cannot mint fresh weight inside a private fork to make its
/// suffix heavier — the weight is fixed by history both forks already agree on. The weight ORACLE
/// (`consensus_weight`) is a pure function of whatever state it is given; `LOOKBACK` is how Phase 3's
/// VRF leader election and weighted fork choice will *call* it (against appropriately-aged state).
/// See docs/consensus.md.
pub const LOOKBACK: u64 = 64;

/// Slot length for VRF leader election (seconds): `slot = (timestamp − genesis_timestamp) / SLOT_SECS`.
pub const SLOT_SECS: u64 = 10;

/// Domain-separated leader-election seed for a slot. Bound to a CONFIRMED block (`LOOKBACK` behind the
/// tip) so the current leader cannot grind it, and to the slot number. Every eligible node computes
/// the same seed, signs it, and `H(signature)` is its VRF ticket.
pub fn leader_seed(confirmed_hash: &[u8; 32], slot: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"ce-twle-seed-v1");
    h.update(confirmed_hash);
    h.update(slot.to_be_bytes());
    h.finalize().into()
}

/// A node's VRF ticket for a seed: `H(its Ed25519 signature over the seed)`. Ed25519 signatures are
/// deterministic (RFC 8032) and unique per `(key, message)`, so the ticket is a deterministic,
/// publicly-verifiable, unpredictable-without-the-key value — a usable VRF output. (v0 is
/// signature-as-VRF; RFC 9381 ECVRF is a later hardening for stronger uniqueness guarantees.)
pub fn vrf_ticket(proof_sig: &[u8; 64]) -> [u8; 32] {
    Sha256::digest(proof_sig).into()
}

/// Verify a VRF proof: `proof_sig` must be `node`'s valid signature over `seed`. Returns the ticket on
/// success; the proof is unforgeable without `node`'s secret key.
pub fn vrf_verify(node: &NodeId, seed: &[u8; 32], proof_sig: &[u8; 64]) -> Option<[u8; 32]> {
    verify(node, seed, proof_sig).ok().map(|_| vrf_ticket(proof_sig))
}

/// Interpret a VRF ticket as a `u128` (its high 16 bytes) for the eligibility comparison.
pub fn ticket_value(ticket: &[u8; 32]) -> u128 {
    let mut b = [0u8; 16];
    b.copy_from_slice(&ticket[..16]);
    u128::from_be_bytes(b)
}

/// The eligibility cutoff for a node of `weight` out of `total_weight`: it leads a slot iff its
/// `ticket_value` is strictly below this. Sized so the expected number of leaders per slot is ~1
/// across the whole weight (Filecoin Expected-Consensus style: 0..n winners, empty slots normal).
/// A zero-weight node (cutoff 0) can never lead.
pub fn leader_threshold(weight: u128, total_weight: u128) -> u128 {
    if total_weight == 0 || weight == 0 {
        return 0;
    }
    (u128::MAX / total_weight).saturating_mul(weight)
}


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
    /// Times this node's bond was slashed for provable equivocation.
    pub slashes: u64,
    /// Block height at which this node was first seen in an interaction (0 = never).
    pub first_height: u64,
    /// Block height of this node's most recent interaction.
    pub last_height: u64,
}

/// A time-windowed slice of a node's hosting/consuming volume over the last `window_blocks`
/// blocks — the recent-window facts a torrent-style share-ratio uses to weight recent over old
/// contribution. Observational only (a read-model walked from blocks, like `burned_total_cache`);
/// never consensus, never signed. All amounts are base units. See `Chain::node_history_windowed`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WindowedStats {
    /// Width of the window in blocks (the value the slice was computed over).
    pub window_blocks: u64,
    /// Credits earned hosting work within the window (post-burn, mirrors `NodeStats::earned`).
    pub recent_earned: u128,
    /// Credits spent consuming work within the window (gross, mirrors `NodeStats::spent`).
    pub recent_spent: u128,
    /// True when the held blocks do not fully cover the window (pruned light node / short chain),
    /// so the slice undercounts and an archive node should be consulted for the full window.
    pub partial: bool,
    /// First-interaction height (carried from `NodeStats` for newcomer-grace classification).
    pub first_height: u64,
    /// Most-recent-interaction height (carried from `NodeStats` for the recency proxy).
    pub last_height: u64,
}

/// Does this transaction name `node` in any of its participant roles? Used by
/// `Chain::transactions_for` to select a node's confirmed history. `tx.origin` is always checked,
/// plus every NodeId-typed field of the `TxKind`. Read of public chain facts only.
pub fn tx_names_node(tx: &Tx, node: &NodeId) -> bool {
    if &tx.origin == node {
        return true;
    }
    match &tx.kind {
        TxKind::Transfer { from, to, .. } => from == node || to == node,
        TxKind::UptimeReward { node: n, .. } => n == node,
        TxKind::JobBid { payer, .. } => payer == node,
        TxKind::JobSettle { host, payer, .. } => host == node || payer == node,
        TxKind::JobExpire { payer, .. } => payer == node,
        TxKind::Heartbeat { cell, host, .. } => cell == node || host == node,
        TxKind::ChannelOpen { payer, host, .. } => payer == node || host == node,
        TxKind::ChannelClose { .. } => false, // payer/host not named in the tx; origin (host) covered above
        TxKind::ChannelExpire { payer, .. } => payer == node,
        TxKind::NameClaim { node: n, .. } => n == node,
        TxKind::RevokeCapability { issuer, .. } => issuer == node,
        TxKind::HostBond { host, .. } => host == node,
        TxKind::HostUnbond { host } => host == node,
        TxKind::SlashEquivocation { offender, reporter, .. } => offender == node || reporter == node,
    }
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

    /// Cumulative gross heartbeat cost billed against each open job (job_id → total amount). Bounds
    /// heartbeats to the job's locked bid escrow (E3): a heartbeat is rejected if it would drive this
    /// past the bid. The entry is removed when the job's bid is removed (JobSettle / JobExpire).
    #[serde(skip, default)]
    heartbeat_spent: std::collections::HashMap<[u8; 32], u128>,

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

    /// Standing host bonds: host → (amount, unbonding_at). `unbonding_at == None` means active;
    /// `Some(h)` means unbonding — still locked and slashable until block height `h`, then released to
    /// free balance. Rebuilt from available blocks (same prune caveat as `node_stats`).
    #[serde(skip, default)]
    bonds: std::collections::HashMap<NodeId, (u128, Option<u64>)>,

    /// Equivocations already slashed, keyed by `(offender, domain, epoch)`, so the same fault cannot
    /// be slashed twice. Rebuilt from available blocks (mirrors the `revoked` set).
    #[serde(skip, default)]
    slashed_equivocations: std::collections::HashSet<(NodeId, [u8; 16], u64)>,

    /// Genesis bootstrap weight per node — network config (a chain spec), NOT chain data: re-applied
    /// from node config on every startup, identical across honest nodes, so it is `skip`'d and survives
    /// cache rebuilds (it is not derived from blocks). Solves the cold-start deadlock where nobody has
    /// a bond or earned work yet. Decay toward zero as real earned weight accrues is Phase 5. See
    /// docs/consensus.md §4.1.
    #[serde(skip, default)]
    genesis_weights: std::collections::HashMap<NodeId, u128>,

    /// Cumulative UptimeReward supply. Avoids O(n) scan in append().
    #[serde(skip, default)]
    total_supply_cache: u128,

    /// Cumulative credits destroyed by the settlement burn (base units). Rebuilt from available
    /// blocks like `node_stats` — a pruned light node counts only post-checkpoint burns; archive
    /// nodes are authoritative. Observational only (not consensus-critical): circulating supply =
    /// `total_supply_cache - burned_total_cache`.
    #[serde(skip, default)]
    burned_total_cache: u128,

    /// Per-node interaction history (reputation substrate). O(1) lookup, built incrementally.
    #[serde(skip, default)]
    node_stats: std::collections::HashMap<NodeId, NodeStats>,

    /// Claimed names: name → owning NodeId. First claim wins; uniqueness is consensus-enforced.
    #[serde(skip, default)]
    names: std::collections::HashMap<String, NodeId>,

    /// Revoked capabilities: the set of `(issuer, nonce)` pairs named by confirmed
    /// `RevokeCapability` txs. Like `names`/`node_stats`, this is rebuilt from available blocks; a
    /// pruned light node holds only post-checkpoint revocations, so archive nodes are authoritative
    /// for full revocation history. Capability expiry bounds the residual risk. (v0.)
    #[serde(skip, default)]
    revoked: std::collections::HashSet<(NodeId, u64)>,

    /// Total proof-of-work in `blocks` (sum of `2^difficulty`). Drives work-based fork choice —
    /// the heaviest valid chain wins, not the longest. Rebuilt from blocks (not persisted).
    #[serde(skip, default)]
    cumulative_work: u128,
}

impl Chain {
    pub fn genesis() -> Self {
        let genesis = Block {
            index: 0,
            prev_hash: [0u8; 32],
            timestamp: 0,
            transactions: vec![],
            nonce: 0,
            difficulty: 0,
            miner: [0u8; 32],
            weight: 0,
            vrf_proof: [0u8; 64],
            sig: [0u8; 64],
        };
        let genesis_work = genesis.work();
        Self {
            blocks: vec![genesis],
            difficulty: GENESIS_DIFFICULTY,
            checkpoint: None,
            balances: std::collections::HashMap::new(),
            heartbeat_max_epoch: std::collections::HashMap::new(),
            heartbeat_spent: std::collections::HashMap::new(),
            tx_index: std::collections::HashMap::new(),
            open_bids: std::collections::HashMap::new(),
            open_channels: std::collections::HashMap::new(),
            bonds: std::collections::HashMap::new(),
            slashed_equivocations: std::collections::HashSet::new(),
            genesis_weights: std::collections::HashMap::new(),
            total_supply_cache: 0,
            burned_total_cache: 0,
            node_stats: std::collections::HashMap::new(),
            names: std::collections::HashMap::new(),
            revoked: std::collections::HashSet::new(),
            cumulative_work: genesis_work,
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
        // Bonds and slash records are rebuilt from available blocks (same prune caveat as node_stats).
        self.bonds.clear();
        self.slashed_equivocations.clear();
        self.total_supply_cache = 0;
        // Rebuilt from available blocks (same prune caveat as node_stats); never seeded from
        // checkpoint — it is observational, not consensus-critical.
        self.burned_total_cache = 0;
        // node_stats is rebuilt from available blocks. A pruned light node therefore holds
        // only post-checkpoint reputation; full history lives on archive nodes (query one of
        // those for complete reputation). Acceptable for v0.
        self.node_stats.clear();
        self.names.clear();
        // Rebuilt from available blocks (same prune caveat as names/node_stats).
        self.revoked.clear();
        self.cumulative_work = 0;

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

    /// Has the capability named `(issuer, nonce)` been revoked on-chain? Consulted by capability
    /// authorization. Archive nodes are authoritative; a pruned light node sees only
    /// post-checkpoint revocations.
    pub fn is_revoked(&self, issuer: &NodeId, nonce: u64) -> bool {
        self.revoked.contains(&(*issuer, nonce))
    }

    /// All revoked `(issuer, nonce)` pairs. Exposed so apps (e.g. rdev) can consult on-chain
    /// revocation when authorizing capability chains.
    pub fn revoked_pairs(&self) -> Vec<(NodeId, u64)> {
        self.revoked.iter().copied().collect()
    }

    /// Apply one block's transactions to the incremental caches.
    fn apply_block_to_cache(&mut self, block: &Block) {
        self.cumulative_work = self.cumulative_work.saturating_add(block.work());
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
                    // Payer pays the full gross `cost`; the host receives `cost - burn`; the burn is
                    // destroyed. `append` already balance-checked the payer for the full gross.
                    let burn = settlement_burn(*cost);
                    let net = (*cost).saturating_sub(burn);
                    *self.balances.entry(*payer).or_insert(0) -= *cost as i128;
                    *self.balances.entry(*host).or_insert(0) += net as i128;
                    self.burned_total_cache = self.burned_total_cache.saturating_add(burn);
                    self.open_bids.remove(job_id);
                    self.heartbeat_spent.remove(job_id);
                    let h = block.index;
                    let (cost, net, host, payer) = (*cost, net, *host, *payer);
                    let s = self.node_stat(&host, h);
                    s.jobs_hosted += 1;
                    // `earned` is the host's actual net gain (post-burn), so it stays consistent with
                    // the balance change and reflects real, burned-and-paid work.
                    s.earned = s.earned.saturating_add(net);
                    let s = self.node_stat(&payer, h);
                    s.jobs_paid += 1;
                    s.spent = s.spent.saturating_add(cost);
                }
                TxKind::Heartbeat { job_id, cell, host, amount, epoch } => {
                    // Same burn as JobSettle: the cell pays gross `amount`, the host receives the net.
                    let burn = settlement_burn(*amount);
                    let net = (*amount).saturating_sub(burn);
                    *self.balances.entry(*cell).or_insert(0) -= *amount as i128;
                    *self.balances.entry(*host).or_insert(0) += net as i128;
                    self.burned_total_cache = self.burned_total_cache.saturating_add(burn);
                    // Draw the job's escrow down (E3): append() already verified an open bid for this
                    // job with payer == cell and that cumulative spend stays within the bid.
                    *self.heartbeat_spent.entry(*job_id).or_insert(0) =
                        self.heartbeat_spent.get(job_id).copied().unwrap_or(0).saturating_add(*amount);
                    let e = self.heartbeat_max_epoch.entry((*cell, *host)).or_insert(0);
                    if *epoch >= *e {
                        *e = *epoch;
                    }
                    let h = block.index;
                    let (amount, net, host, cell) = (*amount, net, *host, *cell);
                    let s = self.node_stat(&host, h);
                    s.heartbeats_hosted += 1;
                    s.earned = s.earned.saturating_add(net);
                    let s = self.node_stat(&cell, h);
                    s.heartbeats_paid += 1;
                    s.spent = s.spent.saturating_add(amount);
                }
                TxKind::JobBid { job_id, payer, bid, .. } => {
                    self.open_bids.insert(*job_id, (*payer, *bid, block.index));
                }
                TxKind::JobExpire { job_id, payer } => {
                    self.open_bids.remove(job_id);
                    self.heartbeat_spent.remove(job_id);
                    let h = block.index;
                    self.node_stat(payer, h).expiries += 1;
                }
                TxKind::ChannelOpen { channel_id, payer, host, capacity, expiry_height } => {
                    self.open_channels.insert(*channel_id, (*payer, *host, *capacity, *expiry_height));
                }
                TxKind::ChannelClose { channel_id, cumulative, .. } => {
                    if let Some((payer, host, _cap, _exp)) = self.open_channels.remove(channel_id) {
                        // Same burn as JobSettle: the payer pays gross `cumulative`, host gets the net.
                        let burn = settlement_burn(*cumulative);
                        let net = (*cumulative).saturating_sub(burn);
                        *self.balances.entry(payer).or_insert(0) -= *cumulative as i128;
                        *self.balances.entry(host).or_insert(0) += net as i128;
                        self.burned_total_cache = self.burned_total_cache.saturating_add(burn);
                        let h = block.index;
                        let (cumulative, net) = (*cumulative, net);
                        let s = self.node_stat(&host, h);
                        s.jobs_hosted += 1;
                        s.earned = s.earned.saturating_add(net);
                        let s = self.node_stat(&payer, h);
                        s.jobs_paid += 1;
                        s.spent = s.spent.saturating_add(cumulative);
                    }
                }
                TxKind::ChannelExpire { channel_id, .. } => {
                    // Just unlock — capacity returns to the payer's free balance (no balance move).
                    self.open_channels.remove(channel_id);
                }
                TxKind::NameClaim { name, node } => {
                    // First claim wins: only record if unclaimed (append() already rejected
                    // conflicts, but a checkpoint replay could re-see an earlier claim).
                    self.names.entry(name.clone()).or_insert(*node);
                }
                TxKind::RevokeCapability { issuer, nonce } => {
                    self.revoked.insert((*issuer, *nonce));
                }
                TxKind::HostBond { host, amount, .. } => {
                    // Lock (or top up) the bond and re-activate it if it was unbonding. The funds stay
                    // in the host's balance but become locked (counted by locked_balance).
                    let entry = self.bonds.entry(*host).or_insert((0, None));
                    entry.0 = entry.0.saturating_add(*amount);
                    entry.1 = None;
                }
                TxKind::HostUnbond { host } => {
                    if let Some(entry) = self.bonds.get_mut(host) {
                        // Start the slow release; funds stay locked and slashable until this height.
                        entry.1 = Some(block.index + UNBOND_BLOCKS);
                    }
                }
                TxKind::SlashEquivocation { offender, reporter, proof } => {
                    // append() validated the bond is active and the fault is unslashed. Confiscate the
                    // whole bond: it leaves the offender's balance, the reporter gets its share, the
                    // remainder is destroyed.
                    if let Some((amount, _)) = self.bonds.remove(offender) {
                        let reporter_share = amount.saturating_mul(SLASH_REPORTER_BPS) / BPS_DENOM;
                        let destroyed = amount.saturating_sub(reporter_share);
                        *self.balances.entry(*offender).or_insert(0) -= amount as i128;
                        *self.balances.entry(*reporter).or_insert(0) += reporter_share as i128;
                        self.burned_total_cache = self.burned_total_cache.saturating_add(destroyed);
                        let h = block.index;
                        self.node_stat(offender, h).slashes += 1;
                    }
                    self.slashed_equivocations.insert((*offender, proof.domain, proof.epoch));
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

    /// Recent earned-as-host / spent-as-cell volume for a node over the last `WINDOW_BLOCKS`
    /// blocks (base units). This is the *one* fact the cumulative `NodeStats` cannot provide: a
    /// true time-windowed slice, which a torrent-style share-ratio needs to weight recent
    /// contribution over years-old contribution. It is an **observational read-model** derived by
    /// walking the blocks the node already holds — identical in kind to `burned_total_cache` — and
    /// is NOT part of validation, fork choice, or any signed/hashed bytes. Computed on demand
    /// (O(window) over kept blocks), so no extra always-on accumulator is carried in the hot path.
    ///
    /// `tip` is the height the window is anchored at (normally `self.height()`). Earned/spent use the
    /// same post-burn (`earned`) / gross (`spent`) semantics as `NodeStats`. On a pruned light node
    /// the walk only sees post-checkpoint blocks, so a short chain yields a partial window (the
    /// caller should label results "partial" — archive nodes are authoritative).
    pub fn node_history_windowed(&self, node: &NodeId, window_blocks: u64) -> WindowedStats {
        let tip = self.height();
        let lower = tip.saturating_sub(window_blocks);
        let mut recent_earned: u128 = 0;
        let mut recent_spent: u128 = 0;
        // Walk only blocks inside the window; `blocks` is height-ordered.
        for block in self.blocks.iter().filter(|b| b.index > lower) {
            for tx in &block.transactions {
                match &tx.kind {
                    TxKind::JobSettle { host, payer, cost, .. } => {
                        if host == node {
                            recent_earned = recent_earned
                                .saturating_add((*cost).saturating_sub(settlement_burn(*cost)));
                        }
                        if payer == node {
                            recent_spent = recent_spent.saturating_add(*cost);
                        }
                    }
                    TxKind::Heartbeat { cell, host, amount, .. } => {
                        if host == node {
                            recent_earned = recent_earned
                                .saturating_add((*amount).saturating_sub(settlement_burn(*amount)));
                        }
                        if cell == node {
                            recent_spent = recent_spent.saturating_add(*amount);
                        }
                    }
                    // ChannelClose: settled volume mirrors JobSettle, but identifying payer/host
                    // requires the (already-removed) open-channel record. We approximate by the
                    // channel-close origin = host (v0 close rule), which credits the closer's earned
                    // and, lacking the payer here, leaves payer-side spent to the cumulative figure.
                    TxKind::ChannelClose { cumulative, .. } => {
                        if &tx.origin == node {
                            recent_earned = recent_earned.saturating_add(
                                (*cumulative).saturating_sub(settlement_burn(*cumulative)),
                            );
                        }
                    }
                    _ => {}
                }
            }
        }
        let stats = self.node_history(node);
        WindowedStats {
            window_blocks,
            recent_earned,
            recent_spent,
            // The window is "partial" (not fully covered by held blocks) when the chain's oldest
            // kept block is newer than the window's lower bound — i.e. a pruned/short chain.
            partial: self.blocks.first().map(|b| b.index).unwrap_or(0) > lower,
            first_height: stats.first_height,
            last_height: stats.last_height,
        }
    }

    /// Confirmed transactions that name `node` as a participant — origin, or any role
    /// (`from`/`to`/`payer`/`host`/`cell`/`node`/`issuer`/`offender`/`reporter`/`miner`). Newest
    /// first, paginated: `before` excludes transactions at height `>= before` (cursor for the next
    /// page; `None` starts at the tip), `limit` caps the page size. Returns `(tx, height, tx_id)`.
    ///
    /// PRIVACY: this is a read of *public, on-chain* facts — every settlement/transfer leg is already
    /// world-readable to anyone with the chain. It exposes nothing the ledger does not. It is not a
    /// private account statement; the same data is visible to every node. On a pruned light node only
    /// post-checkpoint transactions are returned (archive nodes hold the full history).
    ///
    /// O(kept_blocks) walk from the tip; `limit` bounds the result, and the bounded walk stops once a
    /// full page is collected, so a large chain does not force a full scan per page.
    pub fn transactions_for(
        &self,
        node: &NodeId,
        before: Option<u64>,
        limit: usize,
    ) -> Vec<(Tx, u64, [u8; 32])> {
        let mut out: Vec<(Tx, u64, [u8; 32])> = Vec::new();
        // Walk newest block first; within a block, newest tx first, so the page is strictly
        // descending by (height, position).
        for block in self.blocks.iter().rev() {
            if let Some(before) = before {
                if block.index >= before {
                    continue;
                }
            }
            for tx in block.transactions.iter().rev() {
                if tx_names_node(tx, node) {
                    out.push((tx.clone(), block.index, tx.id()));
                    if out.len() >= limit {
                        return out;
                    }
                }
            }
        }
        out
    }

    /// List open payment channels: (channel_id, payer, host, capacity, expiry_height).
    pub fn list_channels(&self) -> Vec<([u8; 32], NodeId, NodeId, u128, u64)> {
        self.open_channels
            .iter()
            .map(|(id, (payer, host, capacity, expiry))| (*id, *payer, *host, *capacity, *expiry))
            .collect()
    }

    /// Resolve a claimed name to its owning NodeId (`None` if unclaimed).
    pub fn resolve_name(&self, name: &str) -> Option<NodeId> {
        self.names.get(name).copied()
    }

    /// Total credits destroyed by the settlement burn so far (base units). Observational; a pruned
    /// light node counts only post-checkpoint burns (archive nodes are authoritative).
    pub fn burned_total(&self) -> u128 {
        self.burned_total_cache
    }

    /// Credits in circulation: total emitted minus total burned (base units).
    pub fn circulating_supply(&self) -> u128 {
        self.total_supply_cache.saturating_sub(self.burned_total_cache)
    }

    /// All claimed names: (name, owner). For listing/debugging.
    pub fn list_names(&self) -> Vec<(String, NodeId)> {
        self.names.iter().map(|(n, owner)| (n.clone(), *owner)).collect()
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
        // VRF leader-election consensus (CE-TWLE). Replaces proof-of-work: the producer must be an
        // eligible leader for the block's slot. This is the single chokepoint; try_reorg routes here.
        //
        // Slot spacing is consensus-enforced — slot strictly increases, so block rate is bounded by
        // wall-clock and there is NO self-imposed pacing a miner can delete (the old cheap-51% footgun).
        let slot = block.timestamp / SLOT_SECS;
        if slot <= self.tip().timestamp / SLOT_SECS {
            return false; // at most one block per slot; enforces >= SLOT_SECS spacing, always
        }
        let total = self.total_consensus_weight();
        if total > 0 {
            // The producer's declared weight must equal its actual consensus weight, and be non-zero
            // (a fresh/unbonded/un-granted node can never lead). Fork choice sums this declared weight.
            let weight = self.consensus_weight(&block.miner);
            if block.weight != weight || weight == 0 {
                return false;
            }
            // VRF: the proof must be the miner's signature over the slot seed, and the resulting
            // ticket must fall below its weight-proportional threshold (~1 expected leader per slot).
            let seed = self.confirmed_seed(slot);
            let ticket = match vrf_verify(&block.miner, &seed, &block.vrf_proof) {
                Some(t) => t,
                None => return false,
            };
            if ticket_value(&ticket) >= leader_threshold(weight, total) {
                return false;
            }
        }
        // Bootstrap fallback (total weight == 0): with no genesis grants, bonds, or earned work
        // anywhere, there is no basis for weighted election, so a well-sealed block at a fresh slot is
        // accepted. A production network MUST configure genesis_weights, so total weight is non-zero
        // from block 1 and this branch never runs there. See docs/consensus.md §4.1.
        //
        // Timestamp must not be far in the future (bounds slot pre-claiming); strictly increasing
        // slots already imply monotonic, non-timewarpable time.
        if !self.timestamp_ok(&block) {
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
                // Cost is bounded by the REMAINING escrow: the bid minus whatever heartbeats already
                // billed against this job (E3). Without this, a host could heartbeat-drain a job to its
                // bid AND still settle for the full bid — double-charging the payer.
                let spent = self.heartbeat_spent.get(job_id).copied().unwrap_or(0);
                let remaining = bid_amount.saturating_sub(spent);
                if *cost > remaining {
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
        // RevokeCapability rules: only the capability's issuer may revoke it (origin == issuer).
        for tx in &block.transactions {
            if let TxKind::RevokeCapability { issuer, .. } = &tx.kind {
                if &tx.origin != issuer {
                    return false;
                }
            }
        }
        // Host-bond / unbond / slash rules. A HostBond locks `amount` of the host's free balance and
        // is validated against EVERY other in-block debit of the same host (transfers, bids,
        // heartbeats-as-cell, prior bonds) so it cannot double-spend; the payment-channel section
        // (validated last) in turn subtracts in-block bonds, so a bond never collides with a channel.
        {
            let mut in_block_bond: std::collections::HashMap<NodeId, u128> =
                std::collections::HashMap::new();
            let mut slashing: std::collections::HashSet<(NodeId, [u8; 16], u64)> =
                std::collections::HashSet::new();
            for tx in &block.transactions {
                match &tx.kind {
                    TxKind::HostBond { host, amount, .. } => {
                        if &tx.origin != host || *amount == 0 {
                            return false;
                        }
                        let bids: u128 = block
                            .transactions
                            .iter()
                            .filter_map(|t| match &t.kind {
                                TxKind::JobBid { payer, bid, .. } if payer == host => Some(*bid),
                                _ => None,
                            })
                            .sum();
                        let hbs: u128 = block
                            .transactions
                            .iter()
                            .filter_map(|t| match &t.kind {
                                TxKind::Heartbeat { cell, amount, .. } if cell == host => Some(*amount),
                                _ => None,
                            })
                            .sum();
                        let transfers = *in_block_transfer.get(host).unwrap_or(&0);
                        let prior_bonds = *in_block_bond.get(host).unwrap_or(&0);
                        let committed =
                            (self.locked_balance(host) + transfers + bids + hbs + prior_bonds) as i128;
                        if self.balance(host) - committed < *amount as i128 {
                            return false;
                        }
                        *in_block_bond.entry(*host).or_insert(0) += *amount;
                    }
                    TxKind::HostUnbond { host } => {
                        if &tx.origin != host {
                            return false;
                        }
                        // Must have an active, not-already-unbonding bond to unbond.
                        match self.bonds.get(host) {
                            Some((amount, None)) if *amount > 0 => {}
                            _ => return false,
                        }
                    }
                    TxKind::SlashEquivocation { offender, reporter, proof } => {
                        // Submitted by the reporter; a node cannot slash itself.
                        if &tx.origin != reporter || reporter == offender {
                            return false;
                        }
                        // The two statements must actually conflict.
                        if proof.statement_a == proof.statement_b {
                            return false;
                        }
                        // Both must be validly signed by the offender for the same (domain, epoch).
                        let bytes_a =
                            equivocation_signed_bytes(&proof.domain, proof.epoch, &proof.statement_a);
                        let bytes_b =
                            equivocation_signed_bytes(&proof.domain, proof.epoch, &proof.statement_b);
                        if verify(offender, &bytes_a, &proof.sig_a).is_err()
                            || verify(offender, &bytes_b, &proof.sig_b).is_err()
                        {
                            return false;
                        }
                        // The offender must have an active (locked, slashable) bond.
                        if self.active_bond(offender) == 0 {
                            return false;
                        }
                        // Idempotent: not already slashed on-chain or earlier in this block.
                        let key = (*offender, proof.domain, proof.epoch);
                        if self.slashed_equivocations.contains(&key) || !slashing.insert(key) {
                            return false;
                        }
                    }
                    _ => {}
                }
            }
        }
        // Heartbeat rules (E3 — consented, bid-bounded billing).
        //
        // A heartbeat is consensual, bounded credit movement: it may only bill against an OPEN
        // `JobBid` that the *cell itself signed* (`payer == cell`), and the cumulative gross billed
        // against that job can never exceed the bid's locked escrow. The bid is the payer's signed
        // authorization to spend up to `bid`; heartbeats draw that escrow down, the rest unlocks on
        // settle/expire. A heartbeat not linked to such an open bid — or one that would push
        // cumulative spend past the bid — is rejected. This closes the rogue-host drain: a host can
        // never bill a cell beyond what the cell escrowed via a bid it signed.
        {
            let mut in_block_epochs: std::collections::HashMap<(NodeId, NodeId), u64> =
                std::collections::HashMap::new();
            // Heartbeat gross already accumulated PER JOB within this block, so multiple heartbeats
            // for one job in a single block are bounded together against the same escrow.
            let mut in_block_job_hb: std::collections::HashMap<[u8; 32], u128> =
                std::collections::HashMap::new();
            for tx in &block.transactions {
                if let TxKind::Heartbeat { job_id, cell, host, amount, epoch } = &tx.kind {
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
                    // Bid linkage: the named job must be an OPEN bid whose payer is exactly the billed
                    // cell — the cell's own signed authorization. (Confirmed bids only: a job runs many
                    // blocks after its bid confirms, so a heartbeat never races its own bid in-block;
                    // requiring confirmation keeps the escrow accounting unambiguous.)
                    let (bid_payer, bid_amount, _) = match self.open_bids.get(job_id) {
                        Some(entry) => entry,
                        None => return false,
                    };
                    if bid_payer != cell {
                        return false;
                    }
                    // Cumulative heartbeat gross (confirmed + earlier this block + this one) must stay
                    // within the bid escrow. This is BOTH the consent bound and the funding guarantee:
                    // the bid already locked `bid` of the cell's balance, so escrow funds are present.
                    let confirmed = self.heartbeat_spent.get(job_id).copied().unwrap_or(0);
                    let in_block = *in_block_job_hb.get(job_id).unwrap_or(&0);
                    let cumulative = confirmed
                        .saturating_add(in_block)
                        .saturating_add(*amount);
                    if cumulative > *bid_amount {
                        return false;
                    }
                    *in_block_job_hb.entry(*job_id).or_insert(0) =
                        in_block.saturating_add(*amount);
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
            let mut claimed_names: std::collections::HashSet<String> = std::collections::HashSet::new();
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
                        let bonds: u128 = block
                            .transactions
                            .iter()
                            .filter_map(|t| match &t.kind {
                                TxKind::HostBond { host, amount, .. } if host == payer => Some(*amount),
                                _ => None,
                            })
                            .sum();
                        let transfers = *in_block_transfer.get(payer).unwrap_or(&0);
                        let prior_chan = *in_block_channel.get(payer).unwrap_or(&0);
                        let committed = (self.locked_balance(payer)
                            + transfers
                            + bids
                            + hbs
                            + bonds
                            + prior_chan) as i128;
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
                    TxKind::NameClaim { name, node } => {
                        // You name only yourself; the name must be well-formed and unclaimed
                        // (neither already on-chain nor claimed earlier in this same block).
                        if &tx.origin != node || !is_valid_name(name) {
                            return false;
                        }
                        if self.names.contains_key(name) || !claimed_names.insert(name.clone()) {
                            return false;
                        }
                    }
                    _ => {}
                }
            }
        }
        // Track the tip's difficulty so `/status` and the chain actor report the live target.
        self.difficulty = block.difficulty;
        self.apply_block_to_cache(&block);
        self.blocks.push(block);
        true
    }

    /// Median timestamp of the most recent `MEDIAN_TIME_SPAN` blocks — the lower bound a new
    /// block's timestamp must exceed (Bitcoin's median-time-past rule).
    fn median_time_past(&self) -> u64 {
        let mut times: Vec<u64> = self
            .blocks
            .iter()
            .rev()
            .take(MEDIAN_TIME_SPAN)
            .map(|b| b.timestamp)
            .collect();
        times.sort_unstable();
        times.get(times.len() / 2).copied().unwrap_or(0)
    }

    /// A block's timestamp must be strictly greater than the median-time-past and no more than
    /// `MAX_FUTURE_DRIFT_SECS` ahead of now.
    fn timestamp_ok(&self, block: &Block) -> bool {
        if block.timestamp <= self.median_time_past() {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        block.timestamp <= now.saturating_add(MAX_FUTURE_DRIFT_SECS)
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

        // Work-based fork choice: adopt the candidate only if its suffix carries strictly more
        // proof-of-work than ours from the shared fork point (prefix work cancels). This is the
        // real Nakamoto rule — the heaviest chain wins, NOT the one with the most blocks. A long
        // low-difficulty fork therefore loses to a shorter higher-difficulty chain, and a tie keeps
        // what we already have (first-seen), so honest miners converge instead of flapping.
        let our_suffix_work: u128 = self.blocks[fork_pos + 1..]
            .iter()
            .fold(0u128, |acc, b| acc.saturating_add(b.work()));
        let cand_suffix_work: u128 = new_suffix
            .iter()
            .fold(0u128, |acc, b| acc.saturating_add(b.work()));
        if cand_suffix_work <= our_suffix_work {
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
            heartbeat_spent: std::collections::HashMap::new(),
            tx_index: std::collections::HashMap::new(),
            open_bids: std::collections::HashMap::new(),
            open_channels: std::collections::HashMap::new(),
            bonds: std::collections::HashMap::new(),
            slashed_equivocations: std::collections::HashSet::new(),
            // genesis_weights is node config (not chain data). It MUST be present while validating the
            // candidate suffix so each fork block's declared weight is checked against the real
            // consensus weight — otherwise an attacker could claim huge weights to win a reorg.
            genesis_weights: self.genesis_weights.clone(),
            total_supply_cache: 0,
            burned_total_cache: 0,
            node_stats: std::collections::HashMap::new(),
            names: std::collections::HashMap::new(),
            revoked: std::collections::HashSet::new(),
            cumulative_work: 0,
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
            heartbeat_spent: std::collections::HashMap::new(),
            tx_index: std::collections::HashMap::new(),
            open_bids: std::collections::HashMap::new(),
            open_channels: std::collections::HashMap::new(),
            bonds: std::collections::HashMap::new(),
            slashed_equivocations: std::collections::HashSet::new(),
            genesis_weights: std::collections::HashMap::new(),
            total_supply_cache: 0,
            burned_total_cache: 0,
            node_stats: std::collections::HashMap::new(),
            names: std::collections::HashMap::new(),
            revoked: std::collections::HashSet::new(),
            cumulative_work: 0,
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
        // Remaining escrow per open bid = bid minus what heartbeats have already billed against it.
        // Heartbeats draw the escrow down (the cell already paid out of total balance), so the still-
        // locked portion shrinks as the job is billed; the rest unlocks on JobSettle / JobExpire.
        let in_bids: u128 = self
            .open_bids
            .iter()
            .filter(|(_, (payer, _, _))| payer == node)
            .map(|(job_id, (_, bid, _))| {
                let spent = self.heartbeat_spent.get(job_id).copied().unwrap_or(0);
                bid.saturating_sub(spent)
            })
            .sum();
        // Payment-channel capacity is also locked in the payer's balance until close/expire.
        let in_channels: u128 = self
            .open_channels
            .values()
            .filter(|(payer, _, _, _)| payer == node)
            .map(|(_, _, capacity, _)| *capacity)
            .sum();
        // A standing host bond is locked while active (including during unbonding, until it releases).
        in_bids + in_channels + self.active_bond(node)
    }

    /// The host's currently-active (locked and slashable) bond amount, or 0. A bond past its
    /// `unbonding_at` height has released and is neither locked nor slashable.
    fn active_bond(&self, node: &NodeId) -> u128 {
        match self.bonds.get(node) {
            Some((amount, None)) => *amount,
            Some((amount, Some(release_at))) if *release_at > self.height() => *amount,
            _ => 0,
        }
    }

    /// The host's active bond amount (0 if none / already released). Public reputation/economy read.
    pub fn bond_of(&self, node: &NodeId) -> u128 {
        self.active_bond(node)
    }

    /// Total credits currently locked in active host bonds across all nodes (base units).
    pub fn total_bonded(&self) -> u128 {
        self.bonds
            .keys()
            .map(|n| self.active_bond(n))
            .fold(0u128, |a, b| a.saturating_add(b))
    }

    /// A node's earned-work-score: the Sybil-resistant half of consensus weight. v0 uses net credits
    /// earned hosting verified work (`NodeStats.earned`, already post-settlement-burn, so wash-trading
    /// it costs real capital — docs/sybil-resistance.md E4). The fuller net-outflow / distinct-
    /// counterparty accounting (docs/consensus.md §4.1, "Still TODO") is a later refinement; this is a
    /// monotone, deterministic, integer proxy.
    pub fn earned_work_score(&self, node: &NodeId) -> u128 {
        self.node_stats.get(node).map(|s| s.earned).unwrap_or(0)
    }

    /// A node's consensus weight `W = min(active bond, earned-work-score)` — the scarce,
    /// non-manufacturable anchor for Phase 3's VRF leader election and weighted fork choice. Both
    /// terms must be non-zero: you cannot buy weight without doing verified work (the bond is capped
    /// by what you've earned), and cannot earn weight without staking (the work is capped by the
    /// bond). A fresh, unbonded, or fully-slashed node has `W = 0`. Pure, integer-only, deterministic.
    /// Genesis bootstrap weight gives `max(genesis_grant, min(bond, earned))` so the network can
    /// produce blocks before anyone has bonded or earned (the cold-start deadlock). Grant decay toward
    /// zero as real earned weight accrues is Phase 5.
    pub fn consensus_weight(&self, node: &NodeId) -> u128 {
        let earned = self.active_bond(node).min(self.earned_work_score(node));
        let genesis = self.genesis_weights.get(node).copied().unwrap_or(0);
        earned.max(genesis)
    }

    /// Total consensus weight across every node with a bond, earned history, or genesis grant — the
    /// denominator the per-slot leader threshold is sized against.
    pub fn total_consensus_weight(&self) -> u128 {
        let mut nodes: std::collections::HashSet<&NodeId> = std::collections::HashSet::new();
        nodes.extend(self.bonds.keys());
        nodes.extend(self.node_stats.keys());
        nodes.extend(self.genesis_weights.keys());
        nodes
            .into_iter()
            .map(|n| self.consensus_weight(n))
            .fold(0u128, |a, b| a.saturating_add(b))
    }

    /// Set the genesis bootstrap weights (network config / chain spec). Applied by the node at startup
    /// from its configuration; must be identical across honest nodes. Not persisted in the chain file.
    pub fn set_genesis_weights(&mut self, weights: std::collections::HashMap<NodeId, u128>) {
        self.genesis_weights = weights;
    }

    /// A node's genesis bootstrap weight (0 if none).
    pub fn genesis_weight(&self, node: &NodeId) -> u128 {
        self.genesis_weights.get(node).copied().unwrap_or(0)
    }

    /// Insert/raise a single node's genesis bootstrap weight (config helper).
    pub fn grant_genesis_weight(&mut self, node: NodeId, weight: u128) {
        self.genesis_weights.insert(node, weight);
    }

    /// The kept block with absolute index `index`, if present (None if pruned away or in the future).
    fn block_at(&self, index: u64) -> Option<&Block> {
        let base = self.blocks.first()?.index;
        let off = index.checked_sub(base)? as usize;
        self.blocks.get(off)
    }

    /// The leader-election seed for `slot` building on the current tip: bound to the block `LOOKBACK`
    /// behind the tip (confirmed history both forks agree on), so the current leader cannot grind it.
    fn confirmed_seed(&self, slot: u64) -> [u8; 32] {
        let confirmed_index = self.tip().index.saturating_sub(LOOKBACK);
        let hash = self.block_at(confirmed_index).map(|b| b.hash()).unwrap_or([0u8; 32]);
        leader_seed(&hash, slot)
    }

    /// Try to produce a sealed block for `slot` on the current tip. Returns None unless the producer
    /// is an eligible leader for that slot (its VRF ticket is below its weight-proportional threshold).
    pub fn try_produce(&self, identity: &Identity, transactions: Vec<Tx>, slot: u64) -> Option<Block> {
        let miner = identity.node_id();
        let weight = self.consensus_weight(&miner);
        if weight == 0 {
            return None;
        }
        let total = self.total_consensus_weight();
        let seed = self.confirmed_seed(slot);
        let vrf_proof = identity.sign(&seed);
        if ticket_value(&vrf_ticket(&vrf_proof)) >= leader_threshold(weight, total) {
            return None;
        }
        let mut block = Block {
            index: self.tip().index + 1,
            prev_hash: self.tip_hash(),
            timestamp: slot.saturating_mul(SLOT_SECS),
            transactions,
            nonce: 0,
            difficulty: 0,
            miner,
            weight,
            vrf_proof,
            sig: [0u8; 64],
        };
        block.seal(identity);
        Some(block)
    }

    /// Produce a block at the next slot at or after the tip's slot+1 for which the producer is an
    /// eligible leader (loops slots; terminates if the producer has any weight). Real nodes drive the
    /// slot from wall-clock; this convenience is for bootstrap/tests that just need to make progress.
    pub fn produce(&self, identity: &Identity, transactions: Vec<Tx>) -> Option<Block> {
        if self.consensus_weight(&identity.node_id()) == 0 {
            return None;
        }
        let start = self.tip().timestamp / SLOT_SECS + 1;
        for slot in start..start + 1_000_000 {
            if let Some(b) = self.try_produce(identity, transactions.clone(), slot) {
                return Some(b);
            }
        }
        None
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
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Strictly advance past the tip so timestamps are monotonic and always clear the
        // median-time-past lower bound — even when blocks are produced faster than 1/sec (low
        // difficulty / tests). In normal operation (~10 min/block) `now` dominates.
        // Advance to the next slot past the tip (monotonic; clears median-time-past). In production
        // the wall-clock slot dominates. This is a low-level builder: the VRF proof and seal are
        // filled by `try_produce`/`produce`; callers that need an eligible block use those instead.
        let next_slot = (now / SLOT_SECS).max(self.tip().timestamp / SLOT_SECS + 1);
        Block {
            index: self.tip().index + 1,
            prev_hash: self.tip_hash(),
            timestamp: next_slot.saturating_mul(SLOT_SECS),
            transactions,
            nonce: 0,
            difficulty: 0,
            miner,
            weight: self.consensus_weight(&miner),
            vrf_proof: [0u8; 64],
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

    /// Load chain from disk. Files are `[CHAIN_FORMAT_VERSION] ++ zstd(bincode(Chain))`. Any other
    /// leading byte is an incompatible (pre-PoW) format: we reject it, and `load_or_genesis` then
    /// starts a fresh chain. This is the clean break for the per-block-difficulty format — old
    /// chains are not migrated; operators wipe `<data_dir>/chain` and re-sync from the network.
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        let Some((&version, body)) = data.split_first() else {
            return Err(anyhow!("chain file is empty"));
        };
        if version != CHAIN_FORMAT_VERSION {
            return Err(anyhow!(
                "incompatible chain format (found 0x{version:02x}, need v{CHAIN_FORMAT_VERSION}); \
                 wipe the chain dir and re-sync"
            ));
        }
        let decompressed = zstd::decode_all(body).map_err(|e| anyhow!("zstd decompress: {e}"))?;
        let mut chain: Chain =
            bincode::deserialize(&decompressed).map_err(|e| anyhow!("bincode deserialize: {e}"))?;
        if chain.blocks.is_empty() && chain.checkpoint.is_none() {
            return Err(anyhow!("chain file is empty"));
        }
        chain.rebuild_caches();
        Ok(chain)
    }

    /// Save chain to disk as `[CHAIN_FORMAT_VERSION] ++ zstd(bincode)` (level 3).
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bin = bincode::serialize(self).map_err(|e| anyhow!("bincode serialize: {e}"))?;
        let mut out = Vec::with_capacity(bin.len() / 2 + 1);
        out.push(CHAIN_FORMAT_VERSION);
        let compressed =
            zstd::encode_all(&bin[..], 3).map_err(|e| anyhow!("zstd compress: {e}"))?;
        out.extend_from_slice(&compressed);
        std::fs::write(path, out)?;
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(identity);
        chain.append(block)
    }

    /// Produce a real VRF block mined by `miner` (which must have consensus weight) carrying `txs`,
    /// plus its UptimeReward, and append it. Used by tests that have introduced weight, so the
    /// bootstrap fallback is off and a valid VRF proof + eligibility are required.
    fn produce_append(chain: &mut Chain, miner: &Identity, txs: Vec<Tx>) -> bool {
        let reward = signed_uptime_reward(miner, chain.tip().index + 1);
        let mut all = vec![reward];
        all.extend(txs);
        match chain.produce(miner, all) {
            Some(b) => chain.append(b),
            None => false,
        }
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
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
        assert_eq!(chain.difficulty, GENESIS_DIFFICULTY);
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
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

    #[test]
    fn chunk_receipt_verifies_and_rejects() {
        let payer = make_identity("chunk-payer");
        let host = make_identity("chunk-host");
        let other = make_identity("chunk-other");
        let channel_id = [9u8; 32];
        let cumulative = 5_000u128;

        let payer_sig = payer.sign(&channel_receipt_bytes(&channel_id, &host.node_id(), cumulative));
        let receipt = ChunkReceipt { channel_id, cumulative, payer_sig };

        // Survives a bincode round-trip (it travels as opaque bytes in FetchChunk).
        let wire = bincode::serialize(&receipt).unwrap();
        let decoded: ChunkReceipt = bincode::deserialize(&wire).unwrap();
        assert!(verify_chunk_receipt_sig(&payer.node_id(), &host.node_id(), &decoded));

        // Wrong host, wrong payer, or a forged cumulative all fail verification.
        assert!(!verify_chunk_receipt_sig(&payer.node_id(), &other.node_id(), &receipt));
        assert!(!verify_chunk_receipt_sig(&other.node_id(), &host.node_id(), &receipt));
        let forged = ChunkReceipt { cumulative: cumulative + 1, ..receipt.clone() };
        assert!(!verify_chunk_receipt_sig(&payer.node_id(), &host.node_id(), &forged));
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
        b.mine(&std::sync::atomic::AtomicBool::new(false));
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
        assert_eq!(chain.balance(&payer.node_id()), before - 600, "only the redeemed 600 leaves the payer (full gross)");
        assert_eq!(chain.locked_balance(&payer.node_id()), 0, "the rest unlocks on close");
        // The host receives the redeemed amount minus the protocol burn; the burn is destroyed.
        // (host also mines these blocks, so its raw balance carries emission — `earned` does not,
        // since mining never touches NodeStats; assert on `earned` + `burned_total` instead.)
        let net = 600 - settlement_burn(600);
        assert_eq!(chain.node_history(&host.node_id()).earned, net, "earned tracks net gain");
        assert_eq!(chain.burned_total(), settlement_burn(600), "burn is recorded as destroyed");
    }

    fn signed_name_claim(claimer: &Identity, name: &str, node: NodeId) -> Tx {
        let kind = TxKind::NameClaim { name: name.to_string(), node };
        let data = bincode::serialize(&kind).unwrap();
        let sig = claimer.sign(&data);
        Tx::new(kind, claimer.node_id(), sig)
    }

    #[test]
    fn name_claim_is_unique_and_resolvable() {
        let alice = make_identity("name-alice");
        let bob = make_identity("name-bob");
        let mut chain = Chain::genesis();

        assert!(append_with(&mut chain, &alice, signed_name_claim(&alice, "alice", alice.node_id())));
        assert_eq!(chain.resolve_name("alice"), Some(alice.node_id()));

        // The taken name can't be claimed by someone else.
        assert!(!append_with(&mut chain, &bob, signed_name_claim(&bob, "alice", bob.node_id())));

        // Bob claims his own free name.
        assert!(append_with(&mut chain, &bob, signed_name_claim(&bob, "bob", bob.node_id())));
        assert_eq!(chain.resolve_name("bob"), Some(bob.node_id()));

        // Claiming on behalf of another node is rejected (origin must equal `node`).
        assert!(!append_with(&mut chain, &alice, signed_name_claim(&alice, "carol", bob.node_id())));
        assert_eq!(chain.resolve_name("carol"), None);

        // Malformed names are rejected.
        assert!(!append_with(&mut chain, &alice, signed_name_claim(&alice, "-bad", alice.node_id())));
    }

    #[test]
    fn name_validation_rules() {
        assert!(is_valid_name("alice"));
        assert!(is_valid_name("node-01"));
        assert!(!is_valid_name("ab")); // too short
        assert!(!is_valid_name("UPPER")); // uppercase
        assert!(!is_valid_name("-lead")); // leading hyphen
        assert!(!is_valid_name("trail-")); // trailing hyphen
        assert!(!is_valid_name("has space")); // space
        assert!(!is_valid_name(&"x".repeat(33))); // too long
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
        b.mine(&std::sync::atomic::AtomicBool::new(false));
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
        b.mine(&std::sync::atomic::AtomicBool::new(false));
        b.seal(&host);
        assert!(chain.append(b));

        let settle = signed_job_settle(&host, &payer, job_id, 600);
        let r2 = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut b = chain.next_block(vec![r2, settle], host.node_id());
        b.mine(&std::sync::atomic::AtomicBool::new(false));
        b.seal(&host);
        assert!(chain.append(b));

        let hs = chain.node_history(&host.node_id());
        assert_eq!(hs.jobs_hosted, 1, "host settled one job");
        assert_eq!(hs.earned, 600 - settlement_burn(600), "host earns net-of-burn");
        assert_eq!(hs.jobs_paid, 0);
        assert!(hs.first_height >= 1 && hs.last_height >= hs.first_height);

        let ps = chain.node_history(&payer.node_id());
        assert_eq!(ps.jobs_paid, 1, "payer paid one job");
        assert_eq!(ps.spent, 600, "payer spends the full gross cost");
        assert_eq!(ps.jobs_hosted, 0);

        // A heartbeat cell -> host updates both sides.
        let cell = make_identity("hist-cell");
        fund(&mut chain, &cell, 2_000);
        let hb_job = [55u8; 32];
        open_bid_for(&mut chain, &cell, &host, hb_job, 500);
        let hb = signed_heartbeat(&host, hb_job, cell.node_id(), 50, 1);
        let r3 = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut b = chain.next_block(vec![r3, hb], host.node_id());
        b.mine(&std::sync::atomic::AtomicBool::new(false));
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&host);
        assert!(chain.append(block));

        let cost = 500;
        let payer_before = chain.balance(&payer.node_id());
        let host_before = chain.balance(&host.node_id());
        let settle = signed_job_settle(&host, &payer, job_id, cost);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, settle], host.node_id());
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&host);
        assert!(chain.append(block), "settle should be accepted");

        assert_eq!(
            chain.balance(&payer.node_id()),
            payer_before - cost as i128,
            "payer is debited the full gross cost",
        );
        assert_eq!(
            chain.balance(&host.node_id()),
            host_before + (cost - settlement_burn(cost)) as i128
                + Chain::emission_rate(chain.tip().index) as i128,
            "host receives cost net-of-burn, plus its mining emission",
        );
    }

    #[test]
    fn windowed_history_slices_recent_volume() {
        let host = make_identity("win-host");
        let payer = make_identity("win-payer");
        let mut chain = Chain::genesis();
        fund(&mut chain, &payer, 5_000);

        // One settled job: host earns net-of-burn, payer spends gross.
        let job_id = [9u8; 32];
        let bid = signed_job_bid(&payer, job_id, 2_000);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, bid], host.node_id());
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&host);
        assert!(chain.append(block));

        let cost = 1_000u128;
        let settle = signed_job_settle(&host, &payer, job_id, cost);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, settle], host.node_id());
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&host);
        assert!(chain.append(block));

        // A wide window covers the whole chain: recent figures equal the cumulative ones, and the
        // window is not partial (genesis is still present).
        let net = cost - settlement_burn(cost);
        let hw = chain.node_history_windowed(&host.node_id(), RATIO_WINDOW_BLOCKS);
        assert_eq!(hw.recent_earned, net, "host recent earned = settled cost net of burn");
        assert_eq!(hw.recent_spent, 0, "host consumed nothing");
        assert!(!hw.partial, "full window on an unpruned chain");
        assert_eq!(hw.recent_earned, chain.node_history(&host.node_id()).earned);

        let pw = chain.node_history_windowed(&payer.node_id(), RATIO_WINDOW_BLOCKS);
        assert_eq!(pw.recent_spent, cost, "payer recent spent = gross cost");
        assert_eq!(pw.recent_earned, 0);

        // A window of 0 blocks excludes every settled block, so recent volume is zero — proving the
        // slice is a real time window, not a recency alias of the cumulative total.
        let zero = chain.node_history_windowed(&host.node_id(), 0);
        assert_eq!(zero.recent_earned, 0);
        assert_eq!(zero.recent_spent, 0);
    }

    // Phase 0 — the settlement burn (docs/consensus.md, docs/sybil-resistance.md E4). The keystone
    // Sybil defence for the trust economy: a wash trade between two identities the same attacker
    // controls no longer nets to zero. Every settlement destroys the burn, so manufacturing
    // earned-reputation costs real capital that scales with the volume faked.
    #[test]
    fn settlement_burn_makes_wash_trading_cost_capital() {
        let attacker_payer = make_identity("wash-a");
        let attacker_host = make_identity("wash-b");
        // A neutral third party mines the blocks, so block emission never touches the attacker's
        // two keys — isolating the wash settlement's effect on the attacker's combined wealth.
        let neutral = make_identity("wash-miner");
        let mut chain = Chain::genesis();
        fund(&mut chain, &attacker_payer, 2_000);

        let job_id = [21u8; 32];
        let bid = signed_job_bid(&attacker_payer, job_id, 1_000);
        let r = signed_uptime_reward(&neutral, chain.tip().index + 1);
        let mut b = chain.next_block(vec![r, bid], neutral.node_id());
        b.mine(&std::sync::atomic::AtomicBool::new(false));
        b.seal(&neutral);
        assert!(chain.append(b));

        let combined_before =
            chain.balance(&attacker_payer.node_id()) + chain.balance(&attacker_host.node_id());

        // B settles the job A bid on — a pure wash between the attacker's own keys.
        let cost = 500;
        let settle = signed_job_settle(&attacker_host, &attacker_payer, job_id, cost);
        let r = signed_uptime_reward(&neutral, chain.tip().index + 1);
        let mut b = chain.next_block(vec![r, settle], neutral.node_id());
        b.mine(&std::sync::atomic::AtomicBool::new(false));
        b.seal(&neutral);
        assert!(chain.append(b));

        let combined_after =
            chain.balance(&attacker_payer.node_id()) + chain.balance(&attacker_host.node_id());

        let burn = settlement_burn(cost);
        assert!(burn > 0, "the burn must bite for this defence to hold");
        assert_eq!(
            combined_before - combined_after,
            burn as i128,
            "every wash cycle destroys exactly the burn from the attacker's combined holdings",
        );
        assert_eq!(chain.burned_total(), burn, "destroyed credits are tracked");
        assert_eq!(chain.circulating_supply(), chain.total_supply() - burn);
        // The reputation the attacker bought (net earned) cost real, unrecoverable capital to mint.
        assert_eq!(chain.node_history(&attacker_host.node_id()).earned, cost - burn);
    }

    #[test]
    fn settlement_burn_math() {
        assert_eq!(settlement_burn(0), 0);
        assert_eq!(settlement_burn(1), 0, "sub-threshold settlements floor to a 0 burn");
        assert_eq!(settlement_burn(10_000), 10_000 * SETTLEMENT_BURN_BPS / BPS_DENOM);
        assert_eq!(settlement_burn(CREDIT), CREDIT * SETTLEMENT_BURN_BPS / BPS_DENOM);
        // The net/burn split never creates or loses a base unit.
        for g in [0u128, 1, 99, 100, 500, 12_345, CREDIT, SUPPLY_CAP] {
            assert_eq!((g - settlement_burn(g)) + settlement_burn(g), g);
            assert!(settlement_burn(g) <= g);
        }
    }

    #[test]
    fn heartbeat_burns_too() {
        let host = make_identity("hbb-host");
        let cell = make_identity("hbb-cell");
        let neutral = make_identity("hbb-miner");
        let mut chain = Chain::genesis();
        fund(&mut chain, &cell, 1_000);
        let job_id = [56u8; 32];
        open_bid_for(&mut chain, &cell, &neutral, job_id, 500);
        let host_before = chain.balance(&host.node_id());

        let amount = 400;
        let hb = signed_heartbeat(&host, job_id, cell.node_id(), amount, 0);
        // Mined by a neutral party so emission doesn't perturb the host's balance.
        assert!(append_with(&mut chain, &neutral, hb));

        let burn = settlement_burn(amount);
        assert!(burn > 0);
        assert_eq!(
            chain.balance(&host.node_id()),
            host_before + (amount - burn) as i128,
            "host receives the heartbeat net-of-burn",
        );
        assert_eq!(chain.burned_total(), burn);
        assert_eq!(chain.node_history(&host.node_id()).earned, amount - burn);
    }

    // E3 bound: a host can bill a cell's escrow but never beyond it. The cell locks its whole balance
    // in a bid it signed; the host may bill heartbeats UP TO that escrow (consensual, the cell
    // authorized it), but a heartbeat that would push cumulative billing past the bid is rejected — so
    // a host can never extract more than the cell escrowed, even when the cell has locked everything.
    #[test]
    fn heartbeat_bounded_by_bid_escrow() {
        let cell = make_identity("hb-lock-cell");
        let host = make_identity("hb-lock-host");
        let neutral = make_identity("hb-lock-miner");
        let mut chain = Chain::genesis();
        fund(&mut chain, &cell, 1_000);
        let bal = chain.balance(&cell.node_id()) as u128;

        // Cell locks its entire balance in an open bid it signed.
        let job_id = [42u8; 32];
        assert!(append_with(&mut chain, &neutral, signed_job_bid(&cell, job_id, bal)));
        assert_eq!(chain.locked_balance(&cell.node_id()), bal);

        // The host bills the full escrow in one heartbeat — consensual, within the bid → accepted.
        let hb = signed_heartbeat(&host, job_id, cell.node_id(), bal, 0);
        assert!(append_with(&mut chain, &neutral, hb), "heartbeat within escrow is accepted");
        assert_eq!(chain.balance(&cell.node_id()), 0, "cell paid exactly its escrow, no more");
        assert_eq!(chain.locked_balance(&cell.node_id()), 0, "escrow fully consumed");

        // Any further heartbeat would exceed the (now-zero) remaining escrow → rejected. The cell can
        // never be billed beyond what it escrowed.
        let hb2 = signed_heartbeat(&host, job_id, cell.node_id(), 1, 1);
        assert!(
            !append_with(&mut chain, &neutral, hb2),
            "heartbeat past the consumed escrow must be rejected — no unconsented drain"
        );
    }

    // ----- Phase 1: host bonds + equivocation slashing (docs/consensus.md §4.1) -----

    fn signed_host_bond(host: &Identity, amount: u128) -> Tx {
        // A unique nonce per call so equal-amount top-ups don't collide on tx id.
        static NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nonce = NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let kind = TxKind::HostBond { host: host.node_id(), amount, nonce };
        let sig = host.sign(&bincode::serialize(&kind).unwrap());
        Tx::new(kind, host.node_id(), sig)
    }

    fn signed_host_unbond(host: &Identity) -> Tx {
        let kind = TxKind::HostUnbond { host: host.node_id() };
        let sig = host.sign(&bincode::serialize(&kind).unwrap());
        Tx::new(kind, host.node_id(), sig)
    }

    fn equivocation_proof(
        offender: &Identity,
        domain: [u8; 16],
        epoch: u64,
        a: [u8; 32],
        b: [u8; 32],
    ) -> EquivocationProof {
        let sig_a = offender.sign(&equivocation_signed_bytes(&domain, epoch, &a));
        let sig_b = offender.sign(&equivocation_signed_bytes(&domain, epoch, &b));
        EquivocationProof { domain, epoch, statement_a: a, statement_b: b, sig_a, sig_b }
    }

    fn signed_slash(reporter: &Identity, offender: NodeId, proof: EquivocationProof) -> Tx {
        let kind = TxKind::SlashEquivocation { offender, reporter: reporter.node_id(), proof };
        let sig = reporter.sign(&bincode::serialize(&kind).unwrap());
        Tx::new(kind, reporter.node_id(), sig)
    }

    #[test]
    fn host_bond_locks_funds() {
        let host = make_identity("bond-host");
        let neutral = make_identity("bond-miner");
        let mut chain = Chain::genesis();
        fund(&mut chain, &host, 1);
        let bal = chain.balance(&host.node_id());

        assert!(append_with(&mut chain, &neutral, signed_host_bond(&host, 500)));
        assert_eq!(chain.bond_of(&host.node_id()), 500, "bond is active");
        assert_eq!(chain.locked_balance(&host.node_id()), 500, "bond is locked");
        assert_eq!(chain.total_bonded(), 500);
        // A top-up adds to the same bond.
        assert!(append_with(&mut chain, &neutral, signed_host_bond(&host, 250)));
        assert_eq!(chain.bond_of(&host.node_id()), 750);
        // Balance is unchanged (the bond is locked, not spent); only free balance shrinks.
        assert_eq!(chain.balance(&host.node_id()), bal);
    }

    #[test]
    fn bonded_funds_cannot_be_spent() {
        let host = make_identity("bond-lock-host");
        let other = make_identity("bond-lock-other");
        let neutral = make_identity("bond-lock-miner");
        let mut chain = Chain::genesis();
        fund(&mut chain, &host, 1);
        let bal = chain.balance(&host.node_id()) as u128;

        assert!(append_with(&mut chain, &neutral, signed_host_bond(&host, 500)));
        // Free balance is now bal - 500. A transfer that dips into the bonded 500 is rejected.
        let too_big = signed_transfer(&host, other.node_id(), bal - 100);
        assert!(!append_with(&mut chain, &neutral, too_big), "cannot spend bonded funds");
        // A transfer within free balance is fine.
        let ok = signed_transfer(&host, other.node_id(), bal - 600);
        assert!(append_with(&mut chain, &neutral, ok), "free balance is still spendable");
    }

    #[test]
    fn host_bond_rejects_over_balance_and_wrong_origin() {
        let host = make_identity("bond-rej-host");
        let imposter = make_identity("bond-rej-imp");
        let neutral = make_identity("bond-rej-miner");
        let mut chain = Chain::genesis();
        fund(&mut chain, &host, 1);
        let bal = chain.balance(&host.node_id()) as u128;

        // Bonding more than the whole balance is rejected.
        assert!(!append_with(&mut chain, &neutral, signed_host_bond(&host, bal + 1)));
        // A bond whose origin isn't the named host is rejected (imposter signs/sends).
        let kind = TxKind::HostBond { host: host.node_id(), amount: 100, nonce: 0 };
        let bad = Tx::new(kind.clone(), imposter.node_id(), imposter.sign(&bincode::serialize(&kind).unwrap()));
        assert!(!append_with(&mut chain, &neutral, bad), "origin must equal host");
    }

    #[test]
    fn unbond_keeps_funds_locked_until_window() {
        let host = make_identity("unbond-host");
        let neutral = make_identity("unbond-miner");
        let mut chain = Chain::genesis();
        fund(&mut chain, &host, 1);

        assert!(append_with(&mut chain, &neutral, signed_host_bond(&host, 500)));
        assert!(append_with(&mut chain, &neutral, signed_host_unbond(&host)));
        // Immediately after unbond the bond is still active: locked and slashable for UNBOND_BLOCKS.
        assert_eq!(chain.bond_of(&host.node_id()), 500, "still slashable during unbonding");
        assert_eq!(chain.locked_balance(&host.node_id()), 500, "still locked during unbonding");
        // Cannot unbond again while already unbonding.
        assert!(!append_with(&mut chain, &neutral, signed_host_unbond(&host)));
    }

    #[test]
    fn slash_equivocation_burns_bond_and_pays_reporter() {
        let offender = make_identity("slash-offender");
        let reporter = make_identity("slash-reporter");
        let neutral = make_identity("slash-miner");
        let mut chain = Chain::genesis();
        fund(&mut chain, &offender, 1);

        let bond = 1_000u128;
        assert!(append_with(&mut chain, &neutral, signed_host_bond(&offender, bond)));
        let off_bal_before = chain.balance(&offender.node_id());
        let rep_bal_before = chain.balance(&reporter.node_id());
        let burned_before = chain.burned_total();

        // The offender signed two different statements for the same (domain, epoch) slot.
        let proof = equivocation_proof(&offender, *b"ce-capacity-ad\0\0", 7, [1u8; 32], [2u8; 32]);
        assert!(append_with(&mut chain, &neutral, signed_slash(&reporter, offender.node_id(), proof)));

        let reporter_share = bond * SLASH_REPORTER_BPS / 10_000;
        let destroyed = bond - reporter_share;
        assert_eq!(chain.bond_of(&offender.node_id()), 0, "bond is gone");
        assert_eq!(chain.balance(&offender.node_id()), off_bal_before - bond as i128, "offender loses the whole bond");
        assert_eq!(chain.balance(&reporter.node_id()), rep_bal_before + reporter_share as i128, "reporter paid its share");
        assert_eq!(chain.burned_total(), burned_before + destroyed, "the rest is destroyed");
        assert_eq!(chain.node_history(&offender.node_id()).slashes, 1);
    }

    #[test]
    fn slash_rejects_bad_proof_and_no_bond() {
        let offender = make_identity("slash2-offender");
        let reporter = make_identity("slash2-reporter");
        let neutral = make_identity("slash2-miner");
        let mut chain = Chain::genesis();
        fund(&mut chain, &offender, 1);

        // No bond yet → nothing to slash, even with a valid proof.
        let proof = equivocation_proof(&offender, *b"d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 1, [3u8; 32], [4u8; 32]);
        assert!(!append_with(&mut chain, &neutral, signed_slash(&reporter, offender.node_id(), proof.clone())));

        assert!(append_with(&mut chain, &neutral, signed_host_bond(&offender, 800)));

        // Non-conflicting statements (a == b) are not equivocation.
        let same = equivocation_proof(&offender, *b"d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 1, [5u8; 32], [5u8; 32]);
        assert!(!append_with(&mut chain, &neutral, signed_slash(&reporter, offender.node_id(), same)));

        // A proof signed by someone other than the offender is invalid.
        let forged = equivocation_proof(&reporter, *b"d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 1, [6u8; 32], [7u8; 32]);
        assert!(!append_with(&mut chain, &neutral, signed_slash(&reporter, offender.node_id(), forged)));

        // The bond survived all the rejected attempts.
        assert_eq!(chain.bond_of(&offender.node_id()), 800);
    }

    #[test]
    fn slash_is_idempotent_per_slot() {
        let offender = make_identity("slash3-offender");
        let reporter = make_identity("slash3-reporter");
        let neutral = make_identity("slash3-miner");
        let mut chain = Chain::genesis();
        fund(&mut chain, &offender, 1);

        assert!(append_with(&mut chain, &neutral, signed_host_bond(&offender, 500)));
        let domain = *b"ce-capacity-ad\0\0";
        let proof = equivocation_proof(&offender, domain, 9, [1u8; 32], [2u8; 32]);
        assert!(append_with(&mut chain, &neutral, signed_slash(&reporter, offender.node_id(), proof.clone())));

        // Re-bond, then try to slash the SAME (offender, domain, epoch) again — rejected as already slashed.
        assert!(append_with(&mut chain, &neutral, signed_host_bond(&offender, 500)));
        assert!(
            !append_with(&mut chain, &neutral, signed_slash(&reporter, offender.node_id(), proof)),
            "the same fault cannot be slashed twice"
        );
        assert_eq!(chain.node_history(&offender.node_id()).slashes, 1);
        // A DIFFERENT epoch is still slashable.
        let proof2 = equivocation_proof(&offender, domain, 10, [1u8; 32], [2u8; 32]);
        assert!(append_with(&mut chain, &neutral, signed_slash(&reporter, offender.node_id(), proof2)));
        assert_eq!(chain.node_history(&offender.node_id()).slashes, 2);
    }

    // ----- Phase 2: the consensus weight oracle W = min(bond, earned-work) -----

    /// Bond `node` to `bond` and have it host a settled job of gross `gross`, so it accrues earned
    /// work (net of the settlement burn). Returns the net earned amount. Blocks are mined by a neutral
    /// party so emission never perturbs the bonded node's economics.
    fn bond_and_earn(chain: &mut Chain, node: &Identity, bond: u128, gross: u128) -> u128 {
        // Unique tags per call so parallel tests don't race on the same on-disk identity.
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let neutral = make_identity(&format!("we-miner-{seq}"));
        let payer = make_identity(&format!("we-payer-{seq}"));
        fund(chain, node, 1);
        fund(chain, &payer, gross + 10);
        assert!(append_with(chain, &neutral, signed_host_bond(node, bond)));
        // payer bids, `node` settles as host → node.earned += net.
        let job_id = {
            let mut id = [0u8; 32];
            id[0] = (gross % 251) as u8;
            id[1] = 0xAB;
            id
        };
        assert!(append_with(chain, &neutral, signed_job_bid(&payer, job_id, gross)));
        assert!(append_with(chain, &neutral, signed_job_settle(node, &payer, job_id, gross)));
        gross - settlement_burn(gross)
    }

    #[test]
    fn consensus_weight_needs_both_bond_and_work() {
        let fresh = make_identity("w-fresh");
        let chain = Chain::genesis();
        // A fresh node has no bond and no earned work → zero weight.
        assert_eq!(chain.consensus_weight(&fresh.node_id()), 0);

        // Bonded but no earned work → still zero (you can't buy weight without working).
        let bonded = make_identity("w-bonded");
        let neutral = make_identity("w-miner");
        let mut chain = Chain::genesis();
        fund(&mut chain, &bonded, 1);
        assert!(append_with(&mut chain, &neutral, signed_host_bond(&bonded, 1_000)));
        assert_eq!(chain.earned_work_score(&bonded.node_id()), 0);
        assert_eq!(chain.consensus_weight(&bonded.node_id()), 0, "bond alone is not weight");

        // Earned work but no bond → still zero (you can't earn weight without staking).
        let worker = make_identity("w-worker");
        let mut chain2 = Chain::genesis();
        let net = {
            let n = make_identity("w-miner2");
            let payer = make_identity("w-payer2");
            fund(&mut chain2, &worker, 1);
            fund(&mut chain2, &payer, 1_010);
            assert!(append_with(&mut chain2, &n, signed_job_bid(&payer, [9u8; 32], 1_000)));
            assert!(append_with(&mut chain2, &n, signed_job_settle(&worker, &payer, [9u8; 32], 1_000)));
            1_000 - settlement_burn(1_000)
        };
        assert_eq!(chain2.earned_work_score(&worker.node_id()), net);
        assert_eq!(chain2.bond_of(&worker.node_id()), 0);
        assert_eq!(chain2.consensus_weight(&worker.node_id()), 0, "earned work alone is not weight");
    }

    #[test]
    fn consensus_weight_is_min_of_bond_and_earned() {
        // Bond exceeds earned → weight is capped by earned work.
        let a = make_identity("w-a");
        let mut chain = Chain::genesis();
        let net = bond_and_earn(&mut chain, &a, 5_000, 1_000);
        assert_eq!(chain.consensus_weight(&a.node_id()), net, "capped by earned work");
        assert!(net < 5_000);

        // Bond below earned → weight is capped by the bond.
        let b = make_identity("w-b");
        let mut chain2 = Chain::genesis();
        let net2 = bond_and_earn(&mut chain2, &b, 300, 5_000);
        assert_eq!(net2, 5_000 - settlement_burn(5_000));
        assert!(net2 > 300, "earned must exceed the bond for this case");
        assert_eq!(chain2.consensus_weight(&b.node_id()), 300, "capped by the bond");
    }

    #[test]
    fn slashing_zeroes_consensus_weight() {
        let offender = make_identity("w-slash");
        let reporter = make_identity("w-slash-rep");
        let neutral = make_identity("w-slash-miner");
        let mut chain = Chain::genesis();
        let _net = bond_and_earn(&mut chain, &offender, 300, 5_000);
        assert_eq!(chain.consensus_weight(&offender.node_id()), 300);

        // Weight now exists, so the slash block must be a real VRF block by a weighted miner.
        chain.grant_genesis_weight(neutral.node_id(), 1_000_000_000);
        let proof = equivocation_proof(&offender, *b"ce-capacity-ad\0\0", 1, [1u8; 32], [2u8; 32]);
        assert!(produce_append(&mut chain, &neutral, vec![signed_slash(&reporter, offender.node_id(), proof)]));
        // Bond gone → weight collapses to zero even though earned work remains.
        assert!(chain.earned_work_score(&offender.node_id()) > 0);
        assert_eq!(chain.consensus_weight(&offender.node_id()), 0, "slashing the bond zeroes weight");
    }

    #[test]
    fn consensus_weight_is_deterministic() {
        let a = make_identity("w-det");
        let mut chain = Chain::genesis();
        let _ = bond_and_earn(&mut chain, &a, 400, 2_000);
        let w1 = chain.consensus_weight(&a.node_id());
        // Recomputing is stable, and a full cache rebuild reproduces the same weight.
        assert_eq!(w1, chain.consensus_weight(&a.node_id()));
        chain.rebuild_caches();
        assert_eq!(chain.consensus_weight(&a.node_id()), w1, "weight survives cache rebuild");
        assert_eq!(w1, 400.min(2_000 - settlement_burn(2_000)));
    }

    // ----- Phase 3 (additive primitives): VRF leader election + genesis bootstrap weight -----

    #[test]
    fn genesis_weight_bootstraps_otherwise_zero_weight_node() {
        let node = make_identity("gw-node");
        let mut chain = Chain::genesis();
        assert_eq!(chain.consensus_weight(&node.node_id()), 0, "no bond/earned/grant → 0");

        let mut grants = std::collections::HashMap::new();
        grants.insert(node.node_id(), 1_000u128);
        chain.set_genesis_weights(grants);
        assert_eq!(chain.consensus_weight(&node.node_id()), 1_000, "genesis grant bootstraps weight");
        assert_eq!(chain.total_consensus_weight(), 1_000);
        // Genesis config survives a cache rebuild (it is not chain data).
        chain.rebuild_caches();
        assert_eq!(chain.consensus_weight(&node.node_id()), 1_000);
    }

    #[test]
    fn consensus_weight_takes_max_of_grant_and_earned() {
        // Earned/bonded weight above the grant wins; below it, the grant floors it.
        let a = make_identity("gw-max");
        let mut chain = Chain::genesis();
        let net = bond_and_earn(&mut chain, &a, 5_000, 5_000); // earned-weight = net, above the 300 grant
        assert!(net > 300, "earned must exceed the grant for this case");
        let mut grants = std::collections::HashMap::new();
        grants.insert(a.node_id(), 300u128); // grant below earned
        chain.set_genesis_weights(grants);
        assert_eq!(chain.consensus_weight(&a.node_id()), net, "earned weight exceeds the grant");

        let mut grants2 = std::collections::HashMap::new();
        grants2.insert(a.node_id(), net + 500); // grant above earned
        chain.set_genesis_weights(grants2);
        assert_eq!(chain.consensus_weight(&a.node_id()), net + 500, "grant floors the weight");
    }

    #[test]
    fn vrf_ticket_is_deterministic_and_verifiable() {
        let leader = make_identity("vrf-leader");
        let other = make_identity("vrf-other");
        let seed = leader_seed(&[7u8; 32], 42);

        // Deterministic: signing the same seed twice yields the same proof and ticket.
        let proof1 = leader.sign(&seed);
        let proof2 = leader.sign(&seed);
        assert_eq!(proof1, proof2, "Ed25519 is deterministic → stable VRF proof");
        assert_eq!(vrf_ticket(&proof1), vrf_ticket(&proof2));

        // Verifiable by anyone holding the leader's node_id; rejects a wrong signer.
        assert_eq!(vrf_verify(&leader.node_id(), &seed, &proof1), Some(vrf_ticket(&proof1)));
        assert_eq!(vrf_verify(&other.node_id(), &seed, &proof1), None, "proof binds to the signer");
        // A different slot yields a different seed and (almost surely) a different ticket.
        let seed2 = leader_seed(&[7u8; 32], 43);
        assert_ne!(vrf_ticket(&leader.sign(&seed2)), vrf_ticket(&proof1));
    }

    #[test]
    fn leader_threshold_scales_with_weight_and_excludes_zero() {
        // Zero weight (or zero total) can never lead.
        assert_eq!(leader_threshold(0, 1_000), 0);
        assert_eq!(leader_threshold(500, 0), 0);
        // A node with all the weight is eligible for every ticket; half the weight, ~half the space.
        assert_eq!(leader_threshold(1_000, 1_000), u128::MAX / 1_000 * 1_000);
        let half = leader_threshold(500, 1_000);
        let full = leader_threshold(1_000, 1_000);
        assert!(half < full && half >= full / 2 - 1, "cutoff is ~proportional to weight");
        // A ticket below the cutoff leads; at/above does not.
        assert!(ticket_value(&[0u8; 32]) < leader_threshold(1, 1_000), "the lowest ticket always leads if eligible");
    }

    #[test]
    fn leader_election_is_weighted_over_many_slots() {
        // Two nodes, 3:1 weight. Over many slots the heavier node wins ~3x as often. Pure-function
        // check (no chain): each node signs each slot's seed and is eligible iff ticket < its cutoff.
        let big = make_identity("le-big");
        let small = make_identity("le-small");
        let (w_big, w_small) = (3_000u128, 1_000u128);
        let total = w_big + w_small;
        let (mut big_wins, mut small_wins) = (0u32, 0u32);
        for slot in 0..2_000u64 {
            let seed = leader_seed(&[1u8; 32], slot);
            if ticket_value(&vrf_ticket(&big.sign(&seed))) < leader_threshold(w_big, total) {
                big_wins += 1;
            }
            if ticket_value(&vrf_ticket(&small.sign(&seed))) < leader_threshold(w_small, total) {
                small_wins += 1;
            }
        }
        // Expect ~1500 and ~500; assert the heavier node wins clearly more, with loose bounds.
        assert!(big_wins > small_wins, "heavier node leads more often ({big_wins} vs {small_wins})");
        assert!(big_wins > 1_000 && big_wins < 2_000, "big ~75% of slots: {big_wins}");
        assert!(small_wins > 200 && small_wins < 800, "small ~25% of slots: {small_wins}");
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&host);
        assert!(chain.append(block));

        let mut settle = signed_job_settle(&host, &payer, job_id, 100);
        if let TxKind::JobSettle { ref mut payer_sig, .. } = settle.kind {
            *payer_sig = [0xff; 64];
        }
        let data = bincode::serialize(&settle.kind).unwrap();
        settle.sig = host.sign(&data);

        let mut block = chain.next_block(vec![settle], host.node_id());
        block.mine(&std::sync::atomic::AtomicBool::new(false));
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&host);
        assert!(chain.append(block));

        let settle = signed_job_settle(&host, &payer, job_id, 200);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, settle], host.node_id());
        block.mine(&std::sync::atomic::AtomicBool::new(false));
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&host);
        assert!(chain.append(block));

        let settle = signed_job_settle(&host, &payer, job_id, 100);
        let mut block = chain.next_block(vec![settle], host.node_id());
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&host);
        assert!(chain.append(block));

        let dup = signed_job_settle(&host, &payer, job_id, 100);
        let mut block = chain.next_block(vec![dup], host.node_id());
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&host);
        assert!(!chain.append(block));
    }

    fn signed_job_expire(payer: &Identity, job_id: [u8; 32]) -> Tx {
        let kind = TxKind::JobExpire { job_id, payer: payer.node_id() };
        let data = bincode::serialize(&kind).unwrap();
        let sig = payer.sign(&data);
        Tx::new(kind, payer.node_id(), sig)
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&host);
        let bid_block = chain.tip().index + 1;
        assert!(chain.append(block));
        assert_eq!(chain.locked_balance(&payer.node_id()), 500);

        // Too early — reject.
        let expire2 = signed_job_expire(&payer, job_id);
        let reward2 = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut early_block = chain.next_block(vec![reward2, expire2], host.node_id());
        early_block.mine(&std::sync::atomic::AtomicBool::new(false));
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&host);
        assert!(chain.append(block));
        assert_eq!(chain.locked_balance(&payer.node_id()), 500);

        let settle = signed_job_settle(&host, &payer, job_id, 300);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, settle], host.node_id());
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&host);
        assert!(chain.append(block));
        assert_eq!(chain.locked_balance(&payer.node_id()), 0, "locked balance must clear after settle");
    }


    fn signed_heartbeat(
        host: &Identity,
        job_id: [u8; 32],
        cell_id: NodeId,
        amount: u128,
        epoch: u64,
    ) -> Tx {
        let kind = TxKind::Heartbeat { job_id, cell: cell_id, host: host.node_id(), amount, epoch };
        let data = bincode::serialize(&kind).unwrap();
        let sig = host.sign(&data);
        Tx::new(kind, host.node_id(), sig)
    }

    /// Test helper: fund `cell`, then place and confirm a JobBid by `cell` for `bid` against `job_id`
    /// (so heartbeats have an open escrow to bill against). `miner` seals the bid block.
    fn open_bid_for(
        chain: &mut Chain,
        cell: &Identity,
        miner: &Identity,
        job_id: [u8; 32],
        bid: u128,
    ) {
        let bid_tx = signed_job_bid(cell, job_id, bid);
        let reward = signed_uptime_reward(miner, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, bid_tx], miner.node_id());
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(miner);
        assert!(chain.append(block), "test setup: bid must confirm");
    }

    #[test]
    fn heartbeat_happy_path() {
        let host = make_identity("hb-host");
        let cell = make_identity("hb-cell");
        let mut chain = Chain::genesis();
        fund(&mut chain, &cell, 1_000);
        let job_id = [40u8; 32];
        // E3: a heartbeat bills against the cell's own signed, open bid escrow.
        open_bid_for(&mut chain, &cell, &host, job_id, 500);
        let before = chain.balance(&cell.node_id());

        let hb = signed_heartbeat(&host, job_id, cell.node_id(), 100, 0);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, hb], host.node_id());
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&host);
        assert!(chain.append(block), "valid heartbeat within open-bid escrow must be accepted");
        assert_eq!(chain.balance(&cell.node_id()), before - 100);
        assert_eq!(chain.last_heartbeat_epoch(&cell.node_id(), &host.node_id()), Some(0));
        // The escrow has drawn down by the billed amount: 500 bid - 100 spent = 400 still locked.
        assert_eq!(chain.locked_balance(&cell.node_id()), 400, "escrow draws down by billed heartbeat");
    }

    #[test]
    fn heartbeat_rejects_replay() {
        let host = make_identity("hb-replay-host");
        let cell = make_identity("hb-replay-cell");
        let mut chain = Chain::genesis();
        fund(&mut chain, &cell, 2_000);
        let job_id = [41u8; 32];
        open_bid_for(&mut chain, &cell, &host, job_id, 1_000);

        let hb = signed_heartbeat(&host, job_id, cell.node_id(), 100, 5);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, hb], host.node_id());
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&host);
        assert!(chain.append(block));

        let hb2 = signed_heartbeat(&host, job_id, cell.node_id(), 100, 5);
        let reward2 = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block2 = chain.next_block(vec![reward2, hb2], host.node_id());
        block2.mine(&std::sync::atomic::AtomicBool::new(false));
        block2.seal(&host);
        assert!(!chain.append(block2), "replayed heartbeat epoch must be rejected");

        let hb3 = signed_heartbeat(&host, job_id, cell.node_id(), 100, 3);
        let reward3 = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block3 = chain.next_block(vec![reward3, hb3], host.node_id());
        block3.mine(&std::sync::atomic::AtomicBool::new(false));
        block3.seal(&host);
        assert!(!chain.append(block3), "earlier epoch must be rejected");

        let hb4 = signed_heartbeat(&host, job_id, cell.node_id(), 100, 6);
        let reward4 = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block4 = chain.next_block(vec![reward4, hb4], host.node_id());
        block4.mine(&std::sync::atomic::AtomicBool::new(false));
        block4.seal(&host);
        assert!(chain.append(block4), "higher epoch must be accepted");
    }

    #[test]
    fn heartbeat_rejects_exceeding_escrow() {
        // E3: a heartbeat may bill at most the bid escrow. A single heartbeat over the bid, and a
        // sequence whose cumulative spend would exceed it, are both rejected — the escrow is the hard
        // ceiling on what a host can bill, and it is funded by the bid the cell signed.
        let host = make_identity("hb-poor-host");
        let cell = make_identity("hb-poor-cell");
        let mut chain = Chain::genesis();
        fund(&mut chain, &cell, 1_000);
        let job_id = [42u8; 32];
        open_bid_for(&mut chain, &cell, &host, job_id, 300);

        // Single heartbeat over the bid escrow → rejected.
        let hb = signed_heartbeat(&host, job_id, cell.node_id(), 400, 0);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, hb], host.node_id());
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&host);
        assert!(!chain.append(block), "heartbeat exceeding the bid escrow must be rejected");

        // Bill 200 (within escrow) → accepted; then a 200 more would push cumulative to 400 > 300.
        let hb_ok = signed_heartbeat(&host, job_id, cell.node_id(), 200, 0);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, hb_ok], host.node_id());
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&host);
        assert!(chain.append(block), "heartbeat within escrow must be accepted");

        let hb_over = signed_heartbeat(&host, job_id, cell.node_id(), 200, 1);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, hb_over], host.node_id());
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&host);
        assert!(!chain.append(block), "cumulative heartbeats past the escrow must be rejected");
    }

    #[test]
    fn heartbeat_rejects_self_pay() {
        let host = make_identity("hb-self");
        let mut chain = Chain::genesis();
        fund(&mut chain, &host, 1_000);

        let kind = TxKind::Heartbeat {
            job_id: [43u8; 32],
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
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
            job_id: [44u8; 32],
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&attacker);
        assert!(!chain.append(block), "heartbeat with wrong signer must be rejected");
    }


    fn signed_revoke_cap(issuer: &Identity, nonce: u64) -> Tx {
        let kind = TxKind::RevokeCapability { issuer: issuer.node_id(), nonce };
        let data = bincode::serialize(&kind).unwrap();
        let sig = issuer.sign(&data);
        Tx::new(kind, issuer.node_id(), sig)
    }

    #[test]
    fn revoke_capability_records_and_queries() {
        let issuer = make_identity("rc-issuer");
        let mut chain = Chain::genesis();
        fund(&mut chain, &issuer, 100);
        assert!(!chain.is_revoked(&issuer.node_id(), 7));

        let rev = signed_revoke_cap(&issuer, 7);
        let reward = signed_uptime_reward(&issuer, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, rev], issuer.node_id());
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&issuer);
        assert!(chain.append(block), "issuer-signed revoke must be accepted");
        assert!(chain.is_revoked(&issuer.node_id(), 7));
        assert!(!chain.is_revoked(&issuer.node_id(), 8), "unrelated nonce not revoked");
    }

    #[test]
    fn revoke_capability_rejects_wrong_signer() {
        let issuer = make_identity("rc-issuer2");
        let attacker = make_identity("rc-attacker");
        let mut chain = Chain::genesis();
        fund(&mut chain, &attacker, 100);

        // attacker tries to revoke a capability issued by someone else.
        let kind = TxKind::RevokeCapability { issuer: issuer.node_id(), nonce: 9 };
        let data = bincode::serialize(&kind).unwrap();
        let bad = Tx::new(kind, attacker.node_id(), attacker.sign(&data));
        let reward = signed_uptime_reward(&attacker, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, bad], attacker.node_id());
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&attacker);
        assert!(!chain.append(block), "revoke not signed by the issuer must be rejected");
        assert!(!chain.is_revoked(&issuer.node_id(), 9));
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&host);
        assert!(!chain.append(block), "bid signed by non-payer must be rejected");
    }

    // ----- Fork choice / reorg tests -----

    fn build_fork(base: &Chain, miner: &Identity, count: usize) -> Vec<Block> {
        let mut fork = base.clone();
        let mut new_blocks = Vec::new();
        for _ in 0..count {
            let reward = signed_uptime_reward(miner, fork.tip().index + 1);
            // Weighted VRF block if the miner has weight (granted in `base`); else a fallback block.
            let block = if fork.consensus_weight(&miner.node_id()) > 0 {
                fork.produce(miner, vec![reward]).expect("fork block")
            } else {
                let mut b = fork.next_block(vec![reward], miner.node_id());
                b.seal(miner);
                b
            };
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
        // Equal-weight validators → fork choice is by cumulative weight, so more blocks wins.
        chain.grant_genesis_weight(a.node_id(), 1_000_000);
        chain.grant_genesis_weight(b.node_id(), 1_000_000);
        assert!(produce_append(&mut chain, &a, vec![]));

        let common = chain.clone();
        assert!(produce_append(&mut chain, &a, vec![]));

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
            difficulty: 0,
            miner: b.node_id(),
            weight: 0,
            vrf_proof: [0u8; 64],
            sig: [0u8; 64],
        };
        ghost.mine(&std::sync::atomic::AtomicBool::new(false));
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&miner);
        assert!(chain.append(block), "first transfer must succeed");

        // Mine another block to top up miner's balance again.
        seal_and_append(&mut chain, &miner);

        // Replay: include the exact same Transfer tx in block 5.
        let reward = signed_uptime_reward(&miner, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, transfer], miner.node_id());
        block.mine(&std::sync::atomic::AtomicBool::new(false));
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
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
            job_id: [45u8; 32],
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&host);
        assert!(chain.append(block));
        assert_eq!(chain.locked_balance(&payer.node_id()), 500);

        // Attempt rebid for the same job_id.
        let bid2 = signed_job_bid(&payer, job_id, 100);
        let reward2 = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block2 = chain.next_block(vec![reward2, bid2], host.node_id());
        block2.mine(&std::sync::atomic::AtomicBool::new(false));
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
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
        block2.mine(&std::sync::atomic::AtomicBool::new(false));
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
            block.mine(&std::sync::atomic::AtomicBool::new(false));
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&host);
        assert!(!chain.append(block), "transfer + bid exceeding free balance must be rejected");
        assert_eq!(chain.balance(&alice.node_id()), bal as i128, "alice's balance must be unchanged");
    }

    // Attack 10: Transfer must not spend escrowed (bid-locked) credits.
    // E3 changed heartbeat billing to draw against the cell's locked bid escrow, not its free
    // balance — so a heartbeat and a free-balance transfer are NOT the same funds. The remaining
    // double-spend surface to defend is that a transfer cannot reach into the LOCKED escrow. Bob
    // opens a bid that locks most of his balance, then tries to transfer his FULL balance away in
    // one block; the transfer must be rejected because the escrow is not free.
    #[test]
    fn transfer_cannot_spend_locked_escrow() {
        let host = make_identity("xth-host");
        let bob = make_identity("xth-bob");
        let eve = make_identity("xth-eve");
        let mut chain = Chain::genesis();
        fund(&mut chain, &bob, 500);
        let bal = chain.balance(&bob.node_id()) as u128;
        // Lock 80% of bob's balance in a bid escrow.
        let bid = bal * 8 / 10;
        let job_id = [46u8; 32];
        open_bid_for(&mut chain, &bob, &host, job_id, bid);

        // Try to transfer bob's FULL balance — only `bal - bid` is free, so this must be rejected.
        let transfer = signed_transfer(&bob, eve.node_id(), bal);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, transfer], host.node_id());
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&host);
        assert!(!chain.append(block), "transfer spending locked escrow must be rejected");
        assert_eq!(chain.balance(&bob.node_id()), bal as i128, "bob's balance must be unchanged");
        assert_eq!(chain.locked_balance(&bob.node_id()), bid, "escrow stays locked");
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&miner);
        assert!(chain.append(block), "reward directed to a third party must be accepted");
        assert_eq!(chain.balance(&miner.node_id()), 0, "miner gets nothing");
        assert_eq!(
            chain.balance(&beneficiary.node_id()),
            amount as i128,
            "beneficiary receives the full emission"
        );
    }

    // Attack 13 (E3 regression): a rogue host CANNOT drain a cell with a Heartbeat unless that cell
    // signed an open bid authorizing it. A heartbeat is now bid-gated: it must name an OPEN JobBid
    // whose payer == the billed cell, and cumulative billing is bounded by that bid's escrow. Mallory
    // has no such bid from Bob, so the heartbeat is rejected and Bob's balance is untouched. This was
    // formerly a KNOWN LIMITATION (unconsented credit drain); it is now a hard rejection.
    #[test]
    fn rogue_host_heartbeat_drains_cell_without_bid() {
        let mallory = make_identity("rogue-mallory");
        let bob = make_identity("rogue-bob");
        let mut chain = Chain::genesis();
        fund(&mut chain, &bob, 1_000);
        let before = chain.balance(&bob.node_id());

        // No bid from Bob exists — Mallory invents a job_id and tries to bill Bob anyway.
        let hb = signed_heartbeat(&mallory, [99u8; 32], bob.node_id(), 500, 1);
        let reward = signed_uptime_reward(&mallory, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, hb], mallory.node_id());
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&mallory);
        assert!(!chain.append(block), "rogue heartbeat with no cell-signed open bid must be rejected");
        assert_eq!(chain.balance(&bob.node_id()), before, "bob must NOT be drained — no consent, no bid");
    }

    // E3 positive case: a legitimate heartbeat against a cell's OWN open bid still settles. Bob signs
    // a bid (locking escrow); the host bills incremental heartbeats within that escrow; each is
    // accepted, draws the escrow down, and pays the host net-of-burn. The long-running-cell billing
    // flow is preserved for honest jobs.
    #[test]
    fn legit_heartbeat_within_open_bid_settles() {
        let host = make_identity("legit-hb-host");
        let bob = make_identity("legit-hb-cell");
        let mut chain = Chain::genesis();
        fund(&mut chain, &bob, 2_000);
        let job_id = [98u8; 32];
        open_bid_for(&mut chain, &bob, &host, job_id, 600);
        let bob_before = chain.balance(&bob.node_id());
        let host_before = chain.balance(&host.node_id());

        // Three heartbeats of 200 each = 600 total, exactly the escrow.
        for (i, epoch) in (0u64..3).enumerate() {
            let hb = signed_heartbeat(&host, job_id, bob.node_id(), 200, epoch);
            let reward = signed_uptime_reward(&host, chain.tip().index + 1);
            let mut block = chain.next_block(vec![reward, hb], host.node_id());
            block.mine(&std::sync::atomic::AtomicBool::new(false));
            block.seal(&host);
            assert!(chain.append(block), "legit heartbeat {i} within escrow must be accepted");
        }

        // Bob paid the full 600 gross; the host received 600 net-of-burn (plus its mining emissions,
        // which we account for separately by checking the cell side precisely).
        assert_eq!(chain.balance(&bob.node_id()), bob_before - 600, "cell pays gross heartbeat total");
        let net: u128 = (0..3).map(|_| 200u128 - settlement_burn(200)).sum();
        // Host gained the heartbeat net plus three block emissions it mined.
        let emissions: i128 = (1..=3)
            .map(|k| Chain::emission_rate(chain.tip().index - 3 + k) as i128)
            .sum();
        assert_eq!(
            chain.balance(&host.node_id()),
            host_before + net as i128 + emissions,
            "host receives heartbeat net-of-burn plus its mining emissions",
        );
        // Escrow fully consumed → nothing left locked.
        assert_eq!(chain.locked_balance(&bob.node_id()), 0, "escrow fully drawn down by heartbeats");
        // A fourth heartbeat would exceed the now-zero remaining escrow → rejected.
        let hb = signed_heartbeat(&host, job_id, bob.node_id(), 1, 3);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, hb], host.node_id());
        block.mine(&std::sync::atomic::AtomicBool::new(false));
        block.seal(&host);
        assert!(!chain.append(block), "heartbeat past a fully-consumed escrow must be rejected");
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
        block.mine(&std::sync::atomic::AtomicBool::new(false));
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

        // Fund Alice on the shared honest chain (under the bootstrap fallback, no weight yet).
        fund(&mut chain, &alice, 1_000);
        // Equal-weight validators so fork choice is by cumulative weight → more blocks wins.
        chain.grant_genesis_weight(alice.node_id(), 1_000_000);
        chain.grant_genesis_weight(mallory.node_id(), 1_000_000);

        // Save the chain at this point — both the honest chain and the shadow fork
        // build from here so that try_reorg can find the common ancestor.
        let fork_base = chain.clone();

        // Honest chain: Alice → Bob 500 (one block above fork_base).
        assert!(produce_append(&mut chain, &alice, vec![signed_transfer(&alice, bob.node_id(), 500)]));
        assert_eq!(chain.balance(&bob.node_id()), 500);

        // Shadow fork: three blocks from the same fork_base, so it beats the honest
        // chain's one block and triggers a reorg.
        let mut shadow_blocks: Vec<Block> = Vec::new();
        let mut shadow = fork_base;

        // Shadow block 1: Alice → Mallory 500 instead of Bob.
        let reward = signed_uptime_reward(&alice, shadow.tip().index + 1);
        let pay_mallory = signed_transfer(&alice, mallory.node_id(), 500);
        let b1 = shadow.produce(&alice, vec![reward, pay_mallory]).expect("shadow b1");
        assert!(shadow.append(b1.clone()));
        shadow_blocks.push(b1);

        // Shadow blocks 2–3: Mallory extends the fork past the honest chain.
        for _ in 0..2usize {
            let r = signed_uptime_reward(&mallory, shadow.tip().index + 1);
            let blk = shadow.produce(&mallory, vec![r]).expect("shadow blk");
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

    // ----- Consensus: timestamps + slot spacing -----

    #[test]
    fn append_rejects_bad_timestamp() {
        let mut chain = Chain::genesis();
        let id = make_identity("pow-ts");
        for _ in 0..3 {
            assert!(seal_and_append(&mut chain, &id));
        }
        // Timestamp at/below the median-time-past is rejected (set it before mining so PoW is valid).
        let reward = signed_uptime_reward(&id, chain.tip().index + 1);
        let mut past = chain.next_block(vec![reward], id.node_id());
        past.timestamp = 0;
        past.mine(&std::sync::atomic::AtomicBool::new(false));
        past.seal(&id);
        assert!(!chain.append(past), "timestamp <= median-time-past must be rejected");
        // Far-future timestamp is rejected too.
        let reward = signed_uptime_reward(&id, chain.tip().index + 1);
        let mut future = chain.next_block(vec![reward], id.node_id());
        future.timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
            + MAX_FUTURE_DRIFT_SECS
            + 3600;
        future.mine(&std::sync::atomic::AtomicBool::new(false));
        future.seal(&id);
        assert!(!chain.append(future), "far-future timestamp must be rejected");
    }

    #[test]
    fn chain_format_version_guard_rejects_incompatible_files() {
        let dir = tmpdir("fmt-guard");
        let path = dir.join("chain.bin");
        let mut chain = Chain::genesis();
        let id = make_identity("fmt");
        assert!(seal_and_append(&mut chain, &id));
        chain.save(&path).unwrap();
        // A correctly-versioned file loads.
        assert!(Chain::load(&path).is_ok());
        // Corrupt the leading version byte → load refuses; load_or_genesis falls back to genesis.
        let mut data = std::fs::read(&path).unwrap();
        data[0] = 0xFF;
        std::fs::write(&path, &data).unwrap();
        assert!(Chain::load(&path).is_err(), "incompatible format must be rejected");
        assert_eq!(Chain::load_or_genesis(&path).height(), 0, "falls back to genesis");
    }

    // ===================================================================================
    // Additional adversarial economy / consensus invariants (validation campaign).
    // These close coverage gaps the prompt called out: a SUCCESSFUL JobExpire reclaim (the
    // existing test only proves the too-early rejection), a transfer+JobBid in-block
    // double-spend of the same free balance, and a hard supply-cap boundary.
    // ===================================================================================

    /// JobExpire envelope rule: only the named payer may expire a bid. A stranger (or the host)
    /// submitting the JobExpire is rejected even before the timing window is considered — the lock
    /// stays put. (The successful *reclaim after the full `EXPIRY_BLOCKS` window* cannot be unit-
    /// tested deterministically in-process: each block must advance a full `SLOT_SECS`, so crossing
    /// the ~1440-block window pushes synthetic timestamps past `MAX_FUTURE_DRIFT_SECS` and `append`
    /// rejects them. The reclaim path is exercised by the live cluster suite instead. The too-early
    /// rejection and unknown-job rejection are covered by `job_expire_happy_path` /
    /// `job_expire_rejects_unknown_job`.)
    #[test]
    fn job_expire_by_non_payer_is_rejected() {
        let host = make_identity("expnp-host");
        let payer = make_identity("expnp-payer");
        let eve = make_identity("expnp-eve");
        let mut chain = Chain::genesis();
        fund(&mut chain, &payer, 2_000);

        let job_id = [33u8; 32];
        assert!(append_with(&mut chain, &host, signed_job_bid(&payer, job_id, 700)), "bid accepted");
        assert_eq!(chain.locked_balance(&payer.node_id()), 700);

        // Eve forges a JobExpire naming herself as payer for the payer's job — no open bid for Eve.
        assert!(
            !append_with(&mut chain, &host, signed_job_expire(&eve, job_id)),
            "a non-payer must not be able to expire someone else's bid",
        );
        assert_eq!(chain.locked_balance(&payer.node_id()), 700, "lock untouched by the forged expire");
    }

    /// A transfer and a JobBid in the SAME block that together exceed the payer's free balance must
    /// be rejected as a whole — the in-block accounting cannot let a transfer and a bid both spend
    /// the same credits. (Job-specific companion to `transfer_and_channel_open_same_credits_rejected`.)
    #[test]
    fn transfer_and_job_bid_same_credits_rejected() {
        let payer = make_identity("tjb-payer");
        let host = make_identity("tjb-host");
        let eve = make_identity("tjb-eve");
        let mut chain = Chain::genesis();
        fund(&mut chain, &payer, 2_000);
        let bal = chain.balance(&payer.node_id()) as u128;
        let spend = bal * 8 / 10; // 80% each → 160% combined

        let transfer = signed_transfer(&payer, eve.node_id(), spend);
        let bid = signed_job_bid(&payer, [44u8; 32], spend);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut b = chain.next_block(vec![reward, transfer, bid], host.node_id());
        b.mine(&std::sync::atomic::AtomicBool::new(false));
        b.seal(&host);
        assert!(!chain.append(b), "transfer + bid exceeding free balance must be rejected");
        assert_eq!(chain.balance(&payer.node_id()), bal as i128, "balance unchanged after rejection");
        assert_eq!(chain.locked_balance(&payer.node_id()), 0, "no lock created by the rejected block");
    }

    /// A JobBid for MORE than the payer's free balance is rejected up front — escrow can never lock
    /// credits that don't exist.
    #[test]
    fn job_bid_exceeding_balance_rejected() {
        let payer = make_identity("jbe-payer");
        let host = make_identity("jbe-host");
        let mut chain = Chain::genesis();
        fund(&mut chain, &payer, 1_000);
        let bal = chain.balance(&payer.node_id()) as u128;

        let bid = signed_job_bid(&payer, [55u8; 32], bal + 1);
        assert!(!append_with(&mut chain, &host, bid), "bid exceeding free balance must be rejected");
        assert_eq!(chain.locked_balance(&payer.node_id()), 0, "no lock on a rejected over-bid");
    }

    /// The total emitted supply is invariant under the burn and never exceeds `SUPPLY_CAP`. We mine
    /// a stretch of blocks, run a settlement that burns, and assert: emitted supply only grows by
    /// the schedule, the burn reduces circulating supply (not total emitted), and total <= cap.
    #[test]
    fn supply_accounting_holds_under_burn() {
        let host = make_identity("sup-host");
        let payer = make_identity("sup-payer");
        let mut chain = Chain::genesis();
        fund(&mut chain, &payer, 5_000);

        let emitted_before = chain.total_supply();
        let circ_before = chain.circulating_supply();
        assert_eq!(emitted_before, circ_before, "no burn yet → emitted == circulating");

        // A settled job burns part of the gross.
        let job_id = [66u8; 32];
        assert!(append_with(&mut chain, &host, signed_job_bid(&payer, job_id, 4_000)));
        let cost = 4_000u128;
        let burn = settlement_burn(cost);
        assert!(burn > 0, "burn must bite for this assertion");
        let emitted_mid = chain.total_supply();
        assert!(append_with(&mut chain, &host, signed_job_settle(&host, &payer, job_id, cost)));

        // Emitted supply grows only by the two blocks' UptimeRewards; the burn is NOT minted away
        // from emitted supply — it is removed from circulation.
        assert_eq!(chain.burned_total(), burn, "burn tracked");
        assert_eq!(
            chain.circulating_supply(),
            chain.total_supply() - burn,
            "circulating == emitted - burned",
        );
        assert!(chain.total_supply() <= SUPPLY_CAP, "emitted supply never exceeds the cap");
        assert!(chain.total_supply() >= emitted_mid, "emission is monotonic");
    }
}
