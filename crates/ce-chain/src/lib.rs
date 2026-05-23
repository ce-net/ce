use anyhow::{anyhow, Result};
use ce_identity::{verify, Identity, NodeId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TxKind {
    /// Credit transfer between nodes.
    Transfer { from: NodeId, to: NodeId, amount: u64 },
    /// Uptime emission: credits minted and credited to a node for staying online.
    UptimeReward { node: NodeId, amount: u64, epoch: u64 },
    /// Open job bid: payer offers up to `bid` credits for a workload.
    /// `cmd` and `env` describe how the container should be launched; they are
    /// included on-chain so any host with capacity can accept the bid deterministically.
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

// ----- Chain -----

const EMISSION_BASE: u64 = 1_000;
pub const SUPPLY_CAP: u64 = 21_000_000_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chain {
    pub blocks: Vec<Block>,
    /// Retained for forward compatibility; not used for validation in the uptime model.
    pub difficulty: u8,
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
        Self { blocks: vec![genesis], difficulty: 0 }
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

    /// Sum of all UptimeReward amounts ever emitted across all blocks.
    pub fn total_supply(&self) -> u64 {
        self.blocks
            .iter()
            .flat_map(|b| &b.transactions)
            .fold(0u64, |acc, tx| {
                if let TxKind::UptimeReward { amount, .. } = &tx.kind {
                    acc.saturating_add(*amount)
                } else {
                    acc
                }
            })
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
        if self.total_supply().saturating_add(new_emission) > SUPPLY_CAP {
            return false;
        }
        // JobBid envelope rule: the Tx must be signed by the named payer.
        for tx in &block.transactions {
            if let TxKind::JobBid { payer, .. } = &tx.kind {
                if &tx.origin != payer {
                    return false;
                }
            }
        }
        // JobSettle rules. Track running per-payer debit so multiple settles
        // in the same block don't double-spend a balance.
        let mut payer_debit: std::collections::HashMap<NodeId, u64> = std::collections::HashMap::new();
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
                // A matching JobBid must exist in a prior block, with the same payer.
                let mut found_bid = false;
                'outer: for prior in &self.blocks {
                    for ptx in &prior.transactions {
                        if let TxKind::JobBid { job_id: bid_id, payer: bid_payer, .. } = &ptx.kind {
                            if bid_id == job_id && bid_payer == payer {
                                found_bid = true;
                                break 'outer;
                            }
                        }
                    }
                }
                if !found_bid {
                    return false;
                }
                // Reject duplicate settlement of the same job_id.
                for prior in &self.blocks {
                    for ptx in &prior.transactions {
                        if let TxKind::JobSettle { job_id: prior_id, .. } = &ptx.kind {
                            if prior_id == job_id {
                                return false;
                            }
                        }
                    }
                }
                // Balance check: chain balance minus accumulated debits in this block must cover cost.
                let prior_balance = self.balance(payer);
                let accumulated = *payer_debit.get(payer).unwrap_or(&0);
                let available = prior_balance.saturating_sub(accumulated as i64);
                if available < *cost as i64 {
                    return false;
                }
                *payer_debit.entry(*payer).or_insert(0) =
                    accumulated.saturating_add(*cost);
            }
        }
        self.blocks.push(block);
        true
    }

    pub fn balance(&self, node: &NodeId) -> i64 {
        let mut bal: i64 = 0;
        for block in &self.blocks {
            for tx in &block.transactions {
                match &tx.kind {
                    TxKind::Transfer { from, to, amount } => {
                        if from == node { bal -= *amount as i64; }
                        if to == node { bal += *amount as i64; }
                    }
                    TxKind::UptimeReward { node: n, amount, .. } => {
                        if n == node { bal += *amount as i64; }
                    }
                    TxKind::JobBid { .. } => {
                        // Bids are market offers; no direct balance effect until settled.
                    }
                    TxKind::JobSettle { host, payer, cost, .. } => {
                        if payer == node { bal -= *cost as i64; }
                        if host == node { bal += *cost as i64; }
                    }
                }
            }
        }
        bal
    }

    /// Linear scan of all blocks for a transaction with the given id.
    /// Returns the tx together with the block height and block hash that
    /// confirmed it. Used by signal verification to validate a `BurnProof`.
    pub fn tx_by_id(&self, tx_id: &[u8; 32]) -> Option<(Tx, u64, [u8; 32])> {
        for block in &self.blocks {
            for tx in &block.transactions {
                if &tx.id() == tx_id {
                    return Some((tx.clone(), block.index, block.hash()));
                }
            }
        }
        None
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

    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)?;
        let chain: Chain = serde_json::from_str(&data)?;
        if chain.blocks.is_empty() {
            return Err(anyhow!("chain file is empty"));
        }
        Ok(chain)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_string(self)?;
        std::fs::write(path, data)?;
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
        let path = dir.join("chain.json");
        let id = make_identity("saveload-id");
        let mut chain = Chain::genesis();
        seal_and_append(&mut chain, &id);

        chain.save(&path).unwrap();
        let loaded = Chain::load(&path).unwrap();

        assert_eq!(loaded.height(), chain.height());
        assert_eq!(loaded.tip().hash(), chain.tip().hash());
        assert_eq!(loaded.difficulty, chain.difficulty);
    }

    #[test]
    fn load_or_genesis_returns_genesis_when_missing() {
        let chain = Chain::load_or_genesis(std::path::Path::new("/nonexistent/chain.json"));
        assert_eq!(chain.height(), 0);
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
        // Block N: the JobBid.
        let bid = signed_job_bid(&payer, job_id, 1_000);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, bid], host.node_id());
        block.seal(&host);
        assert!(chain.append(block));

        // Block N+1: the JobSettle.
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
        // Re-sign the Tx envelope so the host envelope is still valid.
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

        // No JobBid was ever mined for job_id = [9u8;32].
        let settle = signed_job_settle(&host, &payer, [9u8; 32], 50);
        let mut block = chain.next_block(vec![settle], host.node_id());
        block.seal(&host);
        assert!(!chain.append(block), "settle without a prior bid must be rejected");
    }

    #[test]
    fn job_settle_rejects_insufficient_balance() {
        let host = make_identity("poor-host");
        let payer = make_identity("poor-payer");
        // payer never mines — balance stays at 0.
        let mut chain = Chain::genesis();
        // Need at least one block so host can submit the bid via host envelope?
        // No: a JobBid is signed by the payer themselves. Mine via host so the
        // chain progresses and the payer can submit a bid as a tx in a future block.
        seal_and_append(&mut chain, &host);

        let job_id = [3u8; 32];
        let bid = signed_job_bid(&payer, job_id, 1_000);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, bid], host.node_id());
        block.seal(&host);
        assert!(chain.append(block));

        // Payer has zero balance; settle for cost=10 must fail.
        let settle = signed_job_settle(&host, &payer, job_id, 10);
        let reward = signed_uptime_reward(&host, chain.tip().index + 1);
        let mut block = chain.next_block(vec![reward, settle], host.node_id());
        block.seal(&host);
        assert!(!chain.append(block));
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

        // Host == payer is forbidden.
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

        // Second settle for the same job must be rejected.
        let dup = signed_job_settle(&host, &payer, job_id, 100);
        let mut block = chain.next_block(vec![dup], host.node_id());
        block.seal(&host);
        assert!(!chain.append(block));
    }

    #[test]
    fn job_bid_must_be_signed_by_payer() {
        let host = make_identity("bidh");
        let payer = make_identity("bidp");
        let mut chain = Chain::genesis();
        fund(&mut chain, &payer, 100);

        // Build a JobBid where the host (not payer) signs the envelope.
        let kind = TxKind::JobBid {
            job_id: [6u8; 32],
            payer: payer.node_id(), // names the payer …
            bid: 50,
            image: "alpine".into(),
            cmd: vec![],
            env: vec![],
            cpu_cores: 1,
            mem_mb: 16,
            duration_secs: 10,
        };
        let data = bincode::serialize(&kind).unwrap();
        let bad_sig = host.sign(&data); // … but the host signs the envelope.
        let bad_bid = Tx::new(kind, host.node_id(), bad_sig);

        let mut block = chain.next_block(vec![bad_bid], host.node_id());
        block.seal(&host);
        assert!(!chain.append(block), "bid signed by non-payer must be rejected");
    }
}
