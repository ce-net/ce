use anyhow::{anyhow, Result};
use ce_identity::{verify, NodeId};
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
    /// Metered workload: payer ran a job on host, cost debited from payer, credited to host.
    Meter { job_id: String, payer: NodeId, host: NodeId, cpu_ms: u64, mem_mb: u64, cost: u64 },
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
}

impl Block {
    pub fn hash(&self) -> [u8; 32] {
        let data = bincode::serialize(self).unwrap_or_default();
        Sha256::digest(data).into()
    }

    pub fn satisfies_difficulty(&self, difficulty: u8) -> bool {
        let hash = self.hash();
        let full_bytes = (difficulty / 8) as usize;
        let rem_bits = difficulty % 8;
        for i in 0..full_bytes {
            if hash[i] != 0 {
                return false;
            }
        }
        if rem_bits > 0 && full_bytes < 32 {
            return hash[full_bytes].leading_zeros() as u8 >= rem_bits;
        }
        true
    }

    pub fn mine(&mut self, difficulty: u8) {
        while !self.satisfies_difficulty(difficulty) {
            self.nonce = self.nonce.wrapping_add(1);
        }
    }
}

// ----- Chain -----

const BLOCK_REWARD_BASE: u64 = 1_000;
pub const INITIAL_DIFFICULTY: u8 = 4;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chain {
    pub blocks: Vec<Block>,
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
        };
        Self { blocks: vec![genesis], difficulty: INITIAL_DIFFICULTY }
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

    /// Validates and appends a block. Returns false if invalid (caller should log and discard).
    pub fn append(&mut self, block: Block) -> bool {
        if block.index != self.tip().index + 1 {
            return false;
        }
        if block.prev_hash != self.tip_hash() {
            return false;
        }
        if !block.satisfies_difficulty(self.difficulty) {
            return false;
        }
        for tx in &block.transactions {
            if tx.verify().is_err() {
                return false;
            }
        }
        self.blocks.push(block);
        if self.blocks.len() % 2016 == 0 {
            self.adjust_difficulty();
        }
        true
    }

    fn adjust_difficulty(&mut self) {
        let window = 2016usize;
        let len = self.blocks.len();
        if len < window + 1 {
            return;
        }
        let start_ts = self.blocks[len - window - 1].timestamp;
        let end_ts = self.tip().timestamp;
        let elapsed = end_ts.saturating_sub(start_ts);
        let target = (window as u64) * 10 * 60;
        if elapsed < target / 2 {
            self.difficulty = self.difficulty.saturating_add(1);
        } else if elapsed > target * 2 {
            self.difficulty = self.difficulty.saturating_sub(1).max(1);
        }
    }

    pub fn block_reward(index: u64) -> u64 {
        let halvings = index / 210_000;
        if halvings >= 64 { 0 } else { BLOCK_REWARD_BASE >> halvings }
    }

    pub fn balance(&self, node: &NodeId) -> i64 {
        let mut bal: i64 = 0;
        for block in &self.blocks {
            if &block.miner == node {
                bal += Self::block_reward(block.index) as i64;
            }
            for tx in &block.transactions {
                match &tx.kind {
                    TxKind::Transfer { from, to, amount } => {
                        if from == node { bal -= *amount as i64; }
                        if to == node { bal += *amount as i64; }
                    }
                    TxKind::Meter { payer, host, cost, .. } => {
                        if payer == node { bal -= *cost as i64; }
                        if host == node { bal += *cost as i64; }
                    }
                }
            }
        }
        bal
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
    fn difficulty_1_bit() {
        let mut block = Block {
            index: 1, prev_hash: [0u8; 32], timestamp: 0,
            transactions: vec![], nonce: 0, miner: [0u8; 32],
        };
        block.mine(1);
        assert!(block.satisfies_difficulty(1));
        // First bit must be 0 → first byte < 128
        assert_eq!(block.hash()[0] >> 7, 0);
    }

    #[test]
    fn difficulty_8_bits_requires_zero_byte() {
        let mut block = Block {
            index: 1, prev_hash: [0u8; 32], timestamp: 0,
            transactions: vec![], nonce: 0, miner: [1u8; 32],
        };
        block.mine(8);
        assert!(block.satisfies_difficulty(8));
        assert_eq!(block.hash()[0], 0);
    }

    // ----- Chain::append tests -----

    #[test]
    fn genesis_structure() {
        let chain = Chain::genesis();
        assert_eq!(chain.height(), 0);
        assert_eq!(chain.blocks.len(), 1);
        assert_eq!(chain.tip().prev_hash, [0u8; 32]);
        assert_eq!(chain.tip().index, 0);
    }

    fn mine_and_append(chain: &mut Chain, miner: NodeId) -> bool {
        let mut block = chain.next_block(vec![], miner);
        block.mine(chain.difficulty);
        chain.append(block)
    }

    #[test]
    fn append_valid_block() {
        let mut chain = Chain::genesis();
        chain.difficulty = 1;
        let id = make_identity("valid");
        assert!(mine_and_append(&mut chain, id.node_id()));
        assert_eq!(chain.height(), 1);
    }

    #[test]
    fn append_rejects_wrong_index() {
        let mut chain = Chain::genesis();
        chain.difficulty = 1;
        let id = make_identity("idx");
        let mut block = chain.next_block(vec![], id.node_id());
        block.index = 99;
        block.mine(1);
        assert!(!chain.append(block));
        assert_eq!(chain.height(), 0);
    }

    #[test]
    fn append_rejects_wrong_prev_hash() {
        let mut chain = Chain::genesis();
        chain.difficulty = 1;
        let id = make_identity("prev");
        let mut block = chain.next_block(vec![], id.node_id());
        block.mine(1);
        block.prev_hash = [0xff; 32]; // corrupt after mining
        assert!(!chain.append(block));
    }

    #[test]
    fn append_rejects_invalid_tx_sig() {
        let mut chain = Chain::genesis();
        chain.difficulty = 1;
        let id = make_identity("txsig");
        let mut tx = signed_transfer(&id, [0u8; 32], 100);
        tx.sig = [0xff; 64]; // corrupt
        let mut block = chain.next_block(vec![tx], id.node_id());
        block.mine(1);
        assert!(!chain.append(block));
    }

    #[test]
    fn three_blocks_chain() {
        let mut chain = Chain::genesis();
        chain.difficulty = 1;
        let id = make_identity("three");
        for expected_height in 1u64..=3 {
            assert!(mine_and_append(&mut chain, id.node_id()));
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
    fn balance_from_block_reward() {
        let mut chain = Chain::genesis();
        chain.difficulty = 1;
        let id = make_identity("reward");
        mine_and_append(&mut chain, id.node_id());
        assert_eq!(chain.balance(&id.node_id()), Chain::block_reward(1) as i64);
    }

    #[test]
    fn balance_with_transfer() {
        let mut chain = Chain::genesis();
        chain.difficulty = 1;
        let alice = make_identity("alice");
        let bob = make_identity("bob");

        // Mine 2 blocks for alice so she has credits.
        mine_and_append(&mut chain, alice.node_id());
        mine_and_append(&mut chain, alice.node_id());
        let alice_before = chain.balance(&alice.node_id());

        // Block 3: alice transfers 10 to bob and mines the block.
        let tx = signed_transfer(&alice, bob.node_id(), 10);
        let mut block = chain.next_block(vec![tx], alice.node_id());
        block.mine(1);
        chain.append(block);

        assert_eq!(chain.balance(&alice.node_id()), alice_before - 10 + Chain::block_reward(3) as i64);
        assert_eq!(chain.balance(&bob.node_id()), 10);
    }

    #[test]
    fn block_reward_halving_schedule() {
        assert_eq!(Chain::block_reward(0), 1_000);
        assert_eq!(Chain::block_reward(209_999), 1_000);
        assert_eq!(Chain::block_reward(210_000), 500);
        assert_eq!(Chain::block_reward(420_000), 250);
        assert_eq!(Chain::block_reward(630_000), 125);
        // Eventually reaches zero
        assert_eq!(Chain::block_reward(u64::MAX), 0);
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
        let mut chain = Chain::genesis();
        chain.difficulty = 1;
        mine_and_append(&mut chain, [9u8; 32]);

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
}
