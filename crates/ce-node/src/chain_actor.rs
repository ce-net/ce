/// Chain actor — single-owner model replacing Arc<Mutex<Chain>>.
///
/// One dedicated task owns the Chain value. All callers send typed ChainCmd
/// messages and receive replies over oneshot channels. This eliminates:
///  - exclusive-lock contention between concurrent readers
///  - deadlock risk from acquiring multiple locks in different orders
///  - priority inversion (a cheap API read blocking an incoming block)
///  - DoS surface where a flood of sync requests could stall mining
///
/// The bounded channel (512) provides natural backpressure so an attacker
/// flooding sync requests can't OOM the node.

use anyhow::Result;
use ce_chain::{Block, Chain, NodeStats, Tx, TxKind};
use ce_identity::NodeId;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::{mpsc, oneshot};
use tracing::warn;

// ----- Snapshot types returned by combined reads -----

#[derive(Debug, Clone)]
pub struct ChainStatusSnap {
    pub height: u64,
    pub difficulty: u8,
    pub balance: i128,
}

#[derive(Debug, Clone)]
pub struct SyncSnap {
    pub height: u64,
    pub tip_hash: [u8; 32],
    pub oldest: u64,
}

// ----- Command enum -----

pub enum ChainCmd {
    // --- reads ---
    Balance { node: NodeId, reply: oneshot::Sender<i128> },
    /// Per-node interaction history (reputation substrate).
    NodeHistory { node: NodeId, reply: oneshot::Sender<NodeStats> },
    Height { reply: oneshot::Sender<u64> },
    Difficulty { reply: oneshot::Sender<u8> },
    /// Combined height + difficulty + balance — avoids two round-trips in status handlers.
    ChainStatus { node: NodeId, reply: oneshot::Sender<ChainStatusSnap> },
    /// Combined height + tip_hash + oldest — used by mesh sync handlers.
    SyncSnap { reply: oneshot::Sender<SyncSnap> },
    TxById { id: [u8; 32], reply: oneshot::Sender<Option<(Tx, u64, [u8; 32])>> },
    BlocksAfter { from_height: u64, max: usize, reply: oneshot::Sender<Vec<Block>> },
    ExportSegment { seg_id: u64, reply: oneshot::Sender<Option<Vec<Block>>> },
    HighestCompleteSegment { reply: oneshot::Sender<Option<u64>> },
    /// Rebuild heartbeat epoch counters for a host from chain history.
    HeartbeatEpochs { host: NodeId, reply: oneshot::Sender<HashMap<NodeId, u64>> },
    /// All JobSettle job_ids confirmed on-chain for a given host.
    SettledOnChain { host: NodeId, reply: oneshot::Sender<Vec<[u8; 32]>> },
    /// Find any tx in chain history with a burnable credit amount (used by tests/signals).
    AnyBurnableTx { reply: oneshot::Sender<Option<([u8; 32], u128)>> },
    /// Like AnyBurnableTx but restricted to txs where tx.origin == origin.
    /// Used by tests to avoid picking up txs from foreign chains after a reorg.
    AnyBurnableTxByOrigin { origin: NodeId, reply: oneshot::Sender<Option<([u8; 32], u128)>> },
    // --- writes ---
    NextBlock { txs: Vec<Tx>, miner: NodeId, reply: oneshot::Sender<Block> },
    Append { block: Block, reply: oneshot::Sender<bool> },
    TryReorg { blocks: Vec<Block>, reply: oneshot::Sender<bool> },
    Save { path: PathBuf, reply: oneshot::Sender<Result<(), String>> },
    Prune { keep: u64 },
}

// ----- Handle (cheap clone, lives in every task that needs chain access) -----

#[derive(Clone)]
pub struct ChainHandle(mpsc::Sender<ChainCmd>);

impl ChainHandle {
    pub async fn balance(&self, node: NodeId) -> i128 {
        let (tx, rx) = oneshot::channel();
        let _ = self.0.send(ChainCmd::Balance { node, reply: tx }).await;
        rx.await.unwrap_or(0)
    }

    pub async fn node_history(&self, node: NodeId) -> NodeStats {
        let (tx, rx) = oneshot::channel();
        let _ = self.0.send(ChainCmd::NodeHistory { node, reply: tx }).await;
        rx.await.unwrap_or_default()
    }

    pub async fn height(&self) -> u64 {
        let (tx, rx) = oneshot::channel();
        let _ = self.0.send(ChainCmd::Height { reply: tx }).await;
        rx.await.unwrap_or(0)
    }

    pub async fn difficulty(&self) -> u8 {
        let (tx, rx) = oneshot::channel();
        let _ = self.0.send(ChainCmd::Difficulty { reply: tx }).await;
        rx.await.unwrap_or(0)
    }

    pub async fn chain_status(&self, node: NodeId) -> ChainStatusSnap {
        let (tx, rx) = oneshot::channel();
        let _ = self.0.send(ChainCmd::ChainStatus { node, reply: tx }).await;
        rx.await.unwrap_or(ChainStatusSnap { height: 0, difficulty: 0, balance: 0 })
    }

    pub async fn sync_snap(&self) -> SyncSnap {
        let (tx, rx) = oneshot::channel();
        let _ = self.0.send(ChainCmd::SyncSnap { reply: tx }).await;
        rx.await.unwrap_or(SyncSnap { height: 0, tip_hash: [0u8; 32], oldest: 0 })
    }

    pub async fn tx_by_id(&self, id: [u8; 32]) -> Option<(Tx, u64, [u8; 32])> {
        let (tx, rx) = oneshot::channel();
        let _ = self.0.send(ChainCmd::TxById { id, reply: tx }).await;
        rx.await.ok().flatten()
    }

    pub async fn blocks_after(&self, from_height: u64, max: usize) -> Vec<Block> {
        let (tx, rx) = oneshot::channel();
        let _ = self.0.send(ChainCmd::BlocksAfter { from_height, max, reply: tx }).await;
        rx.await.unwrap_or_default()
    }

    pub async fn export_segment(&self, seg_id: u64) -> Option<Vec<Block>> {
        let (tx, rx) = oneshot::channel();
        let _ = self.0.send(ChainCmd::ExportSegment { seg_id, reply: tx }).await;
        rx.await.ok().flatten()
    }

    pub async fn highest_complete_segment(&self) -> Option<u64> {
        let (tx, rx) = oneshot::channel();
        let _ = self.0.send(ChainCmd::HighestCompleteSegment { reply: tx }).await;
        rx.await.ok().flatten()
    }

    pub async fn heartbeat_epochs(&self, host: NodeId) -> HashMap<NodeId, u64> {
        let (tx, rx) = oneshot::channel();
        let _ = self.0.send(ChainCmd::HeartbeatEpochs { host, reply: tx }).await;
        rx.await.unwrap_or_default()
    }

    pub async fn settled_on_chain(&self, host: NodeId) -> Vec<[u8; 32]> {
        let (tx, rx) = oneshot::channel();
        let _ = self.0.send(ChainCmd::SettledOnChain { host, reply: tx }).await;
        rx.await.unwrap_or_default()
    }

    pub async fn any_burnable_tx(&self) -> Option<([u8; 32], u128)> {
        let (tx, rx) = oneshot::channel();
        let _ = self.0.send(ChainCmd::AnyBurnableTx { reply: tx }).await;
        rx.await.ok().flatten()
    }

    pub async fn any_burnable_tx_by_origin(&self, origin: NodeId) -> Option<([u8; 32], u128)> {
        let (tx, rx) = oneshot::channel();
        let _ = self.0.send(ChainCmd::AnyBurnableTxByOrigin { origin, reply: tx }).await;
        rx.await.ok().flatten()
    }

    pub async fn next_block(&self, txs: Vec<Tx>, miner: NodeId) -> Block {
        let (tx, rx) = oneshot::channel();
        let _ = self.0.send(ChainCmd::NextBlock { txs, miner, reply: tx }).await;
        rx.await.expect("chain actor stopped")
    }

    pub async fn append(&self, block: Block) -> bool {
        let (tx, rx) = oneshot::channel();
        let _ = self.0.send(ChainCmd::Append { block, reply: tx }).await;
        rx.await.unwrap_or(false)
    }

    pub async fn try_reorg(&self, blocks: Vec<Block>) -> bool {
        let (tx, rx) = oneshot::channel();
        let _ = self.0.send(ChainCmd::TryReorg { blocks, reply: tx }).await;
        rx.await.unwrap_or(false)
    }

    pub async fn save(&self, path: PathBuf) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        let _ = self.0.send(ChainCmd::Save { path, reply: tx }).await;
        rx.await
            .unwrap_or_else(|_| Err("chain actor stopped".to_string()))
            .map_err(|e| anyhow::anyhow!(e))
    }

    pub async fn prune(&self, keep: u64) {
        let _ = self.0.send(ChainCmd::Prune { keep }).await;
    }
}

// ----- Actor spawn -----

/// Spawn the chain actor and return a `ChainHandle` to communicate with it.
/// The channel is bounded to 512 — this caps the command backlog so a flood
/// of attacker-driven sync requests can't consume unbounded memory.
pub fn spawn_chain_actor(chain: Chain) -> ChainHandle {
    let (tx, rx) = mpsc::channel(512);
    tokio::spawn(chain_actor(chain, rx));
    ChainHandle(tx)
}

// ----- Actor loop -----

async fn chain_actor(mut chain: Chain, mut rx: mpsc::Receiver<ChainCmd>) {
    while let Some(cmd) = rx.recv().await {
        match cmd {
            ChainCmd::Balance { node, reply } => {
                let _ = reply.send(chain.balance(&node));
            }
            ChainCmd::NodeHistory { node, reply } => {
                let _ = reply.send(chain.node_history(&node));
            }
            ChainCmd::Height { reply } => {
                let _ = reply.send(chain.height());
            }
            ChainCmd::Difficulty { reply } => {
                let _ = reply.send(chain.difficulty);
            }
            ChainCmd::ChainStatus { node, reply } => {
                let _ = reply.send(ChainStatusSnap {
                    height: chain.height(),
                    difficulty: chain.difficulty,
                    balance: chain.balance(&node),
                });
            }
            ChainCmd::SyncSnap { reply } => {
                let oldest = chain.blocks.first().map(|b| b.index).unwrap_or(0);
                let _ = reply.send(SyncSnap {
                    height: chain.height(),
                    tip_hash: chain.tip_hash(),
                    oldest,
                });
            }
            ChainCmd::TxById { id, reply } => {
                let _ = reply.send(chain.tx_by_id(&id));
            }
            ChainCmd::BlocksAfter { from_height, max, reply } => {
                let blocks: Vec<Block> = chain
                    .blocks
                    .iter()
                    .filter(|b| b.index > from_height)
                    .take(max)
                    .cloned()
                    .collect();
                let _ = reply.send(blocks);
            }
            ChainCmd::ExportSegment { seg_id, reply } => {
                let _ = reply.send(chain.export_segment(seg_id));
            }
            ChainCmd::HighestCompleteSegment { reply } => {
                let _ = reply.send(chain.highest_complete_segment());
            }
            ChainCmd::HeartbeatEpochs { host, reply } => {
                let mut epochs: HashMap<NodeId, u64> = HashMap::new();
                for block in &chain.blocks {
                    for tx in &block.transactions {
                        if let TxKind::Heartbeat { cell, host: h, epoch, .. } = &tx.kind {
                            if h == &host {
                                let e = epochs.entry(*cell).or_insert(0);
                                if *epoch >= *e {
                                    *e = *epoch + 1;
                                }
                            }
                        }
                    }
                }
                let _ = reply.send(epochs);
            }
            ChainCmd::SettledOnChain { host, reply } => {
                let settled: Vec<[u8; 32]> = chain
                    .blocks
                    .iter()
                    .flat_map(|b| &b.transactions)
                    .filter_map(|tx| {
                        if let TxKind::JobSettle { job_id, host: h, .. } = &tx.kind {
                            if h == &host { Some(*job_id) } else { None }
                        } else {
                            None
                        }
                    })
                    .collect();
                let _ = reply.send(settled);
            }
            ChainCmd::AnyBurnableTx { reply } => {
                let found = chain
                    .blocks
                    .iter()
                    .flat_map(|b| &b.transactions)
                    .find_map(|tx| tx_burn_amount(tx).map(|a| (tx.id(), a)));
                let _ = reply.send(found);
            }
            ChainCmd::AnyBurnableTxByOrigin { origin, reply } => {
                let found = chain
                    .blocks
                    .iter()
                    .flat_map(|b| &b.transactions)
                    .find_map(|tx| {
                        if tx.origin == origin {
                            tx_burn_amount(tx).map(|a| (tx.id(), a))
                        } else {
                            None
                        }
                    });
                let _ = reply.send(found);
            }
            ChainCmd::NextBlock { txs, miner, reply } => {
                let _ = reply.send(chain.next_block(txs, miner));
            }
            ChainCmd::Append { block, reply } => {
                let _ = reply.send(chain.append(block));
            }
            ChainCmd::TryReorg { blocks, reply } => {
                let _ = reply.send(chain.try_reorg(blocks));
            }
            ChainCmd::Save { path, reply } => {
                let result = chain.save(&path).map_err(|e| e.to_string());
                let _ = reply.send(result);
            }
            ChainCmd::Prune { keep } => {
                chain.prune(keep);
            }
        }
    }
    warn!("chain actor stopped — all ChainHandle instances dropped");
}

fn tx_burn_amount(tx: &Tx) -> Option<u128> {
    match &tx.kind {
        TxKind::Transfer { amount, .. } => Some(*amount),
        TxKind::UptimeReward { amount, .. } => Some(*amount),
        TxKind::JobBid { bid, .. } => Some(*bid),
        TxKind::JobSettle { cost, .. } => Some(*cost),
        TxKind::Heartbeat { amount, .. } => Some(*amount),
        TxKind::JobExpire { .. }
        | TxKind::TrustGrant { .. }
        | TxKind::ChannelOpen { .. }
        | TxKind::ChannelClose { .. }
        | TxKind::ChannelExpire { .. } => None,
    }
}
