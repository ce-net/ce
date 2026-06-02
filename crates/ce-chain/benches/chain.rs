use ce_chain::{Chain, Tx, TxKind};
use ce_identity::Identity;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn tmp_identity(tag: &str) -> Identity {
    let dir = std::env::temp_dir().join(format!("ce-bench-chain-{}-{}", std::process::id(), tag));
    std::fs::create_dir_all(&dir).unwrap();
    Identity::load_or_generate(&dir).unwrap()
}

fn signed_transfer(from: &Identity, to: ce_identity::NodeId, amount: u128) -> Tx {
    let kind = TxKind::Transfer { from: from.node_id(), to, amount };
    let data = bincode::serialize(&kind).unwrap();
    let sig = from.sign(&data);
    Tx::new(kind, from.node_id(), sig)
}

// Build a chain of `n` sealed blocks, each carrying one transfer tx.
fn build_chain(n: u64) -> (Chain, Identity) {
    let id = tmp_identity(&format!("build{n}"));
    let mut chain = Chain::genesis();
    for _ in 0..n {
        let tx = signed_transfer(&id, [1u8; 32], 1);
        let mut block = chain.next_block(vec![tx], id.node_id());
        block.seal(&id);
        chain.append(block);
    }
    (chain, id)
}

// ----- block_hash -----

fn bench_block_hash(c: &mut Criterion) {
    let chain = Chain::genesis();
    let block = chain.next_block(vec![], [0u8; 32]);
    c.bench_function("block_hash", |b| b.iter(|| black_box(block.hash())));
}

// ----- block_seal / verify_seal -----

fn bench_block_seal(c: &mut Criterion) {
    let id = tmp_identity("seal");
    let chain = Chain::genesis();
    let mut group = c.benchmark_group("block_seal");
    group.bench_function("seal", |b| {
        b.iter_batched(
            || chain.next_block(vec![], id.node_id()),
            |mut block| { block.seal(&id); black_box(block) },
            criterion::BatchSize::SmallInput,
        )
    });
    group.bench_function("verify_seal", |b| {
        let mut block = chain.next_block(vec![], id.node_id());
        block.seal(&id);
        b.iter(|| black_box(block.verify_seal()))
    });
    group.finish();
}

// ----- chain_append -----

fn bench_chain_append(c: &mut Criterion) {
    let id = tmp_identity("append_setup");
    c.bench_function("chain_append", |b| {
        b.iter_batched(
            || {
                let mut chain = Chain::genesis();
                let mut block = chain.next_block(vec![], id.node_id());
                block.seal(&id);
                (chain, block)
            },
            |(mut chain, block)| black_box(chain.append(block)),
            criterion::BatchSize::SmallInput,
        )
    });
}

// ----- tx_verify -----

fn bench_tx_verify(c: &mut Criterion) {
    let id = tmp_identity("txverify");
    let tx = signed_transfer(&id, [1u8; 32], 100);
    c.bench_function("tx_verify", |b| b.iter(|| black_box(tx.verify().is_ok())));
}

// ----- tx_id -----

fn bench_tx_id(c: &mut Criterion) {
    let id = tmp_identity("txid");
    let tx = signed_transfer(&id, [1u8; 32], 100);
    c.bench_function("tx_id", |b| b.iter(|| black_box(tx.id())));
}

// ----- chain_balance scan over N blocks -----

fn bench_chain_balance(c: &mut Criterion) {
    let mut group = c.benchmark_group("chain_balance");
    for n in [10u64, 100, 500] {
        let (chain, id) = build_chain(n);
        let node_id = id.node_id();
        group.bench_with_input(BenchmarkId::new("blocks", n), &n, |b, _| {
            b.iter(|| black_box(chain.balance(&node_id)))
        });
    }
    group.finish();
}

// ----- JSON serialize / deserialize -----

fn bench_chain_json(c: &mut Criterion) {
    let (chain, _) = build_chain(50);
    let json = serde_json::to_string(&chain).unwrap();

    let mut group = c.benchmark_group("chain_json");
    group.bench_function("serialize/50blocks", |b| {
        b.iter(|| black_box(serde_json::to_string(&chain).unwrap()))
    });
    group.bench_function("deserialize/50blocks", |b| {
        b.iter(|| black_box(serde_json::from_str::<Chain>(&json).unwrap()))
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_block_hash,
    bench_block_seal,
    bench_chain_append,
    bench_tx_verify,
    bench_tx_id,
    bench_chain_balance,
    bench_chain_json,
);
criterion_main!(benches);
