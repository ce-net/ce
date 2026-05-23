use ce_identity::Identity;
use ce_protocol::{BurnProof, CellAddress, CellSignal, Capability};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn tmp_identity(tag: &str) -> Identity {
    let dir =
        std::env::temp_dir().join(format!("ce-bench-proto-{}-{}", std::process::id(), tag));
    std::fs::create_dir_all(&dir).unwrap();
    Identity::load_or_generate(&dir).unwrap()
}

fn make_signal(id: &Identity, payload_len: usize, with_burn: bool) -> CellSignal {
    let payload = vec![0xABu8; payload_len];
    let burn = with_burn.then_some(BurnProof {
        tx_id: [1u8; 32],
        amount: 100,
        block_height: 42,
        block_hash: [2u8; 32],
    });
    CellSignal::build(
        id.node_id(),
        CellAddress::Broadcast,
        vec![Capability { name: "inference".into(), version: 1 }],
        payload,
        burn,
        0,
        id,
    )
}

// ----- signal_build (sign) -----

fn bench_signal_build(c: &mut Criterion) {
    let id = tmp_identity("build");
    let node_id = id.node_id();
    let mut group = c.benchmark_group("signal_build");
    for payload_len in [0usize, 64, 1024] {
        group.bench_with_input(
            BenchmarkId::new("payload_bytes", payload_len),
            &payload_len,
            |b, &len| {
                b.iter(|| {
                    black_box(CellSignal::build(
                        node_id,
                        CellAddress::Broadcast,
                        vec![],
                        vec![0u8; len],
                        None,
                        0,
                        &id,
                    ))
                })
            },
        );
    }
    group.finish();
}

// ----- signal_verify -----

fn bench_signal_verify(c: &mut Criterion) {
    let id = tmp_identity("verify");
    let signal = make_signal(&id, 64, true);
    c.bench_function("signal_verify", |b| {
        b.iter(|| black_box(signal.verify().is_ok()))
    });
}

// ----- encode / decode (bincode) -----

fn bench_signal_codec(c: &mut Criterion) {
    let id = tmp_identity("codec");
    let mut group = c.benchmark_group("signal_codec");
    for payload_len in [0usize, 64, 1024] {
        let signal = make_signal(&id, payload_len, payload_len > 0);
        let encoded = signal.encode().unwrap();
        group.bench_with_input(
            BenchmarkId::new("encode_bytes", payload_len),
            &payload_len,
            |b, _| b.iter(|| black_box(signal.encode().unwrap())),
        );
        group.bench_with_input(
            BenchmarkId::new("decode_bytes", payload_len),
            &payload_len,
            |b, _| b.iter(|| black_box(CellSignal::decode(&encoded).unwrap())),
        );
    }
    group.finish();
}

// ----- signal_id (SHA256) -----

fn bench_signal_id(c: &mut Criterion) {
    let id = tmp_identity("sid");
    let signal = make_signal(&id, 64, true);
    c.bench_function("signal_id", |b| b.iter(|| black_box(signal.id())));
}

criterion_group!(
    benches,
    bench_signal_build,
    bench_signal_verify,
    bench_signal_codec,
    bench_signal_id,
);
criterion_main!(benches);
