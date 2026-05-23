use ce_identity::{Identity, verify};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn tmp_identity(tag: &str) -> Identity {
    let dir = std::env::temp_dir().join(format!("ce-bench-id-{}-{}", std::process::id(), tag));
    std::fs::create_dir_all(&dir).unwrap();
    Identity::load_or_generate(&dir).unwrap()
}

fn bench_sign(c: &mut Criterion) {
    let id = tmp_identity("sign");
    let data = b"benchmark payload for ed25519 signing";
    c.bench_function("identity_sign", |b| b.iter(|| black_box(id.sign(data))));
}

fn bench_verify(c: &mut Criterion) {
    let id = tmp_identity("verify");
    let data = b"benchmark payload for ed25519 verify";
    let sig = id.sign(data);
    let node_id = id.node_id();
    c.bench_function("identity_verify", |b| {
        b.iter(|| black_box(verify(&node_id, data, &sig).is_ok()))
    });
}

fn bench_key_load(c: &mut Criterion) {
    let dir = std::env::temp_dir().join(format!("ce-bench-load-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // Pre-generate the key so the bench measures load, not generate.
    Identity::load_or_generate(&dir).unwrap();
    c.bench_function("identity_load_from_disk", |b| {
        b.iter(|| black_box(Identity::load_or_generate(&dir).unwrap().node_id()))
    });
}

criterion_group!(benches, bench_sign, bench_verify, bench_key_load);
criterion_main!(benches);
