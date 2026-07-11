use bipon39::{compute_wordlist_merkle_root, entropy_to_mnemonic, mnemonic_to_seed};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn entropy_to_mnemonic_256(c: &mut Criterion) {
    let entropy = [0x42u8; 32];
    c.bench_function("entropy_to_mnemonic_256", |b| {
        b.iter(|| entropy_to_mnemonic(black_box(&entropy)).unwrap())
    });
}

fn mnemonic_to_seed_256(c: &mut Criterion) {
    let entropy = [0x42u8; 32];
    let mnemonic = entropy_to_mnemonic(&entropy).unwrap();
    let words = mnemonic.iter().map(String::as_str).collect::<Vec<_>>();

    c.bench_function("mnemonic_to_seed_256", |b| {
        b.iter(|| mnemonic_to_seed(black_box(&words), black_box("àṣẹ")).unwrap())
    });
}

fn wordlist_merkle_root(c: &mut Criterion) {
    c.bench_function("compute_wordlist_merkle_root", |b| {
        b.iter(compute_wordlist_merkle_root)
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(100);
    targets = entropy_to_mnemonic_256, mnemonic_to_seed_256, wordlist_merkle_root
}
criterion_main!(benches);
