use ark_bn254::Bn254;
use criterion::{criterion_group, criterion_main, Criterion};
use std::path::PathBuf;

fn groth16_zkey_parse(c: &mut Criterion) {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("../../test_vectors/Groth16/bn254/multiplier2/circuit.zkey");
    let zkey = std::fs::read(d).unwrap();
    c.bench_function("groth16 zkey parse", |b| {
        b.iter(|| {
            circom_types::groth16::ZKey::<Bn254>::from_reader(&zkey[..]).unwrap();
        })
    });
}

fn plonk_zkey_parse(c: &mut Criterion) {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("../../test_vectors/Plonk/bn254/multiplier2/circuit.zkey");
    let zkey = std::fs::read(d).unwrap();
    c.bench_function("plonk zkey parse", |b| {
        b.iter(|| {
            circom_types::plonk::ZKey::<Bn254>::from_reader(&zkey[..]).unwrap();
        })
    });
}

criterion_group!(benches, groth16_zkey_parse, plonk_zkey_parse);
criterion_main!(benches);
