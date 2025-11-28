use ark_bn254::Bn254;
use circom_types::CheckElement;
use criterion::{Criterion, criterion_group, criterion_main};
use std::path::PathBuf;

fn groth16_zkey_parse_check_elements(c: &mut Criterion) {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("../../test_vectors/Groth16/bn254/multiplier2/circuit.zkey");
    let zkey = std::fs::read(d).unwrap();
    c.bench_function("groth16 zkey parse", |b| {
        b.iter(|| {
            circom_types::groth16::Zkey::<Bn254>::from_reader(&zkey[..], CheckElement::Yes)
                .unwrap();
        })
    });
}

fn plonk_zkey_parse_check_elements(c: &mut Criterion) {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("../../test_vectors/Plonk/bn254/multiplier2/circuit.zkey");
    let zkey = std::fs::read(d).unwrap();
    c.bench_function("plonk zkey parse", |b| {
        b.iter(|| {
            circom_types::plonk::Zkey::<Bn254>::from_reader(&zkey[..], CheckElement::Yes).unwrap();
        })
    });
}

fn groth16_zkey_parse_dont_check_elements(c: &mut Criterion) {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("../../test_vectors/Groth16/bn254/multiplier2/circuit.zkey");
    let zkey = std::fs::read(d).unwrap();
    c.bench_function("groth16 zkey parse", |b| {
        b.iter(|| {
            circom_types::groth16::Zkey::<Bn254>::from_reader(&zkey[..], CheckElement::No).unwrap();
        })
    });
}

fn plonk_zkey_parse_dont_check_elements(c: &mut Criterion) {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("../../test_vectors/Plonk/bn254/multiplier2/circuit.zkey");
    let zkey = std::fs::read(d).unwrap();
    c.bench_function("plonk zkey parse", |b| {
        b.iter(|| {
            circom_types::plonk::Zkey::<Bn254>::from_reader(&zkey[..], CheckElement::No).unwrap();
        })
    });
}

criterion_group!(
    benches,
    groth16_zkey_parse_check_elements,
    plonk_zkey_parse_check_elements,
    groth16_zkey_parse_dont_check_elements,
    plonk_zkey_parse_dont_check_elements
);
criterion_main!(benches);
