use ark_serialize::{CanonicalDeserialize as _, CanonicalSerialize as _};
use ark_std::UniformRand as _;
use criterion::*;
use mpc_core::protocols::wire;

type F = ark_bn254::Fr;

fn wire_bench(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    for exp in [16u32, 20] {
        let n = 1usize << exp;
        let data: Vec<F> = (0..n).map(|_| F::rand(&mut rng)).collect();

        let mut group = c.benchmark_group(format!("serialize 2^{exp} bn254 scalars"));
        group.throughput(Throughput::Elements(n as u64));
        // The production ark send path (`send_many`) additionally pays this O(n)
        // sizing pass per message, so the measured ark-vs-raw gap is a lower bound
        // on the production send-path win.
        let ark_size = data.serialized_size(ark_serialize::Compress::No);
        group.bench_function("ark uncompressed", |b| {
            b.iter(|| {
                let mut ser = Vec::with_capacity(ark_size);
                data.serialize_uncompressed(&mut ser).unwrap();
                black_box(ser)
            })
        });
        group.bench_function("raw wire", |b| b.iter(|| black_box(wire::to_bytes(&data))));
        group.finish();

        let mut ark_ser = Vec::new();
        data.serialize_uncompressed(&mut ark_ser).unwrap();
        let raw = wire::to_bytes(&data);
        let mut group = c.benchmark_group(format!("deserialize 2^{exp} bn254 scalars"));
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function("ark uncompressed unchecked", |b| {
            b.iter(|| {
                black_box(Vec::<F>::deserialize_uncompressed_unchecked(ark_ser.as_slice()).unwrap())
            })
        });
        group.bench_function("raw wire", |b| {
            // `clone` on `Bytes` is a refcount bump, not a copy
            b.iter(|| black_box(wire::from_bytes::<F>(raw.clone()).unwrap()))
        });
        group.finish();
    }
}

criterion_group!(benches, wire_bench);
criterion_main!(benches);
