use ark_ff::UniformRand;
use criterion::*;
use mpc_core::gadgets::poseidon2::Poseidon2;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

type Fr = ark_bn254::Fr;

fn bench_permutation<const T: usize>(c: &mut Criterion, label: &str)
where
    Poseidon2<Fr, T, 5>: Default,
{
    let poseidon = Poseidon2::<Fr, T, 5>::default();
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let input: [Fr; T] = std::array::from_fn(|_| Fr::rand(&mut rng));

    let mut group = c.benchmark_group(label);
    group.throughput(Throughput::Elements(1));
    group.bench_function("permutation", |b| {
        b.iter(|| {
            let mut state = black_box(input);
            poseidon.permutation_in_place(&mut state);
            black_box(state);
        })
    });

    // Also benchmark a batch so per-call overhead dilutes
    let batch = 1000usize;
    let inputs: Vec<[Fr; T]> = (0..batch)
        .map(|_| std::array::from_fn(|_| Fr::rand(&mut rng)))
        .collect();
    group.throughput(Throughput::Elements(batch as u64));
    group.bench_function(BenchmarkId::new("permutation_batch", batch), |b| {
        b.iter(|| {
            for inp in inputs.iter() {
                let mut state = *inp;
                poseidon.permutation_in_place(&mut state);
                black_box(state);
            }
        })
    });
    group.finish();
}

fn poseidon2_bench(c: &mut Criterion) {
    bench_permutation::<2>(c, "poseidon2_bn254_t2");
    bench_permutation::<3>(c, "poseidon2_bn254_t3");
    bench_permutation::<4>(c, "poseidon2_bn254_t4");
    bench_permutation::<16>(c, "poseidon2_bn254_t16");
}

criterion_group!(benches, poseidon2_bench);
criterion_main!(benches);
