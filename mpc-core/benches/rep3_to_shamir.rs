use ark_bn254::Fr;
use ark_ff::{Field, UniformRand};
use criterion::{
    BatchSize, BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main,
};
use mpc_core::protocols::{
    rep3::{Rep3PrimeFieldShare, id::PartyID},
    shamir::{ShamirPrimeFieldShare, ShamirState},
};
use rand::thread_rng;

fn benchmark_translation(c: &mut Criterion) {
    let available_threads = std::thread::available_parallelism().map_or(1, usize::from);
    let mut thread_counts = vec![1, 8, available_threads];
    thread_counts.sort_unstable();
    thread_counts.dedup();

    for threads in thread_counts {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap();
        let mut group = c.benchmark_group(format!("rep3_to_shamir/{threads}_threads"));

        for size in [256, 4096, 65536, 1_048_576] {
            let mut rng = thread_rng();
            let input = (0..size)
                .map(|_| Rep3PrimeFieldShare::new(Fr::rand(&mut rng), Fr::rand(&mut rng)))
                .collect::<Vec<_>>();
            group.throughput(Throughput::Elements(size as u64));

            group.bench_with_input(BenchmarkId::new("serial", size), &input, |b, input| {
                b.iter_batched(
                    || input.clone(),
                    |input| black_box(translate_serial(black_box(input))),
                    BatchSize::LargeInput,
                )
            });
            group.bench_with_input(BenchmarkId::new("adaptive", size), &input, |b, input| {
                b.iter_batched(
                    || input.clone(),
                    |input| {
                        pool.install(|| {
                            black_box(ShamirState::translate_primefield_repshare_vec(
                                black_box(input),
                                PartyID::ID0,
                            ))
                        })
                    },
                    BatchSize::LargeInput,
                )
            });
        }
        group.finish();
    }
}

fn translate_serial(input: Vec<Rep3PrimeFieldShare<Fr>>) -> Vec<ShamirPrimeFieldShare<Fr>> {
    // Translation coefficients for party 0, computed once as in the production implementation.
    let x = Fr::from(2_u64) * Fr::from(3_u64).inverse().unwrap();
    let y = Fr::from(2_u64).inverse().unwrap();
    input
        .into_iter()
        .map(|share| ShamirPrimeFieldShare {
            a: share.a * x + share.b * y,
        })
        .collect()
}

criterion_group!(benches, benchmark_translation);
criterion_main!(benches);
