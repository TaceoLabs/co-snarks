//! Benchmarks the Shamir double-share generation (preprocessing) and the king-based degree
//! reduction (online multiplication), with all parties running in one process over a
//! [`LocalNetwork`].
//!
//! The reported time is the slowest party's time, i.e., the time until the protocol is done.

use std::{
    sync::{Arc, Barrier},
    time::{Duration, Instant},
};

use ark_bn254::Fr;
use ark_ff::UniformRand;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use mpc_core::protocols::shamir::{
    ShamirPreprocessing, ShamirPrimeFieldShare, ShamirState, arithmetic,
};
use mpc_net::local::LocalNetwork;
use rand::thread_rng;

const CONFIGS: [(usize, usize); 3] = [(3, 1), (5, 2), (10, 4)];
const SIZES: [usize; 2] = [1 << 14, 1 << 18];

/// Runs the preprocessing for `size` pairs for all parties, returning the slowest party's time.
fn run_preprocessing(num_parties: usize, threshold: usize, size: usize) -> Duration {
    let nets = LocalNetwork::new(num_parties);
    let handles = nets
        .into_iter()
        .map(|net| {
            std::thread::spawn(move || {
                let start = Instant::now();
                let prep = ShamirPreprocessing::<Fr>::new(num_parties, threshold, size, &net)
                    .expect("preprocessing works");
                let elapsed = start.elapsed();
                drop(prep);
                elapsed
            })
        })
        .collect::<Vec<_>>();
    handles
        .into_iter()
        .map(|h| h.join().expect("party does not panic"))
        .max()
        .expect("at least one party")
}

/// Runs one vector multiplication of `size` elements (preprocessing excluded), returning the
/// slowest party's time.
fn run_mul_vec(num_parties: usize, threshold: usize, size: usize) -> Duration {
    let nets = LocalNetwork::new(num_parties);
    // The multiplication does not care whether the inputs are consistent sharings.
    let mut rng = thread_rng();
    // All parties start the multiplication together, once every preprocessing is done
    let barrier = Arc::new(Barrier::new(num_parties));
    let handles = nets
        .into_iter()
        .map(|net| {
            let barrier = Arc::clone(&barrier);
            let a = (0..size)
                .map(|_| ShamirPrimeFieldShare::new(Fr::rand(&mut rng)))
                .collect::<Vec<_>>();
            let b = a.clone();
            std::thread::spawn(move || {
                let mut state: ShamirState<Fr> =
                    ShamirPreprocessing::new(num_parties, threshold, size, &net)
                        .expect("preprocessing works")
                        .into();
                barrier.wait();
                let start = Instant::now();
                let res = arithmetic::mul_vec(&a, &b, &net, &mut state).expect("mul works");
                let elapsed = start.elapsed();
                drop(res);
                elapsed
            })
        })
        .collect::<Vec<_>>();
    handles
        .into_iter()
        .map(|h| h.join().expect("party does not panic"))
        .max()
        .expect("at least one party")
}

fn bench(c: &mut Criterion) {
    for (name, f) in [
        (
            "shamir/preprocessing",
            run_preprocessing as fn(usize, usize, usize) -> Duration,
        ),
        ("shamir/mul_vec", run_mul_vec),
    ] {
        let mut group = c.benchmark_group(name);
        group.sample_size(10);
        for (num_parties, threshold) in CONFIGS {
            for size in SIZES {
                group.throughput(Throughput::Elements(size as u64));
                group.bench_function(
                    BenchmarkId::new(format!("n{num_parties}_t{threshold}"), size),
                    |b| {
                        b.iter_custom(|iters| {
                            (0..iters)
                                .map(|_| f(num_parties, threshold, size))
                                .sum::<Duration>()
                        })
                    },
                );
            }
        }
        group.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
