//! Benchmarks for the Poseidon2 *circom accelerator* paths in
//! [`mpc_core::gadgets::poseidon2::poseidon2_circom_accelerator`].
//!
//! These functions compute a Poseidon2 permutation **plus** the intermediate witness values
//! needed to build a circom trace; they are what coCircom's witness extension calls into.
//!
//! Two layers are benchmarked:
//!
//! 1. The plain (single-party) `plain_permutation_intermediate` from the
//!    [`CircomTracePlainHasher`] trait. This is what plain witness extension and the public-only
//!    fallback in the MPC VM use.
//! 2. The Rep3 MPC variant `rep3_permutation_in_place_with_precomputation_intermediate` over an
//!    in-process [`LocalNetwork`] (3 parties). This is the actual hot path inside coCircom MPC
//!    witness extension when poseidon2 is invoked.
//!
//! Sizes covered: t=2, t=3, t=4, t=16 (the four state sizes the circom accelerator supports).

use std::array;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use ark_bn254::Fr;
use ark_ff::UniformRand;
use criterion::*;
use itertools::izip;
use mpc_core::{
    gadgets::poseidon2::{CircomTracePlainHasher, Poseidon2},
    protocols::rep3::{self, Rep3PrimeFieldShare, Rep3State, conversion::A2BType},
};
use mpc_net::local::LocalNetwork;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const NUM_PARTIES: usize = 3;
/// Cap on perms per precompute batch to keep memory bounded for large `iters` from criterion.
const PRECOMP_BATCH_CAP: usize = 64;

// ---- Plain (single-party) ---------------------------------------------------

fn bench_plain_intermediate<const T: usize>(c: &mut Criterion, label: &str)
where
    Poseidon2<Fr, T, 5>: Default + CircomTracePlainHasher<Fr, T>,
{
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let input: [Fr; T] = array::from_fn(|_| Fr::rand(&mut rng));
    let poseidon = Poseidon2::<Fr, T, 5>::default();

    let mut group = c.benchmark_group(label);
    group.throughput(Throughput::Elements(1));

    group.bench_function("plain_permutation_intermediate", |b| {
        b.iter(|| {
            let (out, trace) = poseidon
                .plain_permutation_intermediate(black_box(input))
                .unwrap();
            black_box((out, trace));
        });
    });

    let batch = 1000usize;
    let inputs: Vec<[Fr; T]> = (0..batch)
        .map(|_| array::from_fn(|_| Fr::rand(&mut rng)))
        .collect();
    group.throughput(Throughput::Elements(batch as u64));
    group.bench_function(
        BenchmarkId::new("plain_permutation_intermediate_batch", batch),
        |b| {
            b.iter(|| {
                for inp in &inputs {
                    let (out, trace) = poseidon.plain_permutation_intermediate(*inp).unwrap();
                    black_box((out, trace));
                }
            });
        },
    );

    group.finish();
}

// ---- Rep3 (3-party LocalNetwork) -------------------------------------------

fn rep3_input_shares<const T: usize>(rng: &mut ChaCha20Rng) -> [Vec<Rep3PrimeFieldShare<Fr>>; 3] {
    let input: [Fr; T] = array::from_fn(|_| Fr::rand(rng));
    rep3::share_field_elements(&input, rng)
}

fn collect_max_elapsed(done_rx: &mpsc::Receiver<Duration>) -> Duration {
    let mut max = Duration::ZERO;
    for _ in 0..NUM_PARTIES {
        let elapsed = done_rx.recv().unwrap();
        if elapsed > max {
            max = elapsed;
        }
    }
    max
}

fn run_in_precomp_batches(iters: u64, mut f: impl FnMut(usize) -> Duration) -> Duration {
    let total = iters as usize;
    let mut elapsed = Duration::ZERO;
    let mut completed = 0;
    while completed < total {
        let batch = (total - completed).min(PRECOMP_BATCH_CAP);
        elapsed += f(batch);
        completed += batch;
    }
    elapsed
}

fn bench_rep3_intermediate<const T: usize>(c: &mut Criterion, label: &str)
where
    Poseidon2<Fr, T, 5>: Default,
{
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let input_shares = rep3_input_shares::<T>(&mut rng);

    let mut group = c.benchmark_group(label);
    group.throughput(Throughput::Elements(1));

    group.bench_function("rep3_permutation_with_precomputation_intermediate", |b| {
        b.iter_custom(|iters| {
            let nets = LocalNetwork::new_3_parties();
            let (done_tx, done_rx) = mpsc::channel::<Duration>();

            for (net, share) in izip!(nets.into_iter(), input_shares.clone().into_iter()) {
                let done_tx = done_tx.clone();
                std::thread::spawn(move || {
                    let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                    let poseidon = Poseidon2::<Fr, T, 5>::default();
                    let share_arr: [Rep3PrimeFieldShare<Fr>; T] =
                        share.try_into().expect("len = T");

                    let elapsed = run_in_precomp_batches(iters, |batch| {
                        let mut precomp =
                            poseidon.precompute_rep3(batch, &net, &mut state).unwrap();
                        let t0 = Instant::now();
                        for _ in 0..batch {
                            let mut s = share_arr;
                            let trace = poseidon
                                .rep3_permutation_in_place_with_precomputation_intermediate(
                                    &mut s,
                                    &mut precomp,
                                    &net,
                                )
                                .unwrap();
                            black_box((s, trace));
                        }
                        t0.elapsed()
                    });
                    done_tx.send(elapsed).unwrap();
                });
            }

            collect_max_elapsed(&done_rx)
        });
    });

    group.finish();
}

// ---- entry point -----------------------------------------------------------

fn poseidon2_circom_accelerator_bench(c: &mut Criterion) {
    bench_plain_intermediate::<2>(c, "plain_circom_accelerator_t2");
    bench_plain_intermediate::<3>(c, "plain_circom_accelerator_t3");
    bench_plain_intermediate::<4>(c, "plain_circom_accelerator_t4");
    bench_plain_intermediate::<16>(c, "plain_circom_accelerator_t16");

    bench_rep3_intermediate::<2>(c, "rep3_circom_accelerator_t2");
    bench_rep3_intermediate::<3>(c, "rep3_circom_accelerator_t3");
    bench_rep3_intermediate::<4>(c, "rep3_circom_accelerator_t4");
    bench_rep3_intermediate::<16>(c, "rep3_circom_accelerator_t16");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = poseidon2_circom_accelerator_bench
}
criterion_main!(benches);
