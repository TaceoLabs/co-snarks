//! Benchmarks for the MPC variants of the Poseidon2 permutation (REP3 and Shamir, 3 parties).
//!
//! Each iteration runs in 3 worker threads connected via in-process [`LocalNetwork`]s. The
//! reported time is the wall-clock duration of the slowest party (`max` across the three),
//! since that is what determines the protocol's actual completion time.
//!
//! Variants benchmarked:
//!   * REP3:   `rep3_permutation`, `rep3_permutation_with_precomputation`,
//!             `rep3_permutation_additive_with_precomputation`
//!   * Shamir: `shamir_permutation`, `shamir_permutation_with_precomputation`
//!
//! Network/state setup is hoisted out of the timed region. For the precompute-based variants the
//! precomputation itself is also outside the timed region — the bench measures only the online
//! permutation cost given precomputed randomness, batching to keep memory bounded.

use std::array;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use ark_bn254::Fr;
use ark_ff::UniformRand;
use criterion::*;
use itertools::izip;
use mpc_core::{
    gadgets::poseidon2::Poseidon2,
    protocols::{
        rep3::{self, Rep3PrimeFieldShare, Rep3State, conversion::A2BType},
        shamir::{self, ShamirPreprocessing, ShamirPrimeFieldShare, ShamirState},
    },
};
use mpc_net::local::LocalNetwork;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const NUM_PARTIES: usize = 3;
/// Threshold t=1 for 3-party Shamir is the standard configuration matching REP3's security model.
const SHAMIR_THRESHOLD: usize = 1;
/// Cap on perms per precompute batch to keep memory bounded for large `iters` from criterion.
const PRECOMP_BATCH_CAP: usize = 64;

// ---- REP3 -------------------------------------------------------------------

fn rep3_input_shares<const T: usize>(rng: &mut ChaCha20Rng) -> [Vec<Rep3PrimeFieldShare<Fr>>; 3] {
    let input: [Fr; T] = array::from_fn(|_| Fr::rand(rng));
    rep3::share_field_elements(&input, rng)
}

fn bench_rep3_permutation<const T: usize>(c: &mut Criterion, label: &str)
where
    Poseidon2<Fr, T, 5>: Default,
{
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let input_shares = rep3_input_shares::<T>(&mut rng);

    let mut group = c.benchmark_group(label);
    group.throughput(Throughput::Elements(1));

    group.bench_function("rep3_permutation", |b| {
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

                    let t0 = Instant::now();
                    for _ in 0..iters {
                        let mut s = share_arr;
                        poseidon
                            .rep3_permutation_in_place(&mut s, &net, &mut state)
                            .unwrap();
                        black_box(s);
                    }
                    let elapsed = t0.elapsed();
                    done_tx.send(elapsed).unwrap();
                });
            }

            collect_max_elapsed(&done_rx)
        })
    });

    group.bench_function("rep3_permutation_with_precomputation", |b| {
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
                            poseidon
                                .rep3_permutation_in_place_with_precomputation(
                                    &mut s,
                                    &mut precomp,
                                    &net,
                                )
                                .unwrap();
                            black_box(s);
                        }
                        t0.elapsed()
                    });
                    done_tx.send(elapsed).unwrap();
                });
            }

            collect_max_elapsed(&done_rx)
        })
    });

    group.bench_function("rep3_permutation_additive_with_precomputation", |b| {
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
                        let mut precomp = poseidon
                            .precompute_rep3_additive(batch, &net, &mut state)
                            .unwrap();
                        let t0 = Instant::now();
                        for _ in 0..batch {
                            let mut s = share_arr;
                            poseidon
                                .rep3_permutation_additive_in_place_with_precomputation(
                                    &mut s,
                                    &mut precomp,
                                    &net,
                                    &mut state,
                                )
                                .unwrap();
                            black_box(s);
                        }
                        t0.elapsed()
                    });
                    done_tx.send(elapsed).unwrap();
                });
            }

            collect_max_elapsed(&done_rx)
        })
    });

    group.finish();
}

// ---- Shamir -----------------------------------------------------------------

fn shamir_input_shares<const T: usize>(rng: &mut ChaCha20Rng) -> Vec<Vec<ShamirPrimeFieldShare<Fr>>> {
    let input: [Fr; T] = array::from_fn(|_| Fr::rand(rng));
    shamir::share_field_elements(&input, SHAMIR_THRESHOLD, NUM_PARTIES, rng)
}

fn bench_shamir_permutation<const T: usize>(c: &mut Criterion, label: &str)
where
    Poseidon2<Fr, T, 5>: Default,
{
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let input_shares = shamir_input_shares::<T>(&mut rng);

    let mut group = c.benchmark_group(label);
    group.throughput(Throughput::Elements(1));

    group.bench_function("shamir_permutation", |b| {
        b.iter_custom(|iters| {
            let nets = LocalNetwork::new(NUM_PARTIES);
            let (done_tx, done_rx) = mpsc::channel::<Duration>();

            for (net, share) in izip!(nets.into_iter(), input_shares.clone().into_iter()) {
                let done_tx = done_tx.clone();
                std::thread::spawn(move || {
                    let poseidon = Poseidon2::<Fr, T, 5>::default();
                    let share_arr: [ShamirPrimeFieldShare<Fr>; T] =
                        share.try_into().expect("len = T");

                    let elapsed = run_in_precomp_batches(iters, |batch| {
                        let rand_required = poseidon.rand_required(batch, false);
                        let mut state: ShamirState<Fr> = ShamirPreprocessing::new(
                            NUM_PARTIES,
                            SHAMIR_THRESHOLD,
                            rand_required,
                            &net,
                        )
                        .unwrap()
                        .into();

                        let t0 = Instant::now();
                        for _ in 0..batch {
                            let s = poseidon
                                .shamir_permutation(&share_arr, &net, &mut state)
                                .unwrap();
                            black_box(s);
                        }
                        t0.elapsed()
                    });
                    done_tx.send(elapsed).unwrap();
                });
            }

            collect_max_elapsed(&done_rx)
        })
    });

    group.bench_function("shamir_permutation_with_precomputation", |b| {
        b.iter_custom(|iters| {
            let nets = LocalNetwork::new(NUM_PARTIES);
            let (done_tx, done_rx) = mpsc::channel::<Duration>();

            for (net, share) in izip!(nets.into_iter(), input_shares.clone().into_iter()) {
                let done_tx = done_tx.clone();
                std::thread::spawn(move || {
                    let poseidon = Poseidon2::<Fr, T, 5>::default();
                    let share_arr: [ShamirPrimeFieldShare<Fr>; T] =
                        share.try_into().expect("len = T");

                    let elapsed = run_in_precomp_batches(iters, |batch| {
                        let rand_required = poseidon.rand_required(batch, true);
                        let mut state: ShamirState<Fr> = ShamirPreprocessing::new(
                            NUM_PARTIES,
                            SHAMIR_THRESHOLD,
                            rand_required,
                            &net,
                        )
                        .unwrap()
                        .into();
                        let mut precomp = poseidon
                            .precompute_shamir(batch, &net, &mut state)
                            .unwrap();

                        let t0 = Instant::now();
                        for _ in 0..batch {
                            let mut s = share_arr;
                            poseidon
                                .shamir_permutation_in_place_with_precomputation(
                                    &mut s,
                                    &mut precomp,
                                    &net,
                                    &mut state,
                                )
                                .unwrap();
                            black_box(s);
                        }
                        t0.elapsed()
                    });
                    done_tx.send(elapsed).unwrap();
                });
            }

            collect_max_elapsed(&done_rx)
        })
    });

    group.finish();
}

// ---- helpers ----------------------------------------------------------------

/// Collect the elapsed durations from all 3 parties and return the slowest one — that's the
/// protocol's actual completion time on a real network.
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

/// Run `iters` total permutations in batches of at most `PRECOMP_BATCH_CAP`, summing only the
/// online (post-precompute) duration returned by `f`. Caps memory for the precomputed randomness.
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

// ---- entry point -----------------------------------------------------------

fn poseidon2_mpc_bench(c: &mut Criterion) {
    bench_rep3_permutation::<2>(c, "rep3_poseidon2_bn254_t2");
    bench_rep3_permutation::<3>(c, "rep3_poseidon2_bn254_t3");
    bench_rep3_permutation::<4>(c, "rep3_poseidon2_bn254_t4");
    bench_rep3_permutation::<16>(c, "rep3_poseidon2_bn254_t16");

    bench_shamir_permutation::<2>(c, "shamir_poseidon2_bn254_t2");
    bench_shamir_permutation::<3>(c, "shamir_poseidon2_bn254_t3");
    bench_shamir_permutation::<4>(c, "shamir_poseidon2_bn254_t4");
    bench_shamir_permutation::<16>(c, "shamir_poseidon2_bn254_t16");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = poseidon2_mpc_bench
}
criterion_main!(benches);
