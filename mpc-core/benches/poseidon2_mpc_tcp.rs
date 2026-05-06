//! Benchmarks for the MPC variants of the Poseidon2 permutation over real **TCP** loopback
//! sockets (3 parties, in-process).
//!
//! Compared to the LocalNetwork bench in `poseidon2_mpc.rs` this exercises the same MPC code
//! against actual TCP I/O — kernel socket buffers, length-prefix framing, the per-recv reader
//! thread inside [`mpc_net::tcp::TcpNetwork`], and real syscall costs. It measures only the
//! online cost of the permutation: TCP setup and protocol-state initialization happen once per
//! bench function, before timing.
//!
//! Each bench function spawns three persistent worker threads that share TCP connections across
//! every `iter_custom` call. Tasks are dispatched over an mpsc channel; the reported time is the
//! slowest party's wall clock for `iters` permutations.
//!
//! Variants benchmarked: same set as the LocalNetwork bench
//!   * REP3:   `permutation`, `permutation_with_precomputation`, `permutation_additive_with_precomputation`
//!   * Shamir: `permutation`, `permutation_with_precomputation`

use std::array;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ark_bn254::Fr;
use ark_ff::UniformRand;
use criterion::*;
use mpc_core::{
    gadgets::poseidon2::Poseidon2,
    protocols::{
        rep3::{self, Rep3PrimeFieldShare, Rep3State, conversion::A2BType},
        shamir::{self, ShamirPreprocessing, ShamirPrimeFieldShare, ShamirState},
    },
};
use mpc_net::{
    config::Address,
    tcp::{NetworkConfig, NetworkParty, TcpNetwork},
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const NUM_PARTIES: usize = 3;
const SHAMIR_THRESHOLD: usize = 1;
/// Cap on perms per precompute batch to keep memory bounded for large `iters` from criterion.
const PRECOMP_BATCH_CAP: usize = 64;

// Allocate disjoint port ranges per bench function to avoid TIME_WAIT collisions when re-running
// or when running benches in parallel test pipelines. We reserve 3 ports per bench function
// (one per party).
static PORT_BASE: AtomicU16 = AtomicU16::new(41000);

fn alloc_ports() -> u16 {
    PORT_BASE.fetch_add(NUM_PARTIES as u16, Ordering::SeqCst)
}

fn make_tcp_config(my_id: usize, base_port: u16) -> NetworkConfig {
    let parties: Vec<NetworkParty> = (0..NUM_PARTIES)
        .map(|i| NetworkParty {
            id: i,
            dns_name: Address::new("127.0.0.1".to_string(), base_port + i as u16),
        })
        .collect();
    let bind_addr: SocketAddr = format!("0.0.0.0:{}", base_port + my_id as u16)
        .parse()
        .unwrap();
    NetworkConfig {
        parties,
        my_id,
        bind_addr,
        timeout: Some(Duration::from_secs(30)),
        max_frame_length: None,
    }
}

// ---- REP3 -------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Rep3Task {
    Perm,
    PermWithPrecomp,
    PermAdditiveWithPrecomp,
}

/// Persistent pool of three TCP-connected REP3 workers. TCP setup and `Rep3State` init happen
/// once at construction; thereafter each `run` call dispatches `iters` permutations to all three
/// workers and waits for the slowest one.
struct Rep3TcpPool<const T: usize> {
    task_txs: Vec<mpsc::Sender<(Rep3Task, u64)>>,
    done_rx: mpsc::Receiver<Duration>,
    handles: Vec<JoinHandle<()>>,
}

impl<const T: usize> Rep3TcpPool<T>
where
    Poseidon2<Fr, T, 5>: Default,
{
    fn start(input_shares: [Vec<Rep3PrimeFieldShare<Fr>>; 3]) -> Self {
        let base_port = alloc_ports();
        let (done_tx, done_rx) = mpsc::channel::<Duration>();
        let mut task_txs = Vec::with_capacity(NUM_PARTIES);
        let mut handles = Vec::with_capacity(NUM_PARTIES);

        for (id, share) in (0..NUM_PARTIES).zip(input_shares) {
            let (task_tx, task_rx) = mpsc::channel::<(Rep3Task, u64)>();
            task_txs.push(task_tx);
            let done_tx = done_tx.clone();
            let cfg = make_tcp_config(id, base_port);

            let handle = std::thread::spawn(move || {
                let net = TcpNetwork::new(cfg).expect("TCP setup");
                let mut state = Rep3State::new(&net, A2BType::default()).expect("Rep3State");
                let poseidon = Poseidon2::<Fr, T, 5>::default();
                let share_arr: [Rep3PrimeFieldShare<Fr>; T] = share.try_into().expect("len = T");

                while let Ok((task, iters)) = task_rx.recv() {
                    let elapsed = match task {
                        Rep3Task::Perm => {
                            let t0 = Instant::now();
                            for _ in 0..iters {
                                let mut s = share_arr;
                                poseidon
                                    .rep3_permutation_in_place(&mut s, &net, &mut state)
                                    .unwrap();
                                black_box(s);
                            }
                            t0.elapsed()
                        }
                        Rep3Task::PermWithPrecomp => run_in_precomp_batches(iters, |batch| {
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
                        }),
                        Rep3Task::PermAdditiveWithPrecomp => {
                            run_in_precomp_batches(iters, |batch| {
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
                            })
                        }
                    };
                    if done_tx.send(elapsed).is_err() {
                        break;
                    }
                }
            });
            handles.push(handle);
        }

        Self {
            task_txs,
            done_rx,
            handles,
        }
    }

    fn run(&self, task: Rep3Task, iters: u64) -> Duration {
        for tx in &self.task_txs {
            tx.send((task, iters)).unwrap();
        }
        let mut max = Duration::ZERO;
        for _ in 0..NUM_PARTIES {
            let elapsed = self.done_rx.recv().unwrap();
            if elapsed > max {
                max = elapsed;
            }
        }
        max
    }
}

impl<const T: usize> Drop for Rep3TcpPool<T> {
    fn drop(&mut self) {
        // Closing the senders ends the workers' recv loops cleanly.
        self.task_txs.clear();
        for h in self.handles.drain(..) {
            let _ = h.join();
        }
    }
}

fn bench_rep3_tcp<const T: usize>(c: &mut Criterion, label: &str)
where
    Poseidon2<Fr, T, 5>: Default,
{
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let input: [Fr; T] = array::from_fn(|_| Fr::rand(&mut rng));
    let input_shares = rep3::share_field_elements(&input, &mut rng);

    let pool = Rep3TcpPool::<T>::start(input_shares);

    let mut group = c.benchmark_group(label);
    group.throughput(Throughput::Elements(1));

    group.bench_function("rep3_permutation", |b| {
        b.iter_custom(|iters| pool.run(Rep3Task::Perm, iters));
    });
    group.bench_function("rep3_permutation_with_precomputation", |b| {
        b.iter_custom(|iters| pool.run(Rep3Task::PermWithPrecomp, iters));
    });
    group.bench_function("rep3_permutation_additive_with_precomputation", |b| {
        b.iter_custom(|iters| pool.run(Rep3Task::PermAdditiveWithPrecomp, iters));
    });

    group.finish();
    drop(pool);
}

// ---- Shamir -----------------------------------------------------------------

#[derive(Clone, Copy)]
enum ShamirTask {
    Perm,
    PermWithPrecomp,
}

struct ShamirTcpPool<const T: usize> {
    task_txs: Vec<mpsc::Sender<(ShamirTask, u64)>>,
    done_rx: mpsc::Receiver<Duration>,
    handles: Vec<JoinHandle<()>>,
}

impl<const T: usize> ShamirTcpPool<T>
where
    Poseidon2<Fr, T, 5>: Default,
{
    fn start(input_shares: Vec<Vec<ShamirPrimeFieldShare<Fr>>>) -> Self {
        assert_eq!(input_shares.len(), NUM_PARTIES);
        let base_port = alloc_ports();
        let (done_tx, done_rx) = mpsc::channel::<Duration>();
        let mut task_txs = Vec::with_capacity(NUM_PARTIES);
        let mut handles = Vec::with_capacity(NUM_PARTIES);

        for (id, share) in (0..NUM_PARTIES).zip(input_shares) {
            let (task_tx, task_rx) = mpsc::channel::<(ShamirTask, u64)>();
            task_txs.push(task_tx);
            let done_tx = done_tx.clone();
            let cfg = make_tcp_config(id, base_port);

            let handle = std::thread::spawn(move || {
                let net = TcpNetwork::new(cfg).expect("TCP setup");
                let poseidon = Poseidon2::<Fr, T, 5>::default();
                let share_arr: [ShamirPrimeFieldShare<Fr>; T] = share.try_into().expect("len = T");

                while let Ok((task, iters)) = task_rx.recv() {
                    let elapsed = match task {
                        ShamirTask::Perm => run_in_precomp_batches(iters, |batch| {
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
                        }),
                        ShamirTask::PermWithPrecomp => run_in_precomp_batches(iters, |batch| {
                            let rand_required = poseidon.rand_required(batch, true);
                            let mut state: ShamirState<Fr> = ShamirPreprocessing::new(
                                NUM_PARTIES,
                                SHAMIR_THRESHOLD,
                                rand_required,
                                &net,
                            )
                            .unwrap()
                            .into();
                            let mut precomp =
                                poseidon.precompute_shamir(batch, &net, &mut state).unwrap();
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
                        }),
                    };
                    if done_tx.send(elapsed).is_err() {
                        break;
                    }
                }
            });
            handles.push(handle);
        }

        Self {
            task_txs,
            done_rx,
            handles,
        }
    }

    fn run(&self, task: ShamirTask, iters: u64) -> Duration {
        for tx in &self.task_txs {
            tx.send((task, iters)).unwrap();
        }
        let mut max = Duration::ZERO;
        for _ in 0..NUM_PARTIES {
            let elapsed = self.done_rx.recv().unwrap();
            if elapsed > max {
                max = elapsed;
            }
        }
        max
    }
}

impl<const T: usize> Drop for ShamirTcpPool<T> {
    fn drop(&mut self) {
        self.task_txs.clear();
        for h in self.handles.drain(..) {
            let _ = h.join();
        }
    }
}

fn bench_shamir_tcp<const T: usize>(c: &mut Criterion, label: &str)
where
    Poseidon2<Fr, T, 5>: Default,
{
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let input: [Fr; T] = array::from_fn(|_| Fr::rand(&mut rng));
    let input_shares =
        shamir::share_field_elements(&input, SHAMIR_THRESHOLD, NUM_PARTIES, &mut rng);

    let pool = ShamirTcpPool::<T>::start(input_shares);

    let mut group = c.benchmark_group(label);
    group.throughput(Throughput::Elements(1));

    group.bench_function("shamir_permutation", |b| {
        b.iter_custom(|iters| pool.run(ShamirTask::Perm, iters));
    });
    group.bench_function("shamir_permutation_with_precomputation", |b| {
        b.iter_custom(|iters| pool.run(ShamirTask::PermWithPrecomp, iters));
    });

    group.finish();
    drop(pool);
}

// ---- helpers ----------------------------------------------------------------

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

fn poseidon2_mpc_tcp_bench(c: &mut Criterion) {
    bench_rep3_tcp::<2>(c, "tcp_rep3_poseidon2_bn254_t2");
    bench_rep3_tcp::<3>(c, "tcp_rep3_poseidon2_bn254_t3");
    bench_rep3_tcp::<4>(c, "tcp_rep3_poseidon2_bn254_t4");
    bench_rep3_tcp::<16>(c, "tcp_rep3_poseidon2_bn254_t16");

    bench_shamir_tcp::<2>(c, "tcp_shamir_poseidon2_bn254_t2");
    bench_shamir_tcp::<3>(c, "tcp_shamir_poseidon2_bn254_t3");
    bench_shamir_tcp::<4>(c, "tcp_shamir_poseidon2_bn254_t4");
    bench_shamir_tcp::<16>(c, "tcp_shamir_poseidon2_bn254_t16");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = poseidon2_mpc_tcp_bench
}
criterion_main!(benches);
