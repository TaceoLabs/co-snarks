use std::{array, sync::mpsc};

use ark_bn254::Fr;
use ark_ff::UniformRand;
use mpc_net::{local::LocalNetwork, Network};
use paste::paste;
use rand::{rngs::StdRng, CryptoRng, Rng, SeedableRng};

use mpc_core::{
    gadgets::poseidon2::{
        CircomTraceBatchedHasher, CircomTracePlainHasher, CircomTraceShamirHasher, Poseidon2,
        Poseidon2Params, POSEIDON2_BN254_T16_PARAMS, POSEIDON2_BN254_T2_PARAMS,
        POSEIDON2_BN254_T3_PARAMS, POSEIDON2_BN254_T4_PARAMS,
    },
    protocols::{
        rep3::{conversion::A2BType, Rep3PrimeFieldShare, Rep3State},
        shamir::{self, ShamirPreprocessing, ShamirPrimeFieldShare, ShamirState},
    },
};

const NUM_PARTIES: usize = 3;
const THRESHOLD: usize = 1;
const COEFFS: [usize; NUM_PARTIES] = [1, 2, 3];
const KAT_BATCH_SIZE: usize = 5;

// ── KAT helpers ───────────────────────────────────────────────────────────────

static KAT_JSON: &str =
    include_str!("../../../../test_vectors/Groth16/bn254/poseidon/poseidon_trace.json");

fn parse_kat(t: usize) -> Vec<Fr> {
    use std::str::FromStr;
    let root: serde_json::Value =
        serde_json::from_str(KAT_JSON).expect("poseidon_trace.json is valid JSON");
    root[t.to_string()]
        .as_array()
        .expect("T key exists")
        .iter()
        .map(|v| Fr::from_str(v.as_str().expect("string value")).expect("valid field element"))
        .collect()
}

fn check_kat(trace: &[Fr], kat: &[Fr], label: &str) {
    use ark_ff::Zero;
    for (i, (&trace_val, &expected)) in trace.iter().zip(kat.iter()).enumerate() {
        if !expected.is_zero() {
            assert_eq!(trace_val, expected, "{label}: mismatch at trace index {i}");
        }
    }
}

// ── KAT inputs ────────────────────────────────────────────────────────────────

fn kat_input_t2() -> [Fr; 2] {
    [Fr::from(0x1515u64), Fr::from(0x8392ef9du64)]
}

fn kat_input_t3() -> [Fr; 3] {
    [
        Fr::from(0x1515u64),
        Fr::from(0x8392ef9du64),
        Fr::from(0x1515u64),
    ]
}

fn kat_input_t4() -> [Fr; 4] {
    [
        Fr::from(0x1515u64),
        Fr::from(0x8392ef9du64),
        Fr::from(0x1515u64),
        Fr::from(0x8392ef9du64),
    ]
}

fn kat_input_t16() -> [Fr; 16] {
    array::from_fn(|i| {
        if i % 2 == 0 {
            Fr::from(0x1515u64)
        } else {
            Fr::from(0x8392ef9du64)
        }
    })
}

// ── Shamir helpers ────────────────────────────────────────────────────────────

fn share_state<const T: usize>(
    input: &[Fr; T],
    rng: &mut (impl Rng + CryptoRng),
) -> Vec<[ShamirPrimeFieldShare<Fr>; T]> {
    let per_party = shamir::share_field_elements(input, THRESHOLD, NUM_PARTIES, rng);
    per_party
        .into_iter()
        .map(|v| v.try_into().expect("share count must equal T"))
        .collect()
}

fn reconstruct_vec(party_shares: &[Vec<ShamirPrimeFieldShare<Fr>>]) -> Vec<Fr> {
    let n = party_shares[0].len();
    (0..n)
        .map(|i| {
            let per_party: Vec<_> = party_shares.iter().map(|p| p[i]).collect();
            shamir::combine_field_element(&per_party, &COEFFS, THRESHOLD).unwrap()
        })
        .collect()
}

fn reconstruct_state<const T: usize>(party_states: &[[ShamirPrimeFieldShare<Fr>; T]]) -> [Fr; T] {
    array::from_fn(|i| {
        let per_party: Vec<_> = party_states.iter().map(|s| s[i]).collect();
        shamir::combine_field_element(&per_party, &COEFFS, THRESHOLD).unwrap()
    })
}

fn run_single<const T: usize>(
    params: &'static Poseidon2Params<Fr, T, 5>,
    party_shares: Vec<[ShamirPrimeFieldShare<Fr>; T]>,
) -> ([Fr; T], Vec<Fr>) {
    let (tx, rx) = mpsc::channel();
    let nets = LocalNetwork::new(NUM_PARTIES);

    for (net, shares) in nets.into_iter().zip(party_shares) {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let party_id = net.id();
            let poseidon2 = Poseidon2::new(params);
            let num_triples = poseidon2.rand_required(1, true);
            let mut shamir_state: ShamirState<Fr> =
                ShamirPreprocessing::new(NUM_PARTIES, THRESHOLD, num_triples, &net)
                    .unwrap()
                    .into();
            let mut precomp = poseidon2
                .precompute_shamir(1, &net, &mut shamir_state)
                .unwrap();
            let mut state = shares;
            let trace = poseidon2
                .shamir_permutation_in_place_with_precomputation_intermediate(
                    &mut state,
                    &mut precomp,
                    &net,
                    &mut shamir_state,
                )
                .unwrap();
            tx.send((party_id, state, trace)).unwrap();
        });
    }
    drop(tx);

    #[allow(clippy::type_complexity)]
    let mut results: Vec<(
        usize,
        [ShamirPrimeFieldShare<Fr>; T],
        Vec<ShamirPrimeFieldShare<Fr>>,
    )> = rx.into_iter().collect();
    results.sort_by_key(|(id, _, _)| *id);

    let out_state = reconstruct_state(&results.iter().map(|(_, s, _)| *s).collect::<Vec<_>>());
    let out_trace = reconstruct_vec(
        &results
            .iter()
            .map(|(_, _, t)| t.clone())
            .collect::<Vec<_>>(),
    );
    (out_state, out_trace)
}

fn run_packed<const T: usize, const T2: usize, const BATCH_SIZE: usize>(
    params: &'static Poseidon2Params<Fr, T, 5>,
    party_shares: Vec<[ShamirPrimeFieldShare<Fr>; T2]>,
) -> (Vec<[Fr; T]>, Vec<Vec<Fr>>) {
    let (tx, rx) = mpsc::channel();
    let nets = LocalNetwork::new(NUM_PARTIES);

    for (net, shares) in nets.into_iter().zip(party_shares) {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let party_id = net.id();
            let poseidon2 = Poseidon2::new(params);
            let num_triples = poseidon2.rand_required(BATCH_SIZE, true);
            let mut shamir_state: ShamirState<Fr> =
                ShamirPreprocessing::new(NUM_PARTIES, THRESHOLD, num_triples, &net)
                    .unwrap()
                    .into();
            let mut precomp = poseidon2
                .precompute_shamir(BATCH_SIZE, &net, &mut shamir_state)
                .unwrap();
            let (out_state, out_traces) = poseidon2
                .shamir_permutation_in_place_with_precomputation_intermediate_packed::<
                    _,
                    T2,
                    BATCH_SIZE,
                >(shares, &mut precomp, &net, &mut shamir_state)
                .unwrap();
            tx.send((party_id, out_state, out_traces)).unwrap();
        });
    }
    drop(tx);

    #[allow(clippy::type_complexity)]
    let mut results: Vec<(
        usize,
        [ShamirPrimeFieldShare<Fr>; T2],
        [Vec<ShamirPrimeFieldShare<Fr>>; BATCH_SIZE],
    )> = rx.into_iter().collect();
    results.sort_by_key(|(id, _, _)| *id);

    let flat_states: Vec<[ShamirPrimeFieldShare<Fr>; T2]> =
        results.iter().map(|(_, s, _)| *s).collect();

    let out_states: Vec<[Fr; T]> = (0..BATCH_SIZE)
        .map(|b| {
            array::from_fn(|i| {
                let per_party: Vec<_> = flat_states.iter().map(|s| s[b * T + i]).collect();
                shamir::combine_field_element(&per_party, &COEFFS, THRESHOLD).unwrap()
            })
        })
        .collect();

    let out_traces: Vec<Vec<Fr>> = (0..BATCH_SIZE)
        .map(|b| {
            let per_party_traces: Vec<_> = results.iter().map(|(_, _, ts)| ts[b].clone()).collect();
            reconstruct_vec(&per_party_traces)
        })
        .collect();

    (out_states, out_traces)
}

fn run_vec<const T: usize>(
    params: &'static Poseidon2Params<Fr, T, 5>,
    party_shares: Vec<Vec<ShamirPrimeFieldShare<Fr>>>, // outer: party, inner: flat T*batch elements
) -> (Vec<Vec<Fr>>, Vec<Vec<Fr>>) {
    let batch = party_shares[0].len() / T;
    let (tx, rx) = mpsc::channel();
    let nets = LocalNetwork::new(NUM_PARTIES);
    for (net, flat_shares) in nets.into_iter().zip(party_shares) {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let party_id = net.id();
            let poseidon2 = Poseidon2::new(params);
            let num_triples = poseidon2.rand_required(batch, true);
            let mut shamir_state: ShamirState<Fr> =
                ShamirPreprocessing::new(NUM_PARTIES, THRESHOLD, num_triples, &net)
                    .unwrap()
                    .into();
            let mut precomp = poseidon2
                .precompute_shamir(batch, &net, &mut shamir_state)
                .unwrap();
            let (out_state, out_traces) = poseidon2
                .shamir_permutation_in_place_with_precomputation_intermediate_vec(
                    flat_shares,
                    &mut precomp,
                    &net,
                    &mut shamir_state,
                )
                .unwrap();
            tx.send((party_id, out_state, out_traces)).unwrap();
        });
    }
    drop(tx);
    #[expect(clippy::type_complexity)]
    let mut results: Vec<(
        usize,
        Vec<ShamirPrimeFieldShare<Fr>>,
        Vec<Vec<ShamirPrimeFieldShare<Fr>>>,
    )> = rx.into_iter().collect();
    results.sort_by_key(|(id, _, _)| *id);

    let out_states: Vec<Vec<Fr>> = (0..batch)
        .map(|b| {
            (0..T)
                .map(|i| {
                    let per_party: Vec<_> = results.iter().map(|(_, s, _)| s[b * T + i]).collect();
                    shamir::combine_field_element(&per_party, &COEFFS, THRESHOLD).unwrap()
                })
                .collect()
        })
        .collect();

    let out_traces: Vec<Vec<Fr>> = (0..batch)
        .map(|b| {
            let per_party_traces: Vec<_> = results.iter().map(|(_, _, ts)| ts[b].clone()).collect();
            reconstruct_vec(&per_party_traces)
        })
        .collect();

    (out_states, out_traces)
}

// ── Rep3 helpers ──────────────────────────────────────────────────────────────

fn share_state_rep3<const T: usize>(
    input: &[Fr; T],
    rng: &mut impl Rng,
) -> Vec<[Rep3PrimeFieldShare<Fr>; T]> {
    // ID0: (x0,x2), ID1: (x1,x0), ID2: (x2,x1) — satisfies open invariant.
    // Sum of .a fields = x0+x1+x2 = secret.
    let shares_per_elem: Vec<[Rep3PrimeFieldShare<Fr>; 3]> = input
        .iter()
        .map(|&v| {
            let x0 = Fr::rand(rng);
            let x1 = Fr::rand(rng);
            let x2 = v - x0 - x1;
            [
                Rep3PrimeFieldShare::new(x0, x2),
                Rep3PrimeFieldShare::new(x1, x0),
                Rep3PrimeFieldShare::new(x2, x1),
            ]
        })
        .collect();
    (0..3)
        .map(|p| array::from_fn(|i| shares_per_elem[i][p]))
        .collect()
}

fn reconstruct_rep3_vec(party_shares: &[Vec<Rep3PrimeFieldShare<Fr>>]) -> Vec<Fr> {
    let n = party_shares[0].len();
    (0..n)
        .map(|i| party_shares.iter().map(|p| p[i].a).sum())
        .collect()
}

fn reconstruct_rep3_state<const T: usize>(
    party_states: &[[Rep3PrimeFieldShare<Fr>; T]],
) -> [Fr; T] {
    array::from_fn(|i| party_states.iter().map(|s| s[i].a).sum())
}

fn run_single_rep3<const T: usize>(
    params: &'static Poseidon2Params<Fr, T, 5>,
    party_shares: Vec<[Rep3PrimeFieldShare<Fr>; T]>,
) -> ([Fr; T], Vec<Fr>) {
    let (tx, rx) = mpsc::channel();
    let nets = LocalNetwork::new(NUM_PARTIES);

    for (net, shares) in nets.into_iter().zip(party_shares) {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let party_id = net.id();
            let mut rep3_state = Rep3State::new(&net, A2BType::Yao).unwrap();
            let poseidon2 = Poseidon2::new(params);
            let mut precomp = poseidon2.precompute_rep3(1, &net, &mut rep3_state).unwrap();
            let mut state = shares;
            let trace = poseidon2
                .rep3_permutation_in_place_with_precomputation_intermediate(
                    &mut state,
                    &mut precomp,
                    &net,
                )
                .unwrap();
            tx.send((party_id, state, trace)).unwrap();
        });
    }
    drop(tx);

    #[allow(clippy::type_complexity)]
    let mut results: Vec<(
        usize,
        [Rep3PrimeFieldShare<Fr>; T],
        Vec<Rep3PrimeFieldShare<Fr>>,
    )> = rx.into_iter().collect();
    results.sort_by_key(|(id, _, _)| *id);

    let out_state = reconstruct_rep3_state(&results.iter().map(|(_, s, _)| *s).collect::<Vec<_>>());
    let out_trace = reconstruct_rep3_vec(
        &results
            .iter()
            .map(|(_, _, t)| t.clone())
            .collect::<Vec<_>>(),
    );
    (out_state, out_trace)
}

fn run_packed_rep3<const T: usize, const T2: usize, const BATCH_SIZE: usize>(
    params: &'static Poseidon2Params<Fr, T, 5>,
    party_shares: Vec<[Rep3PrimeFieldShare<Fr>; T2]>,
) -> (Vec<[Fr; T]>, Vec<Vec<Fr>>) {
    let (tx, rx) = mpsc::channel();
    let nets = LocalNetwork::new(NUM_PARTIES);

    for (net, shares) in nets.into_iter().zip(party_shares) {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let party_id = net.id();
            let mut rep3_state = Rep3State::new(&net, A2BType::Yao).unwrap();
            let poseidon2 = Poseidon2::new(params);
            let mut precomp = poseidon2
                .precompute_rep3(BATCH_SIZE, &net, &mut rep3_state)
                .unwrap();
            let (out_state, out_traces) = poseidon2
                .rep3_permutation_in_place_with_precomputation_intermediate_packed::<
                    _,
                    T2,
                    BATCH_SIZE,
                >(shares, &mut precomp, &net)
                .unwrap();
            tx.send((party_id, out_state, out_traces)).unwrap();
        });
    }
    drop(tx);

    #[allow(clippy::type_complexity)]
    let mut results: Vec<(
        usize,
        [Rep3PrimeFieldShare<Fr>; T2],
        [Vec<Rep3PrimeFieldShare<Fr>>; BATCH_SIZE],
    )> = rx.into_iter().collect();
    results.sort_by_key(|(id, _, _)| *id);

    let out_states: Vec<[Fr; T]> = (0..BATCH_SIZE)
        .map(|b| array::from_fn(|i| results.iter().map(|(_, s, _)| s[b * T + i].a).sum()))
        .collect();

    let out_traces: Vec<Vec<Fr>> = (0..BATCH_SIZE)
        .map(|b| {
            let per_party_traces: Vec<_> = results.iter().map(|(_, _, ts)| ts[b].clone()).collect();
            reconstruct_rep3_vec(&per_party_traces)
        })
        .collect();

    (out_states, out_traces)
}

fn run_vec_rep3<const T: usize>(
    params: &'static Poseidon2Params<Fr, T, 5>,
    party_shares: Vec<Vec<Rep3PrimeFieldShare<Fr>>>, // outer: party, inner: flat T*batch elements
) -> (Vec<Vec<Fr>>, Vec<Vec<Fr>>) {
    let batch = party_shares[0].len() / T;
    let (tx, rx) = mpsc::channel();
    let nets = LocalNetwork::new(NUM_PARTIES);
    for (net, flat_shares) in nets.into_iter().zip(party_shares) {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let party_id = net.id();
            let mut rep3_state = Rep3State::new(&net, A2BType::Yao).unwrap();
            let poseidon2 = Poseidon2::new(params);
            let mut precomp = poseidon2
                .precompute_rep3(batch, &net, &mut rep3_state)
                .unwrap();
            let (out_state, out_traces) = poseidon2
                .rep3_permutation_in_place_with_precomputation_intermediate_vec(
                    flat_shares,
                    &mut precomp,
                    &net,
                )
                .unwrap();
            tx.send((party_id, out_state, out_traces)).unwrap();
        });
    }
    drop(tx);
    #[expect(clippy::type_complexity)]
    let mut results: Vec<(
        usize,
        Vec<Rep3PrimeFieldShare<Fr>>,
        Vec<Vec<Rep3PrimeFieldShare<Fr>>>,
    )> = rx.into_iter().collect();
    results.sort_by_key(|(id, _, _)| *id);

    let out_states: Vec<Vec<Fr>> = (0..batch)
        .map(|b| {
            (0..T)
                .map(|i| results.iter().map(|(_, s, _)| s[b * T + i].a).sum())
                .collect()
        })
        .collect();

    let out_traces: Vec<Vec<Fr>> = (0..batch)
        .map(|b| {
            let per_party_traces: Vec<_> = results.iter().map(|(_, _, ts)| ts[b].clone()).collect();
            reconstruct_rep3_vec(&per_party_traces)
        })
        .collect();

    (out_states, out_traces)
}

fn run_plain<const T: usize>(
    params: &'static Poseidon2Params<Fr, T, 5>,
    input: [Fr; T],
) -> ([Fr; T], Vec<Fr>) {
    Poseidon2::new(params)
        .plain_permutation_intermediate(input)
        .unwrap()
}

// ── Test generator macro ──────────────────────────────────────────────────────

macro_rules! define_tests {
    (
        t = $T:literal,
        t_batch = $Tbatch:literal,
        params = $params:ident,
        input = $input_fn:ident $(,)?
    ) => {
        paste! {
            // ── Single-instance KAT tests ──────────────────────────────────

            #[test]
            fn [<kat_plain_t $T>]() {
                let kat = parse_kat($T);
                let (_, trace) = run_plain(&$params, $input_fn());
                check_kat(&trace, &kat, concat!("plain T=", stringify!($T)));
            }

            #[test]
            fn [<kat_shamir_t $T>]() {
                let kat = parse_kat($T);
                let mut rng = StdRng::seed_from_u64(42);
                let shares = share_state(&$input_fn(), &mut rng);
                let (_, trace) = run_single(&$params, shares);
                check_kat(&trace, &kat, concat!("shamir T=", stringify!($T)));
            }

            #[test]
            fn [<kat_rep3_t $T>]() {
                let kat = parse_kat($T);
                let mut rng = StdRng::seed_from_u64(42);
                let shares = share_state_rep3(&$input_fn(), &mut rng);
                let (_, trace) = run_single_rep3(&$params, shares);
                check_kat(&trace, &kat, concat!("rep3 T=", stringify!($T)));
            }

            // ── Packed KAT tests (KAT_BATCH_SIZE copies of the KAT input) ─

            #[test]
            fn [<kat_packed_plain_t $T>]() {
                let kat = parse_kat($T);
                let input = $input_fn();
                for slot in 0..KAT_BATCH_SIZE {
                    let (_, trace) = run_plain(&$params, input);
                    check_kat(
                        &trace,
                        &kat,
                        &format!(concat!("packed_plain T=", stringify!($T), " slot={}"), slot),
                    );
                }
            }

            #[test]
            fn [<kat_packed_shamir_t $T>]() {
                let kat = parse_kat($T);
                let mut rng = StdRng::seed_from_u64(42);
                let input = $input_fn();
                let per_slot: Vec<Vec<[ShamirPrimeFieldShare<Fr>; $T]>> =
                    (0..KAT_BATCH_SIZE).map(|_| share_state(&input, &mut rng)).collect();
                let packed: Vec<[ShamirPrimeFieldShare<Fr>; $Tbatch]> = (0..NUM_PARTIES)
                    .map(|p| array::from_fn(|i| per_slot[i / $T][p][i % $T]))
                    .collect();
                let (_, traces) =
                    run_packed::<$T, $Tbatch, KAT_BATCH_SIZE>(&$params, packed);
                for (slot, trace) in traces.iter().enumerate() {
                    check_kat(
                        trace,
                        &kat,
                        &format!(concat!("packed_shamir T=", stringify!($T), " slot={}"), slot),
                    );
                }
            }

            #[test]
            fn [<kat_vec_shamir_t $T>]() {
                let kat = parse_kat($T);
                let mut rng = StdRng::seed_from_u64(42);
                let input = $input_fn();
                // Build 2 identical copies as the batch
                let batch = 2usize;
                let per_slot: Vec<Vec<[ShamirPrimeFieldShare<Fr>; $T]>> =
                    (0..batch).map(|_| share_state(&input, &mut rng)).collect();
                // flat: party → Vec of T*batch shares
                let flat_per_party: Vec<Vec<ShamirPrimeFieldShare<Fr>>> = (0..NUM_PARTIES)
                    .map(|p| {
                        (0..batch)
                            .flat_map(|slot| per_slot[slot][p].iter().copied())
                            .collect()
                    })
                    .collect();
                let (_, traces) = run_vec(&$params, flat_per_party);
                for (slot, trace) in traces.iter().enumerate() {
                    check_kat(
                        trace,
                        &kat,
                        &format!(concat!("vec_shamir T=", stringify!($T), " slot={}"), slot),
                    );
                }
            }

            #[test]
            fn [<kat_vec_rep3_t $T>]() {
                let kat = parse_kat($T);
                let mut rng = StdRng::seed_from_u64(42);
                let input = $input_fn();
                // Build 2 identical copies as the batch
                let batch = 2usize;
                let per_slot: Vec<Vec<[Rep3PrimeFieldShare<Fr>; $T]>> =
                    (0..batch).map(|_| share_state_rep3(&input, &mut rng)).collect();
                // flat: party → Vec of T*batch shares
                let flat_per_party: Vec<Vec<Rep3PrimeFieldShare<Fr>>> = (0..NUM_PARTIES)
                    .map(|p| {
                        (0..batch)
                            .flat_map(|slot| per_slot[slot][p].iter().copied())
                            .collect()
                    })
                    .collect();
                let (_, traces) = run_vec_rep3(&$params, flat_per_party);
                for (slot, trace) in traces.iter().enumerate() {
                    check_kat(
                        trace,
                        &kat,
                        &format!(concat!("vec_rep3 T=", stringify!($T), " slot={}"), slot),
                    );
                }
            }

            #[test]
            fn [<random_vec_rep3_t $T>]() {
                let mut rng = StdRng::from_entropy();
                let batch = 3usize;
                let inputs: Vec<[Fr; $T]> =
                    (0..batch).map(|_| array::from_fn(|_| Fr::rand(&mut rng))).collect();
                let expected_traces: Vec<Vec<Fr>> = inputs
                    .iter()
                    .map(|input| run_plain(&$params, *input).1)
                    .collect();
                let per_slot: Vec<Vec<[Rep3PrimeFieldShare<Fr>; $T]>> = inputs
                    .iter()
                    .map(|input| share_state_rep3(input, &mut rng))
                    .collect();
                let flat_per_party: Vec<Vec<Rep3PrimeFieldShare<Fr>>> = (0..NUM_PARTIES)
                    .map(|p| {
                        (0..batch)
                            .flat_map(|slot| per_slot[slot][p].iter().copied())
                            .collect()
                    })
                    .collect();
                let (_, traces) = run_vec_rep3(&$params, flat_per_party);
                for (slot, (trace, expected)) in traces.iter().zip(expected_traces.iter()).enumerate() {
                    check_kat(
                        trace,
                        expected,
                        &format!(concat!("random_vec_rep3 T=", stringify!($T), " slot={}"), slot),
                    );
                    check_kat(
                        expected,
                        trace,
                        &format!(concat!("random_vec_rep3_inv T=", stringify!($T), " slot={}"), slot),
                    );
                }
            }

            #[test]
            fn [<kat_packed_rep3_t $T>]() {
                let kat = parse_kat($T);
                let mut rng = StdRng::seed_from_u64(42);
                let input = $input_fn();
                let per_slot: Vec<Vec<[Rep3PrimeFieldShare<Fr>; $T]>> =
                    (0..KAT_BATCH_SIZE).map(|_| share_state_rep3(&input, &mut rng)).collect();
                let packed: Vec<[Rep3PrimeFieldShare<Fr>; $Tbatch]> = (0..NUM_PARTIES)
                    .map(|p| array::from_fn(|i| per_slot[i / $T][p][i % $T]))
                    .collect();
                let (_, traces) =
                    run_packed_rep3::<$T, $Tbatch, KAT_BATCH_SIZE>(&$params, packed);
                for (slot, trace) in traces.iter().enumerate() {
                    check_kat(
                        trace,
                        &kat,
                        &format!(concat!("packed_rep3 T=", stringify!($T), " slot={}"), slot),
                    );
                }
            }

            // ── Random-input correctness tests ─────────────────────────────

            #[test]
            fn [<random_plain_t $T>]() {
                let mut rng = StdRng::from_entropy();
                let input: [Fr; $T] = array::from_fn(|_| Fr::rand(&mut rng));
                let poseidon2 = Poseidon2::new(&$params);
                let plain_state = poseidon2.permutation(&input);
                let (state_out, _) = run_plain(&$params, input);
                assert_eq!(
                    state_out,
                    plain_state,
                    concat!("plain T=", stringify!($T), ": output state mismatch"),
                );
            }

            #[test]
            fn [<random_rep3_t $T>]() {
                let mut rng = StdRng::from_entropy();
                let input: [Fr; $T] = array::from_fn(|_| Fr::rand(&mut rng));
                let (_, expected_trace) = run_plain(&$params, input);
                let shares = share_state_rep3(&input, &mut rng);
                let (_, rep3_trace) = run_single_rep3(&$params, shares);
                check_kat(
                    &rep3_trace,
                    &expected_trace,
                    concat!("random_rep3 T=", stringify!($T)),
                );
                check_kat(
                    &expected_trace,
                    &rep3_trace,
                    concat!("random_rep3_inv T=", stringify!($T)),
                );
            }

            #[test]
            fn [<random_shamir_t $T>]() {
                let mut rng = StdRng::from_entropy();
                let input: [Fr; $T] = array::from_fn(|_| Fr::rand(&mut rng));
                let poseidon2 = Poseidon2::new(&$params);
                let expected_state = poseidon2.permutation(&input);
                let (_, expected_trace) = run_plain(&$params, input);
                let shares = share_state(&input, &mut rng);
                let (shamir_state_out, shamir_trace) = run_single(&$params, shares);
                assert_eq!(
                    shamir_state_out,
                    expected_state,
                    concat!("shamir T=", stringify!($T), ": output state mismatch"),
                );
                check_kat(
                    &shamir_trace,
                    &expected_trace,
                    concat!("random_shamir T=", stringify!($T)),
                );
                check_kat(
                    &expected_trace,
                    &shamir_trace,
                    concat!("random_shamir_inv T=", stringify!($T)),
                );
            }
        }
    };
}

define_tests!(
    t = 2,
    t_batch = 10,
    params = POSEIDON2_BN254_T2_PARAMS,
    input = kat_input_t2
);
define_tests!(
    t = 3,
    t_batch = 15,
    params = POSEIDON2_BN254_T3_PARAMS,
    input = kat_input_t3
);
define_tests!(
    t = 4,
    t_batch = 20,
    params = POSEIDON2_BN254_T4_PARAMS,
    input = kat_input_t4
);
define_tests!(
    t = 16,
    t_batch = 80,
    params = POSEIDON2_BN254_T16_PARAMS,
    input = kat_input_t16
);
