//! Micro-benchmarks for the primitives that dominate the Groth16 prover, so the
//! end-to-end gap against gnark can be attributed:
//!
//! * the `h`-polynomial FFT pattern (3 iFFT + 3 coset FFT + 1 coset iFFT), which is
//!   identical in `LibSnarkReduction` and in gnark's `computeH`
//! * a single variable-base MSM in G1 / G2 (as scheduled by `mpc_core::msm`)
//! * the 4xG1 + 1xG2 concurrent MSM pattern of `create_proof_with_assignment`
//!
//! Usage: `cargo run --release --example bench_primitives -- [k ...]` (default 20).

use std::hint::black_box;
use std::time::{Duration, Instant};

use ark_bn254::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::CurveGroup;
use ark_ff::{FftField, Field, One, UniformRand};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use rayon::prelude::*;

/// Distinct random points, tiled to `n`. MSM cost does not depend on the point
/// values (bucket assignment is driven by the scalars), so tiling keeps setup cheap.
fn tiled_points<C: CurveGroup>(n: usize, rng: &mut impl rand::Rng) -> Vec<C::Affine> {
    let distinct = 1024.min(n);
    let base = C::generator();
    let seeds: Vec<C::Affine> = (0..distinct)
        .map(|_| (base * C::ScalarField::rand(rng)).into_affine())
        .collect();
    (0..n).map(|i| seeds[i % distinct]).collect()
}

fn stats(mut times: Vec<Duration>) -> (Duration, Duration) {
    times.sort();
    (times[0], times[times.len() / 2])
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn report(name: &str, times: Vec<Duration>) {
    let (min, med) = stats(times);
    println!(
        "{name:<46} min {:>9.1} ms | median {:>9.1} ms",
        ms(min),
        ms(med)
    );
}

fn main() -> eyre::Result<()> {
    let ks: Vec<u32> = {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.is_empty() {
            vec![20]
        } else {
            args.iter().map(|s| s.parse().unwrap()).collect()
        }
    };
    let reps: usize = std::env::var("REPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);

    println!("arkworks / co-snarks primitives (BN254)");
    println!("rayon threads: {}", rayon::current_num_threads());

    let mut rng = rand::thread_rng();

    for k in ks {
        let n = 1usize << k;
        println!("\n=== n = 2^{k} = {n} | reps = {reps} ===");

        // ---- h-polynomial FFT pattern ----
        let domain = GeneralEvaluationDomain::<Fr>::new(n).unwrap();
        assert_eq!(domain.size(), n);
        let coset_domain = domain.get_coset(Fr::GENERATOR).unwrap();
        let vals: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let den = domain
            .evaluate_vanishing_polynomial(Fr::GENERATOR)
            .inverse()
            .unwrap();

        let mut times = Vec::new();
        for _ in 0..reps {
            let mut a = vals.clone();
            let mut b = vals.clone();
            let mut c = vals.clone();
            let start = Instant::now();
            domain.ifft_in_place(&mut a);
            domain.ifft_in_place(&mut b);
            domain.ifft_in_place(&mut c);
            coset_domain.fft_in_place(&mut a);
            coset_domain.fft_in_place(&mut b);
            coset_domain.fft_in_place(&mut c);
            a.par_iter_mut()
                .zip(b.par_iter())
                .zip(c.par_iter())
                .with_min_len(512)
                .for_each(|((a, b), c)| {
                    *a *= *b;
                    *a -= *c;
                    *a *= den;
                });
            coset_domain.ifft_in_place(&mut a);
            times.push(start.elapsed());
            black_box(a);
        }
        report("h pattern: 3 ifft + 3 coset fft + coset ifft", times);

        // ---- same pattern with the mpc-core DIF/DIT domain ----
        let fast = mpc_core::fft::Domain::<Fr>::new(n).unwrap();
        let log_size = fast.log_size();
        let mut coset_powers = Vec::with_capacity(n);
        let mut current = Fr::one();
        for _ in 0..n {
            coset_powers.push(current);
            current *= Fr::GENERATOR;
        }
        let mut coset_powers_inv = Vec::with_capacity(n);
        let mut current = Fr::one();
        let generator_inv = Fr::GENERATOR.inverse().unwrap();
        for _ in 0..n {
            coset_powers_inv.push(current);
            current *= generator_inv;
        }

        let mut times = Vec::new();
        for _ in 0..reps {
            let mut a = vals.clone();
            let mut b = vals.clone();
            let mut c = vals.clone();
            let start = Instant::now();
            // interpolate: natural -> bit-reversed
            fast.ifft_in_to_out(&mut a);
            fast.ifft_in_to_out(&mut b);
            fast.ifft_in_to_out(&mut c);
            // shift onto the coset (table indexed in bit-reversed order) and evaluate:
            // bit-reversed -> natural
            for values in [&mut a, &mut b, &mut c] {
                values
                    .par_iter_mut()
                    .enumerate()
                    .with_min_len(512)
                    .for_each(|(index, value)| {
                        *value *= coset_powers[mpc_core::fft::bit_reverse_index(index, log_size)]
                    });
                fast.fft_out_to_in(values);
            }
            a.par_iter_mut()
                .zip(b.par_iter())
                .zip(c.par_iter())
                .with_min_len(512)
                .for_each(|((a, b), c)| {
                    *a *= *b;
                    *a -= *c;
                    *a *= den;
                });
            // back to coefficients: natural -> bit-reversed, then one permutation so that `h`
            // matches the natural order of `h_query`
            fast.ifft_in_to_out(&mut a);
            a.par_iter_mut()
                .enumerate()
                .with_min_len(512)
                .for_each(|(index, value)| {
                    *value *= coset_powers_inv[mpc_core::fft::bit_reverse_index(index, log_size)]
                });
            mpc_core::fft::bit_reverse(&mut a);
            times.push(start.elapsed());
            black_box(a);
        }
        report("h pattern: mpc-core DIF/DIT domain", times);

        if std::env::var("FFT_ONLY").is_ok() {
            continue;
        }

        // ---- MSMs ----
        let g1: Vec<G1Affine> = tiled_points::<G1Projective>(n, &mut rng);
        let g2: Vec<G2Affine> = tiled_points::<G2Projective>(n, &mut rng);
        let scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

        let mut times = Vec::new();
        for _ in 0..reps {
            let start = Instant::now();
            let acc = mpc_core::msm::msm_unchecked::<G1Projective>(&g1, &scalars);
            times.push(start.elapsed());
            let _ = black_box(acc);
        }
        report("single G1 MSM (mpc_core::msm)", times);

        let mut times = Vec::new();
        for _ in 0..reps {
            let start = Instant::now();
            let acc = mpc_core::msm::msm_unchecked::<G2Projective>(&g2, &scalars);
            times.push(start.elapsed());
            let _ = black_box(acc);
        }
        report("single G2 MSM (mpc_core::msm)", times);

        // The prover's pattern: 4 G1 MSMs + 1 G2 MSM, all concurrent (rayon_join5).
        let mut times = Vec::new();
        for _ in 0..reps {
            let start = Instant::now();
            let (((a, b), c), (d, e)) = rayon::join(
                || {
                    rayon::join(
                        || {
                            rayon::join(
                                || mpc_core::msm::msm_unchecked::<G1Projective>(&g1, &scalars),
                                || mpc_core::msm::msm_unchecked::<G1Projective>(&g1, &scalars),
                            )
                        },
                        || mpc_core::msm::msm_unchecked::<G1Projective>(&g1, &scalars),
                    )
                },
                || {
                    rayon::join(
                        || mpc_core::msm::msm_unchecked::<G1Projective>(&g1, &scalars),
                        || mpc_core::msm::msm_unchecked::<G2Projective>(&g2, &scalars),
                    )
                },
            );
            times.push(start.elapsed());
            let _ = black_box((a, b, c, d, e));
        }
        report("prover pattern: 4x G1 + 1x G2 concurrent", times);
    }

    Ok(())
}
