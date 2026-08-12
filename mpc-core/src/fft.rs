//! # FFT
//!
//! Radix-2 FFTs over a multiplicative subgroup, with the twiddle factors precomputed once per
//! domain and the bit-reversal permutation left to the caller.
//!
//! [`ark_poly::GeneralEvaluationDomain`] only exposes transforms that take their input *and*
//! produce their output in natural order, so every call pays a bit-reversal permutation
//! (`derange`) over the whole array, and it recomputes the roots of unity on each call. A
//! Groth16 `h`-polynomial computation performs seven transforms in a row, which means seven
//! permutations and seven root tables.
//!
//! This module instead offers the two half-transforms separately, as gnark-crypto does:
//!
//! * [`Domain::fft_in_to_out`] / [`Domain::ifft_in_to_out`] (decimation in frequency, "DIF"):
//!   natural-order input, bit-reversed output.
//! * [`Domain::fft_out_to_in`] / [`Domain::ifft_out_to_in`] (decimation in time, "DIT"):
//!   bit-reversed input, natural-order output.
//!
//! Chaining a DIF transform into a DIT transform cancels the permutations, so a chain of
//! transforms only needs a bit reversal if its *final* output order differs from its input
//! order. See [`bit_reverse`] and [`bit_reverse_index`] for the cases that do.
//!
//! Everything is generic over [`DomainCoeff`], so secret-shared coefficients (e.g.
//! [`crate::protocols::rep3::Rep3PrimeFieldShare`]) work unchanged.

use ark_ff::FftField;
use ark_poly::domain::DomainCoeff;
use rayon::prelude::*;

/// Below this many butterflies a stage is not worth parallelizing.
const MIN_BUTTERFLIES_FOR_PARALLELIZATION: usize = 1 << 11;

/// Granularity of a parallel butterfly stage.
const BUTTERFLY_CHUNK: usize = 1 << 10;

/// Reverses the lowest `log_len` bits of `index`.
///
/// This is the permutation that relates the output order of a DIF transform to the input order
/// of a DIT transform: element `i` of a bit-reversed array is element `bit_reverse_index(i, ..)`
/// of the same array in natural order.
#[inline]
pub const fn bit_reverse_index(index: usize, log_len: u32) -> usize {
    (index as u64).reverse_bits().wrapping_shr(64 - log_len) as usize
}

/// Permutes `values` between natural and bit-reversed order. The permutation is an involution,
/// so the same call undoes it.
///
/// # Panics
///
/// Panics if `values.len()` is not a power of two.
pub fn bit_reverse<T>(values: &mut [T]) {
    assert!(
        values.len().is_power_of_two(),
        "bit reversal requires a power-of-two length"
    );
    if values.len() <= 2 {
        return;
    }
    let log_len = values.len().trailing_zeros();
    for index in 1..values.len() - 1 {
        let reversed = bit_reverse_index(index, log_len);
        if index < reversed {
            values.swap(index, reversed);
        }
    }
}

/// A power-of-two evaluation domain with precomputed twiddle factors.
#[derive(Clone, Debug)]
pub struct Domain<F: FftField> {
    size: usize,
    log_size: u32,
    group_gen: F,
    group_gen_inv: F,
    size_inv: F,
    /// `twiddles[stage][j] == group_gen^(j * 2^stage)`, with `size >> (stage + 1)` entries.
    twiddles: Vec<Vec<F>>,
    /// The same table for `group_gen_inv`.
    twiddles_inv: Vec<Vec<F>>,
}

impl<F: FftField> Domain<F> {
    /// Constructs the domain of size `num_coeffs.next_power_of_two()`, using the same generator
    /// as [`ark_poly::Radix2EvaluationDomain`].
    ///
    /// Returns `None` if the domain is larger than the two-adicity of `F` allows.
    pub fn new(num_coeffs: usize) -> Option<Self> {
        let size = num_coeffs.next_power_of_two();
        if size.trailing_zeros() > F::TWO_ADICITY {
            return None;
        }
        let group_gen = F::get_root_of_unity(size as u64)?;
        Self::with_group_gen(size, group_gen)
    }

    /// Constructs the domain of size `num_coeffs.next_power_of_two()` with an explicitly provided
    /// generator, for callers that need a specific root of unity (e.g. the snarkjs-compatible one
    /// used by the circom witness map).
    ///
    /// Returns `None` if the domain is larger than the two-adicity of `F` allows, or if the
    /// generator is not invertible.
    pub fn with_group_gen(num_coeffs: usize, group_gen: F) -> Option<Self> {
        let size = num_coeffs.next_power_of_two();
        let log_size = size.trailing_zeros();
        if log_size > F::TWO_ADICITY {
            return None;
        }
        debug_assert_eq!(group_gen.pow([size as u64]), F::one());
        let group_gen_inv = group_gen.inverse()?;
        let size_inv = F::from(size as u64).inverse()?;

        let (twiddles, twiddles_inv) = rayon::join(
            || build_twiddles(size, log_size, group_gen),
            || build_twiddles(size, log_size, group_gen_inv),
        );

        Some(Self {
            size,
            log_size,
            group_gen,
            group_gen_inv,
            size_inv,
            twiddles,
            twiddles_inv,
        })
    }

    /// The size of the domain, always a power of two.
    pub fn size(&self) -> usize {
        self.size
    }

    /// The base-two logarithm of [`Domain::size`].
    pub fn log_size(&self) -> u32 {
        self.log_size
    }

    /// The generator of the domain.
    pub fn group_gen(&self) -> F {
        self.group_gen
    }

    /// The inverse of [`Domain::group_gen`].
    pub fn group_gen_inv(&self) -> F {
        self.group_gen_inv
    }

    /// The inverse of the domain size, i.e. the scaling factor of an inverse transform.
    pub fn size_inv(&self) -> F {
        self.size_inv
    }

    /// Evaluates the polynomial given by natural-order coefficients, leaving the evaluations in
    /// bit-reversed order.
    pub fn fft_in_to_out<T: DomainCoeff<F>>(&self, values: &mut [T]) {
        self.assert_size(values.len());
        dif(values, &self.twiddles, 0, max_splits());
    }

    /// Evaluates the polynomial given by bit-reversed coefficients, leaving the evaluations in
    /// natural order.
    pub fn fft_out_to_in<T: DomainCoeff<F>>(&self, values: &mut [T]) {
        self.assert_size(values.len());
        dit(values, &self.twiddles, 0, max_splits());
    }

    /// Interpolates natural-order evaluations, leaving the coefficients in bit-reversed order.
    pub fn ifft_in_to_out<T: DomainCoeff<F>>(&self, values: &mut [T]) {
        self.assert_size(values.len());
        dif(values, &self.twiddles_inv, 0, max_splits());
        self.scale_by_size_inv(values);
    }

    /// Interpolates bit-reversed evaluations, leaving the coefficients in natural order.
    pub fn ifft_out_to_in<T: DomainCoeff<F>>(&self, values: &mut [T]) {
        self.assert_size(values.len());
        dit(values, &self.twiddles_inv, 0, max_splits());
        self.scale_by_size_inv(values);
    }

    fn scale_by_size_inv<T: DomainCoeff<F>>(&self, values: &mut [T]) {
        let size_inv = self.size_inv;
        values
            .par_iter_mut()
            .with_min_len(BUTTERFLY_CHUNK)
            .for_each(|value| *value *= size_inv);
    }

    fn assert_size(&self, len: usize) {
        assert_eq!(
            len, self.size,
            "input length does not match the domain size"
        );
    }
}

/// `twiddles[stage][j] = gen^(j * 2^stage)`, `size >> (stage + 1)` entries per stage.
///
/// Stage 0 is computed in parallel chunks, the remaining stages are strided views of it, as in
/// gnark-crypto's `buildTwiddles`.
fn build_twiddles<F: FftField>(size: usize, log_size: u32, generator: F) -> Vec<Vec<F>> {
    if log_size == 0 {
        return Vec::new();
    }
    let half = size / 2;
    let mut stage0 = vec![F::one(); half];
    let chunk = half.div_ceil(rayon::current_num_threads()).max(1);
    stage0
        .par_chunks_mut(chunk)
        .enumerate()
        .for_each(|(chunk_index, values)| {
            let mut current = generator.pow([(chunk_index * chunk) as u64]);
            for value in values.iter_mut() {
                *value = current;
                current *= generator;
            }
        });

    let mut twiddles = Vec::with_capacity(log_size as usize);
    for stage in 1..log_size as usize {
        let len = size >> (stage + 1);
        let stride = 1usize << stage;
        twiddles.push((0..len).map(|j| stage0[j * stride]).collect());
    }
    twiddles.insert(0, stage0);
    twiddles
}

/// The recursion depth up to which we spawn tasks; `2^max_splits` is the number of leaf tasks.
fn max_splits() -> usize {
    rayon::current_num_threads()
        .next_power_of_two()
        .trailing_zeros() as usize
}

#[inline(always)]
fn butterfly_dif<F: FftField, T: DomainCoeff<F>>(lo: &mut T, hi: &mut T, twiddle: F) {
    let mut neg = *lo;
    neg -= *hi;
    *lo += *hi;
    neg *= twiddle;
    *hi = neg;
}

#[inline(always)]
fn butterfly_dit<F: FftField, T: DomainCoeff<F>>(lo: &mut T, hi: &mut T, twiddle: F) {
    *hi *= twiddle;
    let mut neg = *lo;
    neg -= *hi;
    *lo += *hi;
    *hi = neg;
}

/// Applies one butterfly stage, in parallel if the stage is large enough to pay for it.
#[inline]
fn butterfly_stage<F, T, G>(values: &mut [T], twiddles: &[F], parallel: bool, butterfly: G)
where
    F: FftField,
    T: DomainCoeff<F>,
    G: Fn(&mut T, &mut T, F) + Copy + Send + Sync,
{
    let half = values.len() / 2;
    let (lo, hi) = values.split_at_mut(half);
    if parallel && half >= MIN_BUTTERFLIES_FOR_PARALLELIZATION {
        lo.par_iter_mut()
            .zip(hi.par_iter_mut())
            .zip(twiddles.par_iter())
            .with_min_len(BUTTERFLY_CHUNK)
            .for_each(|((lo, hi), twiddle)| butterfly(lo, hi, *twiddle));
    } else {
        lo.iter_mut()
            .zip(hi.iter_mut())
            .zip(twiddles.iter())
            .for_each(|((lo, hi), twiddle)| butterfly(lo, hi, *twiddle));
    }
}

/// Decimation in frequency: butterflies first, then recurse. Natural in, bit-reversed out.
fn dif<F: FftField, T: DomainCoeff<F>>(
    values: &mut [T],
    twiddles: &[Vec<F>],
    stage: usize,
    max_splits: usize,
) {
    if values.len() == 1 {
        return;
    }
    butterfly_stage(
        values,
        &twiddles[stage],
        stage < max_splits,
        butterfly_dif::<F, T>,
    );
    if values.len() == 2 {
        return;
    }
    let half = values.len() / 2;
    let (lo, hi) = values.split_at_mut(half);
    if stage < max_splits {
        rayon::join(
            || dif(lo, twiddles, stage + 1, max_splits),
            || dif(hi, twiddles, stage + 1, max_splits),
        );
    } else {
        dif(lo, twiddles, stage + 1, max_splits);
        dif(hi, twiddles, stage + 1, max_splits);
    }
}

/// Decimation in time: recurse first, then butterflies. Bit-reversed in, natural out.
fn dit<F: FftField, T: DomainCoeff<F>>(
    values: &mut [T],
    twiddles: &[Vec<F>],
    stage: usize,
    max_splits: usize,
) {
    if values.len() == 1 {
        return;
    }
    if values.len() > 2 {
        let half = values.len() / 2;
        let (lo, hi) = values.split_at_mut(half);
        if stage < max_splits {
            rayon::join(
                || dit(lo, twiddles, stage + 1, max_splits),
                || dit(hi, twiddles, stage + 1, max_splits),
            );
        } else {
            dit(lo, twiddles, stage + 1, max_splits);
            dit(hi, twiddles, stage + 1, max_splits);
        }
    }
    butterfly_stage(
        values,
        &twiddles[stage],
        stage < max_splits,
        butterfly_dit::<F, T>,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::rep3::Rep3PrimeFieldShare;
    use ark_bn254::Fr;
    use ark_ff::{Field, One, UniformRand};
    use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, Radix2EvaluationDomain};
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    fn rng() -> ChaCha12Rng {
        ChaCha12Rng::from_seed([42; 32])
    }

    fn random_values(size: usize, rng: &mut ChaCha12Rng) -> Vec<Fr> {
        (0..size).map(|_| Fr::rand(rng)).collect()
    }

    fn random_shares(size: usize, rng: &mut ChaCha12Rng) -> Vec<Rep3PrimeFieldShare<Fr>> {
        (0..size)
            .map(|_| Rep3PrimeFieldShare::new(Fr::rand(rng), Fr::rand(rng)))
            .collect()
    }

    #[test]
    fn fft_matches_ark_poly() {
        let mut rng = rng();
        for log_size in 0..=10 {
            let size = 1usize << log_size;
            let domain = Domain::<Fr>::new(size).unwrap();
            let ark = GeneralEvaluationDomain::<Fr>::new(size).unwrap();
            assert_eq!(domain.size(), ark.size());

            let input = random_values(size, &mut rng);

            let mut expected = input.clone();
            ark.fft_in_place(&mut expected);

            // DIF produces bit-reversed output
            let mut actual = input.clone();
            domain.fft_in_to_out(&mut actual);
            bit_reverse(&mut actual);
            assert_eq!(actual, expected, "fft_in_to_out, size {size}");

            // DIT consumes bit-reversed input
            let mut actual = input.clone();
            bit_reverse(&mut actual);
            domain.fft_out_to_in(&mut actual);
            assert_eq!(actual, expected, "fft_out_to_in, size {size}");
        }
    }

    #[test]
    fn ifft_matches_ark_poly() {
        let mut rng = rng();
        for log_size in 0..=10 {
            let size = 1usize << log_size;
            let domain = Domain::<Fr>::new(size).unwrap();
            let ark = GeneralEvaluationDomain::<Fr>::new(size).unwrap();

            let input = random_values(size, &mut rng);

            let mut expected = input.clone();
            ark.ifft_in_place(&mut expected);

            let mut actual = input.clone();
            domain.ifft_in_to_out(&mut actual);
            bit_reverse(&mut actual);
            assert_eq!(actual, expected, "ifft_in_to_out, size {size}");

            let mut actual = input.clone();
            bit_reverse(&mut actual);
            domain.ifft_out_to_in(&mut actual);
            assert_eq!(actual, expected, "ifft_out_to_in, size {size}");
        }
    }

    #[test]
    fn dif_dit_round_trip_needs_no_permutation() {
        let mut rng = rng();
        for log_size in 0..=12 {
            let size = 1usize << log_size;
            let domain = Domain::<Fr>::new(size).unwrap();
            let input = random_values(size, &mut rng);

            let mut values = input.clone();
            domain.ifft_in_to_out(&mut values);
            domain.fft_out_to_in(&mut values);
            assert_eq!(values, input, "size {size}");

            let mut values = input.clone();
            domain.fft_in_to_out(&mut values);
            domain.ifft_out_to_in(&mut values);
            assert_eq!(values, input, "size {size}");
        }
    }

    #[test]
    fn coset_evaluation_matches_ark_poly() {
        // The pattern used by the Groth16 witness maps: interpolate, shift onto a coset,
        // evaluate. With DIF/DIT no bit reversal is needed, but the coset table has to be
        // indexed in bit-reversed order.
        let mut rng = rng();
        for log_size in 1..=10 {
            let size = 1usize << log_size;
            let domain = Domain::<Fr>::new(size).unwrap();
            let ark = GeneralEvaluationDomain::<Fr>::new(size).unwrap();
            let coset = ark.get_coset(Fr::GENERATOR).unwrap();

            let input = random_values(size, &mut rng);

            let mut expected = input.clone();
            ark.ifft_in_place(&mut expected);
            coset.fft_in_place(&mut expected);

            let mut powers = Vec::with_capacity(size);
            let mut current = Fr::one();
            for _ in 0..size {
                powers.push(current);
                current *= Fr::GENERATOR;
            }

            let mut actual = input.clone();
            domain.ifft_in_to_out(&mut actual);
            let log_size = domain.log_size();
            actual.iter_mut().enumerate().for_each(|(index, value)| {
                *value *= powers[bit_reverse_index(index, log_size)];
            });
            domain.fft_out_to_in(&mut actual);
            assert_eq!(actual, expected, "size {size}");
        }
    }

    #[test]
    fn works_for_shared_coefficients() {
        let mut rng = rng();
        let size = 1usize << 8;
        let domain = Domain::<Fr>::new(size).unwrap();
        let ark = GeneralEvaluationDomain::<Fr>::new(size).unwrap();
        let input = random_shares(size, &mut rng);

        let mut expected = input.clone();
        ark.ifft_in_place(&mut expected);

        let mut actual = input.clone();
        domain.ifft_in_to_out(&mut actual);
        bit_reverse(&mut actual);
        assert_eq!(actual, expected);
    }

    #[test]
    fn custom_group_gen_matches_overridden_ark_domain() {
        // Mirrors what the circom witness map does: keep the domain size but replace the
        // generator with the snarkjs-compatible root of unity.
        let mut rng = rng();
        let size = 1usize << 6;
        let ark = Radix2EvaluationDomain::<Fr>::new(size).unwrap();
        let ark_squared = Radix2EvaluationDomain::<Fr>::new(size / 2).unwrap();
        assert_eq!(ark.group_gen.square(), ark_squared.group_gen);

        let domain = Domain::<Fr>::with_group_gen(size / 2, ark_squared.group_gen).unwrap();
        let input = random_values(size / 2, &mut rng);

        let mut expected = input.clone();
        ark_squared.fft_in_place(&mut expected);

        let mut actual = input.clone();
        domain.fft_in_to_out(&mut actual);
        bit_reverse(&mut actual);
        assert_eq!(actual, expected);
    }

    #[test]
    fn non_power_of_two_sizes_round_up() {
        let domain = Domain::<Fr>::new(1000).unwrap();
        assert_eq!(domain.size(), 1024);
        let ark = GeneralEvaluationDomain::<Fr>::new(1000).unwrap();
        assert_eq!(domain.size(), ark.size());
        assert_eq!(domain.group_gen(), ark.group_gen());
    }
}
