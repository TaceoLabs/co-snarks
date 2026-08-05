//! Temporary variable-base MSM implementation for co-snarks.
//! This is a temporary performance workaround for the Arkworks 0.6
//! `msm_bigint_wnaf` scheduling strategy. Arkworks splits each MSM according to
//! the total Rayon pool size, which performs poorly when co-snarks runs several
//! MSMs concurrently.

use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger, PrimeField};
use rayon::prelude::*;

/// Computes an inner product between the [`PrimeField`] elements in `scalars`
/// and the corresponding group elements in `bases`.
///
/// If the elements have different length, it will chop the slices to the
/// shortest length between `scalars.len()` and `bases.len()`.
///
/// Reference: [`VariableBaseMSM::msm_unchecked`]
pub fn msm_unchecked<C: CurveGroup>(bases: &[C::Affine], scalars: &[C::ScalarField]) -> C {
    let bigints = scalars
        .par_iter()
        .map(|scalar| scalar.into_bigint())
        .collect::<Vec<_>>();
    msm_bigint::<C>(bases, &bigints)
}

/// Optimized implementation of multi-scalar multiplication.
///
/// WARNING: This is a temporary performance workaround for the Arkworks 0.6
/// `msm_bigint_wnaf` scheduling strategy. Arkworks splits each MSM according to
/// the total Rayon pool size, which performs poorly when co-snarks runs several
/// MSMs concurrently.
///
/// TODO: Replace this implementation with the upstream Arkworks MSM once its
/// parallel scheduling composes efficiently with nested/concurrent callers.
pub fn msm_bigint<V: VariableBaseMSM>(
    bases: &[V::MulBase],
    bigints: &[<V::ScalarField as PrimeField>::BigInt],
) -> V {
    msm_bigint_wnaf::<V>(bases, bigints)
}

// Compute msm using windowed non-adjacent form
fn msm_bigint_wnaf_parallel<V: VariableBaseMSM>(
    bases: &[V::MulBase],
    bigints: &[<V::ScalarField as PrimeField>::BigInt],
) -> V {
    let size = bases.len().min(bigints.len());
    let scalars = &bigints[..size];
    let bases = &bases[..size];

    let c = if size < 32 {
        3
    } else {
        ln_without_floats(size) + 2
    };

    let num_bits = V::ScalarField::MODULUS_BIT_SIZE as usize;
    let digits_count = num_bits.div_ceil(c);
    let scalar_digits = scalars
        .par_iter()
        .flat_map_iter(|s| make_digits(s, c, num_bits))
        .collect::<Vec<_>>();

    let zero = V::ZERO_BUCKET;
    let window_sums: Vec<_> = (0..digits_count)
        .into_par_iter()
        .map(|i| {
            let mut buckets = vec![zero; 1 << c];
            for (digits, base) in scalar_digits.chunks(digits_count).zip(bases) {
                use std::cmp::Ordering;
                let scalar = digits[i];
                match 0.cmp(&scalar) {
                    Ordering::Less => buckets[(scalar - 1) as usize] += base,
                    Ordering::Greater => buckets[(-scalar - 1) as usize] -= base,
                    Ordering::Equal => (),
                }
            }

            // prefix sum
            let mut running_sum = V::ZERO_BUCKET;
            let mut res = V::ZERO_BUCKET;
            buckets.into_iter().rev().for_each(|b| {
                running_sum += &b;
                res += &running_sum;
            });
            res
        })
        .collect();

    // We store the sum for the lowest window.
    let lowest: V = (*window_sums.first().unwrap()).into();

    // We're traversing windows from high to low.
    lowest
        + (&window_sums[1..])
            .iter()
            .rev()
            .fold(V::ZERO, |mut total, sum_i| {
                total += sum_i;
                for _ in 0..c {
                    total.double_in_place();
                }
                total
            })
}

/// Computes an MSM using the windowed non-adjacent form (WNAF) algorithm.
fn msm_bigint_wnaf<V: VariableBaseMSM>(
    bases: &[V::MulBase],
    scalars: &[<V::ScalarField as PrimeField>::BigInt],
) -> V {
    let size = bases.len().min(scalars.len());
    if size == 0 {
        return V::ZERO;
    }

    // WARNING: Unlike Arkworks 0.6, do not split this into per-thread chunks.
    // Doing so regresses co-snarks because several MSMs already run concurrently.
    msm_bigint_wnaf_parallel::<V>(&bases[..size], &scalars[..size])
}

const fn log2(value: usize) -> u32 {
    if value == 0 {
        0
    } else if value.is_power_of_two() {
        1usize.leading_zeros() - value.leading_zeros()
    } else {
        0usize.leading_zeros() - value.leading_zeros()
    }
}

/// The result of this function is only approximately `ln(a)`
/// [`Explanation of usage`]
///
/// [`Explanation of usage`]: https://github.com/scipr-lab/zexe/issues/79#issue-556220473
const fn ln_without_floats(a: usize) -> usize {
    // log2(a) * ln(2)
    (log2(a) * 69 / 100) as usize
}

// From: https://github.com/arkworks-rs/gemini/blob/main/src/kzg/msm/variable_base.rs#L20
fn make_digits(a: &impl BigInteger, w: usize, num_bits: usize) -> impl Iterator<Item = i64> + '_ {
    let scalar = a.as_ref();
    let radix: u64 = 1 << w;
    let window_mask: u64 = radix - 1;

    let mut carry = 0u64;
    let num_bits = if num_bits == 0 {
        a.num_bits() as usize
    } else {
        num_bits
    };
    let digits_count = num_bits.div_ceil(w);

    (0..digits_count).map(move |i| {
        // Construct a buffer of bits of the scalar, starting at `bit_offset`.
        let bit_offset = i * w;
        let u64_idx = bit_offset / 64;
        let bit_idx = bit_offset % 64;
        // Read the bits from the scalar
        let bit_buf = if bit_idx < 64 - w || u64_idx == scalar.len() - 1 {
            // This window's bits are contained in a single u64,
            // or it's the last u64 anyway.
            scalar[u64_idx] >> bit_idx
        } else {
            // Combine the current u64's bits with the bits from the next u64
            (scalar[u64_idx] >> bit_idx) | (scalar[1 + u64_idx] << (64 - bit_idx))
        };

        // Read the actual coefficient value from the window
        let coef = carry + (bit_buf & window_mask); // coef = [0, 2^r)

        // Recenter coefficients from [0,2^w) to [-2^w/2, 2^w/2)
        carry = (coef + radix / 2) >> w;
        let mut digit = (coef as i64) - (carry << w) as i64;

        if i == digits_count - 1 {
            digit += (carry << w) as i64;
        }
        digit
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fr, G1Projective};
    use ark_ff::UniformRand;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn matches_arkworks_msm() {
        let mut rng = StdRng::seed_from_u64(0x5eed);
        for size in [0, 1, 31, 32, 213, 810] {
            let projective = (0..size)
                .map(|_| G1Projective::rand(&mut rng))
                .collect::<Vec<_>>();
            let bases = G1Projective::normalize_batch(&projective);
            let scalars = (0..size).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

            let expected = G1Projective::msm_unchecked(&bases, &scalars);
            let actual = msm_unchecked::<G1Projective>(&bases, &scalars);
            assert_eq!(actual, expected);
        }
    }
}
