//! Variable-base multi-scalar multiplication for co-snarks.
//!
//! The structure is the usual signed-digit bucket method, with one Rayon task per window. Two
//! things differ from [`ark_ec::VariableBaseMSM`]:
//!
//! * **Scheduling.** Arkworks additionally splits each MSM according to the total Rayon pool
//!   size, which performs poorly when co-snarks runs several MSMs concurrently (the Groth16
//!   prover runs five). We only parallelize over windows.
//! * **Bucket accumulation.** For the window sizes that large MSMs use, buckets are kept in
//!   *affine* coordinates and additions are deferred into a batch that is resolved with a single
//!   Montgomery batch inversion, as gnark-crypto does (see section 5.3 of
//!   <https://ia.cr/2022/1396>). That trades the multiplications of an extended-Jacobian mixed
//!   addition for three multiplications, a square and an amortized inversion. Small windows keep
//!   using arkworks' extended-Jacobian buckets, where the batching overhead would not pay off.
//!
//! Digits are stored window-major so that each window task streams its digits contiguously
//! instead of striding through the whole array.

use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, Field, PrimeField};
use rayon::prelude::*;

/// Window sizes at least this large use the batch-affine bucket accumulation. Below it, the
/// buckets are few enough that batches conflict constantly and the extended-Jacobian
/// accumulation wins.
const MIN_WINDOW_FOR_BATCH_AFFINE: usize = 10;

/// Upper bound on the number of additions resolved by a single batch inversion.
const MAX_BATCH_SIZE: usize = 512;

/// Number of conflicting points held back before they are pushed into the fallback buckets.
const QUEUE_CAPACITY: usize = 32;

/// A curve group whose affine points can be built from their coordinates.
///
/// Batch-affine bucket accumulation needs to construct points from the coordinates it computes,
/// and [`AffineRepr`] exposes no such constructor. The single blanket implementation below covers
/// every short-Weierstrass curve, which is every curve used in co-snarks.
pub trait SwCurveGroup: CurveGroup {
    /// Builds the affine point with the given coordinates.
    ///
    /// The point is not checked to be on the curve or in the correct subgroup; callers are
    /// expected to have derived the coordinates from points that were.
    fn affine_from_xy_unchecked(x: Self::BaseField, y: Self::BaseField) -> Self::Affine;
}

impl<P: SWCurveConfig> SwCurveGroup for Projective<P> {
    fn affine_from_xy_unchecked(x: P::BaseField, y: P::BaseField) -> Affine<P> {
        Affine::new_unchecked(x, y)
    }
}

type BaseFieldOf<C> = <C as CurveGroup>::BaseField;
type BigIntOf<C> = <<C as PrimeGroup>::ScalarField as PrimeField>::BigInt;

/// Computes an inner product between the [`PrimeField`] elements in `scalars`
/// and the corresponding group elements in `bases`.
///
/// If the elements have different length, it will chop the slices to the
/// shortest length between `scalars.len()` and `bases.len()`.
///
/// Reference: [`ark_ec::VariableBaseMSM::msm_unchecked`]
pub fn msm_unchecked<C: SwCurveGroup>(bases: &[C::Affine], scalars: &[C::ScalarField]) -> C {
    let bigints = scalars
        .par_iter()
        .map(|scalar| scalar.into_bigint())
        .collect::<Vec<_>>();
    msm_bigint::<C>(bases, &bigints)
}

/// Computes an MSM over scalars that are already in their integer representation.
///
/// If the elements have different length, it will chop the slices to the
/// shortest length between `scalars.len()` and `bases.len()`.
pub fn msm_bigint<C: SwCurveGroup>(bases: &[C::Affine], scalars: &[BigIntOf<C>]) -> C {
    msm_windows::<C>(bases, scalars, |bases, digits, window_size, num_buckets| {
        if window_size >= MIN_WINDOW_FOR_BATCH_AFFINE {
            batch_affine_window_sum::<C>(bases, digits, num_buckets)
        } else {
            extended_jacobian_window_sum::<C>(bases, digits, num_buckets)
        }
    })
}

/// Like [`msm_unchecked`], for curves that cannot name the [`SwCurveGroup`] bound.
///
/// This keeps the window scheduling but always accumulates into extended-Jacobian buckets, so it
/// is slower than [`msm_unchecked`] for large inputs. It exists for callers that are generic over
/// a curve group without the short-Weierstrass bound; prefer [`msm_unchecked`] where the bound can
/// be threaded through.
pub fn msm_unchecked_generic<C: CurveGroup>(bases: &[C::Affine], scalars: &[C::ScalarField]) -> C {
    let bigints = scalars
        .par_iter()
        .map(|scalar| scalar.into_bigint())
        .collect::<Vec<_>>();
    msm_bigint_generic::<C>(bases, &bigints)
}

/// Like [`msm_bigint`], for curves that cannot name the [`SwCurveGroup`] bound. See
/// [`msm_unchecked_generic`].
pub fn msm_bigint_generic<C: CurveGroup>(bases: &[C::Affine], scalars: &[BigIntOf<C>]) -> C {
    msm_windows::<C>(bases, scalars, |bases, digits, _, num_buckets| {
        extended_jacobian_window_sum::<C>(bases, digits, num_buckets)
    })
}

/// Splits the scalars into signed digits and sums one window per Rayon task, combining the window
/// sums from the highest window down.
fn msm_windows<C: CurveGroup>(
    bases: &[C::Affine],
    scalars: &[BigIntOf<C>],
    window_sum: impl Fn(&[C::Affine], &[u32], usize, usize) -> C + Send + Sync,
) -> C {
    let size = bases.len().min(scalars.len());
    if size == 0 {
        return C::ZERO;
    }
    let bases = &bases[..size];
    let scalars = &scalars[..size];

    let window_size = if size < 32 {
        3
    } else {
        ln_without_floats(size) + 2
    };
    let num_bits = C::ScalarField::MODULUS_BIT_SIZE as usize;
    let num_windows = num_bits.div_ceil(window_size);

    let digits = window_major_digits::<C>(scalars, window_size, num_bits, num_windows);

    let window_sums: Vec<C> = (0..num_windows)
        .into_par_iter()
        .map(|window| {
            // Recentering keeps every digit in `[-2^(window_size - 1), 2^(window_size - 1)]`,
            // except in the last window, which absorbs the final carry and can reach
            // `2^window_size`.
            let num_buckets = if window + 1 == num_windows {
                1usize << window_size
            } else {
                1usize << (window_size - 1)
            };
            window_sum(
                bases,
                &digits[window * size..(window + 1) * size],
                window_size,
                num_buckets,
            )
        })
        .collect();

    // We store the sum for the lowest window.
    let lowest = *window_sums.first().expect("at least one window");

    // We're traversing windows from high to low.
    lowest
        + window_sums[1..]
            .iter()
            .rev()
            .fold(C::ZERO, |mut total, sum_i| {
                total += sum_i;
                for _ in 0..window_size {
                    total.double_in_place();
                }
                total
            })
}

/// Encodes the signed digits of every scalar into a window-major array: the digits of window `w`
/// occupy `digits[w * scalars.len()..(w + 1) * scalars.len()]`.
///
/// A digit is `0` if it does not contribute, and `(|digit| << 1) | is_negative` otherwise, so the
/// bucket index of a non-zero digit is `(encoded >> 1) - 1`.
fn window_major_digits<C: CurveGroup>(
    scalars: &[BigIntOf<C>],
    window_size: usize,
    num_bits: usize,
    num_windows: usize,
) -> Vec<u32> {
    let size = scalars.len();
    let mut digits = vec![0u32; size * num_windows];

    // The signed-digit recoding carries from the low windows to the high ones, so the digits of
    // one scalar have to be produced in order. We therefore parallelize over ranges of scalars
    // and hand each task the matching range of every window, which are all disjoint.
    let task_size = size.div_ceil(rayon::current_num_threads()).max(1);
    let num_tasks = size.div_ceil(task_size);
    let mut tasks: Vec<Vec<&mut [u32]>> = (0..num_tasks)
        .map(|_| Vec::with_capacity(num_windows))
        .collect();
    for window in digits.chunks_mut(size) {
        for (task, chunk) in window.chunks_mut(task_size).enumerate() {
            tasks[task].push(chunk);
        }
    }

    tasks
        .into_par_iter()
        .enumerate()
        .for_each(|(task, mut windows)| {
            let offset = task * task_size;
            for (index, scalar) in scalars[offset..].iter().take(task_size).enumerate() {
                for (window, digit) in make_digits(scalar, window_size, num_bits).enumerate() {
                    windows[window][index] = encode_digit(digit);
                }
            }
        });

    digits
}

#[inline]
fn encode_digit(digit: i64) -> u32 {
    if digit == 0 {
        0
    } else if digit > 0 {
        (digit as u32) << 1
    } else {
        (((-digit) as u32) << 1) | 1
    }
}

/// The sum of one window, with buckets in affine coordinates.
fn batch_affine_window_sum<C: SwCurveGroup>(
    bases: &[C::Affine],
    digits: &[u32],
    num_buckets: usize,
) -> C {
    let mut accumulator = BucketAccumulator::<C>::new(num_buckets);
    for (digit, base) in digits.iter().zip(bases) {
        if *digit == 0 {
            continue;
        }
        let Some((x, y)) = base.xy() else {
            continue;
        };
        let bucket = ((*digit >> 1) as usize) - 1;
        let y = if *digit & 1 == 1 { -y } else { y };
        accumulator.add(bucket, x, y);
    }
    accumulator.finish()
}

/// The sum of one window, with buckets in arkworks' extended Jacobian representation.
fn extended_jacobian_window_sum<C: CurveGroup>(
    bases: &[C::Affine],
    digits: &[u32],
    num_buckets: usize,
) -> C {
    let mut buckets = vec![C::ZERO_BUCKET; num_buckets];
    for (digit, base) in digits.iter().zip(bases) {
        if *digit == 0 {
            continue;
        }
        let bucket = ((*digit >> 1) as usize) - 1;
        if *digit & 1 == 1 {
            buckets[bucket] -= *base;
        } else {
            buckets[bucket] += *base;
        }
    }

    let mut running_sum = C::ZERO_BUCKET;
    let mut total = C::ZERO;
    for bucket in buckets.iter().rev() {
        running_sum += bucket;
        total += &running_sum;
    }
    total
}

/// Buckets in affine coordinates, plus the machinery that lets a whole batch of additions share
/// one field inversion.
struct BucketAccumulator<C: SwCurveGroup> {
    /// The affine buckets. The point at infinity marks an empty bucket.
    buckets: Vec<C::Affine>,
    /// Additions that could not be batched: doublings, and points that conflicted with the
    /// pending batch for too long.
    fallback: Vec<C::Bucket>,
    /// Whether a bucket is already referenced by the pending batch. All buckets in a batch have
    /// to be distinct, otherwise the additions would not be independent.
    pending: Vec<bool>,
    batch_buckets: Vec<usize>,
    batch_points: Vec<(BaseFieldOf<C>, BaseFieldOf<C>)>,
    queue: Vec<(usize, BaseFieldOf<C>, BaseFieldOf<C>)>,
    denominators: Vec<BaseFieldOf<C>>,
    inverses: Vec<BaseFieldOf<C>>,
    batch_size: usize,
}

impl<C: SwCurveGroup> BucketAccumulator<C> {
    fn new(num_buckets: usize) -> Self {
        // Keep the batch small relative to the number of buckets so that conflicts stay rare for
        // uniformly distributed digits.
        let batch_size = MAX_BATCH_SIZE.min(num_buckets / 8).max(1);
        Self {
            buckets: vec![C::Affine::zero(); num_buckets],
            fallback: vec![C::ZERO_BUCKET; num_buckets],
            pending: vec![false; num_buckets],
            batch_buckets: Vec::with_capacity(batch_size),
            batch_points: Vec::with_capacity(batch_size),
            queue: Vec::with_capacity(QUEUE_CAPACITY),
            denominators: Vec::with_capacity(batch_size),
            inverses: Vec::with_capacity(batch_size),
            batch_size,
        }
    }

    /// Adds the point `(x, y)` to bucket `bucket`. The sign of the digit is expected to be baked
    /// into `y` already, so this is a plain addition.
    fn add(&mut self, bucket: usize, x: BaseFieldOf<C>, y: BaseFieldOf<C>) {
        if self.pending[bucket] {
            self.queue.push((bucket, x, y));
            if self.queue.len() == QUEUE_CAPACITY {
                self.flush_queue();
            }
            return;
        }
        self.add_to_batch(bucket, x, y);
        if self.batch_buckets.len() == self.batch_size {
            self.execute_batch();
            self.take_from_queue();
        }
    }

    /// Handles the cases the batched affine addition cannot express, and otherwise appends to the
    /// pending batch.
    fn add_to_batch(&mut self, bucket: usize, x: BaseFieldOf<C>, y: BaseFieldOf<C>) {
        let Some((bucket_x, bucket_y)) = self.buckets[bucket].xy() else {
            self.buckets[bucket] = C::affine_from_xy_unchecked(x, y);
            return;
        };
        if bucket_x == x {
            if bucket_y == y {
                // Doubling. Rare enough that the extended Jacobian fallback is fine, and it keeps
                // the special case out of the batched formula.
                self.fallback[bucket] += C::affine_from_xy_unchecked(x, y);
            } else {
                // The point is the negation of the bucket, so the bucket becomes empty.
                self.buckets[bucket] = C::Affine::zero();
            }
            return;
        }
        self.pending[bucket] = true;
        self.batch_buckets.push(bucket);
        self.batch_points.push((x, y));
    }

    /// Resolves the pending batch with a single inversion, then applies the affine addition
    /// `l = (y2 - y1) / (x2 - x1)`, `x3 = l^2 - x1 - x2`, `y3 = l * (x1 - x3) - y1` to each entry.
    fn execute_batch(&mut self) {
        let Self {
            buckets,
            pending,
            batch_buckets,
            batch_points,
            denominators,
            inverses,
            ..
        } = self;
        if batch_buckets.is_empty() {
            return;
        }

        denominators.clear();
        for (bucket, (x, _)) in batch_buckets.iter().zip(batch_points.iter()) {
            let (bucket_x, _) = buckets[*bucket]
                .xy()
                .expect("batched bucket is not infinity");
            denominators.push(*x - bucket_x);
        }
        batch_inverse(denominators, inverses);

        for ((bucket, (point_x, point_y)), inverse) in batch_buckets
            .iter()
            .zip(batch_points.iter())
            .zip(inverses.iter())
        {
            let (bucket_x, bucket_y) = buckets[*bucket]
                .xy()
                .expect("batched bucket is not infinity");

            let mut lambda = *point_y - bucket_y;
            lambda *= *inverse;

            let mut x = lambda.square();
            x -= bucket_x;
            x -= *point_x;

            let mut y = bucket_x - x;
            y *= lambda;
            y -= bucket_y;

            buckets[*bucket] = C::affine_from_xy_unchecked(x, y);
            pending[*bucket] = false;
        }

        batch_buckets.clear();
        batch_points.clear();
    }

    /// Moves points off the top of the queue into the batch, while they do not conflict with it.
    fn take_from_queue(&mut self) {
        while let Some(&(bucket, x, y)) = self.queue.last() {
            if self.pending[bucket] || self.batch_buckets.len() == self.batch_size {
                return;
            }
            self.queue.pop();
            self.add_to_batch(bucket, x, y);
        }
    }

    fn flush_queue(&mut self) {
        let Self {
            queue, fallback, ..
        } = self;
        for (bucket, x, y) in queue.drain(..) {
            fallback[bucket] += C::affine_from_xy_unchecked(x, y);
        }
    }

    /// `total = sum_i (i + 1) * bucket_i`, traversing the buckets from the highest index down.
    fn finish(mut self) -> C {
        self.execute_batch();
        self.flush_queue();

        let mut running_sum = C::ZERO_BUCKET;
        let mut total = C::ZERO;
        for (fallback, affine) in self.fallback.iter().zip(self.buckets.iter()).rev() {
            running_sum += fallback;
            if !affine.is_zero() {
                running_sum += *affine;
            }
            total += &running_sum;
        }
        total
    }
}

/// Inverts every element of `values` with a single field inversion, writing the results to `out`.
///
/// # Panics
///
/// Panics if any element is zero.
fn batch_inverse<F: Field>(values: &[F], out: &mut Vec<F>) {
    out.clear();
    let mut accumulator = F::ONE;
    for value in values {
        out.push(accumulator);
        accumulator *= *value;
    }
    let mut accumulator = accumulator
        .inverse()
        .expect("batched denominators are non-zero");
    for index in (0..values.len()).rev() {
        out[index] *= accumulator;
        accumulator *= values[index];
    }
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
    use ark_bn254::{Fr, G1Affine, G1Projective, G2Projective};
    use ark_ec::VariableBaseMSM;
    use ark_ff::{One, UniformRand, Zero};
    use rand::{Rng, SeedableRng, rngs::StdRng};

    fn random_bases(size: usize, rng: &mut StdRng) -> Vec<G1Affine> {
        let projective = (0..size)
            .map(|_| G1Projective::rand(rng))
            .collect::<Vec<_>>();
        G1Projective::normalize_batch(&projective)
    }

    #[test]
    fn matches_arkworks_msm() {
        let mut rng = StdRng::seed_from_u64(0x5eed);
        // Sizes straddling the window-size thresholds, so both bucket accumulations run.
        for size in [0, 1, 31, 32, 213, 810, 4096, 5000, 20000] {
            let bases = random_bases(size, &mut rng);
            let scalars = (0..size).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

            let expected = G1Projective::msm_unchecked(&bases, &scalars);
            let actual = msm_unchecked::<G1Projective>(&bases, &scalars);
            assert_eq!(actual, expected, "size {size}");
        }
    }

    #[test]
    fn matches_arkworks_msm_in_g2() {
        let mut rng = StdRng::seed_from_u64(0x6002);
        let size = 5000;
        let projective = (0..size)
            .map(|_| G2Projective::rand(&mut rng))
            .collect::<Vec<_>>();
        let bases = G2Projective::normalize_batch(&projective);
        let scalars = (0..size).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

        let expected = G2Projective::msm_unchecked(&bases, &scalars);
        let actual = msm_unchecked::<G2Projective>(&bases, &scalars);
        assert_eq!(actual, expected);
    }

    #[test]
    fn handles_mismatched_lengths() {
        let mut rng = StdRng::seed_from_u64(0x1e00);
        let bases = random_bases(5000, &mut rng);
        let scalars = (0..300).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

        let expected = G1Projective::msm_unchecked(&bases, &scalars);
        let actual = msm_unchecked::<G1Projective>(&bases, &scalars);
        assert_eq!(actual, expected);
    }

    #[test]
    fn handles_infinity_bases_and_zero_scalars() {
        let mut rng = StdRng::seed_from_u64(0x2000);
        let size = 5000;
        let mut bases = random_bases(size, &mut rng);
        let mut scalars = (0..size).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        for index in 0..size {
            if index % 7 == 0 {
                bases[index] = G1Affine::zero();
            }
            if index % 5 == 0 {
                scalars[index] = Fr::zero();
            }
            if index % 11 == 0 {
                scalars[index] = Fr::one();
            }
        }

        let expected = G1Projective::msm_unchecked(&bases, &scalars);
        let actual = msm_unchecked::<G1Projective>(&bases, &scalars);
        assert_eq!(actual, expected);
    }

    #[test]
    fn handles_repeated_points_and_doublings() {
        // Few distinct points and few distinct scalars, so buckets collide constantly: this
        // exercises the conflict queue, the fallback buckets, `P + P` and `P + (-P)`.
        let mut rng = StdRng::seed_from_u64(0x3000);
        let size = 20000;
        let distinct = random_bases(8, &mut rng);
        let bases = (0..size)
            .map(|index| {
                let point = distinct[index % distinct.len()];
                if index % 3 == 0 { -point } else { point }
            })
            .collect::<Vec<_>>();
        let small_scalars = (0..4).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let scalars = (0..size)
            .map(|index| small_scalars[index % small_scalars.len()])
            .collect::<Vec<_>>();

        let expected = G1Projective::msm_unchecked(&bases, &scalars);
        let actual = msm_unchecked::<G1Projective>(&bases, &scalars);
        assert_eq!(actual, expected);
    }

    #[test]
    fn handles_generator_multiples() {
        // Small multiples of the generator combined with small scalars, which produces both
        // equal-x and negated-x collisions inside batches.
        let mut rng = StdRng::seed_from_u64(0x4000);
        let size = 8192;
        let generator = G1Projective::generator();
        let bases = G1Projective::normalize_batch(
            &(0..size)
                .map(|index| generator * Fr::from((index % 16 + 1) as u64))
                .collect::<Vec<_>>(),
        );
        let scalars = (0..size)
            .map(|_| Fr::from(rng.gen_range(0u64..8)))
            .collect::<Vec<_>>();

        let expected = G1Projective::msm_unchecked(&bases, &scalars);
        let actual = msm_unchecked::<G1Projective>(&bases, &scalars);
        assert_eq!(actual, expected);
    }

    #[test]
    fn handles_top_window_carry() {
        // The last window absorbs the final carry, so its digits can reach `2^window_size` while
        // every other window stays within `2^(window_size - 1)`. Whether that overflows an
        // undersized bucket array depends on how many bits of the modulus the last window covers,
        // so this needs both a scalar near the modulus and a 255-bit field: with BN254's 254-bit
        // modulus the top window of a small window size only holds two bits and stays in range.
        let mut rng = StdRng::seed_from_u64(0x6000);
        for size in [1, 3, 31, 32, 5000] {
            let bases = random_bases(size, &mut rng);
            for scalar in [-Fr::one(), Fr::from(2u64).inverse().unwrap(), Fr::one()] {
                let scalars = vec![scalar; size];
                let expected = G1Projective::msm_unchecked(&bases, &scalars);
                let actual = msm_unchecked::<G1Projective>(&bases, &scalars);
                assert_eq!(actual, expected, "bn254, size {size}");
            }
        }

        type BlsFr = ark_bls12_381::Fr;
        type BlsG1 = ark_bls12_381::G1Projective;
        for size in [1, 3, 31, 32, 5000] {
            let projective = (0..size).map(|_| BlsG1::rand(&mut rng)).collect::<Vec<_>>();
            let bases = BlsG1::normalize_batch(&projective);
            for scalar in [-BlsFr::one(), BlsFr::from(2u64).inverse().unwrap()] {
                let scalars = vec![scalar; size];
                let expected = BlsG1::msm_unchecked(&bases, &scalars);
                let actual = msm_unchecked::<BlsG1>(&bases, &scalars);
                assert_eq!(actual, expected, "bls12-381, size {size}");
            }
        }
    }

    #[test]
    fn batch_inverse_matches_individual_inverses() {
        let mut rng = StdRng::seed_from_u64(0x5000);
        let values = (0..37).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let mut inverses = Vec::new();
        batch_inverse(&values, &mut inverses);
        for (value, inverse) in values.iter().zip(&inverses) {
            assert_eq!(*inverse, value.inverse().unwrap());
        }
    }
}
