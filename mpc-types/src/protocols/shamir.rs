//! # Shamir
//!
//! This module implements the shamir share and combine opertions and shamir preprocessing

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use itertools::izip;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use rand::{CryptoRng, Rng};

pub mod arithmetic;
pub mod pointshare;

pub use arithmetic::types::ShamirPrimeFieldShare;
pub use pointshare::types::ShamirPointShare;

type ShamirShare<F> = ShamirPrimeFieldShare<F>;

/// Share a field element into Shamir shares with given `degree` and `num_parties`
pub fn share_field_element<F: PrimeField, R: Rng + CryptoRng>(
    val: F,
    degree: usize,
    num_parties: usize,
    rng: &mut R,
) -> Vec<ShamirShare<F>> {
    let shares = share(val, num_parties, degree, rng);
    ShamirShare::convert_vec_rev(shares)
}

/// Reconstructs a field element from its Shamir shares and lagrange coefficients. Thereby at least `degree` + 1 shares need to be present.
pub fn combine_field_element<F: PrimeField>(
    shares: &[ShamirShare<F>],
    coeffs: &[usize],
    degree: usize,
) -> eyre::Result<F> {
    if shares.len() != coeffs.len() {
        eyre::bail!(
            "Number of shares ({}) does not match number of party indices ({})",
            shares.len(),
            coeffs.len()
        );
    }
    if shares.len() <= degree {
        eyre::bail!(
            "Not enough shares to reconstruct the secret. Expected {}, got {}",
            degree + 1,
            shares.len()
        );
    }

    let lagrange = lagrange_from_coeff(&coeffs[..=degree]);
    let shares = ShamirShare::convert_slice(shares);
    let rec = reconstruct(&shares[..=degree], &lagrange);
    Ok(rec)
}

/// Secret shares a vector of field element using Shamir secret sharing and a unique RNG per thread. The field elements are split into num_parties shares each, where each party holds just one. The outputs are `Vecs` of `Vecs` of type [`ShamirPrimeFieldShare`]. The degree of the sharing polynomial (i.e., the threshold of maximum number of tolerated colluding parties) is specified by the degree parameter.
pub fn share_field_elements<F: PrimeField, R: Rng + CryptoRng>(
    vals: &[F],
    degree: usize,
    num_parties: usize,
    _rng: &mut R,
) -> Vec<Vec<ShamirShare<F>>> {
    let mut result = vec![Vec::with_capacity(vals.len()); num_parties];

    let shares_vec: Vec<Vec<ShamirShare<F>>> = vals.into_par_iter()
        .map_init(
            || rand::thread_rng(),
            |mut rng, val| {
                let shares = share(*val, num_parties, degree, &mut rng);
                ShamirShare::convert_vec_rev(shares)
            },
        )
        .collect();

    for shares in shares_vec {
        for (r, s) in result.iter_mut().zip(shares.into_iter()) {
            r.push(s);
        }
    }

    result
}

/// Reconstructs a vector of field elements from its Shamir shares and lagrange coefficients. The input is a slice of `Vecs` of [ShamirPrimeFieldShare] per party. Thus, shares\[i\]\[j\] represents the j-th share of party i. Thereby at least `degree` + 1 shares need to be present per field element (i.e., i > degree).
pub fn combine_field_elements<F: PrimeField>(
    shares: &[Vec<ShamirShare<F>>],
    coeffs: &[usize],
    degree: usize,
) -> eyre::Result<Vec<F>> {
    if shares.len() != coeffs.len() {
        eyre::bail!(
            "Number of shares ({}) does not match number of party indices ({})",
            shares.len(),
            coeffs.len()
        );
    }
    if shares.len() <= degree {
        eyre::bail!(
            "Not enough shares to reconstruct the secret. Expected {}, got {}",
            degree + 1,
            shares.len()
        );
    }

    let num_vals = shares[0].len();
    for share in shares.iter().skip(1) {
        if share.len() != num_vals {
            eyre::bail!(
                "Number of shares ({}) does not match number of shares in first party ({})",
                share.len(),
                num_vals
            );
        }
    }
    let mut result = Vec::with_capacity(num_vals);

    let lagrange = lagrange_from_coeff(&coeffs[..=degree]);

    for i in 0..num_vals {
        let s = shares
            .iter()
            .take(degree + 1)
            .map(|s| s[i].a)
            .collect::<Vec<_>>();
        let rec = reconstruct(&s, &lagrange);
        result.push(rec);
    }
    Ok(result)
}

/// Secret shares a curve point using Shamir secret sharing and the provided random number generator. The point is split into num_parties shares, where each party holds just one. The outputs are of type [ShamirPointShare]. The degree of the sharing polynomial (i.e., the threshold of maximum number of tolerated colluding parties) is specified by the degree parameter.
pub fn share_curve_point<C: CurveGroup, R: Rng + CryptoRng>(
    val: C,
    degree: usize,
    num_parties: usize,
    rng: &mut R,
) -> Vec<ShamirPointShare<C>> {
    let shares = share_point(val, num_parties, degree, rng);
    ShamirPointShare::convert_vec_rev(shares)
}

/// Reconstructs a curve point from its Shamir shares and lagrange coefficients. Thereby at least `degree` + 1 shares need to be present.
pub fn combine_curve_point<C: CurveGroup>(
    shares: &[ShamirPointShare<C>],
    coeffs: &[usize],
    degree: usize,
) -> eyre::Result<C> {
    if shares.len() != coeffs.len() {
        eyre::bail!(
            "Number of shares ({}) does not match number of party indices ({})",
            shares.len(),
            coeffs.len()
        );
    }
    if shares.len() <= degree {
        eyre::bail!(
            "Not enough shares to reconstruct the secret. Expected {}, got {}",
            degree + 1,
            shares.len()
        );
    }

    let lagrange = lagrange_from_coeff(&coeffs[..=degree]);
    let shares = ShamirPointShare::convert_slice(shares);
    let rec = reconstruct_point(&shares[..=degree], &lagrange);

    Ok(rec)
}

/// Evaluate the poly at the given x
pub fn evaluate_poly<F: PrimeField>(poly: &[F], x: F) -> F {
    debug_assert!(!poly.is_empty());
    let mut iter = poly.iter().rev();
    let mut eval = iter.next().unwrap().to_owned();
    for coeff in iter {
        eval *= x;
        eval += coeff;
    }
    eval
}

/// Evaluate the poly at the given point
pub fn evaluate_poly_point<C: CurveGroup>(poly: &[C], x: C::ScalarField) -> C {
    debug_assert!(!poly.is_empty());
    let mut iter = poly.iter().rev();
    let mut eval = iter.next().unwrap().to_owned();
    for coeff in iter {
        eval.mul_assign(&x);
        eval.add_assign(coeff);
    }
    eval
}

/// Share
pub fn share<F: PrimeField, R: Rng>(
    secret: F,
    num_shares: usize,
    degree: usize,
    rng: &mut R,
) -> Vec<F> {
    let mut shares = Vec::with_capacity(num_shares);
    let mut coeffs = Vec::with_capacity(degree + 1);
    coeffs.push(secret);
    for _ in 0..degree {
        coeffs.push(F::rand(rng));
    }
    for i in 1..=num_shares {
        let share = evaluate_poly(&coeffs, F::from(i as u64));
        shares.push(share);
    }
    shares
}

/// Share with zeros
// sets the shares of parties in points to 0
pub fn share_with_zeros<F: PrimeField>(
    secret: &F,
    zero_points: &[usize],
    share_points: &[usize],
) -> Vec<F> {
    let poly = interpolate_poly_from_secret_and_zeros(secret, zero_points);
    debug_assert_eq!(poly.len(), zero_points.len() + 1);

    let mut shares = Vec::with_capacity(share_points.len());
    for x in share_points {
        let share = evaluate_poly(&poly, F::from(*x as u64));
        shares.push(share);
    }

    shares
}

/// Create the poly from secret and precomputed values
// sets the shares of parties in points to 0
pub fn poly_with_zeros_from_precomputed<F: PrimeField>(secret: &F, precomp: Vec<F>) -> Vec<F> {
    let mut poly = precomp;
    for r in poly.iter_mut() {
        *r *= *secret;
    }

    poly
}

/// Create the poly from secret pont and precomputed values
// sets the shares of parties in points to 0
pub fn poly_with_zeros_from_precomputed_point<F: PrimeField, C>(secret: &C, precomp: &[F]) -> Vec<C>
where
    C: CurveGroup + std::ops::Mul<F, Output = C> + for<'a> std::ops::Mul<&'a F, Output = C>,
{
    let mut poly = Vec::with_capacity(precomp.len());
    for r in precomp.iter() {
        poly.push(secret.mul(r));
    }
    poly
}

/// Share a curve point
pub fn share_point<C: CurveGroup, R: Rng>(
    secret: C,
    num_shares: usize,
    degree: usize,
    rng: &mut R,
) -> Vec<C> {
    let mut shares = Vec::with_capacity(num_shares);
    let mut coeffs = Vec::with_capacity(degree + 1);
    coeffs.push(secret);
    for _ in 0..degree {
        coeffs.push(C::rand(rng));
    }
    for i in 1..=num_shares {
        let share = evaluate_poly_point(&coeffs, C::ScalarField::from(i as u64));
        shares.push(share);
    }
    shares
}

/// Compute the lagrange coeffs
pub fn lagrange_from_coeff<F: PrimeField>(coeffs: &[usize]) -> Vec<F> {
    let num = coeffs.len();
    let mut res = Vec::with_capacity(num);
    for i in coeffs.iter() {
        let mut num = F::one();
        let mut den = F::one();
        let i_ = F::from(*i as u64);
        for j in coeffs.iter() {
            if i != j {
                let j_ = F::from(*j as u64);
                num *= j_;
                den *= j_ - i_;
            }
        }
        let res_ = num * den.inverse().unwrap();
        res.push(res_);
    }
    res
}

#[cfg(test)]
pub(crate) fn lagrange<F: PrimeField>(amount: usize) -> Vec<F> {
    let mut res = Vec::with_capacity(amount);
    for i in 1..=amount {
        let mut num = F::one();
        let mut den = F::one();
        let i_ = F::from(i as u64);
        for j in 1..=amount {
            if i != j {
                let j_ = F::from(j as u64);
                num *= j_;
                den *= j_ - i_;
            }
        }
        let res_ = num * den.inverse().unwrap();
        res.push(res_);
    }
    res
}

/// Reconstruct the from its shares and lagrange coefficients.
pub fn reconstruct<F: PrimeField>(shares: &[F], lagrange: &[F]) -> F {
    debug_assert_eq!(shares.len(), lagrange.len());
    let mut res = F::zero();
    for (s, l) in shares.iter().zip(lagrange.iter()) {
        res += *s * l
    }

    res
}

fn poly_times_root_inplace<F: PrimeField>(poly: &mut Vec<F>, root: &F) {
    poly.insert(0, F::zero());

    for i in 1..poly.len() {
        let tmp = poly[i];
        poly[i - 1] -= tmp * root;
    }
}

/// Precompute the interpolation polys from the given coeffs
pub fn precompute_interpolation_polys<F: PrimeField>(coeffs: &[usize]) -> Vec<Vec<F>> {
    let mut res = Vec::with_capacity(coeffs.len());
    for i in coeffs.iter() {
        let i_f = F::from(*i as u64);
        let mut num = Vec::with_capacity(coeffs.len());
        num.push(F::one());
        let mut d = F::one();
        for j in coeffs.iter() {
            if i != j {
                let j_f = F::from(*j as u64);
                poly_times_root_inplace(&mut num, &j_f);
                d *= i_f - j_f;
            }
        }
        let c = d.inverse().expect("Inverse in lagrange should work");
        for r in num.iter_mut() {
            *r *= c;
        }
        res.push(num);
    }

    res
}

/// Interpolate the poly from the shares and precomputed values
pub fn interpolate_poly_from_precomputed<F: PrimeField>(
    shares: &[F],
    precomputed: &[Vec<F>],
) -> Vec<F> {
    debug_assert_eq!(shares.len(), precomputed.len());

    let mut res = vec![F::zero(); shares.len()];
    for (i, p) in precomputed.iter().zip(shares.iter()) {
        debug_assert_eq!(i.len(), res.len());
        for (r, n) in res.iter_mut().zip(i.iter()) {
            *r += *n * p;
        }
    }
    res
}

#[cfg(test)]
pub(crate) fn interpolate_poly<F: PrimeField>(shares: &[F], coeffs: &[usize]) -> Vec<F> {
    debug_assert_eq!(shares.len(), coeffs.len());

    let mut res = vec![F::zero(); shares.len()];
    for (i, p) in coeffs.iter().zip(shares.iter()) {
        let i_f = F::from(*i as u64);
        let mut num = Vec::with_capacity(coeffs.len());
        num.push(F::one());
        let mut d = F::one();
        for j in coeffs.iter() {
            if i != j {
                let j_f = F::from(*j as u64);
                poly_times_root_inplace(&mut num, &j_f);
                d *= i_f - j_f;
            }
        }
        let mut c = d.inverse().expect("Inverse in lagrange should work");
        c *= p;
        for (r, n) in res.iter_mut().zip(num.iter()) {
            *r += *n * c;
        }
    }
    res
}

/// Interpolate the poly from the given points at zero.
pub fn interpolation_poly_from_zero_points<F: PrimeField>(zero_points: &[usize]) -> Vec<F> {
    let poly_len = zero_points.len() + 1;

    // First round: i = 0, p = secret
    let mut num = Vec::with_capacity(poly_len);
    num.push(F::one());
    let mut d = F::one();
    for j in zero_points.iter() {
        debug_assert_ne!(0, *j);
        let j_f = F::from(*j as u64);
        poly_times_root_inplace(&mut num, &j_f);
        d *= -j_f;
    }
    let c = d.inverse().expect("Inverse in lagrange should work");
    for r in num.iter_mut() {
        *r *= c;
    }
    num
}

/// Puts the secret at x=0 and sets all other p\[x\] to 0 for x in zero_points
pub fn interpolate_poly_from_secret_and_zeros<F: PrimeField>(
    secret: &F,
    zero_points: &[usize],
) -> Vec<F> {
    let num = interpolation_poly_from_zero_points(zero_points);
    poly_with_zeros_from_precomputed(secret, num)
}

/// Reconstructs a curve point from its Shamir shares and lagrange coefficients.
pub fn reconstruct_point<C: CurveGroup>(shares: &[C], lagrange: &[C::ScalarField]) -> C {
    debug_assert_eq!(shares.len(), lagrange.len());
    let mut res = C::zero();
    for (s, l) in shares.iter().zip(lagrange.iter()) {
        res += *s * l
    }

    res
}

#[cfg(test)]
mod shamir_test {
    use super::*;
    use ark_ff::UniformRand;
    use rand::{seq::IteratorRandom, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    const TESTRUNS: usize = 5;

    fn test_shamir<F: PrimeField, const NUM_PARTIES: usize, const DEGREE: usize>() {
        let mut rng = ChaCha12Rng::from_entropy();

        for _ in 0..TESTRUNS {
            let secret = F::rand(&mut rng);
            let shares = super::share(secret, NUM_PARTIES, DEGREE, &mut rng);

            // Test first D+1 shares
            let lagrange = super::lagrange(DEGREE + 1);
            let reconstructed = super::reconstruct(&shares[..=DEGREE], &lagrange);
            assert_eq!(secret, reconstructed);

            // Test random D+1 shares
            let parties = (1..=NUM_PARTIES).choose_multiple(&mut rng, DEGREE + 1);
            let shares = parties.iter().map(|&i| shares[i - 1]).collect::<Vec<_>>();
            let lagrange = super::lagrange_from_coeff(&parties);
            let reconstructed = super::reconstruct(&shares, &lagrange);
            assert_eq!(secret, reconstructed);
        }
    }

    fn test_shamir_point<C: CurveGroup, const NUM_PARTIES: usize, const DEGREE: usize>() {
        let mut rng = ChaCha12Rng::from_entropy();

        for _ in 0..TESTRUNS {
            let secret = C::rand(&mut rng);
            let shares = super::share_point(secret, NUM_PARTIES, DEGREE, &mut rng);

            // Test first D+1 shares
            let lagrange = super::lagrange(DEGREE + 1);
            let reconstructed = super::reconstruct_point(&shares[..=DEGREE], &lagrange);
            assert_eq!(secret, reconstructed);

            // Test random D+1 shares
            let parties = (1..=NUM_PARTIES).choose_multiple(&mut rng, DEGREE + 1);
            let shares = parties.iter().map(|&i| shares[i - 1]).collect::<Vec<_>>();
            let lagrange = super::lagrange_from_coeff(&parties);
            let reconstructed = super::reconstruct_point(&shares, &lagrange);
            assert_eq!(secret, reconstructed);
        }
    }

    fn test_shamir_field_to_point<C: CurveGroup, const NUM_PARTIES: usize, const DEGREE: usize>() {
        let mut rng = ChaCha12Rng::from_entropy();

        for _ in 0..TESTRUNS {
            let secret = C::ScalarField::rand(&mut rng);
            let shares = super::share(secret, NUM_PARTIES, DEGREE, &mut rng);

            // To point
            let secret = C::generator().mul(secret);
            let shares = shares
                .into_iter()
                .map(|s| C::generator().mul(s))
                .collect::<Vec<_>>();

            // Test first D+1 shares
            let lagrange = super::lagrange(DEGREE + 1);
            let reconstructed = super::reconstruct_point(&shares[..=DEGREE], &lagrange);
            assert_eq!(secret, reconstructed);

            // Test random D+1 shares
            let parties = (1..=NUM_PARTIES).choose_multiple(&mut rng, DEGREE + 1);
            let shares = parties.iter().map(|&i| shares[i - 1]).collect::<Vec<_>>();
            let lagrange = super::lagrange_from_coeff(&parties);
            let reconstructed = super::reconstruct_point(&shares, &lagrange);
            assert_eq!(secret, reconstructed);
        }
    }

    fn test_shamir_poly<F: PrimeField, const NUM_PARTIES: usize, const DEGREE: usize>() {
        let mut rng = ChaCha12Rng::from_entropy();

        for _ in 0..TESTRUNS {
            let secret = F::rand(&mut rng);

            // Random poly
            let mut poly = Vec::with_capacity(DEGREE + 1);
            poly.push(secret);
            for _ in 0..DEGREE {
                poly.push(F::rand(&mut rng));
            }

            // Get Shares
            let mut shares = Vec::with_capacity(NUM_PARTIES);
            for i in 1..=NUM_PARTIES {
                let share = evaluate_poly(&poly, F::from(i as u64));
                shares.push(share);
            }

            // Test first D+1 shares
            let reconstructed =
                super::interpolate_poly(&shares[..=DEGREE], &(1..=DEGREE + 1).collect::<Vec<_>>());
            assert_eq!(poly, reconstructed);

            // Test random D+1 shares
            let parties = (1..=NUM_PARTIES).choose_multiple(&mut rng, DEGREE + 1);
            let shares = parties.iter().map(|&i| shares[i - 1]).collect::<Vec<_>>();
            let reconstructed = super::interpolate_poly(&shares, &parties);
            assert_eq!(poly, reconstructed);
        }
    }

    #[test]
    fn test_shamir_3_1() {
        const NUM_PARTIES: usize = 3;
        const DEGREE: usize = 1;
        test_shamir::<ark_bn254::Fr, NUM_PARTIES, DEGREE>();
        test_shamir_point::<ark_bn254::G1Projective, NUM_PARTIES, DEGREE>();
        test_shamir_field_to_point::<ark_bn254::G1Projective, NUM_PARTIES, DEGREE>();
        test_shamir_poly::<ark_bn254::Fr, NUM_PARTIES, DEGREE>();
    }

    #[test]
    fn test_shamir_10_6() {
        const NUM_PARTIES: usize = 10;
        const DEGREE: usize = 6;
        test_shamir::<ark_bn254::Fr, NUM_PARTIES, DEGREE>();
        test_shamir_point::<ark_bn254::G1Projective, NUM_PARTIES, DEGREE>();
        test_shamir_field_to_point::<ark_bn254::G1Projective, NUM_PARTIES, DEGREE>();
        test_shamir_poly::<ark_bn254::Fr, NUM_PARTIES, DEGREE>();
    }
}
