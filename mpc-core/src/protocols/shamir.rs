//! # Shamir
//!
//! This module implements the shamir share and combine opertions and shamir preprocessing

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use itertools::izip;
use mpc_engine::Network;
use rngs::ShamirRng;
use std::time::Instant;

use rand::{CryptoRng, Rng, SeedableRng};

use crate::{Fork, RngType};

pub mod arithmetic;
pub mod core;
pub mod network;
pub mod pointshare;
pub mod poly;
mod rngs;

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
    let shares = core::share(val, num_parties, degree, rng);
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

    let lagrange = core::lagrange_from_coeff(&coeffs[..=degree]);
    let shares = ShamirShare::convert_slice(shares);
    let rec = core::reconstruct(&shares[..=degree], &lagrange);
    Ok(rec)
}

/// Secret shares a vector of field element using Shamir secret sharing and the provided random number generator. The field elements are split into num_parties shares each, where each party holds just one. The outputs are `Vecs` of `Vecs` of type [`ShamirPrimeFieldShare`]. The degree of the sharing polynomial (i.e., the threshold of maximum number of tolerated colluding parties) is specified by the degree parameter.
pub fn share_field_elements<F: PrimeField, R: Rng + CryptoRng>(
    vals: &[F],
    degree: usize,
    num_parties: usize,
    rng: &mut R,
) -> Vec<Vec<ShamirShare<F>>> {
    let mut result = (0..num_parties)
        .map(|_| Vec::with_capacity(vals.len()))
        .collect::<Vec<_>>();

    for val in vals {
        let shares = core::share(*val, num_parties, degree, rng);
        let shares = ShamirShare::convert_vec_rev(shares);
        for (r, s) in izip!(&mut result, shares) {
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

    let lagrange = core::lagrange_from_coeff(&coeffs[..=degree]);

    for i in 0..num_vals {
        let s = shares
            .iter()
            .take(degree + 1)
            .map(|s| s[i].a)
            .collect::<Vec<_>>();
        let rec = core::reconstruct(&s, &lagrange);
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
    let shares = core::share_point(val, num_parties, degree, rng);
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

    let lagrange = core::lagrange_from_coeff(&coeffs[..=degree]);
    let shares = ShamirPointShare::convert_slice(shares);
    let rec = core::reconstruct_point(&shares[..=degree], &lagrange);

    Ok(rec)
}

/// This type is used to construct a [`ShamirProtocol`].
/// Preprocess `amount` number of corre;ated randomness pairs that are consumed while using the protocol.
pub struct ShamirPreprocessing<F: PrimeField> {
    party_id: usize,
    num_parties: usize,
    threshold: usize,
    rng_buffer: ShamirRng<F>,
}

impl<F: PrimeField> ShamirPreprocessing<F> {
    /// Construct a new [`ShamirPreprocessing`] type and generate `amount` number of corr rand pairs
    pub fn new<N: Network>(
        num_parties: usize,
        threshold: usize,
        amount: usize,
        net: &N,
    ) -> eyre::Result<Self> {
        if 2 * threshold + 1 > num_parties {
            eyre::bail!("Threshold too large for number of parties")
        }

        let seed: [u8; crate::SEED_SIZE] = RngType::from_entropy().gen();
        let mut rng_buffer = ShamirRng::new(seed, num_parties, threshold, net)?;

        let start = Instant::now();
        // buffer_triple generates amount * batch_size, so we ceil dive the amount we want
        let amount = amount.div_ceil(rng_buffer.get_size_per_batch());
        rng_buffer.buffer_triples(net, amount)?;
        tracing::debug!(
            "generating {amount} triples took {} ms",
            start.elapsed().as_micros() as f64 / 1000.0
        );

        Ok(Self {
            party_id: net.id(),
            num_parties,
            threshold,
            rng_buffer,
        })
    }
}

impl<F: PrimeField> From<ShamirPreprocessing<F>> for ShamirProtocol<F> {
    fn from(value: ShamirPreprocessing<F>) -> Self {
        // We send in circles, so we need to receive from the last parties
        let id = value.party_id;
        let open_lagrange_t = core::lagrange_from_coeff(
            &(0..value.threshold + 1)
                .map(|i| (id + value.num_parties - i) % value.num_parties + 1)
                .collect::<Vec<_>>(),
        );
        let open_lagrange_2t = core::lagrange_from_coeff(
            &(0..2 * value.threshold + 1)
                .map(|i| (id + value.num_parties - i) % value.num_parties + 1)
                .collect::<Vec<_>>(),
        );

        let mul_lagrange_2t =
            core::lagrange_from_coeff(&(1..=2 * value.threshold + 1).collect::<Vec<_>>());

        debug_assert_eq!(Self::KING_ID, 0); // Slightly different implementation required in degree reduce if not

        // precompute the poly for interpolating a secret with known zero shares
        let num_non_zero = value.num_parties - value.threshold;
        let zero_points = (num_non_zero + 1..=value.num_parties).collect::<Vec<_>>();
        let mul_reconstruct_with_zeros = core::interpolation_poly_from_zero_points(&zero_points);

        ShamirProtocol {
            num_parties: value.num_parties,
            threshold: value.threshold,
            open_lagrange_t,
            open_lagrange_2t,
            mul_lagrange_2t,
            mul_reconstruct_with_zeros,
            rng_buffer: value.rng_buffer,
            generation_amount: Self::DEFAULT_PAIR_GEN_AMOUNT,
        }
    }
}

/// This struct holds all necessary information for an MPC protocol based on Shamir. It contains
/// a [`ShamirNetwork`], the randomness, the threshold and the lagrange
/// polynomials for opening.
pub struct ShamirProtocol<F: PrimeField> {
    /// The number of parties
    pub num_parties: usize,
    /// The threshold, degree of polynomial
    pub threshold: usize,
    /// The open lagrange coeffs
    pub open_lagrange_t: Vec<F>,
    /// The open lagrange coeffs for threshold * 2
    pub open_lagrange_2t: Vec<F>,
    mul_lagrange_2t: Vec<F>,
    mul_reconstruct_with_zeros: Vec<F>,
    rng_buffer: ShamirRng<F>,
    generation_amount: usize,
}

impl<F: PrimeField> ShamirProtocol<F> {
    const KING_ID: usize = 0;
    const DEFAULT_PAIR_GEN_AMOUNT: usize = 1024;

    /// Get a correlated randomness pair
    pub fn get_pair<N: Network>(&mut self, net: &N) -> eyre::Result<(F, F)> {
        if self.rng_buffer.r_t.is_empty() {
            debug_assert!(self.rng_buffer.r_2t.is_empty());
            if self.rng_buffer.num_parties != 3 {
                // In the 3-party case no communication is required, so we do not print a warning
                tracing::warn!("Precomputed randomness buffer empty, refilling...");
            }
            self.rng_buffer
                .buffer_triples(net, self.generation_amount)?;
            self.generation_amount *= 2; // We increase the amount for preprocessing exponentially
        }

        Ok((
            self.rng_buffer.r_t.pop().unwrap(),
            self.rng_buffer.r_2t.pop().unwrap(),
        ))
    }

    /// Makes sure that num_triples are already preprocessed. It will thus create present_triples - num_triples new triples if not enough are present.
    pub fn buffer_triples<N: Network>(&mut self, net: &N, num_triples: usize) -> eyre::Result<()> {
        let present_triples = self.rng_buffer.r_t.len();
        debug_assert_eq!(self.rng_buffer.r_2t.len(), present_triples);
        if present_triples >= num_triples {
            return Ok(());
        }

        self.rng_buffer.buffer_triples(
            net,
            (num_triples - present_triples).div_ceil(self.rng_buffer.get_size_per_batch()),
        )
    }

    /// Generates a random field element and returns it as a share.
    pub fn rand<N: Network>(&mut self, net: &N) -> eyre::Result<ShamirPrimeFieldShare<F>> {
        self.get_pair(net)
            .map(|(r, _)| ShamirPrimeFieldShare::new(r))
    }
}

impl<F: PrimeField> Fork for ShamirProtocol<F> {
    fn fork(&mut self, n: usize) -> eyre::Result<Self> {
        Ok(Self {
            num_parties: self.num_parties,
            threshold: self.threshold,
            open_lagrange_t: self.open_lagrange_t.clone(),
            open_lagrange_2t: self.open_lagrange_2t.clone(),
            mul_lagrange_2t: self.mul_lagrange_2t.clone(),
            mul_reconstruct_with_zeros: self.mul_reconstruct_with_zeros.clone(),
            rng_buffer: self.rng_buffer.fork_with_pairs(n),
            generation_amount: self.generation_amount,
        })
    }
}
