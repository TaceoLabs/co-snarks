//! # Shamir
//!
//! This module implements the shamir share and combine opertions and shamir preprocessing

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use itertools::izip;
use network::{ShamirMpcNet, ShamirNetwork};
use rngs::ShamirRng;
use std::time::Instant;

use rand::{CryptoRng, Rng, SeedableRng};

use crate::RngType;

pub mod arithmetic;
pub mod core;
pub mod network;
pub mod pointshare;
pub mod poly;
mod rngs;

pub use arithmetic::types::ShamirPrimeFieldShare;
pub use pointshare::types::ShamirPointShare;

type IoResult<T> = std::io::Result<T>;
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
pub struct ShamirPreprocessing<F: PrimeField, N: ShamirNetwork> {
    threshold: usize,
    rng_buffer: ShamirRng<F>,
    network: N,
}

impl<F: PrimeField, N: ShamirNetwork> ShamirPreprocessing<F, N> {
    /// Construct a new [`ShamirPreprocessing`] type and generate `amount` number of corr rand pairs
    pub fn new(threshold: usize, mut network: N, amount: usize) -> eyre::Result<Self> {
        let num_parties = network.get_num_parties();

        if 2 * threshold + 1 > num_parties {
            eyre::bail!("Threshold too large for number of parties")
        }

        let seed: [u8; crate::SEED_SIZE] = RngType::from_entropy().gen();
        let mut rng_buffer = ShamirRng::new(seed, threshold, &mut network)?;

        let start = Instant::now();
        // buffer_triple generates amount * batch_size, so we ceil dive the amount we want
        let amount = amount.div_ceil(rng_buffer.get_size_per_batch());
        rng_buffer.buffer_triples(&mut network, amount)?;
        tracing::debug!(
            "generating {amount} triples took {} ms",
            start.elapsed().as_micros() as f64 / 1000.0
        );

        Ok(Self {
            threshold,
            rng_buffer,
            network,
        })
    }
}

impl<F: PrimeField, N: ShamirNetwork> From<ShamirPreprocessing<F, N>> for ShamirProtocol<F, N> {
    fn from(value: ShamirPreprocessing<F, N>) -> Self {
        let num_parties = value.network.get_num_parties();
        // We send in circles, so we need to receive from the last parties
        let id = value.network.get_id();
        let open_lagrange_t = core::lagrange_from_coeff(
            &(0..value.threshold + 1)
                .map(|i| (id + num_parties - i) % num_parties + 1)
                .collect::<Vec<_>>(),
        );
        let open_lagrange_2t = core::lagrange_from_coeff(
            &(0..2 * value.threshold + 1)
                .map(|i| (id + num_parties - i) % num_parties + 1)
                .collect::<Vec<_>>(),
        );

        let mul_lagrange_2t =
            core::lagrange_from_coeff(&(1..=2 * value.threshold + 1).collect::<Vec<_>>());

        debug_assert_eq!(Self::KING_ID, 0); // Slightly different implementation required in degree reduce if not

        // precompute the poly for interpolating a secret with known zero shares
        let num_non_zero = num_parties - value.threshold;
        let zero_points = (num_non_zero + 1..=num_parties).collect::<Vec<_>>();
        let mul_reconstruct_with_zeros = core::interpolation_poly_from_zero_points(&zero_points);

        ShamirProtocol {
            threshold: value.threshold,
            open_lagrange_t,
            open_lagrange_2t,
            mul_lagrange_2t,
            mul_reconstruct_with_zeros,
            network: value.network,
            rng_buffer: value.rng_buffer,
            generation_amount: Self::DEFAULT_PAIR_GEN_AMOUNT,
        }
    }
}

/// This struct holds all necessary information for an MPC protocol based on Shamir. It contains
/// a [`ShamirNetwork`], the randomness, the threshold and the lagrange
/// polynomials for opening.
pub struct ShamirProtocol<F: PrimeField, N: ShamirNetwork> {
    /// The threshold, degree of polynomial
    pub threshold: usize,
    /// The open lagrange coeffs
    pub open_lagrange_t: Vec<F>,
    /// The open lagrange coeffs for threshold * 2
    pub open_lagrange_2t: Vec<F>,
    mul_lagrange_2t: Vec<F>,
    mul_reconstruct_with_zeros: Vec<F>,
    /// The underlying [`ShamirNetwork`]
    pub network: N,
    rng_buffer: ShamirRng<F>,
    generation_amount: usize,
}

impl<F: PrimeField, N: ShamirNetwork> ShamirProtocol<F, N> {
    const KING_ID: usize = 0;
    const DEFAULT_PAIR_GEN_AMOUNT: usize = 1024;

    /// Create a forked [`ShamirProtocol`] that consumes `amount` number of corr rand pairs from its parent
    pub fn fork_with_pairs(&mut self, amount: usize) -> std::io::Result<Self> {
        Ok(Self {
            threshold: self.threshold,
            open_lagrange_t: self.open_lagrange_t.clone(),
            open_lagrange_2t: self.open_lagrange_2t.clone(),
            mul_lagrange_2t: self.mul_lagrange_2t.clone(),
            mul_reconstruct_with_zeros: self.mul_reconstruct_with_zeros.clone(),
            network: self.network.fork()?,
            rng_buffer: self.rng_buffer.fork_with_pairs(amount),
            generation_amount: self.generation_amount,
        })
    }

    /// Get a correlated randomness pair
    pub fn get_pair(&mut self) -> std::io::Result<(F, F)> {
        if self.rng_buffer.r_t.is_empty() {
            debug_assert!(self.rng_buffer.r_2t.is_empty());
            if self.rng_buffer.num_parties != 3 {
                // In the 3-party case no communication is required, so we do not print a warning
                tracing::warn!("Precomputed randomness buffer empty, refilling...");
            }
            self.rng_buffer
                .buffer_triples(&mut self.network, self.generation_amount)?;
            self.generation_amount *= 2; // We increase the amount for preprocessing exponentially
        }

        Ok((
            self.rng_buffer.r_t.pop().unwrap(),
            self.rng_buffer.r_2t.pop().unwrap(),
        ))
    }

    /// Makes sure that num_triples are already preprocessed. It will thus create present_triples - num_triples new triples if not enough are present.
    pub fn buffer_triples(&mut self, num_triples: usize) -> std::io::Result<()> {
        let present_triples = self.rng_buffer.r_t.len();
        debug_assert_eq!(self.rng_buffer.r_2t.len(), present_triples);
        if present_triples >= num_triples {
            return Ok(());
        }

        self.rng_buffer.buffer_triples(
            &mut self.network,
            (num_triples - present_triples).div_ceil(self.rng_buffer.get_size_per_batch()),
        )
    }

    /// Generates a random field element and returns it as a share.
    pub fn rand(&mut self) -> std::io::Result<ShamirPrimeFieldShare<F>> {
        self.get_pair().map(|(r, _)| ShamirPrimeFieldShare::new(r))
    }

    pub(crate) fn degree_reduce(&mut self, mut input: F) -> std::io::Result<ShamirShare<F>> {
        let num_non_zero = self.network.get_num_parties() - self.threshold;

        let (r_t, r_2t) = self.get_pair()?;
        input += r_2t;

        let my_id = self.network.get_id();
        let my_share = if my_id == Self::KING_ID {
            // Accumulate the result
            let mut acc = F::zero();
            for (other_id, lagrange) in self.mul_lagrange_2t.iter().enumerate() {
                if other_id == Self::KING_ID {
                    acc += input * lagrange;
                } else {
                    let r = self.network.recv::<F>(other_id)?;
                    acc += r * lagrange;
                }
            }
            // So far parties who do not require sending, do not send, so no receive here

            // Send fresh shares
            // Since <acc> does not have to be private, we share it as a known polynomial, such that t parties know their share is 0. Consequently we can reduce the amount of communication.
            // Note: When expanding t+1 double shares to n double shares (Atlas) we cannot do this anymore, since <acc> needs to stay private. Atlas also requires rotating the King server.

            let poly = core::poly_with_zeros_from_precomputed(
                &acc,
                self.mul_reconstruct_with_zeros.to_owned(),
            );

            let mut my_share = F::default();
            for id in 0..num_non_zero {
                let val = core::evaluate_poly(&poly, F::from(id as u64 + 1));
                if id == my_id {
                    my_share = val;
                } else {
                    self.network.send(id, val)?;
                }
            }
            my_share
        } else {
            if my_id <= self.threshold * 2 {
                // Only send if my items are required
                self.network.send(Self::KING_ID, input)?;
            }
            if my_id < num_non_zero {
                self.network.recv(Self::KING_ID)?
            } else {
                F::zero()
            }
        };

        Ok(ShamirShare::new(my_share - r_t))
    }

    /// Degree reduce all inputs
    pub fn degree_reduce_vec(
        &mut self,
        mut inputs: Vec<F>,
    ) -> std::io::Result<Vec<ShamirShare<F>>> {
        let num_non_zero = self.network.get_num_parties() - self.threshold;

        let len = inputs.len();
        let mut r_ts = Vec::with_capacity(len);

        for inp in inputs.iter_mut() {
            let (r_t, r_2t) = self.get_pair()?;
            *inp += r_2t;
            r_ts.push(r_t);
        }

        let my_id = self.network.get_id();
        let mut my_shares = if my_id == Self::KING_ID {
            // Accumulate the result
            let mut acc = vec![F::zero(); len];
            for (other_id, lagrange) in self.mul_lagrange_2t.iter().enumerate() {
                if other_id == Self::KING_ID {
                    for (acc, muls) in izip!(&mut acc, &inputs) {
                        *acc += *muls * lagrange;
                    }
                } else {
                    let r = self.network.recv_many::<F>(other_id)?;
                    if r.len() != len {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,"During execution of degree_reduce_vec in MPC: Invalid number of elements received",
                        ));
                    }
                    for (acc, muls) in izip!(&mut acc, r) {
                        *acc += muls * lagrange;
                    }
                }
            }
            // So far parties who do not require sending, do not send, so no receive here

            // Send fresh shares
            // Since <acc> does not have to be private, we share it as a known polynomial, such that t parties know their share is 0. Consequently we can reduce the amount of communication.
            // Note: When expanding t+1 double shares to n double shares (Atlas) we cannot do this anymore, since <acc> needs to stay private. Atlas also requires rotating the King server.

            let mut polys = Vec::with_capacity(acc.len());
            for acc in acc {
                let poly = core::poly_with_zeros_from_precomputed(
                    &acc,
                    self.mul_reconstruct_with_zeros.to_owned(),
                );
                polys.push(poly);
            }

            let mut my_share = Vec::new();
            for id in 0..num_non_zero {
                let id_f = F::from(id as u64 + 1);
                let vals = polys
                    .iter()
                    .map(|poly| core::evaluate_poly(poly, id_f))
                    .collect::<Vec<_>>();
                if id == my_id {
                    my_share = vals;
                } else {
                    self.network.send_many(id, &vals)?;
                }
            }
            my_share
        } else {
            if my_id <= self.threshold * 2 {
                // Only send if my items are required
                self.network.send_many(Self::KING_ID, &inputs)?;
            }
            if my_id < num_non_zero {
                let r = self.network.recv_many::<F>(Self::KING_ID)?;
                if r.len() != len {
                    return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,"During execution of degree_reduce_vec in MPC: Invalid number of elements received",
                ));
                }
                r
            } else {
                vec![F::zero(); len]
            }
        };

        for (share, r) in izip!(&mut my_shares, r_ts) {
            *share -= r;
        }
        Ok(ShamirShare::convert_vec_rev(my_shares))
    }

    /// Reduces the degree of a point share C from 2*t to t
    pub fn degree_reduce_point<C>(&mut self, mut input: C) -> std::io::Result<ShamirPointShare<C>>
    where
        C: CurveGroup + std::ops::Mul<F, Output = C> + for<'a> std::ops::Mul<&'a F, Output = C>,
    {
        let num_non_zero = self.network.get_num_parties() - self.threshold;

        let (r_t, r_2t) = self.get_pair()?;
        let r_t = C::generator().mul(r_t);
        let r_2t = C::generator().mul(r_2t);

        input += r_2t;
        let my_id = self.network.get_id();

        let my_share = if my_id == Self::KING_ID {
            // Accumulate the result
            let mut acc = C::zero();
            for (other_id, lagrange) in self.mul_lagrange_2t.iter().enumerate() {
                if other_id == Self::KING_ID {
                    acc += input * lagrange;
                } else {
                    let r = self.network.recv::<C>(other_id)?;
                    acc += r * lagrange;
                }
            }
            // So far parties who do not require sending, do not send, so no receive here

            // Send fresh shares
            // Since <acc> does not have to be private, we share it as a known polynomial, such that t parties know their share is 0. Consequently we can reduce the amount of communication.
            // Note: When expanding t+1 double shares to n double shares (Atlas) we cannot do this anymore, since <acc> needs to stay private. Atlas also requires rotating the King server.

            let poly = core::poly_with_zeros_from_precomputed_point(
                &acc,
                &self.mul_reconstruct_with_zeros,
            );

            let mut my_share = C::default();
            for id in 0..num_non_zero {
                let val = core::evaluate_poly_point(&poly, C::ScalarField::from(id as u64 + 1));
                if id == my_id {
                    my_share = val;
                } else {
                    self.network.send(id, val)?;
                }
            }

            my_share
        } else {
            if my_id <= self.threshold * 2 {
                // Only send if my items are required
                self.network.send(Self::KING_ID, input)?;
            }
            if my_id < num_non_zero {
                self.network.recv(Self::KING_ID)?
            } else {
                C::default()
            }
        };

        Ok(ShamirPointShare::new(my_share - r_t))
    }

    /// Consumes self and returns the network
    pub fn into_network(self) -> N {
        self.network
    }
}

impl<F: PrimeField> ShamirProtocol<F, ShamirMpcNet> {
    /// Get the underlying network
    pub fn get_network(self) -> ShamirMpcNet {
        self.network
    }
}
