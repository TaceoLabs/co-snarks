//! # Shamir
//!
//! This module implements the shamir share and combine opertions and shamir preprocessing

use ark_ff::PrimeField;
use mpc_net::Network;
use rngs::ShamirRng;
use std::time::Instant;

use rand::{Rng, SeedableRng};

use crate::{MpcState, RngType};

pub mod arithmetic;
pub mod network;
pub mod pointshare;
pub mod poly;
mod rngs;

pub use mpc_types::protocols::shamir::{
    ShamirPointShare, ShamirPrimeFieldShare, combine_curve_point, combine_field_element,
    combine_field_elements, evaluate_poly, evaluate_poly_point,
    interpolation_poly_from_zero_points, lagrange_from_coeff, poly_with_zeros_from_precomputed,
    poly_with_zeros_from_precomputed_point, reconstruct_point, share_curve_point,
    share_field_element, share_field_elements,
};

/// This type is used to construct a [`ShamirState`].
/// Preprocess `amount` number of correlated randomness pairs that are consumed while using the protocol.
pub struct ShamirPreprocessing<F: PrimeField> {
    id: usize,
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

        let seed: [u8; crate::SEED_SIZE] = RngType::from_entropy().r#gen();
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
            id: net.id(),
            num_parties,
            threshold,
            rng_buffer,
        })
    }
}

impl<F: PrimeField> From<ShamirPreprocessing<F>> for ShamirState<F> {
    fn from(value: ShamirPreprocessing<F>) -> Self {
        // We send in circles, so we need to receive from the last parties
        let id = value.id;
        let open_lagrange_t = lagrange_from_coeff(
            &(0..value.threshold + 1)
                .map(|i| (id + value.num_parties - i) % value.num_parties + 1)
                .collect::<Vec<_>>(),
        );
        let open_lagrange_2t = lagrange_from_coeff(
            &(0..2 * value.threshold + 1)
                .map(|i| (id + value.num_parties - i) % value.num_parties + 1)
                .collect::<Vec<_>>(),
        );

        let mul_lagrange_2t =
            lagrange_from_coeff(&(1..=2 * value.threshold + 1).collect::<Vec<_>>());

        debug_assert_eq!(Self::KING_ID, 0); // Slightly different implementation required in degree reduce if not

        // precompute the poly for interpolating a secret with known zero shares
        let num_non_zero = value.num_parties - value.threshold;
        let zero_points = (num_non_zero + 1..=value.num_parties).collect::<Vec<_>>();
        let mul_reconstruct_with_zeros = interpolation_poly_from_zero_points(&zero_points);

        ShamirState {
            id,
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

/// This struct holds all necessary information for an MPC protocol based on Shamir. It contains the randomness, the threshold and the lagrange polynomials for opening.
pub struct ShamirState<F: PrimeField> {
    id: usize,
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

impl<F: PrimeField> ShamirState<F> {
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

impl<F: PrimeField> MpcState for ShamirState<F> {
    type PartyID = usize;

    fn id(&self) -> Self::PartyID {
        self.id
    }

    fn fork(&mut self, n: usize) -> eyre::Result<Self> {
        Ok(Self {
            id: self.id,
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
