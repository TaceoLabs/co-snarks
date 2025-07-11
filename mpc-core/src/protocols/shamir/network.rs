//! Shamir Network
//!
//! This module contains the networking functionality for the Shamir MPC protocol.

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use itertools::izip;
use mpc_net::Network;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use super::{
    ShamirPointShare, ShamirPrimeFieldShare, ShamirState, evaluate_poly, evaluate_poly_point,
    poly_with_zeros_from_precomputed, poly_with_zeros_from_precomputed_point,
};

const KING_ID: usize = 0;

/// A extension trait that Shamir specific methods to [`Network`].
pub trait ShamirNetworkExt: Network {
    /// Sends data to the target party
    #[inline(always)]
    fn send_to<F: CanonicalSerialize>(&self, to: usize, data: F) -> eyre::Result<()> {
        self.send_many(to, &[data])
    }

    /// Sends a vector of data to the target party.
    #[inline(always)]
    fn send_many<F: CanonicalSerialize>(&self, to: usize, data: &[F]) -> eyre::Result<()> {
        let size = data.serialized_size(ark_serialize::Compress::No);
        let mut ser_data = Vec::with_capacity(size);
        data.serialize_uncompressed(&mut ser_data)?;
        self.send(to, &ser_data)?;
        Ok(())
    }

    /// Receives data from the party with the given id.
    #[inline(always)]
    fn recv_from<F: CanonicalDeserialize>(&self, from: usize) -> eyre::Result<F> {
        let mut res = self.recv_many(from)?;
        if res.len() != 1 {
            eyre::bail!("Expected 1 element, got more",)
        } else {
            Ok(res.pop().unwrap())
        }
    }

    /// Receives a vector of data from the party with the given id.
    #[inline(always)]
    fn recv_many<F: CanonicalDeserialize>(&self, from: usize) -> eyre::Result<Vec<F>> {
        let data = self.recv(from)?;

        let res = Vec::<F>::deserialize_uncompressed_unchecked(&data[..])?;

        Ok(res)
    }

    /// Send and reveive data to and from all parties.
    #[inline(always)]
    fn broadcast<F: CanonicalSerialize + CanonicalDeserialize + Clone + Send>(
        &self,

        num_parties: usize,
        data: F,
    ) -> eyre::Result<Vec<F>> {
        // Serialize
        let size = data.serialized_size(ark_serialize::Compress::No);
        let mut ser_data = Vec::with_capacity(size);
        data.to_owned().serialize_uncompressed(&mut ser_data)?;

        (0..num_parties)
            .into_par_iter()
            .map(|other_id| {
                // Send
                if other_id != self.id() {
                    self.send(other_id, &ser_data)?;
                }
                // Receive
                if other_id != self.id() {
                    let data = self.recv(other_id)?;
                    eyre::Ok(F::deserialize_uncompressed_unchecked(&data[..])?)
                } else {
                    eyre::Ok(data.to_owned())
                }
            })
            .collect::<eyre::Result<Vec<_>>>()
    }

    /// Send and reveive a vector of data to and from all parties.
    #[inline(always)]
    fn broadcast_next<F: CanonicalSerialize + CanonicalDeserialize + Clone + Send>(
        &self,

        num_parties: usize,
        num: usize,
        data: F,
    ) -> eyre::Result<Vec<F>> {
        // Serialize
        let size = data.serialized_size(ark_serialize::Compress::No);
        let mut ser_data = Vec::with_capacity(size);
        data.to_owned().serialize_uncompressed(&mut ser_data)?;

        let mut res = Vec::with_capacity(num);
        res.push(data);

        let remaining = (1..num)
            .into_par_iter()
            .map(|i| {
                // Send
                let other_id = (self.id() + i) % num_parties;
                self.send(other_id, &ser_data)?;
                // Receive
                let other_id = (self.id() + num_parties - i) % num_parties;
                let data = self.recv(other_id)?;
                eyre::Ok(F::deserialize_uncompressed_unchecked(&data[..])?)
            })
            .collect::<eyre::Result<Vec<_>>>()?;

        res.extend(remaining);

        Ok(res)
    }

    /// Degree reduce
    #[inline(always)]
    fn degree_reduce<F: PrimeField>(
        &self,

        state: &mut ShamirState<F>,
        input: F,
    ) -> eyre::Result<ShamirPrimeFieldShare<F>>
    where
        Self: Sized,
    {
        let mut res = self.degree_reduce_many(state, vec![input])?;
        if res.len() != 1 {
            eyre::bail!("Expected 1 element, got more",)
        } else {
            //we checked that there is really one element
            Ok(res.pop().unwrap())
        }
    }

    /// Degree reduce many
    #[inline(always)]
    fn degree_reduce_many<F: PrimeField>(
        &self,

        state: &mut ShamirState<F>,
        mut inputs: Vec<F>,
    ) -> eyre::Result<Vec<ShamirPrimeFieldShare<F>>>
    where
        Self: Sized,
    {
        let num_non_zero = state.num_parties - state.threshold;

        let len = inputs.len();
        let mut r_ts = Vec::with_capacity(len);

        for inp in inputs.iter_mut() {
            let (r_t, r_2t) = state.get_pair(self)?;
            *inp += r_2t;
            r_ts.push(r_t);
        }

        let my_id = self.id();
        let mut my_shares = if my_id == KING_ID {
            // Accumulate the result
            let mut acc = vec![F::zero(); len];
            for (other_id, lagrange) in state.mul_lagrange_2t.iter().enumerate() {
                if other_id == KING_ID {
                    for (acc, muls) in izip!(&mut acc, &inputs) {
                        *acc += *muls * lagrange;
                    }
                } else {
                    let r = self.recv_many::<F>(other_id)?;
                    if r.len() != len {
                        eyre::bail!(
                            "During execution of degree_reduce_vec in MPC: Invalid number of elements received"
                        );
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
                let poly = poly_with_zeros_from_precomputed(
                    &acc,
                    state.mul_reconstruct_with_zeros.to_owned(),
                );
                polys.push(poly);
            }

            let mut my_share = Vec::new();
            for id in 0..num_non_zero {
                let id_f = F::from(id as u64 + 1);
                let vals = polys
                    .iter()
                    .map(|poly| evaluate_poly(poly, id_f))
                    .collect::<Vec<_>>();
                if id == my_id {
                    my_share = vals;
                } else {
                    self.send_many(id, &vals)?;
                }
            }
            my_share
        } else {
            if my_id <= state.threshold * 2 {
                // Only send if my items are required
                self.send_many(KING_ID, &inputs)?;
            }
            if my_id < num_non_zero {
                let r = self.recv_many::<F>(KING_ID)?;
                if r.len() != len {
                    eyre::bail!(
                        "During execution of degree_reduce_vec in MPC: Invalid number of elements received"
                    );
                }
                r
            } else {
                vec![F::zero(); len]
            }
        };

        for (share, r) in izip!(&mut my_shares, r_ts) {
            *share -= r;
        }
        Ok(ShamirPrimeFieldShare::convert_vec_rev(my_shares))
    }

    /// Degree reduce point
    #[inline(always)]
    fn degree_reduce_point<C, F: PrimeField>(
        &self,

        state: &mut ShamirState<F>,
        mut input: C,
    ) -> eyre::Result<ShamirPointShare<C>>
    where
        C: CurveGroup + std::ops::Mul<F, Output = C> + for<'a> std::ops::Mul<&'a F, Output = C>,
        Self: Sized,
    {
        let num_non_zero = state.num_parties - state.threshold;

        let (r_t, r_2t) = state.get_pair(self)?;
        let r_t = C::generator().mul(r_t);
        let r_2t = C::generator().mul(r_2t);

        input += r_2t;
        let my_id = self.id();

        let my_share = if my_id == KING_ID {
            // Accumulate the result
            let mut acc = C::zero();
            for (other_id, lagrange) in state.mul_lagrange_2t.iter().enumerate() {
                if other_id == KING_ID {
                    acc += input * lagrange;
                } else {
                    let r = self.recv_from::<C>(other_id)?;
                    acc += r * lagrange;
                }
            }
            // So far parties who do not require sending, do not send, so no receive here

            // Send fresh shares
            // Since <acc> does not have to be private, we share it as a known polynomial, such that t parties know their share is 0. Consequently we can reduce the amount of communication.
            // Note: When expanding t+1 double shares to n double shares (Atlas) we cannot do this anymore, since <acc> needs to stay private. Atlas also requires rotating the King server.

            let poly =
                poly_with_zeros_from_precomputed_point(&acc, &state.mul_reconstruct_with_zeros);

            let mut my_share = C::default();
            for id in 0..num_non_zero {
                let val = evaluate_poly_point(&poly, C::ScalarField::from(id as u64 + 1));
                if id == my_id {
                    my_share = val;
                } else {
                    self.send_to(id, val)?;
                }
            }

            my_share
        } else {
            if my_id <= state.threshold * 2 {
                // Only send if my items are required
                self.send_to(KING_ID, input)?;
            }
            if my_id < num_non_zero {
                self.recv_from(KING_ID)?
            } else {
                C::default()
            }
        };

        Ok(ShamirPointShare::new(my_share - r_t))
    }

    /// Send and recv `to` and `from` party
    #[inline(always)]
    fn send_and_recv<F: CanonicalSerialize + CanonicalDeserialize + Send>(
        &self,

        to: usize,
        data: F,
        from: usize,
    ) -> eyre::Result<F> {
        let mut res = self.send_and_recv_many(to, &[data], from)?;
        if res.len() != 1 {
            eyre::bail!("Expected 1 element, got more",)
        } else {
            //we checked that there is really one element
            Ok(res.pop().unwrap())
        }
    }

    /// Send and recv `to` and `from` party
    #[inline(always)]
    fn send_and_recv_many<F: CanonicalSerialize + CanonicalDeserialize + Send>(
        &self,

        to: usize,
        data: &[F],
        from: usize,
    ) -> eyre::Result<Vec<F>> {
        self.send_many(to, data)?;
        self.recv_many(from)
    }
}

impl<N: Network> ShamirNetworkExt for N {}
