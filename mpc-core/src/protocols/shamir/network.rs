//! Shamir Network
//!
//! This module contains the networking functionality for the Shamir MPC protocol.

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bytes::Bytes;
use mpc_net::Network;
use rayon::prelude::*;

use super::{ShamirPointShare, ShamirPrimeFieldShare, ShamirState};

const KING_ID: usize = 0;

/// Vectors with fewer elements are processed on the calling thread, and larger vectors are
/// split into pieces of at least this size. The work per element is only a few field
/// operations, so smaller pieces are not worth the coordination with the thread pool.
pub(super) const MIN_PAR_LEN: usize = 4096;

/// The number of bytes used to encode the length of a serialized vector.
const LEN_PREFIX: usize = std::mem::size_of::<u64>();

/// Serializes the `len` field elements produced by `element`, using multiple threads if there
/// are enough elements. The result is the uncompressed serialization of a `Vec<F>`.
pub(super) fn serialize_field_elements<F: PrimeField>(
    len: usize,
    element: impl Fn(usize) -> F + Sync,
) -> eyre::Result<Bytes> {
    let elem_size = F::zero().uncompressed_size();
    let mut data = vec![0u8; LEN_PREFIX + len * elem_size];
    let (prefix, payload) = data.split_at_mut(LEN_PREFIX);
    prefix.copy_from_slice(&(len as u64).to_le_bytes());

    let serialize = |(i, chunk): (usize, &mut [u8])| element(i).serialize_uncompressed(chunk);
    if len < MIN_PAR_LEN {
        payload
            .chunks_exact_mut(elem_size)
            .enumerate()
            .try_for_each(serialize)?;
    } else {
        payload
            .par_chunks_exact_mut(elem_size)
            .enumerate()
            .with_min_len(MIN_PAR_LEN)
            .try_for_each(serialize)?;
    }
    Ok(Bytes::from(data))
}

/// Deserializes the received `Vec<F>`s and calls `f` with each element, the index of its
/// message and the corresponding `stride` elements of `out`. All messages are processed in a
/// single pass over `out`, using multiple threads if there are enough elements.
/// Fails if a message does not contain exactly one field element per `stride` elements of `out`.
pub(super) fn for_each_received<F: PrimeField, T: Send>(
    messages: &[Bytes],
    out: &mut [T],
    stride: usize,
    f: impl Fn(&mut [T], usize, F) + Sync,
) -> eyre::Result<()> {
    debug_assert_eq!(out.len() % stride, 0);
    let len = out.len() / stride;
    let elem_size = F::zero().uncompressed_size();
    let valid = |data: &Bytes| {
        data.len() == LEN_PREFIX + len * elem_size
            && data[..LEN_PREFIX] == (len as u64).to_le_bytes()
    };
    if !messages.iter().all(valid) {
        eyre::bail!("Invalid number of elements received");
    }
    if messages.is_empty() {
        return Ok(());
    }

    let process = |(i, out): (usize, &mut [T])| {
        let start = LEN_PREFIX + i * elem_size;
        messages.iter().enumerate().try_for_each(|(msg, data)| {
            F::deserialize_uncompressed_unchecked(&data[start..start + elem_size])
                .map(|elem| f(out, msg, elem))
        })
    };
    if len < MIN_PAR_LEN {
        out.chunks_exact_mut(stride)
            .enumerate()
            .try_for_each(process)?;
    } else {
        out.par_chunks_exact_mut(stride)
            .enumerate()
            .with_min_len(MIN_PAR_LEN)
            .try_for_each(process)?;
    }
    Ok(())
}

/// Calls `f` for each element of `values` together with its index, using multiple threads if
/// there are enough elements.
pub(super) fn for_each_indexed<T: Send>(values: &mut [T], f: impl Fn(usize, &mut T) + Sync) {
    if values.len() < MIN_PAR_LEN {
        values.iter_mut().enumerate().for_each(|(i, v)| f(i, v));
    } else {
        values
            .par_iter_mut()
            .enumerate()
            .with_min_len(MIN_PAR_LEN)
            .for_each(|(i, v)| f(i, v));
    }
}

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
        self.send(to, Bytes::from(ser_data))?;
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

    /// Send and receive data to and from all parties.
    #[inline(always)]
    fn broadcast<F: CanonicalSerialize + CanonicalDeserialize + Clone + Send>(
        &self,

        num_parties: usize,
        data: F,
    ) -> eyre::Result<Vec<F>> {
        // Serialize
        let size = data.serialized_size(ark_serialize::Compress::No);
        let mut ser_data = Vec::with_capacity(size);
        data.serialize_uncompressed(&mut ser_data)?;

        // Send (convert once; `clone` on `Bytes` is a refcount bump, not a copy)
        let ser_data = Bytes::from(ser_data);
        for other_id in 0..num_parties {
            if other_id != self.id() {
                self.send(other_id, ser_data.clone())?;
            }
        }

        // Receive
        let mut res = Vec::with_capacity(num_parties);
        for other_id in 0..num_parties {
            if other_id != self.id() {
                let data = self.recv(other_id)?;
                let deser = F::deserialize_uncompressed_unchecked(&data[..])?;
                res.push(deser);
            } else {
                res.push(data.to_owned());
            }
        }

        Ok(res)
    }

    /// Send and receive a vector of data to and from all parties.
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
        data.serialize_uncompressed(&mut ser_data)?;

        // Send (convert once; `clone` on `Bytes` is a refcount bump, not a copy)
        let ser_data = Bytes::from(ser_data);
        for s in 1..num {
            let other_id = (self.id() + s) % num_parties;
            self.send(other_id, ser_data.clone())?;
        }

        // Receive
        let mut res = Vec::with_capacity(num);
        res.push(data);
        for r in 1..num {
            let other_id = (self.id() + num_parties - r) % num_parties;
            let data = self.recv(other_id)?;
            let deser = F::deserialize_uncompressed_unchecked(&data[..])?;
            res.push(deser);
        }

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
        inputs: Vec<F>,
    ) -> eyre::Result<Vec<ShamirPrimeFieldShare<F>>>
    where
        Self: Sized,
    {
        let num_non_zero = state.num_parties - state.threshold;

        let len = inputs.len();
        let (mut my_shares, r_2ts) = state.get_pairs(self, len)?;

        // my_shares holds r_t at this point, which is subtracted from the fresh shares
        let my_id = self.id();
        if my_id == KING_ID {
            // Accumulate the result, starting with my own share
            let mut acc = inputs;
            let lagrange = &state.mul_lagrange_2t;
            for_each_indexed(&mut acc, |i, acc| {
                *acc = (*acc + r_2ts[i]) * lagrange[KING_ID]
            });
            drop(r_2ts);
            debug_assert_eq!(lagrange.len(), 2 * state.threshold + 1);
            let received = (1..lagrange.len())
                .map(|other_id| self.recv(other_id))
                .collect::<eyre::Result<Vec<_>>>()?;
            for_each_received(&received, &mut acc, 1, |acc, msg, mul: F| {
                acc[0] += mul * lagrange[msg + 1]
            })?;
            drop(received);
            // So far parties who do not require sending, do not send, so no receive here

            // Send fresh shares
            // Since <acc> does not have to be private, we share it as a known polynomial, such that t parties know their share is 0. Consequently we can reduce the amount of communication.
            // The polynomial is acc times a fixed polynomial, thus each share is acc times a precomputed coefficient.
            // Note: When expanding the n-t double shares to n double shares (Atlas) we cannot do this anymore, since <acc> needs to stay private. Atlas also requires rotating the King server.
            for (id, coeff) in state.mul_king_share_coeffs.iter().enumerate() {
                debug_assert!(id < num_non_zero);
                if id != KING_ID {
                    let data = serialize_field_elements(len, |i| acc[i] * coeff)?;
                    self.send(id, data)?;
                }
            }
            let coeff = state.mul_king_share_coeffs[KING_ID];
            for_each_indexed(&mut my_shares, |i, share| *share = acc[i] * coeff - *share);
        } else {
            if my_id <= state.threshold * 2 {
                // Only send if my items are required
                let data = serialize_field_elements(len, |i| inputs[i] + r_2ts[i])?;
                self.send(KING_ID, data)?;
            }
            drop((inputs, r_2ts));
            if my_id < num_non_zero {
                let data = self.recv(KING_ID)?;
                for_each_received(&[data], &mut my_shares, 1, |share, _, fresh: F| {
                    share[0] = fresh - share[0]
                })?;
            } else {
                for_each_indexed(&mut my_shares, |_, share| *share = -*share);
            }
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
            // Note: When expanding the n-t double shares to n double shares (Atlas) we cannot do this anymore, since <acc> needs to stay private. Atlas also requires rotating the King server.

            // The polynomial is acc times a fixed polynomial, thus each share is acc times a precomputed coefficient.
            let mut my_share = C::default();
            for (id, coeff) in state.mul_king_share_coeffs.iter().enumerate() {
                debug_assert!(id < num_non_zero);
                let val = acc * coeff;
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
