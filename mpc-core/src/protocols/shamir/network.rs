//! Shamir Network
//!
//! This module contains the trait for specifying a network interface for the Shamir MPC protocol. It also contains an implementation of the trait using the [mpc_net] crate.

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use itertools::izip;
use mpc_engine::Network;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use super::{ShamirPointShare, ShamirPrimeFieldShare, ShamirProtocol};

/// Sends data to the target party. This function has a default implementation for calling [ShamirNetwork::send_many].
pub fn send<N: Network, F: CanonicalSerialize>(net: &N, to: usize, data: F) -> eyre::Result<()> {
    send_many(net, to, &[data])
}

/// Sends a vector of data to the target party.
pub fn send_many<N: Network, F: CanonicalSerialize>(
    net: &N,
    to: usize,
    data: &[F],
) -> eyre::Result<()> {
    let size = data.serialized_size(ark_serialize::Compress::No);
    let mut ser_data = Vec::with_capacity(size);
    data.serialize_uncompressed(&mut ser_data)?;
    net.send(to, &ser_data).unwrap();
    Ok(())
}

/// Receives data from the party with the given id.
pub fn recv<N: Network, F: CanonicalDeserialize>(net: &N, from: usize) -> eyre::Result<F> {
    let mut res = recv_many(net, from)?;
    if res.len() != 1 {
        eyre::bail!("Expected 1 element, got more",)
    } else {
        Ok(res.pop().unwrap())
    }
}

/// Receives a vector of data from the party with the given id.
pub fn recv_many<N: Network, F: CanonicalDeserialize>(
    net: &N,
    from: usize,
) -> eyre::Result<Vec<F>> {
    let data = net.recv(from)?;

    let res = Vec::<F>::deserialize_uncompressed_unchecked(&data[..])?;

    Ok(res)
}

pub fn broadcast<N: Network, F: CanonicalSerialize + CanonicalDeserialize + Clone + Send>(
    net: &N,
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
            if other_id != net.id() {
                net.send(other_id, &ser_data)?;
            }
            // Receive
            if other_id != net.id() {
                let data = net.recv(other_id)?;
                eyre::Ok(F::deserialize_uncompressed_unchecked(&data[..])?)
            } else {
                eyre::Ok(data.to_owned())
            }
        })
        .collect::<eyre::Result<Vec<_>>>()
}

pub fn broadcast_next<N: Network, F: CanonicalSerialize + CanonicalDeserialize + Clone + Send>(
    net: &N,
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
            let other_id = (net.id() + i) % num_parties;
            net.send(other_id, &ser_data)?;
            // Receive
            let other_id = (net.id() + num_parties - i) % num_parties;
            let data = net.recv(other_id)?;
            eyre::Ok(F::deserialize_uncompressed_unchecked(&data[..])?)
        })
        .collect::<eyre::Result<Vec<_>>>()?;

    res.extend(remaining);

    Ok(res)
}

const KING_ID: usize = 0;

pub fn degree_reduce<N: Network, F: PrimeField>(
    net: &N,
    state: &mut ShamirProtocol<F>,
    input: F,
) -> eyre::Result<ShamirPrimeFieldShare<F>> {
    let mut res = degree_reduce_many(net, state, vec![input])?;
    if res.len() != 1 {
        eyre::bail!("Expected 1 element, got more",)
    } else {
        //we checked that there is really one element
        Ok(res.pop().unwrap())
    }
}

// TODO use rayon
pub fn degree_reduce_many<N: Network, F: PrimeField>(
    net: &N,
    state: &mut ShamirProtocol<F>,
    mut inputs: Vec<F>,
) -> eyre::Result<Vec<ShamirPrimeFieldShare<F>>> {
    let num_non_zero = state.num_parties - state.threshold;

    let len = inputs.len();
    let mut r_ts = Vec::with_capacity(len);

    for inp in inputs.iter_mut() {
        let (r_t, r_2t) = state.get_pair(net)?;
        *inp += r_2t;
        r_ts.push(r_t);
    }

    let my_id = net.id();
    let mut my_shares = if my_id == KING_ID {
        // Accumulate the result
        let mut acc = vec![F::zero(); len];
        for (other_id, lagrange) in state.mul_lagrange_2t.iter().enumerate() {
            if other_id == KING_ID {
                for (acc, muls) in izip!(&mut acc, &inputs) {
                    *acc += *muls * lagrange;
                }
            } else {
                let r = recv_many::<_, F>(net, other_id)?;
                if r.len() != len {
                    eyre::bail!("During execution of degree_reduce_vec in MPC: Invalid number of elements received");
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
            let poly = super::core::poly_with_zeros_from_precomputed(
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
                .map(|poly| super::core::evaluate_poly(poly, id_f))
                .collect::<Vec<_>>();
            if id == my_id {
                my_share = vals;
            } else {
                send_many(net, id, &vals)?;
            }
        }
        my_share
    } else {
        if my_id <= state.threshold * 2 {
            // Only send if my items are required
            send_many(net, KING_ID, &inputs)?;
        }
        if my_id < num_non_zero {
            let r = recv_many::<_, F>(net, KING_ID)?;
            if r.len() != len {
                eyre::bail!("During execution of degree_reduce_vec in MPC: Invalid number of elements received");
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

// TODO use rayon
pub fn degree_reduce_point<N: Network, C, F: PrimeField>(
    net: &N,
    state: &mut ShamirProtocol<F>,
    mut input: C,
) -> eyre::Result<ShamirPointShare<C>>
where
    C: CurveGroup + std::ops::Mul<F, Output = C> + for<'a> std::ops::Mul<&'a F, Output = C>,
{
    let num_non_zero = state.num_parties - state.threshold;

    let (r_t, r_2t) = state.get_pair(net)?;
    let r_t = C::generator().mul(r_t);
    let r_2t = C::generator().mul(r_2t);

    input += r_2t;
    let my_id = net.id();

    let my_share = if my_id == KING_ID {
        // Accumulate the result
        let mut acc = C::zero();
        for (other_id, lagrange) in state.mul_lagrange_2t.iter().enumerate() {
            if other_id == KING_ID {
                acc += input * lagrange;
            } else {
                let r = recv::<_, C>(net, other_id)?;
                acc += r * lagrange;
            }
        }
        // So far parties who do not require sending, do not send, so no receive here

        // Send fresh shares
        // Since <acc> does not have to be private, we share it as a known polynomial, such that t parties know their share is 0. Consequently we can reduce the amount of communication.
        // Note: When expanding t+1 double shares to n double shares (Atlas) we cannot do this anymore, since <acc> needs to stay private. Atlas also requires rotating the King server.

        let poly = super::core::poly_with_zeros_from_precomputed_point(
            &acc,
            &state.mul_reconstruct_with_zeros,
        );

        let mut my_share = C::default();
        for id in 0..num_non_zero {
            let val = super::core::evaluate_poly_point(&poly, C::ScalarField::from(id as u64 + 1));
            if id == my_id {
                my_share = val;
            } else {
                send(net, id, val)?;
            }
        }

        my_share
    } else {
        if my_id <= state.threshold * 2 {
            // Only send if my items are required
            send(net, KING_ID, input)?;
        }
        if my_id < num_non_zero {
            recv(net, KING_ID)?
        } else {
            C::default()
        }
    };

    Ok(ShamirPointShare::new(my_share - r_t))
}

/// Send and recv `to` and `from` party
pub fn send_and_recv<N: Network, F: CanonicalSerialize + CanonicalDeserialize + Send>(
    net: &N,
    to: usize,
    data: F,
    from: usize,
) -> eyre::Result<F> {
    let mut res = send_and_recv_many(net, to, &[data], from)?;
    if res.len() != 1 {
        eyre::bail!("Expected 1 element, got more",)
    } else {
        //we checked that there is really one element
        Ok(res.pop().unwrap())
    }
}

/// Send and recv `to` and `from` party
pub fn send_and_recv_many<N: Network, F: CanonicalSerialize + CanonicalDeserialize + Send>(
    net: &N,
    to: usize,
    data: &[F],
    from: usize,
) -> eyre::Result<Vec<F>> {
    send_many(net, to, data)?;
    recv_many(net, from)
}
