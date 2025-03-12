//! Rep3 Network
//!
//! This module contains implementation of the rep3 mpc network

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use mpc_engine::Network;

use super::Rep3PartyId;

/// Sends `data` to the next party and receives from the previous party. Use this whenever
/// possible in contrast to calling [`Self::send_next()`] and [`Self::recv_prev()`] sequential. This method
/// executes send/receive concurrently.
pub fn reshare<N: Network + Send + Sync, F: CanonicalSerialize + CanonicalDeserialize + Send>(
    net: &N,
    data: F,
) -> eyre::Result<F> {
    let mut res = reshare_many(net, &[data])?;
    if res.len() != 1 {
        eyre::bail!("Expected 1 element, got more",)
    } else {
        //we checked that there is really one element
        Ok(res.pop().unwrap())
    }
}

/// Perform multiple reshares with one networking round
pub fn reshare_many<N: Network + Sync, F: CanonicalSerialize + CanonicalDeserialize + Send>(
    net: &N,
    data: &[F],
) -> eyre::Result<Vec<F>> {
    let id = net.id();
    send_and_recv_many(net, id.next(), data, id.prev())
}

/// Broadcast data to the other two parties and receive data from them
pub fn broadcast<N: Network + Sync, F: CanonicalSerialize + CanonicalDeserialize + Send>(
    net: &N,
    data: F,
) -> eyre::Result<(F, F)> {
    let (mut prev, mut next) = broadcast_many(net, &[data])?;
    if prev.len() != 1 || next.len() != 1 {
        eyre::bail!("Expected 1 element, got more",)
    } else {
        //we checked that there is really one element
        let prev = prev.pop().unwrap();
        let next = next.pop().unwrap();
        Ok((prev, next))
    }
}

/// Broadcast data to the other two parties and receive data from them
pub fn broadcast_many<N: Network + Sync, F: CanonicalSerialize + CanonicalDeserialize + Send>(
    net: &N,
    data: &[F],
) -> eyre::Result<(Vec<F>, Vec<F>)> {
    let id = net.id();
    let next_id = id.next();
    let prev_id = id.prev();

    debug_assert!(rayon::current_num_threads() >= 4);

    let (prev_res, next_res) = rayon::join(
        || send_and_recv_many(net, prev_id, data, prev_id),
        || send_and_recv_many(net, next_id, data, next_id),
    );

    Ok((prev_res?, next_res?))
}

/// Sends data to the target party. This function has a default implementation for calling [Rep3Network::send_many].
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

/// Sends data to the party with id = next_id (i.e., my_id + 1 mod 3). This function has a default implementation for calling [Rep3Network::send] with the next_id.
pub fn send_next<N: Network, F: CanonicalSerialize>(net: &N, data: F) -> eyre::Result<()> {
    send(net, net.id().next(), data)
}

/// Sends a vector data to the party with id = next_id (i.e., my_id + 1 mod 3). This function has a default implementation for calling [Rep3Network::send_many] with the next_id.
pub fn send_next_many<N: Network, F: CanonicalSerialize>(net: &N, data: &[F]) -> eyre::Result<()> {
    send_many(net, net.id().next(), data)
}

/// Receives data from the party with the given id. This function has a default implementation for calling [Rep3Network::recv_many] and checking for the correct length of 1.
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

/// Receives data from the party with the id = prev_id (i.e., my_id + 2 mod 3). This function has a default implementation for calling [Rep3Network::recv] with the prev_id.
pub fn recv_prev<N: Network, F: CanonicalDeserialize>(net: &N) -> eyre::Result<F> {
    recv(net, net.id().prev())
}

/// Receives a vector of data from the party with the id = prev_id (i.e., my_id + 2 mod 3). This function has a default implementation for calling [Rep3Network::recv_many] with the prev_id.
pub fn recv_prev_many<N: Network, F: CanonicalDeserialize>(net: &N) -> eyre::Result<Vec<F>> {
    recv_many(net, net.id().prev())
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
    let (send, recv) = rayon::join(|| send_many(net, to, data), || recv_many(net, from));
    send?;
    recv
}
