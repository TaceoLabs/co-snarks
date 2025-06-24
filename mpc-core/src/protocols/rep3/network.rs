//! Rep3 Network
//!
//! This module contains the networking functionality for the Rep3 MPC protocol.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use mpc_net::Network;
use mpc_types::protocols::rep3::id::PartyID;

/// Sends `data` to the next party and receives from the previous party.
pub fn reshare<N: Network, F: CanonicalSerialize + CanonicalDeserialize + Send>(
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
pub fn reshare_many<N: Network, F: CanonicalSerialize + CanonicalDeserialize + Send>(
    net: &N,
    data: &[F],
) -> eyre::Result<Vec<F>> {
    let id = PartyID::try_from(net.id())?;
    send_and_recv_many(net, id.next(), data, id.prev())
}

/// Broadcast data to the other two parties and receive data from them
pub fn broadcast<N: Network, F: CanonicalSerialize + CanonicalDeserialize + Send>(
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
pub fn broadcast_many<N: Network, F: CanonicalSerialize + CanonicalDeserialize + Send>(
    net: &N,
    data: &[F],
) -> eyre::Result<(Vec<F>, Vec<F>)> {
    let id = PartyID::try_from(net.id())?;
    let next_id = id.next();
    let prev_id = id.prev();

    debug_assert!(rayon::current_num_threads() >= 4);

    let (prev_res, next_res) = rayon::join(
        || send_and_recv_many(net, prev_id, data, prev_id),
        || send_and_recv_many(net, next_id, data, next_id),
    );

    Ok((prev_res?, next_res?))
}

/// Sends data to the target party.
pub fn send<N: Network, F: CanonicalSerialize>(net: &N, to: PartyID, data: F) -> eyre::Result<()> {
    send_many(net, to, &[data])
}

/// Sends a vector of data to the target party.
pub fn send_many<N: Network, F: CanonicalSerialize>(
    net: &N,
    to: PartyID,
    data: &[F],
) -> eyre::Result<()> {
    let size = data.serialized_size(ark_serialize::Compress::No);
    let mut ser_data = Vec::with_capacity(size);
    data.serialize_uncompressed(&mut ser_data)?;
    net.send(to.into(), &ser_data).unwrap();
    Ok(())
}

/// Sends data to the party with id = next_id (i.e., my_id + 1 mod 3).
pub fn send_next<N: Network, F: CanonicalSerialize>(net: &N, data: F) -> eyre::Result<()> {
    let id = PartyID::try_from(net.id())?;
    send(net, id.next(), data)
}

/// Sends a vector data to the party with id = next_id (i.e., my_id + 1 mod 3).
pub fn send_next_many<N: Network, F: CanonicalSerialize>(net: &N, data: &[F]) -> eyre::Result<()> {
    let id = PartyID::try_from(net.id())?;
    send_many(net, id.next(), data)
}

/// Receives data from the party with the given id
pub fn recv<N: Network, F: CanonicalDeserialize>(net: &N, from: PartyID) -> eyre::Result<F> {
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
    from: PartyID,
) -> eyre::Result<Vec<F>> {
    let data = net.recv(from.into())?;
    let res = Vec::<F>::deserialize_uncompressed_unchecked(&data[..])?;
    Ok(res)
}

/// Receives data from the party with the id = prev_id (i.e., my_id + 2 mod 3)
pub fn recv_prev<N: Network, F: CanonicalDeserialize>(net: &N) -> eyre::Result<F> {
    let id = PartyID::try_from(net.id())?;
    recv(net, id.prev())
}

/// Receives a vector of data from the party with the id = prev_id (i.e., my_id + 2 mod 3).
pub fn recv_prev_many<N: Network, F: CanonicalDeserialize>(net: &N) -> eyre::Result<Vec<F>> {
    let id = PartyID::try_from(net.id())?;
    recv_many(net, id.prev())
}

/// Send and recv `to` and `from` party
pub fn send_and_recv<N: Network, F: CanonicalSerialize + CanonicalDeserialize + Send>(
    net: &N,
    to: PartyID,
    data: F,
    from: PartyID,
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
    to: PartyID,
    data: &[F],
    from: PartyID,
) -> eyre::Result<Vec<F>> {
    send_many(net, to, data)?;
    recv_many(net, from)
}
