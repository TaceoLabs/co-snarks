//! Rep3 Network
//!
//! This module contains the networking functionality for the Rep3 MPC protocol.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use mpc_net::Network;

use super::id::PartyID;

/// A extension trait that REP3 specific methods to [`Network`].
pub trait Rep3NetworkExt: Network {
    /// Sends `data` to the next party and receives from the previous party.
    #[inline(always)]
    fn reshare<F: CanonicalSerialize + CanonicalDeserialize + Send>(
        &self,
        data: F,
    ) -> eyre::Result<F> {
        let mut res = self.reshare_many(&[data])?;
        if res.len() != 1 {
            eyre::bail!("Expected 1 element, got more",)
        } else {
            //we checked that there is really one element
            Ok(res.pop().unwrap())
        }
    }

    /// Perform multiple reshares with one networking round
    #[inline(always)]
    fn reshare_many<F: CanonicalSerialize + CanonicalDeserialize + Send>(
        &self,
        data: &[F],
    ) -> eyre::Result<Vec<F>> {
        let id = PartyID::try_from(self.id())?;
        self.send_and_recv_many(id.next(), data, id.prev())
    }

    /// Broadcast data to the other two parties and receive data from them
    #[inline(always)]
    fn broadcast<F: CanonicalSerialize + CanonicalDeserialize + Send>(
        &self,
        data: F,
    ) -> eyre::Result<(F, F)> {
        let (mut prev, mut next) = self.broadcast_many(&[data])?;
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
    #[inline(always)]
    fn broadcast_many<F: CanonicalSerialize + CanonicalDeserialize + Send>(
        &self,
        data: &[F],
    ) -> eyre::Result<(Vec<F>, Vec<F>)> {
        let id = PartyID::try_from(self.id())?;
        let next_id = id.next();
        let prev_id = id.prev();

        debug_assert!(rayon::current_num_threads() >= 4);

        let (prev_res, next_res) = rayon::join(
            || self.send_and_recv_many(prev_id, data, prev_id),
            || self.send_and_recv_many(next_id, data, next_id),
        );

        Ok((prev_res?, next_res?))
    }

    /// Sends data to the target party.
    #[inline(always)]
    fn send_to<F: CanonicalSerialize>(&self, to: PartyID, data: F) -> eyre::Result<()> {
        self.send_many(to, &[data])
    }

    /// Sends a vector of data to the target party.
    #[inline(always)]
    fn send_many<F: CanonicalSerialize>(&self, to: PartyID, data: &[F]) -> eyre::Result<()> {
        let size = data.serialized_size(ark_serialize::Compress::No);
        let mut ser_data = Vec::with_capacity(size);
        data.serialize_uncompressed(&mut ser_data)?;
        self.send(to.into(), &ser_data)?;
        Ok(())
    }

    /// Sends data to the party with id = next_id (i.e., my_id + 1 mod 3).
    #[inline(always)]
    fn send_next<F: CanonicalSerialize>(&self, data: F) -> eyre::Result<()> {
        let id = PartyID::try_from(self.id())?;
        self.send_to(id.next(), data)
    }

    /// Sends a vector data to the party with id = next_id (i.e., my_id + 1 mod 3).
    #[inline(always)]
    fn send_next_many<F: CanonicalSerialize>(&self, data: &[F]) -> eyre::Result<()> {
        let id = PartyID::try_from(self.id())?;
        self.send_many(id.next(), data)
    }

    /// Sends data to the party with id = prev_id (i.e., my_id + 2 mod 3).
    #[inline(always)]
    fn send_prev<F: CanonicalSerialize>(&self, data: F) -> eyre::Result<()> {
        let id = PartyID::try_from(self.id())?;
        self.send_to(id.prev(), data)
    }

    /// Sends a vector data to the party with id = prev_id (i.e., my_id + 2 mod 3).
    #[inline(always)]
    fn send_prev_many<F: CanonicalSerialize>(&self, data: &[F]) -> eyre::Result<()> {
        let id = PartyID::try_from(self.id())?;
        self.send_many(id.prev(), data)
    }

    /// Receives data from the party with the given id
    #[inline(always)]
    fn recv_from<F: CanonicalDeserialize>(&self, from: PartyID) -> eyre::Result<F> {
        let mut res = self.recv_many(from)?;
        if res.len() != 1 {
            eyre::bail!("Expected 1 element, got more",)
        } else {
            Ok(res.pop().unwrap())
        }
    }

    /// Receives a vector of data from the party with the given id.
    #[inline(always)]
    fn recv_many<F: CanonicalDeserialize>(&self, from: PartyID) -> eyre::Result<Vec<F>> {
        let data = self.recv(from.into())?;
        let res = Vec::<F>::deserialize_uncompressed_unchecked(&data[..])?;
        Ok(res)
    }

    /// Receives data from the party with the id = next_id (i.e., my_id + 1 mod 3)
    #[inline(always)]
    fn recv_next<F: CanonicalDeserialize>(&self) -> eyre::Result<F> {
        let id = PartyID::try_from(self.id())?;
        self.recv_from(id.next())
    }

    /// Receives a vector of data from the party with the id = next_id (i.e., my_id + 1 mod 3).
    #[inline(always)]
    fn recv_next_many<F: CanonicalDeserialize>(&self) -> eyre::Result<Vec<F>> {
        let id = PartyID::try_from(self.id())?;
        self.recv_many(id.next())
    }

    /// Receives data from the party with the id = prev_id (i.e., my_id + 2 mod 3)
    #[inline(always)]
    fn recv_prev<F: CanonicalDeserialize>(&self) -> eyre::Result<F> {
        let id = PartyID::try_from(self.id())?;
        self.recv_from(id.prev())
    }

    /// Receives a vector of data from the party with the id = prev_id (i.e., my_id + 2 mod 3).
    #[inline(always)]
    fn recv_prev_many<F: CanonicalDeserialize>(&self) -> eyre::Result<Vec<F>> {
        let id = PartyID::try_from(self.id())?;
        self.recv_many(id.prev())
    }

    /// Send and recv `to` and `from` party
    #[inline(always)]
    fn send_and_recv<F: CanonicalSerialize + CanonicalDeserialize + Send>(
        &self,
        to: PartyID,
        data: F,
        from: PartyID,
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
        to: PartyID,
        data: &[F],
        from: PartyID,
    ) -> eyre::Result<Vec<F>> {
        self.send_many(to, data)?;
        self.recv_many(from)
    }
}

impl<N: Network> Rep3NetworkExt for N {}
