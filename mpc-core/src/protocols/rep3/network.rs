//! Rep3 Network
//!
//! This module contains the networking functionality for the Rep3 MPC protocol.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bytes::Bytes;
use mpc_net::Network;

use super::id::PartyID;
use crate::protocols::wire::{self, WireFormat};

/// A extension trait that REP3 specific methods to [`Network`].
///
/// The `_raw` methods (e.g. [`reshare_many_raw`](Rep3NetworkExt::reshare_many_raw),
/// [`send_next_many_raw`](Rep3NetworkExt::send_next_many_raw),
/// [`recv_prev_many_raw`](Rep3NetworkExt::recv_prev_many_raw)) and the
/// ark-format methods (e.g. [`reshare_many`](Rep3NetworkExt::reshare_many))
/// use two incompatible wire formats: a logical message sent with a `_raw`
/// method must be received with a `_raw` method, and one sent with an
/// ark-format method must be received with an ark-format method. Keep all
/// legs of one exchange co-located in the same function so they flip
/// together under refactors, rather than letting one leg's format drift out
/// of sync with the others.
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
        // Post BOTH sends before blocking on either receive. Each party emits all
        // of its outgoing data up front, so no party can be parked on a `recv`
        // before its peers have sent — which is exactly what previously forced
        // the two send/recv pairs onto separate threads (`mpc_net::join`) to avoid
        // a deadlock in the 3-party ring. This mirrors `shamir::network`'s
        // `broadcast`/`broadcast_next`, which already use this ordering.
        //
        // Safe for arbitrarily large frames on the current transports: the peer's
        // background reader thread drains the socket independently of its main
        // thread's phase, so the sends here cannot deadlock against a peer that
        // is itself still in its send phase.
        self.send_both_many(data)?;
        let prev_res = self.recv_many(prev_id)?;
        let next_res = self.recv_many(next_id)?;
        Ok((prev_res, next_res))
    }

    /// Sends the same data to the other two parties, serializing it only once.
    #[inline(always)]
    fn send_both_many<F: CanonicalSerialize>(&self, data: &[F]) -> eyre::Result<()> {
        let id = PartyID::try_from(self.id())?;
        let size = data.serialized_size(ark_serialize::Compress::No);
        let mut ser_data = Vec::with_capacity(size);
        data.serialize_uncompressed(&mut ser_data)?;
        // `clone` on `Bytes` is a refcount bump, not a copy
        let ser_data = Bytes::from(ser_data);
        self.send(id.prev().into(), ser_data.clone())?;
        self.send(id.next().into(), ser_data)?;
        Ok(())
    }

    /// Sends a slice of elements to the target party in the raw wire format
    /// (see [`wire`]). The receiving side must use
    /// [`recv_many_raw`](Self::recv_many_raw), never the ark-format methods.
    #[inline(always)]
    fn send_many_raw<F: WireFormat>(&self, to: PartyID, data: &[F]) -> eyre::Result<()> {
        self.send(to.into(), wire::to_bytes(data))
    }

    /// Sends a slice of elements to the next party in the raw wire format.
    #[inline(always)]
    fn send_next_many_raw<F: WireFormat>(&self, data: &[F]) -> eyre::Result<()> {
        let id = PartyID::try_from(self.id())?;
        self.send_many_raw(id.next(), data)
    }

    /// Receives a vector of elements in the raw wire format (see [`wire`])
    /// from the party with the given id. The sending side must use
    /// [`send_many_raw`](Self::send_many_raw), never the ark-format methods.
    #[inline(always)]
    fn recv_many_raw<F: WireFormat>(&self, from: PartyID) -> eyre::Result<Vec<F>> {
        wire::from_bytes(self.recv(from.into())?)
    }

    /// Receives a vector of elements in the raw wire format from the previous
    /// party.
    #[inline(always)]
    fn recv_prev_many_raw<F: WireFormat>(&self) -> eyre::Result<Vec<F>> {
        let id = PartyID::try_from(self.id())?;
        self.recv_many_raw(id.prev())
    }

    /// Performs multiple reshares with one networking round in the raw wire
    /// format: sends `data` to the next party and receives from the previous.
    #[inline(always)]
    fn reshare_many_raw<F: WireFormat>(&self, data: &[F]) -> eyre::Result<Vec<F>> {
        let id = PartyID::try_from(self.id())?;
        self.send_many_raw(id.next(), data)?;
        self.recv_many_raw(id.prev())
    }

    /// Broadcasts a slice of elements to the other two parties and receives
    /// theirs, in the raw wire format. Serializes once; see
    /// [`broadcast_many`](Self::broadcast_many) for the send/receive ordering
    /// rationale.
    #[inline(always)]
    fn broadcast_many_raw<F: WireFormat>(&self, data: &[F]) -> eyre::Result<(Vec<F>, Vec<F>)> {
        let id = PartyID::try_from(self.id())?;
        let ser_data = wire::to_bytes(data);
        // `clone` on `Bytes` is a refcount bump, not a copy
        self.send(id.prev().into(), ser_data.clone())?;
        self.send(id.next().into(), ser_data)?;
        let prev_res = self.recv_many_raw(id.prev())?;
        let next_res = self.recv_many_raw(id.next())?;
        Ok((prev_res, next_res))
    }

    /// Sends to `to` and receives from `from`, in the raw wire format.
    #[inline(always)]
    fn send_and_recv_many_raw<F: WireFormat>(
        &self,
        to: PartyID,
        data: &[F],
        from: PartyID,
    ) -> eyre::Result<Vec<F>> {
        self.send_many_raw(to, data)?;
        self.recv_many_raw(from)
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
        self.send(to.into(), Bytes::from(ser_data))?;
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
