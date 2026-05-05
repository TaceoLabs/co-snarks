//! Rep3 Network
//!
//! This module contains the networking functionality for the Rep3 MPC protocol.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress};
use mpc_net::Network;

use super::id::PartyID;

/// Size in bytes of the `Vec<F>` length prefix in `ark_serialize`'s uncompressed encoding (a `u64`).
const LEN_PREFIX_BYTES: usize = 8;

/// A extension trait that REP3 specific methods to [`Network`].
pub trait Rep3NetworkExt: Network {
    /// Sends `data` to the next party and receives from the previous party.
    ///
    /// Specialized for a single element: maintains the same `Vec<F>(1)` wire format as
    /// `reshare_many(&[data])` (so peers using `recv_many` / `recv_prev` are unaffected), but
    /// skips the recv-side `Vec<F>` allocation by reading past the 8-byte length prefix and
    /// deserializing directly into `F`.
    #[inline(always)]
    fn reshare<F: CanonicalSerialize + CanonicalDeserialize + Send>(
        &self,
        data: F,
    ) -> eyre::Result<F> {
        let id = PartyID::try_from(self.id())?;
        let elem_size = data.serialized_size(Compress::No);
        let mut ser_data = Vec::with_capacity(LEN_PREFIX_BYTES + elem_size);
        1u64.serialize_uncompressed(&mut ser_data)?;
        data.serialize_uncompressed(&mut ser_data)?;
        self.send(id.next().into(), &ser_data)?;
        let recv = self.recv(id.prev().into())?;
        if recv.len() < LEN_PREFIX_BYTES {
            eyre::bail!("reshare: recv payload too short");
        }
        let res = F::deserialize_uncompressed_unchecked(&recv[LEN_PREFIX_BYTES..])?;
        Ok(res)
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

    /// Broadcast data to the other two parties and receive data from them.
    ///
    /// Specialized for a single element. Maintains the same `Vec<F>(1)` wire format as
    /// `broadcast_many(&[data])` (so peers using `recv_many` / `recv_prev` / `recv_next` are
    /// unaffected). Compared to the default path this:
    ///   * avoids the per-call thread spawn from `mpc_net::join` — both sends are issued before
    ///     either recv, which is safe because small payloads always fit in any reasonable
    ///     send buffer;
    ///   * avoids two `Vec<F>` allocations on the recv side by reading past the 8-byte length
    ///     prefix and deserializing directly into `F`.
    /// On hot paths like the Poseidon2 additive precomp sbox (one broadcast per internal round)
    /// the thread spawn was the dominant cost.
    #[inline(always)]
    fn broadcast<F: CanonicalSerialize + CanonicalDeserialize + Send>(
        &self,
        data: F,
    ) -> eyre::Result<(F, F)> {
        let id = PartyID::try_from(self.id())?;
        let next_id = id.next();
        let prev_id = id.prev();

        let elem_size = data.serialized_size(Compress::No);
        let mut ser = Vec::with_capacity(LEN_PREFIX_BYTES + elem_size);
        1u64.serialize_uncompressed(&mut ser)?;
        data.serialize_uncompressed(&mut ser)?;

        // Issue both sends before either recv. The bounded crossbeam channels (and OS socket
        // buffers for real networks) hold these small payloads without blocking before the peers
        // post their recvs.
        self.send(next_id.into(), &ser)?;
        self.send(prev_id.into(), &ser)?;

        let prev_raw = self.recv(prev_id.into())?;
        let next_raw = self.recv(next_id.into())?;
        if prev_raw.len() < LEN_PREFIX_BYTES || next_raw.len() < LEN_PREFIX_BYTES {
            eyre::bail!("broadcast: recv payload too short");
        }
        let prev = F::deserialize_uncompressed_unchecked(&prev_raw[LEN_PREFIX_BYTES..])?;
        let next = F::deserialize_uncompressed_unchecked(&next_raw[LEN_PREFIX_BYTES..])?;
        Ok((prev, next))
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
        let (prev_res, next_res) = mpc_net::join(
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
