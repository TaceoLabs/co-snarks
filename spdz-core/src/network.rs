// SPDZ Network Extension — convenience methods for 2-party communication.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use mpc_net::Network;

/// Extension trait adding SPDZ-specific convenience methods to [`Network`].
pub trait SpdzNetworkExt: Network {
    /// The ID of the other party (there are only 2).
    fn other_id(&self) -> usize {
        1 - self.id()
    }

    /// Send a single serializable value to the other party.
    fn send_to_other<F: CanonicalSerialize>(&self, data: F) -> eyre::Result<()> {
        self.send_many_to_other(&[data])
    }

    /// Send a slice of serializable values to the other party.
    fn send_many_to_other<F: CanonicalSerialize>(&self, data: &[F]) -> eyre::Result<()> {
        let size = data.serialized_size(ark_serialize::Compress::No);
        let mut ser_data = Vec::with_capacity(size);
        data.serialize_uncompressed(&mut ser_data)?;
        self.send(self.other_id(), &ser_data)?;
        Ok(())
    }

    /// Receive a single value from the other party.
    fn recv_from_other<F: CanonicalDeserialize>(&self) -> eyre::Result<F> {
        let mut res: Vec<F> = self.recv_many_from_other()?;
        if res.len() != 1 {
            eyre::bail!("Expected 1 element, got {}", res.len())
        }
        Ok(res.pop().unwrap())
    }

    /// Receive a vector of values from the other party.
    fn recv_many_from_other<F: CanonicalDeserialize>(&self) -> eyre::Result<Vec<F>> {
        let data = self.recv(self.other_id())?;
        let res = Vec::<F>::deserialize_uncompressed_unchecked(&data[..])?;
        Ok(res)
    }

    /// Exchange a single value: send ours, receive theirs.
    ///
    /// Party 0 sends first, party 1 sends first — the network layer
    /// handles the ordering, but to avoid deadlocks both parties must
    /// call this simultaneously.
    fn exchange<F: CanonicalSerialize + CanonicalDeserialize + Send>(
        &self,
        data: F,
    ) -> eyre::Result<F> {
        count_round_trip();
        if self.id() == 0 {
            self.send_to_other(data)?;
            self.recv_from_other()
        } else {
            let received = self.recv_from_other()?;
            self.send_to_other(data)?;
            Ok(received)
        }
    }

    /// Exchange vectors: send ours, receive theirs.
    fn exchange_many<F: CanonicalSerialize + CanonicalDeserialize + Send>(
        &self,
        data: &[F],
    ) -> eyre::Result<Vec<F>> {
        count_round_trip();
        if self.id() == 0 {
            self.send_many_to_other(data)?;
            self.recv_many_from_other()
        } else {
            let received = self.recv_many_from_other()?;
            self.send_many_to_other(data)?;
            Ok(received)
        }
    }
}

/// Blanket implementation for anything implementing `Network`.
impl<N: Network> SpdzNetworkExt for N {}

/// Global counter for network round trips (for profiling).
pub static ROUND_TRIP_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Increment the round trip counter.
pub fn count_round_trip() {
    ROUND_TRIP_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Get and reset the round trip counter.
pub fn get_and_reset_round_trips() -> usize {
    ROUND_TRIP_COUNT.swap(0, std::sync::atomic::Ordering::Relaxed)
}
