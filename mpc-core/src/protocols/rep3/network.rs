use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bytes::{Bytes, BytesMut};
use eyre::{bail, eyre, Report};
use mpc_net::{channel::ChannelHandle, config::NetworkConfig, MpcNetworkHandler};

use super::id::PartyID;

/// This trait defines the network interface for the REP3 protocol.
pub trait Rep3Network {
    /// Returns the id of the party. The id is in the range 0 <= id < 3
    fn get_id(&self) -> PartyID;

    /// Sends data to the target party. This function has a default implementation for calling [Rep3Network::send_many].
    fn send<F: CanonicalSerialize>(&mut self, target: PartyID, data: F) -> std::io::Result<()> {
        self.send_many(target, &[data])
    }

    /// Sends a vector of data to the target party.
    fn send_many<F: CanonicalSerialize>(
        &mut self,
        target: PartyID,
        data: &[F],
    ) -> std::io::Result<()>;

    /// Sends data to the party with id = next_id (i.e., my_id + 1 mod 3). This function has a default implementation for calling [Rep3Network::send] with the next_id.
    fn send_next<F: CanonicalSerialize>(&mut self, data: F) -> std::io::Result<()> {
        self.send(self.get_id().next_id(), data)
    }

    /// Sends a vector data to the party with id = next_id (i.e., my_id + 1 mod 3). This function has a default implementation for calling [Rep3Network::send_many] with the next_id.
    fn send_next_many<F: CanonicalSerialize>(&mut self, data: &[F]) -> std::io::Result<()> {
        self.send_many(self.get_id().next_id(), data)
    }

    /// Receives data from the party with the given id. This function has a default implementation for calling [Rep3Network::recv_many] and checking for the correct length of 1.
    fn recv<F: CanonicalDeserialize>(&mut self, from: PartyID) -> std::io::Result<F> {
        let mut res = self.recv_many(from)?;
        if res.len() != 1 {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Expected 1 element, got more",
            ))
        } else {
            Ok(res.pop().unwrap())
        }
    }

    /// Receives a vector of data from the party with the given id.
    fn recv_many<F: CanonicalDeserialize>(&mut self, from: PartyID) -> std::io::Result<Vec<F>>;

    /// Receives data from the party with the id = prev_id (i.e., my_id + 2 mod 3). This function has a default implementation for calling [Rep3Network::recv] with the prev_id.
    fn recv_prev<F: CanonicalDeserialize>(&mut self) -> std::io::Result<F> {
        self.recv(self.get_id().prev_id())
    }

    /// Receives a vector of data from the party with the id = prev_id (i.e., my_id + 2 mod 3). This function has a default implementation for calling [Rep3Network::recv_many] with the prev_id.
    fn recv_prev_many<F: CanonicalDeserialize>(&mut self) -> std::io::Result<Vec<F>> {
        self.recv_many(self.get_id().prev_id())
    }
}

/// This struct can be used to facilitate network communication for the REP3 MPC protocol.
#[derive(Debug)]
pub struct Rep3MpcNet {
    pub(crate) id: PartyID,
    pub(crate) runtime: tokio::runtime::Runtime,
    pub(crate) net_handler: MpcNetworkHandler,
    pub(crate) chan_next: ChannelHandle<Bytes, BytesMut>,
    pub(crate) chan_prev: ChannelHandle<Bytes, BytesMut>,
}

impl Rep3MpcNet {
    /// Takes a [NetworkConfig] struct and constructs the network interface. The network needs to contain exactly 3 parties with ids 0, 1, and 2.
    pub fn new(config: NetworkConfig) -> Result<Self, Report> {
        if config.parties.len() != 3 {
            bail!("REP3 protocol requires exactly 3 parties")
        }
        let id = PartyID::try_from(config.my_id)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let (net_handler, chan_next, chan_prev) = runtime.block_on(async {
            let mut net_handler = MpcNetworkHandler::establish(config).await?;
            let mut channels = net_handler.get_byte_channels().await?;
            let chan_next = channels
                .remove(&id.next_id().into())
                .ok_or(eyre!("no next channel found"))?;
            let chan_prev = channels
                .remove(&id.prev_id().into())
                .ok_or(eyre!("no prev channel found"))?;
            if !channels.is_empty() {
                bail!("unexpected channels found")
            }

            let chan_next = ChannelHandle::manage(chan_next);
            let chan_prev = ChannelHandle::manage(chan_prev);
            Ok((net_handler, chan_next, chan_prev))
        })?;
        Ok(Self {
            id,
            runtime,
            net_handler,
            chan_next,
            chan_prev,
        })
    }

    /// Shuts down the network interface.
    pub fn shutdown(self) {
        let Self {
            id: _,
            runtime,
            net_handler,
            chan_next,
            chan_prev,
        } = self;
        drop(chan_next);
        drop(chan_prev);
        runtime.block_on(async {
            net_handler.shutdown().await;
        });
    }

    /// Sends bytes over the network to the target party.
    pub fn send_bytes(&mut self, target: PartyID, data: Bytes) -> std::io::Result<()> {
        if target == self.id.next_id() {
            std::mem::drop(self.chan_next.blocking_send(data));
            Ok(())
        } else if target == self.id.prev_id() {
            std::mem::drop(self.chan_prev.blocking_send(data));
            Ok(())
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Cannot send to self",
            ));
        }
    }

    /// Receives bytes over the network from the party with the given id.
    pub fn recv_bytes(&mut self, from: PartyID) -> std::io::Result<BytesMut> {
        let data = if from == self.id.prev_id() {
            self.chan_prev.blocking_recv().blocking_recv()
        } else if from == self.id.next_id() {
            self.chan_next.blocking_recv().blocking_recv()
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Cannot recv from self",
            ));
        };
        let data = data.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "receive channel end died")
        })??;
        Ok(data)
    }
    pub(crate) fn _id(&self) -> PartyID {
        self.id
    }
}

impl Rep3Network for Rep3MpcNet {
    fn get_id(&self) -> PartyID {
        self.id
    }

    fn send_many<F: CanonicalSerialize>(
        &mut self,
        target: PartyID,
        data: &[F],
    ) -> std::io::Result<()> {
        let size = data.serialized_size(ark_serialize::Compress::No);
        let mut ser_data = Vec::with_capacity(size);
        data.serialize_uncompressed(&mut ser_data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        self.send_bytes(target, Bytes::from(ser_data))
    }

    fn recv_many<F: CanonicalDeserialize>(&mut self, from: PartyID) -> std::io::Result<Vec<F>> {
        let data = self.recv_bytes(from)?;

        let res = Vec::<F>::deserialize_uncompressed(&data[..])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        Ok(res)
    }
}
