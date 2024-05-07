use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bytes::{Bytes, BytesMut};
use eyre::{bail, eyre, Report};
use mpc_net::{channel::ChannelHandle, config::NetworkConfig, MpcNetworkHandler};

use super::id::PartyID;

pub trait Aby3Network {
    fn get_id(&self) -> PartyID;
    fn send_and_receive_seed(&mut self, seed: Bytes) -> std::io::Result<BytesMut>;

    fn send<F: CanonicalSerialize>(&mut self, target: PartyID, data: F) -> std::io::Result<()> {
        self.send_many(target, &[data])
    }
    fn send_many<F: CanonicalSerialize>(
        &mut self,
        target: PartyID,
        data: &[F],
    ) -> std::io::Result<()>;
    fn send_next<F: CanonicalSerialize>(&mut self, data: F) -> std::io::Result<()> {
        self.send(self.get_id().next_id(), data)
    }
    fn send_next_many<F: CanonicalSerialize>(&mut self, data: &[F]) -> std::io::Result<()> {
        self.send_many(self.get_id().next_id(), data)
    }

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
    fn recv_many<F: CanonicalDeserialize>(&mut self, from: PartyID) -> std::io::Result<Vec<F>>;
    fn recv_prev<F: CanonicalDeserialize>(&mut self) -> std::io::Result<F> {
        self.recv(self.get_id().prev_id())
    }
    fn recv_prev_many<F: CanonicalDeserialize>(&mut self) -> std::io::Result<Vec<F>> {
        self.recv_many(self.get_id().prev_id())
    }
}

pub struct Aby3MpcNet {
    id: PartyID,
    runtime: tokio::runtime::Runtime,
    net_handler: MpcNetworkHandler,
    chan_next: ChannelHandle<Bytes, BytesMut>,
    chan_prev: ChannelHandle<Bytes, BytesMut>,
}

impl Aby3MpcNet {
    pub fn new(config: NetworkConfig) -> Result<Self, Report> {
        if config.parties.len() != 3 {
            bail!("ABY3 protocol requires exactly 3 parties")
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

impl Aby3Network for Aby3MpcNet {
    fn get_id(&self) -> PartyID {
        self.id
    }

    fn send_and_receive_seed(&mut self, seed: Bytes) -> std::io::Result<BytesMut> {
        self.send_bytes(self.id.next_id(), seed)?;
        self.recv_bytes(self.id.prev_id())
    }

    fn send_many<F: CanonicalSerialize>(
        &mut self,
        target: PartyID,
        data: &[F],
    ) -> std::io::Result<()> {
        let size = data.serialized_size(ark_serialize::Compress::No);
        let mut ser_data = vec![0u8; size];
        data.serialize_uncompressed(&mut ser_data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        if target == self.id.next_id() {
            std::mem::drop(self.chan_next.blocking_send(Bytes::from(ser_data)));
            Ok(())
        } else if target == self.id.prev_id() {
            std::mem::drop(self.chan_prev.blocking_send(Bytes::from(ser_data)));
            Ok(())
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Cannot send to self",
            ));
        }
    }

    fn recv_many<F: CanonicalDeserialize>(&mut self, from: PartyID) -> std::io::Result<Vec<F>> {
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

        let res = Vec::<F>::deserialize_uncompressed(&data[..])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        Ok(res)
    }
}
