//! Rep3 Network
//!
//! This module contains implementation of the rep3 mpc network

use std::sync::Arc;

use crate::{IoResult, RngType};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bytes::{Bytes, BytesMut};
use eyre::{bail, eyre, Report};
use mpc_net::{
    channel::ChannelHandle, config::NetworkConfig, MpcNetworkHandler, MpcNetworkHandlerWrapper,
};

use super::{
    conversion::A2BType,
    rngs::{Rep3CorrelatedRng, Rep3Rand, Rep3RandBitComp},
    PartyID,
};
use rand::{distributions::Standard, prelude::Distribution, CryptoRng, Rng, SeedableRng};

// this will be moved later
/// This struct handles networking and rng
pub struct IoContext<N: Rep3Network> {
    /// The party id
    pub id: PartyID,
    /// The correlated rng
    pub rngs: Rep3CorrelatedRng,
    /// The underlying unique rng used for, e.g., Yao
    pub rng: RngType,
    /// The underlying network
    pub network: N,
    /// The used arithmetic/binary conversion protocol
    pub a2b_type: A2BType,
}

impl<N: Rep3Network> IoContext<N> {
    fn setup_prf<R: Rng + CryptoRng>(network: &mut N, rng: &mut R) -> IoResult<Rep3Rand> {
        let seed1: [u8; crate::SEED_SIZE] = rng.gen();
        network.send_next(seed1)?;
        let seed2: [u8; crate::SEED_SIZE] = network.recv_prev()?;

        Ok(Rep3Rand::new(seed1, seed2))
    }

    fn setup_bitcomp(
        network: &mut N,
        rands: &mut Rep3Rand,
    ) -> IoResult<(Rep3RandBitComp, Rep3RandBitComp)> {
        let (k1a, k1c) = rands.random_seeds();
        let (k2a, k2c) = rands.random_seeds();

        match network.get_id() {
            PartyID::ID0 => {
                network.send_next(k1c)?;
                let k2b: [u8; crate::SEED_SIZE] = network.recv_prev()?;
                let bitcomp1 = Rep3RandBitComp::new_2keys(k1a, k1c);
                let bitcomp2 = Rep3RandBitComp::new_3keys(k2a, k2b, k2c);
                Ok((bitcomp1, bitcomp2))
            }
            PartyID::ID1 => {
                network.send_next((k1c, k2c))?;
                let k1b: [u8; crate::SEED_SIZE] = network.recv_prev()?;
                let bitcomp1 = Rep3RandBitComp::new_3keys(k1a, k1b, k1c);
                let bitcomp2 = Rep3RandBitComp::new_2keys(k2a, k2c);
                Ok((bitcomp1, bitcomp2))
            }
            PartyID::ID2 => {
                network.send_next(k2c)?;
                let (k1b, k2b): ([u8; crate::SEED_SIZE], [u8; crate::SEED_SIZE]) =
                    network.recv_prev()?;
                let bitcomp1 = Rep3RandBitComp::new_3keys(k1a, k1b, k1c);
                let bitcomp2 = Rep3RandBitComp::new_3keys(k2a, k2b, k2c);
                Ok((bitcomp1, bitcomp2))
            }
        }
    }

    /// Construct  a new [`IoContext`] with the given network
    pub fn init(mut network: N) -> IoResult<Self> {
        let mut rng = RngType::from_entropy();
        let mut rand = Self::setup_prf(&mut network, &mut rng)?;
        let bitcomps = Self::setup_bitcomp(&mut network, &mut rand)?;
        let rngs = Rep3CorrelatedRng::new(rand, bitcomps.0, bitcomps.1);

        Ok(Self {
            id: network.get_id(), //shorthand access
            network,
            rngs,
            rng,
            a2b_type: A2BType::default(),
        })
    }

    /// Allows to change the used arithmetic/binary conversion protocol
    pub fn set_a2b_type(&mut self, a2b_type: A2BType) {
        self.a2b_type = a2b_type;
    }

    /// Cronstruct a fork of the [`IoContext`]. This fork can be used concurrently with its parent.
    pub fn fork(&mut self) -> IoResult<Self> {
        let network = self.network.fork()?;
        let rngs = self.rngs.fork();
        let rng = RngType::from_seed(self.rng.gen());
        let id = self.id;
        let a2b_type = self.a2b_type;

        Ok(Self {
            id,
            rngs,
            network,
            rng,
            a2b_type,
        })
    }

    /// Generate two random elements
    pub fn random_elements<T>(&mut self) -> (T, T)
    where
        Standard: Distribution<T>,
    {
        self.rngs.rand.random_elements()
    }

    /// Generate two random field elements
    pub fn random_fes<F: PrimeField>(&mut self) -> (F, F) {
        self.rngs.rand.random_fes()
    }

    /// Generate a masking field element
    pub fn masking_field_element<F: PrimeField>(&mut self) -> F {
        let (a, b) = self.random_fes::<F>();
        a - b
    }
}

/// This trait defines the network interface for the REP3 protocol.
pub trait Rep3Network: Send {
    /// Returns the id of the party. The id is in the range 0 <= id < 3
    fn get_id(&self) -> PartyID;

    /// Sends `data` to the next party and receives from the previous party. Use this whenever
    /// possible in contrast to calling [`Self::send_next()`] and [`Self::recv_prev()`] sequential. This method
    /// executes send/receive concurrently.
    fn reshare<F: CanonicalSerialize + CanonicalDeserialize>(
        &mut self,
        data: F,
    ) -> std::io::Result<F> {
        let mut res = self.reshare_many(&[data])?;
        if res.len() != 1 {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Expected 1 element, got more",
            ))
        } else {
            //we checked that there is really one element
            Ok(res.pop().unwrap())
        }
    }

    /// Perform multiple reshares with one networking round
    fn reshare_many<F: CanonicalSerialize + CanonicalDeserialize>(
        &mut self,
        data: &[F],
    ) -> std::io::Result<Vec<F>>;

    /// Broadcast data to the other two parties and receive data from them
    fn broadcast<F: CanonicalSerialize + CanonicalDeserialize>(
        &mut self,
        data: F,
    ) -> std::io::Result<(F, F)> {
        let (mut prev, mut next) = self.broadcast_many(&[data])?;
        if prev.len() != 1 || next.len() != 1 {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Expected 1 element, got more",
            ))
        } else {
            //we checked that there is really one element
            let prev = prev.pop().unwrap();
            let next = next.pop().unwrap();
            Ok((prev, next))
        }
    }

    /// Broadcast data to the other two parties and receive data from them
    fn broadcast_many<F: CanonicalSerialize + CanonicalDeserialize>(
        &mut self,
        data: &[F],
    ) -> std::io::Result<(Vec<F>, Vec<F>)>;

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

    /// Fork the network into two separate instances with their own connections
    fn fork(&mut self) -> std::io::Result<Self>
    where
        Self: Sized;
}

// TODO make generic over codec?
/// This struct can be used to facilitate network communication for the REP3 MPC protocol.
#[derive(Debug)]
pub struct Rep3MpcNet {
    pub(crate) id: PartyID,
    pub(crate) chan_next: ChannelHandle<Bytes, BytesMut>,
    pub(crate) chan_prev: ChannelHandle<Bytes, BytesMut>,
    /// I don't care
    pub net_handler: Arc<MpcNetworkHandlerWrapper>,
}

impl Rep3MpcNet {
    /// Takes a [NetworkConfig] struct and constructs the network interface. The network needs to contain exactly 3 parties with ids 0, 1, and 2.
    pub fn new(config: NetworkConfig) -> Result<Self, Report> {
        if config.parties.len() != 3 {
            bail!("REP3 protocol requires exactly 3 parties")
        }
        let id = PartyID::try_from(config.my_id)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let (net_handler, chan_next, chan_prev) = runtime.block_on(async {
            let net_handler = MpcNetworkHandler::establish(config).await?;
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
            net_handler: Arc::new(MpcNetworkHandlerWrapper::new(runtime, net_handler)),
            chan_next,
            chan_prev,
        })
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
}

impl Rep3Network for Rep3MpcNet {
    fn get_id(&self) -> PartyID {
        self.id
    }

    fn reshare_many<F: CanonicalSerialize + CanonicalDeserialize>(
        &mut self,
        data: &[F],
    ) -> std::io::Result<Vec<F>> {
        self.send_many(self.id.next_id(), data)?;
        self.recv_many(self.id.prev_id())
    }

    fn broadcast_many<F: CanonicalSerialize + CanonicalDeserialize>(
        &mut self,
        data: &[F],
    ) -> std::io::Result<(Vec<F>, Vec<F>)> {
        self.send_many(self.id.next_id(), data)?;
        self.send_many(self.id.prev_id(), data)?;
        let recv_next = self.recv_many(self.id.next_id())?;
        let recv_prev = self.recv_many(self.id.prev_id())?;
        Ok((recv_prev, recv_next))
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

        let res = Vec::<F>::deserialize_uncompressed_unchecked(&data[..])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        Ok(res)
    }

    fn fork(&mut self) -> std::io::Result<Self> {
        let id = self.id;
        let net_handler = Arc::clone(&self.net_handler);
        let (chan_next, chan_prev) = net_handler.runtime.block_on(async {
            let mut channels = net_handler.inner.get_byte_channels().await?;

            let chan_next = channels
                .remove(&id.next_id().into())
                .expect("to find next channel");
            let chan_prev = channels
                .remove(&id.prev_id().into())
                .expect("to find prev channel");
            if !channels.is_empty() {
                panic!("unexpected channels found")
            }

            let chan_next = ChannelHandle::manage(chan_next);
            let chan_prev = ChannelHandle::manage(chan_prev);
            Ok::<_, std::io::Error>((chan_next, chan_prev))
        })?;

        Ok(Self {
            id,
            net_handler,
            chan_next,
            chan_prev,
        })
    }
}
