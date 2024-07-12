//! Shamir Network
//!
//! This module contains the trait for specifying a network interface for the Shamir MPC protocol. It also contains an implementation of the trait using the [mpc_net] crate.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bytes::{Bytes, BytesMut};
use eyre::{bail, eyre, Report};
use mpc_net::{channel::ChannelHandle, config::NetworkConfig, MpcNetworkHandler};
use std::collections::HashMap;

/// This trait defines the network interface for the Shamir protocol.
pub trait ShamirNetwork {
    /// Returns the id of the party. The id is in the range 0 <= id < num_parties
    fn get_id(&self) -> usize;

    /// Returns the number of parties participating in the MPC protocol.
    fn get_num_parties(&self) -> usize;

    /// Sends data to the target party. This function has a default implementation for calling [ShamirNetwork::send_many].
    fn send<F: CanonicalSerialize>(&mut self, target: usize, data: F) -> std::io::Result<()> {
        self.send_many(target, &[data])
    }

    /// Sends a vector of data to the target party.
    fn send_many<F: CanonicalSerialize>(
        &mut self,
        target: usize,
        data: &[F],
    ) -> std::io::Result<()>;

    /// Receives data from the party with the given id. This function has a default implementation for calling [ShamirNetwork::recv_many] and checking for the correct length of 1.
    fn recv<F: CanonicalDeserialize>(&mut self, from: usize) -> std::io::Result<F> {
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
    fn recv_many<F: CanonicalDeserialize>(&mut self, from: usize) -> std::io::Result<Vec<F>>;

    /// Sends data to all parties and receives data from all other parties. The result is a vector where the data from party i is at index i, including my own data.
    fn broadcast<F: CanonicalSerialize + CanonicalDeserialize + Clone>(
        &mut self,
        data: F,
    ) -> std::io::Result<Vec<F>>;

    /// Sends data to the next num - 1 parties and receives from the previous num -1 parties. Thus, the result is a vector of length num, where the data from party my_id + num_partes - i mod num_parties is at index i, including my own data.
    fn broadcast_next<F: CanonicalSerialize + CanonicalDeserialize + Clone>(
        &mut self,
        data: F,
        num: usize,
    ) -> std::io::Result<Vec<F>>;
}

/// This struct can be used to facilitate network communication for the Shamir MPC protocol.
pub struct ShamirMpcNet {
    pub(crate) id: usize, // 0 <= id < num_parties
    pub(crate) num_parties: usize,
    pub(crate) runtime: tokio::runtime::Runtime,
    pub(crate) net_handler: MpcNetworkHandler,
    pub(crate) channels: HashMap<usize, ChannelHandle<Bytes, BytesMut>>,
}

impl ShamirMpcNet {
    /// Takes a [NetworkConfig] struct and constructs the network interface. The network needs to contain at least 3 parties and all ids need to be in the range of 0 <= id < num_parties.
    pub fn new(config: NetworkConfig) -> Result<Self, Report> {
        let num_parties = config.parties.len();

        if config.parties.len() <= 2 {
            bail!("Shamir protocol requires at least 3 parties")
        }
        let id = config.my_id;
        if id >= num_parties {
            bail!("Invalid party id={} for {} parties", id, num_parties)
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(num_parties - 1)
            .enable_all()
            .build()?;
        let (net_handler, channels) = runtime.block_on(async {
            let mut net_handler = MpcNetworkHandler::establish(config).await?;
            let mut channels = net_handler.get_byte_channels().await?;

            let mut channels_ = HashMap::with_capacity(num_parties - 1);

            for other_id in 0..num_parties {
                if other_id != id {
                    let chan = channels
                        .remove(&other_id)
                        .ok_or_else(|| eyre!("no channel found for party id={}", other_id))?;
                    channels_.insert(other_id, ChannelHandle::manage(chan));
                }
            }

            if !channels.is_empty() {
                bail!("unexpected channels found")
            }

            Ok((net_handler, channels_))
        })?;
        Ok(Self {
            id,
            num_parties,
            runtime,
            net_handler,
            channels,
        })
    }

    /// Shuts down the network interface.
    pub fn shutdown(self) {
        let Self {
            id: _,
            num_parties: _,
            runtime,
            net_handler,
            channels,
        } = self;
        for chan in channels.into_iter() {
            drop(chan);
        }
        runtime.block_on(async {
            net_handler.shutdown().await;
        });
    }

    /// Sends bytes over the network to the target party.
    pub fn send_bytes(&mut self, target: usize, data: Bytes) -> std::io::Result<()> {
        if let Some(chan) = self.channels.get_mut(&target) {
            std::mem::drop(chan.blocking_send(data));
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("No channel found for party id={}", target),
            ))
        }
    }

    /// Receives bytes over the network from the party with the given id.
    pub fn recv_bytes(&mut self, from: usize) -> std::io::Result<BytesMut> {
        let data = if let Some(chan) = self.channels.get_mut(&from) {
            chan.blocking_recv().blocking_recv()
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("No channel found for party id={}", from),
            ));
        };

        let data = data.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "receive channel end died")
        })??;
        Ok(data)
    }

    pub(crate) fn _id(&self) -> usize {
        self.id
    }
}

impl ShamirNetwork for ShamirMpcNet {
    fn get_id(&self) -> usize {
        self.id
    }

    fn get_num_parties(&self) -> usize {
        self.num_parties
    }

    fn send_many<F: CanonicalSerialize>(
        &mut self,
        target: usize,
        data: &[F],
    ) -> std::io::Result<()> {
        let size = data.serialized_size(ark_serialize::Compress::No);
        let mut ser_data = Vec::with_capacity(size);
        data.serialize_uncompressed(&mut ser_data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        self.send_bytes(target, Bytes::from(ser_data))
    }

    fn recv_many<F: CanonicalDeserialize>(&mut self, from: usize) -> std::io::Result<Vec<F>> {
        let data = self.recv_bytes(from)?;

        let res = Vec::<F>::deserialize_uncompressed(&data[..])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        Ok(res)
    }

    fn broadcast<F: CanonicalSerialize + CanonicalDeserialize + Clone>(
        &mut self,
        data: F,
    ) -> std::io::Result<Vec<F>> {
        // Serialize
        let size = data.serialized_size(ark_serialize::Compress::No);
        let mut ser_data = Vec::with_capacity(size);
        data.to_owned()
            .serialize_uncompressed(&mut ser_data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let send_data = Bytes::from(ser_data);

        // Send
        for other_id in 0..self.num_parties {
            if other_id != self.id {
                self.send_bytes(other_id, send_data.to_owned())?;
            }
        }

        // Receive
        let mut res = Vec::with_capacity(self.num_parties);
        for other_id in 0..self.num_parties {
            if other_id != self.id {
                let data = self.recv_bytes(other_id)?;
                let deser = F::deserialize_uncompressed(&data[..])
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                res.push(deser);
            } else {
                res.push(data.to_owned());
            }
        }

        Ok(res)
    }

    fn broadcast_next<F: CanonicalSerialize + CanonicalDeserialize + Clone>(
        &mut self,
        data: F,
        num: usize,
    ) -> std::io::Result<Vec<F>> {
        // Serialize
        let size = data.serialized_size(ark_serialize::Compress::No);
        let mut ser_data = Vec::with_capacity(size);
        data.to_owned()
            .serialize_uncompressed(&mut ser_data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let send_data = Bytes::from(ser_data);

        // Send
        for s in 1..num {
            let other_id = (self.id + s) % self.num_parties;
            // if other_id != self.id {
            self.send_bytes(other_id, send_data.to_owned())?;
            // }
        }

        // Receive
        let mut res = Vec::with_capacity(num);
        res.push(data);
        for r in 1..num {
            let other_id = (self.id + self.num_parties - r) % self.num_parties;
            let data = self.recv_bytes(other_id)?;
            let deser = F::deserialize_uncompressed(&data[..])
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            res.push(deser);
        }

        Ok(res)
    }
}
