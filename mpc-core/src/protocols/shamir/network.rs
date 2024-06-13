use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bytes::{Bytes, BytesMut};
use eyre::{bail, eyre, Report};
use mpc_net::{channel::ChannelHandle, config::NetworkConfig, MpcNetworkHandler};
use std::collections::HashMap;

pub trait ShamirNetwork {
    fn get_id(&self) -> usize;
    fn get_num_parties(&self) -> usize;

    fn send<F: CanonicalSerialize>(&mut self, target: usize, data: F) -> std::io::Result<()> {
        self.send_many(target, &[data])
    }
    fn send_many<F: CanonicalSerialize>(
        &mut self,
        target: usize,
        data: &[F],
    ) -> std::io::Result<()>;

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
    fn recv_many<F: CanonicalDeserialize>(&mut self, from: usize) -> std::io::Result<Vec<F>>;

    fn broadcast<F: CanonicalSerialize + CanonicalDeserialize + Clone>(
        &mut self,
        data: F,
    ) -> std::io::Result<Vec<F>>;

    // sends data to the next num parties and receives from the previous num
    fn broadcast_next<F: CanonicalSerialize + CanonicalDeserialize + Clone>(
        &mut self,
        data: F,
        num: usize,
    ) -> std::io::Result<Vec<F>>;
}

pub struct ShamirMpcNet {
    id: usize, // 0 <= id < num_parties
    num_parties: usize,
    runtime: tokio::runtime::Runtime,
    net_handler: MpcNetworkHandler,
    channels: HashMap<usize, ChannelHandle<Bytes, BytesMut>>,
}

impl ShamirMpcNet {
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
                let data = self.recv(other_id)?;
                res.push(data);
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
        for s in 1..=num {
            let other_id = (self.id + s) % self.num_parties;
            if other_id != self.id {
                self.send_bytes(other_id, send_data.to_owned())?;
            }
        }

        // Receive
        let mut res = Vec::with_capacity(num);
        for r in 1..=num {
            let other_id = (self.id + self.num_parties - r) % self.num_parties;
            if other_id != self.id {
                let data = self.recv(other_id)?;
                res.push(data);
            } else {
                res.push(data.to_owned());
            }
        }

        Ok(res)
    }
}
