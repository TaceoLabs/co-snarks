//! Local MPC network

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use crossbeam_channel::{Receiver, Sender};
use eyre::ContextCompat;
use intmap::IntMap;
use std::{sync::atomic::AtomicUsize, time::Duration};

use crate::{ConnectionStats, DEFAULT_CONNECTION_TIMEOUT, Network};

/// A MPC network using channels. Used for testing.
#[derive(Debug)]
pub struct LocalNetwork {
    id: usize,
    timeout: std::time::Duration,
    send: IntMap<usize, (Sender<Vec<u8>>, AtomicUsize)>,
    recv: IntMap<usize, (Receiver<Vec<u8>>, AtomicUsize)>,
}

impl LocalNetwork {
    /// Create new [LocalNetwork]s for `num_parties`.
    pub fn new(num_parties: usize) -> Vec<Self> {
        Self::new_with_timeout(num_parties, DEFAULT_CONNECTION_TIMEOUT)
    }

    /// Create new [LocalNetwork]s for `num_parties`, setting a timeout.
    pub fn new_with_timeout(num_parties: usize, timeout: Duration) -> Vec<Self> {
        let mut networks = Vec::with_capacity(num_parties);
        let mut senders = Vec::new();
        let mut receivers = Vec::new();

        for _ in 0..num_parties {
            senders.push(IntMap::new());
            receivers.push(IntMap::new());
        }

        #[allow(clippy::needless_range_loop)]
        for i in 0..num_parties {
            for j in 0..num_parties {
                if i != j {
                    let (tx, rx) = crossbeam_channel::bounded(32);
                    senders[i].insert(j, (tx, AtomicUsize::default()));
                    receivers[j].insert(i, (rx, AtomicUsize::default()));
                }
            }
        }

        for (id, (send, recv)) in senders.into_iter().zip(receivers).enumerate() {
            networks.push(LocalNetwork {
                id,
                timeout,
                send,
                recv,
            });
        }

        networks
    }

    /// Create new [LocalNetwork]s for 3 parties.
    pub fn new_3_parties() -> [Self; 3] {
        Self::new(3).try_into().expect("correct len")
    }
}

impl Network for LocalNetwork {
    fn id(&self) -> usize {
        self.id
    }

    fn send<T: CanonicalSerialize>(&self, to: usize, data: &T) -> eyre::Result<()> {
        let (sender, sent_bytes) = self.send.get(to).context("party id out-of-bounds")?;
        let size = data.serialized_size(ark_serialize::Compress::No);
        let mut buf = Vec::with_capacity(size);
        data.serialize_uncompressed(&mut buf)?;
        sent_bytes.fetch_add(size, std::sync::atomic::Ordering::Relaxed);
        sender.send_timeout(buf, self.timeout)?;
        Ok(())
    }

    fn recv<T: CanonicalDeserialize>(&self, from: usize) -> eyre::Result<T> {
        let (receiver, recv_bytes) = self.recv.get(from).context("party id out-of-bounds")?;
        let buf = receiver.recv_timeout(self.timeout)?;
        let data = T::deserialize_uncompressed(buf.as_slice())?;
        recv_bytes.fetch_add(buf.len(), std::sync::atomic::Ordering::Relaxed);
        Ok(data)
    }

    fn get_connection_stats(&self) -> ConnectionStats {
        let mut stats = std::collections::BTreeMap::new();
        for (id, (_, sent_bytes)) in self.send.iter() {
            let recv_bytes = &self.recv.get(id).expect("was in send so must be in recv").1;
            stats.insert(
                id,
                (
                    sent_bytes.load(std::sync::atomic::Ordering::Relaxed),
                    recv_bytes.load(std::sync::atomic::Ordering::Relaxed),
                ),
            );
        }
        ConnectionStats {
            my_id: self.id,
            stats,
        }
    }
}
