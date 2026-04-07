//! MPI based MPC net

use std::{
    collections::HashMap,
    sync::{Arc, atomic::AtomicUsize},
};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use eyre::ContextCompat as _;
use mpi::{
    Threading,
    environment::Universe,
    topology::SimpleCommunicator,
    traits::{Communicator as _, Destination as _, Source},
};

use crate::{ConnectionStats, Network};

/// A MPC network using MPI
pub struct MpiNetwork {
    rank: usize,
    universe: Arc<Universe>,
    world: SimpleCommunicator,
    sent_bytes: HashMap<usize, AtomicUsize>,
    recv_bytes: HashMap<usize, AtomicUsize>,
}

// SAFETY: MPI is initialized with Threading::Multiple, which guarantees it is
// safe to call MPI routines from any thread. The raw pointer inside
// SimpleCommunicator is effectively a stable handle managed by the MPI runtime.
unsafe impl Send for MpiNetwork {}
unsafe impl Sync for MpiNetwork {}

impl MpiNetwork {
    /// Create a new `MpiNetwork`.
    pub fn new() -> eyre::Result<Self> {
        let (universe, _) = mpi::initialize_with_threading(Threading::Multiple).unwrap();
        let world = universe.world();
        let rank = world.rank();
        let size = world.size();
        let mut sent_bytes = HashMap::new();
        let mut recv_bytes = HashMap::new();
        for id in 0..size {
            if id != rank {
                sent_bytes.insert(id as usize, AtomicUsize::default());
                recv_bytes.insert(id as usize, AtomicUsize::default());
            }
        }
        Ok(Self {
            rank: rank as usize,
            universe: Arc::new(universe),
            world,
            sent_bytes,
            recv_bytes,
        })
    }

    /// Create `N` new `MpiNetwork`s.
    pub fn networks<const N: usize>() -> eyre::Result<[Self; N]> {
        let network = Self::new()?;
        let networks = std::array::from_fn(|_| {
            let world = network.world.duplicate();
            Self {
                rank: world.rank() as usize,
                universe: network.universe.clone(),
                world,
                sent_bytes: network
                    .sent_bytes
                    .keys()
                    .copied()
                    .map(|id| (id, AtomicUsize::default()))
                    .collect(),
                recv_bytes: network
                    .recv_bytes
                    .keys()
                    .copied()
                    .map(|id| (id, AtomicUsize::default()))
                    .collect(),
            }
        });
        Ok(networks)
    }
}

impl Network for MpiNetwork {
    fn id(&self) -> usize {
        self.rank
    }

    fn send<T: CanonicalSerialize>(&self, to: usize, data: &T) -> eyre::Result<()> {
        let mut buf = Vec::new();
        data.serialize_uncompressed(&mut buf)?;
        self.world.process_at_rank(to as i32).send(&buf);
        self.sent_bytes
            .get(&to)
            .context("party id out-of-bounds")?
            .fetch_add(buf.len(), std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    fn recv<T: CanonicalDeserialize>(&self, from: usize) -> eyre::Result<T> {
        let (buf, _) = self.world.process_at_rank(from as i32).receive_vec();
        let data = T::deserialize_uncompressed(buf.as_slice())?;
        self.recv_bytes
            .get(&from)
            .context("party id out-of-bounds")?
            .fetch_add(buf.len(), std::sync::atomic::Ordering::Relaxed);
        Ok(data)
    }

    fn get_connection_stats(&self) -> ConnectionStats {
        let mut stats = std::collections::BTreeMap::new();
        for (id, sent_bytes) in &self.sent_bytes {
            let recv_bytes = self
                .recv_bytes
                .get(id)
                .expect("was in sent_bytes so must be in recv_bytes");
            stats.insert(
                *id,
                (
                    sent_bytes.load(std::sync::atomic::Ordering::Relaxed),
                    recv_bytes.load(std::sync::atomic::Ordering::Relaxed),
                ),
            );
        }
        ConnectionStats::new(self.rank, stats)
    }
}
