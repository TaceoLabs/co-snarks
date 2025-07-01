//! Test MPC network

use crossbeam_channel::{Receiver, Sender};
use eyre::ContextCompat;
use intmap::IntMap;

use crate::{DEFAULT_CONNECTION_TIMEOUT, Network};

/// A MPC network using channels. Used for testing.
#[derive(Debug)]
pub struct TestNetwork {
    id: usize,
    send: IntMap<usize, Sender<Vec<u8>>>,
    recv: IntMap<usize, Receiver<Vec<u8>>>,
}

impl TestNetwork {
    /// Create new [TestNetwork]s for `num_parties`.
    pub fn new(num_parties: usize) -> Vec<Self> {
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
                    senders[i].insert(j, tx);
                    receivers[j].insert(i, rx);
                }
            }
        }

        for (id, (send, recv)) in senders.into_iter().zip(receivers).enumerate() {
            networks.push(TestNetwork { id, send, recv });
        }

        networks
    }

    /// Create new [TestNetwork]s for 3 parties.
    pub fn new_3_parties() -> [Self; 3] {
        Self::new(3).try_into().expect("correct len")
    }
}

impl Network for TestNetwork {
    fn id(&self) -> usize {
        self.id
    }

    fn send(&self, to: usize, data: &[u8]) -> eyre::Result<()> {
        self.send
            .get(to)
            .context("party id out-of-bounds")?
            .send_timeout(data.to_owned(), DEFAULT_CONNECTION_TIMEOUT)?;
        Ok(())
    }

    fn recv(&self, from: usize) -> eyre::Result<Vec<u8>> {
        Ok(self
            .recv
            .get(from)
            .context("party id out-of-bounds")?
            .recv_timeout(DEFAULT_CONNECTION_TIMEOUT)?)
    }
}
