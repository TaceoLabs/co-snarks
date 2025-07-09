//! A simple networking layer for MPC protocols.
#![warn(missing_docs)]
use std::{
    collections::{BTreeMap, HashMap},
    time::Duration,
};

pub mod config;
#[cfg(feature = "local")]
pub mod local;
#[cfg(feature = "quic")]
pub mod quic;
#[cfg(feature = "tcp")]
pub mod tcp;
#[cfg(feature = "tls")]
pub mod tls;

const DEFAULT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MAX_FRAME_LENTH: usize = 64 * 1024 * 1024; // 64MB

/// A MPC network that can be used to send and receive data to and from other parties
///
/// Can be used to send to multiple parties in parallel, but sending to the same party must happen in sequence.
pub trait Network: Send + Sync {
    /// The id of the party
    fn id(&self) -> usize;
    /// Send data to other party
    fn send(&self, to: usize, data: &[u8]) -> eyre::Result<()>;
    /// Receive data from other party
    fn recv(&self, from: usize) -> eyre::Result<Vec<u8>>;

    /// Get connection statistics for the Network.
    /// The returned HashMap maps party_id to a tuple of (sent_bytes, received_bytes).
    fn get_connection_stats(&self) -> ConnectionStats;
}

// This implements a dummy network that is used for plain variants of MPC protocols
impl Network for () {
    fn id(&self) -> usize {
        0
    }

    fn send(&self, _to: usize, _data: &[u8]) -> eyre::Result<()> {
        Ok(())
    }

    fn recv(&self, _from: usize) -> eyre::Result<Vec<u8>> {
        Ok(vec![])
    }

    fn get_connection_stats(&self) -> ConnectionStats {
        ConnectionStats {
            my_id: 0,
            stats: BTreeMap::new(),
        }
    }
}

/// Statistics about the number of bytes sent over the network.
pub struct ConnectionStats {
    my_id: usize,
    stats: BTreeMap<usize, (usize, usize)>,
}

impl ConnectionStats {
    /// Get connection statistics for a specific party.
    /// Returns a tuple of (sent_bytes, received_bytes) if the party_id exists, otherwise returns None.
    pub fn get(&self, party_id: usize) -> Option<(usize, usize)> {
        self.stats.get(&party_id).cloned()
    }

    /// Get an iterator over the connection statistics.
    /// Iterates over the parties in ascending order of their IDs.
    pub fn iter(&self) -> impl Iterator<Item = (usize, (usize, usize))> {
        self.stats.iter().map(|(&id, &stats)| (id, stats))
    }

    /// Get connection statistics for a given time period by calculating the difference between two ConnectionStats instances.
    pub fn get_diff_to(&self, other: &ConnectionStats) -> HashMap<usize, (usize, usize)> {
        let mut diff = HashMap::new();
        for (&id, &(sent, recv)) in &self.stats {
            if let Some(&(other_sent, other_recv)) = other.stats.get(&id) {
                diff.insert(id, (sent - other_sent, recv - other_recv));
            } else {
                diff.insert(id, (sent, recv));
            }
        }
        diff
    }
}

impl std::fmt::Display for ConnectionStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (id, (sent, recv)) in self.iter() {
            writeln!(
                f,
                "Party {my_id} <-> {id}: SENT {sent} bytes, RECV {recv} bytes",
                my_id = self.my_id
            )?;
        }
        Ok(())
    }
}
