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

/// The default connection timeout
pub const DEFAULT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
/// The default max frame length for sending messages
pub const DEFAULT_MAX_FRAME_LENGTH: usize = 64 * 1024 * 1024; // 64MB

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
    /// Create new `ConnectionStats`
    pub fn new(my_id: usize, stats: BTreeMap<usize, (usize, usize)>) -> Self {
        Self { my_id, stats }
    }
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

/// Run 2 network closures
#[inline(always)]
pub fn join<R0: Send, R1: Send>(
    f0: impl FnOnce() -> R0 + Send,
    f1: impl FnOnce() -> R1 + Send,
) -> (R0, R1) {
    std::thread::scope(|s| {
        let r0 = s.spawn(f0);
        let r1 = f1();
        (r0.join().expect("can join"), r1)
    })
}

/// Run 3 network closures
#[inline(always)]
pub fn join3<R0: Send, R1: Send, R2: Send>(
    f0: impl FnOnce() -> R0 + Send,
    f1: impl FnOnce() -> R1 + Send,
    f2: impl FnOnce() -> R2 + Send,
) -> (R0, R1, R2) {
    std::thread::scope(|s| {
        let r0 = s.spawn(f0);
        let r1 = s.spawn(f1);
        let r2 = f2();
        (
            r0.join().expect("can join"),
            r1.join().expect("can join"),
            r2,
        )
    })
}

/// Run 4 network closures
#[inline(always)]
pub fn join4<R0: Send, R1: Send, R2: Send, R3: Send>(
    f0: impl FnOnce() -> R0 + Send,
    f1: impl FnOnce() -> R1 + Send,
    f2: impl FnOnce() -> R2 + Send,
    f3: impl FnOnce() -> R3 + Send,
) -> (R0, R1, R2, R3) {
    std::thread::scope(|s| {
        let r0 = s.spawn(f0);
        let r1 = s.spawn(f1);
        let r2 = s.spawn(f2);
        let r3 = f3();
        (
            r0.join().expect("can join"),
            r1.join().expect("can join"),
            r2.join().expect("can join"),
            r3,
        )
    })
}

/// Run 5 network closures
#[inline(always)]
pub fn join5<R0: Send, R1: Send, R2: Send, R3: Send, R4: Send>(
    f0: impl FnOnce() -> R0 + Send,
    f1: impl FnOnce() -> R1 + Send,
    f2: impl FnOnce() -> R2 + Send,
    f3: impl FnOnce() -> R3 + Send,
    f4: impl FnOnce() -> R4 + Send,
) -> (R0, R1, R2, R3, R4) {
    std::thread::scope(|s| {
        let r0 = s.spawn(f0);
        let r1 = s.spawn(f1);
        let r2 = s.spawn(f2);
        let r3 = s.spawn(f3);
        let r4 = f4();
        (
            r0.join().expect("can join"),
            r1.join().expect("can join"),
            r2.join().expect("can join"),
            r3.join().expect("can join"),
            r4,
        )
    })
}

/// Run 6 network closures
#[inline(always)]
pub fn join6<R0: Send, R1: Send, R2: Send, R3: Send, R4: Send, R5: Send>(
    f0: impl FnOnce() -> R0 + Send,
    f1: impl FnOnce() -> R1 + Send,
    f2: impl FnOnce() -> R2 + Send,
    f3: impl FnOnce() -> R3 + Send,
    f4: impl FnOnce() -> R4 + Send,
    f5: impl FnOnce() -> R5 + Send,
) -> (R0, R1, R2, R3, R4, R5) {
    std::thread::scope(|s| {
        let r0 = s.spawn(f0);
        let r1 = s.spawn(f1);
        let r2 = s.spawn(f2);
        let r3 = s.spawn(f3);
        let r4 = s.spawn(f4);
        let r5 = f5();
        (
            r0.join().expect("can join"),
            r1.join().expect("can join"),
            r2.join().expect("can join"),
            r3.join().expect("can join"),
            r4.join().expect("can join"),
            r5,
        )
    })
}

/// Run 7 network closures
#[inline(always)]
pub fn join7<R0: Send, R1: Send, R2: Send, R3: Send, R4: Send, R5: Send, R6: Send>(
    f0: impl FnOnce() -> R0 + Send,
    f1: impl FnOnce() -> R1 + Send,
    f2: impl FnOnce() -> R2 + Send,
    f3: impl FnOnce() -> R3 + Send,
    f4: impl FnOnce() -> R4 + Send,
    f5: impl FnOnce() -> R5 + Send,
    f6: impl FnOnce() -> R6 + Send,
) -> (R0, R1, R2, R3, R4, R5, R6) {
    std::thread::scope(|s| {
        let r0 = s.spawn(f0);
        let r1 = s.spawn(f1);
        let r2 = s.spawn(f2);
        let r3 = s.spawn(f3);
        let r4 = s.spawn(f4);
        let r5 = s.spawn(f5);
        let r6 = f6();
        (
            r0.join().expect("can join"),
            r1.join().expect("can join"),
            r2.join().expect("can join"),
            r3.join().expect("can join"),
            r4.join().expect("can join"),
            r5.join().expect("can join"),
            r6,
        )
    })
}

/// Run 8 network closures
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub fn join8<R0: Send, R1: Send, R2: Send, R3: Send, R4: Send, R5: Send, R6: Send, R7: Send>(
    f0: impl FnOnce() -> R0 + Send,
    f1: impl FnOnce() -> R1 + Send,
    f2: impl FnOnce() -> R2 + Send,
    f3: impl FnOnce() -> R3 + Send,
    f4: impl FnOnce() -> R4 + Send,
    f5: impl FnOnce() -> R5 + Send,
    f6: impl FnOnce() -> R6 + Send,
    f7: impl FnOnce() -> R7 + Send,
) -> (R0, R1, R2, R3, R4, R5, R6, R7) {
    std::thread::scope(|s| {
        let r0 = s.spawn(f0);
        let r1 = s.spawn(f1);
        let r2 = s.spawn(f2);
        let r3 = s.spawn(f3);
        let r4 = s.spawn(f4);
        let r5 = s.spawn(f5);
        let r6 = s.spawn(f6);
        let r7 = f7();
        (
            r0.join().expect("can join"),
            r1.join().expect("can join"),
            r2.join().expect("can join"),
            r3.join().expect("can join"),
            r4.join().expect("can join"),
            r5.join().expect("can join"),
            r6.join().expect("can join"),
            r7,
        )
    })
}
