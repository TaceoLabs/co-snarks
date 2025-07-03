//! A simple networking layer for MPC protocols.
#![warn(missing_docs)]
use std::time::Duration;

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
}
