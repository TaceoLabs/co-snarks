//! Ephemeral TCP MPC network (blocking)
//!
//! See [`SessionHandler`] for the session model.
//!
//! # Security
//!
//! This transport is **not secure**: the traffic is not encrypted and the peers are not authenticated. Every host that can reach the port can take the place of a party, since a peer is identified by the party id it sends, and everyone who can observe the traffic learns all messages, which include the shares and the seeds of the correlated randomness of the MPC protocols. Only use it for tests and benchmarks, or in a trusted, isolated network. Use the TLS transport (`tls` features) otherwise.

use std::net::TcpStream;

use crate::{
    config::{Address, TlsConfig},
    session_blocking::Transport,
};

pub use crate::session_blocking::{SessionHandler, SessionNetwork as TcpNetwork};
pub use crate::session_config::{
    SessionConfig as NetworkConfig, SessionConfigFile as NetworkConfigFile,
};

/// Plain TCP transport (no encryption, no authentication of the peers).
///
/// **Not secure:** no encryption and no authentication of the peers, see the [module documentation](self).
#[derive(Debug)]
pub struct TcpTransport;

impl Transport for TcpTransport {
    type Stream = TcpStream;

    fn new(_party_id: usize, _tls: Option<TlsConfig>) -> eyre::Result<Self> {
        Ok(Self)
    }

    fn connect(&self, stream: TcpStream, _addr: &Address) -> eyre::Result<TcpStream> {
        Ok(stream)
    }

    fn accept(&self, stream: TcpStream) -> eyre::Result<TcpStream> {
        Ok(stream)
    }

    fn socket(stream: &TcpStream) -> &TcpStream {
        stream
    }

    fn verify_peer(&self, _stream: &TcpStream, _party_id: usize) -> eyre::Result<()> {
        Ok(())
    }

    const DUPLEX: bool = true;

    fn split(stream: TcpStream) -> eyre::Result<(TcpStream, TcpStream)> {
        Ok((stream.try_clone()?, stream))
    }
}

/// TCP session network handler.
///
/// **Not secure:** no encryption and no authentication of the peers, see the [module documentation](self).
pub type TcpNetworkHandler = SessionHandler<TcpTransport>;
