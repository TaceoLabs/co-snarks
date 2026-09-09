//! Ephemeral TCP MPC network (blocking)
//!
//! See [`SessionHandler`] for the session model.

use std::net::TcpStream;

use crate::{
    config::{Address, TlsConfig},
    session_blocking::Transport,
};

pub use crate::session_blocking::{SessionHandler, SessionNetwork as TcpNetwork};
pub use crate::session_config::{
    SessionConfig as NetworkConfig, SessionConfigFile as NetworkConfigFile,
};

/// Plain TCP transport (no encryption).
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
pub type TcpNetworkHandler = SessionHandler<TcpTransport>;
