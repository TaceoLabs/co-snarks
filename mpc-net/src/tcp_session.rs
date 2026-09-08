//! Ephemeral TCP MPC network
//!
//! See [`SessionHandler`] for the session model.

use tokio::net::TcpStream;

use crate::{
    config::{Address, TlsConfig},
    session::Transport,
};

pub use crate::session::{SessionHandler, SessionNetwork as TcpNetwork};
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

    async fn connect(&self, stream: TcpStream, _addr: &Address) -> eyre::Result<TcpStream> {
        Ok(stream)
    }

    async fn accept(&self, stream: TcpStream) -> eyre::Result<TcpStream> {
        Ok(stream)
    }
}

/// TCP session network handler.
pub type TcpNetworkHandler = SessionHandler<TcpTransport>;
