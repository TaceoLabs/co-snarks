//! Ephemeral TLS MPC network
//!
//! See [`SessionHandler`] for the session model. Every connection is wrapped in mutual TLS (via
//! `tokio-rustls`). Peers authenticate each other with the certificates from [`TlsConfig`]:
//! both sides present their certificate, and the peer's certificate must be the one of the
//! party id it claims. The connecting side additionally verifies the accepting side's
//! certificate against the hostname in [`NetworkConfig::node_addrs`].

use std::sync::Arc;

use rustls::{ClientConfig, ServerConfig, pki_types::ServerName};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::{
    config::{Address, TlsConfig},
    session::Transport,
};

pub use crate::session::{SessionHandler, SessionNetwork as TlsNetwork};
pub use crate::session_config::{
    SessionConfig as NetworkConfig, SessionConfigFile as NetworkConfigFile,
};

/// A TLS stream over a [`TcpStream`], either the client or the server side.
pub type TlsStream = tokio_rustls::TlsStream<TcpStream>;

/// TLS transport.
#[derive(Debug)]
pub struct TlsTransport {
    tls: TlsConfig,
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
}

impl Transport for TlsTransport {
    type Stream = TlsStream;

    fn new(party_id: usize, tls: Option<TlsConfig>) -> eyre::Result<Self> {
        let tls = tls.ok_or_else(|| eyre::eyre!("TLS config is required for TlsNetworkHandler"))?;
        let (client_config, server_config) = tls.into_rustls_configs(party_id)?;
        Ok(Self {
            tls,
            client_config,
            server_config,
        })
    }

    async fn connect(&self, stream: TcpStream, addr: &Address) -> eyre::Result<TlsStream> {
        let name = ServerName::try_from(addr.hostname.clone())?;
        let stream = TlsConnector::from(self.client_config.clone())
            .connect(name, stream)
            .await?;
        Ok(stream.into())
    }

    async fn accept(&self, stream: TcpStream) -> eyre::Result<TlsStream> {
        let stream = TlsAcceptor::from(self.server_config.clone())
            .accept(stream)
            .await?;
        Ok(stream.into())
    }

    fn verify_peer(&self, stream: &TlsStream, party_id: usize) -> eyre::Result<()> {
        self.tls.verify_peer(stream.get_ref().1, party_id)
    }
}

/// TLS session network handler.
pub type TlsNetworkHandler = SessionHandler<TlsTransport>;
