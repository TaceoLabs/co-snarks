//! Ephemeral TLS MPC network
//!
//! See [`SessionHandler`] for the session model. Every connection is wrapped in TLS (via
//! `tokio-rustls`). Peers authenticate each other with the certificates from
//! [`TlsConfig`]; the connecting side verifies the accepting side's certificate against the
//! hostname in [`NetworkConfig::node_addrs`].

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
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
}

impl Transport for TlsTransport {
    type Stream = TlsStream;

    fn new(party_id: usize, tls: Option<TlsConfig>) -> eyre::Result<Self> {
        let tls = tls.ok_or_else(|| eyre::eyre!("TLS config is required for TlsNetworkHandler"))?;
        let (client_config, server_config) = tls.into_rustls_configs(party_id)?;
        Ok(Self {
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
}

/// TLS session network handler.
pub type TlsNetworkHandler = SessionHandler<TlsTransport>;
