//! Ephemeral TLS MPC network (blocking)
//!
//! See [`SessionHandler`] for the session model. Every connection is wrapped in TLS (via
//! `rustls`). Peers authenticate each other with the certificates from [`TlsConfig`]; the
//! connecting side verifies the accepting side's certificate against the hostname in
//! [`NetworkConfig::node_addrs`].

use std::{net::TcpStream, sync::Arc};

use rustls::{
    ClientConfig, ClientConnection, ServerConfig, ServerConnection, StreamOwned,
    pki_types::ServerName,
};

use crate::{
    config::{Address, TlsConfig},
    session_blocking::Transport,
};

pub use crate::blocking::TlsStream;
pub use crate::session_blocking::{SessionHandler, SessionNetwork as TlsNetwork};
pub use crate::session_config::{
    SessionConfig as NetworkConfig, SessionConfigFile as NetworkConfigFile,
};

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

    fn connect(&self, stream: TcpStream, addr: &Address) -> eyre::Result<TlsStream> {
        let name = ServerName::try_from(addr.hostname.clone())?;
        let conn = ClientConnection::new(self.client_config.clone(), name)?;
        Ok(StreamOwned::new(conn, stream).into())
    }

    fn accept(&self, stream: TcpStream) -> eyre::Result<TlsStream> {
        let conn = ServerConnection::new(self.server_config.clone())?;
        Ok(StreamOwned::new(conn, stream).into())
    }

    fn socket(stream: &TlsStream) -> &TcpStream {
        match stream {
            TlsStream::Client(s) => &s.sock,
            TlsStream::Server(s) => &s.sock,
        }
    }
}

/// TLS session network handler.
pub type TlsNetworkHandler = SessionHandler<TlsTransport>;
