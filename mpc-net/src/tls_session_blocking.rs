//! Ephemeral TLS MPC network (blocking)
//!
//! See [`SessionHandler`] for the session model. Every connection is wrapped in mutual TLS (via
//! `rustls`). As a blocking TLS stream cannot be split into independent reader and writer
//! halves, two connections are opened per peer and session. Peers authenticate each other with
//! the certificates from [`TlsConfig`]: both sides present their certificate, and the peer's
//! certificate must be the one of the party id it claims. The connecting side additionally
//! verifies the accepting side's certificate against the hostname in [`NetworkConfig::node_addrs`].

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

    fn verify_peer(&self, stream: &TlsStream, party_id: usize) -> eyre::Result<()> {
        let conn: &rustls::CommonState = match stream {
            TlsStream::Client(s) => &s.conn,
            TlsStream::Server(s) => &s.conn,
        };
        self.tls.verify_peer(conn, party_id)
    }

    const DUPLEX: bool = false;

    fn split(_stream: TlsStream) -> eyre::Result<(TlsStream, TlsStream)> {
        eyre::bail!("TLS streams cannot be split")
    }
}

/// TLS session network handler.
pub type TlsNetworkHandler = SessionHandler<TlsTransport>;
