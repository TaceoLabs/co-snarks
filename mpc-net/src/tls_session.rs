//! Ephemeral TLS MPC network
//!
//! Same session model as [`crate::tcp_session`], but every connection is wrapped in TLS
//! (via `tokio-rustls`). Peers authenticate each other with the certificates from
//! [`TlsConfig`]; the connecting side verifies the accepting side's certificate against
//! the hostname in [`NetworkConfig::node_addrs`].

use std::cmp::Ordering;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt as _;
use rustls::{ClientConfig, RootCertStore, ServerConfig, pki_types::ServerName};
use serde::Deserialize;
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::{
    ConnectionStats, DEFAULT_MAX_FRAME_LENGTH, Network,
    async_net::AsyncChannels,
    config::{Address, TlsConfig, TlsConfigFile},
    session::SessionStreams,
};
use bytes::Bytes;

/// A TLS stream over a [`TcpStream`], either the client or the server side.
pub type TlsStream = tokio_rustls::TlsStream<TcpStream>;

/// The network configuration file.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub struct NetworkConfigFile {
    /// Our own id in the network.
    pub party_id: usize,
    /// The [SocketAddr] we bind to.
    pub bind_addr: SocketAddr,
    /// The addresses of the other nodes (ordered by party_id, including our own address).
    /// The hostname is checked against the certificate of the party.
    pub node_addrs: Vec<Address>,
    /// The TLS configuration.
    pub tls: TlsConfigFile,
    /// The `init_session` timeout for the network. If not set, the `init_session` will be unbounded.
    #[serde(with = "humantime_serde", default)]
    pub init_session_timeout: Option<Duration>,
    /// The send/recv timeout
    #[serde(with = "humantime_serde", default)]
    pub timeout: Option<Duration>,
    /// The flush timeout for the network. If not set, the flush will be unbounded.
    #[serde(with = "humantime_serde", default)]
    pub flush_timeout: Option<Duration>,
    /// The time to idle for incoming connections that were not picked up because, e.g.
    /// `init_session` for that session id was never called. Defaults to 30 seconds.
    #[serde(with = "humantime_serde", default = "default_time_to_idle")]
    pub time_to_idle: Duration,
    /// The max length (in bytes) of a single frame
    #[serde(default = "default_max_frame_length")]
    pub max_frame_length: usize,
}

/// The network configuration.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NetworkConfig {
    /// Our own id in the network.
    pub party_id: usize,
    /// The [SocketAddr] we bind to.
    pub bind_addr: SocketAddr,
    /// The addresses of the other nodes (ordered by party_id, including our own address).
    /// The hostname is checked against the certificate of the party.
    pub node_addrs: Vec<Address>,
    /// The TLS configuration.
    pub tls: TlsConfig,
    /// The `init_session` timeout for the network. If not set, the `init_session` will be unbounded.
    ///
    /// Not applied by this crate; wrap `init_session` in `tokio::time::timeout` downstream.
    pub init_session_timeout: Option<Duration>,
    /// The send/recv timeout
    pub timeout: Option<Duration>,
    /// The flush timeout for the network. If not set, the flush will be unbounded.
    pub flush_timeout: Option<Duration>,
    /// The time to idle for incoming connections that were not picked up because, e.g.
    /// `init_session` for that session id was never called.
    pub time_to_idle: Duration,
    /// The max length (in bytes) of a single frame
    pub max_frame_length: usize,
}

impl TryFrom<NetworkConfigFile> for NetworkConfig {
    type Error = eyre::Report;

    fn try_from(value: NetworkConfigFile) -> Result<Self, Self::Error> {
        Ok(NetworkConfig {
            party_id: value.party_id,
            bind_addr: value.bind_addr,
            node_addrs: value.node_addrs,
            tls: TlsConfig::try_from(value.tls)?,
            init_session_timeout: value.init_session_timeout,
            timeout: value.timeout,
            flush_timeout: value.flush_timeout,
            time_to_idle: value.time_to_idle,
            max_frame_length: value.max_frame_length,
        })
    }
}

fn default_max_frame_length() -> usize {
    DEFAULT_MAX_FRAME_LENGTH
}

fn default_time_to_idle() -> Duration {
    Duration::from_secs(30)
}

/// TLS session network handler. Listens for incoming connections, performs the TLS handshake
/// and matches them to sessions based on a session id and party id.
#[derive(Debug, Clone)]
pub struct TlsNetworkHandler {
    party_id: usize,
    streams: SessionStreams<TlsStream>,
    node_addrs: Vec<Address>,
    client_config: Arc<ClientConfig>,
    max_frame_length: usize,
    timeout: Option<Duration>,
    flush_timeout: Option<Duration>,
}

impl TlsNetworkHandler {
    /// Creates a new `TlsNetworkHandler`. Use `init_session` to create a new `TlsNetwork` for a session.
    ///
    /// Spawns two background tasks:
    /// - One for accepting incoming connections (including the TLS handshake).
    /// - One for cleaning up idle (incoming connections that were not picked up because, e.g. `init_session` for that session id was never called) connections.
    pub async fn new(
        NetworkConfig {
            party_id,
            bind_addr,
            node_addrs,
            tls,
            init_session_timeout: _,
            timeout,
            flush_timeout,
            time_to_idle,
            max_frame_length,
        }: NetworkConfig,
    ) -> eyre::Result<Self> {
        let mut root_store = RootCertStore::empty();
        for cert in &tls.certs {
            root_store.add(cert.clone())?;
        }
        let client_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let own_cert = tls
            .certs
            .get(party_id)
            .ok_or_else(|| eyre::eyre!("missing certificate for party {party_id}"))?
            .clone();
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![own_cert], tls.key)?;
        // We only ever connect once per session to each peer, session tickets are not needed.
        server_config.send_tls13_tickets = 0;
        let client_config = Arc::new(client_config);
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        let streams = SessionStreams::new();

        tokio::spawn({
            let streams = streams.clone();
            async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, addr)) => {
                            tracing::trace!("accepted incoming connection from {addr}");
                            // Handshake + header read per connection in its own task so a
                            // slow/malicious peer cannot stall the accept loop.
                            tokio::spawn({
                                let streams = streams.clone();
                                let acceptor = acceptor.clone();
                                async move {
                                    let res = async {
                                        stream.set_nodelay(true)?;
                                        let stream = acceptor.accept(stream).await?;
                                        streams.insert(TlsStream::Server(stream)).await
                                    }
                                    .await;
                                    if let Err(err) = res {
                                        tracing::warn!(
                                            "failed to insert incoming connection from {addr}: {err:?}"
                                        );
                                    }
                                }
                            });
                        }
                        Err(err) => tracing::warn!("failed to accept incoming connection: {err:?}"),
                    }
                }
            }
        });
        streams.spawn_cleanup(time_to_idle);

        Ok(TlsNetworkHandler {
            party_id,
            streams,
            node_addrs,
            client_config,
            max_frame_length,
            timeout,
            flush_timeout,
        })
    }

    /// Initializes a new `TlsNetwork` for a session.
    ///
    /// All parties must call this method with the same `session_id` to establish the connections for that session.
    /// The `session_id` should be unique for each session, but can be reused across different sessions as long as they are not active at the same time.
    pub async fn init_session(&self, session_id: u128) -> eyre::Result<TlsNetwork> {
        tracing::debug!("initializing session {session_id}");
        let connector = TlsConnector::from(self.client_config.clone());
        let mut streams = HashMap::new();
        for (other_id, addr) in self.node_addrs.iter().enumerate() {
            match other_id.cmp(&self.party_id) {
                Ordering::Less => {
                    tracing::trace!("connecting to peer: {addr}");
                    let stream = TcpStream::connect(addr.to_string()).await?;
                    stream.set_nodelay(true)?;
                    let name = ServerName::try_from(addr.hostname.clone())?;
                    let mut stream = connector.connect(name, stream).await?;
                    stream.write_u128(session_id).await?;
                    stream.write_u64(self.party_id as u64).await?;
                    stream.flush().await?;
                    tracing::trace!("connected");
                    streams.insert(other_id, TlsStream::Client(stream));
                }
                Ordering::Greater => {
                    tracing::trace!("waiting for peer: {addr}");
                    let stream = self.streams.get(session_id, other_id).await?;
                    tracing::trace!("got connection from peer");
                    streams.insert(other_id, stream);
                }
                Ordering::Equal => continue,
            }
        }
        TlsNetwork::new(
            self.party_id,
            streams,
            self.max_frame_length,
            self.timeout,
            self.flush_timeout,
        )
    }
}

/// A MPC network using [`TlsStream`]s
///
/// # Note
/// On Drop, the network will attempt to flush all channels. If the flush fails, an error will be logged but not returned.
/// This includes spawning a new thread to run the flush, so that if the network is dropped from within an async context, it will not panic.
#[derive(Debug)]
pub struct TlsNetwork {
    id: usize,
    channels: AsyncChannels,
}

impl Drop for TlsNetwork {
    fn drop(&mut self) {
        // See `tcp_session::TcpNetwork::drop`.
        let res = std::thread::scope(|s| s.spawn(|| self.flush()).join());
        if let Ok(Err(err)) = res {
            tracing::error!("error flushing channels on drop: {err:?}");
        }
    }
}

impl TlsNetwork {
    /// Create a new `TlsNetwork` from already established, handshaked streams.
    ///
    /// Must be called from within a tokio runtime context.
    pub fn new(
        id: usize,
        streams: HashMap<usize, TlsStream>,
        max_frame_length: usize,
        timeout: Option<Duration>,
        flush_timeout: Option<Duration>,
    ) -> eyre::Result<Self> {
        let mut channels = AsyncChannels::new(
            tokio::runtime::Handle::current(),
            max_frame_length,
            timeout,
            flush_timeout,
        );
        let codec = LengthDelimitedCodec::builder()
            .length_field_type::<u64>()
            .max_frame_length(max_frame_length)
            .new_codec();

        for (other_id, stream) in streams {
            let (sink, source) = Framed::new(stream, codec.clone()).split();
            channels.add_peer(other_id, sink, source);
        }

        Ok(Self { id, channels })
    }
}

impl Network for TlsNetwork {
    fn id(&self) -> usize {
        self.id
    }

    fn send(&self, to: usize, data: Bytes) -> eyre::Result<()> {
        self.channels.send(to, data)
    }

    fn recv(&self, from: usize) -> eyre::Result<Bytes> {
        self.channels.recv(from)
    }

    fn flush(&self) -> eyre::Result<()> {
        self.channels.flush()
    }

    fn get_connection_stats(&self) -> ConnectionStats {
        self.channels.stats(self.id)
    }
}
