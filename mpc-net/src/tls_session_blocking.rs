//! Ephemeral TLS MPC network (blocking)
//!
//! Same session model as [`crate::tcp_session_blocking`], but every connection is wrapped
//! in TLS (via `rustls`). Since a blocking TLS stream cannot be split into independent
//! reader and writer halves, two TLS connections are opened per peer and session, one per
//! direction (as in [`crate::tls`]).
//!
//! Peers authenticate each other with the certificates from [`TlsConfig`]; the connecting
//! side verifies the accepting side's certificate against the hostname in
//! [`NetworkConfig::node_addrs`].

use std::cmp::Ordering;
use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs as _};
use std::sync::Arc;
use std::time::Duration;

use byteorder::{NetworkEndian, ReadBytesExt as _, WriteBytesExt as _};
use eyre::ContextCompat as _;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::ServerName,
};
use serde::Deserialize;

pub use crate::blocking::TlsStream;
use crate::{
    ConnectionStats, DEFAULT_MAX_FRAME_LENGTH, Network,
    blocking::BlockingChannels,
    config::{Address, TlsConfig, TlsConfigFile},
    session_blocking::SessionStreams,
};
use bytes::Bytes;

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

/// Direction tag sent by the connecting party: this connection is its send direction.
const STREAM_SEND: u8 = 0;
/// Direction tag sent by the connecting party: this connection is its receive direction.
const STREAM_RECV: u8 = 1;

/// `(session_id, party_id, direction)`, where `direction` is from the connecting party's view.
type Key = (u128, usize, u8);

/// Perform the server handshake on an accepted stream and read its [`Key`] header.
fn accept_header(
    stream: TcpStream,
    server_config: Arc<ServerConfig>,
    init_session_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
) -> eyre::Result<(Key, TlsStream)> {
    stream.set_nodelay(true)?;
    // bound the handshake + header read, so that we don't block forever
    stream.set_read_timeout(init_session_timeout)?;
    stream.set_write_timeout(write_timeout)?;

    let conn = ServerConnection::new(server_config)?;
    let mut stream = StreamOwned::new(conn, stream);

    let session_id = stream.read_u128::<NetworkEndian>()?;
    let party_id = stream.read_u64::<NetworkEndian>()? as usize;
    let direction = stream.read_u8()?;
    tracing::trace!("got header: session {session_id}, party {party_id}, direction {direction}");

    // reset read timeout to None, so that we don't timeout in the recv task
    stream.sock.set_read_timeout(None)?;
    Ok(((session_id, party_id, direction), stream.into()))
}

/// TLS session network handler. Listens for incoming connections, performs the TLS handshake
/// and matches them to sessions based on a session id and party id.
#[derive(Debug, Clone)]
pub struct TlsNetworkHandler {
    party_id: usize,
    streams: SessionStreams<Key, TlsStream>,
    node_addrs: Vec<Address>,
    client_config: Arc<ClientConfig>,
    max_frame_length: usize,
    timeout: Option<Duration>,
    flush_timeout: Option<Duration>,
    init_session_timeout: Option<Duration>,
}

impl TlsNetworkHandler {
    /// Creates a new `TlsNetworkHandler`. Use `init_session` to create a new `TlsNetwork` for a session.
    ///
    /// Spawns two background threads:
    /// - One for accepting incoming connections (each handshake runs on its own short-lived thread).
    /// - One for cleaning up idle (incoming connections that were not picked up because, e.g. `init_session` for that session id was never called) connections.
    pub fn new(
        NetworkConfig {
            party_id,
            bind_addr,
            node_addrs,
            tls,
            init_session_timeout,
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
        // Disable TLS 1.3 session tickets to avoid sending data back via the write half.
        // It never gets read there, thus leading to sporadic errors.
        server_config.send_tls13_tickets = 0;
        let client_config = Arc::new(client_config);
        let server_config = Arc::new(server_config);

        let listener = TcpListener::bind(bind_addr)?;
        let streams = SessionStreams::new();

        std::thread::spawn({
            let streams = streams.clone();
            move || {
                loop {
                    match listener.accept() {
                        Ok((stream, addr)) => {
                            tracing::trace!("accepted incoming connection from {addr}");
                            let streams = streams.clone();
                            let server_config = server_config.clone();
                            std::thread::spawn(move || {
                                match accept_header(
                                    stream,
                                    server_config,
                                    init_session_timeout,
                                    timeout,
                                ) {
                                    Ok((key, stream)) => streams.insert(key, stream),
                                    Err(err) => tracing::warn!(
                                        "failed to insert incoming connection from {addr}: {err:?}"
                                    ),
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
            init_session_timeout,
        })
    }

    fn connect(&self, addr: &Address, session_id: u128, direction: u8) -> eyre::Result<TlsStream> {
        let socket_addr = addr
            .to_socket_addrs()?
            .next()
            .with_context(|| format!("failed to resolve address {addr}"))?;
        let stream = if let Some(init_session_timeout) = self.init_session_timeout {
            TcpStream::connect_timeout(&socket_addr, init_session_timeout)?
        } else {
            TcpStream::connect(socket_addr)?
        };
        stream.set_nodelay(true)?;
        stream.set_write_timeout(self.timeout)?;

        let name = ServerName::try_from(addr.hostname.clone())?;
        let conn = ClientConnection::new(self.client_config.clone(), name)?;
        let mut stream = StreamOwned::new(conn, stream);
        stream.write_u128::<NetworkEndian>(session_id)?;
        stream.write_u64::<NetworkEndian>(self.party_id as u64)?;
        stream.write_u8(direction)?;
        Ok(stream.into())
    }

    /// Initializes a new `TlsNetwork` for a session.
    ///
    /// All parties must call this method with the same `session_id` to establish the connections for that session.
    /// The `session_id` should be unique for each session, but can be reused across different sessions as long as they are not active at the same time.
    pub fn init_session(&self, session_id: u128) -> eyre::Result<TlsNetwork> {
        tracing::debug!("initializing session {session_id}");
        let mut streams = HashMap::new();
        for (other_id, addr) in self.node_addrs.iter().enumerate() {
            match other_id.cmp(&self.party_id) {
                Ordering::Less => {
                    tracing::trace!("connecting to peer: {addr}");
                    let write_stream = self.connect(addr, session_id, STREAM_SEND)?;
                    let read_stream = self.connect(addr, session_id, STREAM_RECV)?;
                    tracing::trace!("connected");
                    streams.insert(other_id, (write_stream, read_stream));
                }
                Ordering::Greater => {
                    tracing::trace!("waiting for peer: {addr}");
                    // The peer's send direction is our read direction and vice versa.
                    let read_stream = self.streams.get(
                        (session_id, other_id, STREAM_SEND),
                        self.init_session_timeout,
                    )?;
                    let write_stream = self.streams.get(
                        (session_id, other_id, STREAM_RECV),
                        self.init_session_timeout,
                    )?;
                    tracing::trace!("got connections from peer");
                    streams.insert(other_id, (write_stream, read_stream));
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
#[derive(Debug)]
pub struct TlsNetwork {
    id: usize,
    channels: BlockingChannels,
}

impl Drop for TlsNetwork {
    fn drop(&mut self) {
        if let Err(e) = self.channels.flush() {
            tracing::error!("error flushing channels on drop: {e:?}");
        }
    }
}

impl TlsNetwork {
    /// Create a new `TlsNetwork` from `(write, read)` stream pairs per peer.
    pub fn new(
        id: usize,
        streams: HashMap<usize, (TlsStream, TlsStream)>,
        max_frame_length: usize,
        timeout: Option<Duration>,
        flush_timeout: Option<Duration>,
    ) -> eyre::Result<Self> {
        let mut channels = BlockingChannels::new(timeout, flush_timeout, max_frame_length);
        for (other_id, (write_stream, read_stream)) in streams {
            channels.add_peer(other_id, write_stream, read_stream);
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
