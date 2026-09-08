//! Ephemeral TCP MPC network

use std::cmp::Ordering;
use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs as _};
use std::time::Duration;

use byteorder::{NetworkEndian, ReadBytesExt as _, WriteBytesExt as _};
use serde::Deserialize;

use crate::blocking::BlockingChannels;
use crate::session_blocking::SessionStreams;
use crate::{ConnectionStats, DEFAULT_MAX_FRAME_LENGTH, Network};
use bytes::Bytes;

/// The network configuration file.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub struct NetworkConfig {
    /// Our own id in the network.
    pub party_id: usize,
    /// The [SocketAddr] we bind to.
    pub bind_addr: SocketAddr,
    /// The addresses of the other nodes (ordered by party_id, including our own address).
    pub node_addrs: Vec<String>,
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
    /// `init_session` for that session id was never called.
    #[serde(with = "humantime_serde", default = "default_time_to_idle")]
    pub time_to_idle: Duration,
    /// The max length (in bytes) of a single frame
    #[serde(default = "default_max_frame_length")]
    pub max_frame_length: usize,
}

fn default_max_frame_length() -> usize {
    DEFAULT_MAX_FRAME_LENGTH
}

fn default_time_to_idle() -> Duration {
    Duration::from_secs(30)
}

/// Configure an accepted stream and read its `(session_id, party_id)` header.
fn accept_header(
    stream: &mut TcpStream,
    init_session_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
) -> eyre::Result<(u128, usize)> {
    stream.set_nodelay(true)?;
    // set read timeout to init_session_timeout, so that we don't block forever
    // if the other party doesn't send the session id and party id
    stream.set_read_timeout(init_session_timeout)?;
    stream.set_write_timeout(write_timeout)?;

    tracing::trace!("reading session id..");
    let session_id = stream.read_u128::<NetworkEndian>()?;
    tracing::trace!("got session id: {session_id:?}");

    tracing::trace!("reading party id..");
    let party_id = stream.read_u64::<NetworkEndian>()? as usize;
    tracing::trace!("got party id: {party_id}");

    // reset read timeout to None, so that we don't timeout in the recv task
    stream.set_read_timeout(None)?;
    Ok((session_id, party_id))
}

/// TCP session network handler. Listens for incoming connections and matches them to sessions based on a session id and party id.
#[derive(Debug, Clone)]
pub struct TcpNetworkHandler {
    party_id: usize,
    streams: SessionStreams<(u128, usize), TcpStream>,
    node_addrs: Vec<String>,
    max_frame_length: usize,
    timeout: Option<Duration>,
    flush_timeout: Option<Duration>,
    init_session_timeout: Option<Duration>,
}

impl TcpNetworkHandler {
    /// Creates a new `TcpNetworkHandler`. Use `init_session` to create a new `TcpNetwork` for a session.
    ///
    /// Spawns two background tasks:
    /// - One for accepting incoming connections.
    /// - One for cleaning up idle (incoming connections that were not picked up because, e.g. `init_session` for that session id was never called) connections.
    pub fn new(
        NetworkConfig {
            party_id,
            bind_addr,
            node_addrs,
            timeout,
            init_session_timeout,
            flush_timeout,
            time_to_idle,
            max_frame_length,
        }: NetworkConfig,
    ) -> eyre::Result<Self> {
        let listener = TcpListener::bind(bind_addr)?;
        let streams = SessionStreams::new();

        std::thread::spawn({
            let streams = streams.clone();
            move || {
                loop {
                    match listener.accept() {
                        Ok((mut stream, addr)) => {
                            tracing::trace!("accepted incoming connection from {addr}");
                            match accept_header(&mut stream, init_session_timeout, timeout) {
                                Ok(key) => streams.insert(key, stream),
                                Err(err) => tracing::warn!(
                                    "failed to insert incoming connection from {addr}: {err:?}"
                                ),
                            }
                        }
                        Err(err) => tracing::warn!("failed to accept incoming connection: {err:?}"),
                    }
                }
            }
        });
        streams.spawn_cleanup(time_to_idle);

        Ok(TcpNetworkHandler {
            party_id,
            streams,
            node_addrs,
            max_frame_length,
            timeout,
            flush_timeout,
            init_session_timeout,
        })
    }

    /// Initializes a new `TcpNetwork` for a session.
    ///
    /// All parties must call this method with the same `session_id` to establish the connections for that session.
    /// The `session_id` should be unique for each session, but can be reused across different sessions as long as they are not active at the same time.
    pub fn init_session(&self, session_id: u128) -> eyre::Result<TcpNetwork> {
        tracing::debug!("initializing session {session_id}");
        let mut streams = HashMap::new();
        for (other_id, addr) in self.node_addrs.iter().enumerate() {
            match other_id.cmp(&self.party_id) {
                Ordering::Less => {
                    tracing::trace!("connecting to peer: {addr}");
                    let mut stream = if let Some(init_session_timeout) = self.init_session_timeout {
                        let addr = addr.to_socket_addrs()?.next().ok_or_else(|| {
                            eyre::eyre!("failed to resolve address {addr} to a socket address")
                        })?;
                        TcpStream::connect_timeout(&addr, init_session_timeout)?
                    } else {
                        TcpStream::connect(addr)?
                    };
                    stream.set_nodelay(true)?;
                    stream.set_write_timeout(self.timeout)?;
                    stream.write_u128::<NetworkEndian>(session_id)?;
                    stream.write_u64::<NetworkEndian>(self.party_id as u64)?;
                    tracing::trace!("connected");
                    streams.insert(other_id, stream);
                }
                Ordering::Greater => {
                    tracing::trace!("waiting for peer: {addr}");
                    let stream = self
                        .streams
                        .get((session_id, other_id), self.init_session_timeout)?;
                    tracing::trace!("got connection from peer");
                    streams.insert(other_id, stream);
                }
                Ordering::Equal => continue,
            }
        }
        TcpNetwork::new(
            self.party_id,
            streams,
            self.max_frame_length,
            self.timeout,
            self.flush_timeout,
        )
    }
}

/// A MPC network using `TcpStream`s
#[derive(Debug)]
pub struct TcpNetwork {
    id: usize,
    channels: BlockingChannels,
}

impl Drop for TcpNetwork {
    fn drop(&mut self) {
        if let Err(e) = self.channels.flush() {
            tracing::error!("error flushing channels on drop: {e:?}");
        }
    }
}

impl TcpNetwork {
    /// Create a new `TcpNetwork`
    pub fn new(
        id: usize,
        streams: HashMap<usize, TcpStream>,
        max_frame_length: usize,
        timeout: Option<Duration>,
        flush_timeout: Option<Duration>,
    ) -> eyre::Result<Self> {
        let mut channels = BlockingChannels::new(timeout, flush_timeout, max_frame_length);

        for (other_id, stream) in streams {
            let write_stream = stream.try_clone().expect("can clone stream");
            channels.add_peer(other_id, write_stream, stream);
        }

        Ok(Self { id, channels })
    }
}

impl Network for TcpNetwork {
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
