//! Ephemeral TCP MPC network

use std::cmp::Ordering;
use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs as _};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use byteorder::{NetworkEndian, ReadBytesExt as _, WriteBytesExt as _};
use crossbeam_channel::Sender;
use eyre::Context;
use serde::Deserialize;

use crate::blocking::BlockingChannels;
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

#[derive(Debug)]
pub(crate) enum MaybeTcpStream {
    TcpStream(TcpStream),
    Waiter(Sender<TcpStream>),
}

#[derive(Default, Debug, Clone)]
#[expect(clippy::complexity)]
pub(crate) struct TcpStreams {
    write_timeout: Option<Duration>,
    init_session_timeout: Option<Duration>,
    streams: Arc<Mutex<HashMap<(u128, usize), (MaybeTcpStream, Instant)>>>,
}

impl TcpStreams {
    pub(crate) fn new(
        write_timeout: Option<Duration>,
        init_session_timeout: Option<Duration>,
    ) -> Self {
        Self {
            write_timeout,
            init_session_timeout,
            streams: Arc::default(),
        }
    }

    pub(crate) fn get(
        &self,
        session_id: u128,
        party_id: usize,
        timeout: Option<Duration>,
    ) -> eyre::Result<TcpStream> {
        let mut streams = self.streams.lock().expect("not poisoned");
        let maybe_stream = streams.remove(&(session_id, party_id));
        match maybe_stream {
            Some((MaybeTcpStream::TcpStream(stream), _)) => Ok(stream),
            Some((MaybeTcpStream::Waiter(_), _)) => {
                eyre::bail!("tried to get same session_id twice")
            }
            None => {
                let (tx, rx) = crossbeam_channel::bounded(1);
                streams.insert(
                    (session_id, party_id),
                    (MaybeTcpStream::Waiter(tx), Instant::now()),
                );
                drop(streams); // drop to release lock
                if let Some(timeout) = timeout {
                    rx.recv_timeout(timeout)
                        .context("while waiting for incoming connection")
                } else {
                    rx.recv().context("while waiting for incoming connection")
                }
            }
        }
    }

    pub(crate) fn insert(&self, mut stream: TcpStream) -> eyre::Result<()> {
        stream.set_nodelay(true)?;
        // set read timeout to init_session_timeout, so that we don't block forever
        // if the other party doesn't send the session id and party id
        stream.set_read_timeout(self.init_session_timeout)?;
        stream.set_write_timeout(self.write_timeout)?;

        tracing::debug!("reading session id..");
        let session_id = stream.read_u128::<NetworkEndian>()?;
        tracing::debug!("got session id: {session_id:?}");

        tracing::debug!("reading party id..");
        let party_id = stream.read_u64::<NetworkEndian>()? as usize;
        tracing::debug!("got party id: {party_id}");

        // reset read timeout to None, so that we don't timeout in the recv task
        stream.set_read_timeout(None)?;

        let mut streams = self.streams.lock().expect("not poisoned");
        let maybe_stream = streams.remove(&(session_id, party_id));
        match maybe_stream {
            Some((MaybeTcpStream::TcpStream(_), _)) => {
                eyre::bail!("tried to insert same session_id twice")
            }
            Some((MaybeTcpStream::Waiter(tx), _)) => {
                tracing::debug!("found waiter, sending stream");
                if tx.send(stream).is_err() {
                    tracing::warn!("failed to send stream to waiter, receiver dropped");
                }
            }
            None => {
                tracing::debug!("no waiter found, inserting stream");
                streams.insert(
                    (session_id, party_id),
                    (MaybeTcpStream::TcpStream(stream), Instant::now()),
                );
            }
        }
        Ok(())
    }
}

/// TCP session network handler. Listens for incoming connections and matches them to sessions based on a session id and party id.
#[derive(Debug, Clone)]
pub struct TcpNetworkHandler {
    party_id: usize,
    streams: TcpStreams,
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
        let streams = TcpStreams::new(timeout, init_session_timeout);

        std::thread::spawn({
            let streams = streams.clone();
            move || {
                loop {
                    if let Ok((stream, addr)) = listener.accept() {
                        tracing::debug!("accepted incoming connection from {addr}");
                        if let Err(err) = streams.insert(stream) {
                            tracing::warn!("failed to insert incoming connection: {err:?}");
                        }
                    } else {
                        tracing::warn!("failed to accept incoming connection");
                    }
                }
                #[allow(unreachable_code)]
                eyre::Ok(())
            }
        });

        std::thread::spawn({
            let streams = streams.clone();
            move || {
                loop {
                    std::thread::sleep(time_to_idle * 2);
                    let mut streams = streams.streams.lock().expect("not poisoned");
                    let now = Instant::now();
                    let before_cleanup = streams.len();
                    streams
                        .retain(|_, (_, last_used)| now.duration_since(*last_used) < time_to_idle);
                    let after_cleanup = streams.len();
                    let removed = before_cleanup - after_cleanup;
                    if removed > 0 {
                        tracing::warn!(
                            "cleaned up {removed} idle streams - this means that some some MPC operations likely failed"
                        );
                    }
                }
            }
        });

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
        let mut streams = HashMap::new();
        for (other_id, addr) in self.node_addrs.iter().enumerate() {
            match other_id.cmp(&self.party_id) {
                Ordering::Less => {
                    tracing::debug!("connecting to peer: {addr}");
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
                    tracing::debug!("connected");
                    streams.insert(other_id, stream);
                }
                Ordering::Greater => {
                    tracing::debug!("waiting for peer: {addr}");
                    let stream =
                        self.streams
                            .get(session_id, other_id, self.init_session_timeout)?;
                    tracing::debug!("got connection from peer");
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
