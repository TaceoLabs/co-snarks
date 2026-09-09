//! Shared implementation of the blocking session-based transports (ephemeral TCP/TLS sessions).
//!
//! A [`SessionHandler`] listens for incoming connections; each one announces a
//! `(session_id, party_id, direction)` header and is parked until the matching
//! `init_session` call picks it up (or vice versa: `init_session` may register a waiter
//! before the connection arrives). The transport-specific parts, wrapping a raw TCP
//! connection (e.g. in TLS) and splitting it into reader and writer halves, are abstracted
//! by [`Transport`]. Transports whose streams cannot be split (TLS) open two connections
//! per peer and session, one per direction.

use std::{
    cmp::Ordering,
    collections::HashMap,
    fmt::Debug,
    io::{Read, Write},
    net::{TcpListener, TcpStream, ToSocketAddrs as _},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use byteorder::{NetworkEndian, ReadBytesExt as _, WriteBytesExt as _};
use bytes::Bytes;
use crossbeam_channel::Sender;
use eyre::{Context as _, ContextCompat as _};

use crate::{
    ConnectionStats, Network,
    blocking::BlockingChannels,
    config::{Address, TlsConfig},
    session_config::SessionConfig,
};

/// How a session transport wraps raw TCP connections (e.g. plain or TLS).
pub trait Transport: Sized + Send + Sync + 'static {
    /// The established (possibly wrapped) connection.
    type Stream: Read + Write + Debug + Send + 'static;
    /// Build the transport for `party_id` from the optional TLS configuration.
    fn new(party_id: usize, tls: Option<TlsConfig>) -> eyre::Result<Self>;
    /// Wrap an outgoing connection to the peer at `addr` (client side).
    fn connect(&self, stream: TcpStream, addr: &Address) -> eyre::Result<Self::Stream>;
    /// Wrap an accepted connection (server side).
    fn accept(&self, stream: TcpStream) -> eyre::Result<Self::Stream>;
    /// The underlying TCP socket of an established connection.
    fn socket(stream: &Self::Stream) -> &TcpStream;
    /// Whether one connection serves both directions via [`split`](Self::split).
    /// If `false`, two connections are opened per peer and session, one per direction.
    const DUPLEX: bool;
    /// Split a connection into independent `(write, read)` halves. Only called if [`DUPLEX`](Self::DUPLEX).
    fn split(stream: Self::Stream) -> eyre::Result<(Self::Stream, Self::Stream)>;
}

/// Backoff after a failed `accept` (e.g. EMFILE), so that we don't spin.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

/// Direction tag sent by the connecting party: this connection is its send direction.
const STREAM_SEND: u8 = 0;
/// Direction tag sent by the connecting party: this connection is its receive direction.
const STREAM_RECV: u8 = 1;
/// Direction tag (local only, not sent) for the single connection of a duplex transport.
const STREAM_DUPLEX: u8 = 2;

/// `(session_id, party_id, direction)`, where `direction` is from the connecting party's view.
/// For duplex transports the direction is always [`STREAM_DUPLEX`] and not part of the header.
type Key = (u128, usize, u8);

#[derive(Debug)]
enum MaybeStream<S> {
    Stream(S),
    Waiter(Sender<S>),
}

/// Map of parked incoming streams / waiters.
#[derive(Debug)]
struct SessionStreams<S> {
    #[expect(clippy::type_complexity)]
    streams: Arc<Mutex<HashMap<Key, (MaybeStream<S>, Instant)>>>,
}

impl<S> Clone for SessionStreams<S> {
    fn clone(&self) -> Self {
        Self {
            streams: self.streams.clone(),
        }
    }
}

impl<S: Send + 'static> SessionStreams<S> {
    fn new() -> Self {
        Self {
            streams: Arc::default(),
        }
    }

    /// Take the parked stream for `key`, or wait (at most `timeout`) until one arrives.
    fn get(&self, key: Key, timeout: Option<Duration>) -> eyre::Result<S> {
        let mut streams = self.streams.lock().expect("not poisoned");
        match streams.remove(&key) {
            Some((MaybeStream::Stream(stream), _)) => Ok(stream),
            x @ (None | Some((MaybeStream::Waiter(_), _))) => {
                if x.is_some() {
                    tracing::warn!(
                        "got duplicate connection waiter for {key:?}, replacing old waiter"
                    );
                }
                drop(x); // drop old waiter if it exists, so that old waiter doesn't block forever
                let (tx, rx) = crossbeam_channel::bounded(1);
                streams.insert(key, (MaybeStream::Waiter(tx), Instant::now()));
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

    /// Park `stream` under `key`, or hand it to a waiter already registered for `key`.
    fn insert(&self, key: Key, stream: S) {
        let mut streams = self.streams.lock().expect("not poisoned");
        match streams.remove(&key) {
            Some((MaybeStream::Stream(_), _)) => {
                tracing::warn!(
                    "got duplicate incoming connection for {key:?}, replacing old connection"
                );
                streams.insert(key, (MaybeStream::Stream(stream), Instant::now()));
            }
            Some((MaybeStream::Waiter(tx), _)) => {
                tracing::trace!("found waiter, sending stream");
                if tx.send(stream).is_err() {
                    tracing::warn!("failed to send stream to waiter, receiver dropped");
                }
            }
            None => {
                tracing::trace!("no waiter found, inserting stream");
                streams.insert(key, (MaybeStream::Stream(stream), Instant::now()));
            }
        }
    }

    /// Spawn a background thread that periodically drops entries idle for longer than `time_to_idle`.
    fn spawn_cleanup(&self, time_to_idle: Duration) {
        let streams = self.streams.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(time_to_idle * 2);
                let mut streams = streams.lock().expect("not poisoned");
                let now = Instant::now();
                let before_cleanup = streams.len();
                streams.retain(|_, (_, last_used)| now.duration_since(*last_used) < time_to_idle);
                let removed = before_cleanup - streams.len();
                if removed > 0 {
                    tracing::warn!(
                        "cleaned up {removed} idle streams - this means that some some MPC operations likely failed"
                    );
                }
            }
        });
    }
}

/// Configure an accepted connection, wrap it via the transport and read its [`Key`] header.
fn accept_header<T: Transport>(
    transport: &T,
    stream: TcpStream,
    init_session_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
) -> eyre::Result<(Key, T::Stream)> {
    stream.set_nodelay(true)?;
    // bound the handshake + header read, so that we don't block forever
    stream.set_read_timeout(init_session_timeout)?;
    stream.set_write_timeout(write_timeout)?;

    let mut stream = transport.accept(stream)?;
    let session_id = stream.read_u128::<NetworkEndian>()?;
    let party_id = stream.read_u64::<NetworkEndian>()? as usize;
    let direction = if T::DUPLEX {
        STREAM_DUPLEX
    } else {
        stream.read_u8()?
    };
    tracing::trace!("got header: session {session_id}, party {party_id}, direction {direction}");

    // reset read timeout to None, so that we don't timeout in the recv thread
    T::socket(&stream).set_read_timeout(None)?;
    Ok(((session_id, party_id, direction), stream))
}

/// Session network handler. Listens for incoming connections and matches them to sessions
/// based on a session id and party id.
#[derive(Debug)]
pub struct SessionHandler<T: Transport> {
    party_id: usize,
    streams: SessionStreams<T::Stream>,
    node_addrs: Vec<Address>,
    transport: Arc<T>,
    max_frame_length: usize,
    timeout: Option<Duration>,
    flush_timeout: Option<Duration>,
    init_session_timeout: Option<Duration>,
}

impl<T: Transport> Clone for SessionHandler<T> {
    fn clone(&self) -> Self {
        Self {
            party_id: self.party_id,
            streams: self.streams.clone(),
            node_addrs: self.node_addrs.clone(),
            transport: self.transport.clone(),
            max_frame_length: self.max_frame_length,
            timeout: self.timeout,
            flush_timeout: self.flush_timeout,
            init_session_timeout: self.init_session_timeout,
        }
    }
}

impl<T: Transport> SessionHandler<T> {
    /// Creates a new handler. Use [`init_session`](Self::init_session) to create a new [`SessionNetwork`] for a session.
    ///
    /// Spawns two background threads:
    /// - One for accepting incoming connections (each handshake runs on its own short-lived thread).
    /// - One for cleaning up idle (incoming connections that were not picked up because, e.g. `init_session` for that session id was never called) connections.
    pub fn new(
        SessionConfig {
            party_id,
            bind_addr,
            node_addrs,
            tls,
            init_session_timeout,
            timeout,
            flush_timeout,
            time_to_idle,
            max_frame_length,
        }: SessionConfig,
    ) -> eyre::Result<Self> {
        let transport = Arc::new(T::new(party_id, tls)?);
        let listener = TcpListener::bind(bind_addr)?;
        let streams = SessionStreams::new();

        std::thread::spawn({
            let streams = streams.clone();
            let transport = transport.clone();
            move || {
                loop {
                    match listener.accept() {
                        Ok((stream, addr)) => {
                            tracing::trace!("accepted incoming connection from {addr}");
                            let streams = streams.clone();
                            let transport = transport.clone();
                            std::thread::spawn(move || {
                                match accept_header(
                                    &*transport,
                                    stream,
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
                        Err(err) => {
                            tracing::warn!("failed to accept incoming connection: {err:?}");
                            std::thread::sleep(ACCEPT_RETRY_DELAY);
                        }
                    }
                }
            }
        });
        streams.spawn_cleanup(time_to_idle);

        Ok(Self {
            party_id,
            streams,
            node_addrs,
            transport,
            max_frame_length,
            timeout,
            flush_timeout,
            init_session_timeout,
        })
    }

    fn connect(&self, addr: &Address, session_id: u128, direction: u8) -> eyre::Result<T::Stream> {
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
        // bound the handshake (driven by the first write) so that we don't block forever
        stream.set_read_timeout(self.init_session_timeout)?;

        let mut stream = self.transport.connect(stream, addr)?;
        stream.write_u128::<NetworkEndian>(session_id)?;
        stream.write_u64::<NetworkEndian>(self.party_id as u64)?;
        if !T::DUPLEX {
            stream.write_u8(direction)?;
        }
        stream.flush()?;

        // reset read timeout to None, so that we don't timeout in the recv thread
        T::socket(&stream).set_read_timeout(None)?;
        Ok(stream)
    }

    /// Initializes a new [`SessionNetwork`] for a session.
    ///
    /// All parties must call this method with the same `session_id` to establish the connections for that session.
    /// The `session_id` should be unique for each session, but can be reused across different sessions as long as they are not active at the same time.
    pub fn init_session(&self, session_id: u128) -> eyre::Result<SessionNetwork> {
        tracing::debug!("initializing session {session_id}");
        let mut streams = HashMap::new();
        for (other_id, addr) in self.node_addrs.iter().enumerate() {
            match other_id.cmp(&self.party_id) {
                Ordering::Less => {
                    tracing::trace!("connecting to peer: {addr}");
                    let pair = if T::DUPLEX {
                        T::split(self.connect(addr, session_id, STREAM_DUPLEX)?)?
                    } else {
                        let write_stream = self.connect(addr, session_id, STREAM_SEND)?;
                        let read_stream = self.connect(addr, session_id, STREAM_RECV)?;
                        (write_stream, read_stream)
                    };
                    tracing::trace!("connected");
                    streams.insert(other_id, pair);
                }
                Ordering::Greater => {
                    tracing::trace!("waiting for peer: {addr}");
                    let get = |direction| {
                        self.streams
                            .get((session_id, other_id, direction), self.init_session_timeout)
                    };
                    let pair = if T::DUPLEX {
                        T::split(get(STREAM_DUPLEX)?)?
                    } else {
                        // The peer's send direction is our read direction and vice versa.
                        let read_stream = get(STREAM_SEND)?;
                        let write_stream = get(STREAM_RECV)?;
                        (write_stream, read_stream)
                    };
                    tracing::trace!("got connection from peer");
                    streams.insert(other_id, pair);
                }
                Ordering::Equal => continue,
            }
        }
        SessionNetwork::new(
            self.party_id,
            streams,
            self.max_frame_length,
            self.timeout,
            self.flush_timeout,
        )
    }
}

/// A MPC network over the streams of one session.
#[derive(Debug)]
pub struct SessionNetwork {
    id: usize,
    channels: BlockingChannels,
}

impl Drop for SessionNetwork {
    fn drop(&mut self) {
        if let Err(e) = self.channels.flush() {
            tracing::error!("error flushing channels on drop: {e:?}");
        }
    }
}

impl SessionNetwork {
    /// Create a new network from already established `(write, read)` stream pairs, one per peer.
    pub fn new<W, R>(
        id: usize,
        streams: HashMap<usize, (W, R)>,
        max_frame_length: usize,
        timeout: Option<Duration>,
        flush_timeout: Option<Duration>,
    ) -> eyre::Result<Self>
    where
        W: Write + Send + 'static,
        R: Read + Send + 'static,
    {
        let mut channels = BlockingChannels::new(timeout, flush_timeout, max_frame_length);
        for (other_id, (write_stream, read_stream)) in streams {
            channels.add_peer(other_id, write_stream, read_stream);
        }
        Ok(Self { id, channels })
    }
}

impl Network for SessionNetwork {
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
