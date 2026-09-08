//! Shared implementation of the async session-based transports (ephemeral TCP/TLS sessions).
//!
//! A [`SessionHandler`] listens for incoming connections; each one announces a
//! `(session_id, party_id)` header and is parked until the matching `init_session` call
//! picks it up (or vice versa: `init_session` may register a waiter before the connection
//! arrives). The only transport-specific part, wrapping a raw TCP connection (e.g. in TLS),
//! is abstracted by [`Transport`].

use std::{
    cmp::Ordering,
    collections::HashMap,
    fmt::Debug,
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures::StreamExt as _;
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    net::TcpStream,
    sync::oneshot,
};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::{
    ConnectionStats, Network,
    async_net::AsyncChannels,
    config::{Address, TlsConfig},
    session_config::SessionConfig,
};

/// How a session transport wraps raw TCP connections (e.g. plain or TLS).
pub trait Transport: Sized + Send + Sync + 'static {
    /// The established (possibly wrapped) connection.
    type Stream: AsyncRead + AsyncWrite + Debug + Send + Unpin + 'static;
    /// Build the transport for `party_id` from the optional TLS configuration.
    fn new(party_id: usize, tls: Option<TlsConfig>) -> eyre::Result<Self>;
    /// Wrap an outgoing connection to the peer at `addr` (client side).
    fn connect(
        &self,
        stream: TcpStream,
        addr: &Address,
    ) -> impl Future<Output = eyre::Result<Self::Stream>> + Send;
    /// Wrap an accepted connection (server side).
    fn accept(&self, stream: TcpStream) -> impl Future<Output = eyre::Result<Self::Stream>> + Send;
}

#[derive(Debug)]
enum MaybeStream<S> {
    Stream(S),
    Waiter(oneshot::Sender<S>),
}

/// Map of parked incoming streams / waiters, keyed by `(session_id, party_id)`.
#[derive(Debug)]
struct SessionStreams<S> {
    #[expect(clippy::type_complexity)]
    streams: Arc<tokio::sync::Mutex<HashMap<(u128, usize), (MaybeStream<S>, Instant)>>>,
}

impl<S> Clone for SessionStreams<S> {
    fn clone(&self) -> Self {
        Self {
            streams: self.streams.clone(),
        }
    }
}

impl<S: AsyncRead + Unpin + Send + 'static> SessionStreams<S> {
    fn new() -> Self {
        Self {
            streams: Arc::default(),
        }
    }

    /// Take the parked stream for `(session_id, party_id)`, or wait until one arrives.
    async fn get(&self, session_id: u128, party_id: usize) -> eyre::Result<S> {
        let mut streams = self.streams.lock().await;
        match streams.remove(&(session_id, party_id)) {
            Some((MaybeStream::Stream(stream), _)) => Ok(stream),
            x @ (None | Some((MaybeStream::Waiter(_), _))) => {
                if x.is_some() {
                    tracing::warn!(
                        "got duplicate connection waiter for session_id {session_id} and party_id {party_id}, replacing old waiter"
                    );
                }
                drop(x); // drop old waiter if it exists, so that old waiter doesn't block forever
                let (tx, rx) = oneshot::channel();
                streams.insert(
                    (session_id, party_id),
                    (MaybeStream::Waiter(tx), Instant::now()),
                );
                drop(streams); // drop to release lock
                Ok(rx.await?)
            }
        }
    }

    /// Read the `(session_id, party_id)` header from `stream` and park it (or hand it to a waiter).
    async fn insert(&self, mut stream: S) -> eyre::Result<()> {
        let session_id = stream.read_u128().await?;
        let party_id = stream.read_u64().await? as usize;
        tracing::trace!("got header: session {session_id}, party {party_id}");

        let mut streams = self.streams.lock().await;
        match streams.remove(&(session_id, party_id)) {
            Some((MaybeStream::Stream(_), _)) => {
                tracing::warn!(
                    "got duplicate incoming connection for session_id {session_id} and party_id {party_id}, replacing old connection"
                );
                streams.insert(
                    (session_id, party_id),
                    (MaybeStream::Stream(stream), Instant::now()),
                );
            }
            Some((MaybeStream::Waiter(tx), _)) => {
                tracing::trace!("found waiter, sending stream");
                if tx.send(stream).is_err() {
                    tracing::warn!("failed to send stream to waiter, receiver dropped");
                }
            }
            None => {
                tracing::trace!("no waiter found, inserting stream");
                streams.insert(
                    (session_id, party_id),
                    (MaybeStream::Stream(stream), Instant::now()),
                );
            }
        }
        Ok(())
    }

    /// Spawn a background task that periodically drops entries idle for longer than `time_to_idle`.
    fn spawn_cleanup(&self, time_to_idle: Duration) {
        let streams = self.streams.clone();
        let mut interval = tokio::time::interval(time_to_idle * 2);
        tokio::spawn(async move {
            loop {
                interval.tick().await;
                let mut streams = streams.lock().await;
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
        }
    }
}

impl<T: Transport> SessionHandler<T> {
    /// Creates a new handler. Use [`init_session`](Self::init_session) to create a new [`SessionNetwork`] for a session.
    ///
    /// Spawns two background tasks:
    /// - One for accepting incoming connections (each handshake runs in its own task).
    /// - One for cleaning up idle (incoming connections that were not picked up because, e.g. `init_session` for that session id was never called) connections.
    pub async fn new(
        SessionConfig {
            party_id,
            bind_addr,
            node_addrs,
            tls,
            init_session_timeout: _,
            timeout,
            flush_timeout,
            time_to_idle,
            max_frame_length,
        }: SessionConfig,
    ) -> eyre::Result<Self> {
        let transport = Arc::new(T::new(party_id, tls)?);
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        let streams = SessionStreams::new();

        tokio::spawn({
            let streams = streams.clone();
            let transport = transport.clone();
            async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, addr)) => {
                            tracing::trace!("accepted incoming connection from {addr}");
                            let streams = streams.clone();
                            let transport = transport.clone();
                            tokio::spawn(async move {
                                let res = async {
                                    stream.set_nodelay(true)?;
                                    let stream = transport.accept(stream).await?;
                                    streams.insert(stream).await
                                }
                                .await;
                                if let Err(err) = res {
                                    tracing::warn!(
                                        "failed to insert incoming connection from {addr}: {err:?}"
                                    );
                                }
                            });
                        }
                        Err(err) => tracing::warn!("failed to accept incoming connection: {err:?}"),
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
        })
    }

    /// Initializes a new [`SessionNetwork`] for a session.
    ///
    /// All parties must call this method with the same `session_id` to establish the connections for that session.
    /// The `session_id` should be unique for each session, but can be reused across different sessions as long as they are not active at the same time.
    pub async fn init_session(&self, session_id: u128) -> eyre::Result<SessionNetwork> {
        tracing::debug!("initializing session {session_id}");
        let mut streams = HashMap::new();
        for (other_id, addr) in self.node_addrs.iter().enumerate() {
            match other_id.cmp(&self.party_id) {
                Ordering::Less => {
                    tracing::trace!("connecting to peer: {addr}");
                    let stream = TcpStream::connect(addr.to_string()).await?;
                    stream.set_nodelay(true)?;
                    let mut stream = self.transport.connect(stream, addr).await?;
                    stream.write_u128(session_id).await?;
                    stream.write_u64(self.party_id as u64).await?;
                    stream.flush().await?;
                    tracing::trace!("connected");
                    streams.insert(other_id, stream);
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
///
/// # Note
/// On Drop, the network will attempt to flush all channels. If the flush fails, an error will be logged but not returned.
/// This includes spawning a new thread to run the flush, so that if the network is dropped from within an async context, it will not panic.
#[derive(Debug)]
pub struct SessionNetwork {
    id: usize,
    channels: AsyncChannels,
}

impl Drop for SessionNetwork {
    fn drop(&mut self) {
        // flush calls `Runtime::block_on` and `blocking_send/blocking_recv` panics
        // if called from within another runtime's async context.
        // The child thread is not part of any runtime, so `block_on` is always
        // valid there. Errors during shutdown are ignored (best-effort cleanup).
        let res = std::thread::scope(|s| s.spawn(|| self.flush()).join());
        if let Ok(Err(err)) = res {
            tracing::error!("error flushing channels on drop: {err:?}");
        }
    }
}

impl SessionNetwork {
    /// Create a new network from already established streams, one per peer.
    ///
    /// Must be called from within a tokio runtime context.
    pub fn new<S>(
        id: usize,
        streams: HashMap<usize, S>,
        max_frame_length: usize,
        timeout: Option<Duration>,
        flush_timeout: Option<Duration>,
    ) -> eyre::Result<Self>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
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
