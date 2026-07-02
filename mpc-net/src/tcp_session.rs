//! Ephemeral TCP MPC network

use std::cmp::Ordering;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::{net::TcpStream, sync::oneshot};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::{ConnectionStats, DEFAULT_MAX_FRAME_LENGTH, Network, async_net::AsyncChannels};
use bytes::Bytes;

/// The default time to idle for incoming connections that were not picked up because, e.g. `init_session` for that session id was never called.
pub const DEFAULT_TIME_TO_IDLE: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub(crate) enum MaybeTcpStream {
    TcpStream(TcpStream),
    Waiter(oneshot::Sender<TcpStream>),
}

#[derive(Default, Debug, Clone)]
#[expect(clippy::complexity)]
pub(crate) struct TcpStreams {
    streams: Arc<tokio::sync::Mutex<HashMap<(u128, usize), (MaybeTcpStream, Instant)>>>,
}

impl TcpStreams {
    pub(crate) fn new() -> Self {
        Self {
            streams: Arc::default(),
        }
    }

    pub(crate) async fn get(&self, session_id: u128, party_id: usize) -> eyre::Result<TcpStream> {
        let mut streams = self.streams.lock().await;
        let maybe_stream = streams.remove(&(session_id, party_id));
        match maybe_stream {
            Some((MaybeTcpStream::TcpStream(stream), _)) => Ok(stream),
            Some((MaybeTcpStream::Waiter(_), _)) => {
                eyre::bail!("tried to get same session_id twice")
            }
            None => {
                let (tx, rx) = oneshot::channel();
                streams.insert(
                    (session_id, party_id),
                    (MaybeTcpStream::Waiter(tx), Instant::now()),
                );
                drop(streams); // drop to release lock
                Ok(rx.await?)
            }
        }
    }

    pub(crate) async fn insert(&self, mut stream: TcpStream) -> eyre::Result<()> {
        stream.set_nodelay(true)?;

        tracing::debug!("reading session id..");
        let session_id = stream.read_u128().await?;
        tracing::debug!("got session id: {session_id:?}");

        tracing::debug!("reading party id..");
        let party_id = stream.read_u64().await? as usize;
        tracing::debug!("got party id: {party_id}");

        let mut streams = self.streams.lock().await;
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

/// TCP session network handler builder. Use `build` to create a new `TcpNetworkHandler`.
#[derive(Debug, Clone)]
pub struct TcpNetworkHandlerBuilder {
    party_id: usize,
    bind_addr: SocketAddr,
    parties: Vec<String>,
    time_to_idle: Duration,
    max_frame_length: usize,
    timeout: Option<Duration>,
    flush_timeout: Option<Duration>,
}

impl TcpNetworkHandlerBuilder {
    /// Create a new `TcpNetworkHandlerBuilder`. Use `build` to create a new `TcpNetworkHandler`.
    ///
    /// # Arguments
    /// - `party_id`: The id of this party (must be unique across all parties).
    /// - `bind_addr`: The address to bind the TCP listener to.
    /// - `parties`: The list of all parties' addresses (including this party's address). The index of each address in the list is the party id.
    pub fn new(party_id: usize, bind_addr: SocketAddr, parties: Vec<String>) -> Self {
        Self {
            party_id,
            bind_addr,
            parties,
            time_to_idle: DEFAULT_TIME_TO_IDLE,
            max_frame_length: DEFAULT_MAX_FRAME_LENGTH,
            timeout: None,
            flush_timeout: None,
        }
    }

    /// Set the time to idle for incoming connections that were not picked up because, e.g. `init_session` for that session id was never called.
    ///
    /// Defaults to `DEFAULT_TIME_TO_IDLE` (30 seconds)
    pub fn time_to_idle(mut self, time_to_idle: Duration) -> Self {
        self.time_to_idle = time_to_idle;
        self
    }

    /// Set the maximum length of a frame that can be sent or received. This is used to prevent DoS attacks by sending very large frames.
    ///
    /// Defaults to `DEFAULT_MAX_FRAME_LENGTH` (64MB)
    pub fn max_frame_length(mut self, max_frame_length: usize) -> Self {
        self.max_frame_length = max_frame_length;
        self
    }

    /// Set the receive timeout for the network.
    ///
    /// Defaults to no timeout.
    pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the flush timeout for the network.
    ///
    /// Defaults to no timeout.
    pub fn flush_timeout(mut self, flush_timeout: Option<Duration>) -> Self {
        self.flush_timeout = flush_timeout;
        self
    }

    /// Creates a new `TcpNetworkHandler`. Use `init_session` to create a new `TcpNetwork` for a session.
    ///
    /// Spawns two background tasks:
    /// - One for accepting incoming connections.
    /// - One for cleaning up idle (incoming connections that were not picked up because, e.g. `init_session` for that session id was never called) connections.
    pub async fn build(self) -> eyre::Result<TcpNetworkHandler> {
        let listener = tokio::net::TcpListener::bind(self.bind_addr).await?;
        let streams = TcpStreams::new();

        tokio::spawn({
            let streams = streams.clone();
            async move {
                loop {
                    if let Ok((stream, addr)) = listener.accept().await {
                        tracing::debug!("accepted incoming connection from {addr}");
                        if let Err(err) = streams.insert(stream).await {
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

        tokio::spawn({
            let streams = streams.clone();
            let mut interval = tokio::time::interval(self.time_to_idle * 2);
            async move {
                loop {
                    interval.tick().await;
                    let mut streams = streams.streams.lock().await;
                    let now = Instant::now();
                    let before_cleanup = streams.len();
                    streams.retain(|_, (_, last_used)| {
                        now.duration_since(*last_used) < self.time_to_idle
                    });
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
            party_id: self.party_id,
            streams,
            parties: self.parties,
            max_frame_length: self.max_frame_length,
            timeout: self.timeout,
            flush_timeout: self.flush_timeout,
        })
    }
}

/// TCP session network handler. Listens for incoming connections and matches them to sessions based on a session id and party id.
#[derive(Debug, Clone)]
pub struct TcpNetworkHandler {
    party_id: usize,
    streams: TcpStreams,
    parties: Vec<String>,
    max_frame_length: usize,
    timeout: Option<Duration>,
    flush_timeout: Option<Duration>,
}

impl TcpNetworkHandler {
    /// Initializes a new `TcpNetwork` for a session.
    ///
    /// All parties must call this method with the same `session_id` to establish the connections for that session.
    /// The `session_id` should be unique for each session, but can be reused across different sessions as long as they are not active at the same time.
    pub async fn init_session(&self, session_id: u128) -> eyre::Result<TcpNetwork> {
        let mut streams = HashMap::new();
        for (other_id, addr) in self.parties.iter().enumerate() {
            match other_id.cmp(&self.party_id) {
                Ordering::Less => {
                    tracing::debug!("connecting to peer: {addr}");
                    let mut stream = TcpStream::connect(addr).await?;
                    stream.set_nodelay(true)?;
                    stream.write_u128(session_id).await?;
                    stream.write_u64(self.party_id as u64).await?;
                    tracing::debug!("connected");
                    streams.insert(other_id, stream);
                }
                Ordering::Greater => {
                    tracing::debug!("waiting for peer: {addr}");
                    let stream = self.streams.get(session_id, other_id).await?;
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
    channels: AsyncChannels,
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
        // `new` is called from within `init_session`'s async context, so the ambient
        // runtime handle is available for the shutdown barrier's bounded receive.
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
