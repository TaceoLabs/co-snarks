//! Ephemeral TCP MPC network

use std::cmp::Ordering;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt as _;
use serde::Deserialize;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::{net::TcpStream, sync::oneshot};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::{ConnectionStats, DEFAULT_MAX_FRAME_LENGTH, Network, async_net::AsyncChannels};
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
    #[allow(
        dead_code,
        reason = "can be used via tokio::time::timeout around init_session, but up to downstream code to do so"
    )]
    pub init_session_timeout: Option<Duration>,
    /// The send/recv timeout
    #[serde(with = "humantime_serde", default)]
    pub timeout: Option<Duration>,
    /// The flush timeout for the network. If not set, the flush will be unbounded.
    #[serde(with = "humantime_serde", default)]
    pub flush_timeout: Option<Duration>,
    /// The time to idle for incoming connections that were not picked up because, e.g.
    /// `init_session` for that session id was never called. Defaults to `DEFAULT_TIME_TO_IDLE` (30 seconds)
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

/// TCP session network handler. Listens for incoming connections and matches them to sessions based on a session id and party id.
#[derive(Debug, Clone)]
pub struct TcpNetworkHandler {
    party_id: usize,
    streams: TcpStreams,
    node_addrs: Vec<String>,
    max_frame_length: usize,
    timeout: Option<Duration>,
    flush_timeout: Option<Duration>,
}

impl TcpNetworkHandler {
    /// Creates a new `TcpNetworkHandler`. Use `init_session` to create a new `TcpNetwork` for a session.
    ///
    /// Spawns two background tasks:
    /// - One for accepting incoming connections.
    /// - One for cleaning up idle (incoming connections that were not picked up because, e.g. `init_session` for that session id was never called) connections.
    pub async fn new(
        NetworkConfig {
            party_id,
            bind_addr,
            node_addrs,
            init_session_timeout: _,
            timeout,
            flush_timeout,
            time_to_idle,
            max_frame_length,
        }: NetworkConfig,
    ) -> eyre::Result<Self> {
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
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
            let mut interval = tokio::time::interval(time_to_idle * 2);
            async move {
                loop {
                    interval.tick().await;
                    let mut streams = streams.streams.lock().await;
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
        })
    }

    /// Initializes a new `TcpNetwork` for a session.
    ///
    /// All parties must call this method with the same `session_id` to establish the connections for that session.
    /// The `session_id` should be unique for each session, but can be reused across different sessions as long as they are not active at the same time.
    pub async fn init_session(&self, session_id: u128) -> eyre::Result<TcpNetwork> {
        let mut streams = HashMap::new();
        for (other_id, addr) in self.node_addrs.iter().enumerate() {
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
///
/// # Note
/// On Drop, the network will attempt to flush all channels. If the flush fails, an error will be logged but not returned.
/// This includes spawning a new thread to run the flush, so that if the network is dropped from within an async context, it will not panic.
#[derive(Debug)]
pub struct TcpNetwork {
    id: usize,
    channels: AsyncChannels,
}

impl Drop for TcpNetwork {
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
