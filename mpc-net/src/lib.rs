//! A simple networking layer for MPC protocols.
#![warn(missing_docs)]
use std::{
    collections::{BTreeMap, HashMap},
    io,
    net::ToSocketAddrs,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};

use channel::{BincodeChannel, BytesChannel, Channel, ChannelHandle, ChannelTasks};
use codecs::BincodeCodec;
use color_eyre::eyre::{bail, Context as Ctx, ContextCompat, Report};
use config::NetworkConfig;
use futures::{Sink, Stream};
use serde::{de::DeserializeOwned, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    runtime::Handle,
    task::JoinError,
};
use tokio_rustls::{
    rustls::{
        pki_types::{CertificateDer, ServerName},
        ClientConfig, RootCertStore, ServerConfig,
    },
    TlsAcceptor, TlsConnector,
};
use tokio_util::codec::{Decoder, Encoder, FramedRead, FramedWrite, LengthDelimitedCodec};

pub mod channel;
pub mod codecs;
pub mod config;

// TODO get this from network config
const STREAMS_PER_CONN: usize = 8;

/// Type alias for a [tokio_rustls::TlsStream] over a [TcpStream].
type TlsStream = tokio_rustls::TlsStream<TcpStream>;

/// A duplex TLS stream that uses one stream for sending and one for receiving.
/// Splitting a single stream would add unwanted syncronization primitives.
#[derive(Debug)]
struct DuplexTlsStream {
    send: TlsStream,
    recv: TlsStream,
}

impl DuplexTlsStream {
    const SPLIT0: u8 = 0;
    const SPLIT1: u8 = 1;

    /// Create a new [DuplexTlsStream].
    pub(crate) fn new(send: TlsStream, recv: TlsStream) -> Self {
        Self { send, recv }
    }
}

/// A connection with a pool of streams and total sent/recv stats.
#[derive(Debug, Default)]
struct Connection {
    streams: Vec<DuplexTlsStream>,
    sent: Arc<AtomicUsize>,
    recv: Arc<AtomicUsize>,
}

/// A network handler for MPC protocols.
#[derive(Debug)]
pub struct MpcNetworkHandler {
    // this is a btreemap because we rely on iteration order
    connections: BTreeMap<usize, Connection>,
    tasks: ChannelTasks,
    my_id: usize,
}

impl MpcNetworkHandler {
    /// Tries to establish a connection to other parties in the network based on the provided [NetworkConfig].
    pub async fn establish(config: NetworkConfig) -> Result<Self, Report> {
        config.check_config()?;
        let certs: HashMap<usize, CertificateDer> = config
            .parties
            .iter()
            .map(|p| (p.id, p.cert.clone()))
            .collect();

        let mut root_store = RootCertStore::empty();
        for (id, cert) in &certs {
            root_store
                .add(cert.clone())
                .with_context(|| format!("adding certificate for party {} to root store", id))?;
        }
        let client_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certs[&config.my_id].clone()], config.key)
            .context("creating our server config")?;
        let our_socket_addr = config.bind_addr;

        let listener = TcpListener::bind(our_socket_addr).await?;
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let connector = TlsConnector::from(Arc::new(client_config));

        tracing::trace!("Party {}: listening on {our_socket_addr}", config.my_id);

        let mut connections: BTreeMap<usize, Connection> = BTreeMap::new();

        let mut accpected_streams = BTreeMap::new();

        let num_parties = config.parties.len();

        for party in config.parties {
            if party.id == config.my_id {
                // skip self
                continue;
            }
            if party.id < config.my_id {
                // connect to party, we are client
                let party_addr = party
                    .dns_name
                    .to_socket_addrs()
                    .with_context(|| format!("while resolving DNS name for {}", party.dns_name))?
                    .next()
                    .with_context(|| format!("could not resolve DNS name {}", party.dns_name))?;

                let domain = ServerName::try_from(party.dns_name.hostname.clone())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))?
                    .to_owned();

                // create all streams for this connection
                for stream_id in 0..STREAMS_PER_CONN {
                    let mut send = None;
                    let mut recv = None;
                    // create 2 streams per stream to get full duplex with tls streams
                    for split in [DuplexTlsStream::SPLIT0, DuplexTlsStream::SPLIT1] {
                        let stream = loop {
                            if let Ok(stream) = TcpStream::connect(party_addr).await {
                                break stream;
                            }
                            std::thread::sleep(Duration::from_millis(100));
                        };
                        // this removes buffering of tcp packets, very important for latency of small packets
                        stream.set_nodelay(true)?;
                        let mut stream = connector.connect(domain.clone(), stream).await?;
                        stream.write_u64(config.my_id as u64).await?;
                        stream.write_u64(stream_id as u64).await?;
                        stream.write_u8(split).await?;
                        if split == DuplexTlsStream::SPLIT0 {
                            send = Some(stream);
                        } else {
                            recv = Some(stream);
                        }
                    }

                    tracing::trace!(
                        "Party {}: connected stream {stream_id} to party {}",
                        party.id,
                        config.my_id
                    );

                    let send = send.expect("not none after connect was succesful");
                    let recv = recv.expect("not none after connect was succesful");

                    if let Some(conn) = connections.get_mut(&party.id) {
                        conn.streams
                            .push(DuplexTlsStream::new(send.into(), recv.into()));
                    } else {
                        let mut conn = Connection::default();
                        conn.streams
                            .push(DuplexTlsStream::new(send.into(), recv.into()));
                        connections.insert(party.id, conn);
                    }
                }
            } else {
                // we are the server, accept connections
                // accept all 2 splits for n streams and store them with (party_id, stream_id, split) so we know were they belong
                for _ in 0..STREAMS_PER_CONN * 2 {
                    let (stream, _peer_addr) = listener.accept().await?;
                    // this removes buffering of tcp packets, very important for latency of small packets
                    stream.set_nodelay(true)?;
                    let mut stream = acceptor.accept(stream).await?;
                    let party_id = stream.read_u64().await? as usize;
                    let stream_id = stream.read_u64().await? as usize;
                    let split = stream.read_u8().await?;
                    assert!(accpected_streams
                        .insert((party_id, stream_id, split), stream)
                        .is_none());
                }
            }
        }

        // assign streams to the right party, stream and duplex half
        // we accepted streams for all parties with id > my_id, so we can iter from my_id + 1..num_parties
        for party_id in config.my_id + 1..num_parties {
            for stream_id in 0..STREAMS_PER_CONN {
                // send and recv is swapped here compared to above
                let recv = accpected_streams
                    .remove(&(party_id, stream_id, DuplexTlsStream::SPLIT0))
                    .context(format!("get recv for stream {stream_id} party {party_id}"))?;
                let send = accpected_streams
                    .remove(&(party_id, stream_id, DuplexTlsStream::SPLIT1))
                    .context(format!("get send for stream {stream_id} party {party_id}"))?;
                if let Some(conn) = connections.get_mut(&party_id) {
                    conn.streams
                        .push(DuplexTlsStream::new(send.into(), recv.into()));
                } else {
                    let mut conn = Connection::default();
                    conn.streams
                        .push(DuplexTlsStream::new(send.into(), recv.into()));
                    connections.insert(party_id, conn);
                }
            }
        }

        if !accpected_streams.is_empty() {
            bail!("not accepted connections should remain");
        }

        tracing::trace!("Party {}: established network handler", config.my_id);

        Ok(MpcNetworkHandler {
            connections,
            tasks: ChannelTasks::new(Handle::current()),
            my_id: config.my_id,
        })
    }

    /// Create a new [`ChannelHandle`] from a [`Channel`]. This spawns a new tokio task that handles the read and write jobs so they can happen concurrently.
    pub fn spawn<MSend, MRecv, R, W, C>(
        &mut self,
        chan: Channel<R, W, C>,
    ) -> ChannelHandle<MSend, MRecv>
    where
        C: 'static,
        R: AsyncRead + Unpin + 'static,
        W: AsyncWrite + Unpin + std::marker::Send + 'static,
        FramedRead<R, C>: Stream<Item = Result<MRecv, io::Error>> + Send,
        FramedWrite<W, C>: Sink<MSend, Error = io::Error> + Send,
        MRecv: Send + std::fmt::Debug + 'static,
        MSend: Send + std::fmt::Debug + 'static,
    {
        self.tasks.spawn(chan)
    }

    /// Shutdown the network, waiting until all read and write tasks are completed. This happens automatically, when the network handler is dropped.
    pub async fn shutdown(&mut self) -> Result<(), JoinError> {
        self.tasks.shutdown().await
    }

    /// Returns the number of sent and received bytes.
    pub fn get_send_receive(&self, i: usize) -> std::io::Result<(usize, usize)> {
        let conn = self
            .connections
            .get(&i)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such connection"))?;
        Ok((
            conn.sent.load(Ordering::SeqCst),
            conn.recv.load(Ordering::SeqCst),
        ))
    }

    /// Prints the connection statistics.
    pub fn print_connection_stats(&self, out: &mut impl std::io::Write) -> std::io::Result<()> {
        for (i, conn) in &self.connections {
            writeln!(
                out,
                "Connection {} stats:\n\tSENT: {} bytes\n\tRECV: {} bytes",
                i,
                conn.sent.load(Ordering::SeqCst),
                conn.recv.load(Ordering::SeqCst)
            )?;
        }
        Ok(())
    }

    /// Get a [Channel] to party with `id`. This pops a stream from the pool.
    pub fn get_byte_channel(
        &mut self,
        id: &usize,
    ) -> Option<BytesChannel<impl AsyncRead, impl AsyncWrite>> {
        let mut codec = LengthDelimitedCodec::new();
        codec.set_max_frame_length(1_000_000_000);
        self.get_custom_channel(id, codec)
    }

    /// Get a [Channel] to party with `id`. This pops a stream from the pool.
    pub fn get_serde_bincode_channel<M: Serialize + DeserializeOwned + 'static>(
        &mut self,
        id: &usize,
    ) -> Option<Channel<impl AsyncRead, impl AsyncWrite, BincodeCodec<M>>> {
        let bincodec = BincodeCodec::<M>::new();
        self.get_custom_channel(id, bincodec)
    }

    /// Get a [Channel] to party with `id` using the provided codec. This pops a stream from the pool.
    pub fn get_custom_channel<
        MSend,
        MRecv,
        C: Encoder<MSend, Error = io::Error>
            + Decoder<Item = MRecv, Error = io::Error>
            + 'static
            + Clone,
    >(
        &mut self,
        id: &usize,
        codec: C,
    ) -> Option<Channel<impl AsyncRead, impl AsyncWrite, C>> {
        debug_assert!(*id != self.my_id);
        if let Some(conn) = self.connections.get_mut(id) {
            if let Some(stream) = conn.streams.pop() {
                let recv = TrackingAsyncReader::new(stream.recv, conn.recv.clone());
                let send = TrackingAsyncWriter::new(stream.send, conn.sent.clone());
                return Some(Channel::new(recv, send, codec));
            }
        }
        None
    }

    /// Get a [Channel] to each party using the provided codec. This pops a stream from each pool.
    pub fn get_custom_channels<
        MSend,
        MRecv,
        C: Encoder<MSend, Error = io::Error>
            + Decoder<Item = MRecv, Error = io::Error>
            + 'static
            + Clone,
    >(
        &mut self,
        codec: C,
    ) -> Option<HashMap<usize, Channel<impl AsyncRead, impl AsyncWrite, C>>> {
        let mut channels = HashMap::new();
        let party_ids: Vec<_> = self.connections.keys().cloned().collect();
        for id in party_ids {
            let chan = self.get_custom_channel(&id, codec.clone())?;
            channels.insert(id, chan);
        }
        Some(channels)
    }

    /// Get a [Channel] to each party. This pops a stream from each pool.
    pub fn get_byte_channels(
        &mut self,
    ) -> Option<HashMap<usize, BytesChannel<impl AsyncRead, impl AsyncWrite>>> {
        let mut codec = LengthDelimitedCodec::new();
        codec.set_max_frame_length(1_000_000_000);
        self.get_custom_channels(codec)
    }

    /// Get a [Channel] to each party. This pops a stream from each pool.
    pub fn get_serde_bincode_channels<M: Serialize + DeserializeOwned + 'static>(
        &mut self,
    ) -> Option<HashMap<usize, BincodeChannel<impl AsyncRead, impl AsyncWrite, M>>> {
        let bincodec = BincodeCodec::<M>::new();
        self.get_custom_channels(bincodec)
    }
}

/// A wrapper around [`AsyncRead`] types that keeps track of the number of read bytes
struct TrackingAsyncReader<R> {
    inner: R,
    bytes_read: Arc<AtomicUsize>,
}

impl<R> TrackingAsyncReader<R> {
    fn new(inner: R, bytes_read: Arc<AtomicUsize>) -> Self {
        Self { inner, bytes_read }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for TrackingAsyncReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let inner = Pin::new(&mut self.inner);
        let initial_len = buf.filled().len();
        let res = inner.poll_read(cx, buf);

        // if the read was ok, update bytes_read
        if let Poll::Ready(Ok(())) = &res {
            self.bytes_read
                .fetch_add(buf.filled().len() - initial_len, Ordering::SeqCst);
        }

        res
    }
}

/// A wrapper around [`AsyncWrite`] types that keeps track of the number of written bytes
struct TrackingAsyncWriter<W> {
    inner: W,
    bytes_written: Arc<AtomicUsize>,
}

impl<R> TrackingAsyncWriter<R> {
    fn new(inner: R, bytes_written: Arc<AtomicUsize>) -> Self {
        Self {
            inner,
            bytes_written,
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for TrackingAsyncWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let inner = Pin::new(&mut self.inner);
        let res = inner.poll_write(cx, buf);

        // if the write was ok, update bytes_written
        if let Poll::Ready(Ok(bytes_written)) = &res {
            self.bytes_written
                .fetch_add(*bytes_written, Ordering::SeqCst);
        }

        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        let inner = Pin::new(&mut self.inner);
        let res = inner.poll_write_vectored(cx, bufs);

        // if the write was ok, update bytes_written
        if let Poll::Ready(Ok(bytes_written)) = &res {
            self.bytes_written
                .fetch_add(*bytes_written, Ordering::SeqCst);
        }

        res
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}
