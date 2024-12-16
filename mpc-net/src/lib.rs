//! A simple networking layer for MPC protocols.
#![warn(missing_docs)]
use std::{
    collections::{BTreeMap, HashMap},
    io,
    net::{SocketAddr, ToSocketAddrs},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use channel::{BincodeChannel, BytesChannel, Channel, ChannelHandle};
use codecs::BincodeCodec;
use color_eyre::eyre::{bail, Context, ContextCompat, Report};
use config::NetworkConfig;
use queue::{ChannelQueue, CreateJob, QueueJob};
use serde::{de::DeserializeOwned, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc::{self},
};
use tokio_rustls::{
    rustls::{
        pki_types::{CertificateDer, ServerName},
        ClientConfig, RootCertStore, ServerConfig,
    },
    TlsAcceptor, TlsConnector,
};
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};
use tracking_rw::{TrackingAsyncReader, TrackingAsyncWriter};

pub mod channel;
pub mod codecs;
pub mod config;
pub mod queue;
mod tracking_rw;

/// Type alias for a [tokio_rustls::TlsStream] over a [TcpStream].
type TlsStream = tokio_rustls::TlsStream<TcpStream>;

/// A duplex TLS stream that uses one stream for sending and one for receiving.
/// Splitting a single stream would add unwanted syncronization primitives.
#[derive(Debug)]
pub(crate) struct DuplexTlsStream {
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

#[derive(Debug)]
struct ConnectionInfo {
    party_hostname: String,
    party_addr: SocketAddr,
    sent: Arc<AtomicUsize>,
    recv: Arc<AtomicUsize>,
}

impl ConnectionInfo {
    pub fn new(party_hostname: String, party_addr: SocketAddr) -> Self {
        Self {
            party_hostname,
            party_addr,
            sent: Arc::default(),
            recv: Arc::default(),
        }
    }
}

/// A network handler for MPC protocols.
pub struct MpcNetworkHandler {
    // this is a btreemap because we rely on iteration order
    conn_infos: BTreeMap<usize, ConnectionInfo>,
    my_id: usize,
    listener: TcpListener,
    acceptor: TlsAcceptor,
    connector: TlsConnector,
}

impl MpcNetworkHandler {
    /// Initialize the [MpcNetworkHandler] based on the provided [NetworkConfig].
    pub async fn init(config: NetworkConfig) -> Result<Self, Report> {
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

        let mut conn_infos = BTreeMap::new();

        for party in config.parties.iter() {
            if party.id == config.my_id {
                // skip self
                continue;
            }
            let party_addr = party
                .dns_name
                .to_socket_addrs()
                .with_context(|| format!("while resolving DNS name for {}", party.dns_name))?
                .next()
                .with_context(|| format!("could not resolve DNS name {}", party.dns_name))?;
            let party_hostname = party.dns_name.hostname.clone();

            for _ in 0..config.conn_queue_size {
                let conn = ConnectionInfo::new(party_hostname.clone(), party_addr);
                conn_infos.insert(party.id, conn);
            }
        }

        Ok(MpcNetworkHandler {
            conn_infos,
            my_id: config.my_id,
            listener,
            acceptor,
            connector,
        })
    }

    /// Tries to establish a connection to other parties in the network.
    pub(crate) async fn establish(&self) -> Result<HashMap<usize, DuplexTlsStream>, Report> {
        let mut streams = HashMap::new();
        let mut unordered_strames = HashMap::new();
        for (id, conn_info) in self.conn_infos.iter() {
            if *id < self.my_id {
                // connect to party, we are client
                let domain = ServerName::try_from(conn_info.party_hostname.as_str())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))?
                    .to_owned();

                let mut send = None;
                let mut recv = None;
                // create 2 streams per stream to get full duplex with tls streams
                for split in [DuplexTlsStream::SPLIT0, DuplexTlsStream::SPLIT1] {
                    let stream = loop {
                        if let Ok(stream) = TcpStream::connect(conn_info.party_addr).await {
                            break stream;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    };
                    // this removes buffering of tcp packets, very important for latency of small packets
                    stream.set_nodelay(true)?;
                    let mut stream = self.connector.connect(domain.clone(), stream).await?;
                    stream.write_u64(self.my_id as u64).await?;
                    stream.write_u8(split).await?;
                    if split == DuplexTlsStream::SPLIT0 {
                        send = Some(stream);
                    } else {
                        recv = Some(stream);
                    }
                }

                tracing::trace!("Party {}: connected stream to party {}", id, self.my_id);

                let send = send.expect("not none after connect was succesful");
                let recv = recv.expect("not none after connect was succesful");

                assert!(streams
                    .insert(*id, DuplexTlsStream::new(send.into(), recv.into()))
                    .is_none());
            } else {
                // we are the server, accept connections
                // accept 2 splits and store them with (party_id, split) so we know were they belong
                for _ in 0..2 {
                    let (stream, _peer_addr) = self.listener.accept().await?;
                    // this removes buffering of tcp packets, very important for latency of small packets
                    stream.set_nodelay(true)?;
                    let mut stream = self.acceptor.accept(stream).await?;
                    let party_id = stream.read_u64().await? as usize;
                    let split = stream.read_u8().await?;
                    assert!(unordered_strames
                        .insert((party_id, split), stream)
                        .is_none());
                }
            }
        }

        // assign streams to the right party and duplex half
        // we accepted streams for all parties with id > my_id, so we can iter from my_id + 1..num_parties
        for id in self.my_id + 1..self.conn_infos.len() + 1 {
            // send and recv is swapped here compared to above
            let recv = unordered_strames
                .remove(&(id, DuplexTlsStream::SPLIT0))
                .context(format!("get recv for party {}", id))
                .unwrap();
            let send = unordered_strames
                .remove(&(id, DuplexTlsStream::SPLIT1))
                .context(format!("get send for party {}", id))
                .unwrap();
            assert!(streams
                .insert(id, DuplexTlsStream::new(send.into(), recv.into()))
                .is_none());
        }

        if !unordered_strames.is_empty() {
            bail!("no stream should remain");
        }

        Ok(streams)
    }

    /// Create a [ChannelQueue] that holds `size` number of [ChannelHandle]s per party.
    /// This queue can be used to quickly get existing connections and create new ones in the background.
    pub async fn queue(net_handler: Self, size: usize) -> eyre::Result<ChannelQueue> {
        let mut init_queue = Vec::new();
        for _ in 0..size {
            init_queue.push(net_handler.get_byte_channels_managed().await?);
        }

        let (queue_sender, queue_receiver) = mpsc::channel::<QueueJob>(size);
        let (create_sender, create_receiver) = mpsc::channel::<CreateJob>(size);

        tokio::spawn(queue::create_channel_actor(
            net_handler,
            create_receiver,
            queue_sender.clone(),
        ));

        tokio::spawn(queue::get_channel_actor(
            init_queue,
            create_sender,
            queue_receiver,
        ));

        Ok(ChannelQueue::new(queue_sender))
    }

    /// Returns the number of sent and received bytes.
    pub fn get_send_receive(&self, i: usize) -> std::io::Result<(usize, usize)> {
        let conn = self
            .conn_infos
            .get(&i)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such connection"))?;
        Ok((
            conn.sent.load(Ordering::SeqCst),
            conn.recv.load(Ordering::SeqCst),
        ))
    }

    /// Prints the connection statistics.
    pub fn print_connection_stats(&self, out: &mut impl std::io::Write) -> std::io::Result<()> {
        for (i, conn) in &self.conn_infos {
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

    /// Get a [Channel] to each party. This establishes a new Connection with each party.
    pub async fn get_custom_channels<
        MSend,
        MRecv,
        C: Encoder<MSend, Error = io::Error>
            + Decoder<Item = MRecv, Error = io::Error>
            + 'static
            + Clone,
    >(
        &self,
        codec: C,
    ) -> eyre::Result<HashMap<usize, Channel<impl AsyncRead, impl AsyncWrite, C>>> {
        self.establish()
            .await?
            .into_iter()
            .map(|(id, stream)| {
                let conn_info = self.conn_infos.get(&id).context("while get conn info")?;
                let recv = TrackingAsyncReader::new(stream.recv, conn_info.recv.clone());
                let send = TrackingAsyncWriter::new(stream.send, conn_info.sent.clone());
                Ok((id, Channel::new(recv, send, codec.clone())))
            })
            .collect()
    }

    /// Get a [Channel] to each party. This establishes a new Connection with each party.
    pub async fn get_byte_channels(
        &self,
    ) -> eyre::Result<HashMap<usize, BytesChannel<impl AsyncRead, impl AsyncWrite>>> {
        // set max frame length to 1Tb and length_field_length to 5 bytes
        const NUM_BYTES: usize = 5;
        let codec = LengthDelimitedCodec::builder()
            .length_field_type::<u64>() // u64 because this is the type the length is decoded into, and u32 doesnt fit 5 bytes
            .length_field_length(NUM_BYTES)
            .max_frame_length(1usize << (NUM_BYTES * 8))
            .new_codec();
        self.get_custom_channels(codec).await
    }

    /// Get a [Channel] to each party. This establishes a new Connection with each party.
    pub async fn get_serde_bincode_channels<M: Serialize + DeserializeOwned + 'static>(
        &self,
    ) -> eyre::Result<HashMap<usize, BincodeChannel<impl AsyncRead, impl AsyncWrite, M>>> {
        let bincodec = BincodeCodec::<M>::new();
        self.get_custom_channels(bincodec).await
    }

    /// Get a [ChannelHandle] to each party. This establishes a new Connection with each party.
    /// Reads and writes are handled in tokio tasks. On drop, these tasks are awaited.
    pub async fn get_custom_channels_managed<
        MSend: std::fmt::Debug + std::marker::Send + 'static,
        MRecv: std::fmt::Debug + std::marker::Send + 'static,
        C: Encoder<MSend, Error = io::Error>
            + Decoder<Item = MRecv, Error = io::Error>
            + 'static
            + Clone
            + std::marker::Send,
    >(
        &self,
        codec: C,
    ) -> eyre::Result<HashMap<usize, ChannelHandle<MSend, MRecv>>> {
        Ok(self
            .get_custom_channels(codec)
            .await?
            .into_iter()
            .map(|(id, chan)| (id, ChannelHandle::spawn(chan)))
            .collect())
    }

    /// Get a [ChannelHandle] to each party. This establishes a new Connection with each party.
    /// Reads and writes are handled in tokio tasks. On drop, these tasks are awaited.
    pub async fn get_byte_channels_managed(
        &self,
    ) -> eyre::Result<HashMap<usize, ChannelHandle<Bytes, BytesMut>>> {
        // set max frame length to 1Tb and length_field_length to 5 bytes
        const NUM_BYTES: usize = 5;
        let codec = LengthDelimitedCodec::builder()
            .length_field_type::<u64>() // u64 because this is the type the length is decoded into, and u32 doesnt fit 5 bytes
            .length_field_length(NUM_BYTES)
            .max_frame_length(1usize << (NUM_BYTES * 8))
            .new_codec();
        self.get_custom_channels_managed(codec).await
    }
}
