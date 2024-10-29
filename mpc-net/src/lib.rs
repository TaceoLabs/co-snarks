//! A simple networking layer for MPC protocols.
#![warn(missing_docs)]
use std::{
    collections::{BTreeMap, HashMap},
    io::{self, Read, Write},
    net::{TcpListener, TcpStream, ToSocketAddrs},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use bytes::{Bytes, BytesMut};
use channel::{Channel, ChannelHandle, ChannelTasks};
use color_eyre::eyre::{bail, Context as Ctx, ContextCompat, Report};
use config::NetworkConfig;
use rustls::{
    pki_types::{CertificateDer, ServerName},
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};

pub mod channel;
pub mod config;

// TODO get this from network config
const STREAMS_PER_CONN: usize = 8;

/// A wrapper type for client and server TLS streams
#[derive(Debug)]
pub enum TlsStream {
    /// A Stream with a client connection
    Client(StreamOwned<ClientConnection, TcpStream>),
    /// A Stream with a sever connection
    Server(StreamOwned<ServerConnection, TcpStream>),
}

impl From<StreamOwned<ClientConnection, TcpStream>> for TlsStream {
    fn from(value: StreamOwned<ClientConnection, TcpStream>) -> Self {
        Self::Client(value)
    }
}

impl From<StreamOwned<ServerConnection, TcpStream>> for TlsStream {
    fn from(value: StreamOwned<ServerConnection, TcpStream>) -> Self {
        Self::Server(value)
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            TlsStream::Client(stream) => stream.read(buf),
            TlsStream::Server(stream) => stream.read(buf),
        }
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            TlsStream::Client(stream) => stream.write(buf),
            TlsStream::Server(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            TlsStream::Client(stream) => stream.flush(),
            TlsStream::Server(stream) => stream.flush(),
        }
    }
}

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
    pub fn establish(config: NetworkConfig) -> Result<Self, Report> {
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

        let listener = TcpListener::bind(our_socket_addr)?;
        let client_config = Arc::new(client_config);
        let server_config = Arc::new(server_config);

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
                            if let Ok(stream) = TcpStream::connect(party_addr) {
                                break stream;
                            }
                            std::thread::sleep(Duration::from_millis(100));
                        };
                        stream.set_nodelay(true)?;

                        let conn =
                            rustls::ClientConnection::new(client_config.clone(), domain.clone())
                                .unwrap();
                        let mut stream = rustls::StreamOwned::new(conn, stream);

                        stream.write_u64::<NetworkEndian>(config.my_id as u64)?;
                        stream.write_u64::<NetworkEndian>(stream_id as u64)?;
                        stream.write_u8(split)?;
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
                    // timeout if no connections is accepted after 60 seconds
                    let (sender, receiver) = std::sync::mpsc::channel();
                    let listener = listener.try_clone()?;
                    std::thread::spawn(move || sender.send(listener.accept()));
                    let (stream, _peer_addr) = receiver.recv_timeout(Duration::from_secs(60))??;

                    stream.set_nodelay(true)?;
                    let conn = rustls::ServerConnection::new(server_config.clone())?;
                    let mut stream = rustls::StreamOwned::new(conn, stream);
                    let party_id = stream.read_u64::<NetworkEndian>()? as usize;
                    let stream_id = stream.read_u64::<NetworkEndian>()? as usize;
                    let split = stream.read_u8()?;
                    tracing::trace!(
                        "Party {}: accpeted stream {stream_id} from party {party_id}",
                        config.my_id
                    );
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
            tasks: ChannelTasks::new(),
            my_id: config.my_id,
        })
    }

    /// Create a new [`ChannelHandle`] from a [`Channel`]. This spawns a new tokio task that handles the read and write jobs so they can happen concurrently.
    pub fn spawn<R, W>(&mut self, chan: Channel<R, W>) -> ChannelHandle<Bytes, BytesMut>
    where
        R: Read + std::marker::Send + 'static,
        W: Write + std::marker::Send + 'static,
    {
        self.tasks.spawn(chan)
    }

    // TODO?
    // /// Shutdown the network, waiting until all read and write tasks are completed. This happens automatically, when the network handler is dropped.
    // pub async fn shutdown(&mut self) -> Result<(), JoinError> {
    //     self.tasks.shutdown().await
    // }

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

    /// Get a [Channel] to party with `id` using the provided codec. This pops a stream from the pool.
    pub fn get_channel(&mut self, id: &usize) -> Option<Channel<TlsStream, TlsStream>> {
        debug_assert!(*id != self.my_id);
        if let Some(conn) = self.connections.get_mut(id) {
            if let Some(stream) = conn.streams.pop() {
                return Some(Channel::new(
                    stream.recv,
                    stream.send,
                    conn.recv.clone(),
                    conn.sent.clone(),
                ));
            }
        }
        None
    }

    /// Get a [Channel] to each party using the provided codec. This pops a stream from each pool.
    pub fn get_channels(&mut self) -> Option<HashMap<usize, Channel<TlsStream, TlsStream>>> {
        let mut channels = HashMap::new();
        let party_ids: Vec<_> = self.connections.keys().cloned().collect();
        for id in party_ids {
            let chan = self.get_channel(&id)?;
            channels.insert(id, chan);
        }
        Some(channels)
    }
}
