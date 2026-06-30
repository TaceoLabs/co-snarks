//! TLS MPC network

use std::{
    array,
    cmp::Ordering,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs as _},
    path::PathBuf,
    sync::{Arc, atomic::AtomicUsize},
    time::{Duration, Instant},
};

use crate::{
    ConnectionStats, DEFAULT_CONNECTION_TIMEOUT, DEFAULT_MAX_FRAME_LENGTH, Network, config::Address,
};
use byteorder::{BigEndian, ReadBytesExt as _, WriteBytesExt as _};
use bytes::Bytes;
use crossbeam_channel::{Receiver, Sender};
use eyre::ContextCompat;
use intmap::IntMap;
use itertools::Itertools;
use parking_lot::Mutex;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Socket, TcpKeepalive, Type};

/// A party in the network config file.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct NetworkPartyConfig {
    /// The id of the party, 0-based indexing.
    pub id: usize,
    /// The DNS name of the party.
    pub dns_name: Address,
    /// The path to the public certificate of the party.
    pub cert_path: PathBuf,
}

/// A party in the network.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NetworkParty {
    /// The id of the party, 0-based indexing.
    pub id: usize,
    /// The DNS name of the party.
    pub dns_name: Address,
    /// The public certificate of the party.
    pub cert: CertificateDer<'static>,
}

impl NetworkParty {
    /// Construct a new [`NetworkParty`] type.
    pub fn new(id: usize, address: Address, cert: CertificateDer<'static>) -> Self {
        Self {
            id,
            dns_name: address,
            cert,
        }
    }
}

impl TryFrom<NetworkPartyConfig> for NetworkParty {
    type Error = std::io::Error;
    fn try_from(value: NetworkPartyConfig) -> Result<Self, Self::Error> {
        let cert = CertificateDer::from(std::fs::read(value.cert_path)?).into_owned();
        Ok(NetworkParty {
            id: value.id,
            dns_name: value.dns_name,
            cert,
        })
    }
}

/// The network configuration file.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct NetworkConfigFile {
    /// The list of parties in the network.
    pub parties: Vec<NetworkPartyConfig>,
    /// Our own id in the network.
    pub my_id: usize,
    /// The [SocketAddr] we bind to.
    pub bind_addr: SocketAddr,
    /// The path to our private key file.
    pub key_path: PathBuf,
    /// The connection timeout
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub timeout: Option<Duration>,
    /// The max length (in bytes) of a single frame
    #[serde(default)]
    pub max_frame_length: Option<usize>,
}

/// The network configuration.
#[derive(Debug, Eq, PartialEq)]
pub struct NetworkConfig {
    /// The list of parties in the network.
    pub parties: Vec<NetworkParty>,
    /// Our own id in the network.
    pub my_id: usize,
    /// The [SocketAddr] we bind to.
    pub bind_addr: SocketAddr,
    /// The private key.
    pub key: PrivateKeyDer<'static>,
    /// The connection timeout
    pub timeout: Option<Duration>,
    /// The max length (in bytes) of a single frame
    pub max_frame_length: Option<usize>,
}

impl Clone for NetworkConfig {
    fn clone(&self) -> Self {
        Self {
            parties: self.parties.clone(),
            my_id: self.my_id,
            bind_addr: self.bind_addr,
            key: self.key.clone_key(),
            timeout: self.timeout,
            max_frame_length: self.max_frame_length,
        }
    }
}

impl NetworkConfig {
    /// Construct a new [`NetworkConfig`] type.
    pub fn new(
        id: usize,
        bind_addr: SocketAddr,
        key: PrivateKeyDer<'static>,
        parties: Vec<NetworkParty>,
        timeout: Option<Duration>,
        max_frame_length: Option<usize>,
    ) -> Self {
        Self {
            parties,
            my_id: id,
            bind_addr,
            key,
            timeout,
            max_frame_length,
        }
    }
}

impl TryFrom<NetworkConfigFile> for NetworkConfig {
    type Error = std::io::Error;
    fn try_from(value: NetworkConfigFile) -> Result<Self, Self::Error> {
        let parties = value
            .parties
            .into_iter()
            .map(NetworkParty::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(std::fs::read(value.key_path)?))
            .clone_key();
        Ok(NetworkConfig {
            parties,
            my_id: value.my_id,
            bind_addr: value.bind_addr,
            key,
            timeout: value.timeout,
            max_frame_length: value.max_frame_length,
        })
    }
}

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
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            TlsStream::Client(stream) => stream.read(buf),
            TlsStream::Server(stream) => stream.read(buf),
        }
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            TlsStream::Client(stream) => stream.write(buf),
            TlsStream::Server(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            TlsStream::Client(stream) => stream.flush(),
            TlsStream::Server(stream) => stream.flush(),
        }
    }
}

/// Capacity (in frames) of each per-peer send queue. Bounds buffered-but-unsent
/// memory and applies backpressure to `send` when a peer cannot keep up.
const SEND_QUEUE_CAP: usize = 32;

/// A message handed to a peer's background writer thread.
enum WriteMsg {
    /// A complete, length-prefixed frame to write to the stream.
    Frame(Vec<u8>),
    /// Flush the stream and acknowledge on the given channel.
    Flush(Sender<()>),
}

/// Drains [`WriteMsg`]s for a single peer, writing them to `stream`. On the first
/// write error it records the error in `err` and exits; subsequent `send`/`flush`
/// calls observe `err` and surface it. Exits cleanly when all senders are dropped.
fn writer_loop(mut stream: TlsStream, rx: Receiver<WriteMsg>, err: Arc<Mutex<Option<String>>>) {
    for msg in rx.iter() {
        match msg {
            WriteMsg::Frame(buf) => {
                if let Err(e) = stream.write_all(&buf) {
                    *err.lock() = Some(e.to_string());
                    break;
                }
            }
            WriteMsg::Flush(ack) => {
                if let Err(e) = stream.flush() {
                    *err.lock() = Some(e.to_string());
                    let _ = ack.send(());
                    break;
                }
                let _ = ack.send(());
            }
        }
    }
}

/// Given an owned send-direction `stream` for `other_id`, spawn its background
/// writer thread and register the resulting send queue on `net`.
fn setup_sender(net: &mut TlsNetwork, other_id: usize, stream: TlsStream) {
    let (send_tx, send_rx) = crossbeam_channel::bounded(SEND_QUEUE_CAP);
    let err = Arc::new(Mutex::new(None));
    {
        let err = Arc::clone(&err);
        std::thread::spawn(move || writer_loop(stream, send_rx, err));
    }
    net.send
        .insert(other_id, (send_tx, AtomicUsize::default(), err));
}

/// A MPC network using [TlsStream]s
#[derive(Debug)]
#[expect(clippy::complexity)]
pub struct TlsNetwork {
    id: usize,
    send: IntMap<usize, (Sender<WriteMsg>, AtomicUsize, Arc<Mutex<Option<String>>>)>,
    recv: IntMap<usize, (Receiver<eyre::Result<Bytes>>, AtomicUsize)>,
    timeout: Duration,
    max_frame_length: usize,
}

impl TlsNetwork {
    /// Create a new [TlsNetwork]
    pub fn new(config: NetworkConfig) -> eyre::Result<Self> {
        let [net] = Self::networks::<1>(config)?;
        Ok(net)
    }

    /// Create `N` new [TlsNetwork]s
    pub fn networks<const N: usize>(config: NetworkConfig) -> eyre::Result<[Self; N]> {
        let id = config.my_id;
        let bind_addr = config.bind_addr;
        let key = config.key;
        let addrs = config
            .parties
            .iter()
            .sorted_by_key(|p| p.id)
            .map(|party| party.dns_name.clone())
            .collect::<Vec<_>>();
        let certs = config
            .parties
            .into_iter()
            .sorted_by_key(|p| p.id)
            .map(|party| party.cert)
            .collect::<Vec<_>>();
        let timeout = config.timeout.unwrap_or(DEFAULT_CONNECTION_TIMEOUT);
        let max_frame_length = config.max_frame_length.unwrap_or(DEFAULT_MAX_FRAME_LENGTH);

        let mut root_store = RootCertStore::empty();
        for cert in &certs {
            root_store.add(cert.clone())?;
        }
        let client_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certs[id].clone()], key)?;

        let client_config = Arc::new(client_config);
        let server_config = Arc::new(server_config);

        let domain = match bind_addr {
            SocketAddr::V4(_) => Domain::IPV4,
            SocketAddr::V6(_) => Domain::IPV6,
        };
        let socket = Socket::new(domain, Type::STREAM, None)?;
        socket.set_reuse_address(true)?;
        if bind_addr.is_ipv6() {
            socket.set_only_v6(false)?;
        }
        // set read_timeout to get a timeout in accept if no party connects
        socket.set_read_timeout(Some(timeout))?;
        let keepalive = TcpKeepalive::new().with_interval(Duration::from_secs(1));
        socket.set_tcp_keepalive(&keepalive)?;
        socket.bind(&bind_addr.into())?;
        socket.listen(128)?;
        let listener = TcpListener::from(socket);

        let mut nets = array::from_fn(|_| Self {
            id,
            send: IntMap::default(),
            recv: IntMap::default(),
            timeout,
            max_frame_length,
        });

        const STREAM_0: u8 = 0;
        const STREAM_1: u8 = 1;

        for i in 0..N {
            for s in [STREAM_0, STREAM_1] {
                for (other_id, addr) in addrs.iter().enumerate() {
                    let host_name = addr.hostname.clone();
                    let addr = addr
                        .to_socket_addrs()?
                        .next()
                        .context("while converting to SocketAddr")?;
                    match id.cmp(&other_id) {
                        Ordering::Less => {
                            let start = Instant::now();
                            let stream = loop {
                                if let Ok(stream) = TcpStream::connect_timeout(&addr, timeout) {
                                    break stream;
                                }
                                std::thread::sleep(Duration::from_millis(50));
                                if start.elapsed() > timeout {
                                    eyre::bail!("timeout while connecting to {addr}");
                                }
                            };
                            stream.set_write_timeout(Some(timeout))?;
                            stream.set_nodelay(true)?;

                            let name = ServerName::try_from(host_name)?.to_owned();
                            let conn = ClientConnection::new(client_config.clone(), name.clone())?;
                            let mut stream = TlsStream::Client(StreamOwned::new(conn, stream));

                            stream.write_u64::<BigEndian>(i as u64)?;
                            stream.write_u64::<BigEndian>(id as u64)?;
                            stream.write_u8(s)?;

                            if s == STREAM_0 {
                                setup_sender(&mut nets[i], other_id, stream);
                            } else {
                                let (tx, rx) = crossbeam_channel::bounded(32);
                                std::thread::spawn(move || {
                                    loop {
                                        let data = read_next_frame(&mut stream, max_frame_length);
                                        if tx.send(data).is_err() {
                                            break;
                                        }
                                    }
                                });
                                nets[i].recv.insert(other_id, (rx, AtomicUsize::default()));
                            }
                        }
                        Ordering::Greater => {
                            let (stream, _) = listener.accept()?;
                            // disable read_timeout again - we only need it for accept
                            let socket = Socket::from(stream);
                            socket.set_read_timeout(None)?;
                            let stream = TcpStream::from(socket);
                            stream.set_write_timeout(Some(timeout))?;
                            stream.set_nodelay(true)?;

                            let conn = ServerConnection::new(server_config.clone())?;
                            let mut stream = TlsStream::Server(StreamOwned::new(conn, stream));

                            let i = stream.read_u64::<BigEndian>()? as usize;
                            let other_id = stream.read_u64::<BigEndian>()? as usize;
                            let s_ = stream.read_u8()?;

                            if s_ == STREAM_0 {
                                let (tx, rx) = crossbeam_channel::bounded(32);
                                std::thread::spawn(move || {
                                    loop {
                                        let data = read_next_frame(&mut stream, max_frame_length);
                                        if tx.send(data).is_err() {
                                            break;
                                        }
                                    }
                                });
                                nets[i].recv.insert(other_id, (rx, AtomicUsize::default()));
                            } else {
                                setup_sender(&mut nets[i], other_id, stream);
                            }
                        }
                        Ordering::Equal => continue,
                    }
                }
            }
        }

        Ok(nets)
    }
}

impl Network for TlsNetwork {
    fn id(&self) -> usize {
        self.id
    }

    fn send(&self, to: usize, data: Bytes) -> eyre::Result<()> {
        if data.len() > self.max_frame_length {
            eyre::bail!("frame len {} > max {}", data.len(), self.max_frame_length);
        }
        let (tx, sent_bytes, err) = self.send.get(to).context("party id out-of-bounds")?;
        if let Some(e) = err.lock().clone() {
            eyre::bail!("connection to party {to} previously failed: {e}");
        }
        // Coalesce the length prefix and payload into a single buffer so each frame
        // is one `write_all` (one TLS record stream write) on the writer thread.
        let mut frame = Vec::with_capacity(8 + data.len());
        frame.extend_from_slice(&(data.len() as u64).to_be_bytes());
        frame.extend_from_slice(&data);
        sent_bytes.fetch_add(data.len(), std::sync::atomic::Ordering::Relaxed);
        tx.send(WriteMsg::Frame(frame))
            .map_err(|_| eyre::eyre!("writer thread for party {to} terminated"))?;
        Ok(())
    }

    fn recv(&self, from: usize) -> eyre::Result<Bytes> {
        let (queue, recv_bytes) = self.recv.get(from).context("party id out-of-bounds")?;
        let data = queue.recv_timeout(self.timeout)??;
        recv_bytes.fetch_add(data.len(), std::sync::atomic::Ordering::Relaxed);
        Ok(data)
    }

    fn flush(&self) -> eyre::Result<()> {
        for (to, (tx, _, err)) in self.send.iter() {
            let (ack_tx, ack_rx) = crossbeam_channel::bounded(1);
            tx.send(WriteMsg::Flush(ack_tx))
                .map_err(|_| eyre::eyre!("writer thread for party {to} terminated"))?;
            ack_rx
                .recv_timeout(self.timeout)
                .map_err(|_| eyre::eyre!("timed out flushing send queue for party {to}"))?;
            if let Some(e) = err.lock().clone() {
                eyre::bail!("connection to party {to} failed: {e}");
            }
        }
        Ok(())
    }

    fn get_connection_stats(&self) -> ConnectionStats {
        let mut stats = std::collections::BTreeMap::new();
        for (id, (_, sent_bytes, _)) in self.send.iter() {
            let recv_bytes = &self.recv.get(id).expect("was in send so must be in recv").1;
            stats.insert(
                id,
                (
                    sent_bytes.load(std::sync::atomic::Ordering::Relaxed),
                    recv_bytes.load(std::sync::atomic::Ordering::Relaxed),
                ),
            );
        }
        ConnectionStats {
            my_id: self.id,
            stats,
        }
    }
}

fn read_next_frame(stream: &mut TlsStream, max_frame_length: usize) -> eyre::Result<Bytes> {
    let len = stream.read_u64::<BigEndian>()? as usize;
    if len > max_frame_length {
        eyre::bail!("frame len {len} > max {max_frame_length}");
    }
    let mut data = vec![0; len];
    stream.read_exact(&mut data)?;
    Ok(Bytes::from(data))
}
