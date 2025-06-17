//! A simple networking layer for MPC protocols.
#![warn(missing_docs)]
use std::{
    array,
    cmp::Ordering,
    collections::{BTreeMap, HashMap},
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    sync::{Arc, mpsc},
    time::Duration,
};

use byteorder::{BigEndian, ReadBytesExt as _, WriteBytesExt as _};
use bytes::Bytes;
use config::NetworkConfig;
use eyre::{Context as _, ContextCompat};
use futures::{SinkExt, StreamExt as _};
use intmap::IntMap;
use parking_lot::Mutex;
use quinn::{Connection, Endpoint, IdleTimeout, TransportConfig, VarInt};
use quinn::{
    crypto::rustls::QuicClientConfig,
    rustls::{RootCertStore, pki_types::CertificateDer},
};
use rustls::{
    ClientConfig, ClientConnection, ServerConfig, ServerConnection, StreamOwned,
    pki_types::ServerName,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    runtime::Runtime,
};
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

pub mod config;

const DEFAULT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// A MPC network that can be used to send and receive data to and from other patires
///
/// Can be used to send to multiple parties in parallel, but sending to the same party must happen in sequence.
pub trait Network: Send + Sync {
    /// The id of the party
    fn id(&self) -> usize;
    /// Send data to other party
    fn send(&self, to: usize, data: &[u8]) -> eyre::Result<()>;
    /// Receive data from other party
    fn recv(&self, from: usize) -> eyre::Result<Vec<u8>>;
}

#[derive(Debug)]
struct QuicConnectionHandler {
    id: usize,
    rt: Runtime,
    // this is a btreemap because we rely on iteration order
    connections: BTreeMap<usize, Connection>,
    endpoints: Vec<Endpoint>,
}

impl QuicConnectionHandler {
    pub fn new(config: NetworkConfig, rt: Runtime) -> eyre::Result<Self> {
        let id = config.my_id;
        let (connections, endpoints) = rt.block_on(Self::init(config))?;
        Ok(Self {
            id,
            rt,
            connections,
            endpoints,
        })
    }

    async fn init(
        config: NetworkConfig,
    ) -> eyre::Result<(BTreeMap<usize, Connection>, Vec<Endpoint>)> {
        let id = config.my_id;
        let certs: HashMap<usize, CertificateDer> = config
            .parties
            .iter()
            .map(|p| (p.id, p.cert.as_ref().expect("cert is required").clone()))
            .collect();

        let mut root_store = RootCertStore::empty();
        for (id, cert) in &certs {
            root_store
                .add(cert.clone())
                .with_context(|| format!("adding certificate for party {id} to root store"))?;
        }
        let crypto = quinn::rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let client_config = {
            let mut transport_config = TransportConfig::default();
            // we dont set this to timeout, because it is the timeout for a idle connection
            // maybe we want to make this configurable too?
            transport_config.max_idle_timeout(Some(
                IdleTimeout::try_from(config.timeout.unwrap_or(DEFAULT_CONNECTION_TIMEOUT))
                    .unwrap(),
            ));
            // atm clients send keepalive packets
            transport_config.keep_alive_interval(Some(Duration::from_secs(1)));
            let mut client_config =
                quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
            client_config.transport_config(Arc::new(transport_config));
            client_config
        };

        let server_config = quinn::ServerConfig::with_single_cert(
            vec![certs[&id].clone()],
            config.key.expect("key is required"),
        )
        .context("creating our server config")?;
        let our_socket_addr = config.bind_addr;
        let server_endpoint = quinn::Endpoint::server(server_config.clone(), our_socket_addr)?;

        let mut endpoints = vec![server_endpoint.clone()];
        let mut connections = BTreeMap::new();

        for party in config.parties {
            if party.id == id {
                // skip self
                continue;
            }
            if party.id < id {
                // connect to party, we are client
                let party_addresses: Vec<SocketAddr> = party
                    .dns_name
                    .to_socket_addrs()
                    .with_context(|| format!("while resolving DNS name for {}", party.dns_name))?
                    .collect();
                if party_addresses.is_empty() {
                    return Err(eyre::eyre!("could not resolve DNS name {}", party.dns_name));
                }
                let party_addr = party_addresses[0];
                tracing::debug!("party {id} connecting to {} at {party_addr}", party.id);
                let local_client_socket: SocketAddr = match party_addr {
                    SocketAddr::V4(_) => {
                        "0.0.0.0:0".parse().expect("hardcoded IP address is valid")
                    }
                    SocketAddr::V6(_) => "[::]:0".parse().expect("hardcoded IP address is valid"),
                };
                let endpoint = quinn::Endpoint::client(local_client_socket)
                    .with_context(|| format!("creating client endpoint to party {}", party.id))?;
                let conn = endpoint
                    .connect_with(client_config.clone(), party_addr, &party.dns_name.hostname)
                    .with_context(|| {
                        format!("setting up client connection with party {}", party.id)
                    })?
                    .await
                    .with_context(|| format!("connecting as a client to party {}", party.id))?;
                let mut uni = conn.open_uni().await?;
                uni.write_u32(u32::try_from(id).expect("party id fits into u32"))
                    .await?;
                uni.flush().await?;
                uni.finish()?;
                tracing::trace!(
                    "Conn with id {} from {} to {}",
                    conn.stable_id(),
                    endpoint.local_addr().unwrap(),
                    conn.remote_address(),
                );
                tracing::debug!("party {id} connected to {}", party.id);
                assert!(connections.insert(party.id, conn).is_none());
                endpoints.push(endpoint);
            } else {
                // we are the server, accept a connection
                tracing::debug!("party {id} listening on {our_socket_addr}");
                match tokio::time::timeout(
                    config.timeout.unwrap_or(DEFAULT_CONNECTION_TIMEOUT),
                    server_endpoint.accept(),
                )
                .await
                {
                    Ok(Some(maybe_conn)) => {
                        let conn = maybe_conn.await?;
                        tracing::trace!(
                            "Conn with id {} from {} to {}",
                            conn.stable_id(),
                            server_endpoint.local_addr().unwrap(),
                            conn.remote_address(),
                        );
                        let mut uni = conn.accept_uni().await?;
                        let other_party_id = uni.read_u32().await?;
                        tracing::debug!("party {id} got conn from {other_party_id}");
                        assert!(
                            connections
                                .insert(
                                    usize::try_from(other_party_id).expect("u32 fits into usize"),
                                    conn
                                )
                                .is_none()
                        );
                    }
                    Ok(None) => {
                        eyre::bail!(
                            "server endpoint did not accept a connection from party {}",
                            party.id
                        )
                    }
                    Err(_) => {
                        eyre::bail!(
                            "party {} did not connect within 60 seconds - timeout",
                            party.id
                        )
                    }
                }
            }
        }

        Ok((connections, endpoints))
    }

    #[expect(clippy::complexity)]
    pub fn get_streams(
        &self,
    ) -> eyre::Result<(
        IntMap<usize, tokio::sync::mpsc::Sender<Vec<u8>>>,
        IntMap<usize, Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>>,
    )> {
        let mut send = IntMap::with_capacity(self.connections.len() - 1);
        let mut recv = IntMap::with_capacity(self.connections.len() - 1);
        for (&id, conn) in self.connections.iter() {
            let (send_stream, recv_stream) = self.rt.block_on(async {
                if id < self.id {
                    // we are the client, so we are the receiver
                    let (mut send_stream, mut recv_stream) = conn.open_bi().await?;
                    send_stream.write_u32(self.id as u32).await?;
                    let their_id = recv_stream.read_u32().await?;
                    assert!(their_id == id as u32);
                    eyre::Ok((send_stream, recv_stream))
                } else {
                    // we are the server, so we are the sender
                    let (mut send_stream, mut recv_stream) = conn.accept_bi().await?;
                    let their_id = recv_stream.read_u32().await?;
                    assert!(their_id == id as u32);
                    send_stream.write_u32(self.id as u32).await?;
                    eyre::Ok((send_stream, recv_stream))
                }
            })?;

            // set max frame length to 1Tb and length_field_length to 5 bytes
            const NUM_BYTES: usize = 5;
            let codec = LengthDelimitedCodec::builder()
                .length_field_type::<u64>() // u64 because this is the type the length is decoded into, and u32 doesnt fit 5 bytes
                .length_field_length(NUM_BYTES)
                .max_frame_length(1usize << (NUM_BYTES * 8))
                .new_codec();

            let mut write = FramedWrite::new(send_stream, codec.clone());
            let mut read = FramedRead::new(recv_stream, codec);

            let (send_tx, mut send_rx) = tokio::sync::mpsc::channel(32);
            let (recv_tx, recv_rx) = tokio::sync::mpsc::channel(32);

            self.rt.spawn(async move {
                while let Some(frame) = send_rx.recv().await {
                    write.send(Bytes::from(frame)).await?;
                }
                eyre::Ok(())
            });

            self.rt.spawn(async move {
                while let Some(Ok(frame)) = read.next().await {
                    recv_tx.send(frame.to_vec()).await?;
                }
                eyre::Ok(())
            });

            assert!(send.insert(id, send_tx).is_none());
            assert!(recv.insert(id, Mutex::new(recv_rx)).is_none());
        }
        Ok((send, recv))
    }

    /// Shutdown all connections, and call [`quinn::Endpoint::wait_idle`] on all of them
    pub async fn shutdown(&self) -> eyre::Result<()> {
        for (id, conn) in self.connections.iter() {
            if self.id < *id {
                let mut send = conn.open_uni().await?;
                send.write_all(b"done").await?;
            } else {
                let mut recv = conn.accept_uni().await?;
                let mut buffer = vec![0u8; b"done".len()];
                recv.read_exact(&mut buffer).await.map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "failed to recv done msg")
                })?;
                tracing::debug!("party {} closing conn = {id}", self.id);
                conn.close(
                    0u32.into(),
                    format!("close from party {}", self.id).as_bytes(),
                );
            }
        }
        for endpoint in self.endpoints.iter() {
            endpoint.wait_idle().await;
            endpoint.close(VarInt::from_u32(0), &[]);
        }
        Ok(())
    }
}

impl Drop for QuicConnectionHandler {
    fn drop(&mut self) {
        // ignore errors in drop
        let _ = self.rt.block_on(self.shutdown());
    }
}

/// A MPC network using the QUIC protocol
#[derive(Debug)]
pub struct QuicNetwork {
    id: usize,
    send: IntMap<usize, tokio::sync::mpsc::Sender<Vec<u8>>>,
    recv: IntMap<usize, Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>>,
    conn_handler: Arc<QuicConnectionHandler>,
    timeout: Duration,
}

impl QuicNetwork {
    /// Create a new [QuicNetwork]
    pub fn new(config: NetworkConfig) -> eyre::Result<Self> {
        config.check_config()?;
        let id = config.my_id;
        let timeout = config.timeout.unwrap_or(DEFAULT_CONNECTION_TIMEOUT);
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let conn_handler = QuicConnectionHandler::new(config, rt)?;
        let (send, recv) = conn_handler.get_streams()?;
        Ok(QuicNetwork {
            id,
            send,
            recv,
            conn_handler: Arc::new(conn_handler),
            timeout,
        })
    }

    /// Create a network fork with new streams for the same connections
    pub fn fork(&self) -> eyre::Result<Self> {
        let id = self.id;
        let (send, recv) = self.conn_handler.get_streams()?;
        let conn_handler = Arc::clone(&self.conn_handler);
        let timeout = self.timeout;
        Ok(QuicNetwork {
            id,
            send,
            recv,
            conn_handler,
            timeout,
        })
    }

    /// Prints the connection statistics.
    pub fn print_connection_stats(&self, out: &mut impl std::io::Write) -> std::io::Result<()> {
        for (i, conn) in &self.conn_handler.connections {
            let stats = conn.stats();
            writeln!(
                out,
                "Connection {} stats:\n\tSENT: {} bytes\n\tRECV: {} bytes",
                i, stats.udp_tx.bytes, stats.udp_rx.bytes
            )?;
        }
        Ok(())
    }
}

impl Network for QuicNetwork {
    fn id(&self) -> usize {
        self.id
    }

    fn send(&self, to: usize, data: &[u8]) -> eyre::Result<()> {
        let stream = self.send.get(to).context("while get stream in send")?;
        tracing::info!("sending to {to}");
        stream.blocking_send(data.to_vec())?;
        Ok(())
    }

    fn recv(&self, from: usize) -> eyre::Result<Vec<u8>> {
        let mut queue = self
            .recv
            .get(from)
            .context("while get stream in recv")?
            .lock();
        queue.blocking_recv().context("while recv")
    }
}

/// A MPC network using [TcpStream]s
#[derive(Debug)]
pub struct TcpNetwork {
    id: usize,
    send: IntMap<usize, Mutex<TcpStream>>,
    recv: IntMap<usize, Mutex<mpsc::Receiver<Vec<u8>>>>,
    timeout: Duration,
}

impl TcpNetwork {
    /// Create a new [TcpNetwork]
    pub fn new(config: NetworkConfig) -> eyre::Result<Self> {
        let [net] = Self::networks::<1>(config)?;
        Ok(net)
    }

    /// Create `N` new [TcpNetwork]
    pub fn networks<const N: usize>(config: NetworkConfig) -> eyre::Result<[Self; N]> {
        let id = config.my_id;
        let bind_addr = config.bind_addr;
        let addrs = config
            .parties
            .into_iter()
            .map(|party| party.dns_name)
            .collect::<Vec<_>>();
        let timeout = config.timeout.unwrap_or(DEFAULT_CONNECTION_TIMEOUT);

        let listener = TcpListener::bind(bind_addr)?;

        let mut nets = array::from_fn(|_| Self {
            id,
            send: IntMap::default(),
            recv: IntMap::default(),
            timeout,
        });

        for i in 0..N {
            for (other_id, addr) in addrs.iter().enumerate() {
                match id.cmp(&other_id) {
                    Ordering::Less => {
                        let mut stream = loop {
                            if let Ok(stream) = TcpStream::connect(addr) {
                                break stream;
                            }
                            std::thread::sleep(Duration::from_millis(50));
                        };
                        stream.set_write_timeout(Some(timeout))?;
                        stream.set_nodelay(true)?;
                        stream.write_u64::<BigEndian>(i as u64)?;
                        stream.write_u64::<BigEndian>(id as u64)?;
                        nets[i]
                            .send
                            .insert(other_id, Mutex::new(stream.try_clone().unwrap()));
                        let (tx, rx) = mpsc::channel();
                        std::thread::spawn(move || {
                            loop {
                                let len = stream.read_u32::<BigEndian>()? as usize;
                                let mut data = vec![0; len];
                                stream.read_exact(&mut data)?;
                                tx.send(data)?;
                            }
                            #[allow(unreachable_code)]
                            eyre::Ok(())
                        });
                        nets[i].recv.insert(other_id, Mutex::new(rx));
                    }
                    Ordering::Greater => {
                        let (mut stream, _) = listener.accept()?;
                        stream.set_write_timeout(Some(timeout))?;
                        stream.set_nodelay(true)?;
                        let i = stream.read_u64::<BigEndian>()? as usize;
                        let other_id = stream.read_u64::<BigEndian>()? as usize;
                        nets[i]
                            .send
                            .insert(other_id, Mutex::new(stream.try_clone().unwrap()));
                        let (tx, rx) = mpsc::channel();
                        std::thread::spawn(move || {
                            loop {
                                let len = stream.read_u32::<BigEndian>()? as usize;
                                let mut data = vec![0; len];
                                stream.read_exact(&mut data)?;
                                tx.send(data)?;
                            }
                            #[allow(unreachable_code)]
                            eyre::Ok(())
                        });
                        nets[i].recv.insert(other_id, Mutex::new(rx));
                    }
                    Ordering::Equal => continue,
                }
            }
        }

        Ok(nets)
    }
}

impl Network for TcpNetwork {
    fn id(&self) -> usize {
        self.id
    }

    fn send(&self, to: usize, data: &[u8]) -> eyre::Result<()> {
        let mut stream = self
            .send
            .get(to)
            .context("while get stream in send")?
            .lock();
        stream.write_u32::<BigEndian>(data.len() as u32)?;
        stream.write_all(data)?;
        Ok(())
    }

    fn recv(&self, from: usize) -> eyre::Result<Vec<u8>> {
        let queue = self
            .recv
            .get(from)
            .context("while get stream in recv")?
            .lock();
        Ok(queue.recv_timeout(self.timeout)?)
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

/// A MPC network using [TlsStream]s
#[derive(Debug)]
pub struct TlsNetwork {
    id: usize,
    send: IntMap<usize, Mutex<TlsStream>>,
    recv: IntMap<usize, Mutex<mpsc::Receiver<Vec<u8>>>>,
    timeout: Duration,
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
            .map(|party| party.dns_name.clone())
            .collect::<Vec<_>>();
        let certs = config
            .parties
            .into_iter()
            .map(|party| party.cert.expect("cert is required"))
            .collect::<Vec<_>>();
        let timeout = config.timeout.unwrap_or(DEFAULT_CONNECTION_TIMEOUT);

        let mut root_store = RootCertStore::empty();
        for cert in &certs {
            root_store.add(cert.clone())?;
        }
        let client_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certs[id].clone()], key.expect("key is required"))?;

        let client_config = Arc::new(client_config);
        let server_config = Arc::new(server_config);

        let listener = TcpListener::bind(bind_addr)?;

        let mut nets = array::from_fn(|_| Self {
            id,
            send: IntMap::default(),
            recv: IntMap::default(),
            timeout,
        });

        const STREAM_0: u8 = 0;
        const STREAM_1: u8 = 1;

        for i in 0..N {
            for s in [STREAM_0, STREAM_1] {
                for (other_id, addr) in addrs.iter().enumerate() {
                    match id.cmp(&other_id) {
                        Ordering::Less => {
                            let stream = loop {
                                if let Ok(stream) = TcpStream::connect(addr) {
                                    break stream;
                                }
                                std::thread::sleep(Duration::from_millis(50));
                            };
                            stream.set_write_timeout(Some(timeout))?;
                            stream.set_nodelay(true)?;

                            let name = ServerName::try_from(addr.hostname.clone())?.to_owned();
                            let conn = ClientConnection::new(client_config.clone(), name.clone())?;
                            let mut stream = StreamOwned::new(conn, stream);

                            stream.write_u64::<BigEndian>(i as u64)?;
                            stream.write_u64::<BigEndian>(id as u64)?;
                            stream.write_u8(s)?;

                            if s == STREAM_0 {
                                nets[i]
                                    .send
                                    .insert(other_id, Mutex::new(TlsStream::Client(stream)));
                            } else {
                                let (tx, rx) = mpsc::channel();
                                std::thread::spawn(move || {
                                    loop {
                                        let len = stream.read_u32::<BigEndian>()? as usize;
                                        let mut data = vec![0; len];
                                        stream.read_exact(&mut data)?;
                                        tx.send(data).unwrap();
                                    }
                                    #[allow(unreachable_code)]
                                    eyre::Ok(())
                                });
                                nets[i].recv.insert(other_id, Mutex::new(rx));
                            }
                        }
                        Ordering::Greater => {
                            let (stream, _) = listener.accept()?;
                            stream.set_write_timeout(Some(timeout))?;
                            stream.set_nodelay(true)?;

                            let conn = ServerConnection::new(server_config.clone())?;
                            let mut stream = StreamOwned::new(conn, stream);

                            let i = stream.read_u64::<BigEndian>()? as usize;
                            let other_id = stream.read_u64::<BigEndian>()? as usize;
                            let s_ = stream.read_u8()?;

                            if s_ == STREAM_0 {
                                let (tx, rx) = mpsc::channel();
                                std::thread::spawn(move || {
                                    loop {
                                        let len = stream.read_u32::<BigEndian>()? as usize;
                                        let mut data = vec![0; len];
                                        stream.read_exact(&mut data)?;
                                        tx.send(data).unwrap();
                                    }
                                    #[allow(unreachable_code)]
                                    eyre::Ok(())
                                });
                                nets[i].recv.insert(other_id, Mutex::new(rx));
                            } else {
                                nets[i]
                                    .send
                                    .insert(other_id, Mutex::new(TlsStream::Server(stream)));
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

    fn send(&self, to: usize, data: &[u8]) -> eyre::Result<()> {
        let mut stream = self
            .send
            .get(to)
            .context("while get stream in send")?
            .lock();
        stream.write_u32::<BigEndian>(data.len() as u32)?;
        stream.write_all(data)?;
        Ok(())
    }

    fn recv(&self, from: usize) -> eyre::Result<Vec<u8>> {
        let queue = self
            .recv
            .get(from)
            .context("while get stream in recv")?
            .lock();
        Ok(queue.recv_timeout(self.timeout)?)
    }
}

/// A MPC network using [mpsc::channel]s. Used for testing.
#[derive(Debug)]
pub struct TestNetwork {
    id: usize,
    send: IntMap<usize, mpsc::Sender<Vec<u8>>>,
    recv: IntMap<usize, Mutex<mpsc::Receiver<Vec<u8>>>>,
}

impl TestNetwork {
    /// Create new [TestNetwork]s for `num_parties`.
    pub fn new(num_parties: usize) -> Vec<Self> {
        let mut networks = Vec::with_capacity(num_parties);
        let mut senders = Vec::new();
        let mut receivers = Vec::new();

        for _ in 0..num_parties {
            senders.push(IntMap::new());
            receivers.push(IntMap::new());
        }

        #[allow(clippy::needless_range_loop)]
        for i in 0..num_parties {
            for j in 0..num_parties {
                if i != j {
                    let (tx, rx) = mpsc::channel();
                    senders[i].insert(j, tx);
                    receivers[j].insert(i, Mutex::new(rx));
                }
            }
        }

        for (id, (send, recv)) in senders.into_iter().zip(receivers).enumerate() {
            networks.push(TestNetwork { id, send, recv });
        }

        networks
    }

    /// Create new [TestNetwork]s for 3 parties.
    pub fn new_3_parties() -> [Self; 3] {
        Self::new(3).try_into().expect("correct len")
    }
}

impl Network for TestNetwork {
    fn id(&self) -> usize {
        self.id
    }

    fn send(&self, to: usize, data: &[u8]) -> eyre::Result<()> {
        self.send
            .get(to)
            .context("while get stream in send")?
            .send(data.to_owned())?;
        Ok(())
    }

    fn recv(&self, from: usize) -> eyre::Result<Vec<u8>> {
        Ok(self
            .recv
            .get(from)
            .context("while get stream in recv")?
            .lock()
            .recv_timeout(DEFAULT_CONNECTION_TIMEOUT)?)
    }
}

// This implements a dummy network that is used for plain variants of MPC protocols
impl Network for () {
    fn id(&self) -> usize {
        0
    }

    fn send(&self, _to: usize, _data: &[u8]) -> eyre::Result<()> {
        Ok(())
    }

    fn recv(&self, _from: usize) -> eyre::Result<Vec<u8>> {
        Ok(vec![])
    }
}
