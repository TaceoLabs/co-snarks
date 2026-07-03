//! TLS MPC network

use std::{
    array,
    cmp::Ordering,
    collections::HashMap,
    io::{IoSlice, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs as _},
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    ConnectionStats, DEFAULT_MAX_FRAME_LENGTH, Network, blocking::BlockingChannels,
    config::NetworkConfig,
};
use byteorder::{BigEndian, ReadBytesExt as _, WriteBytesExt as _};
use bytes::Bytes;
use eyre::ContextCompat;
use itertools::Itertools;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::ServerName,
};
use socket2::{Domain, Socket, TcpKeepalive, Type};

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

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
        // rustls' `StreamOwned` does not override `write_vectored`, so the default would
        // emit only the first slice (e.g. an 8-byte length header) as its own TLS record.
        // Coalesce into a single buffer and write once so the framed message stays in one
        // record. This keeps a single copy (as the previous framing did) rather than
        // producing a tiny header record followed by the payload.
        let total: usize = bufs.iter().map(|b| b.len()).sum();
        let mut buf = Vec::with_capacity(total);
        for b in bufs {
            buf.extend_from_slice(b);
        }
        self.write_all(&buf)?;
        Ok(total)
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
    channels: BlockingChannels,
}

impl Drop for TlsNetwork {
    fn drop(&mut self) {
        if let Err(e) = self.channels.flush() {
            tracing::error!("error flushing channels on drop: {e:?}");
        }
    }
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
        let addrs = config
            .parties
            .iter()
            .sorted_by_key(|p| p.id)
            .map(|party| party.dns_name.clone())
            .collect::<Vec<_>>();
        let tls_config = config
            .tls
            .ok_or_else(|| eyre::eyre!("TLS config is required for TlsNetwork"))?;
        let key = tls_config.key;
        let certs = tls_config.certs;
        let timeout = config.timeout;
        let connect_timeout = config.connect_timeout;
        let flush_timeout = config.flush_timeout;
        let max_frame_length = config.max_frame_length.unwrap_or(DEFAULT_MAX_FRAME_LENGTH);

        let mut root_store = RootCertStore::empty();
        for cert in &certs {
            root_store.add(cert.clone())?;
        }
        let client_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certs[id].clone()], key)?;
        // Disable TLS 1.3 session tickets to avoid sending data back via the write half.
        // It never gets read there, thus leading to sporadic errors.
        // We don't need session tickets anyway, as we only ever connect once to each peer.
        server_config.send_tls13_tickets = 0;

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
        socket.set_read_timeout(connect_timeout)?;
        let keepalive = TcpKeepalive::new().with_interval(Duration::from_secs(1));
        socket.set_tcp_keepalive(&keepalive)?;
        socket.bind(&bind_addr.into())?;
        socket.listen(128)?;
        let listener = TcpListener::from(socket);

        let mut nets = array::from_fn(|_| Self {
            id,
            channels: BlockingChannels::new(timeout, flush_timeout, max_frame_length),
        });

        const STREAM_0: u8 = 0;
        const STREAM_1: u8 = 1;

        // For each peer we open two TLS connections, one per direction. They are
        // established in separate iterations of the `s` loop, so buffer the
        // (write, read) halves per (net, peer) and register them together once both
        // are present.
        type Pair = (Option<TlsStream>, Option<TlsStream>);
        let mut pending: Vec<HashMap<usize, Pair>> = (0..N).map(|_| HashMap::new()).collect();

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
                                if let Some(connect_timeout) = connect_timeout {
                                    if let Ok(stream) =
                                        TcpStream::connect_timeout(&addr, connect_timeout)
                                    {
                                        break stream;
                                    } else if start.elapsed() > connect_timeout {
                                        eyre::bail!(
                                            "timeout while connecting to party {other_id} at {addr}"
                                        );
                                    }
                                } else {
                                    if let Ok(stream) = TcpStream::connect(addr) {
                                        break stream;
                                    }
                                }
                                std::thread::sleep(Duration::from_millis(100));
                            };
                            stream.set_write_timeout(timeout)?;
                            stream.set_nodelay(true)?;

                            let name = ServerName::try_from(host_name)?.to_owned();
                            let conn = ClientConnection::new(client_config.clone(), name.clone())?;
                            let mut stream = TlsStream::Client(StreamOwned::new(conn, stream));

                            stream.write_u64::<BigEndian>(i as u64)?;
                            stream.write_u64::<BigEndian>(id as u64)?;
                            stream.write_u8(s)?;

                            // As the connecting party, STREAM_0 is our send direction
                            // and STREAM_1 is our receive direction.
                            let entry = pending[i].entry(other_id).or_insert((None, None));
                            if s == STREAM_0 {
                                entry.0 = Some(stream);
                            } else {
                                entry.1 = Some(stream);
                            }
                        }
                        Ordering::Greater => {
                            let (stream, _) = listener.accept()?;
                            // disable read_timeout again - we only need it for accept
                            let socket = Socket::from(stream);
                            socket.set_read_timeout(None)?;
                            let stream = TcpStream::from(socket);
                            stream.set_write_timeout(timeout)?;
                            stream.set_nodelay(true)?;

                            let conn = ServerConnection::new(server_config.clone())?;
                            let mut stream = TlsStream::Server(StreamOwned::new(conn, stream));

                            let i = stream.read_u64::<BigEndian>()? as usize;
                            let other_id = stream.read_u64::<BigEndian>()? as usize;
                            let s_ = stream.read_u8()?;

                            // As the accepting party, the peer's STREAM_0 is our receive
                            // direction and its STREAM_1 is our send direction.
                            let entry = pending[i].entry(other_id).or_insert((None, None));
                            if s_ == STREAM_0 {
                                entry.1 = Some(stream);
                            } else {
                                entry.0 = Some(stream);
                            }
                        }
                        Ordering::Equal => continue,
                    }
                }
            }
        }

        for (i, net_pending) in pending.into_iter().enumerate() {
            for (other_id, (write_stream, read_stream)) in net_pending {
                let write_stream = write_stream.context("missing TLS send connection")?;
                let read_stream = read_stream.context("missing TLS recv connection")?;
                nets[i]
                    .channels
                    .add_peer(other_id, write_stream, read_stream);
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
