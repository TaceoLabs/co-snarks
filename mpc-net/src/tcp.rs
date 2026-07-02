//! TCP MPC network

use std::{
    array,
    cmp::Ordering,
    net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    time::{Duration, Instant},
};

use crate::{
    ConnectionStats, DEFAULT_MAX_FRAME_LENGTH, Network, blocking::BlockingChannels, config::Address,
};
use byteorder::{BigEndian, ReadBytesExt as _, WriteBytesExt as _};
use bytes::Bytes;
use eyre::ContextCompat;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Socket, TcpKeepalive, Type};

/// A party in the network.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct NetworkParty {
    /// The id of the party, 0-based indexing.
    pub id: usize,
    /// The DNS name of the party.
    pub dns_name: Address,
}

impl NetworkParty {
    /// Construct a new [`NetworkParty`] type.
    pub fn new(id: usize, address: Address) -> Self {
        Self {
            id,
            dns_name: address,
        }
    }
}

/// The network configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct NetworkConfig {
    /// The list of parties in the network.
    pub parties: Vec<NetworkParty>,
    /// Our own id in the network.
    pub my_id: usize,
    /// The [SocketAddr] we bind to.
    pub bind_addr: SocketAddr,
    /// The send/recv timeout
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub timeout: Option<Duration>,
    /// The connection establish timeout
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Option<Duration>,
    /// The flush timeout for the network. If not set, the flush will be unbounded.
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub flush_timeout: Option<Duration>,
    /// The max length (in bytes) of a single frame
    #[serde(default)]
    pub max_frame_length: Option<usize>,
}

impl NetworkConfig {
    /// Construct a new [`NetworkConfig`] type.
    pub fn new(
        id: usize,
        bind_addr: SocketAddr,
        parties: Vec<NetworkParty>,
        timeout: Option<Duration>,
        connect_timeout: Option<Duration>,
        flush_timeout: Option<Duration>,
        max_frame_length: Option<usize>,
    ) -> Self {
        Self {
            parties,
            my_id: id,
            bind_addr,
            timeout,
            connect_timeout,
            flush_timeout,
            max_frame_length,
        }
    }
}

/// A MPC network using [TcpStream]s
#[derive(Debug)]
pub struct TcpNetwork {
    id: usize,
    channels: BlockingChannels,
}

impl Drop for TcpNetwork {
    fn drop(&mut self) {
        if let Err(e) = self.channels.flush() {
            tracing::error!("error flushing channels on drop: {e:?}");
        }
    }
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
            .sorted_by_key(|p| p.id)
            .map(|party| party.dns_name)
            .collect::<Vec<_>>();
        let timeout = config.timeout;
        let flush_timeout = config.flush_timeout;
        let connect_timeout = config.connect_timeout;
        let max_frame_length = config.max_frame_length.unwrap_or(DEFAULT_MAX_FRAME_LENGTH);

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

        for i in 0..N {
            for (other_id, addr) in addrs.iter().enumerate() {
                let addr = addr
                    .to_socket_addrs()?
                    .next()
                    .context("while converting to SocketAddr")?;
                match id.cmp(&other_id) {
                    Ordering::Less => {
                        let start = Instant::now();
                        let mut stream = loop {
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
                        };
                        stream.set_write_timeout(timeout)?;
                        stream.set_nodelay(true)?;
                        stream.write_u64::<BigEndian>(i as u64)?;
                        stream.write_u64::<BigEndian>(id as u64)?;
                        let write_stream = stream.try_clone().expect("can clone stream");
                        nets[i].channels.add_peer(other_id, write_stream, stream);
                    }
                    Ordering::Greater => {
                        let (stream, _) = listener.accept()?;
                        // disable read_timeout again - we only need it for accept
                        let socket = Socket::from(stream);
                        socket.set_read_timeout(None)?;
                        let mut stream = TcpStream::from(socket);
                        stream.set_write_timeout(timeout)?;
                        stream.set_nodelay(true)?;
                        let i = stream.read_u64::<BigEndian>()? as usize;
                        let other_id = stream.read_u64::<BigEndian>()? as usize;
                        let write_stream = stream.try_clone().expect("can clone stream");
                        nets[i].channels.add_peer(other_id, write_stream, stream);
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
