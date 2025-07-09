//! TCP MPC network

use std::{
    array,
    cmp::Ordering,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    sync::atomic::AtomicUsize,
    time::{Duration, Instant},
};

use crate::{
    ConnectionStats, DEFAULT_CONNECTION_TIMEOUT, DEFAULT_MAX_FRAME_LENTH, Network, config::Address,
};
use byteorder::{BigEndian, ReadBytesExt as _, WriteBytesExt as _};
use crossbeam_channel::Receiver;
use eyre::ContextCompat;
use intmap::IntMap;
use parking_lot::Mutex;
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
    /// The connection timeout
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub timeout: Option<Duration>,
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
        max_frame_length: Option<usize>,
    ) -> Self {
        Self {
            parties,
            my_id: id,
            bind_addr,
            timeout,
            max_frame_length,
        }
    }
}

/// A MPC network using [TcpStream]s
#[derive(Debug)]
#[expect(clippy::complexity)]
pub struct TcpNetwork {
    id: usize,
    send: IntMap<usize, (Mutex<TcpStream>, AtomicUsize)>,
    recv: IntMap<usize, (Receiver<eyre::Result<Vec<u8>>>, AtomicUsize)>,
    timeout: Duration,
    max_frame_length: usize,
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
        let max_frame_length = config.max_frame_length.unwrap_or(DEFAULT_MAX_FRAME_LENTH);

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
                        stream.write_u64::<BigEndian>(i as u64)?;
                        stream.write_u64::<BigEndian>(id as u64)?;
                        nets[i].send.insert(
                            other_id,
                            (
                                Mutex::new(stream.try_clone().expect("can clone stream")),
                                AtomicUsize::default(),
                            ),
                        );
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
                    Ordering::Greater => {
                        let (stream, _) = listener.accept()?;
                        // disable read_timeout again - we only need it for accept
                        let socket = Socket::from(stream);
                        socket.set_read_timeout(None)?;
                        let mut stream = TcpStream::from(socket);
                        stream.set_write_timeout(Some(timeout))?;
                        stream.set_nodelay(true)?;
                        let i = stream.read_u64::<BigEndian>()? as usize;
                        let other_id = stream.read_u64::<BigEndian>()? as usize;
                        nets[i].send.insert(
                            other_id,
                            (
                                Mutex::new(stream.try_clone().expect("can clone stream")),
                                AtomicUsize::default(),
                            ),
                        );
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
        if data.len() > self.max_frame_length {
            eyre::bail!("frame len {} > max {}", data.len(), self.max_frame_length);
        }
        let (stream, sent_bytes) = self.send.get(to).context("party id out-of-bounds")?;
        sent_bytes.fetch_add(data.len(), std::sync::atomic::Ordering::Relaxed);
        let mut stream = stream.lock();
        stream.write_u64::<BigEndian>(data.len() as u64)?;
        stream.write_all(data)?;
        Ok(())
    }

    fn recv(&self, from: usize) -> eyre::Result<Vec<u8>> {
        let (queue, recv_bytes) = self.recv.get(from).context("party id out-of-bounds")?;
        let data = queue.recv_timeout(self.timeout)??;
        recv_bytes.fetch_add(data.len(), std::sync::atomic::Ordering::Relaxed);
        Ok(data)
    }

    fn get_connection_stats(&self) -> ConnectionStats {
        let mut stats = std::collections::BTreeMap::new();
        for (id, (_, sent_bytes)) in self.send.iter() {
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

fn read_next_frame(stream: &mut TcpStream, max_frame_length: usize) -> eyre::Result<Vec<u8>> {
    let len = stream.read_u64::<BigEndian>()? as usize;
    if len > max_frame_length {
        eyre::bail!("frame len {len} > max {max_frame_length}");
    }
    let mut data = vec![0; len];
    stream.read_exact(&mut data)?;
    Ok(data)
}
