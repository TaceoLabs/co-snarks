//! TCP MPC network

use std::{
    array,
    cmp::Ordering,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
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
use serde::{Deserialize, Serialize};
use socket2::{Domain, Socket, TcpKeepalive, Type};

/// Capacity (in frames) of each per-peer send queue. Bounds buffered-but-unsent
/// memory and applies backpressure to `send` when a peer cannot keep up.
const SEND_QUEUE_CAP: usize = 32;

/// A message handed to a peer's background writer thread.
enum WriteMsg {
    /// A complete, length-prefixed frame to write to the socket.
    Frame(Vec<u8>),
    /// Flush the socket and acknowledge on the given channel.
    Flush(Sender<()>),
}

/// Drains [`WriteMsg`]s for a single peer, writing them to `stream`. On the first
/// write error it records the error in `err` and exits; subsequent `send`/`flush`
/// calls observe `err` and surface it. Exits cleanly when all senders are dropped.
fn writer_loop(mut stream: TcpStream, rx: Receiver<WriteMsg>, err: Arc<Mutex<Option<String>>>) {
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

/// Given a fully-handshaked `stream` for `other_id`, spawn the per-peer writer and
/// reader threads and register the resulting send queue / receive queue on `net`.
fn setup_streams(net: &mut TcpNetwork, other_id: usize, stream: TcpStream, max_frame_length: usize) {
    // Send side: a background writer thread owns one clone of the socket and drains
    // the bounded send queue, so `send` only enqueues and never blocks on socket IO
    // (except for backpressure when the queue is full).
    let write_stream = stream.try_clone().expect("can clone stream");
    let (send_tx, send_rx) = crossbeam_channel::bounded(SEND_QUEUE_CAP);
    let err = Arc::new(Mutex::new(None));
    {
        let err = Arc::clone(&err);
        std::thread::spawn(move || writer_loop(write_stream, send_rx, err));
    }
    net.send
        .insert(other_id, (send_tx, AtomicUsize::default(), err));

    // Recv side: a background reader thread owns the other clone and feeds frames
    // into the bounded receive queue.
    let mut read_stream = stream;
    let (tx, rx) = crossbeam_channel::bounded(32);
    std::thread::spawn(move || {
        loop {
            let data = read_next_frame(&mut read_stream, max_frame_length);
            if tx.send(data).is_err() {
                break;
            }
        }
    });
    net.recv.insert(other_id, (rx, AtomicUsize::default()));
}

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
    send: IntMap<usize, (Sender<WriteMsg>, AtomicUsize, Arc<Mutex<Option<String>>>)>,
    recv: IntMap<usize, (Receiver<eyre::Result<Bytes>>, AtomicUsize)>,
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
            .sorted_by_key(|p| p.id)
            .map(|party| party.dns_name)
            .collect::<Vec<_>>();
        let timeout = config.timeout.unwrap_or(DEFAULT_CONNECTION_TIMEOUT);
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
                        setup_streams(&mut nets[i], other_id, stream, max_frame_length);
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
                        setup_streams(&mut nets[i], other_id, stream, max_frame_length);
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
        let (tx, sent_bytes, err) = self.send.get(to).context("party id out-of-bounds")?;
        if let Some(e) = err.lock().clone() {
            eyre::bail!("connection to party {to} previously failed: {e}");
        }
        // Coalesce the length prefix and payload into a single buffer so each frame
        // is one `write_all` (one segment under TCP_NODELAY) on the writer thread.
        let mut frame = Vec::with_capacity(8 + data.len());
        frame.extend_from_slice(&(data.len() as u64).to_be_bytes());
        frame.extend_from_slice(data);
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

fn read_next_frame(stream: &mut TcpStream, max_frame_length: usize) -> eyre::Result<Bytes> {
    let len = stream.read_u64::<BigEndian>()? as usize;
    if len > max_frame_length {
        eyre::bail!("frame len {len} > max {max_frame_length}");
    }
    let mut data = vec![0; len];
    stream.read_exact(&mut data)?;
    Ok(Bytes::from(data))
}
