//! TCP MPC network

use std::{
    array,
    cmp::Ordering,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    time::Duration,
};

use crate::{DEFAULT_CONNECTION_TIMEOUT, Network, config::Address};
use byteorder::{BigEndian, ReadBytesExt as _, WriteBytesExt as _};
use crossbeam_channel::Receiver;
use eyre::ContextCompat;
use intmap::IntMap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

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
}

impl NetworkConfig {
    /// Construct a new [`NetworkConfig`] type.
    pub fn new(
        id: usize,
        bind_addr: SocketAddr,
        parties: Vec<NetworkParty>,
        timeout: Option<Duration>,
    ) -> Self {
        Self {
            parties,
            my_id: id,
            bind_addr,
            timeout,
        }
    }
}

/// A MPC network using [TcpStream]s
#[derive(Debug)]
pub struct TcpNetwork {
    id: usize,
    send: IntMap<usize, Mutex<TcpStream>>,
    recv: IntMap<usize, Receiver<Vec<u8>>>,
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
                        let (tx, rx) = crossbeam_channel::bounded(32);
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
                        nets[i].recv.insert(other_id, rx);
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
                        let (tx, rx) = crossbeam_channel::bounded(32);
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
                        nets[i].recv.insert(other_id, rx);
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
        let queue = self.recv.get(from).context("while get stream in recv")?;
        Ok(queue.recv_timeout(self.timeout)?)
    }
}
