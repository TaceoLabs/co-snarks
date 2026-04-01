//! libfabric based MPC net

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, atomic::AtomicUsize, mpsc},
};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use eyre::ContextCompat as _;
use libfabric_efa_rs::{FabricAddress, FabricEndpoint, PeerId};

use crate::{
    ConnectionStats, DEFAULT_MAX_FRAME_LENTH, Network,
    tcp::{NetworkConfig, TcpNetwork},
};

#[allow(clippy::complexity)]
struct PeerConnection {
    endpoint: Arc<FabricEndpoint>,
    peer_id: PeerId,
    sent_bytes: AtomicUsize,
    recv_bytes: AtomicUsize,
    send_buffer: Mutex<Vec<u8>>,
    rx: Mutex<mpsc::Receiver<(Vec<u8>, mpsc::Sender<Vec<u8>>)>>,
}

impl std::fmt::Debug for PeerConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerConnection")
            .field("peer_id", &self.peer_id)
            .finish_non_exhaustive()
    }
}

/// A zero-copy MPC network that holds `FabricEndpoint`s directly — no background tasks, no
/// intermediate channels.  The caller owns the buffers and passes them in for both send and recv;
/// each function returns the same allocation once the NIC signals completion, allowing the caller
/// to reuse it for the next operation with a single allocation.
#[derive(Debug)]
pub struct FabricNetwork {
    id: usize,
    peers: HashMap<usize, PeerConnection>,
}

impl FabricNetwork {
    /// Create a new `FabricNetwork`.
    pub fn new(config: NetworkConfig) -> eyre::Result<Self> {
        let tcp_network = TcpNetwork::new(config.clone())?;
        let id = config.my_id;
        let max_frame_length = config.max_frame_length.unwrap_or(DEFAULT_MAX_FRAME_LENTH);
        let mut party_id_to_peer_id = HashMap::new();
        let mut endpoints = HashMap::new();
        for party in config.parties.iter() {
            let other_id = party.id;
            if other_id != id {
                tracing::debug!(
                    "connecting to peer {other_id} with addr {:?}",
                    party.dns_name
                );
                let mut endpoint = FabricEndpoint::new()?;
                tcp_network.send(other_id, &endpoint.local_address()?.as_bytes())?;
                let peer_addr = FabricAddress::from(tcp_network.recv::<Vec<u8>>(other_id)?);
                tracing::debug!("exchanged addresses, got addr {peer_addr:?}");
                let peer_id = endpoint.insert_peer(&peer_addr)?;
                party_id_to_peer_id.insert(other_id, peer_id);
                endpoints.insert(other_id, endpoint);
                tracing::debug!("inserted peer {other_id} with peer id {peer_id:?}");
            }
        }

        let mut peers = HashMap::new();
        for (other_id, peer_id) in party_id_to_peer_id {
            let endpoint = endpoints
                .remove(&other_id)
                .expect("must exist since we just inserted it");
            let endpoint = Arc::new(endpoint);
            let (tx, rx) = mpsc::channel::<(Vec<u8>, mpsc::Sender<Vec<u8>>)>();
            std::thread::spawn({
                let endpoint = Arc::clone(&endpoint);
                move || {
                    let endpoint = endpoint.clone();
                    let mut size_buffer = vec![0; 8];
                    let mut recv_buffer = vec![0; max_frame_length];
                    loop {
                        let res = endpoint.recv(&mut size_buffer);
                        match res {
                            Ok(()) => {
                                let size = usize::from_le_bytes(
                                    size_buffer
                                        .as_slice()
                                        .try_into()
                                        .expect("size must be 8 bytes in little endian"),
                                );
                                // tracing::debug!("ready to receive data from peer {other_id} with size {size} bytes");
                                recv_buffer.resize(size, 0);
                                endpoint.recv(&mut recv_buffer).expect("recv must succeed");
                                // tracing::debug!("got data from peer {other_id} with size {} bytes", recv_buffer.len());
                                let (buf_tx, buf_rx) = mpsc::channel();
                                // tracing::debug!("sending data via channel to recv");
                                tx.send((recv_buffer, buf_tx))
                                    .expect("receiver not dropped");
                                match buf_rx.recv() {
                                    Ok(buf) => {
                                        recv_buffer = buf;
                                    }
                                    Err(err) => {
                                        tracing::warn!("recv error: {err:?}");
                                        break;
                                    }
                                }
                                // tracing::debug!("got buffer back from recv, ready for next recv");
                            }
                            Err(err) => {
                                tracing::warn!("recv error: {err:?}");
                                break;
                            }
                        }
                    }
                }
            });
            peers.insert(
                other_id,
                PeerConnection {
                    endpoint,
                    peer_id,
                    sent_bytes: AtomicUsize::default(),
                    recv_bytes: AtomicUsize::default(),
                    send_buffer: Mutex::new(vec![0; max_frame_length]),
                    // recv_buffer: Mutex::new(vec![0; max_frame_length]),
                    rx: Mutex::new(rx),
                },
            );
        }

        Ok(Self { id, peers })
    }
}

impl Network for FabricNetwork {
    fn id(&self) -> usize {
        self.id
    }

    fn send<T: CanonicalSerialize>(&self, to: usize, data: &T) -> eyre::Result<()> {
        // tracing::debug!("sending data to peer {to}");
        let peer = self.peers.get(&to).context("party id out-of-bounds")?;
        let mut send_buffer = peer.send_buffer.lock().expect("not poisoned");
        let size = data.serialized_size(ark_serialize::Compress::No);
        send_buffer.resize(size, 0);
        // tracing::debug!("data serialized size is {size} bytes");
        data.serialize_uncompressed(send_buffer.as_mut_slice())?;
        peer.endpoint
            .send_to(peer.peer_id, size.to_le_bytes().as_slice())?;
        peer.endpoint.send_to(peer.peer_id, &send_buffer)?;
        peer.sent_bytes
            .fetch_add(size, std::sync::atomic::Ordering::Relaxed);
        // tracing::debug!("finished sending data to peer {to}");
        Ok(())
    }

    fn recv<T: CanonicalDeserialize>(&self, from: usize) -> eyre::Result<T> {
        // tracing::debug!("receiving data from peer {from}");
        let peer = self.peers.get(&from).context("party id out-of-bounds")?;
        let (buf, buf_tx) = peer
            .rx
            .lock()
            .expect("not poisoned")
            .recv()
            .expect("sender not dropped");
        // tracing::debug!("got data from peer {from} with size {} bytes", buf.len());
        let data = T::deserialize_uncompressed_unchecked(buf.as_slice())?;
        peer.recv_bytes
            .fetch_add(buf.len(), std::sync::atomic::Ordering::Relaxed);
        buf_tx.send(buf).expect("receiver not dropped");
        // tracing::debug!("finished receiving data from peer {from}");
        Ok(data)
    }

    fn get_connection_stats(&self) -> ConnectionStats {
        let mut stats = std::collections::BTreeMap::new();
        for (id, peer) in &self.peers {
            stats.insert(
                *id,
                (
                    peer.sent_bytes.load(std::sync::atomic::Ordering::Relaxed),
                    peer.recv_bytes.load(std::sync::atomic::Ordering::Relaxed),
                ),
            );
        }
        ConnectionStats::new(self.id, stats)
    }
}
