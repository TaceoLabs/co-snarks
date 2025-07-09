//! QUIC MPC network

use std::{
    collections::{BTreeMap, HashMap},
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use crate::{
    ConnectionStats, DEFAULT_CONNECTION_TIMEOUT, DEFAULT_MAX_FRAME_LENTH, Network, config::Address,
};
use bytes::Bytes;
use eyre::{Context as _, ContextCompat};
use futures::{SinkExt, StreamExt as _};
use intmap::IntMap;
use parking_lot::Mutex;
use quinn::{
    Connection, Endpoint, IdleTimeout, TransportConfig, VarInt, rustls::pki_types::PrivateKeyDer,
};
use quinn::{
    crypto::rustls::QuicClientConfig,
    rustls::{RootCertStore, pki_types::CertificateDer},
};
use rustls::pki_types::PrivatePkcs8KeyDer;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    runtime::Runtime,
};
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

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

#[derive(Debug)]
struct QuicConnectionHandler {
    id: usize,
    rt: Runtime,
    // this is a btreemap because we rely on iteration order
    connections: BTreeMap<usize, Connection>,
    endpoints: Vec<Endpoint>,
    max_frame_length: usize,
}

impl QuicConnectionHandler {
    pub fn new(config: NetworkConfig, rt: Runtime) -> eyre::Result<Self> {
        let id = config.my_id;
        let max_frame_length = config.max_frame_length.unwrap_or(DEFAULT_MAX_FRAME_LENTH);
        let (connections, endpoints) = rt.block_on(Self::init(config))?;
        Ok(Self {
            id,
            rt,
            connections,
            endpoints,
            max_frame_length,
        })
    }

    async fn init(
        config: NetworkConfig,
    ) -> eyre::Result<(BTreeMap<usize, Connection>, Vec<Endpoint>)> {
        let id = config.my_id;
        let certs: HashMap<usize, CertificateDer> = config
            .parties
            .iter()
            .map(|p| (p.id, p.cert.clone()))
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

        let server_config =
            quinn::ServerConfig::with_single_cert(vec![certs[&id].clone()], config.key)
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
                    eyre::bail!("could not resolve DNS name {}", party.dns_name);
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

            let codec = LengthDelimitedCodec::builder()
                .length_field_type::<u64>()
                .max_frame_length(self.max_frame_length)
                .new_codec();

            let mut write = FramedWrite::new(send_stream, codec.clone());
            let mut read = FramedRead::new(recv_stream, codec);

            let (send_tx, mut send_rx) = tokio::sync::mpsc::channel(32);
            let (recv_tx, recv_rx) = tokio::sync::mpsc::channel(32);

            self.rt.spawn(async move {
                while let Some(frame) = send_rx.recv().await {
                    if let Err(err) = write.send(Bytes::from(frame)).await {
                        tracing::warn!("failed to send data: {err:?}");
                        break;
                    }
                }
            });

            self.rt.spawn(async move {
                while let Some(frame) = read.next().await {
                    match frame {
                        Ok(frame) => {
                            if recv_tx.send(frame.to_vec()).await.is_err() {
                                tracing::warn!("recv receiver dropped");
                                break;
                            }
                        }
                        Err(err) => {
                            tracing::warn!("failed to recv data: {err:?}");
                            break;
                        }
                    }
                }
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
                if let Err(err) = recv.read_exact(&mut buffer).await {
                    tracing::warn!("failed to recv from conn {id}: {err:?}");
                }
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
}

impl Network for QuicNetwork {
    fn id(&self) -> usize {
        self.id
    }

    fn send(&self, to: usize, data: &[u8]) -> eyre::Result<()> {
        if data.len() > self.conn_handler.max_frame_length {
            eyre::bail!(
                "frame len {} > max {}",
                data.len(),
                self.conn_handler.max_frame_length
            );
        }
        let stream = self.send.get(to).context("party id out-of-bounds")?;
        stream.blocking_send(data.to_vec())?;
        Ok(())
    }

    fn recv(&self, from: usize) -> eyre::Result<Vec<u8>> {
        let mut queue = self
            .recv
            .get(from)
            .context("party id out-of-bounds")?
            .lock();
        queue.blocking_recv().context("while recv")
    }

    fn get_connection_stats(&self) -> ConnectionStats {
        let mut stats = std::collections::BTreeMap::new();
        for (id, conn) in &self.conn_handler.connections {
            let conn_stats = conn.stats();
            stats.insert(
                *id,
                (
                    conn_stats.udp_tx.bytes as usize,
                    conn_stats.udp_rx.bytes as usize,
                ),
            );
        }
        ConnectionStats {
            my_id: self.id,
            stats,
        }
    }
}
