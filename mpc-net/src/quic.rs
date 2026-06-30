//! QUIC MPC network

use std::{
    collections::{BTreeMap, HashMap},
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use crate::{
    ConnectionStats, DEFAULT_CONNECTION_TIMEOUT, DEFAULT_MAX_FRAME_LENGTH, Network,
    async_net::AsyncChannels, config::Address,
};
use bytes::Bytes;
use eyre::Context as _;
use quinn::{
    Connection, Endpoint, IdleTimeout, TransportConfig, VarInt, rustls::pki_types::PrivateKeyDer,
};
use quinn::{
    crypto::rustls::QuicClientConfig,
    rustls::{
        RootCertStore,
        pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    },
};
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
        let max_frame_length = config.max_frame_length.unwrap_or(DEFAULT_MAX_FRAME_LENGTH);
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

    pub fn get_streams(&self) -> eyre::Result<AsyncChannels> {
        let codec = LengthDelimitedCodec::builder()
            .length_field_type::<u64>()
            .max_frame_length(self.max_frame_length)
            .new_codec();

        // Open every bidirectional stream first — each open/handshake needs `block_on`,
        // which would panic if attempted while inside the runtime context entered below.
        let mut framed = Vec::with_capacity(self.connections.len());
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
            let sink = FramedWrite::new(send_stream, codec.clone());
            let source = FramedRead::new(recv_stream, codec.clone());
            framed.push((id, sink, source));
        }

        // Spawn the pump tasks onto our runtime by entering it for the duration.
        let mut channels = AsyncChannels::default();
        let _enter = self.rt.enter();
        for (id, sink, source) in framed {
            channels.add_peer(id, sink, source);
        }
        Ok(channels)
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
        // `Runtime::block_on` panics if it is called from within another runtime's
        // async context. The current stack is fully synchronous and never drops a
        // network from async code, but run the graceful shutdown on a dedicated
        // thread so that a future async embedder cannot turn teardown into a panic.
        // The child thread is not part of any runtime, so `block_on` is always
        // valid there. Errors during shutdown are ignored (best-effort cleanup).
        let res = std::thread::scope(|s| s.spawn(|| self.rt.block_on(self.shutdown())).join());
        if let Ok(Err(err)) = res {
            tracing::warn!("error during QUIC shutdown: {err:?}");
        }
    }
}

/// A MPC network using the QUIC protocol
#[derive(Debug)]
pub struct QuicNetwork {
    id: usize,
    channels: AsyncChannels,
    conn_handler: Arc<QuicConnectionHandler>,
}

impl QuicNetwork {
    /// Create a new [QuicNetwork]
    pub fn new(config: NetworkConfig) -> eyre::Result<Self> {
        let id = config.my_id;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let conn_handler = QuicConnectionHandler::new(config, rt)?;
        let channels = conn_handler.get_streams()?;
        Ok(QuicNetwork {
            id,
            channels,
            conn_handler: Arc::new(conn_handler),
        })
    }

    /// Create a network fork with new streams for the same connections
    pub fn fork(&self) -> eyre::Result<Self> {
        let channels = self.conn_handler.get_streams()?;
        Ok(QuicNetwork {
            id: self.id,
            channels,
            conn_handler: Arc::clone(&self.conn_handler),
        })
    }
}

impl Network for QuicNetwork {
    fn id(&self) -> usize {
        self.id
    }

    fn send(&self, to: usize, data: Bytes) -> eyre::Result<()> {
        self.channels
            .send(to, data, self.conn_handler.max_frame_length)
    }

    fn recv(&self, from: usize) -> eyre::Result<Bytes> {
        self.channels.recv(from)
    }

    fn flush(&self) -> eyre::Result<()> {
        self.channels.flush()
    }

    fn shutdown(&self) -> eyre::Result<()> {
        self.channels.shutdown(self.conn_handler.max_frame_length)
    }

    fn get_connection_stats(&self) -> ConnectionStats {
        self.channels.stats(self.id)
    }
}
