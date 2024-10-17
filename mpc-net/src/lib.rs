//! A simple networking layer for MPC protocols.
#![warn(missing_docs)]
use std::{
    collections::{BTreeMap, HashMap},
    io,
    net::ToSocketAddrs,
    sync::Arc,
    time::Duration,
};

use channel::{BincodeChannel, BytesChannel, Channel};
use codecs::BincodeCodec;
use color_eyre::eyre::{self, bail, Context, ContextCompat, Report};
use config::NetworkConfig;
use serde::{de::DeserializeOwned, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{
    rustls::{
        pki_types::{CertificateDer, ServerName},
        ClientConfig, RootCertStore, ServerConfig,
    },
    TlsAcceptor, TlsConnector,
};
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

pub mod channel;
pub mod codecs;
pub mod config;

// TODO get this from network config
const STREAMS_PER_CONN: usize = 8;

/// Type alias for a [rustls::TcpStream] over a [TcpStream].
type TlsStream = tokio_rustls::TlsStream<TcpStream>;

/// A network handler for MPC protocols.
#[derive(Debug)]
pub struct MpcNetworkHandler {
    // this is a btreemap because we rely on iteration order
    connections: BTreeMap<usize, Vec<TlsStream>>,
    my_id: usize,
}

impl MpcNetworkHandler {
    /// Tries to establish a connection to other parties in the network based on the provided [NetworkConfig].
    pub async fn establish(config: NetworkConfig) -> Result<Self, Report> {
        config.check_config()?;
        // TODO should mayb be called in application not lib
        tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("Failed to install rustls crypto provider");
        let certs: HashMap<usize, CertificateDer> = config
            .parties
            .iter()
            .map(|p| (p.id, p.cert.clone()))
            .collect();

        let mut root_store = RootCertStore::empty();
        for (id, cert) in &certs {
            root_store
                .add(cert.clone())
                .with_context(|| format!("adding certificate for party {} to root store", id))?;
        }
        let client_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certs[&config.my_id].clone()], config.key)
            .context("creating our server config")?;
        let our_socket_addr = config.bind_addr;

        let listener = TcpListener::bind(our_socket_addr).await?;
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let connector = TlsConnector::from(Arc::new(client_config));

        tracing::trace!("Party {}: listening on {our_socket_addr}", config.my_id);

        let mut connections: BTreeMap<usize, Vec<_>> = BTreeMap::new();

        let mut accpected_streams = BTreeMap::new();

        let num_parties = config.parties.len();

        for party in config.parties {
            if party.id == config.my_id {
                // skip self
                continue;
            }
            if party.id < config.my_id {
                // connect to party, we are client
                let party_addr = party
                    .dns_name
                    .to_socket_addrs()
                    .with_context(|| format!("while resolving DNS name for {}", party.dns_name))?
                    .next()
                    .context(format!("could not resolve DNS name {}", party.dns_name))?;

                let domain = ServerName::try_from(party.dns_name.hostname.clone())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))?
                    .to_owned();

                // create all streams for this connection
                for stream_id in 0..STREAMS_PER_CONN {
                    let stream = loop {
                        if let Ok(stream) = TcpStream::connect(party_addr).await {
                            break stream;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    };
                    tracing::trace!(
                        "Party {}: connected stream {stream_id} to party {}",
                        party.id,
                        config.my_id
                    );
                    let mut stream = connector.connect(domain.clone(), stream).await?;
                    stream.write_u64(config.my_id as u64).await?;
                    stream.write_u64(stream_id as u64).await?;

                    if let Some(streams) = connections.get_mut(&party.id) {
                        streams.push(stream.into());
                    } else {
                        connections.insert(party.id, vec![stream.into()]);
                    }
                }
            } else {
                // we are the server, accept connections
                // accept all streams and store them with key (party_id, stream_id)
                for _ in 0..STREAMS_PER_CONN {
                    match tokio::time::timeout(Duration::from_secs(60), listener.accept()).await {
                        Ok(Ok((stream, _peer_addr))) => {
                            let mut stream = acceptor.accept(stream).await?;
                            let party_id = stream.read_u64().await? as usize;
                            let stream_id = stream.read_u64().await? as usize;
                            tracing::trace!(
                                "Party {}: accpeted stream {stream_id} from party {party_id}",
                                config.my_id
                            );
                            assert!(accpected_streams
                                .insert((party_id, stream_id), stream.into())
                                .is_none());
                        }
                        Ok(Err(_)) => {
                            return Err(eyre::eyre!(
                                "server endpoint did not accept a connection from party {}",
                                party.id
                            ))
                        }
                        Err(_) => {
                            return Err(eyre::eyre!(
                                "party {} did not connect within 60 seconds - timeout",
                                party.id
                            ))
                        }
                    }
                }
            }
        }

        // assign streams to the right party and stream id
        // we accepted streams for all parties with id > my-id, so we can iter from my_id + 1..num_parties
        for party_id in config.my_id + 1..num_parties {
            for stream_id in 0..STREAMS_PER_CONN {
                let stream = accpected_streams
                    .remove(&(party_id, stream_id))
                    .context(format!("get recv for stream {stream_id} party {party_id}"))?;
                if let Some(streams) = connections.get_mut(&party_id) {
                    streams.push(stream);
                } else {
                    connections.insert(party_id, vec![stream]);
                }
            }
        }

        if !accpected_streams.is_empty() {
            bail!("not accepted connections should remain");
        }

        tracing::trace!("Party {}: established network handler", config.my_id);

        Ok(MpcNetworkHandler {
            connections,
            my_id: config.my_id,
        })
    }

    // TODO add stats tracking
    /// Returns the number of sent and received bytes.
    pub fn get_send_receive(&self, _i: usize) -> std::io::Result<(u64, u64)> {
        // let conn = self
        //     .connections
        //     .get(&i)
        //     .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such connection"))?;
        // let stats = conn.stats();
        // Ok((stats.udp_tx.bytes, stats.udp_rx.bytes))
        todo!()
    }

    /// Prints the connection statistics.
    pub fn print_connection_stats(&self, _out: &mut impl std::io::Write) -> std::io::Result<()> {
        // for (i, conn) in &self.connections {
        //     let stats = conn.stats();
        //     writeln!(
        //         out,
        //         "Connection {} stats:\n\tSENT: {} bytes\n\tRECV: {} bytes",
        //         i, stats.udp_tx.bytes, stats.udp_rx.bytes
        //     )?;
        // }
        Ok(())
    }

    /// Get a [Channel] to party with `id`. This pops a stream from the pool.
    pub fn get_byte_channel(
        &mut self,
        id: &usize,
    ) -> Option<BytesChannel<ReadHalf<TlsStream>, WriteHalf<TlsStream>>> {
        let mut codec = LengthDelimitedCodec::new();
        codec.set_max_frame_length(1_000_000_000);
        self.get_custom_channel(id, codec)
    }

    /// Get a [Channel] to party with `id`. This pops a stream from the pool.
    pub fn get_serde_bincode_channel<M: Serialize + DeserializeOwned + 'static>(
        &mut self,
        id: &usize,
    ) -> Option<Channel<ReadHalf<TlsStream>, WriteHalf<TlsStream>, BincodeCodec<M>>> {
        let bincodec = BincodeCodec::<M>::new();
        self.get_custom_channel(id, bincodec)
    }

    /// Get a [Channel] to party with `id` using the provided codec. This pops a stream from the pool.
    #[allow(clippy::type_complexity)]
    pub fn get_custom_channel<
        MSend,
        MRecv,
        C: Encoder<MSend, Error = io::Error>
            + Decoder<Item = MRecv, Error = io::Error>
            + 'static
            + Clone,
    >(
        &mut self,
        id: &usize,
        codec: C,
    ) -> Option<Channel<ReadHalf<TlsStream>, WriteHalf<TlsStream>, C>> {
        debug_assert!(*id != self.my_id);
        if let Some(pool) = self.connections.get_mut(id) {
            if let Some(stream) = pool.pop() {
                // TODO split adds a BiLock, we could avoid this using 1 stream for send and 1 for recv
                let (recv, send) = tokio::io::split(stream);
                return Some(Channel::new(recv, send, codec));
            }
        }
        None
    }

    /// Get a [Channel] to each party using the provided codec. This pops a stream from each pool.
    #[allow(clippy::type_complexity)]
    pub fn get_custom_channels<
        MSend,
        MRecv,
        C: Encoder<MSend, Error = io::Error>
            + Decoder<Item = MRecv, Error = io::Error>
            + 'static
            + Clone,
    >(
        &mut self,
        codec: C,
    ) -> Option<HashMap<usize, Channel<ReadHalf<TlsStream>, WriteHalf<TlsStream>, C>>> {
        self.connections
            .iter_mut()
            .map(|(id, streams)| {
                debug_assert!(*id != self.my_id);
                let stream = streams.pop()?;
                // TODO split adds a BiLock, we could avoid this using 1 stream for send and 1 for recv
                let (recv, send) = tokio::io::split(stream);
                Some((*id, Channel::new(recv, send, codec.clone())))
            })
            .collect()
    }

    /// Get a [Channel] to each party. This pops a stream from each pool.
    #[allow(clippy::type_complexity)]
    pub fn get_byte_channels(
        &mut self,
    ) -> Option<HashMap<usize, BytesChannel<ReadHalf<TlsStream>, WriteHalf<TlsStream>>>> {
        let mut codec = LengthDelimitedCodec::new();
        codec.set_max_frame_length(1_000_000_000);
        self.get_custom_channels(codec)
    }

    /// Get a [Channel] to each party. This pops a stream from each pool.
    #[allow(clippy::type_complexity)]
    pub fn get_serde_bincode_channels<M: Serialize + DeserializeOwned + 'static>(
        &mut self,
    ) -> Option<HashMap<usize, BincodeChannel<ReadHalf<TlsStream>, WriteHalf<TlsStream>, M>>> {
        let bincodec = BincodeCodec::<M>::new();
        self.get_custom_channels(bincodec)
    }
}
