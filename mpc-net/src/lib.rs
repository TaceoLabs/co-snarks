//! A simple networking layer for MPC protocols.
#![warn(missing_docs)]
use std::{
    collections::{BTreeMap, HashMap},
    net::{SocketAddr, ToSocketAddrs},
    num::NonZeroU64,
    time::Duration,
};

use async_smux::{MuxAcceptor, MuxBuilder, MuxConnector, MuxStream};
use bytes::Bytes;
use color_eyre::eyre::{self, Context, Report};
use config::NetworkConfig;
use futures::{SinkExt, StreamExt};
use quinn::rustls::pki_types::CertificateDer;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

pub mod channel;
pub mod codecs;
pub mod config;

/// A network handler for MPC protocols.
pub struct MpcNetworkHandler {
    // this is a btreemap because we rely on iteration order
    connections: BTreeMap<usize, (MuxConnector<TcpStream>, MuxAcceptor<TcpStream>)>,
    my_id: usize,
}

impl MpcNetworkHandler {
    /// Tries to establish a connection to other parties in the network based on the provided [NetworkConfig].
    pub async fn establish(config: NetworkConfig) -> Result<Self, Report> {
        config.check_config()?;
        let certs: HashMap<usize, CertificateDer> = config
            .parties
            .iter()
            .map(|p| {
                let cert = std::fs::read(&p.cert_path)
                    .with_context(|| format!("reading certificate of party {}", p.id))?;
                Ok((p.id, CertificateDer::from(cert)))
            })
            .collect::<Result<_, Report>>()?;

        let our_socket_addr = config.bind_addr;

        let listener = TcpListener::bind(our_socket_addr).await?;

        let mut connections = BTreeMap::new();

        tracing::info!("Party {}: establish", config.my_id);

        for party in config.parties {
            if party.id == config.my_id {
                // skip self
                continue;
            }
            if party.id < config.my_id {
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

                let stream = loop {
                    if let Ok(stream) = TcpStream::connect(party_addr).await {
                        break stream;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                };

                let (connector, acceptor, worker) = MuxBuilder::client()
                    .with_keep_alive_interval(NonZeroU64::new(1).unwrap())
                    .with_idle_timeout(NonZeroU64::new(10).unwrap())
                    .with_connection(stream)
                    .build();

                tokio::spawn(worker);
                assert!(connections
                    .insert(party.id, (connector, acceptor))
                    .is_none());
            } else {
                // we are the server, accept a connection
                let (stream, _peer_addr) = listener.accept().await?;
                let (connector, acceptor, worker) = MuxBuilder::server()
                    .with_keep_alive_interval(NonZeroU64::new(1).unwrap())
                    .with_idle_timeout(NonZeroU64::new(10).unwrap())
                    .with_connection(stream)
                    .build();
                tokio::spawn(worker);
                assert!(connections
                    .insert(party.id, (connector, acceptor))
                    .is_none());
            }
        }
        tracing::info!("Party {}: establish done", config.my_id);

        Ok(MpcNetworkHandler {
            connections,
            my_id: config.my_id,
        })
    }

    /// Returns the number of sent and received bytes.
    pub fn get_send_receive(&self, i: usize) -> std::io::Result<(u64, u64)> {
        // let conn = self
        //     .connections
        //     .get(&i)
        //     .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such connection"))?;
        // let stats = conn.stats();
        // Ok((stats.udp_tx.bytes, stats.udp_rx.bytes))
        todo!()
    }

    /// Prints the connection statistics.
    pub fn print_connection_stats(&self, out: &mut impl std::io::Write) -> std::io::Result<()> {
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

    /// Sets up a new [BytesChannel] between each party. The resulting map maps the id of the party to its respective [BytesChannel].
    pub async fn get_byte_channels(
        &mut self,
    ) -> std::io::Result<HashMap<usize, Framed<MuxStream<TcpStream>, LengthDelimitedCodec>>> {
        // let mut codec = LengthDelimitedCodec::new();
        // codec.set_max_frame_length(1_000_000_000);
        self.get_custom_channels().await
    }

    /// Set up a new [Channel] using [BincodeCodec] between each party. The resulting map maps the id of the party to its respective [Channel].
    // pub async fn get_serde_bincode_channels<M: Serialize + DeserializeOwned + 'static>(
    //     &self,
    // ) -> std::io::Result<HashMap<usize, Channel<RecvStream, SendStream, BincodeCodec<M>>>> {
    //     let bincodec = BincodeCodec::<M>::new();
    //     self.get_custom_channels(bincodec).await
    // }

    /// Set up a new [Channel] using the provided codec between each party. The resulting map maps the id of the party to its respective [Channel].
    pub async fn get_custom_channels(
        &mut self,
    ) -> std::io::Result<HashMap<usize, Framed<MuxStream<TcpStream>, LengthDelimitedCodec>>> {
        let mut channels = HashMap::with_capacity(self.connections.len() - 1);

        for (&id, (conn, acc)) in self.connections.iter_mut() {
            if id < self.my_id {
                // we are the client, so we are the receiver
                let stream = conn.connect().unwrap();
                let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
                let _ = framed.next().await.unwrap().unwrap();
                framed.send(Bytes::from_static(b"init")).await.unwrap();
                tracing::info!("Party {}: recv from {} in establish done", self.my_id, id);
                assert!(channels.insert(id, framed).is_none());
            } else {
                // we are the server, so we are the sender
                let stream = acc.accept().await.unwrap();
                let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
                framed.send(Bytes::from_static(b"init")).await.unwrap();
                let _ = framed.next().await.unwrap().unwrap();
                tracing::info!("Party {}: recv from {} in establish done", self.my_id, id);
                assert!(channels.insert(id, framed).is_none());
            }
        }
        Ok(channels)
    }

    /// Shutdown all connections, and call [`quinn::Endpoint::wait_idle`] on all of them
    pub async fn shutdown(mut self) -> std::io::Result<()> {
        tracing::debug!(
            "party {} shutting down, conns = {:?}",
            self.my_id,
            self.connections.keys()
        );

        for (id, (conn, acc)) in self.connections.iter_mut() {
            // conn.close().await.unwrap();
            // if self.my_id < *id {
            //     let mut stream = conn.connect().unwrap();
            //     stream.write_all(b"done").await?;
            //     stream.shutdown().await?;
            // } else {
            //     let mut stream = acc.accept().await.unwrap();
            //     let mut buffer = vec![0u8; b"done".len()];
            //     stream.read_exact(&mut buffer).await.map_err(|_| {
            //         std::io::Error::new(std::io::ErrorKind::BrokenPipe, "failed to recv done msg")
            //     })?;

            //     // stream.shutdown().await?;
            //     conn.close().await.unwrap();

            //     tracing::debug!("party {} closing conn = {id}", self.my_id);
            // }
        }
        Ok(())
    }
}
