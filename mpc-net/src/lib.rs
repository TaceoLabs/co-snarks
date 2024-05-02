use std::{
    collections::{BTreeMap, HashMap},
    io,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use channel::{BytesChannel, Channel};
use codecs::BincodeCodec;
use color_eyre::eyre::{self, Context, Report};
use config::NetworkConfig;
use quinn::{
    ClientConfig, Connection, Endpoint, IdleTimeout, RecvStream, SendStream, TransportConfig,
    VarInt,
};
use rustls::{Certificate, PrivateKey};
use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

pub mod codecs;

pub mod channel;
pub mod config;

#[derive(Debug)]
pub struct MpcNetworkHandler {
    // this is a btreemap because we rely on iteration order
    connections: BTreeMap<usize, Connection>,
    endpoints: Vec<Endpoint>,
    my_id: usize,
}

impl MpcNetworkHandler {
    pub async fn establish(config: NetworkConfig) -> Result<Self, Report> {
        config.check_config()?;
        // a client socket, let the OS pick the port
        let local_client_socket = SocketAddr::from(([0, 0, 0, 0], 0));
        let certs: HashMap<usize, Certificate> = config
            .parties
            .iter()
            .map(|p| {
                let cert = std::fs::read(&p.cert_path)
                    .with_context(|| format!("reading certificate of party {}", p.id))?;
                Ok((p.id, Certificate(cert)))
            })
            .collect::<Result<_, Report>>()?;

        let mut root_store = rustls::RootCertStore::empty();
        for (id, cert) in &certs {
            root_store
                .add(cert)
                .with_context(|| format!("adding certificate for party {} to root store", id))?;
        }
        let crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let client_config = {
            let mut transport_config = TransportConfig::default();
            transport_config.max_idle_timeout(Some(
                IdleTimeout::try_from(Duration::from_secs(60)).unwrap(),
            ));
            // atm clients send keepalive packets
            transport_config.keep_alive_interval(Some(Duration::from_secs(1)));
            let mut client_config = ClientConfig::new(Arc::new(crypto));
            client_config.transport_config(Arc::new(transport_config));
            client_config
        };

        let key = PrivateKey(std::fs::read(config.key_path).context("reading own key file")?);
        let server_config =
            quinn::ServerConfig::with_single_cert(vec![certs[&config.my_id].clone()], key)
                .context("creating our server config")?;
        let our_socket_addr = config
            .parties
            .iter()
            .find(|p| p.id == config.my_id)
            .map(|p| p.bind_addr)
            .expect("we are in the list of parties, so we should have a socket address");

        let mut endpoints = Vec::new();
        let server_endpoint = quinn::Endpoint::server(server_config.clone(), our_socket_addr)?;

        let mut connections = BTreeMap::new();

        for party in config.parties {
            if party.id == config.my_id {
                // skip self
                continue;
            }
            if party.id < config.my_id {
                // connect to party, we are client
                let endpoint = quinn::Endpoint::client(local_client_socket)
                    .with_context(|| format!("creating client endpoint to party {}", party.id))?;
                let conn = endpoint
                    .connect_with(client_config.clone(), party.public_addr, &party.dns_name)
                    .with_context(|| {
                        format!("setting up client connection with party {}", party.id)
                    })?
                    .await
                    .with_context(|| format!("connecting as a client to party {}", party.id))?;
                let mut uni = conn.open_uni().await?;
                uni.write_u32(u32::try_from(config.my_id).expect("party id fits into u32"))
                    .await?;
                uni.flush().await?;
                uni.finish().await?;
                tracing::trace!(
                    "Conn with id {} from {} to {}",
                    conn.stable_id(),
                    endpoint.local_addr().unwrap(),
                    conn.remote_address(),
                );
                assert!(connections.insert(party.id, conn).is_none());
                endpoints.push(endpoint);
            } else {
                // we are the server, accept a connection
                if let Some(maybe_conn) = server_endpoint.accept().await {
                    let conn = maybe_conn.await?;
                    tracing::trace!(
                        "Conn with id {} from {} to {}",
                        conn.stable_id(),
                        server_endpoint.local_addr().unwrap(),
                        conn.remote_address(),
                    );
                    let mut uni = conn.accept_uni().await?;
                    let other_party_id = uni.read_u32().await?;
                    assert!(connections
                        .insert(
                            usize::try_from(other_party_id).expect("u32 fits into usize"),
                            conn
                        )
                        .is_none());
                } else {
                    return Err(eyre::eyre!(
                        "server endpoint did not accept a connection from party {}",
                        party.id
                    ));
                }
            }
        }
        endpoints.push(server_endpoint);

        Ok(MpcNetworkHandler {
            connections,
            endpoints,
            my_id: config.my_id,
        })
    }

    pub fn get_send_receive(&self, i: usize) -> std::io::Result<(u64, u64)> {
        let conn = self
            .connections
            .get(&i)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such connection"))?;
        let stats = conn.stats();
        Ok((stats.udp_tx.bytes, stats.udp_rx.bytes))
    }

    pub fn print_connection_stats(&self, out: &mut impl std::io::Write) -> std::io::Result<()> {
        for (i, conn) in &self.connections {
            let stats = conn.stats();
            writeln!(
                out,
                "Connection {} stats:\n\tSENT: {} bytes\n\tRECV: {} bytes",
                i, stats.udp_tx.bytes, stats.udp_rx.bytes
            )?;
        }
        Ok(())
    }
    pub async fn get_byte_channels(
        &mut self,
    ) -> std::io::Result<HashMap<usize, BytesChannel<RecvStream, SendStream>>> {
        self.get_custom_channels(LengthDelimitedCodec::new()).await
    }

    pub async fn get_serde_bincode_channels<M: Serialize + DeserializeOwned + 'static>(
        &mut self,
    ) -> std::io::Result<HashMap<usize, Channel<RecvStream, SendStream, BincodeCodec<M>>>> {
        let bincodec = BincodeCodec::<M>::new();
        self.get_custom_channels(bincodec).await
    }

    pub async fn get_custom_channels<
        MSend,
        MRecv,
        C: Encoder<MSend, Error = io::Error>
            + Decoder<Item = MRecv, Error = io::Error>
            + 'static
            + Clone,
    >(
        &mut self,
        codec: C,
    ) -> std::io::Result<HashMap<usize, Channel<RecvStream, SendStream, C>>> {
        let mut channels = HashMap::with_capacity(self.connections.len() - 1);
        for (&id, conn) in &mut self.connections {
            if id < self.my_id {
                // we are the client, so we are the receiver
                let (mut send_stream, mut recv_stream) = conn.open_bi().await?;
                send_stream.write_u32(self.my_id as u32).await?;
                let their_id = recv_stream.read_u32().await?;
                assert!(their_id == id as u32);
                let conn = Channel::new(recv_stream, send_stream, codec.clone());
                assert!(channels.insert(id, conn).is_none());
            } else {
                // we are the server, so we are the sender
                let (mut send_stream, mut recv_stream) = conn.accept_bi().await?;
                let their_id = recv_stream.read_u32().await?;
                assert!(their_id == id as u32);
                send_stream.write_u32(self.my_id as u32).await?;
                let conn = Channel::new(recv_stream, send_stream, codec.clone());
                assert!(channels.insert(id, conn).is_none());
            }
        }
        Ok(channels)
    }

    /// Shutdown all connections, and call [`quinn::Endpoint::wait_idle`] on all of them
    pub async fn shutdown(self) {
        for conn in self.connections.into_values() {
            conn.close(0u32.into(), b"");
        }
        for endpoint in self.endpoints {
            endpoint.wait_idle().await;
            endpoint.close(VarInt::from_u32(0), &[]);
        }
    }
}
