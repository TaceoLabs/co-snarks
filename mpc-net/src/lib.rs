//! A simple networking layer for MPC protocols.

#![warn(missing_docs)]

use std::{collections::HashMap, net::ToSocketAddrs, str::FromStr, sync::Arc};

use crate::proto_generated::party_node::{
    party_node_client::PartyNodeClient, party_node_server::PartyNode, SendRequest, SendResponse,
};

use backoff::{future::retry, ExponentialBackoff};
use config::{NetworkConfig, NetworkParty};
use eyre::{eyre, Context, ContextCompat};
use futures::TryFutureExt;
use proto_generated::party_node::{
    party_node_server::PartyNodeServer, ShutdownRequest, ShutdownResponse,
};
use tokio::sync::{
    mpsc::{self, UnboundedSender},
    Mutex, Notify, RwLock,
};
use tokio_stream::StreamExt;
use tonic::{
    async_trait,
    metadata::AsciiMetadataValue,
    transport::{Channel, ClientTlsConfig, Identity, Server, ServerTlsConfig},
    Request, Response, Status, Streaming,
};

pub mod config;
mod proto_generated;

/// A gRPC MPC network
#[derive(Debug, Clone)]
pub struct GrpcNetworking {
    id: usize,
    num_parties: usize,
    // (other party id, session_id) -> outgoing streams to send messages to that party
    #[allow(clippy::complexity)]
    outgoing: Arc<RwLock<HashMap<(usize, usize), Arc<UnboundedSender<SendRequest>>>>>,
    // (other party id, session_id) -> incoming message streams
    #[allow(clippy::complexity)]
    incoming: Arc<RwLock<HashMap<(usize, usize), Mutex<Streaming<SendRequest>>>>>,
    // other party id -> client to call that party
    clients: Arc<RwLock<HashMap<usize, PartyNodeClient<Channel>>>>,
    // session_id -> number of accepted streams
    ready_sem: Arc<(Mutex<HashMap<usize, usize>>, Notify)>,
    shutdown_sem: Arc<(Mutex<usize>, Notify)>,
}

impl GrpcNetworking {
    /// Create a new [GrpcNetworking]
    pub async fn new(config: NetworkConfig) -> eyre::Result<Self> {
        let num_parties = config.parties.len();
        let net = Self {
            id: config.my_id,
            num_parties,
            outgoing: Arc::default(),
            incoming: Arc::default(),
            clients: Arc::default(),
            shutdown_sem: Arc::new((Mutex::new(num_parties - 1), Notify::new())),
            ready_sem: Arc::default(),
        };

        let mut server = if let Some(key) = config.key {
            let cert = config.parties[config.my_id]
                .cert
                .as_ref()
                .ok_or(eyre!("secret key is present, but no certificate found"))?;
            let identity = Identity::from_pem(cert, key);
            Server::builder().tls_config(ServerTlsConfig::new().identity(identity))?
        } else {
            Server::builder()
        };

        // Initialize server
        let net_ = net.clone();
        tokio::spawn(async move {
            server
                .add_service(PartyNodeServer::new(net_).max_decoding_message_size(usize::MAX))
                .serve(config.bind_addr)
                .await?;
            Ok::<_, eyre::Report>(())
        });

        // Connect to parties
        for party in config.parties {
            if party.id == config.my_id {
                continue;
            }
            net.connect_to_party(party).await?;
        }

        net.new_session(0).await?;

        Ok(net)
    }

    async fn connect_to_party(&self, party: NetworkParty) -> eyre::Result<()> {
        tracing::debug!("Party {}: connecting to party {} with", self.id, party.id);
        let addr = party
            .dns_name
            .to_socket_addrs()
            .with_context(|| format!("while resolving DNS name for {}", party.dns_name))?
            .next()
            .with_context(|| format!("could not resolve DNS name {}", party.dns_name))?
            .to_string();

        let backoff = ExponentialBackoff {
            max_elapsed_time: Some(std::time::Duration::from_secs(30)),
            max_interval: std::time::Duration::from_secs(1),
            multiplier: 1.1,
            initial_interval: std::time::Duration::from_millis(10),
            ..Default::default()
        };

        if let Some(cert) = party.cert {
            let tls = ClientTlsConfig::new()
                .ca_certificate(cert)
                .domain_name(party.dns_name.hostname);

            let endpoint = Channel::builder(format!("https://{addr}").parse()?).tls_config(tls)?;

            let channel = retry(backoff, || async {
                endpoint.connect().map_err(|e| e.into()).await
            })
            .await?;

            let client = PartyNodeClient::new(channel);

            self.clients.write().await.insert(party.id, client);
        } else {
            let endpoint = Channel::builder(format!("http://{addr}").parse()?);
            let client = retry(backoff, || async {
                PartyNodeClient::connect(endpoint.clone())
                    .map_err(|e| e.into())
                    .await
            })
            .await?;
            self.clients.write().await.insert(party.id, client);
        }

        Ok(())
    }

    /// Create a new session
    pub async fn new_session(&self, session: usize) -> eyre::Result<()> {
        tracing::debug!("Party {}: new session {session}", self.id);
        for (id, client) in self.clients.write().await.iter_mut() {
            if self.outgoing.read().await.contains_key(&(*id, session)) {
                return Err(eyre!(
                    "Party {:?} has already created session {session:?}",
                    self.id
                ));
            }

            // send message stream
            let (tx, rx) = mpsc::unbounded_channel();
            self.outgoing
                .write()
                .await
                .insert((*id, session), Arc::new(tx));
            let receiving_stream = tokio_stream::wrappers::UnboundedReceiverStream::new(rx);
            let mut request = Request::new(receiving_stream);
            request.metadata_mut().insert(
                "sender_id",
                AsciiMetadataValue::from_str(&self.id.to_string())?,
            );
            request.metadata_mut().insert(
                "session_id",
                AsciiMetadataValue::from_str(&session.to_string())?,
            );
            let _response = client.send_message(request).await?;
        }

        // wait until all parties connected
        tracing::debug!("Party {}: wating for new session {session}", self.id);
        let (ready, notify) = &*self.ready_sem;
        loop {
            if *ready
                .lock()
                .await
                .entry(session)
                .or_insert(self.num_parties - 1)
                == 0
            {
                break;
            }
            notify.notified().await;
        }
        ready.lock().await.remove(&session);
        tracing::debug!("Party {}: wating for new session {session} done ", self.id);

        Ok(())
    }

    /// Send data to `receiver` for `session`
    pub async fn send(&self, value: Vec<u8>, receiver: usize, session: usize) -> eyre::Result<()> {
        let outgoing_stream = self
            .outgoing
            .read()
            .await
            .get(&(receiver, session))
            .context("while get stream in send")?
            .clone();

        // Send message via the outgoing stream
        let request = SendRequest { data: value };
        outgoing_stream
            .send(request.clone())
            .map_err(|e| eyre!(e.to_string()))?;
        Ok(())
    }

    /// Receive data from `sender` for `session`
    pub async fn receive(&self, sender: usize, session: usize) -> eyre::Result<Vec<u8>> {
        // Just retrieve the first message from the corresponding queue
        let incoming = self.incoming.read().await;
        let queue = incoming
            .get(&(sender, session))
            .context("while get stream in receive")?;

        let res = queue
            .lock()
            .await
            .next()
            .await
            .ok_or(eyre!("No message received"))??;

        Ok(res.data)
    }

    /// Shutdown and wait for all parties to be done
    pub async fn shutdown(&self) -> eyre::Result<()> {
        for (id, client) in self.clients.write().await.iter_mut() {
            tracing::debug!("Party {}: sending shutdown to {id}", self.id);
            let mut request = Request::new(ShutdownRequest::default());
            request.metadata_mut().insert(
                "sender_id",
                AsciiMetadataValue::from_str(&self.id.to_string())?,
            );
            // get response can fail, we dont care
            let _response = client.shutdown(request).await;
        }

        let (shutdown, notify) = &*self.shutdown_sem;
        loop {
            if *shutdown.lock().await == 0 {
                break;
            }
            notify.notified().await;
        }

        tracing::debug!("Party {}: shutdown", self.id);

        Ok(())
    }
}

// Server implementation
#[async_trait]
impl PartyNode for GrpcNetworking {
    async fn send_message(
        &self,
        request: Request<Streaming<SendRequest>>,
    ) -> Result<Response<SendResponse>, Status> {
        let sender_id: usize = request
            .metadata()
            .get("sender_id")
            .ok_or(Status::unauthenticated("Sender ID not found"))?
            .to_str()
            .map_err(|_| Status::unauthenticated("Sender ID is not a string"))?
            .parse()
            .map_err(|_| Status::invalid_argument("Sender ID is not a number"))?;
        if sender_id == self.id {
            return Err(Status::unauthenticated(format!(
                "Sender ID coincides with receiver ID: {:?}",
                sender_id
            )));
        }

        let session_id: usize = request
            .metadata()
            .get("session_id")
            .ok_or(Status::unauthenticated("Session ID not found"))?
            .to_str()
            .map_err(|_| Status::unauthenticated("Session ID is not a string"))?
            .parse()
            .map_err(|_| Status::invalid_argument("Session ID is not a number"))?;

        let incoming_stream = request.into_inner();

        self.incoming
            .write()
            .await
            .insert((sender_id, session_id), incoming_stream.into());

        // increase ready sem for this seassion
        let (ready, notify) = &*self.ready_sem;
        *ready
            .lock()
            .await
            .entry(session_id)
            .or_insert(self.num_parties - 1) -= 1;
        notify.notify_one();

        tracing::debug!(
            "Party {}: inserted new stream for party {sender_id} and session {session_id} ",
            self.id
        );

        Ok(Response::new(SendResponse {}))
    }

    async fn shutdown(
        &self,
        _request: Request<ShutdownRequest>,
    ) -> Result<Response<ShutdownResponse>, Status> {
        tracing::debug!("Party {}: recv shutdown", self.id);
        let (shutdown, notify) = &*self.shutdown_sem;
        *shutdown.lock().await -= 1;
        notify.notify_one();
        Ok(Response::new(ShutdownResponse {}))
    }
}
