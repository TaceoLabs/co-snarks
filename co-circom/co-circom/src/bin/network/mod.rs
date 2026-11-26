//! The network connecting the MPC parties, shared by the binaries of this crate.

use color_eyre::eyre::{self, Context};
use mpc_net::{
    ConnectionStats, Network, bytes::Bytes, config::NetworkConfig, tcp::TcpNetwork, tls::TlsNetwork,
};

/// The network connecting the MPC parties.
///
/// The parties exchange their shares and the seeds of their correlated randomness over this network, so it has to be encrypted and the peers have to be authenticated. This is the case for [`MpcNetwork::Tls`], which is used unless plain TCP is explicitly requested.
#[derive(Debug)]
pub enum MpcNetwork {
    /// Mutual TLS, each peer is bound to its party id via its certificate.
    Tls(TlsNetwork),
    /// Plain TCP without encryption and without authentication of the peers.
    Tcp(TcpNetwork),
}

impl MpcNetwork {
    /// Connects to the other parties.
    ///
    /// Uses TLS and fails if the network config has no TLS section. Plain TCP is only used if `insecure_tcp` is set.
    pub fn connect(config: NetworkConfig, insecure_tcp: bool) -> eyre::Result<Self> {
        if insecure_tcp {
            tracing::warn!(
                "Using plain TCP: the MPC traffic is NOT encrypted and the other parties are NOT authenticated. Anyone who can observe or reach the network can learn the secret inputs. Only use this in a trusted, isolated network."
            );
            let net = TcpNetwork::new(config).context("while connecting to network")?;
            return Ok(Self::Tcp(net));
        }
        eyre::ensure!(
            config.tls.is_some(),
            "The network config has no TLS section. Add a [network.tls] section with the private key of this party and the certificates of all parties, or pass --insecure-tcp (insecure_tcp = true in the config) to use plain, unauthenticated TCP"
        );
        let net = TlsNetwork::new(config).context("while connecting to network")?;
        Ok(Self::Tls(net))
    }
}

impl Network for MpcNetwork {
    fn id(&self) -> usize {
        match self {
            Self::Tls(net) => net.id(),
            Self::Tcp(net) => net.id(),
        }
    }

    fn send(&self, to: usize, data: Bytes) -> eyre::Result<()> {
        match self {
            Self::Tls(net) => net.send(to, data),
            Self::Tcp(net) => net.send(to, data),
        }
    }

    fn recv(&self, from: usize) -> eyre::Result<Bytes> {
        match self {
            Self::Tls(net) => net.recv(from),
            Self::Tcp(net) => net.recv(from),
        }
    }

    fn flush(&self) -> eyre::Result<()> {
        match self {
            Self::Tls(net) => net.flush(),
            Self::Tcp(net) => net.flush(),
        }
    }

    fn get_connection_stats(&self) -> ConnectionStats {
        match self {
            Self::Tls(net) => net.get_connection_stats(),
            Self::Tcp(net) => net.get_connection_stats(),
        }
    }
}
