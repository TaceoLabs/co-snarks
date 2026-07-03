//! Data structures and helpers for the network configuration.
use eyre::Context;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Formatter,
    net::{SocketAddr, ToSocketAddrs},
    num::ParseIntError,
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

/// A network address wrapper.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct Address {
    /// The hostname of the address, will be DNS resolved. This hostname is also checked to be contained in the certificate for the party.
    pub hostname: String,
    /// The port of the address.
    pub port: u16,
}

impl Address {
    /// Construct a new [`Address`] type.
    pub fn new(hostname: String, port: u16) -> Self {
        Self { hostname, port }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.hostname, self.port)
    }
}

/// An error for parsing [`Address`]es.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseAddressError {
    /// Must be hostname:port
    InvalidFormat,
    /// Invalid port
    InvalidPort(ParseIntError),
}

impl std::error::Error for ParseAddressError {}

impl std::fmt::Display for ParseAddressError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseAddressError::InvalidFormat => {
                write!(f, "invalid format, expected hostname:port")
            }
            ParseAddressError::InvalidPort(e) => write!(f, "cannot parse port: {e}"),
        }
    }
}

impl FromStr for Address {
    type Err = ParseAddressError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(ParseAddressError::InvalidFormat);
        }
        let hostname = parts[0].to_string();
        let port = parts[1].parse().map_err(ParseAddressError::InvalidPort)?;
        Ok(Address { hostname, port })
    }
}

impl ToSocketAddrs for Address {
    type Iter = std::vec::IntoIter<SocketAddr>;
    fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        format!("{}:{}", self.hostname, self.port).to_socket_addrs()
    }
}

impl Serialize for Address {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{}:{}", self.hostname, self.port))
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Address::from_str(&s).map_err(serde::de::Error::custom)
    }
}

/// The TLS configuration file.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct TlsConfigFile {
    /// The private key of the party.
    pub key: PathBuf,
    /// The public certificates of the parties indexed by id (including our own).
    pub certs: Vec<PathBuf>,
}

/// The TLS configuration.
#[derive(Debug, Eq, PartialEq)]
pub struct TlsConfig {
    /// The private key of the party.
    pub key: PrivateKeyDer<'static>,
    /// The public certificates of the parties indexed by id (including our own).
    pub certs: Vec<CertificateDer<'static>>,
}

impl Clone for TlsConfig {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone_key(),
            certs: self.certs.clone(),
        }
    }
}

impl TlsConfig {
    /// Construct a new [`TlsConfig`] type.
    pub fn new(key: PrivateKeyDer<'static>, certs: Vec<CertificateDer<'static>>) -> Self {
        Self { key, certs }
    }
}

/// A party in the network.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
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

/// The network configuration file.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NetworkConfigFile {
    /// The list of parties in the network.
    pub parties: Vec<NetworkParty>,
    /// Our own id in the network.
    pub my_id: usize,
    /// The [SocketAddr] we bind to.
    pub bind_addr: SocketAddr,
    /// The TLS configuration.
    ///
    /// Required for `crate::tls::TlsNetwork` and `crate::quic::QuicNetwork`.
    pub tls: Option<TlsConfigFile>,
    /// The send/recv timeout
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub timeout: Option<Duration>,
    /// The connection establish timeout
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Option<Duration>,
    /// The flush timeout for the network. If not set, the flush will be unbounded.
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub flush_timeout: Option<Duration>,
    /// The max length (in bytes) of a single frame
    #[serde(default)]
    pub max_frame_length: Option<usize>,
}

/// The network configuration.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NetworkConfig {
    /// The list of parties in the network.
    pub parties: Vec<NetworkParty>,
    /// Our own id in the network.
    pub my_id: usize,
    /// The [SocketAddr] we bind to.
    pub bind_addr: SocketAddr,
    /// The TLS configuration.
    ///
    /// Required for `crate::tls::TlsNetwork` and `crate::quic::QuicNetwork`.
    pub tls: Option<TlsConfig>,
    /// The send/recv timeout
    ///
    /// If `None`, the send/recv will be unbounded.
    pub timeout: Option<Duration>,
    /// The connection establish timeout
    ///
    /// If `None`, the connection establish will be unbounded.
    pub connect_timeout: Option<Duration>,
    /// The flush timeout for the network.
    ///
    /// If `None`, the flush will be unbounded.
    pub flush_timeout: Option<Duration>,
    /// The max length (in bytes) of a single frame
    ///
    /// If `None`, the [`crate::DEFAULT_MAX_FRAME_LENGTH`] will be used.
    pub max_frame_length: Option<usize>,
}

impl TryFrom<NetworkConfigFile> for NetworkConfig {
    type Error = eyre::Report;

    fn try_from(value: NetworkConfigFile) -> Result<Self, Self::Error> {
        let tls_config = match value.tls {
            Some(tls_config) => {
                let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    std::fs::read(tls_config.key).context("while reading key")?,
                ))
                .clone_key();
                let certs = tls_config
                    .certs
                    .into_iter()
                    .map(|cert_path| {
                        let cert = CertificateDer::from(
                            std::fs::read(cert_path).context("while reading cert")?,
                        )
                        .into_owned();
                        eyre::Ok(cert)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Some(TlsConfig { key, certs })
            }
            None => None,
        };
        Ok(NetworkConfig {
            parties: value.parties,
            my_id: value.my_id,
            bind_addr: value.bind_addr,
            tls: tls_config,
            timeout: value.timeout,
            connect_timeout: value.connect_timeout,
            flush_timeout: value.flush_timeout,
            max_frame_length: value.max_frame_length,
        })
    }
}

impl NetworkConfig {
    /// Construct a new [`NetworkConfigBuilder`] with the required fields.
    pub fn builder(
        my_id: usize,
        bind_addr: SocketAddr,
        parties: Vec<NetworkParty>,
    ) -> NetworkConfigBuilder {
        NetworkConfigBuilder::new(my_id, bind_addr, parties)
    }
}

/// A builder for [`NetworkConfig`].
#[derive(Debug, Clone)]
pub struct NetworkConfigBuilder {
    parties: Vec<NetworkParty>,
    my_id: usize,
    bind_addr: SocketAddr,
    tsl_config: Option<TlsConfig>,
    timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
    flush_timeout: Option<Duration>,
    max_frame_length: Option<usize>,
}

impl NetworkConfigBuilder {
    /// Construct a new [`NetworkConfigBuilder`] with the required fields.
    pub fn new(my_id: usize, bind_addr: SocketAddr, parties: Vec<NetworkParty>) -> Self {
        Self {
            parties,
            my_id,
            bind_addr,
            tsl_config: None,
            timeout: None,
            connect_timeout: None,
            flush_timeout: None,
            max_frame_length: None,
        }
    }

    /// Set the TLS configuration.
    pub fn tls_config(mut self, tls_config: TlsConfig) -> Self {
        self.tsl_config = Some(tls_config);
        self
    }

    /// Set the send/recv timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set the connection establish timeout.
    pub fn connect_timeout(mut self, connect_timeout: Duration) -> Self {
        self.connect_timeout = Some(connect_timeout);
        self
    }

    /// Set the flush timeout.
    pub fn flush_timeout(mut self, flush_timeout: Duration) -> Self {
        self.flush_timeout = Some(flush_timeout);
        self
    }

    /// Set the max length (in bytes) of a single frame.
    pub fn max_frame_length(mut self, max_frame_length: usize) -> Self {
        self.max_frame_length = Some(max_frame_length);
        self
    }

    /// Build the [`NetworkConfig`].
    pub fn build(self) -> NetworkConfig {
        NetworkConfig {
            parties: self.parties,
            my_id: self.my_id,
            bind_addr: self.bind_addr,
            tls: self.tsl_config,
            timeout: self.timeout,
            connect_timeout: self.connect_timeout,
            flush_timeout: self.flush_timeout,
            max_frame_length: self.max_frame_length,
        }
    }
}
