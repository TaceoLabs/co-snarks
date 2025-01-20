//! Data structures and helpers for the network configuration.
use color_eyre::eyre;
use serde::{Deserialize, Serialize};
use std::{
    fmt::Formatter,
    net::{SocketAddr, ToSocketAddrs},
    num::ParseIntError,
    path::PathBuf,
    str::FromStr,
};
use tonic::transport::Certificate;

/// A network address wrapper.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct Address {
    /// The hostname of the address, will be DNS resolved. This hostname is also checked to be contained in the certificate for the party.
    pub hostname: String,
    /// The port of the address.
    pub port: u16,
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

/// A party in the network config file.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct NetworkPartyConfig {
    /// The id of the party, 0-based indexing.
    pub id: usize,
    /// The DNS name of the party.
    pub dns_name: Address,
    /// The path to the public certificate of the party.
    pub cert_path: Option<PathBuf>,
}

/// A party in the network.
#[derive(Debug, Clone)]
pub struct NetworkParty {
    /// The id of the party, 0-based indexing.
    pub id: usize,
    /// The DNS name of the party.
    pub dns_name: Address,
    /// The public certificate of the party.
    pub cert: Option<Certificate>,
}

impl TryFrom<NetworkPartyConfig> for NetworkParty {
    type Error = std::io::Error;
    fn try_from(value: NetworkPartyConfig) -> Result<Self, Self::Error> {
        let cert = if let Some(path) = value.cert_path {
            Some(Certificate::from_pem(std::fs::read(path)?))
        } else {
            None
        };
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
    pub key_path: Option<PathBuf>,
}

/// The network configuration.
#[derive(Debug)]
pub struct NetworkConfig {
    /// The list of parties in the network.
    pub parties: Vec<NetworkParty>,
    /// Our own id in the network.
    pub my_id: usize,
    /// The [SocketAddr] we bind to.
    pub bind_addr: SocketAddr,
    /// The private key.
    pub key: Option<Vec<u8>>,
}

impl TryFrom<NetworkConfigFile> for NetworkConfig {
    type Error = std::io::Error;
    fn try_from(value: NetworkConfigFile) -> Result<Self, Self::Error> {
        let parties = value
            .parties
            .into_iter()
            .map(NetworkParty::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let key = if let Some(path) = value.key_path {
            Some(std::fs::read(path)?)
        } else {
            None
        };
        Ok(NetworkConfig {
            parties,
            my_id: value.my_id,
            bind_addr: value.bind_addr,
            key,
        })
    }
}

impl Clone for NetworkConfig {
    fn clone(&self) -> Self {
        Self {
            parties: self.parties.clone(),
            my_id: self.my_id,
            bind_addr: self.bind_addr,
            key: self.key.clone(),
        }
    }
}

impl NetworkConfig {
    /// Basic sanity checks for the configuration.
    pub fn check_config(&self) -> eyre::Result<()> {
        // sanity check config
        // 1. check that my_id is in the list of parties
        self.parties
            .iter()
            .find(|p| p.id == self.my_id)
            .ok_or_else(|| {
                eyre::eyre!(
                    "my_id {} not found in list of parties: {:?}",
                    self.my_id,
                    self.parties
                )
            })?;
        // 2. check that all parties have a unique id
        let mut ids = self.parties.iter().map(|p| p.id).collect::<Vec<_>>();
        ids.sort_unstable();
        ids.dedup();
        if ids.len() != self.parties.len() {
            return Err(eyre::eyre!("duplicate party ids found"));
        }
        Ok(())
    }
}
