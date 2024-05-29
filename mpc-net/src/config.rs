use color_eyre::eyre;
use serde::{Deserialize, Serialize};
use std::{
    fmt::Formatter,
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
};

#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct Address {
    pub hostname: String,
    pub port: u16,
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.hostname, self.port)
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
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(serde::de::Error::custom("invalid address format"));
        }
        let hostname = parts[0].to_string();
        let port = parts[1].parse().map_err(serde::de::Error::custom)?;
        Ok(Address { hostname, port })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct NetworkParty {
    pub id: usize,
    pub dns_name: Address,
    pub cert_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct NetworkConfig {
    pub parties: Vec<NetworkParty>,
    pub my_id: usize,
    pub bind_addr: SocketAddr,
    pub key_path: PathBuf,
}

impl NetworkConfig {
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
