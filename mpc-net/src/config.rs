//! Data structures and helpers for the network configuration.
use serde::{Deserialize, Serialize};
use std::{
    fmt::Formatter,
    net::{SocketAddr, ToSocketAddrs},
    num::ParseIntError,
    str::FromStr,
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
