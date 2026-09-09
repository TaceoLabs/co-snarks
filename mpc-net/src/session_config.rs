//! Configuration types shared by the session-based transports (async and blocking, TCP and TLS).

use std::{net::SocketAddr, time::Duration};

use serde::Deserialize;

use crate::{
    DEFAULT_MAX_FRAME_LENGTH,
    config::{Address, TlsConfig, TlsConfigFile},
};

fn default_max_frame_length() -> usize {
    DEFAULT_MAX_FRAME_LENGTH
}

fn default_time_to_idle() -> Duration {
    Duration::from_secs(30)
}

/// The network configuration file for the session transports.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub struct SessionConfigFile {
    /// Our own id in the network.
    pub party_id: usize,
    /// The [SocketAddr] we bind to.
    pub bind_addr: SocketAddr,
    /// The addresses of the other nodes (ordered by party_id, including our own address).
    /// For TLS transports, the hostname is checked against the certificate of the party.
    pub node_addrs: Vec<Address>,
    /// The TLS configuration. Required for the TLS transports, ignored by the TCP transports.
    #[serde(default)]
    pub tls: Option<TlsConfigFile>,
    /// The `init_session` timeout for the network. If not set, the `init_session` will be unbounded.
    /// Also bounds the handshake + header read of each incoming connection.
    #[serde(with = "humantime_serde", default)]
    pub init_session_timeout: Option<Duration>,
    /// The send/recv timeout
    #[serde(with = "humantime_serde", default)]
    pub timeout: Option<Duration>,
    /// The flush timeout for the network. If not set, the flush will be unbounded.
    #[serde(with = "humantime_serde", default)]
    pub flush_timeout: Option<Duration>,
    /// The time to idle for incoming connections that were not picked up because, e.g.
    /// `init_session` for that session id was never called. Defaults to 30 seconds.
    #[serde(with = "humantime_serde", default = "default_time_to_idle")]
    pub time_to_idle: Duration,
    /// The max length (in bytes) of a single frame
    #[serde(default = "default_max_frame_length")]
    pub max_frame_length: usize,
}

/// The network configuration for the session transports.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SessionConfig {
    /// Our own id in the network.
    pub party_id: usize,
    /// The [SocketAddr] we bind to.
    pub bind_addr: SocketAddr,
    /// The addresses of the other nodes (ordered by party_id, including our own address).
    /// For TLS transports, the hostname is checked against the certificate of the party.
    pub node_addrs: Vec<Address>,
    /// The TLS configuration. Required for the TLS transports, ignored by the TCP transports.
    pub tls: Option<TlsConfig>,
    /// The `init_session` timeout for the network. If not set, the `init_session` will be unbounded.
    /// Also bounds the handshake + header read of each incoming connection.
    pub init_session_timeout: Option<Duration>,
    /// The send/recv timeout
    pub timeout: Option<Duration>,
    /// The flush timeout for the network. If not set, the flush will be unbounded.
    pub flush_timeout: Option<Duration>,
    /// The time to idle for incoming connections that were not picked up because, e.g.
    /// `init_session` for that session id was never called.
    pub time_to_idle: Duration,
    /// The max length (in bytes) of a single frame
    pub max_frame_length: usize,
}

impl TryFrom<SessionConfigFile> for SessionConfig {
    type Error = eyre::Report;

    fn try_from(value: SessionConfigFile) -> Result<Self, Self::Error> {
        Ok(SessionConfig {
            party_id: value.party_id,
            bind_addr: value.bind_addr,
            node_addrs: value.node_addrs,
            tls: value.tls.map(TlsConfig::try_from).transpose()?,
            init_session_timeout: value.init_session_timeout,
            timeout: value.timeout,
            flush_timeout: value.flush_timeout,
            time_to_idle: value.time_to_idle,
            max_frame_length: value.max_frame_length,
        })
    }
}
