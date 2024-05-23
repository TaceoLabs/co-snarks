use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    my_id: usize,
    bind_addr: SocketAddr,
    parties: Vec<NetworkParty>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkParty {
    party_id: usize,
    addr: String,
}
