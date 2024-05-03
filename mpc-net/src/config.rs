use color_eyre::eyre;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord)]
pub struct NetworkParty {
    pub id: usize,
    pub dns_name: String,
    pub bind_addr: SocketAddr,
    pub public_addr: SocketAddr,
    pub cert_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord)]
pub struct NetworkConfig {
    pub parties: Vec<NetworkParty>,
    pub my_id: usize,
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
