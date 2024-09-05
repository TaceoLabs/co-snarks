use crate::{
    protocols::rep3::{
        id::PartyID,
        network::Rep3Network,
        rngs::{Rep3CorrelatedRng, Rep3Rand, Rep3RandBitComp},
    },
    RngType,
};

use super::IoResult;
use rand::{Rng, SeedableRng};

// this will be moved later
pub struct IoContext<N: Rep3Network> {
    pub id: PartyID,
    pub rngs: Rep3CorrelatedRng,
    pub network: N,
}

impl<N: Rep3Network> IoContext<N> {
    async fn setup_prf(network: &mut N) -> IoResult<Rep3Rand> {
        let seed1: [u8; crate::SEED_SIZE] = RngType::from_entropy().gen();
        network.send_next(seed1).await?;
        let seed2: [u8; crate::SEED_SIZE] = network.recv_prev().await?;

        Ok(Rep3Rand::new(seed1, seed2))
    }

    async fn setup_bitcomp(
        network: &mut N,
        rands: &mut Rep3Rand,
    ) -> IoResult<(Rep3RandBitComp, Rep3RandBitComp)> {
        let (k1a, k1c) = rands.random_seeds();
        let (k2a, k2c) = rands.random_seeds();

        match network.get_id() {
            PartyID::ID0 => {
                network.send_next(k1c).await?;
                let k2b: [u8; crate::SEED_SIZE] = network.recv_prev().await?;
                let bitcomp1 = Rep3RandBitComp::new_2keys(k1a, k1c);
                let bitcomp2 = Rep3RandBitComp::new_3keys(k2a, k2b, k2c);
                Ok((bitcomp1, bitcomp2))
            }
            PartyID::ID1 => {
                network.send_next((k1c, k2c)).await?;
                let k1b: [u8; crate::SEED_SIZE] = network.recv_prev().await?;
                let bitcomp1 = Rep3RandBitComp::new_3keys(k1a, k1b, k1c);
                let bitcomp2 = Rep3RandBitComp::new_2keys(k2a, k2c);
                Ok((bitcomp1, bitcomp2))
            }
            PartyID::ID2 => {
                network.send_next(k2c).await?;
                let (k1b, k2b): ([u8; crate::SEED_SIZE], [u8; crate::SEED_SIZE]) =
                    network.recv_prev().await?;
                let bitcomp1 = Rep3RandBitComp::new_3keys(k1a, k1b, k1c);
                let bitcomp2 = Rep3RandBitComp::new_3keys(k2a, k2b, k2c);
                Ok((bitcomp1, bitcomp2))
            }
        }
    }
    pub async fn init(mut network: N) -> IoResult<Self> {
        let mut rand = Self::setup_prf(&mut network).await?;
        let bitcomps = Self::setup_bitcomp(&mut network, &mut rand).await?;
        let rngs = Rep3CorrelatedRng::new(rand, bitcomps.0, bitcomps.1);

        Ok(Self {
            id: network.get_id(), //shorthand access
            network,
            rngs,
        })
    }
}
