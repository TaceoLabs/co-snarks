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
    pub(crate) id: PartyID,
    pub(crate) rngs: Rep3CorrelatedRng,
    pub(crate) network: N,
}

impl<N: Rep3Network> IoContext<N> {
    fn setup_prf(network: &mut N) -> IoResult<Rep3Rand> {
        let seed1: [u8; crate::SEED_SIZE] = RngType::from_entropy().gen();
        network.send_next(seed1)?;
        let seed2: [u8; crate::SEED_SIZE] = network.recv_prev()?;

        Ok(Rep3Rand::new(seed1, seed2))
    }

    fn setup_bitcomp(
        network: &mut N,
        rands: &mut Rep3Rand,
    ) -> IoResult<(Rep3RandBitComp, Rep3RandBitComp)> {
        let (k1a, k1c) = rands.random_seeds();
        let (k2a, k2c) = rands.random_seeds();

        match network.get_id() {
            PartyID::ID0 => {
                network.send_next(k1c)?;
                let k2b: [u8; crate::SEED_SIZE] = network.recv_prev()?;
                let bitcomp1 = Rep3RandBitComp::new_2keys(k1a, k1c);
                let bitcomp2 = Rep3RandBitComp::new_3keys(k2a, k2b, k2c);
                Ok((bitcomp1, bitcomp2))
            }
            PartyID::ID1 => {
                network.send_next((k1c, k2c))?;
                let k1b: [u8; crate::SEED_SIZE] = network.recv_prev()?;
                let bitcomp1 = Rep3RandBitComp::new_3keys(k1a, k1b, k1c);
                let bitcomp2 = Rep3RandBitComp::new_2keys(k2a, k2c);
                Ok((bitcomp1, bitcomp2))
            }
            PartyID::ID2 => {
                network.send_next(k2c)?;
                let (k1b, k2b): ([u8; crate::SEED_SIZE], [u8; crate::SEED_SIZE]) =
                    network.recv_prev()?;
                let bitcomp1 = Rep3RandBitComp::new_3keys(k1a, k1b, k1c);
                let bitcomp2 = Rep3RandBitComp::new_3keys(k2a, k2b, k2c);
                Ok((bitcomp1, bitcomp2))
            }
        }
    }
    pub fn init(mut network: N) -> IoResult<Self> {
        let mut rand = Self::setup_prf(&mut network)?;
        let bitcomps = Self::setup_bitcomp(&mut network, &mut rand)?;
        let rngs = Rep3CorrelatedRng::new(rand, bitcomps.0, bitcomps.1);

        Ok(Self {
            id: network.get_id(), //shorthand access
            network,
            rngs,
        })
    }
}
