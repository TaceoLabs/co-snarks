//! # REP3
//!
//! This module implements the rep3 share and combine operations

pub mod arithmetic;
pub mod binary;
pub mod conversion;
mod detail;
pub mod gadgets;
pub mod network;
pub mod pointshare;
pub mod poly;
pub mod rngs;
pub mod yao;

use conversion::A2BType;
use mpc_net::Network;
pub use mpc_types::protocols::rep3::id::PartyID;
pub use mpc_types::protocols::rep3::{
    Rep3BigUintShare, Rep3PointShare, Rep3PrimeFieldShare, combine_binary_element,
    combine_curve_point, combine_field_element, combine_field_elements, share_biguint,
    share_curve_point, share_field_element, share_field_elements,
};
use rand::{CryptoRng, Rng, SeedableRng as _};
use rngs::{Rep3CorrelatedRng, Rep3Rand, Rep3RandBitComp};

use crate::{MpcState, RngType};

/// The internal state of the REP3 protocl
pub struct Rep3State {
    /// The id of the party
    pub id: PartyID,
    /// The correlated rng for rep3
    pub rngs: Rep3CorrelatedRng,
    /// The rng type
    pub rng: RngType,
    /// A2B conversion type
    pub a2b_type: A2BType,
}

impl Rep3State {
    /// Create a new [Rep3State]
    pub fn new<N: Network>(net: &N) -> eyre::Result<Self> {
        let id = PartyID::try_from(net.id())?;
        let mut rng = rand_chacha::ChaCha12Rng::from_entropy();
        let mut rand = Self::setup_prf(net, &mut rng)?;
        let bitcomps = Self::setup_bitcomp(net, &mut rand)?;
        let rngs = Rep3CorrelatedRng::new(rand, bitcomps.0, bitcomps.1);

        Ok(Rep3State {
            id,
            rngs,
            rng,
            a2b_type: A2BType::default(),
        })
    }

    fn setup_prf<N: Network, R: Rng + CryptoRng>(net: &N, rng: &mut R) -> eyre::Result<Rep3Rand> {
        let seed1: [u8; crate::SEED_SIZE] = rng.r#gen();
        let seed2: [u8; crate::SEED_SIZE] = network::reshare(net, seed1)?;

        Ok(Rep3Rand::new(seed1, seed2))
    }

    fn setup_bitcomp<N: Network>(
        net: &N,
        rands: &mut Rep3Rand,
    ) -> eyre::Result<(Rep3RandBitComp, Rep3RandBitComp)> {
        let id = PartyID::try_from(net.id())?;
        let (k1a, k1c) = rands.random_seeds();
        let (k2a, k2c) = rands.random_seeds();

        match id {
            PartyID::ID0 => {
                let k2b: [u8; crate::SEED_SIZE] =
                    network::send_and_recv(net, PartyID::ID1, k1c, PartyID::ID2)?;
                let bitcomp1 = Rep3RandBitComp::new_2keys(k1a, k1c);
                let bitcomp2 = Rep3RandBitComp::new_3keys(k2a, k2b, k2c);
                Ok((bitcomp1, bitcomp2))
            }
            PartyID::ID1 => {
                network::send_next(net, (k1c, k2c))?;
                let k1b: [u8; crate::SEED_SIZE] = network::recv_prev(net)?;
                let bitcomp1 = Rep3RandBitComp::new_3keys(k1a, k1b, k1c);
                let bitcomp2 = Rep3RandBitComp::new_2keys(k2a, k2c);
                Ok((bitcomp1, bitcomp2))
            }
            PartyID::ID2 => {
                network::send_next(net, k2c)?;
                let (k1b, k2b): ([u8; crate::SEED_SIZE], [u8; crate::SEED_SIZE]) =
                    network::recv_prev(net)?;
                let bitcomp1 = Rep3RandBitComp::new_3keys(k1a, k1b, k1c);
                let bitcomp2 = Rep3RandBitComp::new_3keys(k2a, k2b, k2c);
                Ok((bitcomp1, bitcomp2))
            }
        }
    }
}

impl MpcState for Rep3State {
    type PartyID = PartyID;

    fn id(&self) -> Self::PartyID {
        self.id
    }

    fn fork(&mut self, _: usize) -> eyre::Result<Self> {
        let id = self.id;
        let rngs = self.rngs.fork();
        let rng = RngType::from_seed(self.rng.r#gen());
        let a2b_type = self.a2b_type;

        Ok(Self {
            id,
            rngs,
            rng,
            a2b_type,
        })
    }
}
