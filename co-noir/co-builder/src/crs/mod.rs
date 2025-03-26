pub(crate) mod parse;

use ark_ec::pairing::Pairing;
use serde::{Deserialize, Serialize};

pub struct Crs<P: Pairing> {
    pub monomials: Vec<P::G1Affine>,
    pub g2_x: P::G2Affine,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct ProverCrs<P: Pairing> {
    #[serde(
        serialize_with = "mpc_core::ark_se",
        deserialize_with = "mpc_core::ark_de"
    )]
    pub monomials: Vec<P::G1Affine>,
}

impl<P: Pairing> Crs<P> {
    pub fn split(self) -> (ProverCrs<P>, P::G2Affine) {
        (
            ProverCrs {
                monomials: self.monomials,
            },
            self.g2_x,
        )
    }
}
