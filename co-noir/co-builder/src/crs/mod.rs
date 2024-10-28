pub(crate) mod parse;

use ark_ec::pairing::Pairing;

pub struct Crs<P: Pairing> {
    pub monomials: Vec<P::G1Affine>,
    pub g2_x: P::G2Affine,
}

pub struct ProverCrs<P: Pairing> {
    pub monomials: Vec<P::G1Affine>,
}
