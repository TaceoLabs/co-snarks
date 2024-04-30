pub mod proof;
pub mod public_input;
pub mod witness;
pub mod zkey;

#[cfg(test)]
pub(crate) mod test_utils {
    macro_rules! to_g1_bls12_381 {
        ($x: expr, $y: expr) => {
            <ark_bls12_381::Bls12_381 as Pairing>::G1Affine::new(
                ark_bls12_381::Fq::from_str($x).unwrap(),
                ark_bls12_381::Fq::from_str($y).unwrap(),
            )
        };
    }
    macro_rules! to_g2_bls12_381 {
        ({$x1: expr, $x2: expr}, {$y1: expr, $y2: expr}) => {
            <ark_bls12_381::Bls12_381 as Pairing>::G2Affine::new(
                ark_bls12_381::Fq2::new(
                    ark_bls12_381::Fq::from_str($x1).unwrap(),
                    ark_bls12_381::Fq::from_str($x2).unwrap(),
                ),
                ark_bls12_381::Fq2::new(
                    ark_bls12_381::Fq::from_str($y1).unwrap(),
                    ark_bls12_381::Fq::from_str($y2).unwrap(),
                ),
            )
        };
    }
    macro_rules! to_g1_bn254 {
        ($x: expr, $y: expr) => {
            <ark_bn254::Bn254 as Pairing>::G1Affine::new(
                ark_bn254::Fq::from_str($x).unwrap(),
                ark_bn254::Fq::from_str($y).unwrap(),
            )
        };
    }

    macro_rules! to_g2_bn254 {
        ({$x1: expr, $x2: expr}, {$y1: expr, $y2: expr}) => {
            <ark_bn254::Bn254 as Pairing>::G2Affine::new(
                ark_bn254::Fq2::new(
                    ark_bn254::Fq::from_str($x1).unwrap(),
                    ark_bn254::Fq::from_str($x2).unwrap(),
                ),
                ark_bn254::Fq2::new(
                    ark_bn254::Fq::from_str($y1).unwrap(),
                    ark_bn254::Fq::from_str($y2).unwrap(),
                ),
            )
        };
    }
    pub(crate) use to_g1_bls12_381;
    pub(crate) use to_g1_bn254;
    pub(crate) use to_g2_bls12_381;
    pub(crate) use to_g2_bn254;
}
