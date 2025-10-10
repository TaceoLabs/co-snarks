use ark_ec::AdditiveGroup;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::FftField;
use ark_ff::{BigInt, BigInteger, Field, PrimeField};
use co_builder::{
    eccvm::{
        NUM_LIMB_BITS_IN_FIELD_SIMULATION,
        ecc_op_queue::{EccOpCode, UltraOp},
    },
    transcript::TranscriptFieldType,
};

// Reference implementations for CoEccOpQueue
pub trait EndomorphismParams {
    const ENDO_G1_LO: u64;
    const ENDO_G1_MID: u64;
    const ENDO_G1_HI: u64;
    const ENDO_G2_LO: u64;
    const ENDO_G2_MID: u64;
    const ENDO_MINUS_B1_LO: u64;
    const ENDO_MINUS_B1_MID: u64;
    const ENDO_B2_LO: u64;
    const ENDO_B2_MID: u64;
}

pub struct Bn254ParamsFr;
pub struct Bn254ParamsFq;

impl EndomorphismParams for Bn254ParamsFr {
    const ENDO_G1_LO: u64 = 0x7a7bd9d4391eb18d;
    const ENDO_G1_MID: u64 = 0x4ccef014a773d2cf;
    const ENDO_G1_HI: u64 = 0x0000000000000002;
    const ENDO_G2_LO: u64 = 0xd91d232ec7e0b3d7;
    const ENDO_G2_MID: u64 = 0x0000000000000002;
    const ENDO_MINUS_B1_LO: u64 = 0x8211bbeb7d4f1128;
    const ENDO_MINUS_B1_MID: u64 = 0x6f4d8248eeb859fc;
    const ENDO_B2_LO: u64 = 0x89d3256894d213e3;
    const ENDO_B2_MID: u64 = 0x0000000000000000;
}

impl EndomorphismParams for Bn254ParamsFq {
    const ENDO_G1_LO: u64 = 0x7a7bd9d4391eb18d;
    const ENDO_G1_MID: u64 = 0x4ccef014a773d2cf;
    const ENDO_G1_HI: u64 = 0x0000000000000002;
    const ENDO_G2_LO: u64 = 0xd91d232ec7e0b3d2;
    const ENDO_G2_MID: u64 = 0x0000000000000002;
    const ENDO_MINUS_B1_LO: u64 = 0x8211bbeb7d4f1129;
    const ENDO_MINUS_B1_MID: u64 = 0x6f4d8248eeb859fc;
    const ENDO_B2_LO: u64 = 0x89d3256894d213e2;
    const ENDO_B2_MID: u64 = 0x0000000000000000;
}

/**
 * For short Weierstrass curves y^2 = x^3 + b mod r, if there exists a cube root of unity mod r,
 * we can take advantage of an enodmorphism to decompose a 254 bit scalar into 2 128 bit scalars.
 * \beta = cube root of 1, mod q (q = order of fq)
 * \lambda = cube root of 1, mod r (r = order of fr)
 *
 * For a point P1 = (X, Y), where Y^2 = X^3 + b, we know that
 * the point P2 = (X * \beta, Y) is also a point on the curve
 * We can represent P2 as a scalar multiplication of P1, where P2 = \lambda * P1
 *
 * For a generic multiplication of P1 by a 254 bit scalar k, we can decompose k
 * into 2 127 bit scalars (k1, k2), such that k = k1 - (k2 * \lambda)
 *
 * We can now represent (k * P1) as (k1 * P1) - (k2 * P2), where P2 = (X * \beta, Y).
 * As k1, k2 have half the bit length of k, we have reduced the number of loop iterations of our
 * scalar multiplication algorithm in half
 *
 * To find k1, k2, We use the extended euclidean algorithm to find 4 short scalars [a1, a2], [b1, b2] such that
 * modulus = (a1 * b2) - (b1 * a2)
 * We then compute scalars c1 = round(b2 * k / r), c2 = round(b1 * k / r), where
 * k1 = (c1 * a1) + (c2 * a2), k2 = -((c1 * b1) + (c2 * b2))
 * We pre-compute scalars g1 = (2^256 * b1) / n, g2 = (2^256 * b2) / n, to avoid having to perform long division
 * on 512-bit scalars
 **/
pub fn split_into_endomorphism_scalars<
    P: CurveGroup<ScalarField = TranscriptFieldType, BaseField: PrimeField>,
    Params: EndomorphismParams,
>(
    scalar: P::ScalarField,
) -> (P::ScalarField, P::ScalarField) {
    let endo_g1 = BigInt([
        Params::ENDO_G1_LO,
        Params::ENDO_G1_MID,
        Params::ENDO_G1_HI,
        0,
    ]);

    let endo_g2 = BigInt([Params::ENDO_G2_LO, Params::ENDO_G2_MID, 0, 0]);

    let endo_minus_b1 = BigInt([Params::ENDO_MINUS_B1_LO, Params::ENDO_MINUS_B1_MID, 0, 0]);

    let endo_b2 = BigInt([Params::ENDO_B2_LO, Params::ENDO_B2_MID, 0, 0]);

    let scalar_bigint = to_montgomery_form(scalar).into_bigint();

    let c1 = endo_g2.mul_high(&scalar_bigint);
    let c2 = endo_g1.mul_high(&scalar_bigint);

    let q1 = c1.mul(&endo_minus_b1).0;
    let q2 = c2.mul(&endo_b2).0;

    let q1 = from_montgomery_form(P::ScalarField::from_bigint(q1).unwrap());
    let q2 = from_montgomery_form(P::ScalarField::from_bigint(q2).unwrap());

    let t1 = q2 - q1;
    let beta = P::ScalarField::get_root_of_unity(3).unwrap();
    let t2 = t1 * beta + scalar;

    (t2, t1)
}

/**
 *
 * @brief Given an ecc operation and its inputs, decompose into ultra format and populate ultra_ops
 *
 * @param op_code
 * @param point
 * @param scalar
 * @return UltraOp
 */
pub fn construct_and_populate_ultra_ops<
    P: CurveGroup<ScalarField = TranscriptFieldType, BaseField: PrimeField>,
>(
    op_code: EccOpCode,
    point: P::Affine,
    scalar: P::ScalarField,
) -> UltraOp<P> {
    let (x, y, return_is_infinity) = (point.x().unwrap(), point.y().unwrap(), point.is_zero());
    let x_256 = x.into_bigint();
    let y_256 = y.into_bigint();

    // Decompose point coordinates (Fq) into hi-lo chunks (Fr)
    const CHUNK_SIZE: u8 = 2 * NUM_LIMB_BITS_IN_FIELD_SIMULATION as u8;
    let x_256 = x_256.to_bytes_be();
    let y_256 = y_256.to_bytes_be();

    let zero_pad_x = vec![0u8; ((2 * CHUNK_SIZE as usize) >> 3) - x_256.len()];
    let zero_pad_y = vec![0u8; ((2 * CHUNK_SIZE as usize) >> 3) - y_256.len()];

    let x_256 = [zero_pad_x, x_256].concat();
    let y_256 = [zero_pad_y, y_256].concat();

    let (x_hi, x_lo) = x_256.split_at(CHUNK_SIZE as usize >> 3);
    let (y_hi, y_lo) = y_256.split_at(CHUNK_SIZE as usize >> 3);

    let (x_lo, x_hi, y_lo, y_hi) = (
        P::ScalarField::from_be_bytes_mod_order(x_lo),
        P::ScalarField::from_be_bytes_mod_order(x_hi),
        P::ScalarField::from_be_bytes_mod_order(y_lo),
        P::ScalarField::from_be_bytes_mod_order(y_hi),
    );

    let converted = from_montgomery_form(scalar);

    let converted_bigint = converted.into_bigint();

    let (z_1, z_2) = if converted_bigint.num_bits() <= 128 {
        (scalar, P::ScalarField::ZERO)
    } else {
        let (z_1, z_2) = split_into_endomorphism_scalars::<P, Bn254ParamsFr>(converted);
        (to_montgomery_form(z_1), to_montgomery_form(z_2))
    };

    UltraOp {
        op_code,
        x_lo,
        x_hi,
        y_lo,
        y_hi,
        z_1,
        z_2,
        return_is_infinity,
    }
}

fn from_montgomery_form(x: TranscriptFieldType) -> TranscriptFieldType {
    let mont_r: TranscriptFieldType = TranscriptFieldType::MODULUS.montgomery_r().into();
    x * mont_r.inverse().unwrap()
}

fn to_montgomery_form(x: TranscriptFieldType) -> TranscriptFieldType {
    let mont_r: TranscriptFieldType = TranscriptFieldType::MODULUS.montgomery_r().into();
    x * mont_r
}

#[cfg(test)]
mod test {
    use ark_bn254::Bn254;
    use ark_ec::pairing::Pairing;
    use co_builder::eccvm::ecc_op_queue::{EccOpCode, UltraOp};
    use mpc_core::gadgets::field_from_hex_string;

    use crate::{Bn254ParamsFr, construct_and_populate_ultra_ops, split_into_endomorphism_scalars};

    type P = Bn254;
    type Bn254G1 = ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>;
    type Point = <P as Pairing>::G1Affine;

    #[test]
    fn test_construct_and_populate_ultra_ops() {
        // Point: (0x211561d55817d8e259180a3e684611e49f458da76ade6a1f5a2bad3dd20ed047, 0x1eab68c1f7807f482ffc7dd13fd9a0ce3bf26240230270ac781e2dc5c5460b3f)
        // Scalar: 0x02d9b5973384d81dc3e502de86b99ff96c38b15c4b1c4520d2a3147c7777ce1f
        // x_lo: 0x000000000000000000000000000000e49f458da76ade6a1f5a2bad3dd20ed047
        // x_hi: 0x0000000000000000000000000000000000211561d55817d8e259180a3e684611
        // y_lo: 0x000000000000000000000000000000ce3bf26240230270ac781e2dc5c5460b3f
        // y_hi: 0x00000000000000000000000000000000001eab68c1f7807f482ffc7dd13fd9a0
        // z_1: 0x0000000000000000000000000000000018ffbbc11990c665e3edc805f6d1ccf9
        // z_2: 0x000000000000000000000000000000004f9333cd430dea1bc75410733863e4f1

        let point = Point {
            x: field_from_hex_string(
                "0x211561d55817d8e259180a3e684611e49f458da76ade6a1f5a2bad3dd20ed047",
            )
            .unwrap(),
            y: field_from_hex_string(
                "0x1eab68c1f7807f482ffc7dd13fd9a0ce3bf26240230270ac781e2dc5c5460b3f",
            )
            .unwrap(),
            infinity: false,
        };

        let scalar = field_from_hex_string(
            "0x02d9b5973384d81dc3e502de86b99ff96c38b15c4b1c4520d2a3147c7777ce1f",
        )
        .unwrap();

        let ultra_op: UltraOp<_> =
            construct_and_populate_ultra_ops::<Bn254G1>(EccOpCode::default(), point, scalar);

        let expected_ultra_op = UltraOp {
            op_code: EccOpCode::default(),
            x_lo: field_from_hex_string(
                "0x000000000000000000000000000000e49f458da76ade6a1f5a2bad3dd20ed047",
            )
            .unwrap(),
            x_hi: field_from_hex_string(
                "0x0000000000000000000000000000000000211561d55817d8e259180a3e684611",
            )
            .unwrap(),
            y_lo: field_from_hex_string(
                "0x000000000000000000000000000000ce3bf26240230270ac781e2dc5c5460b3f",
            )
            .unwrap(),
            y_hi: field_from_hex_string(
                "0x00000000000000000000000000000000001eab68c1f7807f482ffc7dd13fd9a0",
            )
            .unwrap(),
            z_1: field_from_hex_string(
                "0x0000000000000000000000000000000018ffbbc11990c665e3edc805f6d1ccf9",
            )
            .unwrap(),
            z_2: field_from_hex_string(
                "0x000000000000000000000000000000004f9333cd430dea1bc75410733863e4f1",
            )
            .unwrap(),
            return_is_infinity: false,
        };

        assert_eq!(ultra_op, expected_ultra_op);
    }

    #[test]
    fn test_split_into_endomorphism_scalars() {
        // Scalar: 0x1a7855215e6c4b0cf02a37d1d2c8fb001f24f29e98a784096786558e824ee6b3
        // t1: 0x1ba2c8d6ff259fa8c79d53093767cd1002d67810d1cb07c131d4fbfac46bf8c9
        // t2: 0x0b8ab330373e7c36cab04db25e7f2a1119d7820f8941279a4ec3718c0ebe742c

        let scalar = field_from_hex_string(
            "0x1a7855215e6c4b0cf02a37d1d2c8fb001f24f29e98a784096786558e824ee6b3",
        )
        .unwrap();

        let expected_result = (
            field_from_hex_string(
                "0x0b8ab330373e7c36cab04db25e7f2a1119d7820f8941279a4ec3718c0ebe742c",
            )
            .unwrap(),
            field_from_hex_string(
                "0x1ba2c8d6ff259fa8c79d53093767cd1002d67810d1cb07c131d4fbfac46bf8c9",
            )
            .unwrap(),
        );

        assert_eq!(
            split_into_endomorphism_scalars::<Bn254G1, Bn254ParamsFr>(scalar),
            expected_result
        );
    }
}
