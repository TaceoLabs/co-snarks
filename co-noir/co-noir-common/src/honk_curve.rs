use ark_ec::{CurveGroup, short_weierstrass};
use ark_ff::{BigInt, Field, One, PrimeField};
use ark_grumpkin::GrumpkinConfig;
use num_bigint::BigUint;
use std::str::FromStr;

// Des describes the PrimeField used for the Transcript
pub trait HonkCurve<Des: PrimeField>: CurveGroup<BaseField: PrimeField> {
    type CycleGroup: CurveGroup<BaseField = Self::ScalarField>;

    const NUM_BASEFIELD_ELEMENTS: usize;
    const NUM_SCALARFIELD_ELEMENTS: usize;
    const SUBGROUP_SIZE: usize;
    const LIBRA_UNIVARIATES_LENGTH: usize;

    fn g1_affine_from_xy(x: Self::BaseField, y: Self::BaseField) -> Self::Affine;
    fn g1_affine_to_xy(p: &Self::Affine) -> (Self::BaseField, Self::BaseField);

    fn convert_scalarfield_into(src: &Self::ScalarField) -> Vec<Des>;
    fn convert_scalarfield_back(src: &[Des]) -> Self::ScalarField;

    fn convert_basefield_into(src: &Self::BaseField) -> Vec<Des>;
    fn convert_basefield_back(src: &[Des]) -> Self::BaseField;

    fn convert_basefield_to_scalarfield(src: &Self::BaseField) -> Vec<Self::ScalarField>;

    // For the challenge
    fn convert_destinationfield_to_scalarfield(des: &Des) -> Self::ScalarField;

    // For the elliptic curve relation
    fn get_curve_b() -> Self::ScalarField;

    fn get_subgroup_generator() -> Self::ScalarField;

    fn get_subgroup_generator_inverse() -> Self::ScalarField {
        Self::get_subgroup_generator().inverse().unwrap()
    }

    fn get_cube_root_of_unity() -> Self::BaseField;

    //this is how the x coordinate of the infinity point is set in BB in certain cases
    fn get_bb_infinity_default() -> Self::BaseField;
}

impl HonkCurve<ark_bn254::Fr> for ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config> {
    type CycleGroup = ark_grumpkin::Projective;

    const NUM_BASEFIELD_ELEMENTS: usize = 2;
    const NUM_SCALARFIELD_ELEMENTS: usize = 1;
    const SUBGROUP_SIZE: usize = 256;
    const LIBRA_UNIVARIATES_LENGTH: usize = 9;

    fn g1_affine_from_xy(x: ark_bn254::Fq, y: ark_bn254::Fq) -> ark_bn254::G1Affine {
        ark_bn254::G1Affine::new(x, y)
    }

    fn g1_affine_to_xy(p: &Self::Affine) -> (Self::BaseField, Self::BaseField) {
        (p.x, p.y)
    }

    fn convert_scalarfield_into(src: &ark_bn254::Fr) -> Vec<ark_bn254::Fr> {
        vec![src.to_owned()]
    }

    fn convert_scalarfield_back(src: &[ark_bn254::Fr]) -> ark_bn254::Fr {
        debug_assert_eq!(src.len(), Self::NUM_SCALARFIELD_ELEMENTS);
        src[0].to_owned()
    }

    fn convert_basefield_into(src: &ark_bn254::Fq) -> Vec<ark_bn254::Fr> {
        let (a, b) = bn254_fq_to_fr(src);
        vec![a, b]
    }

    fn convert_basefield_to_scalarfield(src: &Self::BaseField) -> Vec<Self::ScalarField> {
        let (a, b) = bn254_fq_to_fr(src);
        vec![a, b]
    }

    fn convert_basefield_back(src: &[ark_bn254::Fr]) -> Self::BaseField {
        debug_assert_eq!(src.len(), Self::NUM_BASEFIELD_ELEMENTS);
        bn254_fq_to_fr_rev(&src[0], &src[1])
    }

    fn convert_destinationfield_to_scalarfield(des: &ark_bn254::Fr) -> ark_bn254::Fr {
        des.to_owned()
    }

    fn get_curve_b() -> Self::ScalarField {
        // We are getting grumpkin::b, which is -17
        -ark_bn254::Fr::from(17)
    }

    fn get_subgroup_generator() -> Self::ScalarField {
        let val = ark_bn254::Fr::from(BigInt::new([
            14453002906517207670,
            7023718024139043376,
            17331575720852783024,
            554159777355432964,
        ]));
        debug_assert_eq!(
            val,
            ark_bn254::Fr::from_str(
                "3478517300119284901893091970156912948790432420133812234316178878452092729974",
            )
            .unwrap()
        );

        val
    }

    fn get_subgroup_generator_inverse() -> Self::ScalarField {
        let val = ark_bn254::Fr::from(BigInt::new([
            7578525993492149718,
            11911168646041470090,
            7238721496332547558,
            2327185798872627923,
        ]));
        debug_assert_eq!(val, Self::get_subgroup_generator().inverse().unwrap());
        val
    }

    fn get_cube_root_of_unity() -> Self::BaseField {
        ark_bn254::Fq::from(BigInt::new([
            6296954981786320894,
            15344436770043026511,
            6476857749317913516,
            0,
        ]))
    }

    fn get_bb_infinity_default() -> Self::BaseField {
        let set_bit = BigUint::one() << (ark_bn254::Fq::MODULUS_BIT_SIZE.next_power_of_two() - 1);
        let mont_r = ark_bn254::Fq::from(ark_bn254::Fq::MODULUS.montgomery_r());
        ark_bn254::Fq::from(set_bit) / mont_r
    }
}

impl HonkCurve<ark_bn254::Fr> for short_weierstrass::Projective<GrumpkinConfig> {
    type CycleGroup = ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>;

    const NUM_BASEFIELD_ELEMENTS: usize = 2;
    const NUM_SCALARFIELD_ELEMENTS: usize = 1;
    const SUBGROUP_SIZE: usize = 87;
    const LIBRA_UNIVARIATES_LENGTH: usize = 3;

    fn g1_affine_from_xy(x: Self::BaseField, y: Self::BaseField) -> Self::Affine {
        ark_grumpkin::Affine::new(x, y)
    }

    fn g1_affine_to_xy(p: &Self::Affine) -> (Self::BaseField, Self::BaseField) {
        (p.x, p.y)
    }

    fn convert_scalarfield_into(src: &Self::ScalarField) -> Vec<ark_bn254::Fr> {
        let (a, b) = convert_grumpkin_fr_to_bn254_frs(src);
        vec![a, b]
    }

    fn convert_scalarfield_back(src: &[ark_bn254::Fr]) -> Self::ScalarField {
        debug_assert_eq!(src.len(), Self::NUM_BASEFIELD_ELEMENTS);
        bn254_fq_to_fr_rev(&src[0], &src[1])
    }

    fn convert_basefield_into(src: &Self::BaseField) -> Vec<ark_bn254::Fr> {
        vec![ark_bn254::Fr::from(*src)]
    }

    fn convert_basefield_back(src: &[ark_bn254::Fr]) -> Self::BaseField {
        debug_assert_eq!(src.len(), Self::NUM_SCALARFIELD_ELEMENTS);
        src[0].to_owned()
    }

    fn convert_destinationfield_to_scalarfield(des: &ark_bn254::Fr) -> Self::ScalarField {
        convert_to_grumpkin_fr(des)
    }

    fn get_curve_b() -> Self::ScalarField {
        ark_grumpkin::Fr::from(3)
    }

    fn get_subgroup_generator() -> Self::ScalarField {
        // 9266039526417139266040601060442016598255985496235718633420974982172445857899
        let val = ark_grumpkin::Fr::from(BigInt::new([
            8945551602226911339,
            13953598326038888636,
            1481858683227075358,
            1476165261776872341,
        ]));
        debug_assert_eq!(
            val,
            ark_grumpkin::Fr::from_str(
                "9266039526417139266040601060442016598255985496235718633420974982172445857899",
            )
            .unwrap()
        );
        val
    }
    fn get_subgroup_generator_inverse() -> Self::ScalarField {
        let val = ark_grumpkin::Fr::from(BigInt::new([
            14836326461244840328,
            12137613447679210578,
            18066067572638974063,
            894213515885537164,
        ]));
        debug_assert_eq!(val, Self::get_subgroup_generator().inverse().unwrap());
        val
    }
    fn get_cube_root_of_unity() -> Self::BaseField {
        todo!("cube root of unity for grumpkin::Fq")
    }

    fn get_bb_infinity_default() -> Self::BaseField {
        let set_bit =
            BigUint::one() << (ark_grumpkin::Fq::MODULUS_BIT_SIZE.next_power_of_two() - 1);
        let mont_r = ark_grumpkin::Fq::from(ark_grumpkin::Fq::MODULUS.montgomery_r());
        ark_grumpkin::Fq::from(set_bit) / mont_r
    }

    fn convert_basefield_to_scalarfield(_src: &Self::BaseField) -> Vec<Self::ScalarField> {
        unimplemented!("Not needed for grumpkin")
    }
}

pub(crate) const NUM_LIMB_BITS: u32 = 68;
const TOTAL_BITS: u32 = 254;

/**
* @brief Converts grumpkin::fr to 2 bb::fr elements
* @details First, this function must return 2 bb::fr elements because the grumpkin::fr field has a larger modulus than
* the bb::fr field, so we choose to send 1 grumpkin::fr element to 2 bb::fr elements to maintain injectivity.
* This function the reverse of convert_from_bn254_frs(std::span&lt;const bb::fr&gt; fr_vec, grumpkin::fr*) by merging the two
* pairs of limbs back into the 2 bb::fr elements. For the implementation, we want to minimize the number of constraints
* created by the circuit form, which happens to use 68 bit limbs to represent a grumpkin::fr (as a bigfield).
* Therefore, our mapping will split a grumpkin::fr into a 136 bit chunk for the lower two bigfield limbs and the upper
* chunk for the upper two limbs. The upper chunk ends up being 254 - 2*68 = 118 bits as a result. We manipulate the
* value using bitwise masks and shifts to obtain our two chunks.
* @param input
* @return std::array&lt; bb::fr, 2&gt;
*/
pub fn bn254_fq_to_fr(fq: &ark_bn254::Fq) -> (ark_bn254::Fr, ark_bn254::Fr) {
    // Goal is to slice up the 64 bit limbs of grumpkin::fr/uint256_t to mirror the 68 bit limbs of bigfield
    // We accomplish this by dividing the grumpkin::fr's value into two 68*2=136 bit pieces.
    const LOWER_BITS: u32 = 2 * NUM_LIMB_BITS;
    let lower_mask = (BigUint::one() << LOWER_BITS) - BigUint::one();
    let value = BigUint::from(*fq);

    debug_assert!(value < (BigUint::one() << TOTAL_BITS));

    let res0 = &value & lower_mask;
    let res1 = value >> LOWER_BITS;

    debug_assert!(res1 < (BigUint::one() << (TOTAL_BITS - LOWER_BITS)));

    let res0 = ark_bn254::Fr::from(res0);
    let res1 = ark_bn254::Fr::from(res1);

    (res0, res1)
}

fn bn254_fq_to_fr_rev(res0: &ark_bn254::Fr, res1: &ark_bn254::Fr) -> ark_bn254::Fq {
    // Combines the two elements into one uint256_t, and then convert that to a grumpkin::fr

    let res0 = BigUint::from(*res0);
    let res1 = BigUint::from(*res1);

    debug_assert!(res0 < (BigUint::one() << (NUM_LIMB_BITS * 2))); // lower 136 bits
    debug_assert!(res1 < (BigUint::one() << (TOTAL_BITS - NUM_LIMB_BITS * 2))); // upper 254-136=118 bits

    let value = res0 + (res1 << (NUM_LIMB_BITS * 2));
    ark_bn254::Fq::from(value)
}

fn convert_grumpkin_fr_to_bn254_frs(val: &ark_grumpkin::Fr) -> (ark_bn254::Fr, ark_bn254::Fr) {
    // Convert grumpkin::fr to 2 bb::fr elements
    bn254_fq_to_fr(&ark_bn254::Fq::from(*val))
}

fn convert_to_grumpkin_fr(f: &ark_bn254::Fr) -> ark_grumpkin::Fr {
    const NUM_BITS_IN_TWO_LIMBS: u32 = 2 * NUM_LIMB_BITS; // the number of bits in 2 bigfield limbs which is 136

    let limb_mask = (BigUint::one() << NUM_BITS_IN_TWO_LIMBS) - BigUint::one(); // split bn254_fr into two 136 bit pieces
    let value = BigUint::from(*f);
    let low = &value & &limb_mask;
    let hi = &value >> NUM_BITS_IN_TWO_LIMBS;

    debug_assert_eq!(&low + (&hi << NUM_BITS_IN_TWO_LIMBS), value);

    let fr_vec = [ark_grumpkin::Fr::from(low), ark_grumpkin::Fr::from(hi)];

    // Combines the two elements into one uint256_t, and then convert that to a grumpkin::fr
    debug_assert!(
        BigUint::from(fr_vec[0]) < (BigUint::one() << (NUM_LIMB_BITS * 2)),
        "Conversion error here usually implies some bad proof serde or parsing"
    );
    debug_assert!(
        BigUint::from(fr_vec[1]) < (BigUint::one() << (TOTAL_BITS - NUM_LIMB_BITS * 2)),
        "Conversion error here usually implies some bad proof serde or parsing"
    );

    let value = BigUint::from(fr_vec[0]) + (BigUint::from(fr_vec[1]) << (NUM_LIMB_BITS * 2));
    ark_grumpkin::Fr::from(value)
}
