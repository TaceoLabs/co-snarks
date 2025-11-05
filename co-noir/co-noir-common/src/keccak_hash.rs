use crate::transcript::TranscriptHasher;
use ark_ec::AffineRepr;
use ark_ff::{PrimeField, Zero};
use noir_types::U256;
use ruint::Uint;
use sha3::{Digest, Keccak256};

impl<F: PrimeField> TranscriptHasher<F> for Keccak256 {
    fn hash(buffer: Vec<Self::DataType>) -> Self::DataType {
        // Losing 2 bits of this is not an issue -> we can just reduce mod p

        let vec = buffer
            .iter()
            .flat_map(|el| el.0.to_be_bytes::<32>().to_vec())
            .collect::<Vec<u8>>();
        let mut hasher = Keccak256::default();
        hasher.update(vec);
        let hash_result = hasher.finalize();

        // Convert the hash result (32 bytes) into a U256
        U256(Uint::<256, 4>::from_be_bytes::<32>(
            hash_result
                .as_slice()
                .try_into()
                .expect("slice with incorrect length"),
        ))
    }

    type DataType = U256;
    const USE_PADDING: bool = false;
    const NUM_BASEFIELD_ELEMENTS: usize = 1;

    fn convert_scalarfield_into<P: crate::honk_curve::HonkCurve<F>>(
        element: &P::ScalarField,
    ) -> Vec<Self::DataType> {
        vec![U256::convert_field_into(element)]
    }

    fn convert_point<P: crate::honk_curve::HonkCurve<F>>(
        element: &P::Affine,
    ) -> Vec<Self::DataType> {
        let (x, y) = if element.is_zero() {
            // we are at infinity
            (
                U256::convert_field_into(&P::BaseField::zero()),
                U256::convert_field_into(&P::BaseField::zero()),
            )
        } else {
            let (x, y) = P::g1_affine_to_xy(element);
            (U256::convert_field_into(&x), U256::convert_field_into(&y))
        };
        vec![x, y]
    }

    fn convert_scalarfield_back<P: crate::honk_curve::HonkCurve<F>>(
        elements: &[Self::DataType],
    ) -> P::ScalarField {
        debug_assert_eq!(elements.len(), 1);
        let bytes = elements[0].0.to_be_bytes::<32>();
        P::ScalarField::from_be_bytes_mod_order(&bytes)
    }

    fn convert_basefield_back<P: crate::honk_curve::HonkCurve<F>>(
        elements: &[Self::DataType],
    ) -> P::BaseField {
        debug_assert_eq!(elements.len(), 1);
        let bytes = elements[0].0.to_be_bytes::<32>();
        P::BaseField::from_be_bytes_mod_order(&bytes)
    }

    fn split_challenge(challenge: Self::DataType) -> [Self::DataType; 2] {
        // Challenges sizes are matched with the challenge sizes used in bb::fr
        // match the parameter used in stdlib, which is derived from cycle_scalar (is 128)
        const LO_BITS: u64 = 128;
        const HI_BITS: u64 = 126;

        let lo = challenge.slice(0, LO_BITS);
        let hi = challenge.slice(LO_BITS, LO_BITS + HI_BITS);

        [lo, hi]
    }

    fn convert_challenge_into<P: crate::honk_curve::HonkCurve<F>>(challenge: &F) -> Self::DataType {
        U256::convert_field_into(challenge)
    }

    fn convert_destinationfield_to_scalarfield<P: crate::honk_curve::HonkCurve<F>>(
        element: &Self::DataType,
    ) -> P::ScalarField {
        let bytes = element.0.to_be_bytes::<32>();
        P::ScalarField::from_be_bytes_mod_order(&bytes)
    }

    fn to_buffer(buffer: &[Self::DataType]) -> Vec<u8> {
        buffer
            .iter()
            .flat_map(|el| el.0.to_be_bytes::<32>().to_vec())
            .collect::<Vec<u8>>()
    }

    fn from_buffer(buffer: &[u8]) -> Vec<Self::DataType> {
        buffer
            .chunks(32)
            .map(|chunk| {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(chunk);
                U256(Uint::<256, 4>::from_be_bytes(bytes))
            })
            .collect::<Vec<U256>>()
    }
}
