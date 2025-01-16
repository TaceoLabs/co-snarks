use std::sync::Arc;

use crate::{
    builder::UltraCircuitBuilder,
    crs::ProverCrs,
    honk_curve::HonkCurve,
    polynomials::polynomial_types::{PrecomputedEntities, PRECOMPUTED_ENTITIES_SIZE},
    serialize::{Serialize, SerializeP},
    types::types::{PairingPointAccumulatorPubInputIndices, PAIRING_POINT_ACCUMULATOR_SIZE},
    utils::Utils,
    HonkProofError, HonkProofResult, TranscriptFieldType,
};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::Zero;
use co_acvm::PlainAcvmSolver;

pub struct VerifyingKey<P: Pairing> {
    pub crs: P::G2Affine,
    pub circuit_size: u32,
    pub num_public_inputs: u32,
    pub pub_inputs_offset: u32,
    pub contains_pairing_point_accumulator: bool,
    pub pairing_point_accumulator_public_input_indices: PairingPointAccumulatorPubInputIndices,
    pub commitments: PrecomputedEntities<P::G1Affine>,
}

impl<P: Pairing> VerifyingKey<P> {
    pub fn create(
        circuit: UltraCircuitBuilder<P>,
        prover_crs: Arc<ProverCrs<P>>,
        verifier_crs: P::G2Affine,
        driver: &mut PlainAcvmSolver<P::ScalarField>,
    ) -> HonkProofResult<Self> {
        let (_, vk) = circuit.create_keys(prover_crs, verifier_crs, driver)?;
        Ok(vk)
    }

    pub fn from_barrettenberg_and_crs(
        barretenberg_vk: VerifyingKeyBarretenberg<P>,
        crs: P::G2Affine,
    ) -> Self {
        Self {
            crs,
            circuit_size: barretenberg_vk.circuit_size as u32,
            num_public_inputs: barretenberg_vk.num_public_inputs as u32,
            pub_inputs_offset: barretenberg_vk.pub_inputs_offset as u32,
            commitments: barretenberg_vk.commitments,
            contains_pairing_point_accumulator: barretenberg_vk.contains_pairing_point_accumulator,
            pairing_point_accumulator_public_input_indices: barretenberg_vk
                .pairing_point_accumulator_public_input_indices,
        }
    }

    pub fn to_barrettenberg(self) -> VerifyingKeyBarretenberg<P> {
        VerifyingKeyBarretenberg {
            circuit_size: self.circuit_size as u64,
            log_circuit_size: Utils::get_msb64(self.circuit_size as u64) as u64,
            num_public_inputs: self.num_public_inputs as u64,
            pub_inputs_offset: self.pub_inputs_offset as u64,
            commitments: self.commitments,
            contains_pairing_point_accumulator: self.contains_pairing_point_accumulator,
            pairing_point_accumulator_public_input_indices: self
                .pairing_point_accumulator_public_input_indices,
        }
    }
}

pub struct VerifyingKeyBarretenberg<P: Pairing> {
    pub circuit_size: u64,
    pub log_circuit_size: u64,
    pub num_public_inputs: u64,
    pub pub_inputs_offset: u64,
    pub contains_pairing_point_accumulator: bool,
    pub pairing_point_accumulator_public_input_indices: PairingPointAccumulatorPubInputIndices,
    pub commitments: PrecomputedEntities<P::G1Affine>,
}

impl<P: HonkCurve<TranscriptFieldType>> VerifyingKeyBarretenberg<P> {
    const FIELDSIZE_BYTES: u32 = SerializeP::<P>::FIELDSIZE_BYTES;
    const SER_FULL_SIZE: usize = 4 * 8
        + 1
        + PAIRING_POINT_ACCUMULATOR_SIZE * 4
        + PRECOMPUTED_ENTITIES_SIZE * 2 * Self::FIELDSIZE_BYTES as usize;
    const SER_COMPRESSED_SIZE: usize = Self::SER_FULL_SIZE - 1 - PAIRING_POINT_ACCUMULATOR_SIZE * 4;

    pub fn to_field_elements(&self) -> Vec<TranscriptFieldType> {
        let len = 4
            + self.pairing_point_accumulator_public_input_indices.len()
            + self.commitments.elements.len() * 2 * P::NUM_BASEFIELD_ELEMENTS;
        let mut field_elements = Vec::with_capacity(len);

        field_elements.push(TranscriptFieldType::from(self.circuit_size));
        field_elements.push(TranscriptFieldType::from(self.num_public_inputs));
        field_elements.push(TranscriptFieldType::from(self.pub_inputs_offset));
        field_elements.push(TranscriptFieldType::from(
            self.contains_pairing_point_accumulator,
        ));

        for val in self.pairing_point_accumulator_public_input_indices.iter() {
            field_elements.push(TranscriptFieldType::from(*val));
        }

        for el in self.commitments.iter() {
            if el.is_zero() {
                let convert = P::convert_basefield_into(&P::BaseField::zero());
                field_elements.extend_from_slice(&convert);
                field_elements.extend(convert);
            } else {
                let (x, y) = P::g1_affine_to_xy(el);
                field_elements.extend(P::convert_basefield_into(&x));
                field_elements.extend(P::convert_basefield_into(&y));
            }
        }

        debug_assert_eq!(field_elements.len(), len);
        field_elements
    }

    pub fn to_buffer(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(Self::SER_FULL_SIZE);

        Serialize::<P::ScalarField>::write_u64(&mut buffer, self.circuit_size);
        Serialize::<P::ScalarField>::write_u64(&mut buffer, self.log_circuit_size);
        Serialize::<P::ScalarField>::write_u64(&mut buffer, self.num_public_inputs);
        Serialize::<P::ScalarField>::write_u64(&mut buffer, self.pub_inputs_offset);
        Serialize::<P::ScalarField>::write_u8(
            &mut buffer,
            self.contains_pairing_point_accumulator as u8,
        );

        for val in self.pairing_point_accumulator_public_input_indices.iter() {
            Serialize::<P::ScalarField>::write_u32(&mut buffer, *val);
        }

        for el in self.commitments.iter() {
            SerializeP::<P>::write_g1_element(&mut buffer, el, true);
        }

        debug_assert_eq!(buffer.len(), Self::SER_FULL_SIZE);
        buffer
    }
    // BB for Keccak doesn't use the recursive stuff in the vk
    pub fn to_buffer_keccak(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(Self::SER_COMPRESSED_SIZE);

        Serialize::<P::ScalarField>::write_u64(&mut buffer, self.circuit_size);
        Serialize::<P::ScalarField>::write_u64(&mut buffer, self.log_circuit_size);
        Serialize::<P::ScalarField>::write_u64(&mut buffer, self.num_public_inputs);
        Serialize::<P::ScalarField>::write_u64(&mut buffer, self.pub_inputs_offset);

        for el in self.commitments.iter() {
            SerializeP::<P>::write_g1_element(&mut buffer, el, true);
        }

        debug_assert_eq!(buffer.len(), Self::SER_COMPRESSED_SIZE);
        buffer
    }

    pub fn from_buffer(buf: &[u8]) -> HonkProofResult<Self> {
        let size = buf.len();
        let mut offset = 0;

        if size != Self::SER_FULL_SIZE && size != Self::SER_COMPRESSED_SIZE {
            return Err(HonkProofError::InvalidKeyLength);
        }

        // Read data
        let circuit_size = Serialize::<P::ScalarField>::read_u64(buf, &mut offset);
        let log_circuit_size = Serialize::<P::ScalarField>::read_u64(buf, &mut offset);
        if log_circuit_size != Utils::get_msb64(circuit_size) as u64 {
            return Err(HonkProofError::CorruptedKey);
        }
        let num_public_inputs = Serialize::<P::ScalarField>::read_u64(buf, &mut offset);
        let pub_inputs_offset = Serialize::<P::ScalarField>::read_u64(buf, &mut offset);

        let (contains_pairing_point_accumulator, pairing_point_accumulator_public_input_indices) =
            if size == Self::SER_FULL_SIZE {
                let contains_pairing_point_accumulator_u8 =
                    Serialize::<P::ScalarField>::read_u8(buf, &mut offset);
                if contains_pairing_point_accumulator_u8 > 1 {
                    return Err(HonkProofError::CorruptedKey);
                }

                let mut pairing_point_accumulator_public_input_indices =
                    PairingPointAccumulatorPubInputIndices::default();
                for val in pairing_point_accumulator_public_input_indices.iter_mut() {
                    *val = Serialize::<P::ScalarField>::read_u32(buf, &mut offset);
                }
                (
                    contains_pairing_point_accumulator_u8 == 1,
                    pairing_point_accumulator_public_input_indices,
                )
            } else {
                (false, Default::default())
            };

        let mut commitments = PrecomputedEntities::default();

        for el in commitments.iter_mut() {
            *el = SerializeP::<P>::read_g1_element(buf, &mut offset, true);
        }

        debug_assert!(offset == Self::SER_FULL_SIZE || offset == Self::SER_COMPRESSED_SIZE);

        Ok(Self {
            circuit_size,
            log_circuit_size,
            num_public_inputs,
            pub_inputs_offset,
            contains_pairing_point_accumulator,
            pairing_point_accumulator_public_input_indices,
            commitments,
        })
    }
}
