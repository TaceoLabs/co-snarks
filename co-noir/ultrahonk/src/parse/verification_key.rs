use super::{
    builder::{GenericUltraCircuitBuilder, UltraCircuitBuilder, UltraCircuitVariable},
    types::{AggregationObjectPubInputIndices, AGGREGATION_OBJECT_SIZE},
};
use crate::{
    prelude::{CrsParser, HonkCurve, TranscriptFieldType, TranscriptType},
    prover::HonkProofResult,
    types::{Crs, HonkProof, PrecomputedEntities, ProverCrs, ProvingKey, VerifyingKey},
    Utils,
};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::PrimeField;
use eyre::Result;

impl<P: Pairing> VerifyingKey<P> {
    pub fn create(circuit: UltraCircuitBuilder<P>, crs: Crs<P>) -> HonkProofResult<Self> {
        let (_, vk) = circuit.create_keys(crs)?;
        Ok(vk)
    }

    pub fn get_crs<S: UltraCircuitVariable<P::ScalarField>>(
        circuit: &GenericUltraCircuitBuilder<P, S>,
        path_g1: &str,
        path_g2: &str,
    ) -> Result<Crs<P>> {
        tracing::info!("Getting crs");
        ProvingKey::get_crs(circuit, path_g1, path_g2)
    }

    pub fn get_prover_crs<S: UltraCircuitVariable<P::ScalarField>>(
        circuit: &GenericUltraCircuitBuilder<P, S>,
        path_g1: &str,
    ) -> Result<ProverCrs<P>> {
        tracing::info!("Getting crs");
        ProvingKey::get_prover_crs(circuit, path_g1)
    }

    pub fn get_verifier_crs<S: UltraCircuitVariable<P::ScalarField>>(
        path_g2: &str,
    ) -> Result<P::G2Affine> {
        tracing::info!("Getting verifier crs");
        CrsParser::<P>::get_crs_g2(path_g2)
    }
}

pub struct VerifyingKeyBarretenberg<P: Pairing> {
    pub(crate) circuit_size: u64,
    pub(crate) log_circuit_size: u64,
    pub(crate) num_public_inputs: u64,
    pub(crate) pub_inputs_offset: u64,
    pub(crate) contains_recursive_proof: bool,
    pub(crate) recursive_proof_public_input_indices: AggregationObjectPubInputIndices,
    pub(crate) commitments: PrecomputedEntities<P::G1Affine>,
}

impl<P: HonkCurve<TranscriptFieldType>> VerifyingKeyBarretenberg<P> {
    const NUM_64_LIMBS: u32 = P::BaseField::MODULUS_BIT_SIZE.div_ceil(64);
    const FIELDSIZE_BYTES: u32 = Self::NUM_64_LIMBS * 8;

    fn write_g1_element(buf: &mut Vec<u8>, el: &P::G1Affine, write_x_first: bool) {
        let prev_len = buf.len();

        if el.is_zero() {
            for _ in 0..Self::FIELDSIZE_BYTES * 2 {
                buf.push(255);
            }
        } else {
            let (x, y) = P::g1_affine_to_xy(el);
            if write_x_first {
                HonkProof::<P::BaseField>::write_field_element(buf, x);
                HonkProof::<P::BaseField>::write_field_element(buf, y);
            } else {
                HonkProof::<P::BaseField>::write_field_element(buf, y);
                HonkProof::<P::BaseField>::write_field_element(buf, x);
            }
        }

        debug_assert_eq!(buf.len() - prev_len, Self::FIELDSIZE_BYTES as usize * 2);
    }

    pub fn to_buffer(&self) -> Vec<u8> {
        let total_size = 4 * 8
            + 1
            + AGGREGATION_OBJECT_SIZE * 4
            + PrecomputedEntities::<P::G1Affine>::len() * 2 * Self::FIELDSIZE_BYTES as usize;

        let mut buffer = Vec::with_capacity(total_size);

        HonkProof::<P::ScalarField>::write_u64(&mut buffer, self.circuit_size);
        HonkProof::<P::ScalarField>::write_u64(&mut buffer, self.log_circuit_size);
        HonkProof::<P::ScalarField>::write_u64(&mut buffer, self.num_public_inputs);
        HonkProof::<P::ScalarField>::write_u64(&mut buffer, self.pub_inputs_offset);
        HonkProof::<P::ScalarField>::write_u8(&mut buffer, self.contains_recursive_proof as u8);

        for val in self.recursive_proof_public_input_indices.iter() {
            HonkProof::<P::ScalarField>::write_u32(&mut buffer, *val);
        }

        for el in self.commitments.iter() {
            Self::write_g1_element(&mut buffer, el, true);
        }

        debug_assert_eq!(buffer.len(), total_size);
        buffer
    }
}
