use crate::{
    acir_format::PROOF_TYPE_HONK,
    builder::GenericUltraCircuitBuilder,
    prelude::{HonkCurve, PAIRING_POINT_ACCUMULATOR_SIZE},
    types::types::{
        AggregationState, FieldCT, PairingPointAccumulatorIndices, RecursionConstraint,
    },
};
use ark_ec::pairing::Pairing;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
pub const HONK_PROOF_PUBLIC_INPUT_OFFSET: u32 = 3;

impl<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> GenericUltraCircuitBuilder<P, T> {
    /// Add constraints required to recursively verify an UltraHonk proof
    pub(crate) fn create_honk_recursion_constraints(
        &mut self,
        input: &RecursionConstraint,
        current_aggregation_object: PairingPointAccumulatorIndices,
        has_valid_witness_assignments: bool,
    ) -> PairingPointAccumulatorIndices {
        assert!(input.proof_type == PROOF_TYPE_HONK);

        // Construct an in-circuit representation of the verification key.
        // For now, the v-key is a circuit constant and is fixed for the circuit.
        // (We may need a separate recursion opcode for this to vary, or add more config witnesses to this opcode)
        let mut key_fields = Vec::with_capacity(input.key.len());
        for idx in &input.key {
            let field = FieldCT::<P::ScalarField>::from_witness_index(*idx);
            key_fields.push(field);
        }

        // Create witness indices for the proof with public inputs reinserted
        let proof_indices =
            create_indices_for_reconstructed_proof(&input.proof, &input.public_inputs);
        let mut proof_fields = Vec::with_capacity(proof_indices.len());
        for idx in &proof_indices {
            let field = FieldCT::<P::ScalarField>::from_witness_index(*idx);
            proof_fields.push(field);
        }

        // Populate the key fields and proof fields with dummy values to prevent issues (e.g., points must be on curve).
        if !has_valid_witness_assignments {
            // In the constraint, the agg object public inputs are still contained in the proof. To get the 'raw' size of
            // the proof and public_inputs, we subtract and add the corresponding amount from the respective sizes.
            let size_of_proof_with_no_pub_inputs =
                input.proof.len() - PAIRING_POINT_ACCUMULATOR_SIZE;
            let total_num_public_inputs =
                input.public_inputs.len() + PAIRING_POINT_ACCUMULATOR_SIZE;

            self.create_dummy_vkey_and_proof(
                size_of_proof_with_no_pub_inputs,
                total_num_public_inputs,
                &mut key_fields,
                &mut proof_fields,
            );
        }

        let input_agg_obj = self.convert_witness_indices_to_agg_obj(current_aggregation_object);

        todo!("create_honk_recursion_constraints not yet implemented")
    }

    /// Creates a dummy vkey and proof object.
    /// Populates the key and proof vectors with dummy values in the write_vk case when we don't have a valid witness. The bulk of the logic is setting up certain values correctly like the circuit size, number of public inputs, aggregation object, and commitments.
    fn create_dummy_vkey_and_proof(
        &mut self,
        _proof_size: usize,
        _public_inputs_size: usize,
        _key_fields: &mut [FieldCT<P::ScalarField>],
        _proof_fields: &mut [FieldCT<P::ScalarField>],
    ) {
        todo!(
            "create_dummy_vkey_and_proof not yet implemented, use the vk from bb in the meanwhile"
        )
    }
    fn convert_witness_indices_to_agg_obj(
        &mut self,
        witness_indices: PairingPointAccumulatorIndices,
    ) -> AggregationState<P::G1> {
        let mut aggregation_elements = [<P as Pairing>::BaseField::default(); 4];
        for i in 0..4 {
            aggregation_elements[i] = self.construct_from_limbs(
                FieldCT::<P::ScalarField>::from_witness_index(
                    witness_indices[4 * i].try_into().unwrap(),
                ),
                FieldCT::<P::ScalarField>::from_witness_index(
                    witness_indices[4 * i + 1].try_into().unwrap(),
                ),
                FieldCT::<P::ScalarField>::from_witness_index(
                    witness_indices[4 * i + 2].try_into().unwrap(),
                ),
                FieldCT::<P::ScalarField>::from_witness_index(
                    witness_indices[4 * i + 3].try_into().unwrap(),
                ),
                false,
            );
            // TACEO TODO aggregation_elements[i].assert_is_in_field();
        }

        AggregationState {
            p0: todo!("typename Curve::Group(aggregation_elements[0], aggregation_elements[1]"), //HonkCurve::g1_affine_from_xy(aggregation_elements[0], aggregation_elements[1]),
            p1: todo!("typename Curve::Group(aggregation_elements[2], aggregation_elements[3])"), //HonkCurve::g1_affine_from_xy(aggregation_elements[2], aggregation_elements[3]),
            has_data: true,
        }
    }
}

fn create_indices_for_reconstructed_proof(proof_in: &[u32], public_inputs: &[u32]) -> Vec<u32> {
    let mut proof_indices = Vec::with_capacity(proof_in.len() + public_inputs.len());
    // Construct the complete proof as the concatenation {"initial data" | public_inputs | proof_in}
    proof_indices.extend(&proof_in[..HONK_PROOF_PUBLIC_INPUT_OFFSET as usize]);
    proof_indices.extend(public_inputs);
    proof_indices.extend(&proof_in[HONK_PROOF_PUBLIC_INPUT_OFFSET as usize..]);

    proof_indices
}
