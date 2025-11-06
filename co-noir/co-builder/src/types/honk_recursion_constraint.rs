use crate::acir_format::ProofType;
use crate::polynomials::polynomial_types::WITNESS_ENTITIES_SIZE;
use crate::prelude::{GenericUltraCircuitBuilder, PrecomputedEntities, VerifyingKeyBarretenberg};
use crate::types::types::{PairingPoints, RecursionConstraint};
use crate::{transcript_ct::TranscriptFieldType, types::field_ct::FieldCT};
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ec::pairing::Pairing;
use ark_ff::Zero;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::types::ZeroKnowledge;

pub const HONK_PROOF_PUBLIC_INPUT_OFFSET: u32 = 3;

pub struct UltraRecursiveVerifierOutput<
    C: CurveGroup,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
> {
    points_accumulator: PairingPoints<C, T>,
    ipa_proof: Vec<FieldCT<C::ScalarField>>,
}

impl<C: HonkCurve<TranscriptFieldType>, T: NoirWitnessExtensionProtocol<C::ScalarField>>
    GenericUltraCircuitBuilder<C, T>
{
    const PUBLIC_INPUTS_SIZE: usize = 16;
    //TODO FLORIN move this somewhere else
    const CONST_PROOF_SIZE_LOG_N: usize = 28;

    /// Add constraints required to recursively verify an UltraHonk proof
    pub(crate) fn create_honk_recursion_constraints(
        &mut self,
        input: &RecursionConstraint,
        has_valid_witness_assignments: bool,
        driver: &mut T,
    ) -> eyre::Result<UltraRecursiveVerifierOutput<C, T>> {
        assert!(
            input.proof_type == ProofType::Honk as u32
                || input.proof_type == ProofType::HonkZk as u32
        );
        let has_zk = if input.proof_type == ProofType::Honk as u32 {
            ZeroKnowledge::No
        } else {
            ZeroKnowledge::Yes
        };

        // Construct an in-circuit representation of the verification key.
        // For now, the v-key is a circuit constant and is fixed for the circuit.
        // (We may need a separate recursion opcode for this to vary, or add more config witnesses to this opcode)
        let mut key_fields = Vec::with_capacity(input.key.len());
        for idx in &input.key {
            let field = FieldCT::<C::ScalarField>::from_witness_index(*idx);
            key_fields.push(field);
        }

        // Create circuit type for vkey hash.
        let vk_hash = FieldCT::<C::ScalarField>::from_witness_index(input.key_hash);

        // Create witness indices for the proof with public inputs reinserted
        let proof_indices =
            create_indices_for_reconstructed_proof(&input.proof, &input.public_inputs);

        let mut proof_fields = Vec::with_capacity(proof_indices.len());
        for idx in &proof_indices {
            let field = FieldCT::<C::ScalarField>::from_witness_index(*idx);
            proof_fields.push(field);
        }

        // Populate the key fields and proof fields with dummy values to prevent issues (e.g., points must be on curve).
        if !has_valid_witness_assignments {
            // In the constraint, the agg object public inputs are still contained in the proof. To get the 'raw' size of
            // the proof and public_inputs, we subtract and add the corresponding amount from the respective sizes.
            let size_of_proof_with_no_pub_inputs = input.proof.len() - Self::PUBLIC_INPUTS_SIZE;
            let total_num_public_inputs = input.public_inputs.len() + Self::PUBLIC_INPUTS_SIZE;

            self.create_dummy_vkey_and_proof(
                size_of_proof_with_no_pub_inputs,
                total_num_public_inputs,
                &mut key_fields,
                &mut proof_fields,
                has_zk,
                driver,
            )?;
        }

        todo!("create_honk_recursion_constraints not yet implemented")
    }

    /// Creates a dummy vkey and proof object.
    /// Populates the key and proof vectors with dummy values in the write_vk case when we don't have a valid witness. The bulk of the logic is setting up certain values correctly like the circuit size, number of public inputs, aggregation object, and commitments.
    fn create_dummy_vkey_and_proof(
        &mut self,
        proof_size: usize,
        public_inputs_size: usize,
        key_fields: &mut [FieldCT<C::ScalarField>],
        proof_fields: &mut [FieldCT<C::ScalarField>],
        has_zk: ZeroKnowledge,
        driver: &mut T,
    ) -> eyre::Result<()> {
        //TODO FLORIN: reinstate this assert
        // Set vkey->circuit_size correctly based on the proof size
        // BB_ASSERT_EQ(proof_size, NativeFlavor::PROOF_LENGTH_WITHOUT_PUB_INPUTS());

        let num_inner_public_inputs = public_inputs_size - Self::PUBLIC_INPUTS_SIZE;
        let pub_inputs_offset = 1; // NativeFlavor::has_zero_row ? 1 : 0; We always have a zero row for Ultra flavours

        // Generate mock honk vk
        let honk_vk = Self::create_mock_honk_vk(
            1 << Self::CONST_PROOF_SIZE_LOG_N,
            pub_inputs_offset,
            num_inner_public_inputs,
        );

        let mut offset = 0;

        // Set honk vk in builder
        for vk_element in honk_vk.to_field_elements() {
            self.set_variable(
                key_fields[offset].witness_index,
                T::AcvmType::from(vk_element),
            );
            offset += 1;
        }

        // Generate dummy honk proof
        let honk_proof = self.create_mock_honk_proof(num_inner_public_inputs, has_zk, driver)?;

        offset = 0;
        // Set honk proof in builder
        for proof_element in honk_proof {
            self.set_variable(proof_fields[offset].witness_index, proof_element);
            offset += 1;
        }

        debug_assert_eq!(offset, proof_size + public_inputs_size);

        Ok(())
    }

    /**
     * @brief Create a mock MegaHonk VK that has the correct structure
     *
     * @param dyadic_size Dyadic size of the circuit for which we generate a vk
     * @param pub_inputs_offest Indicating whether the circuit has a first zero row
     * @param inner_public_inputs_size Number of public inputs coming from the ACIR constraints
     */
    fn create_mock_honk_vk(
        dyadic_size: usize,
        pub_inputs_offset: usize,
        inner_public_inputs_size: usize,
    ) -> VerifyingKeyBarretenberg<C> {
        let mut commitments = PrecomputedEntities::default();
        for el in commitments.iter_mut() {
            *el = C::generator().into_affine();
        }

        VerifyingKeyBarretenberg {
            log_circuit_size: dyadic_size.ilog2().into(),
            num_public_inputs: (inner_public_inputs_size + Self::PUBLIC_INPUTS_SIZE) as u64,
            pub_inputs_offset: pub_inputs_offset as u64,
            commitments,
        }
    }

    /**
     * @brief Create a mock honk proof that has the correct structure but is not in general valid
     *
     * @param inner_public_inputs_size Number of public inputs coming from the ACIR constraints
     */
    fn create_mock_honk_proof(
        &mut self,
        inner_public_inputs_size: usize,
        has_zk: ZeroKnowledge,
        driver: &mut T,
    ) -> eyre::Result<Vec<T::AcvmType>> {
        // Construct a Honk proof as the concatenation of an Oink proof and a Decider proof
        let mut proof = Vec::with_capacity(1); //TODO FLORIN set correct size
        proof.extend_from_slice(&self.create_mock_oink_proof(inner_public_inputs_size, driver)?);
        proof.extend_from_slice(&self.create_mock_decider_proof(has_zk, driver)?);
        Ok(proof)
    }

    fn create_mock_oink_proof(
        &mut self,
        inner_public_inputs_size: usize,
        driver: &mut T,
    ) -> eyre::Result<Vec<T::AcvmType>> {
        self.add_default_to_public_inputs(driver)?;

        let mut proof = Vec::with_capacity(1); //TODO FLORIN set correct size

        // Populate the proof with as many public inputs as required from the ACIR constraints
        populate_field_elements::<C, T>(&mut proof, inner_public_inputs_size, None, driver)?;

        // Populate the proof with the public inputs added from barretenberg
        for public_input in self.public_inputs.iter() {
            proof.push(self.get_variable(*public_input as usize));
        }

        // Populate mock witness polynomial commitments
        populate_field_elements_for_mock_commitments::<C, T>(&mut proof, WITNESS_ENTITIES_SIZE);

        Ok(proof)
    }

    /*
     * @brief Create a mock decider proof that has the correct structure but is not in general valid
     *
     */
    fn create_mock_decider_proof(
        &mut self,
        has_zk: ZeroKnowledge,
        driver: &mut T,
    ) -> eyre::Result<Vec<T::AcvmType>> {
        let mut proof = Vec::with_capacity(1); //TODO FLORIN set correct size

        let const_proof_log_n = Self::CONST_PROOF_SIZE_LOG_N; //TODO FLORIN FIX THIS DEP ON FLAVOUR

        if has_zk == ZeroKnowledge::Yes {
            // Libra concatenation commitment
            populate_field_elements_for_mock_commitments::<C, T>(&mut proof, 1);
            // Libra sum
            populate_field_elements::<C, T>(&mut proof, 1, None, driver)?;
        }

        // Sumcheck univariates
        let total_size_sumcheck_univariates = const_proof_log_n; //TODO FLORIN: * BATCHED_RELATION_PARTIAL_LENGTH;
        populate_field_elements::<C, T>(&mut proof, total_size_sumcheck_univariates, None, driver)?;

        let num_all_entities = 41; // TODO FLORIN: NUM_ALL_ENTITIES<Flavor>;
        populate_field_elements::<C, T>(&mut proof, num_all_entities, None, driver)?;

        if has_zk == ZeroKnowledge::Yes {
            // Libra claimed evaluation
            populate_field_elements::<C, T>(&mut proof, 1, None, driver)?;

            // Libra grand sum commitment
            populate_field_elements_for_mock_commitments::<C, T>(&mut proof, 1);

            // Libra quotient commitment
            populate_field_elements_for_mock_commitments::<C, T>(&mut proof, 1);

            // Gemini masking commitment
            populate_field_elements_for_mock_commitments::<C, T>(&mut proof, 1);

            // Gemini masking evaluation
            populate_field_elements::<C, T>(&mut proof, 1, None, driver)?;
        }

        // Gemini fold commitments
        let num_gemini_fold_commitments = const_proof_log_n - 1;
        populate_field_elements_for_mock_commitments::<C, T>(
            &mut proof,
            num_gemini_fold_commitments,
        );

        // Gemini fold evaluations
        let num_gemini_fold_evaluations = const_proof_log_n;
        populate_field_elements::<C, T>(&mut proof, num_gemini_fold_evaluations, None, driver)?;

        if has_zk == ZeroKnowledge::Yes {
            let num_small_ipa_evaluations = 4; // TODO FLORIN: NUM_SMALL_IPA_EVALUATIONS<Flavor>;
            // NUM_SMALL_IPA_EVALUATIONS libra evals
            populate_field_elements::<C, T>(&mut proof, num_small_ipa_evaluations, None, driver)?;
        }

        // Shplonk batched quotient commitment
        populate_field_elements_for_mock_commitments::<C, T>(&mut proof, 1);
        // KZG quotient commitment
        populate_field_elements_for_mock_commitments::<C, T>(&mut proof, 1);

        Ok(proof)
    }
}

fn create_indices_for_reconstructed_proof(proof_in: &[u32], public_inputs: &[u32]) -> Vec<u32> {
    let mut proof = Vec::with_capacity(proof_in.len() + public_inputs.len());
    proof.extend_from_slice(public_inputs);
    proof.extend_from_slice(proof_in);
    proof
}

fn populate_field_elements<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
>(
    fields: &mut [T::AcvmType],
    num_elements: usize,
    value: Option<C::ScalarField>,
    driver: &mut T,
) -> eyre::Result<()> {
    for field in fields.iter_mut().take(num_elements) {
        let val = match &value {
            Some(v) => T::AcvmType::from(*v),
            None => T::AcvmType::from(driver.rand()?),
        };
        *field = val;
    }

    Ok(())
}

fn populate_field_elements_for_mock_commitments<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
>(
    fields: &mut [T::AcvmType],
    num_commitments: usize,
) {
    let mock_commitment = C::Affine::generator();
    let mock_commitment_frs = if mock_commitment.is_zero() {
        let convert = C::convert_basefield_to_scalarfield(&C::BaseField::zero());
        [
            T::AcvmType::from(convert[0]),
            T::AcvmType::from(convert[1]),
            T::AcvmType::from(convert[0]),
            T::AcvmType::from(convert[1]),
        ]
    } else {
        let (x, y) = C::g1_affine_to_xy(&mock_commitment);
        [
            T::AcvmType::from(C::convert_basefield_to_scalarfield(&x)[0]),
            T::AcvmType::from(C::convert_basefield_to_scalarfield(&x)[1]),
            T::AcvmType::from(C::convert_basefield_to_scalarfield(&y)[0]),
            T::AcvmType::from(C::convert_basefield_to_scalarfield(&y)[1]),
        ]
    };

    for _ in 0..num_commitments {
        fields.clone_from_slice(&mock_commitment_frs);
    }
}
