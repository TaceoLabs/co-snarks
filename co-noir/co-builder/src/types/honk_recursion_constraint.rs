use crate::acir_format::ProofType;
use crate::honk_verifier::recursive_decider_verification_key::{
    RecursiveDeciderVerificationKey, VKAndHash,
};
use crate::honk_verifier::ultra_recursive_verifier::UltraRecursiveVerifier;
use crate::keys::proving_key::ProvingKeyTrait;
use crate::prelude::GenericUltraCircuitBuilder;
use crate::transcript_ct::{Poseidon2SpongeCT, TranscriptCT, TranscriptHasherCT};
use crate::types::big_field::BigField;
use crate::types::big_group::BigGroup;
use crate::types::field_ct::BoolCT;
use crate::types::types::{AddQuad, PairingPoints, RecursionConstraint};
use crate::{transcript_ct::TranscriptFieldType, types::field_ct::FieldCT};
use ark_ec::AffineRepr;
use ark_ff::{One, Zero};
use co_acvm::PlainAcvmSolver;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::constants::{
    BATCHED_RELATION_PARTIAL_LENGTH, BATCHED_RELATION_PARTIAL_LENGTH_ZK, CONST_PROOF_SIZE_LOG_N,
    DECIDER_PROOF_LENGTH, NUM_ALL_ENTITIES, NUM_SMALL_IPA_EVALUATIONS,
    OINK_PROOF_LENGTH_WITHOUT_PUB_INPUTS, PUBLIC_INPUTS_SIZE,
    ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS, ULTRA_VERIFICATION_KEY_LENGTH,
};
use co_noir_common::crs::ProverCrs;
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::HonkProofResult;
use co_noir_common::keys::proving_key::ProvingKey;
use co_noir_common::keys::verification_key::VerifyingKeyBarretenberg;
use co_noir_common::mpc::plain::PlainUltraHonkDriver;
use co_noir_common::polynomials::entities::{PrecomputedEntities, WITNESS_ENTITIES_SIZE};
use co_noir_common::transcript::{Poseidon2Sponge, Transcript};
use co_noir_common::types::ZeroKnowledge;
use co_ultrahonk::prelude::CoUltraHonk;
use mpc_core::MpcState;
use std::any::Any;
use std::array;

pub type PrecomputedCommitments<C, T> = PrecomputedEntities<BigGroup<C, T>>;

// TACEO TODO: This is not so nice, can we avoid?
fn downcast<A: 'static, B: 'static>(a: &A) -> Option<&B> {
    (a as &dyn Any).downcast_ref::<B>()
}

pub struct RecursiveVerificationKey<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
> {
    pub log_circuit_size: FieldCT<C::ScalarField>,
    pub num_public_inputs: FieldCT<C::ScalarField>,
    pub pub_inputs_offset: FieldCT<C::ScalarField>,
    pub precomputed_commitments: PrecomputedCommitments<C::ScalarField, T>,
}

impl<C: HonkCurve<TranscriptFieldType>, T: NoirWitnessExtensionProtocol<C::ScalarField>>
    RecursiveVerificationKey<C, T>
{
    fn new(
        elements: &[FieldCT<C::ScalarField>],
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<Self> {
        let log_circuit_size = elements[0].clone();
        let num_public_inputs = elements[1].clone();
        let pub_inputs_offset = elements[2].clone();
        let mut precomputed_commitments = PrecomputedCommitments::default();

        // TACEO TODO: Maybe we could batch the is_zero checks here
        for (des, src) in precomputed_commitments
            .elements
            .iter_mut()
            .zip(elements[3..].chunks(BigGroup::<C::ScalarField, T>::NUM_BN254_FRS))
        {
            let [x_lo, x_hi] = [&src[0], &src[1]];
            let [y_lo, y_hi] = [&src[2], &src[3]];

            let x = BigField::from_slices(x_lo, x_hi, driver, builder)?;
            let y = BigField::from_slices(y_lo, y_hi, driver, builder)?;
            let is_zero = FieldCT::check_point_at_infinity::<C, T>(src, builder, driver)?;

            let mut result = BigGroup::new(x, y);

            result.set_is_infinity(is_zero);

            // Note that in the case of bn254 with Mega arithmetization, the check is delegated to ECCVM, see
            // `on_curve_check` in `ECCVMTranscriptRelationImpl`.
            result.validate_on_curve(builder, driver)?;
            *des = result;
        }

        Ok(RecursiveVerificationKey {
            log_circuit_size,
            num_public_inputs,
            pub_inputs_offset,
            precomputed_commitments,
        })
    }

    pub fn hash_through_transcript<H: TranscriptHasherCT<C>>(
        &self,
        transcript: &mut TranscriptCT<C, H>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> eyre::Result<FieldCT<C::ScalarField>> {
        transcript.add_fr_to_independent_hash_buffer::<T>(&self.log_circuit_size);
        transcript.add_fr_to_independent_hash_buffer::<T>(&self.num_public_inputs);
        transcript.add_fr_to_independent_hash_buffer::<T>(&self.pub_inputs_offset);

        for commitment in self.precomputed_commitments.elements.iter() {
            transcript.add_point_to_independent_hash_buffer(commitment, builder, driver)?;
        }

        transcript.hash_independent_buffer(builder, driver)
    }
}

impl<C: HonkCurve<TranscriptFieldType>, T: NoirWitnessExtensionProtocol<C::ScalarField>>
    GenericUltraCircuitBuilder<C, T>
{
    /// Add constraints required to recursively verify an UltraHonk proof
    pub(crate) fn create_honk_recursion_constraints(
        &mut self,
        input: &RecursionConstraint<C::ScalarField>,
        has_valid_witness_assignments: bool,
        crs: &ProverCrs<C>,
        driver: &mut T,
    ) -> eyre::Result<PairingPoints<C, T>> {
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
        let mut vk_fields = Vec::with_capacity(input.key.len());
        for idx in &input.key {
            let field = FieldCT::<C::ScalarField>::from_witness_index(*idx);
            vk_fields.push(field);
        }

        // Create circuit type for vkey hash.
        let mut vk_hash = FieldCT::<C::ScalarField>::from_witness_index(input.key_hash);

        // Create witness indices for the proof with public inputs reinserted
        let proof_indices =
            create_indices_for_reconstructed_proof(&input.proof, &input.public_inputs);

        let mut proof_fields = Vec::with_capacity(proof_indices.len());
        for idx in &proof_indices {
            let field = FieldCT::<C::ScalarField>::from_witness_index(*idx);
            proof_fields.push(field);
        }
        // Recursion constraints come with a predicate (e.g. when the black-box call is done in an if conditional depending
        // on a witness value in a Noir circuit) To keep the circuit constants (selectors and copy constraints) the same
        // independent of value of the conditional, we create a place holder proof, vk and vk_hash and conditionally select
        // between the two (in circuit) depending on the predicate value.
        let mut place_holder_vk_fields: Vec<C::ScalarField> =
            Vec::with_capacity(ULTRA_VERIFICATION_KEY_LENGTH);
        let mut place_holder_proof: Vec<C::ScalarField> =
            Vec::with_capacity(ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS);
        let mut place_holder_vk_hash = FieldCT::<C::ScalarField>::default();

        self.place_holder_proof_and_vk(
            &mut place_holder_vk_fields,
            &mut place_holder_proof,
            &mut place_holder_vk_hash,
            has_valid_witness_assignments,
            input.proof.len(),
            input.public_inputs.len(),
            &mut vk_fields,
            &mut proof_fields,
            has_zk,
            crs,
            driver,
        )?;

        if !input.predicate.is_constant {
            let predicate_witness = BoolCT::from_witness_index_unsafe(input.predicate.index, self);

            let mut result_proof: Vec<FieldCT<C::ScalarField>> =
                Vec::with_capacity(proof_fields.len());
            let mut result_vk: Vec<FieldCT<C::ScalarField>> = Vec::with_capacity(vk_fields.len());
            // Replace the proof by the placeholder proof in case the predicate is 1
            for (i, p) in place_holder_proof.iter().enumerate() {
                let place_holder_proof_witness = FieldCT::from_witness((*p).into(), self);
                let valid_proof = FieldCT::conditional_assign(
                    &predicate_witness,
                    &proof_fields[i],
                    &place_holder_proof_witness,
                    self,
                    driver,
                )?;
                result_proof.push(valid_proof);
            }
            // Replace the VK with the placeholder vk in case the predicate is 1
            for (i, vk) in place_holder_vk_fields.iter().enumerate() {
                let place_holder_vk_witness = FieldCT::from_witness((*vk).into(), self);
                let valid_vk = FieldCT::conditional_assign(
                    &predicate_witness,
                    &vk_fields[i],
                    &place_holder_vk_witness,
                    self,
                    driver,
                )?;
                result_vk.push(valid_vk);
            }
            let place_holder_vk_hash_val = place_holder_vk_hash.get_value(self, driver);
            vk_hash = FieldCT::conditional_assign(
                &predicate_witness,
                &vk_hash,
                &FieldCT::from_witness(place_holder_vk_hash_val, self),
                self,
                driver,
            )?;
            proof_fields = result_proof;
            vk_fields = result_vk;
        }

        let vkey = RecursiveVerificationKey::<C, T>::new(&vk_fields, self, driver)?;
        let vk_and_hash = VKAndHash {
            vk: vkey,
            hash: vk_hash,
        };
        let recursive_decider_vkey = RecursiveDeciderVerificationKey {
            vk_and_hash,
            is_complete: false,
            public_inputs: proof_fields
                .iter()
                .take(input.public_inputs.len())
                .cloned()
                .collect(),
            relation_parameters: Default::default(),
            target_sum: FieldCT::<C::ScalarField>::default(),
            witness_commitments: Default::default(),
            alphas: array::from_fn(|_| FieldCT::<C::ScalarField>::default()),
            gate_challenges: Vec::new(),
        };

        UltraRecursiveVerifier::verify_proof::<C, Poseidon2SpongeCT<C>, T>(
            proof_fields,
            recursive_decider_vkey,
            self,
            driver,
            has_zk,
        )
    }

    /**
     * @brief Creates a vkey and proof object.
     * @details if has_valid_witness_assignments is false, generates a dummy proof and vkey matching the given sizes.
     * the data is not meaningful but its structure is correct.
     * if has_valid_witness_assignments is true, generates a valid proof and vkey for a simple circuit, matching the given
     * sizes. This simple proof will be used if the recursion is done under a false predicate. In that case, the recursive
     * verification must not fail so that's why a valid proof is needed.
     * @param builder
     * @param proof_size Size of proof with NO public inputs
     * @param public_inputs_size Total size of public inputs including aggregation object
     * @param key_fields
     * @param proof_fields
     */
    #[allow(clippy::too_many_arguments)]
    pub fn place_holder_proof_and_vk(
        &mut self,
        place_holder_vk_fields: &mut Vec<C::ScalarField>,
        place_holder_proof: &mut Vec<C::ScalarField>,
        place_holder_vk_hash: &mut FieldCT<C::ScalarField>,
        has_valid_witness_assignments: bool,
        proof_size: usize,
        public_inputs_size: usize,
        vk_fields: &mut [FieldCT<C::ScalarField>],
        proof_fields: &mut [FieldCT<C::ScalarField>],
        has_zk: ZeroKnowledge,
        crs: &ProverCrs<C>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        let mut transcript = Transcript::<TranscriptFieldType, Poseidon2Sponge>::new();
        // Populate the key fields and proof fields with dummy values to prevent issues (e.g. points must be on curve).
        if !has_valid_witness_assignments {
            // proof_size here includes the aggregation object; remove it to get raw proof size (without pub inputs)
            let size_of_proof_with_no_pub_inputs = proof_size - PUBLIC_INPUTS_SIZE;
            // Add aggregation object public inputs to inner public inputs
            let total_num_public_inputs = public_inputs_size + PUBLIC_INPUTS_SIZE;

            // Set a dummy vk and proof in the circuit so structure constraints exist even without a witness
            self.create_dummy_vkey_and_proof(
                size_of_proof_with_no_pub_inputs,
                total_num_public_inputs,
                vk_fields,
                proof_fields,
                has_zk,
                driver,
            )?;

            // Generate a mock place holder proof, vk and vk hash, to keep the circuit the same independent of whether a
            // witness is provided or not.
            let pub_inputs_offset = 1; // Ultra flavors always have a zero row

            let honk_vk = Self::create_mock_honk_vk(
                1 << CONST_PROOF_SIZE_LOG_N,
                pub_inputs_offset,
                public_inputs_size,
            );
            *place_holder_vk_fields = honk_vk.to_field_elements();

            let mock_proof = self.create_mock_honk_proof(public_inputs_size, has_zk, driver)?;
            *place_holder_proof = mock_proof;

            // Assume a function exists to compute hash of vk (returns scalar field element)
            *place_holder_vk_hash =
                FieldCT::from(honk_vk.hash_through_transcript("", &mut transcript));
        } else {
            // Generate an actually verifiable honk proof & vk for a trivial circuit.
            // Assume this helper exists and returns (proof, vk, vk_hash_scalar).
            let (place_holder_honk_proof, place_holder_vk) = self
                .construct_honk_proof_for_simple_circuit(public_inputs_size, crs, has_zk, driver)?;
            *place_holder_proof = place_holder_honk_proof;
            *place_holder_vk_fields = place_holder_vk.to_field_elements();
            *place_holder_vk_hash =
                FieldCT::from(place_holder_vk.hash_through_transcript("", &mut transcript));
        }

        Ok(())
    }

    /**
     * @brief Create a verifiable honk proof for a circuit with a single big add gate. Adds random public inputs to match
     * num_public_inputs provided
     *
     * @param inner_public_inputs_size Number of public inputs coming from the ACIR constraints
     */
    pub fn construct_honk_proof_for_simple_circuit(
        &mut self,
        num_inner_public_inputs: usize,
        crs: &ProverCrs<C>,
        has_zk: ZeroKnowledge,
        driver: &mut T,
    ) -> eyre::Result<(Vec<C::ScalarField>, VerifyingKeyBarretenberg<C>)> {
        let mut random_fields = Vec::with_capacity(3 + num_inner_public_inputs);
        for _ in 0..num_inner_public_inputs + 3 {
            let pi = driver.rand()?;
            random_fields.push(pi);
        }
        let opened = driver.open_many(&random_fields)?;
        let a = opened[0];
        let b = opened[1];
        let c = opened[2];
        let public_inputs = &opened[3..];
        let d = a + b + c;

        // TACEO TODO: I think this is fine?
        let mut builder =
            GenericUltraCircuitBuilder::<C, PlainAcvmSolver<C::ScalarField>>::new_minimal(0);
        let mut plain_driver = PlainAcvmSolver::<C::ScalarField>::new();

        let a_idx = builder.add_variable(a);
        let b_idx = builder.add_variable(b);
        let c_idx = builder.add_variable(c);
        let d_idx = builder.add_variable(d);

        builder.create_big_add_gate(
            &AddQuad {
                a: a_idx,
                b: b_idx,
                c: c_idx,
                d: d_idx,
                a_scaling: C::ScalarField::one(),
                b_scaling: C::ScalarField::one(),
                c_scaling: C::ScalarField::one(),
                d_scaling: -C::ScalarField::one(),
                const_scaling: C::ScalarField::zero(),
            },
            false,
        );

        // Add the public inputs
        for pi in public_inputs.iter() {
            builder.add_public_variable(*pi);
        }

        // Add the default pairing points and IPA claim
        builder.add_default_to_public_inputs(&mut plain_driver)?;

        builder.finalize_circuit(true, &mut plain_driver)?;

        // prove the circuit constructed above
        // Create the decider proving key
        let (pk, vk) = ProvingKey::create_keys_barretenberg::<PlainAcvmSolver<_>>(
            ().id(),
            builder,
            crs,
            &mut plain_driver,
        )?;

        let proof = CoUltraHonk::<PlainUltraHonkDriver, _, Poseidon2Sponge>::prove_inner(
            &(),
            &mut (),
            pk,
            crs,
            has_zk,
            &vk,
        )?
        .inner();
        let proof: Vec<C::ScalarField> = downcast::<_, Vec<C::ScalarField>>(&proof)
            .expect("We checked types")
            .clone();

        Ok((proof, vk))
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
        assert_eq!(proof_size, ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS);

        let num_inner_public_inputs = public_inputs_size - PUBLIC_INPUTS_SIZE;
        let pub_inputs_offset = 1; // NativeFlavor::has_zero_row ? 1 : 0; We always have a zero row for Ultra flavours

        // Generate mock honk vk
        let honk_vk = Self::create_mock_honk_vk(
            1 << CONST_PROOF_SIZE_LOG_N,
            pub_inputs_offset,
            num_inner_public_inputs,
        );

        let mut offset = 0;

        // Set honk vk in builder
        for vk_element in honk_vk.to_field_elements() {
            let index = key_fields[offset].get_witness_index(self, driver);
            self.set_variable(index, T::AcvmType::from(vk_element));
            offset += 1;
        }

        // Generate dummy honk proof
        let honk_proof = self.create_mock_honk_proof(num_inner_public_inputs, has_zk, driver)?;

        offset = 0;
        // Set honk proof in builder
        for proof_element in honk_proof {
            self.set_variable(proof_fields[offset].witness_index, proof_element.into());
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
            num_public_inputs: (inner_public_inputs_size + PUBLIC_INPUTS_SIZE) as u64,
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
    ) -> eyre::Result<Vec<C::ScalarField>> {
        // Construct a Honk proof as the concatenation of an Oink proof and a Decider proof
        let mut proof = Vec::with_capacity(ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS);
        proof.extend_from_slice(&self.create_mock_oink_proof(inner_public_inputs_size, driver)?);
        proof.extend_from_slice(&self.create_mock_decider_proof(has_zk, driver)?);
        let shared: Vec<_> = proof.iter().map(|y| driver.get_as_shared(y)).collect();
        let proof_as_scalars: Vec<C::ScalarField> = driver.open_many(&shared)?;

        Ok(proof_as_scalars)
    }

    fn create_mock_oink_proof(
        &mut self,
        inner_public_inputs_size: usize,
        driver: &mut T,
    ) -> eyre::Result<Vec<T::AcvmType>> {
        self.add_default_to_public_inputs(driver)?;

        let mut proof = Vec::with_capacity(OINK_PROOF_LENGTH_WITHOUT_PUB_INPUTS);

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
        let mut proof = Vec::with_capacity(DECIDER_PROOF_LENGTH);

        let const_proof_log_n = CONST_PROOF_SIZE_LOG_N;

        if has_zk == ZeroKnowledge::Yes {
            // Libra concatenation commitment
            populate_field_elements_for_mock_commitments::<C, T>(&mut proof, 1);
            // Libra sum
            populate_field_elements::<C, T>(&mut proof, 1, None, driver)?;
        }

        // Sumcheck univariates
        let total_size_sumcheck_univariates = if has_zk == ZeroKnowledge::Yes {
            const_proof_log_n * BATCHED_RELATION_PARTIAL_LENGTH_ZK
        } else {
            const_proof_log_n * BATCHED_RELATION_PARTIAL_LENGTH
        };
        populate_field_elements::<C, T>(&mut proof, total_size_sumcheck_univariates, None, driver)?;

        let num_all_entities = NUM_ALL_ENTITIES;
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
            let num_small_ipa_evaluations = NUM_SMALL_IPA_EVALUATIONS;
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
