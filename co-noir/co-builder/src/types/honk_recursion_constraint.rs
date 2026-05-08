use crate::acir_format::ProofType;
use crate::honk_verifier::recursive_decider_verification_key::{
    RecursiveDeciderVerificationKey, VKAndHash,
};
use crate::honk_verifier::ultra_recursive_verifier::UltraRecursiveVerifier;
use crate::keys::proving_key::create_keys_barretenberg;
use crate::prelude::GenericUltraCircuitBuilder;
use crate::transcript_ct::{Poseidon2SpongeCT, TranscriptCT, TranscriptHasherCT};
use crate::types::big_group::BigGroup;
use crate::types::types::{AddQuad, PairingPoints, RecursionConstraint};
use crate::{transcript_ct::TranscriptFieldType, types::field_ct::FieldCT};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, One, PrimeField, Zero};
use co_acvm::PlainAcvmSolver;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::constants::{
    BATCHED_RELATION_PARTIAL_LENGTH, BATCHED_RELATION_PARTIAL_LENGTH_ZK, CONST_PROOF_SIZE_LOG_N,
    DECIDER_PROOF_LENGTH, NUM_ALL_ENTITIES, NUM_SMALL_IPA_EVALUATIONS, NUM_ZERO_ROWS,
    OINK_PROOF_LENGTH_WITHOUT_PUB_INPUTS, OINK_PROOF_LENGTH_WITHOUT_PUB_INPUTS_ZK,
    PUBLIC_INPUTS_SIZE, ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS,
    ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS_ZK,
};
use co_noir_common::crs::ProverCrs;
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::HonkProofResult;
use co_noir_common::keys::verification_key::VerifyingKeyBarretenberg;
use co_noir_common::mpc::plain::PlainUltraHonkDriver;
use co_noir_common::polynomials::entities::{PrecomputedEntities, WITNESS_ENTITIES_SIZE};
use co_noir_common::transcript::{Poseidon2Sponge, Transcript};
use co_noir_common::types::ZeroKnowledge;
use co_ultrahonk::prelude::CoUltraHonk;
use itertools::izip;
use mpc_core::{MpcState, PlainState};
use rand::SeedableRng;
use std::any::{Any, TypeId};
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
            *des = BigGroup::reconstruct_from_public(src, builder, driver)?;
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
        crs: &ProverCrs<C>,
        driver: &mut T,
    ) -> eyre::Result<PairingPoints<C, T>> {
        let is_honk = input.proof_type == ProofType::Honk as u32;
        let is_honk_zk = input.proof_type == ProofType::HonkZk as u32;
        assert!(
            is_honk || is_honk_zk,
            "create_honk_recursion_constraints: Only HONK, HONK_ZK proof types are supported."
        );

        let has_zk = if input.proof_type == ProofType::Honk as u32 {
            ZeroKnowledge::No
        } else {
            ZeroKnowledge::Yes
        };

        // Currently no IPA support

        // Step 1.
        // Construct in-circuit representations of the recursion data.
        let mut vk_fields: Vec<FieldCT<C::ScalarField>> = input
            .key
            .iter()
            .map(|idx| FieldCT::<C::ScalarField>::from_witness_index(*idx))
            .collect();
        let mut vk_hash = FieldCT::<C::ScalarField>::from_witness_index(input.key_hash);
        let proof_indices =
            create_indices_for_reconstructed_proof(&input.proof, &input.public_inputs);
        let mut proof_fields: Vec<FieldCT<C::ScalarField>> = proof_indices
            .iter()
            .map(|idx| FieldCT::<C::ScalarField>::from_witness_index(*idx))
            .collect();
        let predicate = input.predicate.to_field_ct().to_bool_ct(self, driver);

        // MPC adaptation: if we have zk, open the recursion data.
        if has_zk == ZeroKnowledge::Yes {
            let mut to_open: (Vec<T::ArithmeticShare>, Vec<usize>) = (
                Vec::with_capacity(proof_fields.len() + vk_fields.len() + 2),
                Vec::with_capacity(proof_fields.len() + vk_fields.len() + 2),
            );
            // Collect all witness indices: proof, key, key_hash and optional predicate witness.
            for idx in proof_indices
                .iter()
                .chain(input.key.iter())
                .chain(std::iter::once(&input.key_hash))
                .chain(
                    std::iter::once(&input.predicate.index)
                        .filter(|_| !input.predicate.is_constant),
                )
            {
                if T::is_shared(&self.get_variable(*idx as usize)) {
                    to_open.0.push(
                        T::get_shared(&self.get_variable(*idx as usize))
                            .expect("We already checked it is shared"),
                    );
                    to_open.1.push(*idx as usize);
                }
            }
            let opened_values = driver.open_many(&to_open.0)?;
            for (idx, value) in izip!(to_open.1.iter(), opened_values.iter()) {
                self.set_variable(*idx as u32, T::AcvmType::from(*value));
            }
        }

        // Construct a Honk proof and vk with the correct number of public inputs.
        // If we are in a write vk scenario, the proof and vk are not necessarily valid
        let (honk_proof_to_be_set, honk_vk_to_be_set) = if self.is_write_vk_mode {
            (
                self.create_mock_honk_proof(input.public_inputs.len(), has_zk, driver)?,
                Self::create_mock_honk_vk(1 << CONST_PROOF_SIZE_LOG_N, input.public_inputs.len()),
            )
        } else {
            self.construct_honk_proof_for_simple_circuit(
                input.public_inputs.len(),
                crs,
                has_zk,
                driver,
            )?
        };
        // Step 2.
        if self.is_write_vk_mode {
            // Set honk vk in builder
            let vk_elements = honk_vk_to_be_set.to_field_elements();
            for (field, value) in vk_fields.iter().zip(vk_elements.iter()) {
                let index = field.get_witness_index(self, driver);
                self.set_variable(index, T::AcvmType::from(*value));
            }

            // Set honk proof in the builder
            for (field, value) in proof_fields.iter().zip(honk_proof_to_be_set.iter()) {
                let index = field.get_witness_index(self, driver);
                self.set_variable(index, T::AcvmType::from(*value));
            }
        }
        // Step 3.
        if !predicate.is_constant() {
            let mut transcript = Transcript::<TranscriptFieldType, Poseidon2Sponge>::new();
            let honk_vk_hash = honk_vk_to_be_set.hash_with_origin_tagging("", &mut transcript);
            // If the predicate is a witness, we conditionally assign a valid vk, proof and vk hash so that verification
            // succeeds. Note: in doing this, we create some new witnesses that are only used in the conditional assignment.
            // It would be optimal to hard-code these values in the selectors, but due to the randomness needed to generate
            // valid ZK proofs, we cannot do that without adding a dependency of the VKs on the witness values. Note that
            // the new witnesses are used only in the recursive verification when the predicate is set to true, so they
            // don't create a soundness issue and can be filled with anything - as long as they contain a valid vk, proof
            // and vk hash
            let vk_elements = honk_vk_to_be_set.to_field_elements();
            for (vk_witness, vk_element) in vk_fields.iter_mut().zip(vk_elements.iter()) {
                let valid_vk_witness = FieldCT::from_witness((*vk_element).into(), self);
                *vk_witness = FieldCT::conditional_assign(
                    &predicate,
                    vk_witness,
                    &valid_vk_witness,
                    self,
                    driver,
                )?;
            }
            for (proof_witness, proof_element) in
                proof_fields.iter_mut().zip(honk_proof_to_be_set.iter())
            {
                let valid_proof_witness = FieldCT::from_witness((*proof_element).into(), self);
                *proof_witness = FieldCT::conditional_assign(
                    &predicate,
                    proof_witness,
                    &valid_proof_witness,
                    self,
                    driver,
                )?;
            }
            let valid_vk_hash_val = T::AcvmType::from(honk_vk_hash);
            vk_hash = FieldCT::conditional_assign(
                &predicate,
                &vk_hash,
                &FieldCT::from_witness(valid_vk_hash_val, self),
                self,
                driver,
            )?;
        }
        let vkey = RecursiveVerificationKey::<C, T>::new(&vk_fields, self, driver)?;
        let vk_and_hash = VKAndHash {
            vk: vkey,
            hash: vk_hash,
        };
        let recursive_decider_vkey = RecursiveDeciderVerificationKey {
            vk_and_hash,
            _is_complete: false,
            public_inputs: proof_fields
                .iter()
                .take(input.public_inputs.len())
                .cloned()
                .collect(),
            relation_parameters: Default::default(),
            target_sum: FieldCT::<C::ScalarField>::default(),
            witness_commitments: Default::default(),
            gemini_masking_commitment: None,
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
        // 3 as inputs for the simple circuit, rest for public inputs and one for the shared randomness for initializing the rng for the plaindriver prover
        let mut random_fields = Vec::with_capacity(num_inner_public_inputs + 3 + 1);
        for _ in 0..num_inner_public_inputs + 4 {
            random_fields.push(driver.rand()?);
        }
        let opened = driver.open_many(&random_fields)?;
        let rng_seed = opened[0];
        let a = opened[1];
        let b = opened[2];
        let c = opened[3];
        let public_inputs = &opened[4..];
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
        builder.add_default_to_public_inputs();

        builder.finalize_circuit(true, &mut plain_driver)?;

        // prove the circuit constructed above
        // Create the decider proving key
        let (pk, vk) = create_keys_barretenberg::<_, _, PlainAcvmSolver<_>>(
            ().id(),
            builder,
            crs,
            &mut plain_driver,
        )?;

        // Every party needs to use the same RNG for the below proofs to be identical. We derive it from shared randomness.
        let rng = rand_chacha::ChaCha12Rng::from_seed(
            rng_seed
                .into_bigint()
                .to_bytes_be()
                .try_into()
                .expect("field element should fit into seed size"),
        );

        let mut plain_state = PlainState::new(rng);
        let proof = CoUltraHonk::<PlainUltraHonkDriver, _, Poseidon2Sponge>::prove_inner(
            &(),
            &mut plain_state,
            pk,
            crs,
            has_zk,
            &vk,
        )?
        .inner();

        // TACEO TODO: Handle unsafeness properly
        if TypeId::of::<C::ScalarField>() != TypeId::of::<TranscriptFieldType>() {
            return Err(eyre::eyre!("Proof type mismatch"));
        }

        let proof: Vec<C::ScalarField> = downcast::<_, Vec<C::ScalarField>>(&proof)
            .expect("We checked types")
            .clone();

        Ok((proof, vk))
    }

    /**
     * @brief Create a mock MegaHonk VK that has the correct structure
     *
     * @param dyadic_size Dyadic size of the circuit for which we generate a vk
     * @param pub_inputs_offset Indicating whether the circuit has a first zero row
     * @param inner_public_inputs_size Number of public inputs coming from the ACIR constraints
     */
    fn create_mock_honk_vk(
        dyadic_size: usize,
        acir_public_inputs_size: usize,
    ) -> VerifyingKeyBarretenberg<C> {
        let mut commitments = PrecomputedEntities::default();
        for el in commitments.iter_mut() {
            *el = C::generator().into_affine();
        }

        VerifyingKeyBarretenberg {
            log_circuit_size: dyadic_size.ilog2().into(),
            num_public_inputs: (acir_public_inputs_size + PUBLIC_INPUTS_SIZE) as u64,
            pub_inputs_offset: NUM_ZERO_ROWS as u64,
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
        acir_public_inputs_size: usize,
        has_zk: ZeroKnowledge,
        driver: &mut T,
    ) -> eyre::Result<Vec<C::ScalarField>> {
        // Construct a Honk proof as the concatenation of an Oink proof and a Decider proof
        let proof_capacity = if has_zk == ZeroKnowledge::Yes {
            ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS_ZK
        } else {
            ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS
        };
        let mut proof = Vec::with_capacity(proof_capacity);
        proof.extend_from_slice(&self.create_mock_oink_proof(
            acir_public_inputs_size,
            has_zk,
            driver,
        )?);
        proof.extend_from_slice(&self.create_mock_decider_proof(has_zk, driver)?);
        let shared: Vec<_> = proof.iter().map(|y| driver.get_as_shared(y)).collect();
        let proof_as_scalars: Vec<C::ScalarField> = driver.open_many(&shared)?;

        Ok(proof_as_scalars)
    }

    fn create_mock_oink_proof(
        &mut self,
        inner_public_inputs_size: usize,
        has_zk: ZeroKnowledge,
        driver: &mut T,
    ) -> eyre::Result<Vec<T::AcvmType>> {
        let proof_capacity = if has_zk == ZeroKnowledge::Yes {
            OINK_PROOF_LENGTH_WITHOUT_PUB_INPUTS_ZK
        } else {
            OINK_PROOF_LENGTH_WITHOUT_PUB_INPUTS
        };
        let mut proof = Vec::with_capacity(proof_capacity);

        // Populate the proof with as many public inputs as required from the ACIR constraints
        populate_field_elements::<C, T>(&mut proof, inner_public_inputs_size, None, driver)?;

        let mut builder =
            GenericUltraCircuitBuilder::<C, PlainAcvmSolver<C::ScalarField>>::new_minimal(0);
        builder.add_default_to_public_inputs();
        // Populate the proof with the public inputs added from barretenberg
        for public_input in builder.public_inputs.iter() {
            proof.push(builder.get_variable(*public_input as usize).into());
        }

        if has_zk == ZeroKnowledge::Yes {
            // ZK proofs bind the Gemini masking commitment in Oink before the witness commitments.
            populate_field_elements_for_mock_commitments::<C, T>(&mut proof, 1);
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

        // No AVM flavor
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

        let num_all_entities = NUM_ALL_ENTITIES + usize::from(has_zk == ZeroKnowledge::Yes);
        populate_field_elements::<C, T>(&mut proof, num_all_entities, None, driver)?;

        if has_zk == ZeroKnowledge::Yes {
            // Libra claimed evaluation
            populate_field_elements::<C, T>(&mut proof, 1, None, driver)?;

            // Libra grand sum commitment
            populate_field_elements_for_mock_commitments::<C, T>(&mut proof, 1);

            // Libra quotient commitment
            populate_field_elements_for_mock_commitments::<C, T>(&mut proof, 1);
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
    fields: &mut Vec<T::AcvmType>,
    num_elements: usize,
    value: Option<C::ScalarField>,
    driver: &mut T,
) -> eyre::Result<()> {
    for _ in 0..num_elements {
        let val = match &value {
            Some(v) => T::AcvmType::from(*v),
            None => T::AcvmType::from(driver.rand()?),
        };
        fields.push(val);
    }

    Ok(())
}

fn populate_field_elements_for_mock_commitments<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
>(
    fields: &mut Vec<T::AcvmType>,
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
        fields.extend_from_slice(&mock_commitment_frs);
    }
}
