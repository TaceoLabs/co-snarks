use std::array;

use co_acvm::mpc::NoirWitnessExtensionProtocol;

use ark_ff::Field;
use co_noir_common::constants::NUM_LIBRA_COMMITMENTS;
use co_noir_common::types::ZeroKnowledge;
use co_noir_common::{constants::CONST_PROOF_SIZE_LOG_N, honk_curve::HonkCurve};

use crate::honk_verifier::padding_indicator_array::padding_indicator_array;
use crate::types::types::PairingPoints;
use crate::{
    honk_verifier::{
        claim_batcher::{Batch, ClaimBatcher},
        kzg::KZG,
        oink_recursive_verifier::OinkRecursiveVerifier,
        recursive_decider_verification_key::RecursiveDeciderVerificationKey,
        shplemini::ShpleminiVerifier,
        sumcheck::SumcheckVerifier,
    },
    prelude::GenericUltraCircuitBuilder,
    transcript_ct::{TranscriptCT, TranscriptFieldType, TranscriptHasherCT},
    types::{big_group::BigGroup, field_ct::FieldCT},
};

pub(crate) struct UltraRecursiveVerifier;

impl UltraRecursiveVerifier {
    pub fn verify_proof<
        C: HonkCurve<TranscriptFieldType>,
        H: TranscriptHasherCT<C>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        proof: Vec<FieldCT<C::ScalarField>>,
        mut key: RecursiveDeciderVerificationKey<C, T>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
        has_zk: ZeroKnowledge,
    ) -> eyre::Result<PairingPoints<C, T>> {
        // TODO CESAR: Assert length of proof
        let mut transcript = TranscriptCT::<C, H>::new_verifier(proof);

        // No IPA accumulator on the UltraRecursiveFlavor

        OinkRecursiveVerifier::verify(&mut key, &mut transcript, builder, driver)?;

        // Get the gate challenges for sumcheck computation
        key.gate_challenges = transcript.get_powers_of_challenge(
            "Sumcheck:gate_challenge".to_string(),
            CONST_PROOF_SIZE_LOG_N,
            builder,
            driver,
        )?;

        // Execute Sumcheck Verifier and extract multivariate opening point u = (u_0, ..., u_{d-1}) and purported
        // multivariate evaluations at u
        let padding_indicator_array = padding_indicator_array::<_, _, CONST_PROOF_SIZE_LOG_N>(
            &key.vk_and_hash.vk.log_circuit_size,
            builder,
            driver,
            has_zk,
        )?;

        // Receive commitments to Libra masking polynomials
        let mut libra_commitments: [BigGroup<C::ScalarField, T>; NUM_LIBRA_COMMITMENTS] =
            array::from_fn(|_| BigGroup::<C::ScalarField, T>::default());

        if has_zk == ZeroKnowledge::Yes {
            libra_commitments[0] = transcript.receive_point_from_prover(
                "Libra:concatenation_commitment".to_owned(),
                builder,
                driver,
            )?;
        }

        let sumcheck_output = SumcheckVerifier::verify::<C, T, H>(
            &mut transcript,
            &mut key.target_sum,
            &key.relation_parameters,
            &key.alphas,
            &key.gate_challenges,
            &padding_indicator_array,
            builder,
            has_zk,
            driver,
        )?;

        if has_zk == ZeroKnowledge::Yes {
            libra_commitments[1] = transcript.receive_point_from_prover(
                "Libra:grand_sum_commitment".to_owned(),
                builder,
                driver,
            )?;
            libra_commitments[2] = transcript.receive_point_from_prover(
                "Libra:quotient_commitment".to_owned(),
                builder,
                driver,
            )?;
        }

        // Execute Shplemini to produce a batch opening claim subsequently verified by a univariate PCS
        let mut consistency_checked = true;
        let unshifted_commitments = [
            key.vk_and_hash.vk.precomputed_commitments.elements.to_vec(),
            key.witness_commitments.elements.to_vec(),
        ]
        .concat();
        let unshifted_scalars = [
            sumcheck_output
                .claimed_evaluations
                .precomputed
                .elements
                .to_vec(),
            sumcheck_output
                .claimed_evaluations
                .witness
                .elements
                .to_vec(),
        ]
        .concat();

        let to_be_shifted_commitments = key.witness_commitments.to_be_shifted().to_vec();
        let shifted_scalars = sumcheck_output
            .claimed_evaluations
            .shifted_witness
            .elements
            .to_vec();

        let mut claim_batcher = ClaimBatcher {
            unshifted: Batch {
                commitments: unshifted_commitments,
                evaluations: unshifted_scalars,
                scalar: FieldCT::from(C::ScalarField::ONE),
            },
            shifted: Batch {
                commitments: to_be_shifted_commitments,
                evaluations: shifted_scalars,
                scalar: FieldCT::from(C::ScalarField::ONE),
            },
        };
        let libra_commitments = if has_zk == ZeroKnowledge::Yes {
            Some(&libra_commitments)
        } else {
            None
        };

        // TODO CESAR: Check if REPEATED_COMMITMENTS is correct
        let mut opening_claim = ShpleminiVerifier::compute_batch_opening_claim(
            &padding_indicator_array,
            &mut claim_batcher,
            &sumcheck_output.challenges,
            &BigGroup::one(builder, driver)?,
            &mut transcript,
            &mut consistency_checked,
            libra_commitments,
            sumcheck_output.claimed_libra_evaluation.as_ref(),
            builder,
            driver,
        )?;

        let pairing_points = KZG::reduce_verify_batch_opening_claim(
            &mut opening_claim,
            &mut transcript,
            builder,
            driver,
        )?;

        let mut inputs =
            PairingPoints::reconstruct_from_public(&key.public_inputs, builder, driver)?;

        inputs.aggregate::<H>(pairing_points, builder, driver)?;

        Ok(inputs)
    }
}
