use co_acvm::mpc::NoirWitnessExtensionProtocol;

use ark_ff::Field;
use co_noir_common::{
    constants::CONST_PROOF_SIZE_LOG_N, honk_curve::HonkCurve, honk_proof::HonkProofResult,
};

use crate::honk_verifier::padding_indicator_array::padding_indicator_array;
use crate::{
    honk_verifier::{
        claim_batcher::{Batch, ClaimBatcher},
        kzg::KZG,
        oink_recursive_verifier::OinkRecursiveVerifier,
        recursive_decider_verification_key::RecursiveDeciderVerificationKey,
        shplemini::ShpleminiVerifier,
        sumcheck::SumcheckVerifier,
    },
    prelude::{GenericUltraCircuitBuilder, UltraRecursiveVerifierOutput},
    transcript_ct::{TranscriptCT, TranscriptFieldType, TranscriptHasherCT},
    types::{big_group::BigGroup, field_ct::FieldCT},
};

struct UltraRecursiveVerifier;

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
    ) -> HonkProofResult<UltraRecursiveVerifierOutput<C, T>> {
        // TODO CESAR: Assert length of proof
        let mut transcript = TranscriptCT::<C, H>::new_verifier(proof);

        // No IPA accumulator on the UltraRecursiveFlavor

        OinkRecursiveVerifier::verify(&mut key, &mut transcript, builder, driver)?;

        let gate_challenges = (0..CONST_PROOF_SIZE_LOG_N)
            .map(|idx| {
                transcript.get_challenge(format!("Sumcheck:gate_challenge_{idx}"), builder, driver)
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Extract the aggregation object from the public inputs
        // let nested_point_accumulator = unimplemented!();

        // output.points_accumulator = nested_point_accumulator;

        // Execute Sumcheck Verifier and extract multivariate opening point u = (u_0, ..., u_{d-1}) and purported
        // multivariate evaluations at u
        let padding_indicator_array = padding_indicator_array::<_, _, CONST_PROOF_SIZE_LOG_N>(
            &key.vk_and_hash.vk.log_circuit_size,
            builder,
            driver,
        )?;

        // Since UltraRecursiveFlavor does not have ZK, we slip the computation of the 0th libra commitment

        let sumcheck_output = SumcheckVerifier::verify::<C, T, H>(
            &mut transcript,
            &mut key.target_sum,
            &key.relation_parameters,
            todo!(), // &key.relation_parameters.alphas,
            &mut gate_challenges,
            &padding_indicator_array,
            builder,
            driver,
        )?;

        // Since UltraRecursiveFlavor does not have ZK, we skip the computation of the 1st and 2nd libra commitments

        // Execute Shplemini to produce a batch opening claim subsequently verified by a univariate PCS
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
                scalar: FieldCT::from_witness(C::ScalarField::ONE.into(), builder),
            },
            shifted: Batch {
                commitments: to_be_shifted_commitments,
                evaluations: shifted_scalars,
                scalar: FieldCT::from_witness(C::ScalarField::ONE.into(), builder),
            },
        };

        // TODO CESAR: Check if REPEATED_COMMITMENTS is correct
        let mut opening_claim = ShpleminiVerifier::compute_batch_opening_claim(
            &padding_indicator_array,
            &mut claim_batcher,
            &sumcheck_output.challenges,
            &BigGroup::one(builder, driver)?,
            &mut transcript,
            builder,
            driver,
        )?;

        KZG::reduce_verify_batch_opening_claim(
            &mut opening_claim,
            &mut transcript,
            builder,
            driver,
        )?;
    }
}
