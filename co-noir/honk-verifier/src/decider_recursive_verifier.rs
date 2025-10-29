use ark_ff::AdditiveGroup;
use ark_ff::fields::Field;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_builder::mega_builder::MegaCircuitBuilder;
use co_builder::polynomials::polynomial_flavours::WitnessEntitiesFlavour;
use co_builder::transcript::TranscriptCT;
use co_builder::transcript::TranscriptHasherCT;
use co_builder::types::field_ct::FieldCT;
use co_builder::types::goblin_types::GoblinElement;
use co_noir_common::barycentric::Barycentric;
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::HonkProofResult;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_protogalaxy::RecursiveDeciderVerificationKey;

use crate::claim_batcher::Batch;
use crate::claim_batcher::ClaimBatcher;
use crate::kzg::KZG;
use crate::shplemini::ShpleminiVerifier;
use crate::sumcheck::SumcheckVerifier;

// The log of the max circuit size assumed in order to achieve constant sized Honk proofs
// AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1046): Remove the need for const sized proofs
const CONST_PROOF_SIZE_LOG_N: usize = 28;

pub struct DeciderRecursiveVerifier;

impl DeciderRecursiveVerifier {
    pub fn verify_proof<
        C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
        H: TranscriptHasherCT<C>,
    >(
        proof: Vec<FieldCT<C::ScalarField>>,
        accumulator: &mut RecursiveDeciderVerificationKey<C, T>,
        builder: &mut MegaCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<(GoblinElement<C, T>, GoblinElement<C, T>)> {
        let mut transcript = TranscriptCT::<C, H>::new_verifier(proof);

        let padding_indicator_array = Self::padding_indicator_array::<C, T, CONST_PROOF_SIZE_LOG_N>(
            &accumulator.verification_key.log_circuit_size,
            builder,
            driver,
        )?;

        Self::constrain_log_circuit_size::<C, T, CONST_PROOF_SIZE_LOG_N>(
            &padding_indicator_array,
            &accumulator.verification_key.circuit_size,
            builder,
            driver,
        )?;

        let output = SumcheckVerifier::verify(
            &mut transcript,
            &mut accumulator.target_sum,
            &accumulator.relation_parameters,
            &accumulator.alphas,
            &mut accumulator.gate_challenges,
            &padding_indicator_array,
            builder,
            driver,
        )?;

        let unshifted_commitments = [
            accumulator.precomputed_commitments.elements.to_vec(),
            accumulator.witness_commitments.elements.to_vec(),
        ]
        .concat();
        let unshifted_scalars = [
            output.claimed_evaluations.precomputed.elements.to_vec(),
            output.claimed_evaluations.witness.elements.to_vec(),
        ]
        .concat();

        let to_be_shifted_commitments = accumulator.witness_commitments.to_be_shifted().to_vec();
        let shifted_scalars = output.claimed_evaluations.shifted_witness.elements.to_vec();

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

        let mut opening_claim = ShpleminiVerifier::compute_batch_opening_claim(
            &padding_indicator_array,
            &mut claim_batcher,
            &output.challenges,
            &GoblinElement::one(builder),
            &mut transcript,
            builder,
            driver,
        )?;

        KZG::reduce_verify_batch_opening_claim(&mut opening_claim, &mut transcript, builder, driver)
    }
}
