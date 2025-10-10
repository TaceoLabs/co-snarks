use ark_ec::CurveGroup;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_builder::{transcript::TranscriptFieldType, types::field_ct::FieldCT};
use co_noir_common::honk_curve::HonkCurve;
use co_ultrahonk::co_decider::types::RelationParameters;

use crate::recursive_verifier::{PrecomputedCommitments, WitnessCommitments};

pub struct RecursiveDeciderVerificationKey<
    P: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<P::ScalarField>,
> {
    pub verification_key: VerificationKey<P>,
    pub is_accumulator: bool,
    pub public_inputs: Vec<FieldCT<P::ScalarField>>,
    pub relation_parameters: RelationParameters<FieldCT<P::ScalarField>>,
    pub alphas: Vec<FieldCT<P::ScalarField>>,
    pub gate_challenges: Vec<FieldCT<P::ScalarField>>,
    pub target_sum: FieldCT<P::ScalarField>,
    pub precomputed_commitments: PrecomputedCommitments<P, T>,
    pub witness_commitments: WitnessCommitments<P, T>,
}

pub struct VerificationKey<P: CurveGroup> {
    pub circuit_size: FieldCT<P::ScalarField>,
    pub log_circuit_size: FieldCT<P::ScalarField>,
    pub num_public_inputs: FieldCT<P::ScalarField>,
    pub pub_inputs_offset: FieldCT<P::ScalarField>,
}
