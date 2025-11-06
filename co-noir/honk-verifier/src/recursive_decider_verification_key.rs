use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_builder::{
    prelude::PrecomputedEntities,
    types::{big_group::BigGroup, field_ct::FieldCT},
};
use co_noir_common::{honk_curve::HonkCurve, honk_proof::TranscriptFieldType};
use co_ultrahonk::co_decider::types::RelationParameters;
use ultrahonk::prelude::WitnessEntities;

pub type PrecomputedCommitments<C, T> = PrecomputedEntities<BigGroup<C, T>>;
pub type WitnessCommitments<C, T> = WitnessEntities<BigGroup<C, T>>;

pub struct RecursiveDeciderVerificationKey<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
> {
    pub verification_key: VerificationKey<C::ScalarField>,
    pub is_accumulator: bool,
    pub public_inputs: Vec<FieldCT<C::ScalarField>>,
    pub relation_parameters: RelationParameters<FieldCT<C::ScalarField>>,
    pub target_sum: FieldCT<C::ScalarField>,
    pub precomputed_commitments: PrecomputedCommitments<C::ScalarField, T>,
    pub witness_commitments: WitnessCommitments<C::ScalarField, T>,
}

pub struct VerificationKey<F: PrimeField> {
    pub circuit_size: FieldCT<F>,
    pub log_circuit_size: FieldCT<F>,
    pub num_public_inputs: FieldCT<F>,
    pub pub_inputs_offset: FieldCT<F>,
}
