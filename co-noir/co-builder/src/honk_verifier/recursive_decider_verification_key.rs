use crate::{
    honk_verifier::verifier_relations::NUM_SUBRELATIONS,
    prelude::RecursiveVerificationKey,
    types::{big_group::BigGroup, field_ct::FieldCT},
};
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::{
    honk_curve::HonkCurve, honk_proof::TranscriptFieldType, polynomials::entities::WitnessEntities,
    types::RelationParameters,
};

pub type WitnessCommitments<C, T> = WitnessEntities<BigGroup<C, T>>;

pub(crate) struct RecursiveDeciderVerificationKey<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
> {
    pub(crate) vk_and_hash: VKAndHash<C, T>,
    pub(crate) is_complete: bool,
    pub(crate) public_inputs: Vec<FieldCT<C::ScalarField>>,
    pub(crate) alphas: [FieldCT<C::ScalarField>; NUM_SUBRELATIONS - 1],
    pub(crate) gate_challenges: Vec<FieldCT<C::ScalarField>>,
    pub(crate) relation_parameters: RelationParameters<FieldCT<C::ScalarField>>,
    pub(crate) target_sum: FieldCT<C::ScalarField>,
    pub(crate) witness_commitments: WitnessCommitments<C::ScalarField, T>,
}

pub(crate) struct VKAndHash<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
> {
    pub(crate) vk: RecursiveVerificationKey<C, T>,
    pub(crate) hash: FieldCT<C::ScalarField>,
}
