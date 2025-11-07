use crate::{
    prelude::RecursiveVerificationKey,
    types::{big_group::BigGroup, field_ct::FieldCT},
};
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::{
    honk_curve::HonkCurve, honk_proof::TranscriptFieldType, polynomials::entities::WitnessEntities,
    types::RelationParameters,
};

pub type WitnessCommitments<C, T> = WitnessEntities<BigGroup<C, T>>;

pub struct RecursiveDeciderVerificationKey<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
> {
    pub vk_and_hash: VKAndHash<C, T>,
    pub is_complete: bool,
    pub public_inputs: Vec<FieldCT<C::ScalarField>>,
    pub relation_parameters: RelationParameters<FieldCT<C::ScalarField>>,
    pub target_sum: FieldCT<C::ScalarField>,
    pub witness_commitments: WitnessCommitments<C::ScalarField, T>,
}

pub struct VKAndHash<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
> {
    pub vk: RecursiveVerificationKey<C, T>,
    pub hash: FieldCT<C::ScalarField>,
}
