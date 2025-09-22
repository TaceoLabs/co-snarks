use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_builder::{flavours::mega_flavour::MegaWitnessEntities, types::goblin_types::GoblinElement};
use common::{honk_curve::HonkCurve, honk_proof::TranscriptFieldType};

mod protogalaxy_recursive_verifier;
mod recursive_decider_verification_key;
mod oink_recursive_verifier;

pub type WitnessCommitments<C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>, T: NoirWitnessExtensionProtocol<C::ScalarField>> = MegaWitnessEntities<GoblinElement<C, T>>;
