use co_builder::{
    flavours::mega_flavour::{MegaPrecomputedEntities, MegaWitnessEntities},
    types::goblin_types::GoblinElement,
};

mod oink_recursive_verifier;
mod protogalaxy_recursive_verifier;
mod recursive_decider_verification_key;

pub type PrecomputedCommitments<C, T> = MegaPrecomputedEntities<GoblinElement<C, T>>;
pub type WitnessCommitments<C, T> = MegaWitnessEntities<GoblinElement<C, T>>;

pub use protogalaxy_recursive_verifier::ProtogalaxyRecursiveVerifier;
pub use recursive_decider_verification_key::RecursiveDeciderVerificationKey;
pub use recursive_decider_verification_key::VerificationKey;
