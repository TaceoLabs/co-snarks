mod prover;
mod recursive_verifier;

pub use prover::{
    BATCHED_EXTENDED_LENGTH, CONST_PG_LOG_N, CoProtogalaxyProver, DeciderProverMemory,
    MAX_TOTAL_RELATION_LENGTH, NUM_KEYS, compute_and_extend_alphas, compute_combiner,
    compute_combiner_quotient, compute_extended_relation_parameters, compute_perturbator,
    compute_row_evaluations, construct_perturbator_coefficients,
};
pub use recursive_verifier::PrecomputedCommitments;
pub use recursive_verifier::ProtogalaxyRecursiveVerifier;
pub use recursive_verifier::RecursiveDeciderVerificationKey;
pub use recursive_verifier::VerificationKey;
pub use recursive_verifier::WitnessCommitments;
