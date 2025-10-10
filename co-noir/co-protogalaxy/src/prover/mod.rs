pub mod co_protogalaxy_prover;
mod co_protogalaxy_prover_internal;

pub use co_protogalaxy_prover::{
    BATCHED_EXTENDED_LENGTH, CONST_PG_LOG_N, CoProtogalaxyProver, DeciderProverMemory,
    MAX_TOTAL_RELATION_LENGTH, NUM_KEYS,
};
pub use co_protogalaxy_prover_internal::{
    compute_and_extend_alphas, compute_combiner, compute_combiner_quotient,
    compute_extended_relation_parameters, compute_perturbator, compute_row_evaluations,
    construct_perturbator_coefficients,
};
