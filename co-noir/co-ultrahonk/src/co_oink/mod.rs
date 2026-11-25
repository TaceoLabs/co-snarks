pub mod co_oink_prover;
pub mod types;

// An inversion consumes two pairs per element: one for the random mask and one to randomize
// the degree-2t sharing that is opened.
// execute_log_derivative_inverse_round: n for mult and 2 * n for inv
// commit_to_lookup_counts_and_w4: at most 2 * n for the ROM-LogUp inverses
pub const CRAND_PAIRS_FACTOR_N: usize = 3 + 2;
// execute_grand_product_computation_round:
//      compute_grand_product:
//      4 * batched_grand_product_num_denom: (domain_size - 1)
//      2 * array_prod_mul: (domain_size - 1) * 6 + 3
//          (rand: m + 1, inv_many: 2 * m + 2, 2 * mul_many: 2 * m, mul_open_many: m)
//      misc: (domain_size - 1) * 5
//          (2 * mul_many: 2 * m, batch_invert: 2 * m, mul_many: m)
pub const CRAND_PAIRS_FACTOR_DOMAIN_SIZE_MINUS_ONE: usize = 4 + 12 + 5;
pub const CRAND_PAIRS_CONST: usize = 6;
