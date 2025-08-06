pub(crate) mod co_oink_prover;
pub(crate) mod types;

// execute_log_derivative_inverse_round: n for inv and n for mult
pub const CRAND_PAIRS_FACTOR_N: usize = 2;
// execute_grand_product_computation_round:
//      compute_grand_product:
//      4 * batched_grand_product_num_denom: (domain_size - 1)
//      2 * array_prod_mul: (domain_size - 1) * 4 + 2
//      misc: (domain_size - 1) * 4
pub const CRAND_PAIRS_FACTOR_DOMAIN_SIZE_MINUS_ONE: usize = 4 + 8 + 4;
pub const CRAND_PAIRS_CONST: usize = 4;
