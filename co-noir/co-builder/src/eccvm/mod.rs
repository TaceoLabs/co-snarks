pub mod co_ecc_op_queue;
pub mod ecc_op_queue;

pub const NUM_SMALL_IPA_EVALUATIONS: usize = 4;
pub const CONST_ECCVM_LOG_N: usize = 16;
pub const ECCVM_FIXED_SIZE: usize = 1usize << CONST_ECCVM_LOG_N;
pub const NUM_TRANSLATION_OPENING_CLAIMS: usize = NUM_SMALL_IPA_EVALUATIONS + 1;
pub const NUM_OPENING_CLAIMS: usize = NUM_TRANSLATION_OPENING_CLAIMS + 1;
pub const NUM_LIMB_BITS_IN_FIELD_SIMULATION: usize = 68;
pub const NUM_SCALAR_BITS: usize = 128; // The length of scalars handled by the ECCVVM
pub const NUM_WNAF_DIGIT_BITS: usize = 4; // Scalars are decompose into base 16 in wNAF form
pub const NUM_WNAF_DIGITS_PER_SCALAR: usize = NUM_SCALAR_BITS / NUM_WNAF_DIGIT_BITS; // 32
pub const WNAF_MASK: u64 = (1 << NUM_WNAF_DIGIT_BITS) - 1;
pub const POINT_TABLE_SIZE: usize = 1 << (NUM_WNAF_DIGIT_BITS);
pub const WNAF_DIGITS_PER_ROW: usize = 4;
pub const ADDITIONS_PER_ROW: usize = 4;
pub const TABLE_WIDTH: usize = 4; // dictated by the number of wires in the Ultra arithmetization
pub const NUM_ROWS_PER_OP: usize = 2; // A single ECC op is split across two width-4 rows
