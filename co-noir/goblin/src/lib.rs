use ultrahonk::NUM_SMALL_IPA_EVALUATIONS;

pub(crate) mod eccvm;
pub(crate) mod ipa;
pub mod merge_prover;
pub mod prelude;
pub(crate) mod translator;

pub(crate) const CONST_ECCVM_LOG_N: usize = 16;
pub(crate) const ECCVM_FIXED_SIZE: usize = 1usize << CONST_ECCVM_LOG_N;
pub(crate) const NUM_TRANSLATION_OPENING_CLAIMS: usize = NUM_SMALL_IPA_EVALUATIONS + 1;
pub(crate) const NUM_OPENING_CLAIMS: usize = NUM_TRANSLATION_OPENING_CLAIMS + 1;
pub(crate) const NUM_LIMB_BITS_IN_FIELD_SIMULATION: usize = 68;
pub(crate) const NUM_SCALAR_BITS: usize = 128; // The length of scalars handled by the ECCVVM
pub(crate) const NUM_WNAF_DIGIT_BITS: usize = 4; // Scalars are decompose into base 16 in wNAF form
pub(crate) const NUM_WNAF_DIGITS_PER_SCALAR: usize = NUM_SCALAR_BITS / NUM_WNAF_DIGIT_BITS; // 32
pub(crate) const WNAF_MASK: u64 = (1 << NUM_WNAF_DIGIT_BITS) - 1;
pub(crate) const POINT_TABLE_SIZE: usize = 1 << (NUM_WNAF_DIGIT_BITS);
pub(crate) const WNAF_DIGITS_PER_ROW: usize = 4;
pub(crate) const ADDITIONS_PER_ROW: usize = 4;
pub(crate) const TABLE_WIDTH: usize = 4; // dictated by the number of wires in the Ultra arithmetization
pub(crate) const NUM_ROWS_PER_OP: usize = 2; // A single ECC op is split across two width-4 rows

// Translator constans:
pub(crate) const CONST_TRANSLATOR_LOG_N: usize = 18;
pub(crate) const NUM_BINARY_LIMBS: usize = 4;
pub(crate) const NUM_Z_LIMBS: usize = 2;
pub(crate) const NUM_MICRO_LIMBS: usize = 6;
pub(crate) const NUM_RELATION_WIDE_LIMBS: usize = 2;
pub(crate) const NUM_LAST_LIMB_BITS: usize = 50;
pub(crate) const NUM_QUOTIENT_BITS: usize = 256;
pub(crate) const NUM_Z_BITS: usize = 128;
pub(crate) const MICRO_LIMB_BITS: usize = 14;
