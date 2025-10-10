pub mod eccvm;
pub mod merge_prover;
pub mod prelude;
pub(crate) mod translator;

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
