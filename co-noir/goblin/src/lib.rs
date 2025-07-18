use ultrahonk::NUM_SMALL_IPA_EVALUATIONS;

pub(crate) mod eccvm;
pub(crate) mod goblin_prover;
pub(crate) mod ipa;

pub(crate) const CONST_ECCVM_LOG_N: usize = 16;
pub(crate) const ECCVM_FIXED_SIZE: usize = 1usize << CONST_ECCVM_LOG_N;
pub(crate) const NUM_TRANSLATION_OPENING_CLAIMS: usize = NUM_SMALL_IPA_EVALUATIONS + 1;
pub(crate) const NUM_OPENING_CLAIMS: usize = NUM_TRANSLATION_OPENING_CLAIMS + 1;
