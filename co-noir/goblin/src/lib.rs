use co_builder::{prelude::HonkCurve, TranscriptFieldType};
use common::transcript::TranscriptHasher;

use crate::merge_prover::MergeProver;

pub mod eccvm;
pub mod merge_prover;

pub struct Goblin<C, H>
where
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
{
    pub merge_prover: MergeProver<C, H>,
}