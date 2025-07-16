use std::sync::Arc;

use ark_ec::CurveGroup;
use co_builder::prelude::ProverCrs;

use crate::eccvm::ecc_op_queue;

pub(crate) type MergeProof<F> = Vec<F>;
pub(crate) struct MergeProver<C, H>
where
    C: CurveGroup,
    H: TranscriptHasher<TranscriptFieldType>,
{
    ecc_op_queue: Arc<EccOpQueue>,
    commitment_key: Arc<ProverCrs<C>>,
    transcript: &mut Transcript<TranscriptFieldType, H>,
}

impl<C, H> MergeProver<C, H> 
where
    C: CurveGroup,
    H: TranscriptHasher<TranscriptFieldType>,
{
    pub fn new(
        ecc_op_queue: Arc<OpQueue>,
        commitment_key: ProverCrs<C>,
        transcript: &mut Transcript<TranscriptFieldType, H>, 
     ) -> Self {
        Self {
            ecc_op_queue,
            commitment_key,
            transcript,
        }
    }

    pub fn prove(&self) -> MergeProof<C::G1Affine> {
        todo!()
    }
}