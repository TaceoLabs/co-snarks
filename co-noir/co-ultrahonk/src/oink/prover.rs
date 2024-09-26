// clang-format off
/*                                            )\   /|
*                                          .-/'-|_/ |
*                       __            __,-' (   / \/
*                   .-'"  "'-..__,-'""          -o.`-._
*                  /                                   '/
*          *--._ ./                                 _.--
*                |                              _.-'
*                :                           .-/
*                 \                       )_ /
*                  \                _)   / \(
*                    `.   /-.___.---'(  /   \\
*                     (  /   \\       \(     L\
*                      \(     L\       \\
*                       \\              \\
*                        L\              L\
*/
// clang-format on

use super::types::ProverMemory;
use crate::types::ProvingKey;
use mpc_core::traits::PrimeFieldMpcProtocol;
use std::marker::PhantomData;
use ultrahonk::prelude::{HonkCurve, HonkProofResult, TranscriptFieldType, TranscriptType};

pub(crate) struct Oink<'a, T, P: HonkCurve<TranscriptFieldType>>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    driver: &'a mut T,
    memory: ProverMemory<T, P>,
    phantom_data: PhantomData<P>,
}

impl<'a, T, P: HonkCurve<TranscriptFieldType>> Oink<'a, T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    pub(crate) fn new(driver: &'a mut T) -> Self {
        Self {
            driver,
            memory: ProverMemory::default(),
            phantom_data: PhantomData,
        }
    }

    pub(crate) fn prove(
        mut self,
        proving_key: &ProvingKey<T, P>,
        transcript: &mut TranscriptType,
    ) -> HonkProofResult<ProverMemory<T, P>> {
        tracing::trace!("Oink prove");

        todo!("Oink prove")
    }
}
