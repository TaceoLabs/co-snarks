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
use crate::{types::ProvingKey, CoUtils};
use mpc_core::traits::{MSMProvider, PrimeFieldMpcProtocol};
use std::marker::PhantomData;
use ultrahonk::prelude::{
    HonkCurve, HonkProofError, HonkProofResult, TranscriptFieldType, TranscriptType,
};

pub(crate) struct CoOink<'a, T, P: HonkCurve<TranscriptFieldType>>
where
    T: PrimeFieldMpcProtocol<P::ScalarField> + MSMProvider<P::G1>,
{
    driver: &'a mut T,
    memory: ProverMemory<T, P>,
    phantom_data: PhantomData<P>,
}

impl<'a, T, P: HonkCurve<TranscriptFieldType>> CoOink<'a, T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField> + MSMProvider<P::G1>,
{
    pub(crate) fn new(driver: &'a mut T) -> Self {
        Self {
            driver,
            memory: ProverMemory::default(),
            phantom_data: PhantomData,
        }
    }

    // Add circuit size public input size and public inputs to transcript
    fn execute_preamble_round(
        transcript: &mut TranscriptType,
        proving_key: &ProvingKey<T, P>,
    ) -> HonkProofResult<()> {
        tracing::trace!("executing preamble round");

        transcript
            .send_u64_to_verifier("circuit_size".to_string(), proving_key.circuit_size as u64);
        transcript.send_u64_to_verifier(
            "public_input_size".to_string(),
            proving_key.num_public_inputs as u64,
        );
        transcript.send_u64_to_verifier(
            "pub_inputs_offset".to_string(),
            proving_key.pub_inputs_offset as u64,
        );

        if proving_key.num_public_inputs as usize != proving_key.public_inputs.len() {
            return Err(HonkProofError::CorruptedWitness(
                proving_key.public_inputs.len(),
            ));
        }

        for (i, public_input) in proving_key.public_inputs.iter().enumerate() {
            // transcript.add_scalar(*public_input);
            transcript.send_fr_to_verifier::<P>(format!("public_input_{}", i), *public_input);
        }
        Ok(())
    }

    // Compute first three wire commitments
    fn execute_wire_commitments_round(
        &mut self,
        transcript: &mut TranscriptType,
        proving_key: &ProvingKey<T, P>,
    ) -> HonkProofResult<()> {
        tracing::trace!("executing wire commitments round");

        // Commit to the first three wire polynomials of the instance
        // We only commit to the fourth wire polynomial after adding memory records

        let w_l = CoUtils::commit(
            self.driver,
            proving_key.polynomials.witness.w_l().as_ref(),
            &proving_key.crs,
        );
        let w_r = CoUtils::commit(
            self.driver,
            proving_key.polynomials.witness.w_r().as_ref(),
            &proving_key.crs,
        );
        let w_o = CoUtils::commit(
            self.driver,
            proving_key.polynomials.witness.w_o().as_ref(),
            &proving_key.crs,
        );

        let res = self.driver.open_point_many(&[w_l, w_r, w_o])?;

        transcript.send_point_to_verifier::<P>("W_L".to_string(), res[0].into());
        transcript.send_point_to_verifier::<P>("W_R".to_string(), res[1].into());
        transcript.send_point_to_verifier::<P>("W_O".to_string(), res[2].into());

        // Round is done since ultra_honk is no goblin flavor
        Ok(())
    }

    pub(crate) fn prove(
        mut self,
        proving_key: &ProvingKey<T, P>,
        transcript: &mut TranscriptType,
    ) -> HonkProofResult<ProverMemory<T, P>> {
        tracing::trace!("Oink prove");

        // Add circuit size public input size and public inputs to transcript
        Self::execute_preamble_round(transcript, proving_key)?;
        // Compute first three wire commitments
        self.execute_wire_commitments_round(transcript, proving_key)?;

        todo!("Oink prove")
    }
}
