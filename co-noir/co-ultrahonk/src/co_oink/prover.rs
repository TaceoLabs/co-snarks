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
use crate::{types::ProvingKey, CoUtils, FieldShare};
use ark_ff::One;
use mpc_core::traits::{MSMProvider, PrimeFieldMpcProtocol};
use std::marker::PhantomData;
use ultrahonk::{
    prelude::{HonkCurve, HonkProofError, HonkProofResult, TranscriptFieldType, TranscriptType},
    Utils,
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

    fn compute_w4(&mut self, proving_key: &ProvingKey<T, P>) {
        tracing::trace!("compute w4");
        // The memory record values are computed at the indicated indices as
        // w4 = w3 * eta^3 + w2 * eta^2 + w1 * eta + read_write_flag;

        debug_assert_eq!(
            proving_key.polynomials.witness.w_l().len(),
            proving_key.polynomials.witness.w_r().len()
        );
        debug_assert_eq!(
            proving_key.polynomials.witness.w_l().len(),
            proving_key.polynomials.witness.w_o().len()
        );
        self.memory.w_4 = proving_key.polynomials.witness.w_4().clone();
        self.memory.w_4.resize(
            proving_key.polynomials.witness.w_l().len(),
            FieldShare::<T, P>::default(),
        );

        // Compute read record values
        for gate_idx in proving_key.memory_read_records.iter() {
            let gate_idx = *gate_idx as usize;
            let target = &mut self.memory.w_4[gate_idx];

            let mul1 = self.driver.mul_with_public(
                &self.memory.challenges.eta_1,
                &proving_key.polynomials.witness.w_l()[gate_idx],
            );
            let mul2 = self.driver.mul_with_public(
                &self.memory.challenges.eta_2,
                &proving_key.polynomials.witness.w_r()[gate_idx],
            );
            let mul3 = self.driver.mul_with_public(
                &self.memory.challenges.eta_3,
                &proving_key.polynomials.witness.w_o()[gate_idx],
            );
            // TODO add_assign?
            *target = self.driver.add(target, &mul1);
            *target = self.driver.add(target, &mul2);
            *target = self.driver.add(target, &mul3);
        }

        // Compute write record values
        for gate_idx in proving_key.memory_write_records.iter() {
            let gate_idx = *gate_idx as usize;
            let target = &mut self.memory.w_4[gate_idx];

            let mul1 = self.driver.mul_with_public(
                &self.memory.challenges.eta_1,
                &proving_key.polynomials.witness.w_l()[gate_idx],
            );
            let mul2 = self.driver.mul_with_public(
                &self.memory.challenges.eta_2,
                &proving_key.polynomials.witness.w_r()[gate_idx],
            );
            let mul3 = self.driver.mul_with_public(
                &self.memory.challenges.eta_3,
                &proving_key.polynomials.witness.w_o()[gate_idx],
            );
            // TODO add_assign?
            *target = self.driver.add(target, &mul1);
            *target = self.driver.add(target, &mul2);
            *target = self.driver.add(target, &mul3);
            *target = self.driver.add_with_public(&P::ScalarField::one(), target);
        }
    }

    // Generate relation separators alphas for sumcheck/combiner computation
    fn generate_alphas_round(&mut self, transcript: &mut TranscriptType) {
        tracing::trace!("generate alpha round");

        for idx in 0..self.memory.challenges.alphas.len() {
            self.memory.challenges.alphas[idx] =
                transcript.get_challenge::<P>(format!("alpha_{}", idx));
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

    // Compute sorted list accumulator and commitment
    fn execute_sorted_list_accumulator_round(
        &mut self,
        transcript: &mut TranscriptType,
        proving_key: &ProvingKey<T, P>,
    ) -> HonkProofResult<()> {
        tracing::trace!("executing sorted list accumulator round");

        let challs = transcript.get_challenges::<P>(&[
            "eta".to_string(),
            "eta_two".to_string(),
            "eta_three".to_string(),
        ]);
        self.memory.challenges.eta_1 = challs[0];
        self.memory.challenges.eta_2 = challs[1];
        self.memory.challenges.eta_3 = challs[2];
        self.compute_w4(proving_key);

        // Commit to lookup argument polynomials and the finalized (i.e. with memory records) fourth wire polynomial
        let lookup_read_counts = Utils::commit(
            proving_key
                .polynomials
                .witness
                .lookup_read_counts()
                .as_ref(),
            &proving_key.crs,
        )?;
        let lookup_read_tags = Utils::commit(
            proving_key.polynomials.witness.lookup_read_tags().as_ref(),
            &proving_key.crs,
        )?;
        let w_4 = CoUtils::commit(self.driver, self.memory.w_4.as_ref(), &proving_key.crs);
        let w_4 = self.driver.open_point(&w_4)?;

        transcript.send_point_to_verifier::<P>(
            "LOOKUP_READ_COUNTS".to_string(),
            lookup_read_counts.into(),
        );
        transcript
            .send_point_to_verifier::<P>("LOOKUP_READ_TAGS".to_string(), lookup_read_tags.into());
        transcript.send_point_to_verifier::<P>("W_4".to_string(), w_4.into());

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
        // Compute sorted list accumulator and commitment
        self.execute_sorted_list_accumulator_round(transcript, proving_key)?;

        todo!("Oink prove");
        // Fiat-Shamir: beta & gamma
        // self.execute_log_derivative_inverse_round(transcript, proving_key)?;
        // Compute grand product(s) and commitments.
        // self.execute_grand_product_computation_round(transcript, proving_key)?;

        // Generate relation separators alphas for sumcheck/combiner computation
        self.generate_alphas_round(transcript);
    }
}
