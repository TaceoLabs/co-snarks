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
use crate::{
    batch_invert,
    honk_curve::HonkCurve,
    prover::{HonkProofError, HonkProofResult},
    transcript::{TranscriptFieldType, TranscriptType},
    types::ProvingKey,
};
use ark_ff::{One, Zero};
use itertools::izip;
use std::marker::PhantomData;

pub(crate) struct Oink<P: HonkCurve<TranscriptFieldType>> {
    memory: ProverMemory<P>,
    phantom_data: PhantomData<P>,
}

impl<P: HonkCurve<TranscriptFieldType>> Default for Oink<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: HonkCurve<TranscriptFieldType>> Oink<P> {
    pub(crate) fn new() -> Self {
        Self {
            memory: ProverMemory::default(),
            phantom_data: PhantomData,
        }
    }

    fn compute_w4(&mut self, proving_key: &ProvingKey<P>) {
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
            P::ScalarField::zero(),
        );

        // Compute read record values
        for gate_idx in proving_key.memory_read_records.iter() {
            let gate_idx = *gate_idx as usize;
            let target = &mut self.memory.w_4[gate_idx];
            *target += proving_key.polynomials.witness.w_l()[gate_idx]
                * self.memory.challenges.eta_1
                + proving_key.polynomials.witness.w_r()[gate_idx] * self.memory.challenges.eta_2
                + proving_key.polynomials.witness.w_o()[gate_idx] * self.memory.challenges.eta_3;
        }

        // Compute write record values
        for gate_idx in proving_key.memory_write_records.iter() {
            let gate_idx = *gate_idx as usize;
            let target = &mut self.memory.w_4[gate_idx];
            *target += proving_key.polynomials.witness.w_l()[gate_idx]
                * self.memory.challenges.eta_1
                + proving_key.polynomials.witness.w_r()[gate_idx] * self.memory.challenges.eta_2
                + proving_key.polynomials.witness.w_o()[gate_idx] * self.memory.challenges.eta_3
                + P::ScalarField::one();
        }
    }

    fn compute_read_term(&self, proving_key: &ProvingKey<P>, i: usize) -> P::ScalarField {
        tracing::trace!("compute read term");

        let gamma = &self.memory.challenges.gamma;
        let eta_1 = &self.memory.challenges.eta_1;
        let eta_2 = &self.memory.challenges.eta_2;
        let eta_3 = &self.memory.challenges.eta_3;
        let w_1 = &proving_key.polynomials.witness.w_l()[i];
        let w_2 = &proving_key.polynomials.witness.w_r()[i];
        let w_3 = &proving_key.polynomials.witness.w_o()[i];
        let w_1_shift = &proving_key.polynomials.witness.w_l().shifted()[i];
        let w_2_shift = &proving_key.polynomials.witness.w_r().shifted()[i];
        let w_3_shift = &proving_key.polynomials.witness.w_o().shifted()[i];
        let table_index = &proving_key.polynomials.precomputed.q_o()[i];
        let negative_column_1_step_size = &proving_key.polynomials.precomputed.q_r()[i];
        let negative_column_2_step_size = &proving_key.polynomials.precomputed.q_m()[i];
        let negative_column_3_step_size = &proving_key.polynomials.precomputed.q_c()[i];

        // The wire values for lookup gates are accumulators structured in such a way that the differences w_i -
        // step_size*w_i_shift result in values present in column i of a corresponding table. See the documentation in
        // method get_lookup_accumulators() in  for a detailed explanation.
        let derived_table_entry_1 = *w_1 + gamma + *negative_column_1_step_size * w_1_shift;
        let derived_table_entry_2 = *w_2 + *negative_column_2_step_size * w_2_shift;
        let derived_table_entry_3 = *w_3 + *negative_column_3_step_size * w_3_shift;

        // (w_1 + \gamma q_2*w_1_shift) + η(w_2 + q_m*w_2_shift) + η₂(w_3 + q_c*w_3_shift) + η₃q_index.
        // deg 2 or 3
        derived_table_entry_1
            + derived_table_entry_2 * eta_1
            + derived_table_entry_3 * eta_2
            + *table_index * eta_3
    }

    // Compute table_1 + gamma + table_2 * eta + table_3 * eta_2 + table_4 * eta_3
    fn compute_write_term(&self, proving_key: &ProvingKey<P>, i: usize) -> P::ScalarField {
        tracing::trace!("compute write term");

        let gamma = &self.memory.challenges.gamma;
        let eta_1 = &self.memory.challenges.eta_1;
        let eta_2 = &self.memory.challenges.eta_2;
        let eta_3 = &self.memory.challenges.eta_3;
        let table_1 = &proving_key.polynomials.precomputed.table_1()[i];
        let table_2 = &proving_key.polynomials.precomputed.table_2()[i];
        let table_3 = &proving_key.polynomials.precomputed.table_3()[i];
        let table_4 = &proving_key.polynomials.precomputed.table_4()[i];

        *table_1 + gamma + *table_2 * eta_1 + *table_3 * eta_2 + *table_4 * eta_3
    }

    fn compute_logderivative_inverses(&mut self, proving_key: &ProvingKey<P>) {
        tracing::trace!("compute logderivative inverse");

        debug_assert_eq!(
            proving_key.polynomials.precomputed.q_lookup().len(),
            proving_key.circuit_size as usize
        );
        debug_assert_eq!(
            proving_key.polynomials.witness.lookup_read_tags().len(),
            proving_key.circuit_size as usize
        );
        self.memory
            .lookup_inverses
            .resize(proving_key.circuit_size as usize, P::ScalarField::zero());

        // const READ_TERMS: usize = 1;
        // const WRITE_TERMS: usize = 1;
        // // 1 + polynomial degree of this relation
        // const LENGTH: usize = 5; // both subrelations are degree 4

        for (i, (q_lookup, lookup_read_tag)) in izip!(
            proving_key.polynomials.precomputed.q_lookup().iter(),
            proving_key.polynomials.witness.lookup_read_tags().iter(),
        )
        .enumerate()
        {
            if !(q_lookup.is_one() || lookup_read_tag.is_one()) {
                continue;
            }

            // READ_TERMS and WRITE_TERMS are 1, so we skip the loop
            let read_term = self.compute_read_term(proving_key, i);
            let write_term = self.compute_write_term(proving_key, i);
            self.memory.lookup_inverses[i] = read_term * write_term;
        }

        batch_invert(self.memory.lookup_inverses.as_mut());
    }

    fn compute_public_input_delta(&self, proving_key: &ProvingKey<P>) -> P::ScalarField {
        tracing::trace!("compute public input delta");

        // Let m be the number of public inputs x₀,…, xₘ₋₁.
        // Recall that we broke the permutation σ⁰ by changing the mapping
        //  (i) -> (n+i)   to   (i) -> (-(i+1))   i.e. σ⁰ᵢ = −(i+1)
        //
        // Therefore, the term in the numerator with ID¹ᵢ = n+i does not cancel out with any term in the denominator.
        // Similarly, the denominator contains an extra σ⁰ᵢ = −(i+1) term that does not appear in the numerator.
        // We expect the values of W⁰ᵢ and W¹ᵢ to be equal to xᵢ.
        // The expected accumulated product would therefore be equal to

        //   ∏ᵢ (γ + W¹ᵢ + β⋅ID¹ᵢ)        ∏ᵢ (γ + xᵢ + β⋅(n+i) )
        //  -----------------------  =  ------------------------
        //   ∏ᵢ (γ + W⁰ᵢ + β⋅σ⁰ᵢ )        ∏ᵢ (γ + xᵢ - β⋅(i+1) )

        // At the start of the loop for each xᵢ where i = 0, 1, …, m-1,
        // we have
        //      numerator_acc   = γ + β⋅(n+i) = γ + β⋅n + β⋅i
        //      denominator_acc = γ - β⋅(1+i) = γ - β   - β⋅i
        // at the end of the loop, add and subtract β to each term respectively to
        // set the expected value for the start of iteration i+1.
        // Note: The public inputs may be offset from the 0th index of the wires, for example due to the inclusion of an
        // initial zero row or Goblin-stlye ECC op gates. Accordingly, the indices i in the above formulas are given by i =
        // [0, m-1] + offset, i.e. i = offset, 1 + offset, …, m - 1 + offset.

        let mut num = P::ScalarField::one();
        let mut denom = P::ScalarField::one();
        let mut num_acc = self.memory.challenges.gamma
            + self.memory.challenges.beta
                * P::ScalarField::from(
                    (proving_key.circuit_size + proving_key.pub_inputs_offset) as u64,
                );
        let mut denom_acc = self.memory.challenges.gamma
            - self.memory.challenges.beta
                * P::ScalarField::from((1 + proving_key.pub_inputs_offset) as u64);

        for x_i in proving_key.public_inputs.iter() {
            num *= num_acc + x_i;
            denom *= denom_acc + x_i;
            num_acc += self.memory.challenges.beta;
            denom_acc -= self.memory.challenges.beta;
        }
        num / denom
    }

    fn compute_grand_product_numerator(
        &self,
        proving_key: &ProvingKey<P>,
        i: usize,
    ) -> P::ScalarField {
        tracing::trace!("compute grand product numerator");

        let w_1 = &proving_key.polynomials.witness.w_l()[i];
        let w_2 = &proving_key.polynomials.witness.w_r()[i];
        let w_3 = &proving_key.polynomials.witness.w_o()[i];
        let w_4 = &self.memory.w_4[i];
        let id_1 = &proving_key.polynomials.precomputed.id_1()[i];
        let id_2 = &proving_key.polynomials.precomputed.id_2()[i];
        let id_3 = &proving_key.polynomials.precomputed.id_3()[i];
        let id_4 = &proving_key.polynomials.precomputed.id_4()[i];
        let beta = &self.memory.challenges.beta;
        let gamma = &self.memory.challenges.gamma;

        // witness degree 4; full degree 8
        (*w_1 + *id_1 * beta + gamma)
            * (*w_2 + *id_2 * beta + gamma)
            * (*w_3 + *id_3 * beta + gamma)
            * (*w_4 + *id_4 * beta + gamma)
    }

    fn grand_product_denominator(&self, proving_key: &ProvingKey<P>, i: usize) -> P::ScalarField {
        tracing::trace!("compute grand product denominator");

        let w_1 = &proving_key.polynomials.witness.w_l()[i];
        let w_2 = &proving_key.polynomials.witness.w_r()[i];
        let w_3 = &proving_key.polynomials.witness.w_o()[i];
        let w_4 = &self.memory.w_4[i];
        let sigma_1 = &proving_key.polynomials.precomputed.sigma_1()[i];
        let sigma_2 = &proving_key.polynomials.precomputed.sigma_2()[i];
        let sigma_3 = &proving_key.polynomials.precomputed.sigma_3()[i];
        let sigma_4 = &proving_key.polynomials.precomputed.sigma_4()[i];
        let beta = &self.memory.challenges.beta;
        let gamma = &self.memory.challenges.gamma;

        // witness degree 4; full degree 8
        (*w_1 + *sigma_1 * beta + gamma)
            * (*w_2 + *sigma_2 * beta + gamma)
            * (*w_3 + *sigma_3 * beta + gamma)
            * (*w_4 + *sigma_4 * beta + gamma)
    }

    fn compute_grand_product(&mut self, proving_key: &ProvingKey<P>) {
        tracing::trace!("compute grand product");
        // Barratenberg uses multithreading here

        // In Barretenberg circuit size is taken from the q_c polynomial
        let mut numerator = Vec::with_capacity(proving_key.circuit_size as usize);
        let mut denominator = Vec::with_capacity(proving_key.circuit_size as usize);

        // Step (1)
        // Populate `numerator` and `denominator` with the algebra described by Relation

        for i in 0..proving_key.circuit_size as usize {
            numerator.push(self.compute_grand_product_numerator(proving_key, i));
            denominator.push(self.grand_product_denominator(proving_key, i));
        }

        // Step (2)
        // Compute the accumulating product of the numerator and denominator terms.
        // In Barretenberg, this is done in parallel across multiple threads, however we just do the computation signlethreaded for simplicity

        for i in 1..proving_key.circuit_size as usize {
            numerator[i] = numerator[i] * numerator[i - 1];
            denominator[i] = denominator[i] * denominator[i - 1];
        }

        // invert denominator
        batch_invert(&mut denominator);

        // Step (3) Compute z_perm[i] = numerator[i] / denominator[i]
        self.memory
            .z_perm
            .resize(proving_key.circuit_size as usize, P::ScalarField::zero());

        for (des, num, den) in izip!(
            self.memory.z_perm.iter_mut().skip(1),
            numerator.into_iter(),
            denominator.into_iter()
        ) {
            *des = num * den;
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
        proving_key: &ProvingKey<P>,
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
        proving_key: &ProvingKey<P>,
    ) -> HonkProofResult<()> {
        tracing::trace!("executing wire commitments round");

        // Commit to the first three wire polynomials of the instance
        // We only commit to the fourth wire polynomial after adding memory records

        let w_l = crate::commit(
            proving_key.polynomials.witness.w_l().as_ref(),
            &proving_key.crs,
        )?;
        let w_r = crate::commit(
            proving_key.polynomials.witness.w_r().as_ref(),
            &proving_key.crs,
        )?;
        let w_o = crate::commit(
            proving_key.polynomials.witness.w_o().as_ref(),
            &proving_key.crs,
        )?;

        transcript.send_point_to_verifier::<P>("W_L".to_string(), w_l.into());
        transcript.send_point_to_verifier::<P>("W_R".to_string(), w_r.into());
        transcript.send_point_to_verifier::<P>("W_O".to_string(), w_o.into());

        // Round is done since ultra_honk is no goblin flavor
        Ok(())
    }

    // Compute sorted list accumulator and commitment
    fn execute_sorted_list_accumulator_round(
        &mut self,
        transcript: &mut TranscriptType,
        proving_key: &ProvingKey<P>,
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
        let lookup_read_counts = crate::commit(
            proving_key
                .polynomials
                .witness
                .lookup_read_counts()
                .as_ref(),
            &proving_key.crs,
        )?;
        let lookup_read_tags = crate::commit(
            proving_key.polynomials.witness.lookup_read_tags().as_ref(),
            &proving_key.crs,
        )?;
        let w_4 = crate::commit(self.memory.w_4.as_ref(), &proving_key.crs)?;

        transcript.send_point_to_verifier::<P>(
            "LOOKUP_READ_COUNTS".to_string(),
            lookup_read_counts.into(),
        );
        transcript
            .send_point_to_verifier::<P>("LOOKUP_READ_TAGS".to_string(), lookup_read_tags.into());
        transcript.send_point_to_verifier::<P>("W_4".to_string(), w_4.into());

        Ok(())
    }

    // Fiat-Shamir: beta & gamma
    fn execute_log_derivative_inverse_round(
        &mut self,
        transcript: &mut TranscriptType,
        proving_key: &ProvingKey<P>,
    ) -> HonkProofResult<()> {
        tracing::trace!("executing log derivative inverse round");

        let challs = transcript.get_challenges::<P>(&["beta".to_string(), "gamma".to_string()]);
        self.memory.challenges.beta = challs[0];
        self.memory.challenges.gamma = challs[1];

        self.compute_logderivative_inverses(proving_key);

        let lookup_inverses =
            crate::commit(self.memory.lookup_inverses.as_ref(), &proving_key.crs)?;

        transcript
            .send_point_to_verifier::<P>("LOOKUP_INVERSES".to_string(), lookup_inverses.into());

        // Round is done since ultra_honk is no goblin flavor
        Ok(())
    }

    // Compute grand product(s) and commitments.
    fn execute_grand_product_computation_round(
        &mut self,
        transcript: &mut TranscriptType,
        proving_key: &ProvingKey<P>,
    ) -> HonkProofResult<()> {
        tracing::trace!("executing grand product computation round");

        self.memory.public_input_delta = self.compute_public_input_delta(proving_key);
        self.compute_grand_product(proving_key);

        let z_perm = crate::commit(self.memory.z_perm.as_ref(), &proving_key.crs)?;

        transcript.send_point_to_verifier::<P>("Z_PERM".to_string(), z_perm.into());
        Ok(())
    }

    pub(crate) fn prove(
        mut self,
        proving_key: &ProvingKey<P>,
        transcript: &mut TranscriptType,
    ) -> HonkProofResult<ProverMemory<P>> {
        tracing::trace!("Oink prove");

        // Add circuit size public input size and public inputs to transcript
        Self::execute_preamble_round(transcript, proving_key)?;
        // Compute first three wire commitments
        self.execute_wire_commitments_round(transcript, proving_key)?;
        // Compute sorted list accumulator and commitment
        self.execute_sorted_list_accumulator_round(transcript, proving_key)?;
        // Fiat-Shamir: beta & gamma
        self.execute_log_derivative_inverse_round(transcript, proving_key)?;
        // Compute grand product(s) and commitments.
        self.execute_grand_product_computation_round(transcript, proving_key)?;

        // Generate relation separators alphas for sumcheck/combiner computation
        self.generate_alphas_round(transcript);

        Ok(self.memory)
    }
}
