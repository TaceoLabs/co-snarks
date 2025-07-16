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
    Utils, decider::relations::databus_lookup_relation::BusData,
    plain_prover_flavour::PlainProverFlavour,
};
use common::transcript::{Transcript, TranscriptFieldType, TranscriptHasher};

use ark_ff::{One, Zero};
use co_builder::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::ProverWitnessEntitiesFlavour;
use co_builder::{HonkProofError, HonkProofResult};
use co_builder::{
    prelude::{HonkCurve, Polynomial, ProverCrs, ProvingKey, ZeroKnowledge},
    prover_flavour::Flavour,
};
use itertools::izip;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use std::marker::PhantomData;

pub(crate) struct Oink<
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    L: PlainProverFlavour,
> {
    memory: ProverMemory<P, L>,
    phantom_data: PhantomData<(P, H, L)>,
    has_zk: ZeroKnowledge,
    rng: ChaCha12Rng,
}

impl<
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    L: PlainProverFlavour,
> Default for Oink<P, H, L>
{
    fn default() -> Self {
        Self::new(ZeroKnowledge::No)
    }
}

impl<
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    L: PlainProverFlavour,
> Oink<P, H, L>
{
    pub(crate) fn new(has_zk: ZeroKnowledge) -> Self {
        Self {
            memory: ProverMemory::default(),
            phantom_data: PhantomData,
            has_zk,
            rng: ChaCha12Rng::from_entropy(),
        }
    }

    /// A uniform method to mask, commit, and send the corresponding commitment to the verifier.
    fn commit_to_witness_polynomial(
        &mut self,
        polynomial: &mut Polynomial<P::ScalarField>,
        label: &str,
        crs: &ProverCrs<P>,
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> HonkProofResult<()> {
        // // Mask the polynomial when proving in zero-knowledge
        if self.has_zk == ZeroKnowledge::Yes {
            polynomial.mask(&mut self.rng)
        };
        // Commit to the polynomial
        let commitment = Utils::commit(polynomial.as_ref(), crs)?;
        // Send the commitment to the verifier
        transcript.send_point_to_verifier::<P>(label.to_string(), commitment.into());

        Ok(())
    }

    fn compute_w4(&mut self, proving_key: &ProvingKey<P, L>) {
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

    fn compute_read_term(&self, proving_key: &ProvingKey<P, L>, i: usize) -> P::ScalarField {
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

    /// Compute table_1 + gamma + table_2 * eta + table_3 * eta_2 + table_4 * eta_3
    fn compute_write_term(&self, proving_key: &ProvingKey<P, L>, i: usize) -> P::ScalarField {
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

    fn compute_read_term_databus(
        &self,
        proving_key: &ProvingKey<P, L>,
        i: usize,
    ) -> P::ScalarField {
        tracing::trace!("compute read term databus");

        // Bus value stored in w_1, index into bus column stored in w_2
        let w_1 = &proving_key.polynomials.witness.w_l()[i];
        let w_2 = &proving_key.polynomials.witness.w_r()[i];
        let gamma = &self.memory.challenges.gamma;
        let beta = &self.memory.challenges.beta;

        // Construct value + index*\beta + \gamma
        (*w_2 * beta) + w_1 + gamma
    }

    /// Compute table_1 + gamma + table_2 * eta + table_3 * eta_2 + table_4 * eta_3
    fn compute_write_term_databus(
        &self,
        proving_key: &ProvingKey<P, L>,
        i: usize,
        bus_idx: BusData,
    ) -> P::ScalarField {
        tracing::trace!("compute write term databus");

        let value = match bus_idx {
            BusData::BusIdx0 => &proving_key.polynomials.witness.calldata()[i],
            BusData::BusIdx1 => &proving_key.polynomials.witness.secondary_calldata()[i],
            BusData::BusIdx2 => &proving_key.polynomials.witness.return_data()[i],
        };
        let id = &proving_key.polynomials.precomputed.databus_id()[i];
        let gamma = &self.memory.challenges.gamma;
        let beta = &self.memory.challenges.beta;
        // Construct value_i + idx_i*\beta + \gamma
        *id * beta + value + gamma // degree 1
    }

    fn compute_logderivative_inverses(&mut self, proving_key: &ProvingKey<P, L>) {
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

        // Compute inverse polynomial I in place by inverting the product at each row
        // Note: zeroes are ignored as they are not used anyway
        Utils::batch_invert(self.memory.lookup_inverses.as_mut());
    }

    fn compute_logderivative_inverses_databus(
        &mut self,
        proving_key: &ProvingKey<P, L>,
        bus_idx: BusData,
    ) {
        tracing::trace!("compute logderivative inverse for Databus");

        match bus_idx {
            BusData::BusIdx0 => self
                .memory
                .calldata_inverses
                .resize(proving_key.circuit_size as usize, P::ScalarField::zero()),
            BusData::BusIdx1 => self
                .memory
                .secondary_calldata_inverses
                .resize(proving_key.circuit_size as usize, P::ScalarField::zero()),
            BusData::BusIdx2 => self
                .memory
                .return_data_inverses
                .resize(proving_key.circuit_size as usize, P::ScalarField::zero()),
        };
        let wire = match bus_idx {
            BusData::BusIdx0 => &proving_key.polynomials.precomputed.q_l(),
            BusData::BusIdx1 => &proving_key.polynomials.precomputed.q_r(),
            BusData::BusIdx2 => &proving_key.polynomials.precomputed.q_o(),
        };
        let read_count = match bus_idx {
            BusData::BusIdx0 => &proving_key.polynomials.witness.calldata_read_counts(),
            BusData::BusIdx1 => &proving_key
                .polynomials
                .witness
                .secondary_calldata_read_counts(),
            BusData::BusIdx2 => &proving_key.polynomials.witness.return_data_read_counts(),
        };

        debug_assert_eq!(wire.len(), proving_key.circuit_size as usize);
        debug_assert_eq!(read_count.len(), proving_key.circuit_size as usize);

        for (i, (w, read)) in izip!(wire.iter(), read_count.iter(),).enumerate() {
            // Determine if the present row contains a databus operation
            let q_busread = &proving_key.polynomials.precomputed.q_busread()[i];
            let is_read = *q_busread == P::ScalarField::one() && *w == P::ScalarField::one();
            let nonzero_read_count = *read != P::ScalarField::zero();

            // We only compute the inverse if this row contains a read gate or data that has been read

            if is_read || nonzero_read_count {
                let read_term = self.compute_read_term_databus(proving_key, i);
                let write_term = self.compute_write_term_databus(proving_key, i, bus_idx);

                match bus_idx {
                    BusData::BusIdx0 => self.memory.calldata_inverses[i] = read_term * write_term,
                    BusData::BusIdx1 => {
                        self.memory.secondary_calldata_inverses[i] = read_term * write_term
                    }
                    BusData::BusIdx2 => {
                        self.memory.return_data_inverses[i] = read_term * write_term
                    }
                };
            }
        }

        // Compute inverse polynomial I in place by inverting the product at each row
        // Note: zeroes are ignored as they are not used anyway
        match bus_idx {
            BusData::BusIdx0 => Utils::batch_invert(self.memory.calldata_inverses.as_mut()),
            BusData::BusIdx1 => {
                Utils::batch_invert(self.memory.secondary_calldata_inverses.as_mut())
            }
            BusData::BusIdx2 => Utils::batch_invert(self.memory.return_data_inverses.as_mut()),
        };
    }

    pub(crate) fn compute_public_input_delta(
        beta: &P::ScalarField,
        gamma: &P::ScalarField,
        public_inputs: &[P::ScalarField],
        circuit_size: u32,
        pub_inputs_offset: u32,
    ) -> P::ScalarField {
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
        let mut num_acc =
            *gamma + P::ScalarField::from((circuit_size + pub_inputs_offset) as u64) * beta;
        let mut denom_acc = *gamma - P::ScalarField::from((1 + pub_inputs_offset) as u64) * beta;

        for x_i in public_inputs.iter() {
            num *= num_acc + x_i;
            denom *= denom_acc + x_i;
            num_acc += beta;
            denom_acc -= beta;
        }
        num / denom
    }

    fn compute_grand_product_numerator(
        &self,
        proving_key: &ProvingKey<P, L>,
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

    fn grand_product_denominator(
        &self,
        proving_key: &ProvingKey<P, L>,
        i: usize,
    ) -> P::ScalarField {
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

    fn compute_grand_product(&mut self, proving_key: &ProvingKey<P, L>) {
        tracing::trace!("compute grand product");

        let has_active_ranges = proving_key.active_region_data.size() > 0;

        // Barratenberg uses multithreading here

        // Set the domain over which the grand product must be computed. This may be less than the dyadic circuit size, e.g
        // the permutation grand product does not need to be computed beyond the index of the last active wire
        let domain_size = proving_key.final_active_wire_idx + 1;

        let active_domain_size = if has_active_ranges {
            proving_key.active_region_data.size()
        } else {
            domain_size
        };

        // In Barretenberg circuit size is taken from the q_c polynomial
        let mut numerator = Vec::with_capacity(active_domain_size - 1);
        let mut denominator = Vec::with_capacity(active_domain_size - 1);

        // Step (1)
        // Populate `numerator` and `denominator` with the algebra described by Relation

        for i in 0..active_domain_size - 1 {
            let idx = if has_active_ranges {
                proving_key.active_region_data.get_idx(i)
            } else {
                i
            };
            numerator.push(self.compute_grand_product_numerator(proving_key, idx));
            denominator.push(self.grand_product_denominator(proving_key, idx));
        }

        // Step (2)
        // Compute the accumulating product of the numerator and denominator terms.
        // In Barretenberg, this is done in parallel across multiple threads, however we just do the computation signlethreaded for simplicity

        for i in 1..active_domain_size - 1 {
            numerator[i] = numerator[i] * numerator[i - 1];
            denominator[i] = denominator[i] * denominator[i - 1];
        }

        // invert denominator
        Utils::batch_invert(&mut denominator);

        // Step (3) Compute z_perm[i] = numerator[i] / denominator[i]
        self.memory
            .z_perm
            .resize(proving_key.circuit_size as usize, P::ScalarField::zero());

        // For Ultra/Mega, the first row is an inactive zero row thus the grand prod takes value 1 at both i = 0 and i = 1
        self.memory.z_perm[1] = P::ScalarField::one();

        // Compute grand product values corresponding only to the active regions of the trace
        for i in 0..active_domain_size - 1 {
            let idx = if has_active_ranges {
                proving_key.active_region_data.get_idx(i)
            } else {
                i
            };
            self.memory.z_perm[idx + 1] = numerator[i] * denominator[i];
        }

        // Final step: If active/inactive regions have been specified, the value of the grand product in the inactive
        // regions have not yet been set. The polynomial takes an already computed constant value across each inactive
        // region (since no copy constraints are present there) equal to the value of the grand product at the first index
        // of the subsequent active region.
        if has_active_ranges {
            for i in 0..domain_size {
                for j in 0..proving_key.active_region_data.num_ranges() - 1 {
                    let previous_range_end = proving_key.active_region_data.get_range(j).1;
                    let next_range_start = proving_key.active_region_data.get_range(j + 1).0;
                    // Set the value of the polynomial if the index falls in an inactive region
                    if i >= previous_range_end && i < next_range_start {
                        self.memory.z_perm[i + 1] = self.memory.z_perm[next_range_start];
                    }
                }
            }
        }
    }

    /// Generate relation separators alphas for sumcheck/combiner computation
    pub(crate) fn generate_alphas_round(
        alphas: &mut L::Alphas<P::ScalarField>,
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) {
        tracing::trace!("generate alpha round");
        L::get_alpha_challenges::<_, _, P>(transcript, alphas);
    }

    /// Add circuit size public input size and public inputs to transcript
    fn execute_preamble_round(
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &ProvingKey<P, L>,
    ) -> HonkProofResult<()> {
        tracing::trace!("executing preamble round");

        transcript
            .add_u64_to_hash_buffer("CIRCUIT_SIZE".to_string(), proving_key.circuit_size as u64);
        transcript.add_u64_to_hash_buffer(
            "PUBLIC_INPUT_SIZE".to_string(),
            proving_key.num_public_inputs as u64,
        );
        transcript.add_u64_to_hash_buffer(
            "PUB_INPUTS_OFFSET".to_string(),
            proving_key.pub_inputs_offset as u64,
        );

        if proving_key.num_public_inputs as usize != proving_key.public_inputs.len() {
            return Err(HonkProofError::CorruptedWitness(
                proving_key.public_inputs.len(),
            ));
        }

        for (i, public_input) in proving_key.public_inputs.iter().enumerate() {
            // transcript.add_scalar(*public_input);
            transcript.send_fr_to_verifier::<P>(format!("PUBLIC_INPUT_{i}"), *public_input);
        }
        Ok(())
    }

    /// Compute first three wire commitments
    fn execute_wire_commitments_round(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &mut ProvingKey<P, L>,
    ) -> HonkProofResult<()> {
        tracing::trace!("executing wire commitments round");

        // Commit to the first three wire polynomials of the instance
        // We only commit to the fourth wire polynomial after adding memory records

        // Ultracircuits are not structured (also our commitment type is CommitType::Default, so no changes are needed here yet)

        self.commit_to_witness_polynomial(
            proving_key.polynomials.witness.w_l_mut(),
            "W_L",
            &proving_key.crs,
            transcript,
        )?;

        self.commit_to_witness_polynomial(
            proving_key.polynomials.witness.w_r_mut(),
            "W_R",
            &proving_key.crs,
            transcript,
        )?;

        self.commit_to_witness_polynomial(
            proving_key.polynomials.witness.w_o_mut(),
            "W_O",
            &proving_key.crs,
            transcript,
        )?;
        if L::FLAVOUR == Flavour::Mega {
            let has_zk = self.has_zk;
            self.has_zk = ZeroKnowledge::No; // MegaZKFlavor does not mask the wires, so we set has_zk to No
            // Commit to Goblin ECC op wires.
            // To avoid possible issues with the current work on the merge protocol, they (the ecc_op_wires) are not
            // masked in MegaZKFlavor
            self.commit_to_witness_polynomial(
                proving_key.polynomials.witness.ecc_op_wire_1_mut(),
                "ECC_OP_WIRE_1",
                &proving_key.crs,
                transcript,
            )?;
            self.commit_to_witness_polynomial(
                proving_key.polynomials.witness.ecc_op_wire_2_mut(),
                "ECC_OP_WIRE_2",
                &proving_key.crs,
                transcript,
            )?;
            self.commit_to_witness_polynomial(
                proving_key.polynomials.witness.ecc_op_wire_3_mut(),
                "ECC_OP_WIRE_3",
                &proving_key.crs,
                transcript,
            )?;
            self.commit_to_witness_polynomial(
                proving_key.polynomials.witness.ecc_op_wire_4_mut(),
                "ECC_OP_WIRE_4",
                &proving_key.crs,
                transcript,
            )?;
            // These polynomials get masked in ZKFlavour
            self.has_zk = has_zk;
            self.commit_to_witness_polynomial(
                proving_key.polynomials.witness.calldata_mut(),
                "CALLDATA",
                &proving_key.crs,
                transcript,
            )?;
            self.commit_to_witness_polynomial(
                proving_key.polynomials.witness.calldata_read_counts_mut(),
                "CALLDATA_READ_COUNTS",
                &proving_key.crs,
                transcript,
            )?;
            self.commit_to_witness_polynomial(
                proving_key.polynomials.witness.calldata_read_tags_mut(),
                "CALLDATA_READ_TAGS",
                &proving_key.crs,
                transcript,
            )?;
            self.commit_to_witness_polynomial(
                proving_key.polynomials.witness.secondary_calldata_mut(),
                "SECONDARY_CALLDATA",
                &proving_key.crs,
                transcript,
            )?;
            self.commit_to_witness_polynomial(
                proving_key
                    .polynomials
                    .witness
                    .secondary_calldata_read_counts_mut(),
                "SECONDARY_CALLDATA_READ_COUNTS",
                &proving_key.crs,
                transcript,
            )?;
            self.commit_to_witness_polynomial(
                proving_key
                    .polynomials
                    .witness
                    .secondary_calldata_read_tags_mut(),
                "SECONDARY_CALLDATA_READ_TAGS",
                &proving_key.crs,
                transcript,
            )?;
            self.commit_to_witness_polynomial(
                proving_key.polynomials.witness.return_data_mut(),
                "RETURN_DATA",
                &proving_key.crs,
                transcript,
            )?;
            self.commit_to_witness_polynomial(
                proving_key
                    .polynomials
                    .witness
                    .return_data_read_counts_mut(),
                "RETURN_DATA_READ_COUNTS",
                &proving_key.crs,
                transcript,
            )?;
            self.commit_to_witness_polynomial(
                proving_key.polynomials.witness.return_data_read_tags_mut(),
                "RETURN_DATA_READ_TAGS",
                &proving_key.crs,
                transcript,
            )?;
        }

        Ok(())
    }

    /// Compute sorted list accumulator and commitment
    fn execute_sorted_list_accumulator_round(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &mut ProvingKey<P, L>,
    ) -> HonkProofResult<()> {
        tracing::trace!("executing sorted list accumulator round");

        let challs = transcript.get_challenges::<P>(&[
            "ETA".to_string(),
            "ETA_TWO".to_string(),
            "ETA_THREE".to_string(),
        ]);
        self.memory.challenges.eta_1 = challs[0];
        self.memory.challenges.eta_2 = challs[1];
        self.memory.challenges.eta_3 = challs[2];
        self.compute_w4(proving_key);

        // Commit to lookup argument polynomials and the finalized (i.e. with memory records) fourth wire polynomial
        // TACEO TODO: BB does "sparse" commitment here, I don't know if that is necessary (performance wise)

        self.commit_to_witness_polynomial(
            proving_key.polynomials.witness.lookup_read_counts_mut(),
            "LOOKUP_READ_COUNTS",
            &proving_key.crs,
            transcript,
        )?;
        self.commit_to_witness_polynomial(
            proving_key.polynomials.witness.lookup_read_tags_mut(),
            "LOOKUP_READ_TAGS",
            &proving_key.crs,
            transcript,
        )?;
        // we do std::mem::take here to avoid borrowing issues with self
        let mut w_4_tmp = std::mem::take(&mut self.memory.w_4);
        self.commit_to_witness_polynomial(&mut w_4_tmp, "W_4", &proving_key.crs, transcript)?;
        std::mem::swap(&mut self.memory.w_4, &mut w_4_tmp);
        Ok(())
    }

    /// Fiat-Shamir: beta & gamma
    fn execute_log_derivative_inverse_round(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &mut ProvingKey<P, L>,
    ) -> HonkProofResult<()> {
        tracing::trace!("executing log derivative inverse round");

        let challs = transcript.get_challenges::<P>(&["beta".to_string(), "gamma".to_string()]);
        self.memory.challenges.beta = challs[0];
        self.memory.challenges.gamma = challs[1];

        self.compute_logderivative_inverses(proving_key);

        // TACEO TODO: BB does "sparse" commitment here, I don't know if that is necessary (performance wise)
        // we do std::mem::take here to avoid borrowing issues with self
        let mut lookup_inverses_tmp = std::mem::take(&mut self.memory.lookup_inverses);
        self.commit_to_witness_polynomial(
            &mut lookup_inverses_tmp,
            "LOOKUP_INVERSES",
            &proving_key.crs,
            transcript,
        )?;
        std::mem::swap(&mut self.memory.lookup_inverses, &mut lookup_inverses_tmp);
        // If Mega, commit to the databus inverse polynomials and send
        if L::FLAVOUR == Flavour::Mega {
            self.compute_logderivative_inverses_databus(proving_key, BusData::BusIdx0);
            self.compute_logderivative_inverses_databus(proving_key, BusData::BusIdx1);
            self.compute_logderivative_inverses_databus(proving_key, BusData::BusIdx2);

            // we do std::mem::take here to avoid borrowing issues with self
            let mut calldata_inverses_tmp = std::mem::take(&mut self.memory.calldata_inverses);
            self.commit_to_witness_polynomial(
                &mut calldata_inverses_tmp,
                "CALLDATA_INVERSES",
                &proving_key.crs,
                transcript,
            )?;
            std::mem::swap(
                &mut self.memory.calldata_inverses,
                &mut calldata_inverses_tmp,
            );
            let mut secondary_calldata_inverses_tmp =
                std::mem::take(&mut self.memory.secondary_calldata_inverses);

            self.commit_to_witness_polynomial(
                &mut secondary_calldata_inverses_tmp,
                "SECONDARY_CALLDATA_INVERSES",
                &proving_key.crs,
                transcript,
            )?;
            std::mem::swap(
                &mut self.memory.secondary_calldata_inverses,
                &mut secondary_calldata_inverses_tmp,
            );
            let mut return_data_inverses_tmp =
                std::mem::take(&mut self.memory.return_data_inverses);
            self.commit_to_witness_polynomial(
                &mut return_data_inverses_tmp,
                "RETURN_DATA_INVERSES",
                &proving_key.crs,
                transcript,
            )?;
            std::mem::swap(
                &mut self.memory.return_data_inverses,
                &mut return_data_inverses_tmp,
            );
        }

        Ok(())
    }

    /// Compute grand product(s) and commitments.
    fn execute_grand_product_computation_round(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &mut ProvingKey<P, L>,
    ) -> HonkProofResult<()> {
        tracing::trace!("executing grand product computation round");

        self.memory.public_input_delta = Self::compute_public_input_delta(
            &self.memory.challenges.beta,
            &self.memory.challenges.gamma,
            &proving_key.public_inputs,
            proving_key.circuit_size,
            proving_key.pub_inputs_offset,
        );
        self.compute_grand_product(proving_key);
        // we do std::mem::take here to avoid borrowing issues with self
        let mut z_perm_tmp = std::mem::take(&mut self.memory.z_perm);
        self.commit_to_witness_polynomial(&mut z_perm_tmp, "Z_PERM", &proving_key.crs, transcript)?;
        std::mem::swap(&mut self.memory.z_perm, &mut z_perm_tmp);
        Ok(())
    }

    pub(crate) fn prove(
        mut self,
        proving_key: &mut ProvingKey<P, L>,
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> HonkProofResult<ProverMemory<P, L>> {
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
        Self::generate_alphas_round(&mut self.memory.challenges.alphas, transcript);

        Ok(self.memory)
    }
}
