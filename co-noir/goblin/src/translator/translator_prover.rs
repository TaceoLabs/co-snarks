use crate::CONST_TRANSLATOR_LOG_N;
use ark_ec::CurveGroup;
use ark_ff::Zero;
use co_builder::HonkProofResult;
use co_builder::flavours::translator_flavour::TranslatorFlavour;
use co_builder::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::ShiftedWitnessEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::WitnessEntitiesFlavour;
use co_builder::prelude::Utils;
use co_builder::prelude::{HonkCurve, Polynomial, Polynomials, ProverCrs};
use common::HonkProof;
use common::compute_opening_proof;
use common::transcript::{Transcript, TranscriptFieldType};
use itertools::izip;
use num_bigint::BigUint;
use std::iter;
use ultrahonk::Utils as UltraHonkUtils;
use ultrahonk::prelude::ZeroKnowledge;
use ultrahonk::prelude::{
    AllEntities, Decider, ProvingKey, SmallSubgroupIPAProver, SumcheckOutput, TranscriptHasher,
    ZKSumcheckData,
};

#[derive(Default)]
pub(crate) struct ProverMemory<P: CurveGroup> {
    pub(crate) z_perm: Polynomial<P::ScalarField>,
}

pub struct Translator<P: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>> {
    decider: Decider<P, H, TranslatorFlavour>,
    batching_challenge_v: P::BaseField,
    evaluation_input_x: P::BaseField,
    memory: ProverMemory<P>, //This is somewhat equivalent to the Oink Memory (i.e stores the lookup_inverses and z_perm)
}

impl<P: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>> Translator<P, H> {
    pub fn new(batching_challenge_v: P::BaseField, evaluation_input_x: P::BaseField) -> Self {
        Self {
            decider: Decider::new(Default::default(), ZeroKnowledge::Yes),
            batching_challenge_v,
            evaluation_input_x,
            memory: ProverMemory::default(),
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
        // polynomial.mask(&mut self.decider.rng); // THERE IS NO MASKING IN TRANSLATOR (YET?)

        // Commit to the polynomial
        let commitment = UltraHonkUtils::commit(polynomial.as_ref(), crs)?;
        // Send the commitment to the verifier
        transcript.send_point_to_verifier::<P>(label.to_string(), commitment.into());

        Ok(())
    }

    pub fn construct_proof(
        &mut self,
        mut transcript: Transcript<TranscriptFieldType, H>,
        mut proving_key: ProvingKey<P, TranslatorFlavour>,
    ) -> HonkProofResult<HonkProof<TranscriptFieldType>> {
        tracing::trace!("TranslatorProver::construct_proof");
        let circuit_size = proving_key.circuit_size;

        // Add circuit size public input size and public inputs to transcript.
        self.execute_preamble_round(&mut transcript, &mut proving_key)?;

        // Compute first three wire commitments
        self.execute_wire_and_sorted_constraints_commitments_round(
            &mut transcript,
            &mut proving_key,
        )?;

        // Fiat-Shamir: gamma
        // Compute grand product(s) and commitments.
        self.execute_grand_product_computation_round(&mut transcript, &proving_key)?;

        self.add_polynomials_to_memory(proving_key.polynomials);

        // Fiat-Shamir: alpha
        // Run sumcheck subprotocol.
        let (sumcheck_output, zk_sumcheck_data) =
            self.execute_relation_check_rounds(&mut transcript, &proving_key.crs, circuit_size)?;

        // Fiat-Shamir: rho, y, x, z
        // Execute Shplemini PCS
        self.execute_pcs_rounds(
            sumcheck_output,
            zk_sumcheck_data,
            &mut transcript,
            &proving_key.crs,
            circuit_size,
        )?;
        Ok(transcript.get_proof())
    }

    fn execute_preamble_round(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &mut ProvingKey<P, TranslatorFlavour>,
    ) -> HonkProofResult<()> {
        const NUM_LIMB_BITS: usize = TranslatorFlavour::NUM_LIMB_BITS;
        let shift: BigUint = BigUint::from(1u32) << NUM_LIMB_BITS;
        let shiftx2: BigUint = BigUint::from(1u32) << (NUM_LIMB_BITS * 2);
        let shiftx3: BigUint = BigUint::from(1u32) << (NUM_LIMB_BITS * 3);
        const RESULT_ROW: usize = TranslatorFlavour::RESULT_ROW;

        let first: BigUint = proving_key
            .polynomials
            .witness
            .accumulators_binary_limbs_0()[RESULT_ROW]
            .into();
        let second: BigUint = proving_key
            .polynomials
            .witness
            .accumulators_binary_limbs_1()[RESULT_ROW]
            .into();
        let third: BigUint = proving_key
            .polynomials
            .witness
            .accumulators_binary_limbs_2()[RESULT_ROW]
            .into();
        let fourth: BigUint = proving_key
            .polynomials
            .witness
            .accumulators_binary_limbs_3()[RESULT_ROW]
            .into();

        let accumulated_result: P::BaseField =
            (first + second * &shift + third * &shiftx2 + fourth * &shiftx3).into();

        self.decider.memory.relation_parameters.accumulated_result = vec![
            proving_key
                .polynomials
                .witness
                .accumulators_binary_limbs_0()[RESULT_ROW],
            proving_key
                .polynomials
                .witness
                .accumulators_binary_limbs_1()[RESULT_ROW],
            proving_key
                .polynomials
                .witness
                .accumulators_binary_limbs_2()[RESULT_ROW],
            proving_key
                .polynomials
                .witness
                .accumulators_binary_limbs_3()[RESULT_ROW],
        ]
        .try_into()
        .expect("We should have 4 limbs in the result");

        transcript.send_fq_to_verifier::<P>("accumulated_result".to_string(), accumulated_result);
        Ok(())
    }

    fn execute_wire_and_sorted_constraints_commitments_round(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &mut ProvingKey<P, TranslatorFlavour>,
    ) -> HonkProofResult<()> {
        let non_shifted_label = TranslatorFlavour::wire_non_shifted_labels();
        let wire_non_shifted = proving_key.polynomials.witness.wire_non_shifted_mut();
        self.commit_to_witness_polynomial(
            wire_non_shifted,
            non_shifted_label,
            &proving_key.crs,
            transcript,
        )?;

        let to_be_shifted_labels = TranslatorFlavour::wire_to_be_shifted_labels();
        let wire_to_be_shifted = proving_key.polynomials.witness.wire_to_be_shifted_mut();
        for (wire, label) in wire_to_be_shifted
            .iter_mut()
            .zip(to_be_shifted_labels.iter())
        {
            self.commit_to_witness_polynomial(wire, label, &proving_key.crs, transcript)?;
        }
        let ordered_range_constraints_labels =
            TranslatorFlavour::get_ordered_range_constraints_labels();
        let ordered_range_constraints = proving_key
            .polynomials
            .witness
            .get_ordered_range_constraints_mut();
        for (constraint, label) in ordered_range_constraints
            .iter_mut()
            .zip(ordered_range_constraints_labels.iter())
        {
            self.commit_to_witness_polynomial(constraint, label, &proving_key.crs, transcript)?;
        }

        Ok(())
    }
    fn execute_grand_product_computation_round(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &ProvingKey<P, TranslatorFlavour>,
    ) -> HonkProofResult<()> {
        let beta = transcript.get_challenge::<P>("BETA".to_string());
        let gamma = transcript.get_challenge::<P>("GAMMA".to_string());

        self.decider.memory.relation_parameters.gamma = gamma;
        self.decider.memory.relation_parameters.beta = beta;
        const NUM_LIMB_BITS: usize = TranslatorFlavour::NUM_LIMB_BITS;

        let uint_evaluation_input_x: BigUint = self.evaluation_input_x.into();

        self.decider.memory.relation_parameters.evaluation_input_x = vec![
            (uint_evaluation_input_x.clone() & ((BigUint::from(1u32) << NUM_LIMB_BITS) - 1u32))
                .into(),
            ((uint_evaluation_input_x.clone() >> NUM_LIMB_BITS)
                & ((BigUint::from(1u32) << NUM_LIMB_BITS) - 1u32))
                .into(),
            ((uint_evaluation_input_x.clone() >> (NUM_LIMB_BITS * 2))
                & ((BigUint::from(1u32) << NUM_LIMB_BITS) - 1u32))
                .into(),
            ((uint_evaluation_input_x.clone() >> (NUM_LIMB_BITS * 3))
                & ((BigUint::from(1u32) << NUM_LIMB_BITS) - 1u32))
                .into(),
            uint_evaluation_input_x.clone().into(),
        ]
        .try_into()
        .expect("We should have 5 limbs in the evaluation input x");

        let mut uint_batching_challenge_powers: Vec<BigUint> = Vec::new();
        let batching_challenge_v: P::BaseField = self.batching_challenge_v;
        uint_batching_challenge_powers.push(batching_challenge_v.into());
        let mut running_power: P::BaseField = batching_challenge_v * batching_challenge_v;
        uint_batching_challenge_powers.push(running_power.into());
        running_power *= batching_challenge_v;
        uint_batching_challenge_powers.push(running_power.into());
        running_power *= batching_challenge_v;
        uint_batching_challenge_powers.push(running_power.into());

        self.decider.memory.relation_parameters.batching_challenge_v =
            uint_batching_challenge_powers
                .iter()
                .flat_map(|power| {
                    vec![
                        Utils::slice_u256(power, 0, NUM_LIMB_BITS as u64).into(),
                        Utils::slice_u256(power, NUM_LIMB_BITS as u64, 2 * NUM_LIMB_BITS as u64)
                            .into(),
                        Utils::slice_u256(
                            power,
                            2 * NUM_LIMB_BITS as u64,
                            3 * NUM_LIMB_BITS as u64,
                        )
                        .into(),
                        Utils::slice_u256(
                            power,
                            3 * NUM_LIMB_BITS as u64,
                            4 * NUM_LIMB_BITS as u64,
                        )
                        .into(),
                        power.clone().into(),
                    ]
                })
                .collect::<Vec<_>>()
                .try_into()
                .expect("We should have 20 batching challenge powers");

        // Compute permutation grand product and their commitments
        self.compute_grand_product(proving_key);
        // we do std::mem::take here to avoid borrowing issues with self
        let mut z_perm_tmp = std::mem::take(&mut self.memory.z_perm);
        self.commit_to_witness_polynomial(&mut z_perm_tmp, "Z_PERM", &proving_key.crs, transcript)?;
        std::mem::swap(&mut self.memory.z_perm, &mut z_perm_tmp);

        Ok(())
    }
    #[expect(clippy::type_complexity)]
    fn execute_relation_check_rounds(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        crs: &ProverCrs<P>,
        circuit_size: u32,
    ) -> HonkProofResult<(
        SumcheckOutput<P::ScalarField, TranslatorFlavour>,
        ZKSumcheckData<P>,
    )> {
        self.decider.memory.alphas =
            vec![transcript.get_challenge::<P>("Sumcheck:alpha".to_string())];
        let mut gate_challenges: Vec<P::ScalarField> =
            Vec::with_capacity(TranslatorFlavour::CONST_TRANSLATOR_LOG_N);

        for idx in 0..TranslatorFlavour::CONST_TRANSLATOR_LOG_N {
            let chall = transcript.get_challenge::<P>(format!("Sumcheck:gate_challenge_{idx}"));
            gate_challenges.push(chall);
        }
        self.decider.memory.gate_challenges = gate_challenges;
        let log_subgroup_size = UltraHonkUtils::get_msb64(P::SUBGROUP_SIZE as u64);
        let commitment_key = &crs.monomials[..1 << (log_subgroup_size + 1)];
        let mut zk_sumcheck_data: ZKSumcheckData<P> = ZKSumcheckData::<P>::new::<H, _>(
            UltraHonkUtils::get_msb64(circuit_size as u64) as usize,
            transcript,
            commitment_key,
            &mut self.decider.rng,
        )?;

        Ok((
            self.decider.sumcheck_prove_zk::<CONST_TRANSLATOR_LOG_N>(
                transcript,
                circuit_size,
                &mut zk_sumcheck_data,
                crs,
            )?,
            zk_sumcheck_data,
        ))
    }
    fn execute_pcs_rounds(
        &mut self,
        sumcheck_output: SumcheckOutput<P::ScalarField, TranslatorFlavour>,
        zk_sumcheck_data: ZKSumcheckData<P>,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        crs: &ProverCrs<P>,
        circuit_size: u32,
    ) -> HonkProofResult<()> {
        let mut small_subgroup_ipa_prover = SmallSubgroupIPAProver::<_>::new::<H>(
            zk_sumcheck_data,
            sumcheck_output
                .claimed_libra_evaluation
                .expect("We have ZK"),
            "Libra:".to_string(),
            &sumcheck_output.challenges,
        )?;
        small_subgroup_ipa_prover.prove(transcript, crs, &mut self.decider.rng)?;

        let witness_polynomials = small_subgroup_ipa_prover.into_witness_polynomials();

        let prover_opening_claim = self.decider.shplemini_prove(
            transcript,
            circuit_size,
            crs,
            sumcheck_output,
            Some(witness_polynomials),
        )?;

        compute_opening_proof(prover_opening_claim, transcript, crs)
    }

    fn compute_grand_product_numerator(
        &self,
        proving_key: &ProvingKey<P, TranslatorFlavour>,
        i: usize,
    ) -> P::ScalarField {
        tracing::trace!("compute grand product numerator");

        let interleaved_range_constraints_0 = &proving_key
            .polynomials
            .witness
            .interleaved_range_constraints_0()[i];
        let interleaved_range_constraints_1 = &proving_key
            .polynomials
            .witness
            .interleaved_range_constraints_1()[i];
        let interleaved_range_constraints_2 = &proving_key
            .polynomials
            .witness
            .interleaved_range_constraints_2()[i];
        let interleaved_range_constraints_3 = &proving_key
            .polynomials
            .witness
            .interleaved_range_constraints_3()[i];

        let ordered_extra_range_constraints_numerator = &proving_key
            .polynomials
            .precomputed
            .ordered_extra_range_constraints_numerator()[i];

        let lagrange_masking = &proving_key.polynomials.precomputed.lagrange_masking()[i];
        let gamma = &self.decider.memory.relation_parameters.gamma;
        let beta = &self.decider.memory.relation_parameters.beta;
        (*interleaved_range_constraints_0 + *lagrange_masking * beta + gamma)
            * (*interleaved_range_constraints_1 + *lagrange_masking * beta + gamma)
            * (*interleaved_range_constraints_2 + *lagrange_masking * beta + gamma)
            * (*interleaved_range_constraints_3 + *lagrange_masking * beta + gamma)
            * (*ordered_extra_range_constraints_numerator + *lagrange_masking * beta + gamma)
    }

    fn compute_grand_product_denominator(
        &self,
        proving_key: &ProvingKey<P, TranslatorFlavour>,
        i: usize,
    ) -> P::ScalarField {
        tracing::trace!("compute grand product denominator");

        let ordered_range_constraints_0 = &proving_key
            .polynomials
            .witness
            .ordered_range_constraints_0()[i];
        let ordered_range_constraints_1 = &proving_key
            .polynomials
            .witness
            .ordered_range_constraints_1()[i];
        let ordered_range_constraints_2 = &proving_key
            .polynomials
            .witness
            .ordered_range_constraints_2()[i];
        let ordered_range_constraints_3 = &proving_key
            .polynomials
            .witness
            .ordered_range_constraints_3()[i];
        let ordered_range_constraints_4 = &proving_key
            .polynomials
            .witness
            .ordered_range_constraints_4()[i];

        let lagrange_masking = &proving_key.polynomials.precomputed.lagrange_masking()[i];

        let gamma = &self.decider.memory.relation_parameters.gamma;
        let beta = &self.decider.memory.relation_parameters.beta;
        (*ordered_range_constraints_0 + *lagrange_masking * beta + gamma)
            * (*ordered_range_constraints_1 + *lagrange_masking * beta + gamma)
            * (*ordered_range_constraints_2 + *lagrange_masking * beta + gamma)
            * (*ordered_range_constraints_3 + *lagrange_masking * beta + gamma)
            * (*ordered_range_constraints_4 + *lagrange_masking * beta + gamma)
    }

    fn compute_grand_product(&mut self, proving_key: &ProvingKey<P, TranslatorFlavour>) {
        tracing::trace!("compute grand product");

        let has_active_ranges = proving_key.active_region_data.size() > 0;

        // Barretenberg uses multithreading here

        // Set the domain over which the grand product must be computed. This may be less than the dyadic circuit size, e.g
        // the permutation grand product does not need to be computed beyond the index of the last active wire
        let domain_size = proving_key.polynomials.witness.op().len();

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
            denominator.push(self.compute_grand_product_denominator(proving_key, idx));
        }

        // Step (2)
        // Compute the accumulating product of the numerator and denominator terms.
        // In Barretenberg, this is done in parallel across multiple threads, however we just do the computation singlethreaded for simplicity

        for i in 1..active_domain_size - 1 {
            numerator[i] = numerator[i] * numerator[i - 1];
            denominator[i] = denominator[i] * denominator[i - 1];
        }
        // invert denominator
        UltraHonkUtils::batch_invert(&mut denominator);

        // Step (3) Compute z_perm[i] = numerator[i] / denominator[i]
        self.memory
            .z_perm
            .resize(proving_key.circuit_size as usize, P::ScalarField::zero());

        // Compute grand product values corresponding only to the active regions of the trace
        for i in 0..active_domain_size - 1 {
            let idx = if has_active_ranges {
                proving_key.active_region_data.get_idx(i + 1)
            } else {
                i + 1
            };
            self.memory.z_perm[idx] = numerator[i] * denominator[i];
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
                        self.memory.z_perm[i] = self.memory.z_perm[next_range_start];
                        break;
                    }
                }
            }
        }
    }

    fn add_polynomials_to_memory(
        &mut self,
        polynomials: Polynomials<P::ScalarField, TranslatorFlavour>,
    ) {
        let mut memory = AllEntities::<Vec<P::ScalarField>, TranslatorFlavour>::default();

        // Copy the (non-shifted) witness polynomials
        *memory.witness.op_mut() = polynomials.witness.op().as_ref().to_vec();
        for (des, src) in izip!(
            memory.witness.get_interleaved_range_constraints_mut(),
            polynomials.witness.get_interleaved_range_constraints()
        ) {
            *des = src.as_ref().to_vec();
        }

        // Shift the witnesses
        for (des_shifted, des, src) in izip!(
            memory.shifted_witness.iter_mut(),
            memory.witness.to_be_shifted_mut(),
            polynomials
                .witness
                .into_shifted_without_z_perm()
                .chain(iter::once(self.memory.z_perm.clone())),
        ) {
            *des_shifted = src.shifted().to_vec();
            *des = src.into_vec();
        }

        // Copy precomputed polynomials
        for (des, src) in izip!(
            memory.precomputed.iter_mut(),
            polynomials.precomputed.into_iter()
        ) {
            *des = src.into_vec();
        }
        self.decider.memory.polys = memory;
    }
}
