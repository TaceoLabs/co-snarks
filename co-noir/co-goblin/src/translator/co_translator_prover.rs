use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_ff::{One, Zero};
use co_builder::flavours::translator_flavour::TranslatorFlavour;
use co_builder::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::ShiftedWitnessEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::WitnessEntitiesFlavour;
use co_builder::prelude::{ActiveRegionData, Utils};
use co_builder::{
    HonkProofResult, TranscriptFieldType,
    flavours::eccvm_flavour::ECCVMFlavour,
    prelude::{HonkCurve, NUM_DISABLED_ROWS_IN_SUMCHECK, Polynomial, ProverCrs},
};
use co_ultrahonk::prelude::AllEntities;
use co_ultrahonk::prelude::Polynomials;
use co_ultrahonk::prelude::{
    CoDecider, ProvingKey, SharedSmallSubgroupIPAProver, SharedZKSumcheckData, SumcheckOutput,
};
use common::co_shplemini::OpeningPair;
use common::shared_polynomial::SharedPolynomial;
use common::{CoUtils, compute_co_opening_proof};
use common::{
    HonkProof,
    co_shplemini::ShpleminiOpeningClaim,
    mpc::NoirUltraHonkProver,
    transcript::{Transcript, TranscriptHasher},
};
use itertools::Itertools;
use itertools::izip;
use mpc_core::MpcState;
use mpc_net::Network;
use num_bigint::BigUint;
use std::iter;
use ultrahonk::{NUM_SMALL_IPA_EVALUATIONS, Utils as UltraHonkUtils};

#[derive(Default)]
pub(crate) struct ProverMemory<T: NoirUltraHonkProver<C>, C: CurveGroup> {
    pub(crate) z_perm: Polynomial<T::ArithmeticShare>,
}

// pub struct Translator<P: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>> {
//     decider: Decider<P, H, TranslatorFlavour>,
//     batching_challenge_v: P::BaseField,
//     evaluation_input_x: P::BaseField,
//     memory: ProverMemory<P>, //This is somewhat equivalent to the Oink Memory (i.e stores the lookup_inverses and z_perm)
// }

pub struct Translator<'a, P, H, T, N>
where
    T: NoirUltraHonkProver<P>,
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    N: Network,
{
    net: &'a N,
    state: &'a mut T::State,
    decider: CoDecider<'a, T, P, H, N, TranslatorFlavour>, // We need the decider struct here for being able to use sumcheck, shplemini, shplonk
    memory: ProverMemory<T, P>, //This is somewhat equivalent to the Oink Memory (i.e stores the lookup_inverses and zPeccv_perm)
    batching_challenge_v: P::BaseField,
    evaluation_input_x: P::BaseField,
}

impl<'a, T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>, H, N>
    Translator<'a, P, H, T, N>
where
    H: TranscriptHasher<TranscriptFieldType>,
    N: Network,
{
    pub(crate) fn new(
        net: &'a N,
        state: &'a mut T::State,
        decider: CoDecider<'a, T, P, H, N, TranslatorFlavour>,
        memory: ProverMemory<T, P>,
        batching_challenge_v: P::BaseField,
        evaluation_input_x: P::BaseField,
    ) -> Self {
        Self {
            decider,
            batching_challenge_v,
            evaluation_input_x,
            memory,
            net,
            state,
        }
    }

    pub fn construct_proof(
        &mut self,
        mut transcript: Transcript<TranscriptFieldType, H>,
        mut proving_key: ProvingKey<T, P, TranslatorFlavour>,
        crs: &ProverCrs<P>,
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
            self.execute_relation_check_rounds(&mut transcript, crs, circuit_size)?;

        // Fiat-Shamir: rho, y, x, z
        // Execute Shplemini PCS
        self.execute_pcs_rounds(
            sumcheck_output,
            zk_sumcheck_data,
            &mut transcript,
            crs,
            circuit_size,
        )?;
        Ok(transcript.get_proof())
    }

    fn execute_preamble_round(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &mut ProvingKey<T, P, TranslatorFlavour>,
    ) -> HonkProofResult<()> {
        const NUM_LIMB_BITS: usize = TranslatorFlavour::NUM_LIMB_BITS;
        // let shift: P::ScalarField = (BigUint::from(1u32) << NUM_LIMB_BITS).into();
        // let shiftx2: P::ScalarField = (BigUint::from(1u32) << (NUM_LIMB_BITS * 2)).into();
        // let shiftx3: P::ScalarField = (BigUint::from(1u32) << (NUM_LIMB_BITS * 3)).into();
        const RESULT_ROW: usize = TranslatorFlavour::RESULT_ROW;

        let first = proving_key
            .polynomials
            .witness
            .accumulators_binary_limbs_0()[RESULT_ROW];
        let second = proving_key
            .polynomials
            .witness
            .accumulators_binary_limbs_1()[RESULT_ROW];
        let third = proving_key
            .polynomials
            .witness
            .accumulators_binary_limbs_2()[RESULT_ROW];
        let fourth = proving_key
            .polynomials
            .witness
            .accumulators_binary_limbs_3()[RESULT_ROW];

        let accumulated_result = T::accumulate_limbs_for_translator(
            &[first, second, third, fourth],
            NUM_LIMB_BITS,
            self.state,
            self.net,
        );

        //TODO FLORIN
        // self.decider.memory.relation_parameters.accumulated_result = vec![
        //     proving_key
        //         .polynomials
        //         .witness
        //         .accumulators_binary_limbs_0()[RESULT_ROW],
        //     proving_key
        //         .polynomials
        //         .witness
        //         .accumulators_binary_limbs_1()[RESULT_ROW],
        //     proving_key
        //         .polynomials
        //         .witness
        //         .accumulators_binary_limbs_2()[RESULT_ROW],
        //     proving_key
        //         .polynomials
        //         .witness
        //         .accumulators_binary_limbs_3()[RESULT_ROW],
        // ]
        // .try_into()
        // .expect("We should have 4 limbs in the result");

        transcript.send_fq_to_verifier::<P>("accumulated_result".to_string(), accumulated_result);
        Ok(())
    }

    fn execute_wire_and_sorted_constraints_commitments_round(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &mut ProvingKey<T, P, TranslatorFlavour>,
    ) -> HonkProofResult<()> {
        let non_shifted_label = TranslatorFlavour::wire_non_shifted_labels();
        let wire_non_shifted = proving_key.polynomials.witness.wire_non_shifted_mut();
        // self.commit_to_witness_polynomial(
        //     wire_non_shifted,
        //     non_shifted_label,
        //     &proving_key.crs,
        //     transcript,
        // )?;

        let to_be_shifted_labels = TranslatorFlavour::wire_to_be_shifted_labels();
        let wire_to_be_shifted = proving_key.polynomials.witness.wire_to_be_shifted_mut();
        for (wire, label) in wire_to_be_shifted
            .iter_mut()
            .zip(to_be_shifted_labels.iter())
        {
            // self.commit_to_witness_polynomial(wire, label, &proving_key.crs, transcript)?;
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
            // self.commit_to_witness_polynomial(constraint, label, &proving_key.crs, transcript)?;
        }

        Ok(())
    }
    fn execute_grand_product_computation_round(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &ProvingKey<T, P, TranslatorFlavour>,
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
        self.compute_grand_product(proving_key)?;
        // we do std::mem::take here to avoid borrowing issues with self
        let mut z_perm_tmp = std::mem::take(&mut self.memory.z_perm);
        // self.commit_to_witness_polynomial(&mut z_perm_tmp, "Z_PERM", &proving_key.crs, transcript)?;
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
        SharedZKSumcheckData<T, P>,
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
        let mut zk_sumcheck_data: SharedZKSumcheckData<T, P> =
            SharedZKSumcheckData::<T, P>::new::<H, _>(
                UltraHonkUtils::get_msb64(circuit_size as u64) as usize,
                transcript,
                commitment_key,
                self.net,
                self.state,
            )?;

        Ok((
            self.decider
                .sumcheck_prove_zk::<{ TranslatorFlavour::CONST_TRANSLATOR_LOG_N }>(
                    transcript,
                    circuit_size,
                    &mut zk_sumcheck_data,
                )?,
            zk_sumcheck_data,
        ))
    }
    fn execute_pcs_rounds(
        &mut self,
        sumcheck_output: SumcheckOutput<P::ScalarField, TranslatorFlavour>,
        zk_sumcheck_data: SharedZKSumcheckData<T, P>,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        crs: &ProverCrs<P>,
        circuit_size: u32,
    ) -> HonkProofResult<()> {
        let mut small_subgroup_ipa_prover = SharedSmallSubgroupIPAProver::<_, _>::new(
            zk_sumcheck_data,
            sumcheck_output
                .claimed_libra_evaluation
                .expect("We have ZK"),
            "Libra:".to_string(),
            &sumcheck_output.challenges,
        )?;
        small_subgroup_ipa_prover.prove::<H, N>(self.net, self.state, transcript, crs)?;

        let witness_polynomials = small_subgroup_ipa_prover.into_witness_polynomials();

        let prover_opening_claim = self.decider.shplemini_prove(
            transcript,
            circuit_size,
            crs,
            sumcheck_output,
            Some(witness_polynomials),
        )?;

        compute_co_opening_proof(self.net, self.state, prover_opening_claim, transcript, crs)
    }

    #[expect(clippy::type_complexity)]
    fn batched_grand_product_num_denom(
        net: &N,
        state: &mut T::State,
        proving_key: &ProvingKey<T, P, TranslatorFlavour>,
        beta: &P::ScalarField,
        gamma: &P::ScalarField,
        output_len: usize,
        active_region_data: &ActiveRegionData,
    ) -> HonkProofResult<(Vec<T::ArithmeticShare>, Vec<T::ArithmeticShare>)> {
        tracing::trace!("compute grand product numerator");

        let has_active_ranges = active_region_data.size() > 0;

        // We drop the last element since it is not needed for the grand product
        let mut mul1_num = Vec::with_capacity(output_len);
        let mut mul2_num = Vec::with_capacity(output_len);
        let mut mul3_num = Vec::with_capacity(output_len);
        let mut mul4_num = Vec::with_capacity(output_len);
        let mut mul1_denom = Vec::with_capacity(output_len);
        let mut mul2_denom = Vec::with_capacity(output_len);
        let mut mul3_denom = Vec::with_capacity(output_len);
        let mut mul4_denom = Vec::with_capacity(output_len);
        let mut mul5_denom = Vec::with_capacity(output_len);

        let public = proving_key.polynomials.precomputed.lagrange_masking();
        let ordered_extra_range_constraints_numerator = proving_key
            .polynomials
            .precomputed
            .ordered_extra_range_constraints_numerator();

        for i in 0..output_len {
            let idx = if has_active_ranges {
                active_region_data.get_idx(i)
            } else {
                i
            };
            let id = state.id();
            let n1 = T::add_with_public(
                public[idx] * beta + gamma,
                proving_key
                    .polynomials
                    .witness
                    .ordered_range_constraints_0()[idx],
                id,
            );
            let n2 = T::add_with_public(
                public[idx] * beta + gamma,
                proving_key
                    .polynomials
                    .witness
                    .ordered_range_constraints_1()[idx],
                id,
            );
            let n3 = T::add_with_public(
                public[idx] * beta + gamma,
                proving_key
                    .polynomials
                    .witness
                    .ordered_range_constraints_2()[idx],
                id,
            );
            let mut n4 = T::add_with_public(
                public[idx] * beta + gamma,
                proving_key
                    .polynomials
                    .witness
                    .ordered_range_constraints_3()[idx],
                id,
            );
            T::mul_assign_with_public(
                &mut n4,
                ordered_extra_range_constraints_numerator[idx] + public[idx] * beta + gamma,
            );
            mul1_num.push(n1);
            mul2_num.push(n2);
            mul3_num.push(n3);
            mul4_num.push(n4);
            let d1 = T::add_with_public(
                public[idx] * beta + gamma,
                proving_key
                    .polynomials
                    .witness
                    .ordered_range_constraints_0()[idx],
                id,
            );
            let d2 = T::add_with_public(
                public[idx] * beta + gamma,
                proving_key
                    .polynomials
                    .witness
                    .ordered_range_constraints_1()[idx],
                id,
            );
            let d3 = T::add_with_public(
                public[idx] * beta + gamma,
                proving_key
                    .polynomials
                    .witness
                    .ordered_range_constraints_2()[idx],
                id,
            );
            let d4 = T::add_with_public(
                public[idx] * beta + gamma,
                proving_key
                    .polynomials
                    .witness
                    .ordered_range_constraints_3()[idx],
                id,
            );
            let d5 = T::add_with_public(
                public[idx] * beta + gamma,
                proving_key
                    .polynomials
                    .witness
                    .ordered_range_constraints_4()[idx],
                id,
            );
            mul1_denom.push(d1);
            mul2_denom.push(d2);
            mul3_denom.push(d3);
            mul4_denom.push(d4);
            mul5_denom.push(d5);
        }
        let mul = T::mul_many(
            &[mul1_num, mul3_num, mul1_denom, mul3_denom].concat(),
            &[mul2_num, mul4_num, mul2_denom, mul4_denom].concat(),
            net,
            state,
        )?;
        let mul = mul.chunks_exact(mul.len() / 4).collect_vec();
        debug_assert_eq!(mul.len(), 4);

        let mul = T::mul_many(
            &[mul[0], mul[2]].concat(),
            &[mul[1], mul[3]].concat(),
            net,
            state,
        )?;
        let mul = mul.chunks_exact(mul.len() / 2).collect_vec();
        debug_assert_eq!(mul.len(), 2);
        let numerator = mul[0];
        let denominator = T::mul_many(&mul5_denom, mul[1], net, state)?;
        Ok((numerator.to_vec(), denominator))
    }

    // To reduce the number of communication rounds, we implement the array_prod_mul macro according to https://www.usenix.org/system/files/sec22-ozdemir.pdf, p11 first paragraph.
    //TODO FLORIN: Deduplicate with common
    fn array_prod_mul(
        &mut self,
        inp: &[T::ArithmeticShare],
    ) -> HonkProofResult<Vec<T::ArithmeticShare>> {
        // Do the multiplications of inp[i] * inp[i-1] in constant rounds
        let len = inp.len();

        let r = (0..=len)
            .map(|_| T::rand(self.net, self.state))
            .collect::<Result<Vec<_>, _>>()?;
        let r_inv = T::inv_many(&r, self.net, self.state)?;
        let r_inv0 = vec![r_inv[0]; len];

        let mut unblind = T::mul_many(&r_inv0, &r[1..], self.net, self.state)?;

        let mul = T::mul_many(&r[..len], inp, self.net, self.state)?;
        let mut open = T::mul_open_many(&mul, &r_inv[1..], self.net, self.state)?;

        for i in 1..open.len() {
            open[i] = open[i] * open[i - 1];
        }

        for (unblind, open) in unblind.iter_mut().zip(open.iter()) {
            *unblind = T::mul_with_public(*open, *unblind);
        }
        Ok(unblind)
    }

    fn compute_grand_product(
        &mut self,
        proving_key: &ProvingKey<T, P, TranslatorFlavour>,
    ) -> HonkProofResult<()> {
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
        // Step (1)
        // Populate `numerator` and `denominator` with the algebra described by Relation

        let (numerator, denominator) = Self::batched_grand_product_num_denom(
            self.net,
            self.state,
            proving_key,
            &self.decider.memory.relation_parameters.beta,
            &self.decider.memory.relation_parameters.gamma,
            active_domain_size - 1,
            &proving_key.active_region_data,
        )?;

        // Step (2)
        // Compute the accumulating product of the numerator and denominator terms.
        // In Barretenberg, this is done in parallel across multiple threads, however we just do the computation singlethreaded for simplicity

        let numerator = self.array_prod_mul(&numerator)?;
        let mut denominator = self.array_prod_mul(&denominator)?;

        // invert denominator
        CoUtils::batch_invert::<T, P, N>(&mut denominator, self.net, self.state)?;

        // Step (3) Compute z_perm[i] = numerator[i] / denominator[i]
        let mul = T::mul_many(&numerator, &denominator, self.net, self.state)?;

        self.memory.z_perm.resize(
            proving_key.circuit_size as usize,
            T::ArithmeticShare::default(),
        );

        // Compute grand product values corresponding only to the active regions of the trace
        for (i, mul) in mul.into_iter().enumerate() {
            let idx = if has_active_ranges {
                proving_key.active_region_data.get_idx(i + 1)
            } else {
                i + 1
            };
            self.memory.z_perm[idx] = mul
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

        Ok(())
    }

    fn add_polynomials_to_memory(
        &mut self,
        polynomials: Polynomials<T::ArithmeticShare, P::ScalarField, TranslatorFlavour>,
    ) {
        let mut memory = AllEntities::<
            Vec<T::ArithmeticShare>,
            Vec<P::ScalarField>,
            TranslatorFlavour,
        >::default();

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
