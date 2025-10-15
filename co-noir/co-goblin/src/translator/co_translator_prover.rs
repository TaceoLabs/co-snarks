use ark_ec::CurveGroup;
use co_builder::flavours::translator_flavour::TranslatorFlavour;
use co_builder::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::ShiftedWitnessEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::WitnessEntitiesFlavour;
use co_builder::prelude::ActiveRegionData;
use co_noir_common::CoUtils;
use co_noir_common::compute_co_opening_proof;
use co_noir_common::crs::ProverCrs;
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::HonkProofResult;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_noir_common::mpc::NoirUltraHonkProver;
use co_noir_common::polynomials::polynomial::Polynomial;
use co_noir_common::transcript::Transcript;
use co_noir_common::transcript::TranscriptHasher;
use co_noir_common::transcript_mpc::TranscriptRef;
use co_noir_common::types::ZeroKnowledge;
use co_noir_common::utils::Utils;
use co_ultrahonk::prelude::AllEntities;
use co_ultrahonk::prelude::Polynomials;
use co_ultrahonk::prelude::{
    CoDecider, ProvingKey, SharedSmallSubgroupIPAProver, SharedZKSumcheckData, SumcheckOutput,
};
use itertools::Itertools;
use itertools::izip;
use mpc_core::MpcState;
use mpc_net::Network;
use num_bigint::BigUint;
use std::iter;
use ultrahonk::Utils as UltraHonkUtils;
use ultrahonk::prelude::HonkProof;

pub(crate) struct ProverMemory<T: NoirUltraHonkProver<C>, C: CurveGroup> {
    pub(crate) z_perm: Polynomial<T::ArithmeticShare>,
}

impl<T: NoirUltraHonkProver<C>, C: CurveGroup> Default for ProverMemory<T, C> {
    fn default() -> Self {
        Self {
            z_perm: Polynomial::default(),
        }
    }
}

pub struct Translator<'a, P, H, T, N>
where
    T: NoirUltraHonkProver<P>,
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType, T, P>,
    N: Network,
{
    decider: CoDecider<'a, T, P, H, N, TranslatorFlavour>, // We need the decider struct here for being able to use sumcheck, shplemini, shplonk
    memory: ProverMemory<T, P>, //This is somewhat equivalent to the Oink Memory (i.e stores the lookup_inverses and zPeccv_perm)
    batching_challenge_v: P::BaseField,
    evaluation_input_x: P::BaseField,
}

impl<'a, T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>, H, N>
    Translator<'a, P, H, T, N>
where
    H: TranscriptHasher<TranscriptFieldType, T, P>,
    N: Network,
{
    pub fn new(
        net: &'a N,
        state: &'a mut T::State,
        batching_challenge_v: P::BaseField,
        evaluation_input_x: P::BaseField,
    ) -> Self {
        Self {
            decider: CoDecider::new(net, state, Default::default(), ZeroKnowledge::Yes),
            batching_challenge_v,
            evaluation_input_x,
            memory: ProverMemory::default(),
        }
    }

    pub fn construct_proof(
        &mut self,
        mut transcript: Transcript<TranscriptFieldType, H, T, P>,
        mut proving_key: ProvingKey<T, P, TranslatorFlavour>,
        crs: &ProverCrs<P>,
    ) -> HonkProofResult<HonkProof<TranscriptFieldType>> {
        tracing::trace!("TranslatorProver::construct_proof");
        let circuit_size = proving_key.circuit_size;

        // We combine the preamble round and the wire commitments round, to batch openings.

        // Add circuit size public input size and public inputs to transcript.
        // Compute first three wire commitments
        self.execute_preamble_and_wire_and_sorted_constraints_commitments_round(
            &mut transcript,
            &mut proving_key,
            crs,
        )?;

        // Fiat-Shamir: gamma
        // Compute grand product(s) and commitments.
        self.execute_grand_product_computation_round(&mut transcript, &proving_key, crs)?;

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

    fn execute_preamble_and_wire_and_sorted_constraints_commitments_round(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H, T, P>,
        proving_key: &mut ProvingKey<T, P, TranslatorFlavour>,
        crs: &ProverCrs<P>,
    ) -> HonkProofResult<()> {
        const NUM_LIMB_BITS: usize = TranslatorFlavour::NUM_LIMB_BITS;
        let shift: BigUint = BigUint::from(1u32) << NUM_LIMB_BITS;
        let shiftx2: BigUint = BigUint::from(1u32) << (NUM_LIMB_BITS * 2);
        let shiftx3: BigUint = BigUint::from(1u32) << (NUM_LIMB_BITS * 3);
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

        let to_be_shifted_labels = TranslatorFlavour::wire_to_be_shifted_labels();
        let ordered_range_constraints_labels =
            TranslatorFlavour::get_ordered_range_constraints_labels();
        let mut commitments = Vec::with_capacity(
            1 + to_be_shifted_labels.len() + ordered_range_constraints_labels.len(),
        );
        let non_shifted_label = TranslatorFlavour::wire_non_shifted_labels();
        let wire_non_shifted_commitment = CoUtils::commit::<T, P>(
            proving_key.polynomials.witness.wire_non_shifted().as_ref(),
            crs,
        );
        commitments.push(wire_non_shifted_commitment);

        let wire_to_be_shifted = proving_key.polynomials.witness.wire_to_be_shifted();
        for wire in wire_to_be_shifted.iter() {
            let commitment = CoUtils::commit::<T, P>(wire.as_ref(), crs);
            commitments.push(commitment);
        }

        let ordered_range_constraints = proving_key
            .polynomials
            .witness
            .get_ordered_range_constraints();
        for constraint in ordered_range_constraints.iter() {
            let commitment = CoUtils::commit::<T, P>(constraint.as_ref(), crs);
            commitments.push(commitment);
        }
        let open = T::open_point_and_field_many(
            &commitments,
            &[first, second, third, fourth],
            self.decider.net,
            self.decider.state,
        )?;
        // Note: We open the limbs here, as the accumulated result (which is sent to the verifier) is computed from the limbs, meaning they would be exposed to the verifier anyway. The first three limbs should be 68 bits, the last one 50 bits, there is just the edge case where the result is larger than the scalarfield modulus.
        let first: BigUint = open.1[0].into();
        let second: BigUint = open.1[1].into();
        let third: BigUint = open.1[2].into();
        let fourth: BigUint = open.1[3].into();
        let accumulated_result: P::BaseField =
            (first + second * &shift + third * &shiftx2 + fourth * &shiftx3).into();
        self.decider.memory.relation_parameters.accumulated_result =
            vec![open.1[0], open.1[1], open.1[2], open.1[3]]
                .try_into()
                .expect("We should have 4 limbs in the result");
        transcript.send_fq_to_verifier::<P>("accumulated_result".to_string(), accumulated_result);

        for (label, commitment) in std::iter::once(&non_shifted_label)
            .chain(to_be_shifted_labels.iter())
            .chain(ordered_range_constraints_labels.iter())
            .zip(open.0.into_iter())
        {
            transcript.send_point_to_verifier::<P>(label.to_string(), commitment.into());
        }

        Ok(())
    }
    fn execute_grand_product_computation_round(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H, T, P>,
        proving_key: &ProvingKey<T, P, TranslatorFlavour>,
        crs: &ProverCrs<P>,
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

        let open = T::open_point(
            CoUtils::commit::<T, P>(self.memory.z_perm.as_ref(), crs),
            self.decider.net,
            self.decider.state,
        )?;
        transcript.send_point_to_verifier::<P>("Z_PERM".to_string(), open.into());

        Ok(())
    }

    fn execute_relation_check_rounds(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H, T, P>,
        crs: &ProverCrs<P>,
        circuit_size: u32,
    ) -> HonkProofResult<(SumcheckOutput<T, P>, SharedZKSumcheckData<T, P>)> {
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
                self.decider.net,
                self.decider.state,
            )?;

        Ok((
            self.decider
                .sumcheck_prove_zk::<{ TranslatorFlavour::CONST_TRANSLATOR_LOG_N }>(
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
        sumcheck_output: SumcheckOutput<T, P>,
        zk_sumcheck_data: SharedZKSumcheckData<T, P>,
        transcript: &mut Transcript<TranscriptFieldType, H, T, P>,
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
        small_subgroup_ipa_prover.prove::<H, N>(
            self.decider.net,
            self.decider.state,
            transcript,
            crs,
        )?;

        let witness_polynomials = small_subgroup_ipa_prover.into_witness_polynomials();
        let mut transcript_plain = TranscriptRef::Plain(transcript);
        let prover_opening_claim = self.decider.shplemini_prove(
            &mut transcript_plain,
            circuit_size,
            crs,
            sumcheck_output,
            Some(witness_polynomials),
        )?;

        compute_co_opening_proof(
            self.decider.net,
            self.decider.state,
            prover_opening_claim,
            &mut transcript_plain,
            crs,
        )
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
                    .interleaved_range_constraints_0()[idx],
                id,
            );
            let n2 = T::add_with_public(
                public[idx] * beta + gamma,
                proving_key
                    .polynomials
                    .witness
                    .interleaved_range_constraints_1()[idx],
                id,
            );
            let n3 = T::add_with_public(
                public[idx] * beta + gamma,
                proving_key
                    .polynomials
                    .witness
                    .interleaved_range_constraints_2()[idx],
                id,
            );
            let mut n4 = T::add_with_public(
                public[idx] * beta + gamma,
                proving_key
                    .polynomials
                    .witness
                    .interleaved_range_constraints_3()[idx],
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
            self.decider.net,
            self.decider.state,
            proving_key,
            &self.decider.memory.relation_parameters.beta,
            &self.decider.memory.relation_parameters.gamma,
            active_domain_size - 1,
            &proving_key.active_region_data,
        )?;

        // Step (2)
        // Compute the accumulating product of the numerator and denominator terms.

        // TACEO TODO could batch here as well
        // Do the multiplications of num[i] * num[i-1] and den[i] * den[i-1] in constant rounds
        let numerator =
            CoUtils::array_prod_mul::<T, P, N>(self.decider.net, self.decider.state, &numerator)?;
        let mut denominator =
            CoUtils::array_prod_mul::<T, P, N>(self.decider.net, self.decider.state, &denominator)?;

        // invert denominator
        CoUtils::batch_invert::<T, P, N>(&mut denominator, self.decider.net, self.decider.state)?;

        // Step (3) Compute z_perm[i] = numerator[i] / denominator[i]
        let mul = T::mul_many(
            &numerator,
            &denominator,
            self.decider.net,
            self.decider.state,
        )?;

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
