use crate::eccvm::co_eccvm_types::SharedTranslationData;
use crate::ipa::compute_ipa_opening_proof;
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_ff::{One, Zero};
use co_builder::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::ShiftedWitnessEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::WitnessEntitiesFlavour;
use co_builder::{
    HonkProofResult, TranscriptFieldType,
    flavours::eccvm_flavour::ECCVMFlavour,
    prelude::{HonkCurve, NUM_DISABLED_ROWS_IN_SUMCHECK, Polynomial, ProverCrs},
};
use co_ultrahonk::prelude::AllEntities;
use co_ultrahonk::prelude::Polynomials;
use co_ultrahonk::prelude::ZeroKnowledge;
use co_ultrahonk::prelude::{
    CoDecider, ProvingKey, SharedSmallSubgroupIPAProver, SharedZKSumcheckData, SumcheckOutput,
};
use common::CoUtils;
use common::co_shplemini::OpeningPair;
use common::shared_polynomial::SharedPolynomial;
use common::{CONST_ECCVM_LOG_N, NUM_OPENING_CLAIMS};
use common::{
    co_shplemini::ShpleminiOpeningClaim,
    mpc::NoirUltraHonkProver,
    transcript::{Transcript, TranscriptHasher},
};
use itertools::Itertools;
use itertools::izip;
use mpc_core::MpcState;
use mpc_net::Network;
use std::iter;
use ultrahonk::prelude::HonkProof;
use ultrahonk::{NUM_SMALL_IPA_EVALUATIONS, Utils as UltraHonkUtils};

pub(crate) struct ProverMemory<T: NoirUltraHonkProver<C>, C: CurveGroup> {
    pub(crate) z_perm: Polynomial<T::ArithmeticShare>,
    pub(crate) lookup_inverses: Polynomial<T::ArithmeticShare>,
    pub(crate) opening_claims: [ShpleminiOpeningClaim<T, C>; NUM_OPENING_CLAIMS],
}
impl<T: NoirUltraHonkProver<C>, C: CurveGroup> Default for ProverMemory<T, C> {
    fn default() -> Self {
        Self {
            z_perm: Polynomial::default(),
            lookup_inverses: Polynomial::default(),
            opening_claims: core::array::from_fn(|_| ShpleminiOpeningClaim::default()),
        }
    }
}

pub struct Eccvm<'a, P, H, T, N>
where
    T: NoirUltraHonkProver<P>,
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    N: Network,
{
    decider: CoDecider<'a, T, P, H, N, ECCVMFlavour>, // We need the decider struct here for being able to use sumcheck, shplemini, shplonk
    memory: ProverMemory<T, P>, //This is somewhat equivalent to the Oink Memory (i.e stores the lookup_inverses and zPeccv_perm)
}

impl<'a, T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>, H, N> Eccvm<'a, P, H, T, N>
where
    H: TranscriptHasher<TranscriptFieldType>,
    N: Network,
{
    pub fn new(net: &'a N, state: &'a mut T::State) -> Self {
        Self {
            // net,
            // state,
            decider: CoDecider::new(net, state, Default::default(), ZeroKnowledge::Yes),
            memory: ProverMemory::default(),
        }
    }

    pub fn construct_proof(
        &mut self,
        mut transcript: Transcript<TranscriptFieldType, H>,
        mut proving_key: ProvingKey<T, P, ECCVMFlavour>,
        crs: &ProverCrs<P>,
    ) -> HonkProofResult<(
        HonkProof<TranscriptFieldType>,
        HonkProof<TranscriptFieldType>,
    )> {
        let circuit_size = proving_key.circuit_size;
        let unmasked_witness_size = (circuit_size - NUM_DISABLED_ROWS_IN_SUMCHECK) as usize;
        let start = std::time::Instant::now();
        self.execute_wire_commitments_round(&mut transcript, &mut proving_key, crs)?;
        println!(
            "Time for wire commitment round: {:?}",
            std::time::Instant::now() - start
        );
        let start = std::time::Instant::now();
        self.execute_log_derivative_commitments_round(
            &mut transcript,
            &proving_key,
            unmasked_witness_size,
        )?;
        println!(
            "Time for log derivative commitment round: {:?}",
            std::time::Instant::now() - start
        );
        let start = std::time::Instant::now();
        self.execute_grand_product_computation_round(
            &mut transcript,
            &proving_key,
            unmasked_witness_size,
            crs,
        )?;
        println!(
            "Time for grand product computation round: {:?}",
            std::time::Instant::now() - start
        );
        self.add_polynomials_to_memory(proving_key.polynomials);
        let start = std::time::Instant::now();
        let (sumcheck_output, zk_sumcheck_data) =
            self.execute_relation_check_rounds(&mut transcript, crs, circuit_size)?;
        println!(
            "Time for relation check rounds: {:?}",
            std::time::Instant::now() - start
        );
        let start = std::time::Instant::now();
        let ipa_transcript = self.execute_pcs_rounds(
            sumcheck_output,
            zk_sumcheck_data,
            &mut transcript,
            crs,
            circuit_size,
        )?;
        println!(
            "Time for PCS rounds: {:?}",
            std::time::Instant::now() - start
        );

        Ok((transcript.get_proof(), ipa_transcript.get_proof()))
    }
    fn execute_wire_commitments_round(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &mut ProvingKey<T, P, ECCVMFlavour>,
        crs: &ProverCrs<P>,
    ) -> HonkProofResult<()> {
        let non_shifted = proving_key.polynomials.witness.non_shifted_mut();
        let first_labels = ECCVMFlavour::non_shifted_labels();
        let second_labels = ECCVMFlavour::to_be_shifted_without_accumulators_labels();
        let third_labels = ECCVMFlavour::to_be_shifted_accumulators_labels();

        let mut commitments =
            Vec::with_capacity(first_labels.len() + second_labels.len() + third_labels.len());
        for wire in non_shifted.iter_mut() {
            CoUtils::mask_polynomial::<T, P, N>(self.decider.net, self.decider.state, wire)?;
            commitments.push(CoUtils::commit::<T, P>(wire.as_ref(), crs));
        }
        let to_be_shifted_without_accumulators = proving_key
            .polynomials
            .witness
            .to_be_shifted_without_accumulators_mut();
        for wire in to_be_shifted_without_accumulators.iter_mut() {
            CoUtils::mask_polynomial::<T, P, N>(self.decider.net, self.decider.state, wire)?;
            commitments.push(CoUtils::commit::<T, P>(wire.as_ref(), crs));
        }
        let to_be_shifted_accumulators = proving_key
            .polynomials
            .witness
            .to_be_shifted_accumulators_mut();
        for wire in to_be_shifted_accumulators.iter_mut() {
            CoUtils::mask_polynomial::<T, P, N>(self.decider.net, self.decider.state, wire)?;
            commitments.push(CoUtils::commit::<T, P>(wire.as_ref(), crs));
        }
        let open = T::open_point_many(&commitments, self.decider.net, self.decider.state)?;
        for (label, commitment) in first_labels
            .iter()
            .chain(second_labels.iter())
            .chain(third_labels.iter())
            .zip(open.into_iter())
        {
            transcript.send_point_to_verifier::<P>(label.to_string(), commitment.into());
        }
        Ok(())
    }

    fn compute_read_term(
        &self,
        proving_key: &ProvingKey<T, P, ECCVMFlavour>,
        i: usize,
        read_index: usize,
    ) -> T::ArithmeticShare {
        tracing::trace!("compute read term");
        let id = self.decider.state.id();

        // read term:
        // pc, slice, x, y
        // static_assert(read_index < READ_TERMS);
        let gamma = &self.decider.memory.relation_parameters.gamma;
        let beta = &self.decider.memory.relation_parameters.beta;
        let beta_sqr = &self.decider.memory.relation_parameters.beta_sqr;
        let beta_cube = &self.decider.memory.relation_parameters.beta_cube;
        let msm_pc = &proving_key.polynomials.witness.msm_pc()[i];
        let msm_count = &proving_key.polynomials.witness.msm_count()[i];
        let msm_slice1 = &proving_key.polynomials.witness.msm_slice1()[i];
        let msm_slice2 = &proving_key.polynomials.witness.msm_slice2()[i];
        let msm_slice3 = &proving_key.polynomials.witness.msm_slice3()[i];
        let msm_slice4 = &proving_key.polynomials.witness.msm_slice4()[i];
        let msm_x1 = &proving_key.polynomials.witness.msm_x1()[i];
        let msm_x2 = &proving_key.polynomials.witness.msm_x2()[i];
        let msm_x3 = &proving_key.polynomials.witness.msm_x3()[i];
        let msm_x4 = &proving_key.polynomials.witness.msm_x4()[i];
        let msm_y1 = &proving_key.polynomials.witness.msm_y1()[i];
        let msm_y2 = &proving_key.polynomials.witness.msm_y2()[i];
        let msm_y3 = &proving_key.polynomials.witness.msm_y3()[i];
        let msm_y4 = &proving_key.polynomials.witness.msm_y4()[i];

        // how do we get pc value
        // row pc = value of pc after msm
        // row count = num processed points in round
        // size_of_msm = msm_size
        // value of pc at start of msm = msm_pc - msm_size_of_msm
        // value of current pc = msm_pc - msm_size_of_msm + msm_count + (0,1,2,3)
        let current_pc = T::sub(*msm_pc, *msm_count);

        match read_index {
            0 => {
                let mut tmp = current_pc;
                T::add_assign_public(&mut tmp, *gamma, id);
                T::add_assign(&mut tmp, T::mul_with_public(*beta, *msm_slice1));
                T::add_assign(&mut tmp, T::mul_with_public(*beta_sqr, *msm_x1));
                T::add_assign(&mut tmp, T::mul_with_public(*beta_cube, *msm_y1));
                tmp
            } // degree 1
            1 => {
                let mut tmp = current_pc;
                T::add_assign_public(&mut tmp, -P::ScalarField::from(1), id);
                T::add_assign_public(&mut tmp, *gamma, id);
                T::add_assign(&mut tmp, T::mul_with_public(*beta, *msm_slice2));
                T::add_assign(&mut tmp, T::mul_with_public(*beta_sqr, *msm_x2));
                T::add_assign(&mut tmp, T::mul_with_public(*beta_cube, *msm_y2));
                tmp
            } // degree 1
            2 => {
                let mut tmp = current_pc;
                T::add_assign_public(&mut tmp, -P::ScalarField::from(2), id);
                T::add_assign_public(&mut tmp, *gamma, id);
                T::add_assign(&mut tmp, T::mul_with_public(*beta, *msm_slice3));
                T::add_assign(&mut tmp, T::mul_with_public(*beta_sqr, *msm_x3));
                T::add_assign(&mut tmp, T::mul_with_public(*beta_cube, *msm_y3));
                tmp
            } // degree 1
            3 => {
                let mut tmp = current_pc;
                T::add_assign_public(&mut tmp, -P::ScalarField::from(3), id);
                T::add_assign_public(&mut tmp, *gamma, id);
                T::add_assign(&mut tmp, T::mul_with_public(*beta, *msm_slice4));
                T::add_assign(&mut tmp, T::mul_with_public(*beta_sqr, *msm_x4));
                T::add_assign(&mut tmp, T::mul_with_public(*beta_cube, *msm_y4));
                tmp
            } // degree 1
            _ => panic!("Invalid read index: {read_index}"),
        }
    }

    fn compute_write_term(
        &self,
        proving_key: &ProvingKey<T, P, ECCVMFlavour>,
        i: usize,
        write_idx: usize,
    ) -> T::ArithmeticShare {
        tracing::trace!("compute write term");
        let id = self.decider.state.id();

        // what are we looking up?
        // we want to map:
        // 1: point pc
        // 2: point slice
        // 3: point x
        // 4: point y
        // for each point in our point table, we want to map `slice` to (x, -y) AND `slice + 8` to (x, y)

        // round starts at 0 and increments to 7
        // point starts at 15[P] and decrements to [P]
        // a slice value of 0 maps to -15[P]
        // 1 -> -13[P]
        // 7 -> -[P]
        // 8 -> P
        // 15 -> 15[P]
        // negative points map pc, round, x, -y
        // positive points map pc, 15 - (round * 2), x, y
        let precompute_pc = &proving_key.polynomials.witness.precompute_pc()[i];
        let tx = &proving_key.polynomials.witness.precompute_tx()[i];
        let ty = &proving_key.polynomials.witness.precompute_ty()[i];
        let precompute_round = &proving_key.polynomials.witness.precompute_round()[i];
        let gamma = &self.decider.memory.relation_parameters.gamma;
        let beta = &self.decider.memory.relation_parameters.beta;
        let beta_sqr = &self.decider.memory.relation_parameters.beta_sqr;
        let beta_cube = &self.decider.memory.relation_parameters.beta_cube;

        // slice value : (wnaf value) : lookup term
        // 0 : -15 : 0
        // 1 : -13 : 1
        // 7 : -1 : 7
        // 8 : 1 : 0
        // 9 : 3 : 1
        // 15 : 15 : 7

        // slice value : negative term : positive term
        // 0 : 0 : 7
        // 1 : 1 : 6
        // 2 : 2 : 5
        // 3 : 3 : 4
        // 7 : 7 : 0

        // | 0 | 15[P].x | 15[P].y  | 0, -15[P].x, -15[P].y | 15, 15[P].x, 15[P].y |
        // | 1 | 13[P].x | 13[P].y | 1, -13[P].x, -13[P].y | 14, 13[P].x, 13[P].y
        // | 2 | 11[P].x | 11[P].y
        // | 3 |  9[P].x |  9[P].y
        // | 4 |  7[P].x |  7[P].y
        // | 5 |  5[P].x |  5[P].y
        // | 6 |  3[P].x |  3[P].y
        // | 7 |  1[P].x |  1[P].y | 7, -[P].x, -[P].y | 8 , [P].x, [P].y |

        match write_idx {
            0 => {
                let mut positive_slice_value = *precompute_round; //-*precompute_round + P::ScalarField::from(15);
                T::mul_assign_with_public(&mut positive_slice_value, -P::ScalarField::one());
                T::add_assign_public(&mut positive_slice_value, P::ScalarField::from(15), id);
                T::mul_assign_with_public(&mut positive_slice_value, *beta);
                T::add_assign(&mut positive_slice_value, *precompute_pc);
                T::add_assign(
                    &mut positive_slice_value,
                    T::mul_with_public(*beta_sqr, *tx),
                );
                T::add_assign_public(&mut positive_slice_value, *gamma, id);
                T::add_assign(
                    &mut positive_slice_value,
                    T::mul_with_public(*beta_cube, *ty),
                );
                positive_slice_value
            }
            1 => {
                let mut tmp = *precompute_pc;
                T::add_assign_public(&mut tmp, *gamma, id);
                T::add_assign(&mut tmp, T::mul_with_public(*beta, *precompute_round));
                T::add_assign(&mut tmp, T::mul_with_public(*beta_sqr, *tx));
                T::add_assign(&mut tmp, T::mul_with_public(-*beta_cube, *ty));
                tmp
            } // degree 1
            _ => panic!("Invalid write index: {write_idx}"),
        }
    }

    fn compute_logderivative_inverses(
        &mut self,
        proving_key: &ProvingKey<T, P, ECCVMFlavour>,
        circuit_size: usize,
    ) -> HonkProofResult<()> {
        tracing::trace!("compute logderivative inverse");

        debug_assert_eq!(
            proving_key.polynomials.witness.msm_add().len(),
            proving_key.circuit_size as usize
        );
        debug_assert_eq!(
            proving_key.polynomials.witness.msm_skew().len(),
            proving_key.circuit_size as usize
        );
        debug_assert_eq!(
            proving_key.polynomials.witness.precompute_select().len(),
            proving_key.circuit_size as usize
        );
        self.memory
            .lookup_inverses
            .resize(circuit_size, T::ArithmeticShare::default());

        // 1 + polynomial degree of this relation
        // const LENGTH: usize = 5; // both subrelations are degree 4

        let a = &proving_key.polynomials.witness.msm_add().coefficients[..circuit_size];
        let b = &proving_key.polynomials.witness.msm_skew().coefficients[..circuit_size];
        let c = &proving_key
            .polynomials
            .witness
            .precompute_select()
            .coefficients[..circuit_size];
        let mut lhs = Vec::with_capacity(a.len() + b.len() + c.len());
        let mut rhs = Vec::with_capacity(lhs.len());
        lhs.extend(a.to_owned());
        rhs.extend(b.to_owned());
        lhs.extend(a.to_owned());
        rhs.extend(c.to_owned());
        lhs.extend(b.to_owned());
        rhs.extend(c.to_owned());
        let mul = T::mul_many(&lhs, &rhs, self.decider.net, self.decider.state)?;
        let mul = mul.chunks_exact(mul.len() / 3).collect_vec();
        debug_assert_eq!(mul.len(), 3);
        let ab = mul[0];
        let ac = mul[1];
        let bc = mul[2];
        let abc = T::mul_many(ab, c, self.decider.net, self.decider.state)?; //TACEO TODO: If really necessary we can batch this multiplication into 'array_prod_inner_mul_many'

        let mut read_and_write_tag = T::sub_many(&abc, ab);
        T::sub_assign_many(&mut read_and_write_tag, ac);
        T::add_assign_many(&mut read_and_write_tag, a);
        T::sub_assign_many(&mut read_and_write_tag, bc);
        T::add_assign_many(&mut read_and_write_tag, b);
        T::add_assign_many(&mut read_and_write_tag, c);

        let mut denominator_to_mul = Vec::with_capacity(circuit_size);

        for i in 0..circuit_size {
            // The following check cannot easily be done since the values are shared. We prepare the read_and_write_tag instead and multiply it later to self.memory.lookup_inverses.
            // (row.msm_add == 1) || (row.msm_skew == 1) || (row.precompute_select == 1)
            // if !(msm_add.is_one() || msm_skew.is_one() || precompute_select.is_one()) {
            //     continue;
            // }

            let read_terms = 4;
            let write_terms = 2;
            let mut tmp = Vec::with_capacity(read_terms + write_terms);
            for read_idx in 0..read_terms {
                tmp.push(self.compute_read_term(proving_key, i, read_idx));
            }
            for write_idx in 0..write_terms {
                tmp.push(self.compute_write_term(proving_key, i, write_idx));
            }
            denominator_to_mul.push(tmp);
        }

        let result = CoUtils::array_prod_inner_mul_many::<T, P, N>(
            self.decider.net,
            self.decider.state,
            &denominator_to_mul,
        )?;

        self.memory
            .lookup_inverses
            .iter_mut()
            .zip(result.iter())
            .for_each(|(lookup_inverse, row_result)| {
                // We only need the last element since this is all previous read and write terms multiplied together.
                *lookup_inverse = *row_result.last().unwrap();
            });

        // Compute inverse polynomial I in place by inverting the product at each row
        // Note: zeroes are ignored as they are not used anyway
        CoUtils::batch_invert_or_zero_many::<T, P, N>(
            self.memory.lookup_inverses.as_mut(),
            self.decider.net,
            self.decider.state,
        )?;
        //We still need to muliply it with the read_and_write_tag
        self.memory.lookup_inverses = Polynomial::new(T::mul_many(
            self.memory.lookup_inverses.as_ref(),
            &read_and_write_tag,
            self.decider.net,
            self.decider.state,
        )?);
        self.memory.lookup_inverses.resize(
            proving_key.circuit_size as usize,
            T::ArithmeticShare::default(),
        );
        Ok(())
    }

    fn execute_log_derivative_commitments_round(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &ProvingKey<T, P, ECCVMFlavour>,
        unmasked_witness_size: usize,
    ) -> HonkProofResult<()> {
        // Compute and add beta to relation parameters
        let challs = transcript.get_challenges::<P>(&["BETA".to_string(), "GAMMA".to_string()]);
        let beta = challs[0];
        let gamma = challs[1];
        // AZTEC TODO(#583)(@zac-williamson): fix Transcript to be able to generate more than 2 challenges per round! oof.
        let beta_sqr = beta * beta;
        self.decider.memory.relation_parameters.gamma = gamma;
        self.decider.memory.relation_parameters.beta = beta;
        self.decider.memory.relation_parameters.beta_sqr = beta_sqr;
        self.decider.memory.relation_parameters.beta_cube = beta_sqr * beta;
        self.decider
            .memory
            .relation_parameters
            .eccvm_set_permutation_delta = gamma
            * (gamma + beta_sqr)
            * (gamma + beta_sqr + beta_sqr)
            * (gamma + beta_sqr + beta_sqr + beta_sqr);
        self.decider
            .memory
            .relation_parameters
            .eccvm_set_permutation_delta = self
            .decider
            .memory
            .relation_parameters
            .eccvm_set_permutation_delta
            .inverse()
            .expect("Challenge should be non-zero");

        // Compute inverse polynomial for our logarithmic-derivative lookup method
        self.compute_logderivative_inverses(proving_key, unmasked_witness_size)?;

        // we commit in execute_grand_product_computation_round to batch the opening
        Ok(())
    }

    #[expect(clippy::type_complexity)]
    fn compute_grand_product_numerator_and_denominator(
        &mut self,
        proving_key: &ProvingKey<T, P, ECCVMFlavour>,
        output_length: usize,
    ) -> HonkProofResult<(Vec<T::ArithmeticShare>, Vec<T::ArithmeticShare>)> {
        tracing::trace!("compute grand product numerator and denominator");
        let id = self.decider.state.id();

        // degree-11
        tracing::trace!("compute grand product numerator");

        let precompute_round =
            &proving_key.polynomials.witness.precompute_round().as_ref()[..output_length];
        let precompute_round2 = T::add_many(precompute_round, precompute_round);
        let precompute_round4 = T::add_many(&precompute_round2, &precompute_round2);

        let gamma = self.decider.memory.relation_parameters.gamma;
        let beta = self.decider.memory.relation_parameters.beta;
        let beta_sqr = self.decider.memory.relation_parameters.beta_sqr;
        let beta_cube = self.decider.memory.relation_parameters.beta_cube;
        let precompute_pc =
            &proving_key.polynomials.witness.precompute_pc().as_ref()[..output_length];
        let precompute_select =
            &proving_key.polynomials.witness.precompute_select().as_ref()[..output_length];

        let msm_pc = &proving_key.polynomials.witness.msm_pc().as_ref()[..output_length];
        let msm_count = &proving_key.polynomials.witness.msm_count().as_ref()[..output_length];
        let msm_round = &proving_key.polynomials.witness.msm_round().as_ref()[..output_length];
        let one = P::ScalarField::one();
        let minus_one = P::ScalarField::from(-1);
        let minus_15 = P::ScalarField::from(-15);
        let two = P::ScalarField::from(2);
        let three = P::ScalarField::from(3);
        let four = P::ScalarField::from(4);

        // First term: tuple of (pc, round, wnaf_slice), computed when slicing scalar multipliers into slices,
        // as part of ECCVMWnafRelation.
        // If precompute_select = 1, tuple entry = (wnaf-slice + point-counter * beta + msm-round * beta_sqr).
        // There are 4 tuple entries per row.
        // let mut numerator = Univariate {
        //     evaluations: [P::ScalarField::one(); SIZE],
        // }; // degree-0

        let s0 = &proving_key.polynomials.witness.precompute_s1hi().as_ref()[..output_length];
        let s1 = &proving_key.polynomials.witness.precompute_s1lo().as_ref()[..output_length];

        let mut wnaf_slice = s0.to_owned();
        T::scale_many_in_place(&mut wnaf_slice, four);
        T::add_assign_many(&mut wnaf_slice, s1);

        let wnaf_slice_input0 = T::add_many(
            &T::add_scalar(&wnaf_slice, gamma, id),
            &T::add_many(
                &T::scale_many(precompute_pc, beta),
                &T::scale_many(&precompute_round4, beta_sqr),
            ),
        );
        let numerator = wnaf_slice_input0; // degree-1

        let s0 = &proving_key.polynomials.witness.precompute_s2hi().as_ref()[..output_length];
        let s1 = &proving_key.polynomials.witness.precompute_s2lo().as_ref()[..output_length];

        let mut wnaf_slice = s0.to_owned();
        T::scale_many_in_place(&mut wnaf_slice, four);
        T::add_assign_many(&mut wnaf_slice, s1);

        let wnaf_slice_input1 = T::add_many(
            &T::add_scalar(&wnaf_slice, gamma, id),
            &T::add_many(
                &T::scale_many(precompute_pc, beta),
                &T::scale_many(&T::add_scalar(&precompute_round4, one, id), beta_sqr),
            ),
        );
        let mut lhs = Vec::with_capacity(15 * numerator.len());
        let mut rhs = Vec::with_capacity(lhs.len());

        lhs.extend(numerator);
        rhs.extend(wnaf_slice_input1);
        // numerator *= wnaf_slice_input1; // degree-2 DONE HERE

        let s0 = &proving_key.polynomials.witness.precompute_s3hi().as_ref()[..output_length];
        let s1 = &proving_key.polynomials.witness.precompute_s3lo().as_ref()[..output_length];

        let mut wnaf_slice = s0.to_owned();
        T::scale_many_in_place(&mut wnaf_slice, four);
        T::add_assign_many(&mut wnaf_slice, s1);

        let wnaf_slice_input2 = T::add_many(
            &T::add_scalar(&wnaf_slice, gamma, id),
            &T::add_many(
                &T::scale_many(precompute_pc, beta),
                &T::scale_many(&T::add_scalar(&precompute_round4, two, id), beta_sqr),
            ),
        );
        // numerator *= wnaf_slice_input2; // degree-3 TODO
        lhs.extend(wnaf_slice_input2);

        let s0 = &proving_key.polynomials.witness.precompute_s4hi().as_ref()[..output_length];
        let s1 = &proving_key.polynomials.witness.precompute_s4lo().as_ref()[..output_length];

        let mut wnaf_slice = s0.to_owned();
        T::scale_many_in_place(&mut wnaf_slice, four);
        T::add_assign_many(&mut wnaf_slice, s1);

        let wnaf_slice_input3 = T::add_many(
            &T::add_scalar(&wnaf_slice, gamma, id),
            &T::add_many(
                &T::scale_many(precompute_pc, beta),
                &T::scale_many(&T::add_scalar(&precompute_round4, three, id), beta_sqr),
            ),
        );
        // numerator *= wnaf_slice_input3; // degree-4 TODO
        rhs.extend(wnaf_slice_input3);

        // skew product if relevant
        let skew = &proving_key.polynomials.witness.precompute_skew().as_ref()[..output_length];
        let precompute_point_transition = &proving_key
            .polynomials
            .witness
            .precompute_point_transition()
            .as_ref()[..output_length];
        let mut skew_input_factor = precompute_pc.to_owned();
        T::scale_many_in_place(&mut skew_input_factor, beta);
        T::add_assign_many(&mut skew_input_factor, skew);
        T::add_assign_many(
            &mut skew_input_factor,
            &T::scale_many(&T::add_scalar(&precompute_round4, four, id), beta_sqr),
        );
        T::add_scalar_in_place(&mut skew_input_factor, gamma, id);
        let mut skew_input_summand = precompute_point_transition.to_owned();
        T::scale_many_in_place(&mut skew_input_summand, minus_one);
        T::add_scalar_in_place(&mut skew_input_summand, one, id);

        // skew
        //     + &gamma
        //     + precompute_pc.to_owned() * beta
        //     + (precompute_round4 + &P::ScalarField::from(4)) * beta_sqr;
        lhs.extend(precompute_point_transition);
        rhs.extend(&skew_input_factor);
        // let skew_input = precompute_point_transition.to_owned() * skew_input_factor
        //     + (T::add_scalar(
        //         &T::scale_many(precompute_point_transition, minus_one),
        //         one,
        //         id,
        //     )); TODO
        // numerator *= skew_input; // degree-5 TODO

        // let eccvm_set_permutation_delta = relation_parameters.eccvm_set_permutation_delta;
        let mut numerator_factor_7 = precompute_select.to_owned();
        T::scale_many_in_place(
            &mut numerator_factor_7,
            one - self
                .decider
                .memory
                .relation_parameters
                .eccvm_set_permutation_delta,
        );
        T::add_scalar_in_place(
            &mut numerator_factor_7,
            self.decider
                .memory
                .relation_parameters
                .eccvm_set_permutation_delta,
            id,
        );

        // Second term: tuple of (point-counter, P.x, P.y, scala r-multiplier), used in ECCVMWnafRelation and
        // ECCVMPointTableRelation. ECCVMWnafRelation validates the sum of the wnaf slices associated with point-counter
        // equals scalar-multiplier. ECCVMPointTableRelation computes a table of multiples of [P]: { -15[P], -13[P], ...,
        // 15[P] }. We need to validate that scalar-multiplier and [P] = (P.x, P.y) come from MUL opcodes in the transcript
        // columns.

        let convert_to_wnaf = |s0: &[<T as NoirUltraHonkProver<P>>::ArithmeticShare],
                               s1: &[<T as NoirUltraHonkProver<P>>::ArithmeticShare]|
         -> Vec<<T as NoirUltraHonkProver<P>>::ArithmeticShare> {
            let mut t = s0.to_owned();
            T::scale_many_in_place(&mut t, four);
            T::add_assign_many(&mut t, s1);
            T::scale_many_in_place(&mut t, two);
            T::add_scalar_in_place(&mut t, minus_15, id);
            t
        };

        let table_x = &proving_key.polynomials.witness.precompute_tx().as_ref()[..output_length];
        let table_y = &proving_key.polynomials.witness.precompute_ty().as_ref()[..output_length];

        let precompute_skew =
            &proving_key.polynomials.witness.precompute_skew().as_ref()[..output_length];
        let negative_inverse_seven = P::ScalarField::from(-7)
            .inverse()
            .expect("-7 is hopefully non-zero");
        let mut adjusted_skew = precompute_skew.to_owned();
        T::scale_many_in_place(&mut adjusted_skew, negative_inverse_seven);

        let wnaf_scalar_sum = &proving_key
            .polynomials
            .witness
            .precompute_scalar_sum()
            .as_ref()[..output_length];
        let w0 = convert_to_wnaf(
            &proving_key.polynomials.witness.precompute_s1hi().as_ref()[..output_length],
            &proving_key.polynomials.witness.precompute_s1lo().as_ref()[..output_length],
        );
        let w1 = convert_to_wnaf(
            &proving_key.polynomials.witness.precompute_s2hi().as_ref()[..output_length],
            &proving_key.polynomials.witness.precompute_s2lo().as_ref()[..output_length],
        );
        let w2 = convert_to_wnaf(
            &proving_key.polynomials.witness.precompute_s3hi().as_ref()[..output_length],
            &proving_key.polynomials.witness.precompute_s3lo().as_ref()[..output_length],
        );
        let w3 = convert_to_wnaf(
            &proving_key.polynomials.witness.precompute_s4hi().as_ref()[..output_length],
            &proving_key.polynomials.witness.precompute_s4lo().as_ref()[..output_length],
        );

        let mut row_slice = w0.clone();
        T::scale_many_in_place(&mut row_slice, P::ScalarField::from(16));
        T::add_assign_many(&mut row_slice, &w1);
        T::scale_many_in_place(&mut row_slice, P::ScalarField::from(16));
        T::add_assign_many(&mut row_slice, &w2);
        T::scale_many_in_place(&mut row_slice, P::ScalarField::from(16));
        T::add_assign_many(&mut row_slice, &w3);

        let mut scalar_sum_full = wnaf_scalar_sum.to_owned();
        T::scale_many_in_place(&mut scalar_sum_full, P::ScalarField::from(65536));
        T::add_assign_many(
            &mut scalar_sum_full,
            &T::add_many(&row_slice, &adjusted_skew),
        );

        let precompute_point_transition = &proving_key
            .polynomials
            .witness
            .precompute_point_transition()
            .as_ref()[..output_length];

        let mut point_table_init_read = table_x.to_owned(); // * beta
        //     + precompute_pc
        //     + table_y.to_owned() * beta_sqr
        //     + scalar_sum_full * beta_cube;
        T::scale_many_in_place(&mut point_table_init_read, beta);
        T::add_assign_many(&mut point_table_init_read, precompute_pc);
        T::add_assign_many(
            &mut point_table_init_read,
            &T::add_many(
                &T::scale_many(table_y, beta_sqr),
                &T::scale_many(&scalar_sum_full, beta_cube),
            ),
        );
        T::add_scalar_in_place(&mut point_table_init_read, gamma, id);
        // let mut point_table_init_read = precompute_point_transition.to_owned()
        //     * (point_table_init_read + &gamma)
        //     + (precompute_point_transition.to_owned() * minus_one + &P::ScalarField::one());
        let mut point_table_init_read_summand = precompute_point_transition.to_owned();
        T::scale_many_in_place(&mut point_table_init_read_summand, minus_one);
        T::add_scalar_in_place(&mut point_table_init_read_summand, one, id);
        lhs.extend(precompute_point_transition);
        rhs.extend(point_table_init_read);

        // numerator *= point_table_init_read; // degree-9 TODO

        // Third term: tuple of (point-counter, P.x, P.y, msm-size) from ECCVMMSMRelation.
        // (P.x, P.y) is the output of a multi-scalar-multiplication evaluated in ECCVMMSMRelation.
        // We need to validate that the same values (P.x, P.y) are present in the Transcript columns and describe a
        // multi-scalar multiplication of size `msm-size`, starting at `point-counter`.

        let lagrange_first_modified = proving_key
            .polynomials
            .precomputed
            .lagrange_first()
            .iter()
            .take(output_length)
            .map(|a| *a * minus_one + one)
            .collect_vec();

        let binding = proving_key.polynomials.witness.msm_transition().shifted();
        let partial_msm_transition_shift = &binding.as_ref()[..output_length];
        let msm_transition_shift =
            T::mul_with_public_many(&lagrange_first_modified, partial_msm_transition_shift);
        let binding = proving_key.polynomials.witness.msm_pc().shifted();
        let msm_pc_shift = &binding.as_ref()[..output_length];

        let binding = proving_key
            .polynomials
            .witness
            .msm_accumulator_x()
            .shifted();
        let msm_x_shift = &binding.as_ref()[..output_length];
        let binding = proving_key
            .polynomials
            .witness
            .msm_accumulator_y()
            .shifted();
        let msm_y_shift = &binding.as_ref()[..output_length];
        let msm_size = &proving_key.polynomials.witness.msm_size_of_msm().as_ref()[..output_length];

        let msm_result_write = T::add_many(
            &T::scale_many(msm_x_shift, beta),
            &T::add_many(
                &T::scale_many(msm_y_shift, beta_sqr),
                &T::add_many(&T::scale_many(msm_size, beta_cube), msm_pc_shift),
            ),
        );

        lhs.extend(&msm_transition_shift);
        rhs.extend(T::add_scalar(&msm_result_write, gamma, id));
        // msm_result_write = msm_transition_shift.to_owned() * (msm_result_write + &gamma)
        //     + (msm_transition_shift * minus_one + &P::ScalarField::one()); //TODO subtract this from the product
        // numerator *= msm_result_write; // degree-11 TODO

        // numerator
        tracing::trace!("compute grand product numinator finished");

        // degree-20
        tracing::trace!("compute grand product denominator");

        // AZTEC TODO(@zac-williamson). The degree of this contribution is 17! makes overall relation degree 19.
        // Can optimise by refining the algebra, once we have a stable base to iterate off of.

        /*
         * @brief First term: tuple of (pc, round, wnaf_slice), used to determine which points we extract from lookup tables
         * when evaluaing MSMs in ECCVMMsmRelation.
         * These values must be equivalent to the values computed in the 1st term of `compute_grand_product_numerator`
         */
        // let mut denominator = Univariate {
        //     evaluations: [P::ScalarField::one(); SIZE],
        // }; // degree-0

        let add1 = &proving_key.polynomials.witness.msm_add1().as_ref()[..output_length];
        let msm_slice1 = &proving_key.polynomials.witness.msm_slice1().as_ref()[..output_length];

        // let wnaf_slice_output1 = add1.to_owned()
        //     * (msm_slice1.to_owned()
        //         + &gamma
        //         + (msm_pc.to_owned() - msm_count) * beta
        //         + msm_round.to_owned() * beta_sqr)
        //     + (add1.to_owned() * minus_one + &P::ScalarField::one());
        let mut wnaf_slice_output1_factor = msm_slice1.to_owned();
        T::add_scalar_in_place(&mut wnaf_slice_output1_factor, gamma, id);
        T::add_assign_many(
            &mut wnaf_slice_output1_factor,
            &T::sub_many(
                &T::scale_many(msm_pc, beta),
                &T::scale_many(msm_count, beta),
            ),
        );
        T::add_assign_many(
            &mut wnaf_slice_output1_factor,
            &T::scale_many(msm_round, beta_sqr),
        );
        let mut wnaf_slice_output1_summand = add1.to_owned();
        T::scale_many_in_place(&mut wnaf_slice_output1_summand, minus_one);
        T::add_scalar_in_place(&mut wnaf_slice_output1_summand, one, id);

        lhs.extend(add1);
        rhs.extend(wnaf_slice_output1_factor);

        // denominator *= wnaf_slice_output1; // degree-2 TODO

        let add2 = &proving_key.polynomials.witness.msm_add2().as_ref()[..output_length];
        let msm_slice2 = &proving_key.polynomials.witness.msm_slice2().as_ref()[..output_length];

        // let wnaf_slice_output2 = add2.to_owned()
        //     * (msm_slice2.to_owned()
        //         + &gamma
        //         + (msm_pc.to_owned() - msm_count + &minus_one) * beta
        //         + msm_round.to_owned() * beta_sqr)
        //     + (add2.to_owned() * minus_one + &P::ScalarField::one());
        let mut wnaf_slice_output2_factor = msm_slice2.to_owned();
        T::add_scalar_in_place(&mut wnaf_slice_output2_factor, gamma, id);
        T::add_assign_many(
            &mut wnaf_slice_output2_factor,
            &T::sub_many(
                &T::scale_many(msm_pc, beta),
                &T::scale_many(&T::add_scalar(msm_count, one, id), beta),
            ),
        );
        T::add_assign_many(
            &mut wnaf_slice_output2_factor,
            &T::scale_many(msm_round, beta_sqr),
        );
        let mut wnaf_slice_output2_summand = add2.to_owned();
        T::scale_many_in_place(&mut wnaf_slice_output2_summand, minus_one);
        T::add_scalar_in_place(&mut wnaf_slice_output2_summand, one, id);
        lhs.extend(add2);
        rhs.extend(wnaf_slice_output2_factor);
        // denominator *= wnaf_slice_output2; // degree-4 TODO

        let add3 = &proving_key.polynomials.witness.msm_add3().as_ref()[..output_length];
        let msm_slice3 = &proving_key.polynomials.witness.msm_slice3().as_ref()[..output_length];

        // let wnaf_slice_output3 = add3.to_owned()
        //     * (msm_slice3.to_owned()
        //         + &gamma
        //         + (msm_pc.to_owned() - msm_count + &P::ScalarField::from(-2)) * beta
        //         + msm_round.to_owned() * beta_sqr)
        //     + (add3.to_owned() * minus_one + &P::ScalarField::one());
        let mut wnaf_slice_output3_factor = msm_slice3.to_owned();
        T::add_scalar_in_place(&mut wnaf_slice_output3_factor, gamma, id);
        T::add_assign_many(
            &mut wnaf_slice_output3_factor,
            &T::sub_many(
                &T::scale_many(msm_pc, beta),
                &T::scale_many(&T::add_scalar(msm_count, two, id), beta),
            ),
        );
        T::add_assign_many(
            &mut wnaf_slice_output3_factor,
            &T::scale_many(msm_round, beta_sqr),
        );
        let mut wnaf_slice_output3_summand = add3.to_owned();
        T::scale_many_in_place(&mut wnaf_slice_output3_summand, minus_one);
        T::add_scalar_in_place(&mut wnaf_slice_output3_summand, one, id);
        lhs.extend(add3);
        rhs.extend(wnaf_slice_output3_factor);
        // denominator *= wnaf_slice_output3; // degree-6 TODO

        let add4 = &proving_key.polynomials.witness.msm_add4().as_ref()[..output_length];
        let msm_slice4 = &proving_key.polynomials.witness.msm_slice4().as_ref()[..output_length];

        // let wnaf_slice_output4 = add4.to_owned()
        //     * (msm_slice4.to_owned()
        //         + &gamma
        //         + (msm_pc.to_owned() - msm_count + &P::ScalarField::from(-3)) * beta
        //         + msm_round.to_owned() * beta_sqr)
        //     + (add4.to_owned() * minus_one + &P::ScalarField::one());
        let mut wnaf_slice_output4_factor = msm_slice4.to_owned();
        T::add_scalar_in_place(&mut wnaf_slice_output4_factor, gamma, id);
        T::add_assign_many(
            &mut wnaf_slice_output4_factor,
            &T::sub_many(
                &T::scale_many(msm_pc, beta),
                &T::scale_many(&T::add_scalar(msm_count, three, id), beta),
            ),
        );
        T::add_assign_many(
            &mut wnaf_slice_output4_factor,
            &T::scale_many(msm_round, beta_sqr),
        );
        let mut wnaf_slice_output4_summand = add4.to_owned();
        T::scale_many_in_place(&mut wnaf_slice_output4_summand, minus_one);
        T::add_scalar_in_place(&mut wnaf_slice_output4_summand, one, id);
        lhs.extend(add4);
        rhs.extend(wnaf_slice_output4_factor);
        // denominator *= wnaf_slice_output4; // degree-8 TODO

        /*
         * @brief Second term: tuple of (transcript_pc, transcript_Px, transcript_Py, z1) OR (transcript_pc, \lambda *
         * transcript_Px, -transcript_Py, z2) for each scalar multiplication in ECCVMTranscriptRelation columns. (the latter
         * term uses the curve endomorphism: \lambda = cube root of unity). These values must be equivalent to the second
         * term values in `compute_grand_product_numerator`
         */
        let transcript_pc =
            &proving_key.polynomials.witness.transcript_pc().as_ref()[..output_length];
        let transcript_px =
            &proving_key.polynomials.witness.transcript_px().as_ref()[..output_length];
        let transcript_py =
            &proving_key.polynomials.witness.transcript_py().as_ref()[..output_length];
        let z1 = &proving_key.polynomials.witness.transcript_z1().as_ref()[..output_length];
        let z2 = &proving_key.polynomials.witness.transcript_z2().as_ref()[..output_length];
        let z1_zero =
            &proving_key.polynomials.witness.transcript_z1zero().as_ref()[..output_length];
        let z2_zero =
            &proving_key.polynomials.witness.transcript_z2zero().as_ref()[..output_length];

        let mut lookup_first = z1_zero.to_owned(); //* minus_one + &P::ScalarField::one();
        T::scale_many_in_place(&mut lookup_first, minus_one);
        T::add_scalar_in_place(&mut lookup_first, one, id);
        let mut lookup_second = z2_zero.to_owned(); // * minus_one + &P::ScalarField::one();
        T::scale_many_in_place(&mut lookup_second, minus_one);
        T::add_scalar_in_place(&mut lookup_second, one, id);
        let endomorphism_base_field_shift = P::CycleGroup::get_cube_root_of_unity();

        let mut transcript_input1 = transcript_px.to_owned(); // * beta
        // + transcript_pc
        // + transcript_py.to_owned() * beta_sqr
        // + z1.to_owned() * beta_cube; // degree = 1
        T::scale_many_in_place(&mut transcript_input1, beta);
        T::add_assign_many(&mut transcript_input1, transcript_pc);
        T::add_assign_many(
            &mut transcript_input1,
            &T::scale_many(transcript_py, beta_sqr),
        );
        T::add_assign_many(&mut transcript_input1, &T::scale_many(z1, beta_cube));
        let mut transcript_input2 = transcript_px.to_owned(); // * endomorphism_base_field_shift * beta
        // + transcript_pc.to_owned()
        // + &minus_one
        // + transcript_py.to_owned() * beta_sqr * minus_one
        // + z2.to_owned() * beta_cube; // degree = 2
        T::scale_many_in_place(&mut transcript_input2, endomorphism_base_field_shift);
        T::scale_many_in_place(&mut transcript_input2, beta);
        T::add_assign_many(&mut transcript_input2, transcript_pc);
        T::add_scalar_in_place(&mut transcript_input2, minus_one, id);
        T::add_assign_many(
            &mut transcript_input2,
            &T::scale_many(transcript_py, beta_sqr * minus_one),
        );
        T::add_assign_many(&mut transcript_input2, &T::scale_many(z2, beta_cube));

        // transcript_input1 = (transcript_input1 + &gamma) * lookup_first.clone()
        //     + (lookup_first.to_owned() * minus_one + &P::ScalarField::one()); // degree 2 TODO ADD THIS
        T::add_scalar_in_place(&mut transcript_input1, gamma, id);
        lhs.extend(transcript_input1);
        rhs.extend(lookup_first.clone());
        // transcript_input2 = (transcript_input2 + &gamma) * lookup_second.clone()
        //     + (lookup_second.to_owned() * minus_one + &P::ScalarField::one()); // degree 3 TODO ADD THIS
        T::add_scalar_in_place(&mut transcript_input2, gamma, id);
        lhs.extend(transcript_input2);
        rhs.extend(lookup_second.clone());

        // let transcript_product = (transcript_input1 * transcript_input2)
        //     * (base_infinity.to_owned() * minus_one + &P::ScalarField::one())
        //     + base_infinity; // degree 6 TODO

        // let point_table_init_write = transcript_mul.to_owned() * transcript_product
        //     + (transcript_mul.to_owned() * minus_one + &P::ScalarField::one()); TODO
        // denominator *= point_table_init_write; // degree 17 TODO

        /*
         * @brief Third term: tuple of (point-counter, P.x, P.y, msm-size) from ECCVMTranscriptRelation.
         *        (P.x, P.y) is the *claimed* output of a multi-scalar-multiplication evaluated in ECCVMMSMRelation.
         *        We need to validate that the msm output produced in ECCVMMSMRelation is equivalent to the output present
         * in `transcript_msm_output_x, transcript_msm_output_y`, for a given multi-scalar multiplication starting at
         * `transcript_pc` and has size `transcript_msm_count`
         */

        let transcript_msm_x =
            &proving_key.polynomials.witness.transcript_msm_x().as_ref()[..output_length];
        let transcript_msm_y =
            &proving_key.polynomials.witness.transcript_msm_y().as_ref()[..output_length];
        let transcript_msm_transition = &proving_key
            .polynomials
            .witness
            .transcript_msm_transition()
            .as_ref()[..output_length];
        let transcript_msm_count = &proving_key
            .polynomials
            .witness
            .transcript_msm_count()
            .as_ref()[..output_length];
        let z1_zero =
            &proving_key.polynomials.witness.transcript_z1zero().as_ref()[..output_length];
        let z2_zero =
            &proving_key.polynomials.witness.transcript_z2zero().as_ref()[..output_length];
        let transcript_mul =
            &proving_key.polynomials.witness.transcript_mul().as_ref()[..output_length];
        let base_infinity = &proving_key
            .polynomials
            .witness
            .transcript_base_infinity()
            .as_ref()[..output_length];

        //  let full_msm_count = transcript_mul.to_owned()
        // * ((z1_zero.to_owned() * minus_one + &P::ScalarField::one())
        //     + (z2_zero.to_owned() * minus_one + &P::ScalarField::one()))
        // * (base_infinity.to_owned() * minus_one + &P::ScalarField::one())
        // + transcript_msm_count;
        let full_msm_count_factor_1 = transcript_mul;
        let mut full_msm_count_factor_2 = z1_zero.to_owned();
        T::scale_many_in_place(&mut full_msm_count_factor_2, minus_one);
        T::add_scalar_in_place(&mut full_msm_count_factor_2, two, id);
        T::sub_assign_many(&mut full_msm_count_factor_2, z2_zero);
        let mut full_msm_count_factor_3 = base_infinity.to_owned();
        T::scale_many_in_place(&mut full_msm_count_factor_3, minus_one);
        T::add_scalar_in_place(&mut full_msm_count_factor_3, one, id);
        let full_msm_count_summand = transcript_msm_count;
        lhs.extend(full_msm_count_factor_1);
        rhs.extend(full_msm_count_factor_2);

        let mut msm_result_read = transcript_msm_x.to_owned(); // * beta
        // + transcript_msm_y.to_owned() * beta_sqr
        // + full_msm_count.to_owned() * beta_cube
        // + transcript_pc_shift;
        T::scale_many_in_place(&mut msm_result_read, beta);
        T::add_assign_many(
            &mut msm_result_read,
            &T::scale_many(transcript_msm_y, beta_sqr),
        );

        let transcript_pc_shift = proving_key.polynomials.witness.transcript_pc().shifted();
        let transcript_pc_shift = &transcript_pc_shift.as_ref()[..output_length];
        T::add_assign_many(&mut msm_result_read, transcript_pc_shift);
        T::add_scalar_in_place(&mut msm_result_read, gamma, id);

        // msm_result_read = transcript_msm_transition.to_owned() * (msm_result_read + &gamma)<- DONE
        //     + (transcript_msm_transition.to_owned() * minus_one + &P::ScalarField::one()); TODO
        // denominator *= msm_result_read; // degree-20 TODO

        let mul = T::mul_many(&lhs, &rhs, self.decider.net, self.decider.state)?;
        let mul = mul.chunks_exact(mul.len() / 12).collect_vec();
        debug_assert_eq!(mul.len(), 12);

        // Numerator stuff:
        let numerator_2 = mul[0].to_owned();
        let wnaf2wnaf3 = mul[1].to_owned(); //TODO multiply to numerator
        let mut skew_input = mul[2].to_owned(); //TODO multiply to numerator
        T::sub_assign_many(&mut skew_input, precompute_point_transition);
        T::add_scalar_in_place(&mut skew_input, one, id);
        let mut point_table_init_read = mul[3].to_owned(); //TODO multiply to numerator
        T::add_assign_many(&mut point_table_init_read, &point_table_init_read_summand);
        let mut msm_result_write = mul[4].to_owned(); //TODO multiply to numerator
        T::sub_assign_many(&mut msm_result_write, &msm_transition_shift);
        T::add_scalar_in_place(&mut msm_result_write, one, id);

        // Denominator stuff:
        let mut wnaf_slice_output1 = mul[5].to_owned();
        T::add_assign_many(&mut wnaf_slice_output1, &wnaf_slice_output1_summand);
        let mut wnaf_slice_output2 = mul[6].to_owned();
        T::add_assign_many(&mut wnaf_slice_output2, &wnaf_slice_output2_summand);
        let mut wnaf_slice_output3 = mul[7].to_owned();
        T::add_assign_many(&mut wnaf_slice_output3, &wnaf_slice_output3_summand);
        let mut wnaf_slice_output4 = mul[8].to_owned();
        T::add_assign_many(&mut wnaf_slice_output4, &wnaf_slice_output4_summand);
        let mut transcript_input1 = mul[9].to_owned();
        T::sub_assign_many(&mut transcript_input1, &lookup_first);
        T::add_scalar_in_place(&mut transcript_input1, one, id);
        let mut transcript_input2 = mul[10].to_owned();
        T::sub_assign_many(&mut transcript_input2, &lookup_second);
        T::add_scalar_in_place(&mut transcript_input2, one, id);
        let full_msm_count = mul[11].to_owned();
        // let mut msm_result_read = mul[12].to_owned(); // TODO multiply to denominator
        // T::sub_assign_many(&mut msm_result_read, &transcript_msm_transition);
        // T::add_scalar_in_place(&mut msm_result_read, one, id);

        let mut lhs2 = Vec::with_capacity(12);
        let mut rhs2 = Vec::with_capacity(lhs2.len());
        lhs2.extend(wnaf2wnaf3);
        rhs2.extend(skew_input);
        lhs2.extend(point_table_init_read);
        rhs2.extend(msm_result_write);

        lhs2.extend(wnaf_slice_output1);
        rhs2.extend(wnaf_slice_output2);
        lhs2.extend(wnaf_slice_output3);
        rhs2.extend(wnaf_slice_output4);
        lhs2.extend(transcript_input1);
        rhs2.extend(transcript_input2);
        lhs2.extend(full_msm_count);
        rhs2.extend(full_msm_count_factor_3);

        let mul2 = T::mul_many(&lhs2, &rhs2, self.decider.net, self.decider.state)?;
        let mul2 = mul2.chunks_exact(mul2.len() / 6).collect_vec();
        debug_assert_eq!(mul2.len(), 6);

        let mut lhs3 = Vec::with_capacity(6);
        let mut rhs3 = Vec::with_capacity(lhs3.len());
        lhs3.extend(mul2[0].to_owned()); // wnaf2wnaf3 * skew_input
        rhs3.extend(mul2[1].to_owned()); // point_table_init_read * msm_result_write

        lhs3.extend(mul2[2].to_owned()); // wnaf_slice_output1 * wnaf_slice_output2
        rhs3.extend(mul2[3].to_owned()); // wnaf_slice_output3 * wnaf_slice_output4
        lhs3.extend(mul2[4].to_owned()); // transcript_input1 * transcript_input2
        rhs3.extend(T::add_scalar(
            &T::scale_many(base_infinity, minus_one),
            one,
            id,
        )); // TODO: add base_infinity to this result
        let mut full_msm_count = T::add_many(mul2[5], full_msm_count_summand);
        T::scale_many_in_place(&mut full_msm_count, beta_cube);
        T::add_assign_many(&mut msm_result_read, &full_msm_count);
        lhs3.extend(transcript_msm_transition.to_owned());
        rhs3.extend(msm_result_read);

        let mul = T::mul_many(&lhs3, &rhs3, self.decider.net, self.decider.state)?;
        let mul = mul.chunks_exact(mul.len() / 4).collect_vec();
        debug_assert_eq!(mul.len(), 4);

        let mut lhs4 = Vec::with_capacity(mul[0].len() * 4);
        let mut rhs4 = Vec::with_capacity(lhs4.len());
        lhs4.extend(mul[0].to_owned()); // (wnaf2wnaf3 * skew_input) *  (point_table_init_read * msm_result_write)
        rhs4.extend(numerator_2); //

        lhs4.extend(T::add_many(mul[2], base_infinity)); // (transcript_input1 * transcript_input2)   * (base_infinity.to_owned() * minus_one + &P::ScalarField::one())
        rhs4.extend(transcript_mul.to_owned());

        let mut msm_result_read = mul[3].to_owned(); //  (transcript_msm_transition.to_owned() * (msm_result_read + &gamma)
        T::sub_assign_many(&mut msm_result_read, transcript_msm_transition);
        T::add_scalar_in_place(&mut msm_result_read, one, id);

        lhs4.extend(mul[1].to_owned()); // (wnaf_slice_output1 * wnaf_slice_output2) * (wnaf_slice_output3 * wnaf_slice_output4)
        rhs4.extend(msm_result_read);

        let mul = T::mul_many(&lhs4, &rhs4, self.decider.net, self.decider.state)?;
        let mul = mul.chunks_exact(mul.len() / 3).collect_vec();
        debug_assert_eq!(mul.len(), 3);

        let final_numerator = mul[0].to_owned();

        let mut point_table_init_write = mul[1].to_owned(); // transcript_mul.to_owned() * transcript_product
        T::sub_assign_many(&mut point_table_init_write, transcript_mul);
        T::add_scalar_in_place(&mut point_table_init_write, one, id);

        let mut lhs5 = Vec::with_capacity(2 * point_table_init_write.len());
        let mut rhs5 = Vec::with_capacity(lhs5.len());
        lhs5.extend(final_numerator);
        rhs5.extend(numerator_factor_7);
        lhs5.extend(point_table_init_write.to_owned());
        rhs5.extend(mul[2].to_owned());

        let mul = T::mul_many(&lhs5, &rhs5, self.decider.net, self.decider.state)?;
        let mul = mul.chunks_exact(mul.len() / 2).collect_vec();
        debug_assert_eq!(mul.len(), 2);
        Ok((mul[0].to_vec(), mul[1].to_vec()))
    }

    fn compute_grand_product(
        &mut self,
        proving_key: &ProvingKey<T, P, ECCVMFlavour>,
        domain_size: usize,
    ) -> HonkProofResult<()> {
        tracing::trace!("compute grand product");

        let has_active_ranges = proving_key.active_region_data.size() > 0;

        // Barretenberg uses multithreading here

        // Set the domain over which the grand product must be computed. This may be less than the dyadic circuit size, e.g
        // the permutation grand product does not need to be computed beyond the index of the last active wire

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
        let (numerator_, denominator_) =
            self.compute_grand_product_numerator_and_denominator(proving_key, active_domain_size)?;

        //TACEO TODO: Could minimize the number of elements being multiplied in the above
        for i in 0..active_domain_size {
            let idx = if has_active_ranges {
                proving_key.active_region_data.get_idx(i)
            } else {
                i
            };
            numerator.push(numerator_[idx]);
            denominator.push(denominator_[idx]);
        }
        // Step (2)
        // Compute the accumulating product of the numerator and denominator terms.

        // TACEO TODO could batch here as well
        // Do the multiplications of num[i] * num[i-1] and den[i] * den[i-1] in constant rounds
        let mut numerator_final = CoUtils::array_prod_mul::<T, P, N>(
            self.decider.net,
            self.decider.state,
            &numerator[..active_domain_size - 2],
        )?;
        let mut denominator_final = CoUtils::array_prod_mul::<T, P, N>(
            self.decider.net,
            self.decider.state,
            &denominator[..active_domain_size - 2],
        )?;
        numerator_final.push(numerator[active_domain_size - 1]);
        denominator_final.push(denominator[active_domain_size - 1]);
        // invert denominator
        CoUtils::batch_invert::<T, P, N>(
            &mut denominator_final,
            self.decider.net,
            self.decider.state,
        )?;
        // Step (3) Compute z_perm[i] = numerator[i] / denominator[i]
        let mul = T::mul_many(
            &numerator_final,
            &denominator_final,
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
                proving_key.active_region_data.get_idx(i)
            } else {
                i
            };
            self.memory.z_perm[idx + 1] = mul
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
        Ok(())
    }

    fn execute_grand_product_computation_round(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &ProvingKey<T, P, ECCVMFlavour>,
        unmasked_witness_size: usize,
        crs: &ProverCrs<P>,
    ) -> HonkProofResult<()> {
        // Compute permutation grand product and their commitments
        self.compute_grand_product(proving_key, unmasked_witness_size)?;

        CoUtils::mask_polynomial::<T, P, N>(
            self.decider.net,
            self.decider.state,
            &mut self.memory.z_perm,
        )?;
        CoUtils::mask_polynomial::<T, P, N>(
            self.decider.net,
            self.decider.state,
            &mut self.memory.lookup_inverses,
        )?;
        let opened = T::open_point_many(
            &[
                CoUtils::commit::<T, P>(self.memory.z_perm.as_ref(), crs),
                CoUtils::commit::<T, P>(self.memory.lookup_inverses.as_ref(), crs),
            ],
            self.decider.net,
            self.decider.state,
        )?;
        transcript.send_point_to_verifier::<P>("LOOKUP_INVERSES".to_string(), opened[1].into());
        transcript.send_point_to_verifier::<P>("Z_PERM".to_string(), opened[0].into());
        Ok(())
    }

    #[expect(clippy::type_complexity)]
    fn execute_relation_check_rounds(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        crs: &ProverCrs<P>,
        circuit_size: u32,
    ) -> HonkProofResult<(
        SumcheckOutput<T, P, ECCVMFlavour>,
        SharedZKSumcheckData<T, P>,
    )> {
        self.decider.memory.alphas =
            vec![transcript.get_challenge::<P>("Sumcheck:alpha".to_string())];
        let mut gate_challenges: Vec<P::ScalarField> = Vec::with_capacity(CONST_ECCVM_LOG_N);

        for idx in 0..CONST_ECCVM_LOG_N {
            let chall = transcript.get_challenge::<P>(format!("Sumcheck:gate_challenge_{idx}"));
            gate_challenges.push(chall);
        }
        self.decider.memory.gate_challenges = gate_challenges;
        let log_subgroup_size = UltraHonkUtils::get_msb64(P::SUBGROUP_SIZE as u64);
        let commitment_key = &crs.monomials[..1 << (log_subgroup_size + 1)];
        let mut zk_sumcheck_data: SharedZKSumcheckData<T, P> =
            SharedZKSumcheckData::<T, P>::new::<H, N>(
                UltraHonkUtils::get_msb64(circuit_size as u64) as usize,
                transcript,
                commitment_key,
                self.decider.net,
                self.decider.state,
            )?;

        Ok((
            self.decider.sumcheck_prove_zk::<CONST_ECCVM_LOG_N>(
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
        sumcheck_output: SumcheckOutput<T, P, ECCVMFlavour>,
        zk_sumcheck_data: SharedZKSumcheckData<T, P>,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        crs: &ProverCrs<P>,
        circuit_size: u32,
    ) -> HonkProofResult<Transcript<TranscriptFieldType, H>> {
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
        let multivariate_to_univariate_opening_claim = self.decider.shplemini_prove(
            transcript,
            circuit_size,
            crs,
            sumcheck_output,
            Some(witness_polynomials),
        )?;

        self.compute_translation_opening_claims(transcript, crs, circuit_size)?;

        self.memory.opening_claims[NUM_OPENING_CLAIMS - 1] =
            multivariate_to_univariate_opening_claim;

        let virtual_log_n = 0; // This is 0 per default
        // Reduce the opening claims to a single opening claim via Shplonk
        let batch_opening_claim = self.decider.shplonk_prove(
            &self.memory.opening_claims,
            crs,
            transcript,
            None,
            None,
            virtual_log_n,
        )?;

        // Compute the opening proof for the batched opening claim with the univariate PCS

        let mut ipa_transcript = Transcript::<TranscriptFieldType, H>::new();
        compute_ipa_opening_proof(
            self.decider.net,
            self.decider.state,
            &mut ipa_transcript,
            batch_opening_claim,
            crs,
        )?;
        Ok(ipa_transcript)
    }

    fn compute_translation_opening_claims(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        crs: &ProverCrs<P>,
        circuit_size: u32,
    ) -> HonkProofResult<()> {
        tracing::trace!("compute translation opening claims");

        // Collect the polynomials to be batched
        let translation_polynomials = [
            self.decider.memory.polys.witness.transcript_op(),
            self.decider.memory.polys.witness.transcript_px(),
            self.decider.memory.polys.witness.transcript_py(),
            self.decider.memory.polys.witness.transcript_z1(),
            self.decider.memory.polys.witness.transcript_z2(),
        ];
        let translation_labels = [
            "Translation:transcript_op".to_string(),
            "Translation:transcript_px".to_string(),
            "Translation:transcript_py".to_string(),
            "Translation:transcript_z1".to_string(),
            "Translation:transcript_z2".to_string(),
        ];

        // Extract the masking terms of `translation_polynomials`, concatenate them in the Lagrange basis over SmallSubgroup
        // H, mask the resulting polynomial, and commit to it
        let mut translation_data = SharedTranslationData::construct_translation_data(
            &translation_polynomials,
            transcript,
            crs,
            self.decider.net,
            self.decider.state,
        )?;

        // Get a challenge to evaluate the `translation_polynomials` as univariates
        let evaluation_challenge_x: P::ScalarField =
            transcript.get_challenge::<P>("Translation:evaluation_challenge_x".to_string());

        // Evaluate `translation_polynomial` as univariates and add their evaluations at x to the transcript
        let mut translation_evaluations = Vec::with_capacity(translation_polynomials.len());
        let mut evaluations = Vec::with_capacity(translation_polynomials.len());
        for poly in translation_polynomials.iter() {
            let eval = T::eval_poly(poly, evaluation_challenge_x);
            evaluations.push(eval);
        }
        let opened = T::open_many(&evaluations, self.decider.net, self.decider.state)?;
        for (eval, label) in opened.into_iter().zip(translation_labels) {
            transcript.send_fr_to_verifier::<P>(label, eval);
            translation_evaluations.push(eval);
        }

        // Get another challenge to batch the evaluations of the transcript polynomials
        let batching_challenge_v =
            transcript.get_challenge::<P>("Translation:batching_challenge_v".to_string());

        let mut translation_masking_term_prover = translation_data
            .compute_small_ipa_prover::<_, _>(
                evaluation_challenge_x,
                batching_challenge_v,
                transcript,
                self.decider.net,
                self.decider.state,
            )?;

        translation_masking_term_prover.prove(
            self.decider.net,
            self.decider.state,
            transcript,
            crs,
        )?;

        // Get the challenge to check evaluations of the SmallSubgroupIPA witness polynomials
        let small_ipa_evaluation_challenge =
            transcript.get_challenge::<P>("Translation:small_ipa_evaluation_challenge".to_string());

        // Populate SmallSubgroupIPA opening claims:
        // 1. Get the evaluation points and labels
        let subgroup_generator = P::get_subgroup_generator();
        let evaluation_points = [
            small_ipa_evaluation_challenge,
            small_ipa_evaluation_challenge * subgroup_generator,
            small_ipa_evaluation_challenge,
            small_ipa_evaluation_challenge,
        ];

        let evaluation_labels = [
            "Translation:concatenation_eval".to_string(),
            "Translation:grand_sum_shift_eval".to_string(),
            "Translation:grand_sum_eval".to_string(),
            "Translation:quotient_eval".to_string(),
        ];

        // 2. Compute the evaluations of witness polynomials at corresponding points, send them to the verifier, and create
        // the opening claims
        // let mut opening_claims = Vec::with_capacity(NUM_SMALL_IPA_EVALUATIONS + 1);
        let witness_polys = translation_masking_term_prover.into_witness_polynomials();
        let mut evaluations = Vec::with_capacity(NUM_SMALL_IPA_EVALUATIONS);
        for idx in 0..NUM_SMALL_IPA_EVALUATIONS {
            let witness_poly = &witness_polys[idx];
            let eval = T::eval_poly(&witness_poly.coefficients, evaluation_points[idx]);
            evaluations.push(eval);
        }
        let opened = T::open_many(&evaluations, self.decider.net, self.decider.state)?; //TACEO TODO Here we open the opening pair evaluations, is this a problem?
        // Also we promote to trivial shares down below, maybe this can be optimized?
        for (i, eval) in opened.iter().enumerate() {
            transcript.send_fr_to_verifier::<P>(evaluation_labels[i].clone(), *eval);
            self.memory.opening_claims[i] = ShpleminiOpeningClaim {
                polynomial: witness_polys[i].clone(),
                opening_pair: OpeningPair {
                    challenge: evaluation_points[i],
                    evaluation: T::promote_to_trivial_share(self.decider.state.id(), *eval),
                },
                gemini_fold: false,
            };
        }

        // Compute the opening claim for the masked evaluations of `op`, `Px`, `Py`, `z1`, and `z2` at
        // `evaluation_challenge_x` batched by the powers of `batching_challenge_v`.
        let mut batched_translation_univariate = SharedPolynomial::new_zero(circuit_size as usize);
        let mut batched_translation_evaluation = P::ScalarField::zero();
        let mut batching_scalar = P::ScalarField::one();
        for (polynomial, eval) in translation_polynomials
            .iter()
            .zip(translation_evaluations.iter())
        {
            batched_translation_univariate.add_scaled_slice(polynomial, &batching_scalar);
            batched_translation_evaluation += *eval * batching_scalar;
            batching_scalar *= batching_challenge_v;
        }

        // Add the batched claim to the array of SmallSubgroupIPA opening claims.
        self.memory.opening_claims[NUM_SMALL_IPA_EVALUATIONS] = ShpleminiOpeningClaim {
            polynomial: batched_translation_univariate,
            opening_pair: OpeningPair {
                challenge: evaluation_challenge_x,
                evaluation: T::promote_to_trivial_share(
                    self.decider.state.id(),
                    batched_translation_evaluation,
                ),
            },
            gemini_fold: false,
        };
        Ok(())
    }

    fn add_polynomials_to_memory(
        &mut self,
        polynomials: Polynomials<T::ArithmeticShare, P::ScalarField, ECCVMFlavour>,
    ) {
        let mut memory =
            AllEntities::<Vec<T::ArithmeticShare>, Vec<P::ScalarField>, ECCVMFlavour>::default();
        *memory.witness.lookup_inverses_mut() = self.memory.lookup_inverses.to_owned().into_vec();

        // Copy the (non-shifted) witness polynomials
        for (des, src) in izip!(
            memory.witness.non_shifted_mut(),
            polynomials.witness.non_shifted()
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
