#![expect(unused)]
use crate::eccvm::eccvm_types::TranslationData;
use crate::ipa::compute_ipa_opening_proof;
use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_ff::Field;
use ark_ff::One;
use ark_ff::PrimeField;
use ark_ff::Zero;
use co_builder::HonkProofError;
use co_builder::flavours::eccvm_flavour::ECCVMFlavour;
use co_builder::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::ProverWitnessEntitiesFlavour;
use co_builder::{
    HonkProofResult, TranscriptFieldType,
    prelude::{HonkCurve, Polynomial, ProverCrs},
};
use itertools::izip;
use rand_chacha::ChaCha12Rng;
use ultrahonk::NUM_SMALL_IPA_EVALUATIONS;
use ultrahonk::prelude::HonkProof;
use ultrahonk::prelude::OpeningPair;
use ultrahonk::prelude::ShpleminiOpeningClaim;
use ultrahonk::{
    Utils as UltraHonkUtils,
    prelude::{
        Decider, ProvingKey, SmallSubgroupIPAProver, SumcheckOutput, Transcript, TranscriptHasher,
        ZKSumcheckData,
    },
};

//TODO FLORIN MOVE THIS SOMEWHERE ELSE LATER
pub(crate) const CONST_ECCVM_LOG_N: usize = 16;
pub(crate) const ECCVM_FIXED_SIZE: usize = 1usize << CONST_ECCVM_LOG_N;
const NUM_RELATIONS: usize = 7;
const NUM_TRANSLATION_OPENING_CLAIMS: usize = NUM_SMALL_IPA_EVALUATIONS + 1;
const NUM_OPENING_CLAIMS: usize = NUM_TRANSLATION_OPENING_CLAIMS + 1;

pub(crate) struct ProverMemory<P: CurveGroup> {
    pub(crate) z_perm: Polynomial<P::ScalarField>,
    pub(crate) lookup_inverses: Polynomial<P::ScalarField>,
    pub(crate) opening_claims: [ShpleminiOpeningClaim<P::ScalarField>; NUM_OPENING_CLAIMS],
}

struct Eccvm<P: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>> {
    //TODO FLORIN: I dont think this is the nicest way to do this, think about it later
    decider: Decider<P, H, ECCVMFlavour>,
    memory: ProverMemory<P>, //This is somewhat equivalent to the Oink Memory (i.e stores the lookup_inverses and z_perm)
}

// This happens when we construct the eccvm prover from the eccopqueue
impl<P: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>> Eccvm<P, H> {
    /// A uniform method to mask, commit, and send the corresponding commitment to the verifier.
    fn commit_to_witness_polynomial(
        &mut self,
        polynomial: &mut Polynomial<P::ScalarField>,
        label: &str,
        crs: &ProverCrs<P>,
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> HonkProofResult<()> {
        polynomial.mask(&mut self.decider.rng);

        // Commit to the polynomial
        let commitment = UltraHonkUtils::commit(polynomial.as_ref(), crs)?;
        // Send the commitment to the verifier
        transcript.send_point_to_verifier::<P>(label.to_string(), commitment.into());

        Ok(())
    }

    fn construct_proof(
        &mut self,
        mut transcript: Transcript<TranscriptFieldType, H>,
        proving_key: &mut ProvingKey<P, ECCVMFlavour>,
    ) -> HonkProofResult<(
        HonkProof<TranscriptFieldType>,
        HonkProof<TranscriptFieldType>,
    )> {
        let circuit_size = proving_key.circuit_size;
        self.execute_wire_commitments_round(&mut transcript, proving_key);
        self.execute_log_derivative_commitments_round(&mut transcript, proving_key);
        self.execute_grand_product_computation_round(&mut transcript, proving_key);
        let (sumcheck_output, zk_sumcheck_data) =
            self.execute_relation_check_rounds(&mut transcript, &proving_key.crs, circuit_size)?;

        let ipa_transcript = self.execute_pcs_rounds(
            sumcheck_output,
            zk_sumcheck_data,
            &mut transcript,
            proving_key,
            circuit_size,
        )?;

        Ok((transcript.get_proof(), ipa_transcript.get_proof()))
    }

    fn execute_wire_commitments_round(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &mut ProvingKey<P, ECCVMFlavour>,
    ) -> HonkProofResult<()> {
        let non_shifted = proving_key.polynomials.witness.non_shifted_mut();
        let first_labels = ECCVMFlavour::non_shifted_labels();
        let second_labels = ECCVMFlavour::to_be_shifted_without_accumulators_labels();
        let third_labels = ECCVMFlavour::to_be_shifted_accumulators_labels();

        for (wire, label) in non_shifted.iter_mut().zip(first_labels.iter()) {
            self.commit_to_witness_polynomial(wire, label, &proving_key.crs, transcript)?;
        }
        let to_be_shifted_without_accumulators = proving_key
            .polynomials
            .witness
            .to_be_shifted_without_accumulators_mut();
        for (wire, label) in to_be_shifted_without_accumulators
            .iter_mut()
            .zip(second_labels.iter())
        {
            self.commit_to_witness_polynomial(wire, label, &proving_key.crs, transcript)?;
        }
        let to_be_shifted_accumulators = proving_key
            .polynomials
            .witness
            .to_be_shifted_accumulators_mut();
        for (wire, label) in to_be_shifted_accumulators
            .iter_mut()
            .zip(third_labels.iter())
        {
            self.commit_to_witness_polynomial(wire, label, &proving_key.crs, transcript)?;
        }
        Ok(())
    }

    fn compute_read_term(
        &self,
        proving_key: &ProvingKey<P, ECCVMFlavour>,
        i: usize,
        read_index: usize,
    ) -> P::ScalarField {
        tracing::trace!("compute read term");

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
        let current_pc = *msm_pc - *msm_count;

        let read_term1 =
            current_pc + *gamma + *msm_slice1 * *beta + *msm_x1 * *beta_sqr + *msm_y1 * *beta_cube;
        let read_term2 = (current_pc - P::ScalarField::from(1))
            + *gamma
            + *msm_slice2 * *beta
            + *msm_x2 * *beta_sqr
            + *msm_y2 * *beta_cube;
        let read_term3 = (current_pc - P::ScalarField::from(2))
            + *gamma
            + *msm_slice3 * *beta
            + *msm_x3 * *beta_sqr
            + *msm_y3 * *beta_cube;
        let read_term4 = (current_pc - P::ScalarField::from(3))
            + *gamma
            + *msm_slice4 * *beta
            + *msm_x4 * *beta_sqr
            + *msm_y4 * *beta_cube;

        match read_index {
            0 => read_term1, // degree 1
            1 => read_term2, // degree 1
            2 => read_term3, // degree 1
            3 => read_term4, // degree 1
            _ => panic!("Invalid read index: {read_index}"),
        }
    }

    fn compute_write_term(
        &self,
        proving_key: &ProvingKey<P, ECCVMFlavour>,
        i: usize,
        write_idx: usize,
    ) -> P::ScalarField {
        tracing::trace!("compute write term");

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

        let negative_term = *precompute_pc + *gamma + *precompute_round * *beta + *tx * *beta_sqr
            - *ty * *beta_cube;
        let positive_slice_value = -*precompute_round + P::ScalarField::from(15);
        let positive_term = *precompute_pc
            + *gamma
            + positive_slice_value * *beta
            + *tx * *beta_sqr
            + *ty * *beta_cube;

        // todo optimize this?
        match write_idx {
            0 => positive_term, // degree 1
            1 => negative_term, // degree 1
            _ => panic!("Invalid write index: {write_idx}"),
        }
    }

    fn compute_logderivative_inverses(&mut self, proving_key: &ProvingKey<P, ECCVMFlavour>) {
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

        // // 1 + polynomial degree of this relation
        // const LENGTH: usize = 5; // both subrelations are degree 4

        for (i, (msm_add, msm_skew, precompute_select)) in izip!(
            proving_key.polynomials.witness.msm_add().iter(),
            proving_key.polynomials.witness.msm_skew().iter(),
            proving_key.polynomials.witness.precompute_select().iter(),
        )
        .enumerate()
        {
            // (row.msm_add == 1) || (row.msm_skew == 1) || (row.precompute_select == 1)
            if !(msm_add.is_one() || msm_skew.is_one() || precompute_select.is_one()) {
                continue;
            }

            let read_terms = 4;
            let write_terms = 2;
            let mut denominator = P::ScalarField::one();
            for read_idx in 0..read_terms {
                let read_term = self.compute_read_term(proving_key, i, read_idx);
                denominator *= read_term;
            }
            for write_idx in 0..write_terms {
                let write_term = self.compute_write_term(proving_key, i, write_idx);
                denominator *= write_term;
            }

            self.memory.lookup_inverses[i] = denominator;
        }

        // Compute inverse polynomial I in place by inverting the product at each row
        // Note: zeroes are ignored as they are not used anyway
        UltraHonkUtils::batch_invert(self.memory.lookup_inverses.as_mut());
    }

    fn execute_log_derivative_commitments_round(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &mut ProvingKey<P, ECCVMFlavour>,
    ) -> HonkProofResult<()> {
        // // Compute and add beta to relation parameters
        let challs = transcript.get_challenges::<P>(&["BETA".to_string(), "GAMMA".to_string()]);
        let beta = challs[0];
        let gamma = challs[1];
        // // AZTEC TODO(#583)(@zac-williamson): fix Transcript to be able to generate more than 2 challenges per round! oof.
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

        // // Compute inverse polynomial for our logarithmic-derivative lookup method
        self.compute_logderivative_inverses(proving_key);

        let mut lookup_inverses_tmp = std::mem::take(&mut self.memory.lookup_inverses);
        self.commit_to_witness_polynomial(
            &mut lookup_inverses_tmp,
            "LOOKUP_INVERSES",
            &proving_key.crs,
            transcript,
        )?;
        std::mem::swap(&mut self.memory.lookup_inverses, &mut lookup_inverses_tmp);
        Ok(())
    }

    fn compute_grand_product_numerator(
        &self,
        proving_key: &ProvingKey<P, ECCVMFlavour>,
        i: usize,
    ) -> P::ScalarField {
        tracing::trace!("compute grand product numerator");

        let precompute_round = &proving_key.polynomials.witness.precompute_round()[i];
        let precompute_round2 = *precompute_round + *precompute_round;
        let precompute_round4 = precompute_round2 + precompute_round2;

        let gamma = &self.decider.memory.relation_parameters.gamma;
        let beta = &self.decider.memory.relation_parameters.beta;
        let beta_sqr = &self.decider.memory.relation_parameters.beta_sqr;
        let beta_cube = &self.decider.memory.relation_parameters.beta_cube;
        let precompute_pc = &proving_key.polynomials.witness.precompute_pc()[i];
        let precompute_select = &proving_key.polynomials.witness.precompute_select()[i];

        // First term: tuple of (pc, round, wnaf_slice), computed when slicing scalar multipliers into slices,
        // as part of ECCVMWnafRelation.
        // If precompute_select = 1, tuple entry = (wnaf-slice + point-counter * beta + msm-round * beta_sqr).
        // There are 4 tuple entries per row.
        let mut numerator = P::ScalarField::one(); // degree-0

        let s0 = &proving_key.polynomials.witness.precompute_s1hi()[i];
        let s1 = &proving_key.polynomials.witness.precompute_s1lo()[i];

        let mut wnaf_slice = *s0 + *s0;
        wnaf_slice += wnaf_slice;
        wnaf_slice += *s1;

        let wnaf_slice_input0 =
            wnaf_slice + *gamma + *precompute_pc * *beta + precompute_round4 * *beta_sqr;
        numerator *= wnaf_slice_input0; // degree-1

        let s0 = &proving_key.polynomials.witness.precompute_s2hi()[i];
        let s1 = &proving_key.polynomials.witness.precompute_s2lo()[i];

        let mut wnaf_slice = *s0 + *s0;
        wnaf_slice += wnaf_slice;
        wnaf_slice += *s1;

        let wnaf_slice_input1 = wnaf_slice
            + *gamma
            + *precompute_pc * *beta
            + (precompute_round4 + P::ScalarField::from(1)) * *beta_sqr;
        numerator *= wnaf_slice_input1; // degree-2

        let s0 = &proving_key.polynomials.witness.precompute_s3hi()[i];
        let s1 = &proving_key.polynomials.witness.precompute_s3lo()[i];

        let mut wnaf_slice = *s0 + *s0;
        wnaf_slice += wnaf_slice;
        wnaf_slice += *s1;

        let wnaf_slice_input2 = wnaf_slice
            + *gamma
            + *precompute_pc * *beta
            + (precompute_round4 + P::ScalarField::from(2)) * *beta_sqr;
        numerator *= wnaf_slice_input2; // degree-3

        let s0 = &proving_key.polynomials.witness.precompute_s4hi()[i];
        let s1 = &proving_key.polynomials.witness.precompute_s4lo()[i];

        let mut wnaf_slice = *s0 + *s0;
        wnaf_slice += wnaf_slice;
        wnaf_slice += *s1;

        let wnaf_slice_input3 = wnaf_slice
            + *gamma
            + *precompute_pc * *beta
            + (precompute_round4 + P::ScalarField::from(3)) * *beta_sqr;
        numerator *= wnaf_slice_input3; // degree-4

        // skew product if relevant
        let skew = &proving_key.polynomials.witness.precompute_skew()[i];
        let precompute_point_transition = &proving_key
            .polynomials
            .witness
            .precompute_point_transition()[i];
        let skew_input = *precompute_point_transition
            * (*skew
                + *gamma
                + *precompute_pc * *beta
                + (precompute_round4 + P::ScalarField::from(4)) * *beta_sqr)
            + (-*precompute_point_transition + P::ScalarField::one());
        numerator *= skew_input; // degree-5

        let eccvm_set_permutation_delta = &self
            .decider
            .memory
            .relation_parameters
            .eccvm_set_permutation_delta;
        numerator *= *precompute_select * (-*eccvm_set_permutation_delta + P::ScalarField::one())
            + *eccvm_set_permutation_delta; // degree-7

        // Second term: tuple of (point-counter, P.x, P.y, scalar-multiplier), used in ECCVMWnafRelation and
        // ECCVMPointTableRelation. ECCVMWnafRelation validates the sum of the wnaf slices associated with point-counter
        // equals scalar-multiplier. ECCVMPointTableRelation computes a table of multiples of [P]: { -15[P], -13[P], ...,
        // 15[P] }. We need to validate that scalar-multiplier and [P] = (P.x, P.y) come from MUL opcodes in the transcript
        // columns.

        fn convert_to_wnaf<F: PrimeField>(s0: &F, s1: &F) -> F {
            let mut t = *s0 + s0;
            t += t;
            t += s1;

            t + t - F::from(15u32)
        }

        let table_x = &proving_key.polynomials.witness.precompute_tx()[i];
        let table_y = &proving_key.polynomials.witness.precompute_ty()[i];

        let precompute_skew = &proving_key.polynomials.witness.precompute_skew()[i];
        let negative_inverse_seven = P::ScalarField::from(-7)
            .inverse()
            .expect("-7 is hopefully non-zero");
        let adjusted_skew = *precompute_skew * negative_inverse_seven;

        let wnaf_scalar_sum = &proving_key.polynomials.witness.precompute_scalar_sum()[i];
        let w0 = convert_to_wnaf::<P::ScalarField>(
            &proving_key.polynomials.witness.precompute_s1hi()[i],
            &proving_key.polynomials.witness.precompute_s1lo()[i],
        );
        let w1 = convert_to_wnaf::<P::ScalarField>(
            &proving_key.polynomials.witness.precompute_s2hi()[i],
            &proving_key.polynomials.witness.precompute_s2lo()[i],
        );
        let w2 = convert_to_wnaf::<P::ScalarField>(
            &proving_key.polynomials.witness.precompute_s3hi()[i],
            &proving_key.polynomials.witness.precompute_s3lo()[i],
        );
        let w3 = convert_to_wnaf::<P::ScalarField>(
            &proving_key.polynomials.witness.precompute_s4hi()[i],
            &proving_key.polynomials.witness.precompute_s4lo()[i],
        );

        let mut row_slice = w0;
        row_slice += row_slice;
        row_slice += row_slice;
        row_slice += row_slice;
        row_slice += row_slice;
        row_slice += w1;
        row_slice += row_slice;
        row_slice += row_slice;
        row_slice += row_slice;
        row_slice += row_slice;
        row_slice += w2;
        row_slice += row_slice;
        row_slice += row_slice;
        row_slice += row_slice;
        row_slice += row_slice;
        row_slice += w3;

        let mut scalar_sum_full = *wnaf_scalar_sum;
        scalar_sum_full += scalar_sum_full;
        scalar_sum_full += scalar_sum_full;
        scalar_sum_full += scalar_sum_full;
        scalar_sum_full += scalar_sum_full;
        scalar_sum_full += scalar_sum_full;
        scalar_sum_full += scalar_sum_full;
        scalar_sum_full += scalar_sum_full;
        scalar_sum_full += scalar_sum_full;
        scalar_sum_full += scalar_sum_full;
        scalar_sum_full += scalar_sum_full;
        scalar_sum_full += scalar_sum_full;
        scalar_sum_full += scalar_sum_full;
        scalar_sum_full += scalar_sum_full;
        scalar_sum_full += scalar_sum_full;
        scalar_sum_full += scalar_sum_full;
        scalar_sum_full += row_slice + adjusted_skew;

        let precompute_point_transition = &proving_key
            .polynomials
            .witness
            .precompute_point_transition()[i];

        let mut point_table_init_read =
            *precompute_pc + *table_x * *beta + *table_y * *beta_sqr + scalar_sum_full * *beta_cube;
        point_table_init_read = *precompute_point_transition * (point_table_init_read + *gamma)
            + (-*precompute_point_transition + P::ScalarField::one());

        numerator *= point_table_init_read; // degree-9

        // Third term: tuple of (point-counter, P.x, P.y, msm-size) from ECCVMMSMRelation.
        // (P.x, P.y) is the output of a multi-scalar-multiplication evaluated in ECCVMMSMRelation.
        // We need to validate that the same values (P.x, P.y) are present in the Transcript columns and describe a
        // multi-scalar multiplication of size `msm-size`, starting at `point-counter`.

        let lagrange_first = &proving_key.polynomials.precomputed.lagrange_first()[i];
        let partial_msm_transition_shift =
            &proving_key.polynomials.witness.msm_transition_shift()[i];
        let msm_transition_shift =
            (-*lagrange_first + P::ScalarField::one()) * *partial_msm_transition_shift;
        let msm_pc_shift = &proving_key.polynomials.witness.msm_pc_shift()[i];

        let msm_x_shift = &proving_key.polynomials.witness.msm_accumulator_x_shift()[i];
        let msm_y_shift = &proving_key.polynomials.witness.msm_accumulator_y_shift()[i];
        let msm_size = &proving_key.polynomials.witness.msm_size_of_msm()[i];

        let mut msm_result_write = *msm_pc_shift
            + *msm_x_shift * *beta
            + *msm_y_shift * *beta_sqr
            + *msm_size * *beta_cube;

        msm_result_write = msm_transition_shift * (msm_result_write + *gamma)
            + (-msm_transition_shift + P::ScalarField::one());
        numerator *= msm_result_write; // degree-11

        numerator
    }

    fn compute_grand_product_denominator(
        &self,
        proving_key: &ProvingKey<P, ECCVMFlavour>,
        i: usize,
    ) -> P::ScalarField {
        tracing::trace!("compute grand product denominator");

        // AZTEC TODO(@zac-williamson). The degree of this contribution is 17! makes overall relation degree 19.
        // Can optimise by refining the algebra, once we have a stable base to iterate off of.
        let gamma = &self.decider.memory.relation_parameters.gamma;
        let beta = &self.decider.memory.relation_parameters.beta;
        let beta_sqr = &self.decider.memory.relation_parameters.beta_sqr;
        let beta_cube = &self.decider.memory.relation_parameters.beta_cube;
        let msm_pc = &proving_key.polynomials.witness.msm_pc()[i];
        let msm_count = &proving_key.polynomials.witness.msm_count()[i];
        let msm_round = &proving_key.polynomials.witness.msm_round()[i];

        /*
         * @brief First term: tuple of (pc, round, wnaf_slice), used to determine which points we extract from lookup tables
         * when evaluaing MSMs in ECCVMMsmRelation.
         * These values must be equivalent to the values computed in the 1st term of `compute_grand_product_numerator`
         */
        let mut denominator = P::ScalarField::one(); // degree-0

        let add1 = &proving_key.polynomials.witness.msm_add1()[i];
        let msm_slice1 = &proving_key.polynomials.witness.msm_slice1()[i];

        let wnaf_slice_output1 = *add1
            * (*msm_slice1 + *gamma + (*msm_pc - *msm_count) * *beta + *msm_round * *beta_sqr)
            + (-*add1 + P::ScalarField::one());
        denominator *= wnaf_slice_output1; // degree-2

        let add2 = &proving_key.polynomials.witness.msm_add2()[i];
        let msm_slice2 = &proving_key.polynomials.witness.msm_slice2()[i];

        let wnaf_slice_output2 = *add2
            * (*msm_slice2
                + *gamma
                + (*msm_pc - *msm_count - P::ScalarField::one()) * *beta
                + *msm_round * *beta_sqr)
            + (-*add2 + P::ScalarField::one());
        denominator *= wnaf_slice_output2; // degree-4

        let add3 = &proving_key.polynomials.witness.msm_add3()[i];
        let msm_slice3 = &proving_key.polynomials.witness.msm_slice3()[i];

        let wnaf_slice_output3 = *add3
            * (*msm_slice3
                + *gamma
                + (*msm_pc - *msm_count - P::ScalarField::from(2)) * *beta
                + *msm_round * *beta_sqr)
            + (-*add3 + P::ScalarField::one());
        denominator *= wnaf_slice_output3; // degree-6

        let add4 = &proving_key.polynomials.witness.msm_add4()[i];
        let msm_slice4 = &proving_key.polynomials.witness.msm_slice4()[i];

        let wnaf_slice_output4 = *add4
            * (*msm_slice4
                + *gamma
                + (*msm_pc - *msm_count - P::ScalarField::from(3)) * *beta
                + *msm_round * *beta_sqr)
            + (-*add4 + P::ScalarField::one());
        denominator *= wnaf_slice_output4; // degree-8

        /*
         * @brief Second term: tuple of (transcript_pc, transcript_Px, transcript_Py, z1) OR (transcript_pc, \lambda *
         * transcript_Px, -transcript_Py, z2) for each scalar multiplication in ECCVMTranscriptRelation columns. (the latter
         * term uses the curve endomorphism: \lambda = cube root of unity). These values must be equivalent to the second
         * term values in `compute_grand_product_numerator`
         */
        let transcript_pc = &proving_key.polynomials.witness.transcript_pc()[i];
        let transcript_px = &proving_key.polynomials.witness.transcript_px()[i];
        let transcript_py = &proving_key.polynomials.witness.transcript_py()[i];
        let z1 = &proving_key.polynomials.witness.transcript_z1()[i];
        let z2 = &proving_key.polynomials.witness.transcript_z2()[i];
        let z1_zero = &proving_key.polynomials.witness.transcript_z1zero()[i];
        let z2_zero = &proving_key.polynomials.witness.transcript_z2zero()[i];
        let base_infinity = &proving_key.polynomials.witness.transcript_base_infinity()[i];
        let transcript_mul = &proving_key.polynomials.witness.transcript_mul()[i];

        let lookup_first = -(*z1_zero) + P::ScalarField::one();
        let lookup_second = -(*z2_zero) + P::ScalarField::one();
        let endomorphism_base_field_shift = P::ScalarField::get_root_of_unity(3)
            .expect("3rd root of unity should exist in the field");

        let mut transcript_input1 =
            *transcript_pc + *transcript_px * *beta + *transcript_py * *beta_sqr + *z1 * *beta_cube; // degree = 1
        let mut transcript_input2 = (*transcript_pc - P::ScalarField::one())
            + *transcript_px * endomorphism_base_field_shift * *beta
            - *transcript_py * *beta_sqr
            + *z2 * *beta_cube; // degree = 2

        transcript_input1 =
            (transcript_input1 + *gamma) * lookup_first + (-lookup_first + P::ScalarField::one()); // degree 2
        transcript_input2 =
            (transcript_input2 + *gamma) * lookup_second + (-lookup_second + P::ScalarField::one()); // degree 3

        let transcript_product = (transcript_input1 * transcript_input2)
            * (-*base_infinity + P::ScalarField::one())
            + *base_infinity; // degree 6

        let point_table_init_write =
            *transcript_mul * transcript_product + (-*transcript_mul + P::ScalarField::one());
        denominator *= point_table_init_write; // degree 17

        /*
         * @brief Third term: tuple of (point-counter, P.x, P.y, msm-size) from ECCVMTranscriptRelation.
         *        (P.x, P.y) is the *claimed* output of a multi-scalar-multiplication evaluated in ECCVMMSMRelation.
         *        We need to validate that the msm output produced in ECCVMMSMRelation is equivalent to the output present
         * in `transcript_msm_output_x, transcript_msm_output_y`, for a given multi-scalar multiplication starting at
         * `transcript_pc` and has size `transcript_msm_count`
         */
        let transcript_pc_shift = &proving_key.polynomials.witness.transcript_pc_shift()[i];
        let transcript_msm_x = &proving_key.polynomials.witness.transcript_msm_x()[i];
        let transcript_msm_y = &proving_key.polynomials.witness.transcript_msm_y()[i];
        let transcript_msm_transition =
            &proving_key.polynomials.witness.transcript_msm_transition()[i];
        let transcript_msm_count = &proving_key.polynomials.witness.transcript_msm_count()[i];
        let z1_zero = &proving_key.polynomials.witness.transcript_z1zero()[i];
        let z2_zero = &proving_key.polynomials.witness.transcript_z2zero()[i];
        let transcript_mul = &proving_key.polynomials.witness.transcript_mul()[i];
        let base_infinity = &proving_key.polynomials.witness.transcript_base_infinity()[i];

        let full_msm_count = *transcript_msm_count
            + *transcript_mul
                * ((-*z1_zero + P::ScalarField::one()) + (-*z2_zero + P::ScalarField::one()))
                * (-*base_infinity + P::ScalarField::one());

        let mut msm_result_read = *transcript_pc_shift
            + *transcript_msm_x * *beta
            + *transcript_msm_y * *beta_sqr
            + full_msm_count * *beta_cube;
        msm_result_read = *transcript_msm_transition * (msm_result_read + *gamma)
            + (-*transcript_msm_transition + P::ScalarField::one());
        denominator *= msm_result_read; // degree-20

        denominator
    }

    fn compute_grand_product(&mut self, proving_key: &ProvingKey<P, ECCVMFlavour>) {
        tracing::trace!("compute grand product");

        let has_active_ranges = proving_key.active_region_data.size() > 0;

        // Barretenberg uses multithreading here

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
            denominator.push(self.compute_grand_product_denominator(proving_key, idx));
        }

        // Step (2)
        // Compute the accumulating product of the numerator and denominator terms.
        // In Barretenberg, this is done in parallel across multiple threads, however we just do the computation signlethreaded for simplicity

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

    fn execute_grand_product_computation_round(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &ProvingKey<P, ECCVMFlavour>,
    ) -> HonkProofResult<()> {
        // // Compute permutation grand product and their commitments
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
        SumcheckOutput<P::ScalarField, ECCVMFlavour>,
        ZKSumcheckData<P>,
    )> {
        self.decider.memory.relation_parameters.alphas =
            transcript.get_challenge::<P>("Sumcheck:alpha".to_string());
        let mut gate_challenges: Vec<P::ScalarField> = Vec::with_capacity(CONST_ECCVM_LOG_N);

        todo!("Add polynomials to the decider memory");

        for idx in 0..CONST_ECCVM_LOG_N {
            let chall = transcript.get_challenge::<P>(format!("Sumcheck:gate_challenge_{idx}"));
            gate_challenges.push(chall);
        }
        let log_subgroup_size = UltraHonkUtils::get_msb64(P::SUBGROUP_SIZE as u64);
        let commitment_key = &crs.monomials[..1 << (log_subgroup_size + 1)];
        let mut zk_sumcheck_data: ZKSumcheckData<P> = ZKSumcheckData::<P>::new::<H, _>(
            UltraHonkUtils::get_msb64(circuit_size as u64) as usize,
            transcript,
            commitment_key,
            &mut self.decider.rng,
        )?;

        Ok((
            self.decider
                .sumcheck_prove_zk(transcript, circuit_size, &mut zk_sumcheck_data),
            zk_sumcheck_data,
        ))
    }

    fn execute_pcs_rounds(
        &mut self,
        sumcheck_output: SumcheckOutput<P::ScalarField, ECCVMFlavour>,
        zk_sumcheck_data: ZKSumcheckData<P>,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &ProvingKey<P, ECCVMFlavour>,
        circuit_size: u32,
    ) -> HonkProofResult<(Transcript<TranscriptFieldType, H>)> {
        let mut small_subgroup_ipa_prover = SmallSubgroupIPAProver::<_>::new::<H>(
            zk_sumcheck_data,
            sumcheck_output
                .claimed_libra_evaluation
                .expect("We have ZK"),
            "Translation:".to_string(),
            &sumcheck_output.challenges,
        )?;
        small_subgroup_ipa_prover.prove(transcript, &proving_key.crs, &mut self.decider.rng)?;

        let witness_polynomials = small_subgroup_ipa_prover.into_witness_polynomials();
        let multivariate_to_univariate_opening_claim = self.decider.shplemini_prove(
            transcript,
            circuit_size,
            &proving_key.crs,
            sumcheck_output,
            Some(witness_polynomials),
        )?;

        self.compute_translation_opening_claims(proving_key, transcript);

        self.memory.opening_claims[NUM_OPENING_CLAIMS - 1] =
            multivariate_to_univariate_opening_claim;

        // Reduce the opening claims to a single opening claim via Shplonk
        let batch_opening_claim = self.decider.shplonk_prove(
            self.memory.opening_claims.to_vec(),
            &proving_key.crs,
            transcript,
            None,
            0,
        )?;

        // Compute the opening proof for the batched opening claim with the univariate PCS

        let mut ipa_transcript = Transcript::<TranscriptFieldType, H>::new();
        compute_ipa_opening_proof(&mut ipa_transcript, batch_opening_claim, &proving_key.crs)?;
        Ok(ipa_transcript)
    }

    fn compute_translation_opening_claims(
        &mut self,
        proving_key: &ProvingKey<P, ECCVMFlavour>,
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> HonkProofResult<()> {
        tracing::trace!("compute translation opening claims");

        // Collect the polynomials to be batched
        let translation_polynomials = [
            proving_key.polynomials.witness.transcript_op(),
            proving_key.polynomials.witness.transcript_px(),
            proving_key.polynomials.witness.transcript_py(),
            proving_key.polynomials.witness.transcript_z1(),
            proving_key.polynomials.witness.transcript_z2(),
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
        let mut translation_data = TranslationData::new(
            &translation_polynomials,
            transcript,
            &proving_key.crs,
            &mut self.decider.rng,
        )?;

        // Get a challenge to evaluate the `translation_polynomials` as univariates
        let evaluation_challenge_x: P::ScalarField =
            transcript.get_challenge::<P>("Translation:evaluation_challenge_x".to_string());

        // Evaluate `translation_polynomial` as univariates and add their evaluations at x to the transcript
        let mut translation_evaluations = Vec::with_capacity(translation_polynomials.len());
        for (poly, label) in translation_polynomials.iter().zip(translation_labels) {
            let eval = poly.eval_poly(evaluation_challenge_x);
            transcript.send_fr_to_verifier::<P>(label, eval);
            translation_evaluations.push(eval);
        }

        // Get another challenge to batch the evaluations of the transcript polynomials
        let batching_challenge_v =
            transcript.get_challenge::<P>("Translation:batching_challenge_v".to_string());

        let mut translation_masking_term_prover = translation_data.compute_small_ipa_prover::<_>(
            evaluation_challenge_x,
            batching_challenge_v,
            transcript,
            &proving_key.crs,
        )?;

        translation_masking_term_prover.prove(
            transcript,
            &proving_key.crs,
            &mut self.decider.rng,
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
        for idx in 0..NUM_SMALL_IPA_EVALUATIONS {
            let witness_poly = &witness_polys[idx];
            let evaluation = witness_poly.eval_poly(evaluation_points[idx]);
            transcript.send_fr_to_verifier::<P>(evaluation_labels[idx].clone(), evaluation);
            self.memory.opening_claims[idx] = ShpleminiOpeningClaim {
                polynomial: witness_poly.clone(),
                opening_pair: OpeningPair {
                    challenge: evaluation_points[idx],
                    evaluation,
                },
                gemini_fold: false,
            };
        }

        // Compute the opening claim for the masked evaluations of `op`, `Px`, `Py`, `z1`, and `z2` at
        // `evaluation_challenge_x` batched by the powers of `batching_challenge_v`.
        let mut batched_translation_univariate = Polynomial::new(vec![
            P::ScalarField::zero();
            proving_key.circuit_size
                as usize
        ]);
        let mut batched_translation_evaluation = P::ScalarField::zero();
        let mut batching_scalar = P::ScalarField::one();
        for (polynomial, eval) in translation_polynomials
            .iter()
            .zip(translation_evaluations.iter())
        {
            batched_translation_univariate.add_scaled(polynomial, &batching_scalar);
            batched_translation_evaluation += *eval * batching_scalar;
            batching_scalar *= batching_challenge_v;
        }

        // Add the batched claim to the array of SmallSubgroupIPA opening claims.
        self.memory.opening_claims[NUM_SMALL_IPA_EVALUATIONS] = ShpleminiOpeningClaim {
            polynomial: batched_translation_univariate,
            opening_pair: OpeningPair {
                challenge: evaluation_challenge_x,
                evaluation: batched_translation_evaluation,
            },
            gemini_fold: false,
        };
        Ok(())
    }
}
