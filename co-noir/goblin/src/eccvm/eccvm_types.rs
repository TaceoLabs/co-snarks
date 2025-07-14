use crate::eccvm::ecc_op_queue::ECCOpQueue;
use crate::eccvm::ecc_op_queue::MSMRow;
use crate::eccvm::ecc_op_queue::ScalarMul;
use crate::eccvm::ecc_op_queue::VMOperation;
use crate::{
    ECCVM_FIXED_SIZE, NUM_WNAF_DIGIT_BITS, NUM_WNAF_DIGITS_PER_SCALAR, POINT_TABLE_SIZE,
    WNAF_DIGITS_PER_ROW,
};
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ff::One;
use ark_ff::PrimeField;
use ark_ff::Zero;
use co_builder::HonkProofResult;
use co_builder::TranscriptFieldType;
use co_builder::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use co_builder::prelude::HonkCurve;
use co_builder::prelude::NUM_DISABLED_ROWS_IN_SUMCHECK;
use co_builder::prelude::NUM_TRANSLATION_EVALUATIONS;
use co_builder::prelude::Polynomial;
use co_builder::prelude::ProverCrs;
use co_builder::prelude::Utils;
use co_builder::prelude::offset_generator_scaled;
use co_builder::{flavours::eccvm_flavour::ECCVMFlavour, prelude::Polynomials};
use num_bigint::BigUint;
use ultrahonk::Utils as UltraHonkUtils;
use ultrahonk::plain_prover_flavour::UnivariateTrait;
use ultrahonk::prelude::SmallSubgroupIPAProver;
use ultrahonk::prelude::Transcript;
use ultrahonk::prelude::TranscriptHasher;
use ultrahonk::prelude::Univariate;

#[derive(Default)]
pub(crate) struct TranslationData<P: CurveGroup> {
    // M(X) whose Lagrange coefficients are given by (m_0 || m_1 || ... || m_{NUM_TRANSLATION_EVALUATIONS-1} || 0 || ... || 0)
    pub(crate) concatenated_polynomial_lagrange: Polynomial<P::ScalarField>,

    // M(X) + Z_H(X) * R(X), where R(X) is a random polynomial of length = WITNESS_MASKING_TERM_LENGTH
    pub(crate) masked_concatenated_polynomial: Polynomial<P::ScalarField>,
    // Interpolation domain {1, g, \ldots, g^{SUBGROUP_SIZE - 1}} required for Lagrange interpolation
    pub(crate) interpolation_domain: Vec<P::ScalarField>,
}

impl<P: HonkCurve<TranscriptFieldType>> TranslationData<P> {
    pub(crate) fn new(interpolation_domain: Vec<P::ScalarField>) -> Self {
        Self {
            concatenated_polynomial_lagrange: Polynomial::new_zero(P::SUBGROUP_SIZE),
            masked_concatenated_polynomial: Polynomial::new_zero(P::SUBGROUP_SIZE * 2),
            interpolation_domain,
        }
    }
    pub(crate) fn construct_translation_data<
        H: TranscriptHasher<TranscriptFieldType>,
        R: rand::Rng + rand::CryptoRng,
    >(
        transcript_polynomials: &[Polynomial<P::ScalarField>],
        transcript: &mut Transcript<TranscriptFieldType, H>,
        crs: &ProverCrs<P>,
        rng: &mut R,
    ) -> HonkProofResult<Self> {
        // Create interpolation domain required for Lagrange interpolation
        let mut interpolation_domain = vec![P::ScalarField::one(); P::SUBGROUP_SIZE];
        let subgroup_generator = P::get_subgroup_generator();
        for idx in 1..P::SUBGROUP_SIZE {
            interpolation_domain[idx] = interpolation_domain[idx - 1] * subgroup_generator;
        }

        let mut translation_data = Self::new(interpolation_domain);

        // Concatenate the last entries of the `translation_polynomials`.

        translation_data.compute_concatenated_polynomials(transcript_polynomials, rng);

        // Commit to M(X) + Z_H(X)*R(X), where R is a random polynomial of WITNESS_MASKING_TERM_LENGTH.
        let commitment = UltraHonkUtils::commit(
            translation_data.masked_concatenated_polynomial.as_ref(),
            crs,
        )?;
        transcript.send_point_to_verifier::<P>(
            "Translation:concatenated_masking_term_commitment".to_string(),
            commitment.into(),
        );

        Ok(translation_data)
    }

    pub fn compute_small_ipa_prover<
        H: TranscriptHasher<TranscriptFieldType>,
        // R: rand::Rng + rand::CryptoRng,
    >(
        &mut self,
        evaluation_challenge_x: P::ScalarField,
        batching_challenge_v: P::ScalarField,
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> HonkProofResult<SmallSubgroupIPAProver<P>> {
        let mut small_ipa_prover = SmallSubgroupIPAProver::<P> {
            interpolation_domain: self.interpolation_domain.to_owned(),
            concatenated_polynomial: self.masked_concatenated_polynomial.to_owned(),
            libra_concatenated_lagrange_form: self.concatenated_polynomial_lagrange.to_owned(),
            challenge_polynomial: Polynomial::new_zero(SmallSubgroupIPAProver::<P>::SUBGROUP_SIZE),
            challenge_polynomial_lagrange: Polynomial::new_zero(
                SmallSubgroupIPAProver::<P>::SUBGROUP_SIZE,
            ),
            grand_sum_polynomial_unmasked: Polynomial::new_zero(
                SmallSubgroupIPAProver::<P>::SUBGROUP_SIZE,
            ),
            grand_sum_polynomial: Polynomial::new_zero(
                SmallSubgroupIPAProver::<P>::MASKED_GRAND_SUM_LENGTH,
            ),
            grand_sum_lagrange_coeffs: vec![
                P::ScalarField::zero();
                SmallSubgroupIPAProver::<P>::SUBGROUP_SIZE
            ],
            grand_sum_identity_polynomial: Polynomial::new_zero(
                SmallSubgroupIPAProver::<P>::GRAND_SUM_IDENTITY_LENGTH,
            ),
            grand_sum_identity_quotient: Polynomial::new_zero(
                SmallSubgroupIPAProver::<P>::QUOTIENT_LENGTH,
            ),
            claimed_inner_product: P::ScalarField::zero(),
            prefix_label: "Translator:".to_string(),
        };

        small_ipa_prover
            .compute_eccvm_challenge_polynomial(evaluation_challenge_x, batching_challenge_v);

        let mut claimed_inner_product = P::ScalarField::zero();
        for idx in 0..P::SUBGROUP_SIZE {
            claimed_inner_product += self.concatenated_polynomial_lagrange[idx]
                * small_ipa_prover.challenge_polynomial_lagrange[idx];
        }
        transcript.send_fr_to_verifier::<P>(
            "Translation:masking_term_eval".to_string(),
            claimed_inner_product,
        );
        small_ipa_prover.claimed_inner_product = claimed_inner_product;

        Ok(small_ipa_prover)
    }
    fn compute_concatenated_polynomials<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        transcript_polynomials: &[Polynomial<P::ScalarField>],
        rng: &mut R,
    ) {
        const WITNESS_MASKING_TERM_LENGTH: usize = 2;
        let circuit_size = transcript_polynomials[0].len();

        let mut coeffs_lagrange_subgroup = vec![P::ScalarField::zero(); P::SUBGROUP_SIZE];

        // Extract the Lagrange coefficients of the concatenated masking term from the transcript polynomials
        for poly_idx in 0..NUM_TRANSLATION_EVALUATIONS {
            for idx in 0..NUM_DISABLED_ROWS_IN_SUMCHECK {
                let idx_to_populate = poly_idx * NUM_DISABLED_ROWS_IN_SUMCHECK + idx;
                coeffs_lagrange_subgroup[idx_to_populate as usize] = transcript_polynomials
                    [poly_idx as usize]
                    [circuit_size - NUM_DISABLED_ROWS_IN_SUMCHECK as usize + idx as usize];
            }
        }
        self.concatenated_polynomial_lagrange = Polynomial {
            coefficients: coeffs_lagrange_subgroup,
        };

        // Generate the masking term
        let masking_scalars =
            Univariate::<P::ScalarField, WITNESS_MASKING_TERM_LENGTH>::get_random(rng);

        // Compute monomial coefficients of the concatenated polynomial
        let concatenated_monomial_form_unmasked = Polynomial::interpolate_from_evals(
            &self.interpolation_domain,
            &self.concatenated_polynomial_lagrange.coefficients,
            P::SUBGROUP_SIZE,
        );

        self.masked_concatenated_polynomial =
            Polynomial::new_zero(P::SUBGROUP_SIZE + WITNESS_MASKING_TERM_LENGTH);
        for idx in 0..P::SUBGROUP_SIZE {
            self.masked_concatenated_polynomial[idx] = concatenated_monomial_form_unmasked[idx];
        }

        // Mask the polynomial in monomial form.
        for idx in 0..WITNESS_MASKING_TERM_LENGTH {
            self.masked_concatenated_polynomial[idx] -= masking_scalars.evaluations[idx];
            self.masked_concatenated_polynomial[P::SUBGROUP_SIZE + idx] +=
                masking_scalars.evaluations[idx];
        }
    }
}

#[derive(Clone)]
struct VMState<C: CurveGroup> {
    pc: u32,
    count: u32,
    accumulator: C::Affine,
    msm_accumulator: C::Affine,
    is_accumulator_empty: bool,
}
impl<C: CurveGroup> VMState<C> {
    fn new() -> Self {
        Self {
            pc: 0,
            count: 0,
            accumulator: C::Affine::zero(),
            msm_accumulator: offset_generator_scaled::<C>(),
            is_accumulator_empty: true,
        }
    }
}

#[derive(Default)]
struct TranscriptRow<F: PrimeField> {
    transcript_msm_infinity: bool,
    accumulator_empty: bool,
    q_add: bool,
    q_mul: bool,
    q_eq: bool,
    q_reset_accumulator: bool,
    msm_transition: bool,
    pc: u32,
    msm_count: u32,
    msm_count_zero_at_transition: bool,
    base_x: F,
    base_y: F,
    base_infinity: bool,
    z1: BigUint,
    z2: BigUint,
    z1_zero: bool,
    z2_zero: bool,
    opcode: u32,

    accumulator_x: F,
    accumulator_y: F,
    msm_output_x: F,
    msm_output_y: F,
    transcript_msm_intermediate_x: F,
    transcript_msm_intermediate_y: F,

    transcript_add_x_equal: bool,
    transcript_add_y_equal: bool,

    base_x_inverse: F,
    base_y_inverse: F,
    transcript_add_lambda: F,
    transcript_msm_x_inverse: F,
    msm_count_at_transition_inverse: F,
}

impl<C: HonkCurve<TranscriptFieldType>> VMState<C> {
    fn process_mul(entry: &VMOperation<C>, updated_state: &mut VMState<C>, state: &VMState<C>) {
        let p = entry.base_point;
        let r = state.msm_accumulator;
        updated_state.msm_accumulator = (r + p * entry.mul_scalar_full).into();
    }

    fn process_add(entry: &VMOperation<C>, updated_state: &mut VMState<C>, state: &VMState<C>) {
        if state.is_accumulator_empty {
            updated_state.accumulator = entry.base_point;
        } else {
            updated_state.accumulator = (state.accumulator + entry.base_point).into();
        }
        updated_state.is_accumulator_empty = updated_state.accumulator.is_zero();
    }

    fn process_msm_transition(
        row: &mut TranscriptRow<C::BaseField>,
        updated_state: &mut VMState<C>,
        state: &VMState<C>,
    ) {
        if state.is_accumulator_empty {
            updated_state.accumulator =
                (updated_state.msm_accumulator - offset_generator_scaled::<C>()).into();
        } else {
            let r = state.accumulator;
            updated_state.accumulator =
                (r + updated_state.msm_accumulator - offset_generator_scaled::<C>()).into();
        }
        updated_state.is_accumulator_empty = updated_state.accumulator.is_zero();

        let msm_output = updated_state.msm_accumulator - offset_generator_scaled::<C>();
        row.transcript_msm_infinity = msm_output.is_zero();
    }

    fn populate_transcript_row(
        row: &mut TranscriptRow<C::BaseField>,
        entry: &VMOperation<C>,
        state: &VMState<C>,
        num_muls: u32,
        msm_transition: bool,
        next_not_msm: bool,
    ) {
        let base_point_infinity = entry.base_point.is_zero();

        row.accumulator_empty = state.is_accumulator_empty;
        row.q_add = entry.op_code.add;
        row.q_mul = entry.op_code.mul;
        row.q_eq = entry.op_code.eq;
        row.q_reset_accumulator = entry.op_code.reset;
        row.msm_transition = msm_transition;
        row.pc = state.pc;
        row.msm_count = state.count;
        row.msm_count_zero_at_transition =
            (state.count + num_muls == 0) && entry.op_code.mul && next_not_msm;
        row.base_x = if (entry.op_code.add || entry.op_code.mul || entry.op_code.eq)
            && !base_point_infinity
        {
            entry
                .base_point
                .x()
                .expect("Base point x should not be zero")
        } else {
            C::BaseField::zero()
        };
        row.base_y = if (entry.op_code.add || entry.op_code.mul || entry.op_code.eq)
            && !base_point_infinity
        {
            entry
                .base_point
                .y()
                .expect("Base point y should not be zero")
        } else {
            C::BaseField::zero()
        };
        row.base_infinity = if entry.op_code.add || entry.op_code.mul || entry.op_code.eq {
            base_point_infinity
        } else {
            false
        };
        row.z1 = if entry.op_code.mul {
            entry.z1.clone()
        } else {
            BigUint::zero()
        };
        row.z2 = if entry.op_code.mul {
            entry.z2.clone()
        } else {
            BigUint::zero()
        };
        row.z1_zero = entry.z1.is_zero();
        row.z2_zero = entry.z2.is_zero();
        row.opcode = entry.op_code.value();
    }
}

fn add_affine_coordinates_to_transcript<C: HonkCurve<TranscriptFieldType>>(
    transcript_state: &mut [TranscriptRow<C::BaseField>],
    accumulator_trace: &[C::Affine],
    msm_accumulator_trace: &[C::Affine],
    intermediate_accumulator_trace: &[C::Affine],
) {
    for i in 0..accumulator_trace.len() {
        let row = &mut transcript_state[i + 1];
        if !accumulator_trace[i].is_zero() {
            row.accumulator_x = accumulator_trace[i]
                .x()
                .expect("Accumulator x-coordinate should not be zero");
            row.accumulator_y = accumulator_trace[i]
                .y()
                .expect("Accumulator y-coordinate should not be zero");
        }
        if !msm_accumulator_trace[i].is_zero() {
            row.msm_output_x = msm_accumulator_trace[i]
                .x()
                .expect("MSM accumulator x-coordinate should not be zero");
            row.msm_output_y = msm_accumulator_trace[i]
                .y()
                .expect("MSM accumulator y-coordinate should not be zero");
        }
        if !intermediate_accumulator_trace[i].is_zero() {
            row.transcript_msm_intermediate_x = intermediate_accumulator_trace[i]
                .x()
                .expect("Intermediate accumulator x-coordinate should not be zero");
            row.transcript_msm_intermediate_y = intermediate_accumulator_trace[i]
                .y()
                .expect("Intermediate accumulator y-coordinate should not be zero");
        }
    }
}

#[expect(clippy::too_many_arguments)]
fn compute_inverse_trace_coordinates<C: HonkCurve<TranscriptFieldType>>(
    msm_transition: bool,
    row: &TranscriptRow<C::BaseField>,
    msm_output: &C::Affine,
    transcript_msm_x_inverse_trace: &mut C::BaseField,
    msm_accumulator_trace: &C::Affine,
    accumulator_trace: &C::Affine,
    inverse_trace_x: &mut C::BaseField,
    inverse_trace_y: &mut C::BaseField,
) {
    let msm_output_infinity = msm_output.is_zero();
    let row_msm_infinity = row.transcript_msm_infinity;

    *transcript_msm_x_inverse_trace = if row_msm_infinity {
        C::BaseField::zero()
    } else {
        msm_accumulator_trace
            .x()
            .unwrap_or(C::get_bb_infinity_default())
            - offset_generator_scaled::<C>()
                .x()
                .expect("Offset generator x-coordinate should not be zero")
    };

    let (lhsx, lhsy) = if msm_transition {
        if msm_output_infinity {
            (C::BaseField::zero(), C::BaseField::zero())
        } else {
            (
                msm_output
                    .x()
                    .expect("MSM output x-coordinate should not be zero"),
                msm_output
                    .y()
                    .expect("MSM output y-coordinate should not be zero"),
            )
        }
    } else {
        (row.base_x, row.base_y)
    };

    let (rhsx, rhsy) = if accumulator_trace.is_zero() {
        (C::BaseField::zero(), C::BaseField::zero())
    } else {
        (
            accumulator_trace
                .x()
                .expect("Accumulator x-coordinate should not be zero"),
            accumulator_trace
                .y()
                .expect("Accumulator y-coordinate should not be zero"),
        )
    };

    *inverse_trace_x = lhsx - rhsx;
    *inverse_trace_y = lhsy - rhsy;
}

fn compute_lambda_numerator_and_denominator<C: HonkCurve<TranscriptFieldType>>(
    row: &mut TranscriptRow<C::BaseField>,
    entry: &VMOperation<C>,
    intermediate_accumulator: &C::Affine,
    accumulator: &C::Affine,
    add_lambda_numerator: &mut C::BaseField,
    add_lambda_denominator: &mut C::BaseField,
) {
    let vm_point = if entry.op_code.add {
        entry.base_point
    } else {
        *intermediate_accumulator
    };

    let vm_infinity = vm_point.is_zero();
    let accumulator_infinity = accumulator.is_zero();

    let vm_x = if vm_infinity {
        C::BaseField::zero()
    } else {
        vm_point
            .x()
            .expect("VM point x-coordinate should not be zero")
    };
    let vm_y = if vm_infinity {
        C::BaseField::zero()
    } else {
        vm_point
            .y()
            .expect("VM point y-coordinate should not be zero")
    };

    let accumulator_x = if accumulator_infinity {
        C::BaseField::zero()
    } else {
        accumulator
            .x()
            .expect("Accumulator x-coordinate should not be zero")
    };
    let accumulator_y = if accumulator_infinity {
        C::BaseField::zero()
    } else {
        accumulator
            .y()
            .expect("Accumulator y-coordinate should not be zero")
    };

    row.transcript_add_x_equal = (vm_x == accumulator_x) || (vm_infinity && accumulator_infinity);
    row.transcript_add_y_equal = (vm_y == accumulator_y) || (vm_infinity && accumulator_infinity);

    if (accumulator_x == vm_x) && (accumulator_y == vm_y) && !vm_infinity && !accumulator_infinity {
        *add_lambda_denominator = vm_y + vm_y;
        *add_lambda_numerator = vm_x * vm_x * C::BaseField::from(3u32);
    } else if (accumulator_x != vm_x) && !vm_infinity && !accumulator_infinity {
        *add_lambda_denominator = accumulator_x - vm_x;
        *add_lambda_numerator = accumulator_y - vm_y;
    }
}

fn finalize_transcript<C: CurveGroup>(updated_state: &VMState<C>) -> TranscriptRow<C::BaseField>
where
    <C as CurveGroup>::BaseField: PrimeField,
{
    let mut final_row = TranscriptRow::<C::BaseField>::default();
    if updated_state.accumulator.is_zero() {
        final_row.accumulator_x = C::BaseField::zero();
        final_row.accumulator_y = C::BaseField::zero();
    } else {
        final_row.accumulator_x = updated_state
            .accumulator
            .x()
            .expect("Accumulator x-coordinate should not be zero");
        final_row.accumulator_y = updated_state
            .accumulator
            .y()
            .expect("Accumulator y-coordinate should not be zero");
    }
    final_row.pc = updated_state.pc;
    final_row.accumulator_empty = updated_state.is_accumulator_empty;
    final_row
}

fn compute_rows<C: HonkCurve<TranscriptFieldType>>(
    vm_operations: &[VMOperation<C>],
    total_number_of_muls: u32,
) -> Vec<TranscriptRow<C::BaseField>> {
    let num_vm_entries = vm_operations.len();
    // The transcript contains an extra zero row at the beginning and the accumulated state at the end
    let transcript_size = num_vm_entries + 2;
    let mut transcript_state = Vec::with_capacity(transcript_size);

    // These vectors track quantities that we need to invert.
    // We fill these vectors and then perform batch inversions to amortize the cost of FF inverts
    let mut inverse_trace_x = vec![C::BaseField::zero(); num_vm_entries];
    let mut inverse_trace_y = vec![C::BaseField::zero(); num_vm_entries];
    let mut transcript_msm_x_inverse_trace = vec![C::BaseField::zero(); num_vm_entries];
    let mut add_lambda_denominator = vec![C::BaseField::zero(); num_vm_entries];
    let mut add_lambda_numerator = vec![C::BaseField::zero(); num_vm_entries];
    let mut msm_count_at_transition_inverse_trace = vec![C::BaseField::zero(); num_vm_entries];

    let mut msm_accumulator_trace: Vec<C::Affine> = vec![C::zero().into(); num_vm_entries];
    let mut accumulator_trace: Vec<C::Affine> = vec![C::zero().into(); num_vm_entries];
    let mut intermediate_accumulator_trace: Vec<C::Affine> = vec![C::zero().into(); num_vm_entries];

    let mut state = VMState::<C> {
        pc: total_number_of_muls,
        count: 0,
        accumulator: C::zero().into(),
        msm_accumulator: offset_generator_scaled::<C>(),
        is_accumulator_empty: true,
    };

    let mut updated_state = VMState::<C>::new();

    // // add an empty row. 1st row all zeroes because of our shiftable polynomials
    transcript_state.push(TranscriptRow::<C::BaseField>::default());

    // // during the first iteration over the ECCOpQueue, the operations are being performed using Jacobian
    // // coordinates and the base point coordinates are recorded in the transcript. at the same time, the transcript
    // // logic is being populated
    for i in 0..num_vm_entries {
        let mut row = TranscriptRow::<C::BaseField>::default();
        let entry = &vm_operations[i];
        updated_state = state.clone();

        let is_mul: bool = entry.op_code.mul;
        let is_add: bool = entry.op_code.add;
        let z1_zero: bool = if is_mul { entry.z1.is_zero() } else { true };
        let z2_zero: bool = if is_mul { entry.z2.is_zero() } else { true };

        let base_point_infinity = entry.base_point.is_zero();
        let mut num_muls: u32 = 0;
        if is_mul {
            num_muls = (!z1_zero as u32) + (!z2_zero as u32);
            if base_point_infinity {
                num_muls = 0;
            }
        }
        updated_state.pc = state.pc - num_muls;

        if entry.op_code.reset {
            updated_state.is_accumulator_empty = true;
            updated_state.accumulator = C::zero().into();
            updated_state.msm_accumulator = offset_generator_scaled::<C>();
        }

        let last_row = i == (num_vm_entries - 1);

        // msm transition = current row is doing a lookup to validate output = msm output
        // i.e. next row is not part of MSM and current row is part of MSM
        //   or next row is irrelevant and current row is a straight MUL
        let next_not_msm = last_row || !vm_operations[i + 1].op_code.mul;

        //     // we reset the count in updated state if we are not accumulating and not doing an msm
        let msm_transition = is_mul && next_not_msm && (state.count + num_muls > 0);

        // determine ongoing msm and update the respective counter
        let current_ongoing_msm = is_mul && !next_not_msm;

        updated_state.count = if current_ongoing_msm {
            state.count + num_muls
        } else {
            0
        };

        if is_mul {
            VMState::<C>::process_mul(entry, &mut updated_state, &state);
        }

        if msm_transition {
            VMState::<C>::process_msm_transition(&mut row, &mut updated_state, &state);
        } else {
            msm_accumulator_trace[i] = C::zero().into();
            intermediate_accumulator_trace[i] = C::zero().into();
        }

        if is_add {
            VMState::<C>::process_add(entry, &mut updated_state, &state);
        }

        //     // populate the first group of TranscriptRow entries
        VMState::<C>::populate_transcript_row(
            &mut row,
            entry,
            &state,
            num_muls,
            msm_transition,
            next_not_msm,
        );

        msm_count_at_transition_inverse_trace[i] = if (state.count + num_muls) == 0 {
            C::BaseField::zero()
        } else {
            C::BaseField::from(state.count + num_muls)
        };

        //     // update the accumulators
        accumulator_trace[i] = state.accumulator;
        msm_accumulator_trace[i] = if msm_transition {
            updated_state.msm_accumulator
        } else {
            C::zero().into()
        };
        intermediate_accumulator_trace[i] = if msm_transition {
            (updated_state.msm_accumulator - offset_generator_scaled::<C>()).into()
        } else {
            C::zero().into()
        };

        state = updated_state.clone();

        if is_mul && next_not_msm {
            state.msm_accumulator = offset_generator_scaled::<C>();
        }
        transcript_state.push(row);
    }
    // compute affine coordinates of the accumulated points
    accumulator_trace = Utils::batch_normalize::<C>(&accumulator_trace);
    msm_accumulator_trace = Utils::batch_normalize::<C>(&msm_accumulator_trace);
    intermediate_accumulator_trace = Utils::batch_normalize::<C>(&intermediate_accumulator_trace);

    // add required affine coordinates to the transcript
    add_affine_coordinates_to_transcript::<C>(
        &mut transcript_state,
        &accumulator_trace,
        &msm_accumulator_trace,
        &intermediate_accumulator_trace,
    );

    // // process the slopes when adding points or results of MSMs. to increase efficiency, we use batch inversion
    // // after the loop
    for i in 0..accumulator_trace.len() {
        let row = &mut transcript_state[i + 1];
        let msm_transition = row.msm_transition;

        let entry = &vm_operations[i];
        let is_add = entry.op_code.add;

        if msm_transition || is_add {
            // compute the differences between point coordinates
            compute_inverse_trace_coordinates::<C>(
                msm_transition,
                row,
                &intermediate_accumulator_trace[i],
                &mut transcript_msm_x_inverse_trace[i],
                &msm_accumulator_trace[i],
                &accumulator_trace[i],
                &mut inverse_trace_x[i],
                &mut inverse_trace_y[i],
            );

            // compute the numerators and denominators of slopes between the points
            compute_lambda_numerator_and_denominator::<C>(
                row,
                entry,
                &intermediate_accumulator_trace[i],
                &accumulator_trace[i],
                &mut add_lambda_numerator[i],
                &mut add_lambda_denominator[i],
            );
        } else {
            row.transcript_add_x_equal = false;
            row.transcript_add_y_equal = false;
            add_lambda_numerator[i] = C::BaseField::zero();
            add_lambda_denominator[i] = C::BaseField::zero();
            inverse_trace_x[i] = C::BaseField::zero();
            inverse_trace_y[i] = C::BaseField::zero();
        }
    }

    // // Perform all required inversions at once
    ark_ff::batch_inversion(&mut inverse_trace_x);
    ark_ff::batch_inversion(&mut inverse_trace_y);
    ark_ff::batch_inversion(&mut transcript_msm_x_inverse_trace);
    ark_ff::batch_inversion(&mut add_lambda_denominator);
    ark_ff::batch_inversion(&mut msm_count_at_transition_inverse_trace);

    // // Populate the fields of the transcript row containing inverted scalars
    for i in 0..num_vm_entries {
        let row = &mut transcript_state[i + 1];
        row.base_x_inverse = inverse_trace_x[i];
        row.base_y_inverse = inverse_trace_y[i];
        row.transcript_msm_x_inverse = transcript_msm_x_inverse_trace[i];
        row.transcript_add_lambda = add_lambda_numerator[i] * add_lambda_denominator[i];
        row.msm_count_at_transition_inverse = msm_count_at_transition_inverse_trace[i];
    }

    // // process the final row containing the result of the sequence of group ops in ECCOpQueue
    let final_row = finalize_transcript(&updated_state);
    transcript_state.push(final_row);

    transcript_state
}
#[derive(Default, Clone, Debug)]
struct PointTablePrecomputationRow<C: CurveGroup> {
    s1: i32,
    s2: i32,
    s3: i32,
    s4: i32,
    s5: i32,
    s6: i32,
    s7: i32,
    s8: i32,
    skew: bool,
    point_transition: bool,
    pc: u32,
    round: u32,
    scalar_sum: BigUint,
    precompute_accumulator: C::Affine,
    precompute_double: C::Affine,
}

impl<C: HonkCurve<TranscriptFieldType>> PointTablePrecomputationRow<C> {
    fn compute_rows(msms: &[ScalarMul<C>]) -> Vec<PointTablePrecomputationRow<C>> {
        let num_rows_per_scalar = NUM_WNAF_DIGITS_PER_SCALAR / WNAF_DIGITS_PER_ROW;
        let num_precompute_rows = num_rows_per_scalar * msms.len() + 1;
        let mut precompute_state =
            vec![PointTablePrecomputationRow::<C>::default(); num_precompute_rows];

        // Start with an empty row (shiftable polynomials must have 0 as the first coefficient)
        precompute_state[0] = PointTablePrecomputationRow::<C>::default();

        // current impl doesn't work if not 4
        assert_eq!(WNAF_DIGITS_PER_ROW, 4);

        msms.iter().enumerate().for_each(|(j, entry)| {
            let slices = &entry.wnaf_digits;
            let mut scalar_sum = BigUint::zero();

            for i in 0..num_rows_per_scalar {
                let mut row = PointTablePrecomputationRow::<C>::default();
                let slice0 = slices[i * WNAF_DIGITS_PER_ROW];
                let slice1 = slices[i * WNAF_DIGITS_PER_ROW + 1];
                let slice2 = slices[i * WNAF_DIGITS_PER_ROW + 2];
                let slice3 = slices[i * WNAF_DIGITS_PER_ROW + 3];

                let slice0base2 = (slice0 + 15) / 2;
                let slice1base2 = (slice1 + 15) / 2;
                let slice2base2 = (slice2 + 15) / 2;
                let slice3base2 = (slice3 + 15) / 2;

                // Convert into 2-bit chunks
                row.s1 = slice0base2 >> 2;
                row.s2 = slice0base2 & 3;
                row.s3 = slice1base2 >> 2;
                row.s4 = slice1base2 & 3;
                row.s5 = slice2base2 >> 2;
                row.s6 = slice2base2 & 3;
                row.s7 = slice3base2 >> 2;
                row.s8 = slice3base2 & 3;

                let last_row = i == num_rows_per_scalar - 1;
                row.skew = if last_row { entry.wnaf_skew } else { false };
                row.scalar_sum = scalar_sum.clone();

                // Ensure slice1 is positive for the first row of each scalar sum
                let row_chunk = slice3 + (slice2 << 4) + (slice1 << 8) + (slice0 << 12);
                let chunk_negative = row_chunk < 0;

                scalar_sum <<= NUM_WNAF_DIGIT_BITS * WNAF_DIGITS_PER_ROW;
                if chunk_negative {
                    scalar_sum -= BigUint::from((-row_chunk) as u64);
                } else {
                    scalar_sum += BigUint::from(row_chunk as u64);
                }

                row.round = i as u32;
                row.point_transition = last_row;
                row.pc = entry.pc;

                if last_row {
                    assert_eq!(
                        scalar_sum.clone() - BigUint::from(entry.wnaf_skew as u64),
                        entry.scalar
                    );
                }

                row.precompute_double = entry.precomputed_table[POINT_TABLE_SIZE];
                // fill accumulator in reverse order i.e. first row = 15[P], then 13[P], ..., 1[P]
                row.precompute_accumulator = entry.precomputed_table[POINT_TABLE_SIZE - 1 - i];
                precompute_state[j * num_rows_per_scalar + i + 1] = row;
            }
        });
        precompute_state
    }
}
pub fn construct_from_builder<C: HonkCurve<TranscriptFieldType>>(
    op_queue: &mut ECCOpQueue<C::CycleGroup>,
) -> Polynomials<C::ScalarField, ECCVMFlavour> {
    let eccvm_ops = op_queue.get_eccvm_ops().to_vec();
    let number_of_muls = op_queue.get_number_of_muls();
    let transcript_rows = compute_rows::<C::CycleGroup>(&eccvm_ops, number_of_muls);
    let msms = op_queue.get_msms();
    let point_table_rows = PointTablePrecomputationRow::<C::CycleGroup>::compute_rows(
        &msms.iter().flat_map(|msm| msm.clone()).collect::<Vec<_>>(),
    );
    let result = MSMRow::<C::CycleGroup>::compute_rows_msms(
        &msms,
        number_of_muls,
        op_queue.get_num_msm_rows(),
    );
    let msm_rows = &result.0;
    let point_table_read_counts = &result.1;

    let num_rows = std::cmp::max(
        std::cmp::max(point_table_rows.len(), msm_rows.len()),
        transcript_rows.len(),
    ) + NUM_DISABLED_ROWS_IN_SUMCHECK as usize;
    let log_num_rows = num_rows.ilog2();
    let dyadic_num_rows = 1
        << (log_num_rows
            + if (1 << log_num_rows) == num_rows {
                0
            } else {
                1
            });

    if ECCVM_FIXED_SIZE < dyadic_num_rows {
        panic!(
            "The ECCVM circuit size has exceeded the fixed upper bound! Fixed size: {ECCVM_FIXED_SIZE} actual size: {dyadic_num_rows}"
        );
    }

    let dyadic_num_rows = ECCVM_FIXED_SIZE;

    let unmasked_witness_size = dyadic_num_rows - NUM_DISABLED_ROWS_IN_SUMCHECK as usize;
    let mut polys = Polynomials::<C::ScalarField, ECCVMFlavour>::new(dyadic_num_rows);

    polys.precomputed.lagrange_first_mut()[0] = C::ScalarField::one();
    polys.precomputed.lagrange_second_mut()[1] = C::ScalarField::one();
    polys.precomputed.lagrange_last_mut()[unmasked_witness_size - 1] = C::ScalarField::one();

    for i in 0..point_table_read_counts[0].len() {
        // Explanation of off-by-one offset:
        // When computing the WNAF slice for a point at point counter value `pc` and a round index `round`, the
        // row number that computes the slice can be derived. This row number is then mapped to the index of
        // `lookup_read_counts`. We do this mapping in `ecc_msm_relation`. We are off-by-one because we add an
        // empty row at the start of the WNAF columns that is not accounted for (index of lookup_read_counts
        // maps to the row in our WNAF columns that computes a slice for a given value of pc and round)
        polys.witness.lookup_read_counts_0_mut()[i + 1] =
            C::ScalarField::from(point_table_read_counts[0][i] as u32);
        polys.witness.lookup_read_counts_1_mut()[i + 1] =
            C::ScalarField::from(point_table_read_counts[1][i] as u32);
    }

    // Compute polynomials for transcript columns
    for (i, row) in transcript_rows.iter().enumerate() {
        polys.witness.transcript_accumulator_empty_mut()[i] =
            C::ScalarField::from(row.accumulator_empty);
        polys.witness.transcript_add_mut()[i] = C::ScalarField::from(row.q_add);
        polys.witness.transcript_mul_mut()[i] = C::ScalarField::from(row.q_mul);
        polys.witness.transcript_eq_mut()[i] = C::ScalarField::from(row.q_eq);
        polys.witness.transcript_reset_accumulator_mut()[i] =
            C::ScalarField::from(row.q_reset_accumulator);
        polys.witness.transcript_msm_transition_mut()[i] = C::ScalarField::from(row.msm_transition);
        polys.witness.transcript_pc_mut()[i] = C::ScalarField::from(row.pc);
        polys.witness.transcript_msm_count_mut()[i] = C::ScalarField::from(row.msm_count);
        polys.witness.transcript_px_mut()[i] = row.base_x;
        polys.witness.transcript_py_mut()[i] = row.base_y;
        polys.witness.transcript_z1_mut()[i] = C::ScalarField::from(row.z1.clone());
        polys.witness.transcript_z2_mut()[i] = C::ScalarField::from(row.z2.clone());
        polys.witness.transcript_z1zero_mut()[i] = C::ScalarField::from(row.z1_zero);
        polys.witness.transcript_z2zero_mut()[i] = C::ScalarField::from(row.z2_zero);
        polys.witness.transcript_op_mut()[i] = C::ScalarField::from(row.opcode);
        polys.witness.transcript_accumulator_x_mut()[i] = row.accumulator_x;
        polys.witness.transcript_accumulator_y_mut()[i] = row.accumulator_y;
        polys.witness.transcript_msm_x_mut()[i] = row.msm_output_x;
        polys.witness.transcript_msm_y_mut()[i] = row.msm_output_y;
        polys.witness.transcript_base_infinity_mut()[i] = C::ScalarField::from(row.base_infinity);
        polys.witness.transcript_base_x_inverse_mut()[i] = row.base_x_inverse;
        polys.witness.transcript_base_y_inverse_mut()[i] = row.base_y_inverse;
        polys.witness.transcript_add_x_equal_mut()[i] =
            C::ScalarField::from(row.transcript_add_x_equal);
        polys.witness.transcript_add_y_equal_mut()[i] =
            C::ScalarField::from(row.transcript_add_y_equal);
        polys.witness.transcript_add_lambda_mut()[i] = row.transcript_add_lambda;
        polys.witness.transcript_msm_intermediate_x_mut()[i] = row.transcript_msm_intermediate_x;
        polys.witness.transcript_msm_intermediate_y_mut()[i] = row.transcript_msm_intermediate_y;
        polys.witness.transcript_msm_infinity_mut()[i] =
            C::ScalarField::from(row.transcript_msm_infinity);
        polys.witness.transcript_msm_x_inverse_mut()[i] = row.transcript_msm_x_inverse;
        polys.witness.transcript_msm_count_zero_at_transition_mut()[i] =
            C::ScalarField::from(row.msm_count_zero_at_transition);
        polys
            .witness
            .transcript_msm_count_at_transition_inverse_mut()[i] =
            row.msm_count_at_transition_inverse;
    }

    // AZTEC TODO(@zac-williamson) if final opcode resets accumulator, all subsequent "is_accumulator_empty" row
    // values must be 1. Ideally we find a way to tweak this so that empty rows that do nothing have column
    // values that are all zero (issue #2217)
    if transcript_rows
        .last()
        .is_some_and(|row| row.accumulator_empty)
    {
        for i in transcript_rows.len()..unmasked_witness_size {
            polys.witness.transcript_accumulator_empty_mut()[i] = C::ScalarField::one();
        }
    }

    // in addition, unless the accumulator is reset, it contains the value from the previous row so this
    // must be propagated
    for i in transcript_rows.len()..unmasked_witness_size {
        polys.witness.transcript_accumulator_x_mut()[i] =
            polys.witness.transcript_accumulator_x_mut()[i - 1];
        polys.witness.transcript_accumulator_y_mut()[i] =
            polys.witness.transcript_accumulator_y_mut()[i - 1];
    }
    for (i, row) in point_table_rows.iter().enumerate() {
        // first row is always an empty row (to accommodate shifted polynomials which must have 0 as 1st
        // coefficient). All other rows in the point_table_rows represent active wnaf gates (i.e.
        // precompute_select = 1)
        polys.witness.precompute_select_mut()[i] = if i != 0 {
            C::ScalarField::one()
        } else {
            C::ScalarField::zero()
        };
        polys.witness.precompute_pc_mut()[i] = C::ScalarField::from(row.pc);
        polys.witness.precompute_point_transition_mut()[i] =
            C::ScalarField::from(row.point_transition as u64);
        polys.witness.precompute_round_mut()[i] = C::ScalarField::from(row.round);
        polys.witness.precompute_scalar_sum_mut()[i] = C::ScalarField::from(row.scalar_sum.clone());
        polys.witness.precompute_s1hi_mut()[i] = C::ScalarField::from(row.s1);
        polys.witness.precompute_s1lo_mut()[i] = C::ScalarField::from(row.s2);
        polys.witness.precompute_s2hi_mut()[i] = C::ScalarField::from(row.s3);
        polys.witness.precompute_s2lo_mut()[i] = C::ScalarField::from(row.s4);
        polys.witness.precompute_s3hi_mut()[i] = C::ScalarField::from(row.s5);
        polys.witness.precompute_s3lo_mut()[i] = C::ScalarField::from(row.s6);
        polys.witness.precompute_s4hi_mut()[i] = C::ScalarField::from(row.s7);
        polys.witness.precompute_s4lo_mut()[i] = C::ScalarField::from(row.s8);
        // If skew is active (i.e. we need to subtract a base point from the msm result),
        // write `7` into rows.precompute_skew. `7`, in binary representation, equals `-1` when converted
        // into WNAF form
        polys.witness.precompute_skew_mut()[i] = if row.skew {
            C::ScalarField::from(7u32)
        } else {
            C::ScalarField::zero()
        };
        polys.witness.precompute_dx_mut()[i] =
            row.precompute_double.x().unwrap_or(C::ScalarField::zero());
        polys.witness.precompute_dy_mut()[i] =
            row.precompute_double.y().unwrap_or(C::ScalarField::zero());
        polys.witness.precompute_tx_mut()[i] = row
            .precompute_accumulator
            .x()
            .unwrap_or(C::ScalarField::zero());
        polys.witness.precompute_ty_mut()[i] = row
            .precompute_accumulator
            .y()
            .unwrap_or(C::ScalarField::zero());
    }

    // Compute polynomials for the MSM rows
    for (i, row) in msm_rows.iter().enumerate() {
        polys.witness.msm_transition_mut()[i] = C::ScalarField::from(row.msm_transition as u64);
        polys.witness.msm_add_mut()[i] = C::ScalarField::from(row.q_add as u64);
        polys.witness.msm_double_mut()[i] = C::ScalarField::from(row.q_double as u64);
        polys.witness.msm_skew_mut()[i] = C::ScalarField::from(row.q_skew as u64);
        polys.witness.msm_accumulator_x_mut()[i] = row.accumulator_x;
        polys.witness.msm_accumulator_y_mut()[i] = row.accumulator_y;
        polys.witness.msm_pc_mut()[i] = C::ScalarField::from(row.pc);
        polys.witness.msm_size_of_msm_mut()[i] = C::ScalarField::from(row.msm_size);
        polys.witness.msm_count_mut()[i] = C::ScalarField::from(row.msm_count);
        polys.witness.msm_round_mut()[i] = C::ScalarField::from(row.msm_round);
        polys.witness.msm_add1_mut()[i] = C::ScalarField::from(msm_rows[i].add_state[0].add);
        polys.witness.msm_add2_mut()[i] = C::ScalarField::from(msm_rows[i].add_state[1].add);
        polys.witness.msm_add3_mut()[i] = C::ScalarField::from(msm_rows[i].add_state[2].add);
        polys.witness.msm_add4_mut()[i] = C::ScalarField::from(msm_rows[i].add_state[3].add);
        polys.witness.msm_x1_mut()[i] = msm_rows[i].add_state[0]
            .point
            .x()
            .unwrap_or(C::ScalarField::zero());
        polys.witness.msm_y1_mut()[i] = msm_rows[i].add_state[0]
            .point
            .y()
            .unwrap_or(C::ScalarField::zero());
        polys.witness.msm_x2_mut()[i] = msm_rows[i].add_state[1]
            .point
            .x()
            .unwrap_or(C::ScalarField::zero());
        polys.witness.msm_y2_mut()[i] = msm_rows[i].add_state[1]
            .point
            .y()
            .unwrap_or(C::ScalarField::zero());
        polys.witness.msm_x3_mut()[i] = msm_rows[i].add_state[2]
            .point
            .x()
            .unwrap_or(C::ScalarField::zero());
        polys.witness.msm_y3_mut()[i] = msm_rows[i].add_state[2]
            .point
            .y()
            .unwrap_or(C::ScalarField::zero());
        polys.witness.msm_x4_mut()[i] = msm_rows[i].add_state[3]
            .point
            .x()
            .unwrap_or(C::ScalarField::zero());
        polys.witness.msm_y4_mut()[i] = msm_rows[i].add_state[3]
            .point
            .y()
            .unwrap_or(C::ScalarField::zero());
        polys.witness.msm_collision_x1_mut()[i] = msm_rows[i].add_state[0].collision_inverse;
        polys.witness.msm_collision_x2_mut()[i] = msm_rows[i].add_state[1].collision_inverse;
        polys.witness.msm_collision_x3_mut()[i] = msm_rows[i].add_state[2].collision_inverse;
        polys.witness.msm_collision_x4_mut()[i] = msm_rows[i].add_state[3].collision_inverse;
        polys.witness.msm_lambda1_mut()[i] = msm_rows[i].add_state[0].lambda;
        polys.witness.msm_lambda2_mut()[i] = msm_rows[i].add_state[1].lambda;
        polys.witness.msm_lambda3_mut()[i] = msm_rows[i].add_state[2].lambda;
        polys.witness.msm_lambda4_mut()[i] = msm_rows[i].add_state[3].lambda;
        polys.witness.msm_slice1_mut()[i] = C::ScalarField::from(msm_rows[i].add_state[0].slice);
        polys.witness.msm_slice2_mut()[i] = C::ScalarField::from(msm_rows[i].add_state[1].slice);
        polys.witness.msm_slice3_mut()[i] = C::ScalarField::from(msm_rows[i].add_state[2].slice);
        polys.witness.msm_slice4_mut()[i] = C::ScalarField::from(msm_rows[i].add_state[3].slice);
    }
    polys
}
