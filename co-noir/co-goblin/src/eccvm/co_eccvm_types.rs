use crate::eccvm::co_ecc_op_queue::{
    CoECCOpQueue, CoEccvmOpsTable, CoEccvmRowTracker, CoUltraEccOpsTable, CoUltraOp, CoVMOperation,
};
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ff::One;
use ark_ff::PrimeField;
use ark_ff::Zero;
use co_builder::flavours::eccvm_flavour::ECCVMFlavour;
use co_builder::prelude::NUM_DISABLED_ROWS_IN_SUMCHECK;
use co_builder::prelude::NUM_TRANSLATION_EVALUATIONS;
use co_builder::prelude::Polynomial;
use co_builder::prelude::offset_generator_scaled;
use co_builder::{
    HonkProofResult,
    prelude::{HonkCurve, ProverCrs},
};
use co_ultrahonk::prelude::Polynomials;
use co_ultrahonk::prelude::SharedSmallSubgroupIPAProver;
use co_ultrahonk::prelude::SharedUnivariate;
use co_ultrahonk::prelude::SharedUnivariateTrait;
use common::CoUtils;
use common::shared_polynomial::SharedPolynomial;
use common::{
    mpc::NoirUltraHonkProver,
    transcript::{Transcript, TranscriptFieldType, TranscriptHasher},
};
use mpc_core::MpcState;
use mpc_net::Network;
use num_bigint::BigUint;
use std::marker::PhantomData;

#[derive(Default)]
pub(crate) struct SharedTranslationData<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    // M(X) whose Lagrange coefficients are given by (m_0 || m_1 || ... || m_{NUM_TRANSLATION_EVALUATIONS-1} || 0 || ... || 0)
    pub(crate) concatenated_polynomial_lagrange: SharedPolynomial<T, P>,

    // M(X) + Z_H(X) * R(X), where R(X) is a random polynomial of length = WITNESS_MASKING_TERM_LENGTH
    pub(crate) masked_concatenated_polynomial: SharedPolynomial<T, P>,
    // Interpolation domain {1, g, \ldots, g^{SUBGROUP_SIZE - 1}} required for Lagrange interpolation
    pub(crate) interpolation_domain: Vec<P::ScalarField>,
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> SharedTranslationData<T, P> {
    pub(crate) fn new(interpolation_domain: Vec<P::ScalarField>) -> Self {
        Self {
            concatenated_polynomial_lagrange: SharedPolynomial::new_zero(P::SUBGROUP_SIZE),
            masked_concatenated_polynomial: SharedPolynomial::new_zero(P::SUBGROUP_SIZE * 2),
            interpolation_domain,
        }
    }
    pub(crate) fn construct_translation_data<
        H: TranscriptHasher<TranscriptFieldType>,
        N: Network,
    >(
        transcript_polynomials: &[&Vec<<T as NoirUltraHonkProver<P>>::ArithmeticShare>],
        transcript: &mut Transcript<TranscriptFieldType, H>,
        crs: &ProverCrs<P>,
        net: &N,
        state: &mut T::State,
    ) -> HonkProofResult<Self> {
        // Create interpolation domain required for Lagrange interpolation
        let mut interpolation_domain = vec![P::ScalarField::one(); P::SUBGROUP_SIZE];
        let subgroup_generator = P::get_subgroup_generator();
        for idx in 1..P::SUBGROUP_SIZE {
            interpolation_domain[idx] = interpolation_domain[idx - 1] * subgroup_generator;
        }

        let mut translation_data = Self::new(interpolation_domain);

        // Concatenate the last entries of the `translation_polynomials`.

        translation_data.compute_concatenated_polynomials(transcript_polynomials, net, state);

        // Commit to M(X) + Z_H(X)*R(X), where R is a random polynomial of WITNESS_MASKING_TERM_LENGTH.
        let commitment = CoUtils::commit::<T, P>(
            translation_data.masked_concatenated_polynomial.as_ref(),
            crs,
        );
        let open = T::open_point(commitment, net, state)?;
        transcript.send_point_to_verifier::<P>(
            "Translation:concatenated_masking_term_commitment".to_string(),
            open.into(),
        );

        Ok(translation_data)
    }

    pub fn compute_small_ipa_prover<H: TranscriptHasher<TranscriptFieldType>, N: Network>(
        &mut self,
        evaluation_challenge_x: P::ScalarField,
        batching_challenge_v: P::ScalarField,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        net: &N,
        state: &mut T::State,
    ) -> HonkProofResult<SharedSmallSubgroupIPAProver<T, P>> {
        let mut small_ipa_prover = SharedSmallSubgroupIPAProver::<T, P> {
            interpolation_domain: self.interpolation_domain.to_owned(),
            concatenated_polynomial: self.masked_concatenated_polynomial.to_owned(),
            libra_concatenated_lagrange_form: self.concatenated_polynomial_lagrange.to_owned(),
            challenge_polynomial: Polynomial::new_zero(
                SharedSmallSubgroupIPAProver::<T, P>::SUBGROUP_SIZE,
            ),
            challenge_polynomial_lagrange: Polynomial::new_zero(
                SharedSmallSubgroupIPAProver::<T, P>::SUBGROUP_SIZE,
            ),
            grand_sum_polynomial_unmasked: SharedPolynomial::new_zero(
                SharedSmallSubgroupIPAProver::<T, P>::SUBGROUP_SIZE,
            ),
            grand_sum_polynomial: SharedPolynomial::new_zero(
                SharedSmallSubgroupIPAProver::<T, P>::MASKED_GRAND_SUM_LENGTH,
            ),
            grand_sum_lagrange_coeffs: vec![
                T::ArithmeticShare::default();
                SharedSmallSubgroupIPAProver::<T, P>::SUBGROUP_SIZE
            ],
            grand_sum_identity_polynomial: SharedPolynomial::new_zero(
                SharedSmallSubgroupIPAProver::<T, P>::GRAND_SUM_IDENTITY_LENGTH,
            ),
            grand_sum_identity_quotient: SharedPolynomial::new_zero(
                SharedSmallSubgroupIPAProver::<T, P>::QUOTIENT_LENGTH,
            ),
            claimed_inner_product: P::ScalarField::zero(),
            prefix_label: "Translator:".to_string(),
            phantom_data: PhantomData,
        };

        small_ipa_prover
            .compute_eccvm_challenge_polynomial(evaluation_challenge_x, batching_challenge_v);

        let mut claimed_inner_product = T::ArithmeticShare::default();
        for idx in 0..P::SUBGROUP_SIZE {
            let tmp = T::mul_with_public(
                small_ipa_prover.challenge_polynomial_lagrange[idx],
                self.concatenated_polynomial_lagrange[idx],
            );
            T::add_assign(&mut claimed_inner_product, tmp);
        }
        let claimed_inner_product = T::open_many(&[claimed_inner_product], net, state)?[0];
        transcript.send_fr_to_verifier::<P>(
            "Translation:masking_term_eval".to_string(),
            claimed_inner_product,
        );
        small_ipa_prover.claimed_inner_product = claimed_inner_product;

        Ok(small_ipa_prover)
    }

    fn compute_concatenated_polynomials<N: Network>(
        &mut self,
        transcript_polynomials: &[&Vec<<T as NoirUltraHonkProver<P>>::ArithmeticShare>],
        net: &N,
        state: &mut T::State,
    ) -> HonkProofResult<()> {
        const WITNESS_MASKING_TERM_LENGTH: usize = 2;
        let circuit_size = transcript_polynomials[0].len();

        let mut coeffs_lagrange_subgroup = vec![T::ArithmeticShare::default(); P::SUBGROUP_SIZE];

        // Extract the Lagrange coefficients of the concatenated masking term from the transcript polynomials
        for poly_idx in 0..NUM_TRANSLATION_EVALUATIONS {
            for idx in 0..NUM_DISABLED_ROWS_IN_SUMCHECK {
                let idx_to_populate = poly_idx * NUM_DISABLED_ROWS_IN_SUMCHECK + idx;
                coeffs_lagrange_subgroup[idx_to_populate as usize] = transcript_polynomials
                    [poly_idx as usize]
                    [circuit_size - NUM_DISABLED_ROWS_IN_SUMCHECK as usize + idx as usize];
            }
        }
        self.concatenated_polynomial_lagrange = SharedPolynomial::new(coeffs_lagrange_subgroup);

        // Generate the masking term
        let masking_scalars =
            SharedUnivariate::<T, P, WITNESS_MASKING_TERM_LENGTH>::get_random(net, state)?;

        // Compute monomial coefficients of the concatenated polynomial
        let concatenated_monomial_form_unmasked = SharedPolynomial::<T, P>::interpolate_from_evals(
            &self.interpolation_domain,
            &self.concatenated_polynomial_lagrange.coefficients,
            P::SUBGROUP_SIZE,
        );

        self.masked_concatenated_polynomial =
            SharedPolynomial::new_zero(P::SUBGROUP_SIZE + WITNESS_MASKING_TERM_LENGTH);
        for idx in 0..P::SUBGROUP_SIZE {
            self.masked_concatenated_polynomial[idx] = concatenated_monomial_form_unmasked[idx];
        }

        // Mask the polynomial in monomial form.
        for idx in 0..WITNESS_MASKING_TERM_LENGTH {
            self.masked_concatenated_polynomial[idx] = T::sub(
                self.masked_concatenated_polynomial[idx],
                masking_scalars.evaluations_as_ref()[idx],
            );

            T::add_assign(
                &mut self.masked_concatenated_polynomial[P::SUBGROUP_SIZE + idx],
                masking_scalars.evaluations_as_ref()[idx],
            );
        }
        Ok(())
    }
}

struct CoVMState<C: HonkCurve<TranscriptFieldType>, T: NoirUltraHonkProver<C>> {
    pc: T::BaseFieldArithmeticShare,
    count: T::BaseFieldArithmeticShare,
    accumulator: T::PointShare,
    msm_accumulator: C::Affine,
    is_accumulator_empty: bool,
}

impl<C: HonkCurve<TranscriptFieldType>, T: NoirUltraHonkProver<C>> Clone for CoVMState<C, T> {
    fn clone(&self) -> Self {
        Self {
            pc: self.pc,
            count: self.count,
            accumulator: self.accumulator,
            msm_accumulator: self.msm_accumulator,
            is_accumulator_empty: self.is_accumulator_empty,
        }
    }
}
impl<C: HonkCurve<TranscriptFieldType>, T: NoirUltraHonkProver<C>> CoVMState<C, T> {
    fn new() -> Self {
        Self {
            pc: T::BaseFieldArithmeticShare::default(),
            count: T::BaseFieldArithmeticShare::default(),
            accumulator: T::PointShare::default(),
            msm_accumulator: offset_generator_scaled::<C>(),
            is_accumulator_empty: true,
        }
    }

    fn process_mul(
        entry: &CoVMOperation<T, C>,
        updated_state: &mut CoVMState<C, T>,
        state: &CoVMState<C, T>,
    ) {
        let p = entry.base_point;
        let r = state.msm_accumulator;
        updated_state.msm_accumulator = (r + p * entry.mul_scalar_full).into();
    }

    fn process_add(
        entry: &CoVMOperation<T, C>,
        updated_state: &mut CoVMState<C, T>,
        state: &CoVMState<C, T>,
    ) {
        if state.is_accumulator_empty {
            updated_state.accumulator = entry.base_point;
        } else {
            updated_state.accumulator = (state.accumulator + entry.base_point).into();
        }
        updated_state.is_accumulator_empty = updated_state.accumulator.is_zero();
    }

    fn process_msm_transition(
        row: &mut TranscriptRow<C::BaseField>,
        updated_state: &mut CoVMState<C, T>,
        state: &CoVMState<C, T>,
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
        entry: &CoVMOperation<T, C>,
        state: &CoVMState<C, T>,
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

fn compute_rows<C: HonkCurve<TranscriptFieldType>, T: NoirUltraHonkProver<C>, N: Network>(
    vm_operations: &[CoVMOperation<T, C>],
    total_number_of_muls: T::BaseFieldArithmeticShare,
    net: &N,
    state_: &mut T::State,
) -> eyre::Result<()> {
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
    let mut msm_count_at_transition_inverse_trace =
        vec![T::BaseFieldArithmeticShare::default(); num_vm_entries];

    let mut msm_accumulator_trace: Vec<C::Affine> = vec![C::zero().into(); num_vm_entries];
    let mut accumulator_trace: Vec<C::Affine> = vec![C::zero().into(); num_vm_entries];
    let mut intermediate_accumulator_trace: Vec<C::Affine> = vec![C::zero().into(); num_vm_entries];

    let mut state = CoVMState::<C, T> {
        pc: total_number_of_muls,
        count: T::BaseFieldArithmeticShare::default(),
        accumulator: C::zero().into(),
        msm_accumulator: offset_generator_scaled::<C>(),
        is_accumulator_empty: true,
    };

    let mut updated_state = CoVMState::<C, T>::new();

    // add an empty row. 1st row all zeroes because of our shiftable polynomials
    transcript_state.push(TranscriptRow::<C::BaseField>::default());

    // during the first iteration over the ECCOpQueue, the operations are being performed using Jacobian
    // coordinates and the base point coordinates are recorded in the transcript. at the same time, the transcript
    // logic is being populated
    let mut tmp_z1_is_zero = Vec::new(); // TODO FLORIN
    let mut tmp_z2_is_zero = Vec::new(); // TODO FLORIN
    let mut indices = Vec::new(); // TODO FLORIN
    let mut base_points = Vec::new(); // TODO FLORIN
    for (i, entry) in vm_operations.iter().enumerate() {
        if entry.op_code.mul {
            tmp_z1_is_zero.push(entry.z1);
            tmp_z2_is_zero.push(entry.z2);
            indices.push(i);
            base_points.push(entry.base_point);
        }
    }
    let is_zero_results =
        T::is_zero_many_basefield(&[tmp_z1_is_zero, tmp_z2_is_zero].concat(), net, state_)?;
    let (mut z1_zero_results, mut z2_zero_results) = is_zero_results.split_at(tmp_z1_is_zero.len());
    T::scale_many_in_place_basefield(&mut z1_zero_results, -C::BaseField::one());
    T::add_scalar_in_place_basefield(&mut z1_zero_results, C::BaseField::one(), state_.id());
    T::scale_many_in_place_basefield(&mut z2_zero_results, -C::BaseField::one());
    T::add_scalar_in_place_basefield(&mut z2_zero_results, C::BaseField::one(), state_.id());
    let num_mul_partial = T::add_many_basefield(&z1_zero_results, &z2_zero_results);

    let mut base_points_is_zero = T::point_is_zero_many(&base_points, net, state_)?;
    T::scale_many_in_place_basefield(&mut base_points_is_zero, -C::BaseField::one());
    T::add_scalar_in_place_basefield(&mut base_points_is_zero, C::BaseField::one(), state_.id());
    let mut num_mul = vec![T::BaseFieldArithmeticShare::default(); num_vm_entries];
    let mul = T::mul_many_basefield(&num_mul_partial, &base_points_is_zero, net, state_)?;
    for (i, idx) in indices.iter().enumerate() {
        num_mul[*idx] = mul[i];
    }

    let mut batch_msm_transition_is_zero_check = Vec::with_capacity(num_vm_entries);
    let mut indices = Vec::with_capacity(num_vm_entries);
    for i in 0..num_vm_entries {
        let mut row = TranscriptRow::<C::BaseField>::default();
        let entry = &vm_operations[i];
        updated_state = state.clone();

        let is_mul: bool = entry.op_code.mul;
        let is_add: bool = entry.op_code.add;
        // let z1_zero: bool = if is_mul { entry.z1.is_zero() } else { true };
        // let z2_zero: bool = if is_mul { entry.z2.is_zero() } else { true };

        // let base_point_infinity = entry.base_point.is_zero();
        let mut num_muls = num_mul[i];

        updated_state.pc = T::sub_basefield(state.pc, num_muls);

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
        let mut msm_transition = true;
        // is_mul && next_not_msm && (state.count + num_muls > 0);
        if !(is_mul && next_not_msm) {
            msm_transition = false;
        } else {
            batch_msm_transition_is_zero_check.push(T::add_basefield(state.count, num_muls));
            indices.push(i);
        }

        // determine ongoing msm and update the respective counter
        let current_ongoing_msm = is_mul && !next_not_msm;

        updated_state.count = if current_ongoing_msm {
            T::add_basefield(state.count, num_muls)
        } else {
            T::BaseFieldArithmeticShare::default()
        };

        if is_mul {
            CoVMState::<C, T>::process_mul(entry, &mut updated_state, &state);
        }

        if msm_transition {
            CoVMState::<C, T>::process_msm_transition(&mut row, &mut updated_state, &state); //TODO NEED TO MULTYIPLY WITH THE IS_ZEROCHECK
        } else {
            msm_accumulator_trace[i] = C::zero().into();
            intermediate_accumulator_trace[i] = C::zero().into();
        }

        if is_add {
            CoVMState::<C, T>::process_add(entry, &mut updated_state, &state);
        }

        //     // populate the first group of TranscriptRow entries
        CoVMState::<C, T>::populate_transcript_row(
            &mut row,
            entry,
            &state,
            num_muls,
            msm_transition,
            next_not_msm,
        );

        msm_count_at_transition_inverse_trace[i] = T::add_basefield(state.count, num_muls);

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
    //TODO FLORIN
    // accumulator_trace = Utils::batch_normalize::<C>(&accumulator_trace);
    // msm_accumulator_trace = Utils::batch_normalize::<C>(&msm_accumulator_trace);
    // intermediate_accumulator_trace = Utils::batch_normalize::<C>(&intermediate_accumulator_trace);

    // add required affine coordinates to the transcript
    add_affine_coordinates_to_transcript::<C>(
        &mut transcript_state,
        &accumulator_trace,
        &msm_accumulator_trace,
        &intermediate_accumulator_trace,
    );

    // process the slopes when adding points or results of MSMs. to increase efficiency, we use batch inversion
    // after the loop
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

    // Perform all required inversions at once
    ark_ff::batch_inversion(&mut inverse_trace_x);
    ark_ff::batch_inversion(&mut inverse_trace_y);
    ark_ff::batch_inversion(&mut transcript_msm_x_inverse_trace);
    ark_ff::batch_inversion(&mut add_lambda_denominator);
    ark_ff::batch_inversion(&mut msm_count_at_transition_inverse_trace);

    // Populate the fields of the transcript row containing inverted scalars
    for i in 0..num_vm_entries {
        let row = &mut transcript_state[i + 1];
        row.base_x_inverse = inverse_trace_x[i];
        row.base_y_inverse = inverse_trace_y[i];
        row.transcript_msm_x_inverse = transcript_msm_x_inverse_trace[i];
        row.transcript_add_lambda = add_lambda_numerator[i] * add_lambda_denominator[i];
        row.msm_count_at_transition_inverse = msm_count_at_transition_inverse_trace[i];
    }

    // process the final row containing the result of the sequence of group ops in ECCOpQueue
    let final_row = finalize_transcript(&updated_state);
    transcript_state.push(final_row);

    transcript_state
}

pub fn construct_from_builder<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirUltraHonkProver<C::CycleGroup>,
    A: NoirUltraHonkProver<C>,
>(
    op_queue: &mut CoECCOpQueue<T, C::CycleGroup>,
) -> Polynomials<A::ArithmeticShare, C::ScalarField, ECCVMFlavour>
where
    A::ArithmeticShare: From<T::ArithmeticShare>,
{
    let eccvm_ops = op_queue.get_eccvm_ops().to_vec();
    let number_of_muls = op_queue.get_number_of_muls();
    // let transcript_rows = compute_rows::<C::CycleGroup, T>(&eccvm_ops, number_of_muls);

    todo!()
}
