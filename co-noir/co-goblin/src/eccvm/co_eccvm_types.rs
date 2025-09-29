use crate::eccvm::co_ecc_op_queue::{CoECCOpQueue, CoVMOperation};
use crate::eccvm::co_ecc_op_queue::{CoScalarMul, MSMRow};
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ff::One;
use ark_ff::PrimeField;
use ark_ff::Zero;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_builder::flavours::eccvm_flavour::ECCVMFlavour;
use co_builder::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
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
use goblin::ECCVM_FIXED_SIZE;
use goblin::{NUM_WNAF_DIGIT_BITS, NUM_WNAF_DIGITS_PER_SCALAR};
use goblin::{POINT_TABLE_SIZE, WNAF_DIGITS_PER_ROW};
use mpc_net::Network;
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

        translation_data.compute_concatenated_polynomials(transcript_polynomials, net, state)?;

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

struct CoVMState<C: HonkCurve<TranscriptFieldType>, T: NoirWitnessExtensionProtocol<C::BaseField>> {
    pc: T::AcvmType,
    count: u32,
    accumulator: T::AcvmPoint<C>,
    msm_accumulator: T::AcvmPoint<C>,
    is_accumulator_empty: T::AcvmType, //bool
}

impl<C: HonkCurve<TranscriptFieldType>, T: NoirWitnessExtensionProtocol<C::BaseField>> Clone
    for CoVMState<C, T>
{
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
impl<C: HonkCurve<TranscriptFieldType>, T: NoirWitnessExtensionProtocol<C::BaseField>>
    CoVMState<C, T>
{
    fn new() -> Self {
        Self {
            pc: T::AcvmType::default(),
            count: 0,
            accumulator: T::AcvmPoint::<C>::default(),
            msm_accumulator: T::AcvmPoint::from(offset_generator_scaled::<C>().into()),
            is_accumulator_empty: T::AcvmType::from(C::BaseField::one()), //true
        }
    }

    fn process_mul(
        entry: &CoVMOperation<T, C>,
        updated_state: &mut CoVMState<C, T>,
        state: &CoVMState<C, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        //TACEO TODO batch this with other process_ calls
        let p = entry.base_point;
        let r = state.msm_accumulator;

        let mul = driver.scale_point_by_scalar(p, entry.mul_scalar_full)?;
        updated_state.msm_accumulator = driver.add_points(r, mul);

        Ok(())
    }

    fn process_add(
        entry: &CoVMOperation<T, C>,
        updated_state: &mut CoVMState<C, T>,
        old_state: &CoVMState<C, T>,
        is_accumulator_empty: T::OtherAcvmType<C>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        //TACEO TODO batch this with other process_ calls
        let mul = driver.mul_with_public_other(-C::ScalarField::one(), is_accumulator_empty);
        let inv = driver.add_other(T::OtherAcvmType::from(C::ScalarField::one()), mul);
        let other = driver.add_points(old_state.accumulator, entry.base_point);
        updated_state.accumulator =
            driver.msm(&[entry.base_point, other], &[is_accumulator_empty, inv])?;

        updated_state.is_accumulator_empty =
            driver.point_is_zero_many(&[updated_state.accumulator])?[0];
        Ok(())
    }

    fn process_msm_transition(
        row: &mut CoTranscriptRow<C, T>,
        updated_state: &mut CoVMState<C, T>,
        old_state: &CoVMState<C, T>,
        is_accumulator_empty: T::OtherAcvmType<C>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        //TACEO TODO batch this with other process_ calls
        let mul = driver.mul_with_public_other(-C::ScalarField::one(), is_accumulator_empty);
        let inv = driver.add_other(T::OtherAcvmType::from(C::ScalarField::one()), mul);
        let if_value = driver.add_points(
            updated_state.msm_accumulator,
            T::AcvmPoint::from(-offset_generator_scaled::<C>().into()),
        );

        let mut else_value =
            driver.add_points(old_state.accumulator, updated_state.msm_accumulator);
        else_value = driver.add_points(
            else_value,
            T::AcvmPoint::from(-offset_generator_scaled::<C>().into()),
        );

        updated_state.accumulator =
            driver.msm(&[if_value, else_value], &[is_accumulator_empty, inv])?;

        let msm_output = driver.sub_points(
            updated_state.msm_accumulator,
            T::AcvmPoint::from(offset_generator_scaled::<C>().into()),
        );
        //TACEO TODO: Batch this is_zero check with others
        let is_zero = driver.point_is_zero_many(&[msm_output, updated_state.accumulator])?;

        updated_state.is_accumulator_empty = is_zero[1];

        row.transcript_msm_infinity = is_zero[0];
        Ok(())
    }

    fn populate_transcript_row(
        row: &mut CoTranscriptRow<C, T>,
        entry: &CoVMOperation<T, C>,
        state: &CoVMState<C, T>,
        num_muls: u32,
        msm_transition: bool,
        next_not_msm: bool,
        driver: &mut T,
    ) -> eyre::Result<()> {
        let base_point_infinity = entry.base_point_is_zero;

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
        //TACEO TODO Batch this function
        let base_point = if !base_point_infinity {
            let res = driver.pointshare_to_field_shares(entry.base_point)?;
            (res.0, res.1)
        } else {
            (
                T::AcvmType::from(C::BaseField::zero()),
                T::AcvmType::from(C::BaseField::zero()),
            )
        };
        row.base_x = if (entry.op_code.add || entry.op_code.mul || entry.op_code.eq)
            && !base_point_infinity
        {
            base_point.0
        } else {
            T::AcvmType::default()
        };
        row.base_y = if (entry.op_code.add || entry.op_code.mul || entry.op_code.eq)
            && !base_point_infinity
        {
            base_point.1
        } else {
            T::AcvmType::default()
        };
        row.base_infinity = if entry.op_code.add || entry.op_code.mul || entry.op_code.eq {
            base_point_infinity
        } else {
            false
        };
        row.z1 = if entry.op_code.mul {
            entry.z1
        } else {
            T::AcvmType::default()
        };
        row.z2 = if entry.op_code.mul {
            entry.z2
        } else {
            T::AcvmType::default()
        };
        row.z1_zero = entry.z1_is_zero;
        row.z2_zero = entry.z2_is_zero;
        row.opcode = entry.op_code.value();

        Ok(())
    }
}

#[expect(clippy::too_many_arguments)]
fn compute_inverse_trace_coordinates<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::BaseField>,
>(
    msm_transition: bool,
    row: &CoTranscriptRow<C, T>,
    intermediate_accumulator_trace_x: T::AcvmType,
    intermediate_accumulator_trace_y: T::AcvmType,
    transcript_msm_x_inverse_trace: &mut T::AcvmType,
    msm_accumulator_trace_x: T::AcvmType,
    msm_accumulator_trace_infinity: T::AcvmType,
    accumulator_trace_x: T::AcvmType,
    accumulator_trace_y: T::AcvmType,
    inverse_trace_x: &mut T::AcvmType,
    inverse_trace_y: &mut T::AcvmType,
    driver: &mut T,
) -> eyre::Result<()> {
    let row_msm_infinity = row.transcript_msm_infinity;
    //TACEO TODO: Batch this cmuxes
    let mut first_cmux = driver.cmux(
        msm_accumulator_trace_infinity,
        T::AcvmType::from(C::get_bb_infinity_default()),
        msm_accumulator_trace_x,
    )?;
    driver.add_assign_with_public(
        -offset_generator_scaled::<C>()
            .x()
            .expect("Offset generator x-coordinate should not be zero"),
        &mut first_cmux,
    );

    *transcript_msm_x_inverse_trace =
        driver.cmux(row_msm_infinity, T::AcvmType::default(), first_cmux)?;

    let (lhsx, lhsy) = if msm_transition {
        (
            intermediate_accumulator_trace_x,
            intermediate_accumulator_trace_y,
        )
    } else {
        (row.base_x, row.base_y)
    };

    let (rhsx, rhsy) = (accumulator_trace_x, accumulator_trace_y);

    *inverse_trace_x = driver.sub(lhsx, rhsx);
    *inverse_trace_y = driver.sub(lhsy, rhsy);

    Ok(())
}

struct CoTranscriptRow<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::BaseField>,
> {
    transcript_msm_infinity: T::AcvmType, //bool
    accumulator_empty: T::AcvmType,
    q_add: bool,
    q_mul: bool,
    q_eq: bool,
    q_reset_accumulator: bool,
    msm_transition: bool,
    pc: T::AcvmType,
    msm_count: u32,
    msm_count_zero_at_transition: bool,
    base_x: T::AcvmType,
    base_y: T::AcvmType,
    base_infinity: bool,
    z1: T::AcvmType,
    z2: T::AcvmType,
    z1_zero: bool,
    z2_zero: bool,
    opcode: u32,

    accumulator_x: T::AcvmType,
    accumulator_y: T::AcvmType,
    msm_output_x: T::AcvmType,
    msm_output_y: T::AcvmType,
    transcript_msm_intermediate_x: T::AcvmType,
    transcript_msm_intermediate_y: T::AcvmType,

    transcript_add_x_equal: T::AcvmType,
    transcript_add_y_equal: T::AcvmType,

    base_x_inverse: T::AcvmType,
    base_y_inverse: T::AcvmType,
    transcript_add_lambda: T::AcvmType,
    transcript_msm_x_inverse: T::AcvmType,
    msm_count_at_transition_inverse: T::AcvmType,
}

impl<C: HonkCurve<TranscriptFieldType>, T: NoirWitnessExtensionProtocol<C::BaseField>> Default
    for CoTranscriptRow<C, T>
{
    fn default() -> Self {
        Self {
            transcript_msm_infinity: T::AcvmType::default(),
            accumulator_empty: T::AcvmType::default(),
            q_add: false,
            q_mul: false,
            q_eq: false,
            q_reset_accumulator: false,
            msm_transition: false,
            pc: T::AcvmType::default(),
            msm_count: 0,
            msm_count_zero_at_transition: false,
            base_x: T::AcvmType::default(),
            base_y: T::AcvmType::default(),
            base_infinity: false,
            z1: T::AcvmType::default(),
            z2: T::AcvmType::default(),
            z1_zero: false,
            z2_zero: false,
            opcode: 0,
            accumulator_x: T::AcvmType::default(),
            accumulator_y: T::AcvmType::default(),
            msm_output_x: T::AcvmType::default(),
            msm_output_y: T::AcvmType::default(),
            transcript_msm_intermediate_x: T::AcvmType::default(),
            transcript_msm_intermediate_y: T::AcvmType::default(),
            transcript_add_x_equal: T::AcvmType::default(),
            transcript_add_y_equal: T::AcvmType::default(),
            base_x_inverse: T::AcvmType::default(),
            base_y_inverse: T::AcvmType::default(),
            transcript_add_lambda: T::AcvmType::default(),
            transcript_msm_x_inverse: T::AcvmType::default(),
            msm_count_at_transition_inverse: T::AcvmType::default(),
        }
    }
}

fn finalize_transcript<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::BaseField>,
>(
    updated_state: &CoVMState<C, T>,
    driver: &mut T,
) -> eyre::Result<CoTranscriptRow<C, T>>
where
    <C as CurveGroup>::BaseField: PrimeField,
{
    let mut final_row = CoTranscriptRow::<C, T>::default();

    let (result_x, result_y, _) = driver.pointshare_to_field_shares(updated_state.accumulator)?; //TACEO TODO: Maybe we can batch this somewhere?

    final_row.accumulator_x = result_x;
    final_row.accumulator_y = result_y;

    final_row.pc = updated_state.pc;
    final_row.accumulator_empty = updated_state.is_accumulator_empty;
    Ok(final_row)
}

fn compute_transcript_rows<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::BaseField>,
>(
    vm_operations: &[CoVMOperation<T, C>],
    total_number_of_muls: u32,
    driver: &mut T,
) -> eyre::Result<Vec<CoTranscriptRow<C, T>>> {
    let num_vm_entries = vm_operations.len();
    // The transcript contains an extra zero row at the beginning and the accumulated state at the end
    let transcript_size = num_vm_entries + 2;
    let mut transcript_state = Vec::with_capacity(transcript_size);

    // These vectors track quantities that we need to invert.
    // We fill these vectors and then perform batch inversions to amortize the cost of FF inverts
    let mut inverse_trace_x = vec![T::AcvmType::default(); num_vm_entries];
    let mut inverse_trace_y = vec![T::AcvmType::default(); num_vm_entries];
    let mut transcript_msm_x_inverse_trace = vec![T::AcvmType::default(); num_vm_entries];
    let mut msm_count_at_transition_inverse_trace = vec![C::BaseField::zero(); num_vm_entries];

    let mut msm_accumulator_trace: Vec<_> = vec![T::AcvmPoint::<C>::default(); num_vm_entries];
    let mut accumulator_trace: Vec<_> = vec![T::AcvmPoint::<C>::default(); num_vm_entries];
    let mut intermediate_accumulator_trace: Vec<_> =
        vec![T::AcvmPoint::<C>::default(); num_vm_entries];

    let mut state = CoVMState::<C, T> {
        pc: T::AcvmType::from(C::BaseField::from(total_number_of_muls)),
        count: 0,
        accumulator: T::AcvmPoint::<C>::default(),
        msm_accumulator: T::AcvmPoint::<C>::from(offset_generator_scaled::<C>().into()),
        is_accumulator_empty: T::AcvmType::from(C::BaseField::one()), //true
    };

    let mut updated_state = CoVMState::<C, T>::new();

    // add an empty row. 1st row all zeroes because of our shiftable polynomials
    transcript_state.push(CoTranscriptRow::<C, T>::default());

    // during the first iteration over the ECCOpQueue, the operations are being performed using Jacobian
    // coordinates and the base point coordinates are recorded in the transcript. at the same time, the transcript
    // logic is being populated
    for i in 0..num_vm_entries {
        let mut row = CoTranscriptRow::<C, T>::default();
        let entry = &vm_operations[i];
        updated_state = state.clone();

        let is_mul: bool = entry.op_code.mul;
        let is_add: bool = entry.op_code.add;
        let z1_zero: bool = if is_mul { entry.z1_is_zero } else { true };
        let z2_zero: bool = if is_mul { entry.z2_is_zero } else { true };

        let base_point_infinity = entry.base_point_is_zero;
        let mut num_muls: u32 = 0;
        if is_mul {
            num_muls = (!z1_zero as u32) + (!z2_zero as u32);
            if base_point_infinity {
                num_muls = 0;
            }
        }
        updated_state.pc = driver.sub(state.pc, T::AcvmType::from(C::BaseField::from(num_muls)));

        if entry.op_code.reset {
            updated_state.is_accumulator_empty = T::AcvmType::from(C::BaseField::one()); //true;
            updated_state.accumulator = T::AcvmPoint::<C>::default();
            updated_state.msm_accumulator =
                T::AcvmPoint::from(offset_generator_scaled::<C>().into());
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
            CoVMState::<C, T>::process_mul(entry, &mut updated_state, &state, driver)?;
        }
        let is_accumulator_empty = driver.convert_fields(&[state.is_accumulator_empty])?[0];
        if msm_transition {
            CoVMState::<C, T>::process_msm_transition(
                &mut row,
                &mut updated_state,
                &state,
                is_accumulator_empty,
                driver,
            )?;
        } else {
            msm_accumulator_trace[i] = T::AcvmPoint::<C>::default();
            intermediate_accumulator_trace[i] = T::AcvmPoint::<C>::default();
        }

        if is_add {
            CoVMState::<C, T>::process_add(
                entry,
                &mut updated_state,
                &state,
                is_accumulator_empty,
                driver,
            )?;
        }

        // populate the first group of TranscriptRow entries
        CoVMState::<C, T>::populate_transcript_row(
            &mut row,
            entry,
            &state,
            num_muls,
            msm_transition,
            next_not_msm,
            driver,
        )?;

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
            T::AcvmPoint::<C>::default()
        };
        intermediate_accumulator_trace[i] = if msm_transition {
            driver.add_points(
                updated_state.msm_accumulator,
                T::AcvmPoint::from(-offset_generator_scaled::<C>().into()),
            )
        } else {
            T::AcvmPoint::<C>::default()
        };

        state = updated_state.clone();

        if is_mul && next_not_msm {
            state.msm_accumulator = T::AcvmPoint::from(offset_generator_scaled::<C>().into());
        }
        transcript_state.push(row);
    }

    // add required affine coordinates to the transcript
    // and
    // process the slopes when adding points or results of MSMs. to increase efficiency, we use batch inversion
    // after the loop

    let accumulator_trace_len = accumulator_trace.len();
    let msm_accumulator_trace_len = msm_accumulator_trace.len();
    let intermediate_accumulator_trace_len = intermediate_accumulator_trace.len();

    let mut is_zero_vm_point = Vec::new();
    for i in 0..accumulator_trace_len {
        let entry = &vm_operations[i];
        if entry.op_code.add {
            is_zero_vm_point.push(vm_operations[i].base_point);
        } else {
            is_zero_vm_point.push(intermediate_accumulator_trace[i]);
        }
    }

    let (xs, ys, inf) = driver.pointshare_to_field_shares_many(
        &[
            accumulator_trace.clone(),
            msm_accumulator_trace.clone(),
            intermediate_accumulator_trace.clone(),
            is_zero_vm_point.clone(),
        ]
        .concat(),
    )?;

    let (acc_xs, rest) = xs.split_at(accumulator_trace_len);
    let (msm_xs, int_xs, vm_points_x) = {
        let (a, r) = rest.split_at(msm_accumulator_trace_len);
        let (b, c) = r.split_at(intermediate_accumulator_trace_len);
        (a, b, c)
    };
    let (acc_ys, rest) = ys.split_at(accumulator_trace_len);
    let (msm_ys, int_ys, vm_points_y) = {
        let (a, r) = rest.split_at(msm_accumulator_trace_len);
        let (b, c) = r.split_at(intermediate_accumulator_trace_len);
        (a, b, c)
    };
    let (acc_inf, rest) = inf.split_at(accumulator_trace_len);
    let (msm_inf, _int_inf, vm_points_inf) = {
        let (a, r) = rest.split_at(msm_accumulator_trace_len);
        let (b, c) = r.split_at(intermediate_accumulator_trace_len);
        (a, b, c)
    };
    for i in 0..accumulator_trace_len {
        let row = &mut transcript_state[i + 1];
        row.accumulator_x = acc_xs[i];
        row.accumulator_y = acc_ys[i];
        row.msm_output_x = msm_xs[i];
        row.msm_output_y = msm_ys[i];
        row.transcript_msm_intermediate_x = int_xs[i];
        row.transcript_msm_intermediate_y = int_ys[i];
    }

    // this is the end of add_affine_coordinates_to_transcript

    let inv_vm_points_inf = vm_points_inf
        .iter()
        .map(|x| driver.sub(T::AcvmType::from(C::BaseField::one()), *x))
        .collect::<Vec<_>>();
    let inv_acc_inf = acc_inf
        .iter()
        .map(|x| driver.sub(T::AcvmType::from(C::BaseField::one()), *x))
        .collect::<Vec<_>>();

    let vm_inf_and_acc_inf = driver.mul_many(
        &[vm_points_inf, &inv_vm_points_inf, vm_points_x].concat(),
        &[acc_inf, &inv_acc_inf, vm_points_x].concat(),
    )?;
    let (vm_inf_and_acc_inf, res) = vm_inf_and_acc_inf.split_at(vm_points_inf.len());
    let (inv_vm_inf_and_acc_inf, vm_x_squared) = res.split_at(inv_vm_points_inf.len());

    let vm_x_squared_times_3 = driver.scale_many(vm_x_squared, C::BaseField::from(3u32));
    let vm_y_doubled = driver.add_many(vm_points_y, vm_points_y);
    let acc_x_minus_vm_x = driver.sub_many(acc_xs, vm_points_x);
    let acc_y_minus_vm_y = driver.sub_many(acc_ys, vm_points_y);

    // Compute row.transcript_add_x_equal and row.transcript_add_y_equal:
    let is_zero_transcript_add = driver.equal_many(
        &[vm_points_x, vm_points_y].concat(),
        &[acc_xs, acc_ys].concat(),
    )?;
    let (is_zero_transcript_add_x, is_zero_transcript_add_y) =
        is_zero_transcript_add.split_at(is_zero_transcript_add.len() / 2);
    let transcript_add_values_x = driver.add_many(is_zero_transcript_add_x, vm_inf_and_acc_inf);
    let transcript_add_values_y = driver.add_many(is_zero_transcript_add_y, vm_inf_and_acc_inf);
    let mut transcript_add_values =
        driver.is_zero_many(&[transcript_add_values_x, transcript_add_values_y].concat())?; //TODO FLORIN: is there a better way to do this OR?
    transcript_add_values.iter_mut().for_each(|x| {
        *x = driver.sub(T::AcvmType::from(C::BaseField::one()), *x);
    });
    let (transcript_add_x_equal, transcript_add_y_equal) =
        transcript_add_values.split_at(transcript_add_values.len() / 2);

    let scale = driver.scale_many(transcript_add_x_equal, -C::BaseField::one());
    let inv_transcript_add_x_equal = driver.add_scalar(&scale, C::BaseField::one());
    let mul = driver.mul_many(is_zero_transcript_add_x, is_zero_transcript_add_y)?; //(accumulator_x == vm_x) && (accumulator_y == vm_y)
    let res = driver.mul_many(
        &[mul, inv_transcript_add_x_equal].concat(),
        &[inv_vm_inf_and_acc_inf, inv_vm_inf_and_acc_inf].concat(),
    )?;
    let (if_mul, else_if_mul) = res.split_at(is_zero_transcript_add_x.len()); //(accumulator_x == vm_x) && (accumulator_y == vm_y) && !vm_infinity && !accumulator_infinity
    // and (accumulator_x != vm_x) && !vm_infinity && !accumulator_infinity

    let zeroes = vec![T::AcvmType::default(); 2 * accumulator_trace_len];
    let (mut add_lambda_numerator, mut add_lambda_denominator) = {
        let else_if_res = driver.cmux_many(
            &[else_if_mul, else_if_mul].concat(),
            &[acc_y_minus_vm_y, acc_x_minus_vm_x].concat(),
            &zeroes,
        )?;
        let res = driver.cmux_many(
            &[if_mul, if_mul].concat(),
            &[vm_x_squared_times_3, vm_y_doubled].concat(),
            &else_if_res,
        )?;
        let (add_lambda_numerator, add_lambda_denominator) = res.split_at(accumulator_trace_len);
        (
            add_lambda_numerator.to_vec(),
            add_lambda_denominator.to_vec(),
        )
    };
    // let mut add_lambda_denominator = {
    //     let else_if_res = driver.cmux_many(else_if_mul, &acc_x_minus_vm_x, &zeroes)?;
    //     driver.cmux_many(if_mul, &vm_y_doubled, &else_if_res)?
    // };

    for i in 0..accumulator_trace_len {
        let row = &mut transcript_state[i + 1];
        let msm_transition = row.msm_transition;
        let entry = &vm_operations[i];
        let is_add = entry.op_code.add;

        if msm_transition || is_add {
            // compute the differences between point coordinates
            compute_inverse_trace_coordinates::<C, T>(
                msm_transition,
                row,
                int_xs[i],
                int_ys[i],
                &mut transcript_msm_x_inverse_trace[i],
                msm_xs[i],
                msm_inf[i],
                acc_xs[i],
                acc_ys[i],
                &mut inverse_trace_x[i],
                &mut inverse_trace_y[i],
                driver,
            )?;
            row.transcript_add_x_equal = transcript_add_x_equal[i]; //(vm_x == accumulator_x) || (vm_infinity && accumulator_infinity);
            row.transcript_add_y_equal = transcript_add_y_equal[i]; //(vm_y == accumulator_y) || (vm_infinity && accumulator_infinity);
        } else {
            row.transcript_add_x_equal = T::AcvmType::default();
            row.transcript_add_y_equal = T::AcvmType::default();
            add_lambda_numerator[i] = T::AcvmType::default();
            add_lambda_denominator[i] = T::AcvmType::default();
            inverse_trace_x[i] = T::AcvmType::default();
            inverse_trace_y[i] = T::AcvmType::default();
        }
    }

    // Perform all required inversions at once
    let inverse_trace_x_len = inverse_trace_x.len();
    let inverse_trace_y_len = inverse_trace_y.len();
    let transcript_msm_x_inverse_trace_len = transcript_msm_x_inverse_trace.len();

    ark_ff::batch_inversion(&mut msm_count_at_transition_inverse_trace);
    let result = driver.inverse_or_zero_many(
        &[
            inverse_trace_x,
            inverse_trace_y,
            transcript_msm_x_inverse_trace,
            add_lambda_denominator,
        ]
        .concat(),
    )?;
    let (res_inverse_trace_x, rest) = result.split_at(inverse_trace_x_len);
    let (res_inverse_trace_y, rest) = rest.split_at(inverse_trace_y_len);
    let (res_transcript_msm_x_inverse_trace, res_add_lambda_denominator) =
        rest.split_at(transcript_msm_x_inverse_trace_len);
    inverse_trace_x = res_inverse_trace_x.to_vec();
    inverse_trace_y = res_inverse_trace_y.to_vec();
    transcript_msm_x_inverse_trace = res_transcript_msm_x_inverse_trace.to_vec();
    add_lambda_denominator = res_add_lambda_denominator.to_vec();

    // Populate the fields of the transcript row containing inverted scalars
    let mul = driver.mul_many(&add_lambda_numerator, &add_lambda_denominator)?;
    for i in 0..num_vm_entries {
        let row = &mut transcript_state[i + 1];
        row.base_x_inverse = inverse_trace_x[i];
        row.base_y_inverse = inverse_trace_y[i];
        row.transcript_msm_x_inverse = transcript_msm_x_inverse_trace[i];
        row.transcript_add_lambda = mul[i];
        row.msm_count_at_transition_inverse =
            T::AcvmType::from(msm_count_at_transition_inverse_trace[i]);
    }

    // process the final row containing the result of the sequence of group ops in ECCOpQueue
    let final_row = finalize_transcript(&updated_state, driver)?;
    transcript_state.push(final_row);

    Ok(transcript_state)
}
#[derive(Debug)]
struct PointTablePrecomputationRow<
    C: CurveGroup<BaseField: PrimeField>,
    T: NoirWitnessExtensionProtocol<C::BaseField>,
> {
    s1: T::AcvmType,
    s2: T::AcvmType,
    s3: T::AcvmType,
    s4: T::AcvmType,
    s5: T::AcvmType,
    s6: T::AcvmType,
    s7: T::AcvmType,
    s8: T::AcvmType,
    skew: T::AcvmType,
    point_transition: bool,
    pc: u32,
    round: u32,
    scalar_sum: T::AcvmType,
    precompute_accumulator: T::AcvmPoint<C>,
    precompute_double: T::AcvmPoint<C>,
}

impl<C: CurveGroup<BaseField: PrimeField>, T: NoirWitnessExtensionProtocol<C::BaseField>> Default
    for PointTablePrecomputationRow<C, T>
{
    fn default() -> Self {
        Self {
            s1: T::AcvmType::default(),
            s2: T::AcvmType::default(),
            s3: T::AcvmType::default(),
            s4: T::AcvmType::default(),
            s5: T::AcvmType::default(),
            s6: T::AcvmType::default(),
            s7: T::AcvmType::default(),
            s8: T::AcvmType::default(),
            skew: T::AcvmType::default(),
            point_transition: false,
            pc: 0,
            round: 0,
            scalar_sum: T::AcvmType::default(),
            precompute_accumulator: T::AcvmPoint::<C>::default(),
            precompute_double: T::AcvmPoint::<C>::default(),
        }
    }
}
impl<C: CurveGroup<BaseField: PrimeField>, T: NoirWitnessExtensionProtocol<C::BaseField>> Clone
    for PointTablePrecomputationRow<C, T>
{
    fn clone(&self) -> Self {
        Self {
            s1: self.s1,
            s2: self.s2,
            s3: self.s3,
            s4: self.s4,
            s5: self.s5,
            s6: self.s6,
            s7: self.s7,
            s8: self.s8,
            skew: self.skew,
            point_transition: self.point_transition,
            pc: self.pc,
            round: self.round,
            scalar_sum: self.scalar_sum,
            precompute_accumulator: self.precompute_accumulator,
            precompute_double: self.precompute_double,
        }
    }
}

impl<C: HonkCurve<TranscriptFieldType>, T: NoirWitnessExtensionProtocol<C::BaseField>>
    PointTablePrecomputationRow<C, T>
{
    fn compute_point_table_rows(
        msms: &[CoScalarMul<T, C>],
        driver: &mut T,
    ) -> eyre::Result<Vec<PointTablePrecomputationRow<C, T>>> {
        let num_rows_per_scalar = NUM_WNAF_DIGITS_PER_SCALAR / WNAF_DIGITS_PER_ROW;
        let num_precompute_rows = num_rows_per_scalar * msms.len() + 1;
        let mut precompute_state =
            vec![PointTablePrecomputationRow::<C, T>::default(); num_precompute_rows];

        // Start with an empty row (shiftable polynomials must have 0 as the first coefficient)
        precompute_state[0] = PointTablePrecomputationRow::<C, T>::default();

        // current impl doesn't work if not 4
        assert_eq!(WNAF_DIGITS_PER_ROW, 4);

        for (j, entry) in msms.iter().enumerate() {
            let mut scalar_sum = T::AcvmType::default();

            for i in 0..num_rows_per_scalar {
                let row_si = entry.wnaf_si[i * 8..(i + 1) * 8].to_vec();
                let mut row = PointTablePrecomputationRow {
                    s1: row_si[0],
                    s2: row_si[1],
                    s3: row_si[2],
                    s4: row_si[3],
                    s5: row_si[4],
                    s6: row_si[5],
                    s7: row_si[6],
                    s8: row_si[7],
                    ..Default::default()
                };

                // Convert into 2-bit chunks

                let last_row = i == num_rows_per_scalar - 1;
                row.skew = if last_row {
                    entry.wnaf_skew
                } else {
                    T::AcvmType::default()
                };
                row.scalar_sum = scalar_sum;

                // Ensure slice1 is positive for the first row of each scalar sum
                let row_chunk = entry.row_chunks[i]; //slice3 + (slice2 << 4) + (slice1 << 8) + (slice0 << 12);
                let chunk_negative = entry.row_chunks_sign[i];
                let truthy = driver.mul_with_public(-C::BaseField::one(), row_chunk);
                let summand = driver.cmux(chunk_negative, truthy, row_chunk)?; // TACEO TODO Batch this function (OR TODO FLORIN)

                let factor = 1 << (NUM_WNAF_DIGIT_BITS * WNAF_DIGITS_PER_ROW);
                scalar_sum = driver.mul_with_public(C::BaseField::from(factor), scalar_sum);
                // scalar_sum <<= NUM_WNAF_DIGIT_BITS * WNAF_DIGITS_PER_ROW;
                driver.add_assign(&mut scalar_sum, summand);

                row.round = i as u32;
                row.point_transition = last_row;
                row.pc = entry.pc;

                // We don't do this assert here
                // if last_row {
                //     assert_eq!(
                //         scalar_sum.clone() - BigUint::from(entry.wnaf_skew as u64),
                //         entry.scalar
                //     );
                // }

                row.precompute_double = entry.precomputed_table[POINT_TABLE_SIZE].to_owned();
                // fill accumulator in reverse order i.e. first row = 15[P], then 13[P], ..., 1[P]
                row.precompute_accumulator =
                    entry.precomputed_table[POINT_TABLE_SIZE - 1 - i].to_owned();
                precompute_state[j * num_rows_per_scalar + i + 1] = row;
            }
        }
        Ok(precompute_state)
    }
}

pub fn construct_from_builder<
    C: HonkCurve<TranscriptFieldType>,
    U: NoirUltraHonkProver<C>,
    T: NoirWitnessExtensionProtocol<
            <<C as HonkCurve<TranscriptFieldType>>::CycleGroup as CurveGroup>::BaseField,
            ArithmeticShare = U::ArithmeticShare,
        >,
>(
    op_queue: &mut CoECCOpQueue<T, C::CycleGroup>,
    driver: &mut T,
) -> eyre::Result<Polynomials<U::ArithmeticShare, C::ScalarField, ECCVMFlavour>> {
    let eccvm_ops = op_queue.get_eccvm_ops().to_vec();
    let number_of_muls = op_queue.get_number_of_muls();
    let transcript_rows =
        compute_transcript_rows::<C::CycleGroup, T>(&eccvm_ops, number_of_muls, driver)?;

    let msms = op_queue.get_msms(driver)?;

    let point_table_rows =
        PointTablePrecomputationRow::<C::CycleGroup, T>::compute_point_table_rows(
            &msms.iter().flat_map(|msm| msm.clone()).collect::<Vec<_>>(),
            driver,
        )?;

    let result = MSMRow::<C::CycleGroup, T>::compute_rows_msms(
        &msms,
        number_of_muls,
        op_queue.get_num_msm_rows(),
        driver,
    )?;

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

    let mut polys =
        Polynomials::<U::ArithmeticShare, C::ScalarField, ECCVMFlavour>::new(dyadic_num_rows);

    polys.precomputed.lagrange_first_mut()[0] = C::ScalarField::one();
    polys.precomputed.lagrange_second_mut()[1] = C::ScalarField::one();
    polys.precomputed.lagrange_last_mut()[unmasked_witness_size - 1] = C::ScalarField::one();

    for i in 0..point_table_read_counts[0].len() {
        // // Explanation of off-by-one offset:
        // // When computing the WNAF slice for a point at point counter value `pc` and a round index `round`, the
        // // row number that computes the slice can be derived. This row number is then mapped to the index of
        // // `lookup_read_counts`. We do this mapping in `ecc_msm_relation`. We are off-by-one because we add an
        // // empty row at the start of the WNAF columns that is not accounted for (index of lookup_read_counts
        // // maps to the row in our WNAF columns that computes a slice for a given value of pc and round)
        polys.witness.lookup_read_counts_0_mut()[i + 1] =
            driver.get_as_shared(&point_table_read_counts[0][i]);
        polys.witness.lookup_read_counts_1_mut()[i + 1] =
            driver.get_as_shared(&point_table_read_counts[1][i]);
    }

    // Compute polynomials for transcript columns
    for (i, row) in transcript_rows.iter().enumerate() {
        polys.witness.transcript_accumulator_empty_mut()[i] =
            driver.get_as_shared(&row.accumulator_empty);
        polys.witness.transcript_add_mut()[i] =
            driver.get_as_shared(&T::AcvmType::from(C::ScalarField::from(row.q_add)));
        polys.witness.transcript_mul_mut()[i] =
            driver.get_as_shared(&T::AcvmType::from(C::ScalarField::from(row.q_mul)));
        polys.witness.transcript_eq_mut()[i] =
            driver.get_as_shared(&T::AcvmType::from(C::ScalarField::from(row.q_eq)));
        polys.witness.transcript_reset_accumulator_mut()[i] = driver.get_as_shared(
            &T::AcvmType::from(C::ScalarField::from(row.q_reset_accumulator)),
        );
        polys.witness.transcript_msm_transition_mut()[i] = driver.get_as_shared(
            &T::AcvmType::from(C::ScalarField::from(row.msm_transition as u32)),
        );
        polys.witness.transcript_pc_mut()[i] = driver.get_as_shared(&row.pc);
        polys.witness.transcript_msm_count_mut()[i] =
            driver.get_as_shared(&T::AcvmType::from(C::ScalarField::from(row.msm_count)));
        polys.witness.transcript_px_mut()[i] = driver.get_as_shared(&row.base_x);
        polys.witness.transcript_py_mut()[i] = driver.get_as_shared(&row.base_y);
        polys.witness.transcript_z1_mut()[i] = driver.get_as_shared(&row.z1);
        polys.witness.transcript_z2_mut()[i] = driver.get_as_shared(&row.z2);
        polys.witness.transcript_z1zero_mut()[i] =
            driver.get_as_shared(&T::AcvmType::from(C::ScalarField::from(row.z1_zero as u32)));
        polys.witness.transcript_z2zero_mut()[i] =
            driver.get_as_shared(&T::AcvmType::from(C::ScalarField::from(row.z2_zero as u32)));
        polys.witness.transcript_op_mut()[i] =
            driver.get_as_shared(&T::AcvmType::from(C::ScalarField::from(row.opcode)));
        polys.witness.transcript_accumulator_x_mut()[i] = driver.get_as_shared(&row.accumulator_x);
        polys.witness.transcript_accumulator_y_mut()[i] = driver.get_as_shared(&row.accumulator_y);
        polys.witness.transcript_msm_x_mut()[i] = driver.get_as_shared(&row.msm_output_x);
        polys.witness.transcript_msm_y_mut()[i] = driver.get_as_shared(&row.msm_output_y);
        polys.witness.transcript_base_infinity_mut()[i] = driver.get_as_shared(&T::AcvmType::from(
            C::ScalarField::from(row.base_infinity as u32),
        ));
        polys.witness.transcript_base_x_inverse_mut()[i] =
            driver.get_as_shared(&row.base_x_inverse);
        polys.witness.transcript_base_y_inverse_mut()[i] =
            driver.get_as_shared(&row.base_y_inverse);
        polys.witness.transcript_add_x_equal_mut()[i] =
            driver.get_as_shared(&row.transcript_add_x_equal);
        polys.witness.transcript_add_y_equal_mut()[i] =
            driver.get_as_shared(&row.transcript_add_y_equal);
        polys.witness.transcript_add_lambda_mut()[i] =
            driver.get_as_shared(&row.transcript_add_lambda);
        polys.witness.transcript_msm_intermediate_x_mut()[i] =
            driver.get_as_shared(&row.transcript_msm_intermediate_x);
        polys.witness.transcript_msm_intermediate_y_mut()[i] =
            driver.get_as_shared(&row.transcript_msm_intermediate_y);
        polys.witness.transcript_msm_infinity_mut()[i] =
            driver.get_as_shared(&row.transcript_msm_infinity);
        polys.witness.transcript_msm_x_inverse_mut()[i] =
            driver.get_as_shared(&row.transcript_msm_x_inverse);
        polys.witness.transcript_msm_count_zero_at_transition_mut()[i] =
            driver.get_as_shared(&T::AcvmType::from(C::ScalarField::from(
                row.msm_count_zero_at_transition as u32,
            )));
        polys
            .witness
            .transcript_msm_count_at_transition_inverse_mut()[i] =
            driver.get_as_shared(&row.msm_count_at_transition_inverse);
    }

    // AZTEC TODO(@zac-williamson) if final opcode resets accumulator, all subsequent "is_accumulator_empty" row
    // values must be 1. Ideally we find a way to tweak this so that empty rows that do nothing have column
    // values that are all zero (issue #2217)
    if transcript_rows.last().is_some() {
        for i in transcript_rows.len()..unmasked_witness_size {
            polys.witness.transcript_accumulator_empty_mut()[i] = driver.get_as_shared(
                &transcript_rows
                    .last()
                    .expect("We checked it is non-empty")
                    .accumulator_empty,
            );
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

    let mut batch_point_to_field_shares =
        Vec::with_capacity(2 * point_table_rows.len() + 4 * msm_rows.len());
    for row in point_table_rows.iter() {
        batch_point_to_field_shares.push(row.precompute_double);
        batch_point_to_field_shares.push(row.precompute_accumulator);
    }
    for row in msm_rows.iter() {
        batch_point_to_field_shares.push(row.add_state[0].point);
        batch_point_to_field_shares.push(row.add_state[1].point);
        batch_point_to_field_shares.push(row.add_state[2].point);
        batch_point_to_field_shares.push(row.add_state[3].point);
    }

    let field_shares = driver.pointshare_to_field_shares_many(&batch_point_to_field_shares)?;

    for (i, row) in point_table_rows.iter().enumerate() {
        // first row is always an empty row (to accommodate shifted polynomials which must have 0 as 1st
        // coefficient). All other rows in the point_table_rows represent active wnaf gates (i.e.
        // precompute_select = 1)
        polys.witness.precompute_select_mut()[i] = if i != 0 {
            driver.get_as_shared(&T::AcvmType::from(C::ScalarField::one()))
        } else {
            driver.get_as_shared(&T::AcvmType::from(C::ScalarField::zero()))
        };
        polys.witness.precompute_pc_mut()[i] =
            driver.get_as_shared(&T::AcvmType::from(C::ScalarField::from(row.pc)));
        polys.witness.precompute_point_transition_mut()[i] = driver.get_as_shared(
            &T::AcvmType::from(C::ScalarField::from(row.point_transition as u32)),
        );
        polys.witness.precompute_round_mut()[i] =
            driver.get_as_shared(&T::AcvmType::from(C::ScalarField::from(row.round)));
        polys.witness.precompute_scalar_sum_mut()[i] =
            driver.get_as_shared(&row.scalar_sum.clone());
        polys.witness.precompute_s1hi_mut()[i] = driver.get_as_shared(&row.s1);
        polys.witness.precompute_s1lo_mut()[i] = driver.get_as_shared(&row.s2);
        polys.witness.precompute_s2hi_mut()[i] = driver.get_as_shared(&row.s3);
        polys.witness.precompute_s2lo_mut()[i] = driver.get_as_shared(&row.s4);
        polys.witness.precompute_s3hi_mut()[i] = driver.get_as_shared(&row.s5);
        polys.witness.precompute_s3lo_mut()[i] = driver.get_as_shared(&row.s6);
        polys.witness.precompute_s4hi_mut()[i] = driver.get_as_shared(&row.s7);
        polys.witness.precompute_s4lo_mut()[i] = driver.get_as_shared(&row.s8);
        // If skew is active (i.e. we need to subtract a base point from the msm result),
        // write `7` into rows.precompute_skew. `7`, in binary representation, equals `-1` when converted
        // into WNAF form
        let tmp = driver.mul_with_public(C::ScalarField::from(7u32), row.skew);
        polys.witness.precompute_skew_mut()[i] = driver.get_as_shared(&tmp);
        polys.witness.precompute_dx_mut()[i] = driver.get_as_shared(&field_shares.0[i * 2]);
        polys.witness.precompute_dy_mut()[i] = driver.get_as_shared(&field_shares.1[i * 2]);
        polys.witness.precompute_tx_mut()[i] = driver.get_as_shared(&field_shares.0[2 * i + 1]);
        polys.witness.precompute_ty_mut()[i] = driver.get_as_shared(&field_shares.1[2 * i + 1]);
    }
    let offset = point_table_rows.len() * 2;

    // Compute polynomials for the MSM rows
    for (i, row) in msm_rows.iter().enumerate() {
        polys.witness.msm_transition_mut()[i] = driver.get_as_shared(&T::AcvmType::from(
            C::ScalarField::from(row.msm_transition as u64),
        ));
        polys.witness.msm_add_mut()[i] =
            driver.get_as_shared(&T::AcvmType::from(C::ScalarField::from(row.q_add as u64)));
        polys.witness.msm_double_mut()[i] = driver.get_as_shared(&T::AcvmType::from(
            C::ScalarField::from(row.q_double as u64),
        ));
        polys.witness.msm_skew_mut()[i] =
            driver.get_as_shared(&T::AcvmType::from(C::ScalarField::from(row.q_skew as u64)));
        polys.witness.msm_accumulator_y_mut()[i] = driver.get_as_shared(&row.accumulator_y);
        polys.witness.msm_accumulator_x_mut()[i] = driver.get_as_shared(&row.accumulator_x);
        polys.witness.msm_pc_mut()[i] =
            driver.get_as_shared(&T::AcvmType::from(C::ScalarField::from(row.pc as u32)));
        polys.witness.msm_size_of_msm_mut()[i] =
            driver.get_as_shared(&T::AcvmType::from(C::ScalarField::from(row.msm_size)));
        polys.witness.msm_count_mut()[i] =
            driver.get_as_shared(&T::AcvmType::from(C::ScalarField::from(row.msm_count)));
        polys.witness.msm_round_mut()[i] =
            driver.get_as_shared(&T::AcvmType::from(C::ScalarField::from(row.msm_round)));
        polys.witness.msm_add1_mut()[i] = driver.get_as_shared(&T::AcvmType::from(
            C::ScalarField::from(msm_rows[i].add_state[0].add),
        ));
        polys.witness.msm_add2_mut()[i] = driver.get_as_shared(&T::AcvmType::from(
            C::ScalarField::from(msm_rows[i].add_state[1].add),
        ));
        polys.witness.msm_add3_mut()[i] = driver.get_as_shared(&T::AcvmType::from(
            C::ScalarField::from(msm_rows[i].add_state[2].add),
        ));
        polys.witness.msm_add4_mut()[i] = driver.get_as_shared(&T::AcvmType::from(
            C::ScalarField::from(msm_rows[i].add_state[3].add),
        ));
        polys.witness.msm_x1_mut()[i] = driver.get_as_shared(&field_shares.0[offset + i * 4]);
        polys.witness.msm_y1_mut()[i] = driver.get_as_shared(&field_shares.1[offset + i * 4]);
        polys.witness.msm_x2_mut()[i] = driver.get_as_shared(&field_shares.0[offset + i * 4 + 1]);
        polys.witness.msm_y2_mut()[i] = driver.get_as_shared(&field_shares.1[offset + i * 4 + 1]);
        polys.witness.msm_x3_mut()[i] = driver.get_as_shared(&field_shares.0[offset + i * 4 + 2]);
        polys.witness.msm_y3_mut()[i] = driver.get_as_shared(&field_shares.1[offset + i * 4 + 2]);
        polys.witness.msm_x4_mut()[i] = driver.get_as_shared(&field_shares.0[offset + i * 4 + 3]);
        polys.witness.msm_y4_mut()[i] = driver.get_as_shared(&field_shares.1[offset + i * 4 + 3]);
        polys.witness.msm_collision_x1_mut()[i] =
            driver.get_as_shared(&msm_rows[i].add_state[0].collision_inverse);
        polys.witness.msm_collision_x2_mut()[i] =
            driver.get_as_shared(&msm_rows[i].add_state[1].collision_inverse);
        polys.witness.msm_collision_x3_mut()[i] =
            driver.get_as_shared(&msm_rows[i].add_state[2].collision_inverse);
        polys.witness.msm_collision_x4_mut()[i] =
            driver.get_as_shared(&msm_rows[i].add_state[3].collision_inverse);
        polys.witness.msm_lambda1_mut()[i] = driver.get_as_shared(&msm_rows[i].add_state[0].lambda);
        polys.witness.msm_lambda2_mut()[i] = driver.get_as_shared(&msm_rows[i].add_state[1].lambda);
        polys.witness.msm_lambda3_mut()[i] = driver.get_as_shared(&msm_rows[i].add_state[2].lambda);
        polys.witness.msm_lambda4_mut()[i] = driver.get_as_shared(&msm_rows[i].add_state[3].lambda);
        polys.witness.msm_slice1_mut()[i] = driver.get_as_shared(&msm_rows[i].add_state[0].slice);
        polys.witness.msm_slice2_mut()[i] = driver.get_as_shared(&msm_rows[i].add_state[1].slice);
        polys.witness.msm_slice3_mut()[i] = driver.get_as_shared(&msm_rows[i].add_state[2].slice);
        polys.witness.msm_slice4_mut()[i] = driver.get_as_shared(&msm_rows[i].add_state[3].slice);
    }
    Ok(polys)
}
