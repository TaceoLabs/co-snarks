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
    msm_accumulator: T::PointShare,
    is_accumulator_empty: T::BaseFieldArithmeticShare, //bool
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
    fn new(id: <T::State as MpcState>::PartyID) -> Self {
        Self {
            pc: T::BaseFieldArithmeticShare::default(),
            count: T::BaseFieldArithmeticShare::default(),
            accumulator: T::PointShare::default(),
            msm_accumulator: T::promote_to_trivial_point_share(
                id,
                offset_generator_scaled::<C>().into(),
            ),
            is_accumulator_empty: T::promote_to_trivial_share_basefield(id, C::BaseField::one()), //true
        }
    }

    fn process_mul<N: Network>(
        entry: &CoVMOperation<T, C>,
        updated_state: &mut CoVMState<C, T>,
        state: &CoVMState<C, T>,
        net: &N,
        state_: &mut T::State,
    ) {
        let p = entry.base_point;
        let r = state.msm_accumulator;
        //TACEO TODO Can we batch these scalar muls?
        let mul = T::scalar_mul(&p, entry.mul_scalar_full, net, state_);
        updated_state.msm_accumulator = T::point_add(&r, &mul);
    }

    fn process_add<N: Network>(
        entry: &CoVMOperation<T, C>,
        updated_state: &mut CoVMState<C, T>,
        old_state: &CoVMState<C, T>,
        is_accumulator_empty: T::ArithmeticShare,
        net: &N,
        state_: &mut T::State,
    ) -> eyre::Result<()> {
        let inv = T::add_with_public(
            C::ScalarField::one(),
            T::mul_with_public(-C::ScalarField::one(), is_accumulator_empty),
            state_.id(),
        );
        let other = T::point_add(&old_state.accumulator, &entry.base_point);
        let mul = T::scalar_mul_many(
            &[entry.base_point, other],
            &[is_accumulator_empty, inv],
            net,
            state_,
        );
        let result = T::point_add(&mul[0], &mul[1]);
        updated_state.accumulator = result.into();
        // if old_state.is_accumulator_empty {
        //     updated_state.accumulator = entry.base_point;
        // } else {
        //     updated_state.accumulator = (old_state.accumulator + entry.base_point).into();
        // }

        updated_state.is_accumulator_empty =
            T::point_is_zero_many(&[updated_state.accumulator], net, state_)?[0];
        Ok(())
    }

    // TODO FLORIN: explain what is going on here
    fn process_msm_transition<N: Network>(
        row: &mut CoTranscriptRow<C, T>,
        updated_state: &mut CoVMState<C, T>,
        old_state: &CoVMState<C, T>,
        is_accumulator_empty: T::ArithmeticShare,
        msm_transition_is_zero: T::ArithmeticShare,
        net: &N,
        state_: &mut T::State,
    ) -> eyre::Result<()> {
        let inv = T::add_with_public(
            C::ScalarField::one(),
            T::mul_with_public(-C::ScalarField::one(), is_accumulator_empty),
            state_.id(),
        );
        let if_value = T::point_add(
            &updated_state.msm_accumulator,
            &T::promote_to_trivial_point_share(state_.id(), -offset_generator_scaled::<C>().into()),
        );
        let mut else_value = T::point_add(&old_state.accumulator, &updated_state.msm_accumulator);
        else_value = T::point_add(
            &else_value,
            &T::promote_to_trivial_point_share(state_.id(), -offset_generator_scaled::<C>().into()),
        );
        let mul = T::scalar_mul_many(
            &[if_value, else_value],
            &[is_accumulator_empty, inv],
            net,
            state_,
        );
        let result = T::point_add(&mul[0], &mul[1]);
        let mul = T::scalar_mul(
            &T::point_sub(&result, &updated_state.accumulator),
            msm_transition_is_zero,
            net,
            state_,
        );
        updated_state.accumulator = T::point_add(&updated_state.accumulator, &mul);

        // if old_state.is_accumulator_empty {
        //     updated_state.accumulator = (updated_state.msm_accumulator
        //         - T::promote_to_trivial_point_share(
        //             state_.id(),
        //             offset_generator_scaled::<C>().into(),
        //         ))
        //     .into();
        // } else {
        //     let r = old_state.accumulator;
        //     updated_state.accumulator = (r + updated_state.msm_accumulator
        //         - T::promote_to_trivial_point_share(
        //             state_.id(),
        //             offset_generator_scaled::<C>().into(),
        //         ))
        //     .into();
        // }
        let msm_output = T::point_sub(
            &updated_state.msm_accumulator,
            &T::promote_to_trivial_point_share(state_.id(), offset_generator_scaled::<C>().into()),
        );
        let is_zero = T::point_is_zero_many(&[msm_output, updated_state.accumulator], net, state_)?;

        updated_state.is_accumulator_empty = is_zero[1];

        //TACEO TODO: Batch this is_zero check with others
        row.transcript_msm_infinity = is_zero[0];
        Ok(())
    }

    fn populate_transcript_row<N: Network>(
        row: &mut CoTranscriptRow<C, T>,
        base_point_infinity: T::BaseFieldArithmeticShare,
        entry: &CoVMOperation<T, C>,
        state: &CoVMState<C, T>,
        msm_transition: T::BaseFieldArithmeticShare,
        net: &N,
        state_: &mut T::State,
    ) -> eyre::Result<()> {
        row.accumulator_empty = state.is_accumulator_empty;
        row.q_add = entry.op_code.add;
        row.q_mul = entry.op_code.mul;
        row.q_eq = entry.op_code.eq;
        row.q_reset_accumulator = entry.op_code.reset;
        row.msm_transition = msm_transition;
        row.pc = state.pc;
        row.msm_count = state.count;
        // row.msm_count_zero_at_transition =
        // (state.count + num_muls == 0) && entry.op_code.mul && next_not_msm; // We do this already outside of the function
        //TACEO TODO Batch this function
        let points = T::pointshare_to_field_shares(entry.base_point, net, state_)?;

        if entry.op_code.add || entry.op_code.mul || entry.op_code.eq {
            let mut inv = T::mul_with_public_basefield(-C::BaseField::one(), base_point_infinity);
            T::add_assign_public_basefield(&mut inv, C::BaseField::one(), state_.id());
            let mul = T::mul_many_basefield(&[points.0, points.1], &[inv, inv], net, state_)?;
            row.base_x = mul[0];
            row.base_y = mul[1];
        }
        // row.base_x = if (entry.op_code.add || entry.op_code.mul || entry.op_code.eq)
        //     && !base_point_infinity
        // {
        //     entry
        //         .base_point
        //         .x()
        //         .expect("Base point x should not be zero")
        // } else {
        //     C::BaseField::zero()
        // };
        // row.base_y = if (entry.op_code.add || entry.op_code.mul || entry.op_code.eq)
        //     && !base_point_infinity
        // {
        //     entry
        //         .base_point
        //         .y()
        //         .expect("Base point y should not be zero")
        // } else {
        //     C::BaseField::zero()
        // };
        row.base_infinity = if entry.op_code.add || entry.op_code.mul || entry.op_code.eq {
            base_point_infinity
        } else {
            T::promote_to_trivial_share_basefield(state_.id(), C::BaseField::zero())
        };
        row.z1 = if entry.op_code.mul {
            entry.z1.clone()
        } else {
            T::BaseFieldArithmeticShare::default()
        };
        row.z2 = if entry.op_code.mul {
            entry.z2.clone()
        } else {
            T::BaseFieldArithmeticShare::default()
        };
        // row.z1_zero = entry.z1.is_zero(); // We do this already outside of the function
        // row.z2_zero = entry.z2.is_zero(); // We do this already outside of the function
        row.opcode = entry.op_code.value();
        Ok(())
    }
}

fn add_affine_coordinates_to_transcript<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirUltraHonkProver<C>,
    N: Network,
>(
    transcript_state: &mut [CoTranscriptRow<C, T>],
    accumulator_trace: &[T::PointShare],
    msm_accumulator_trace: &[T::PointShare],
    intermediate_accumulator_trace: &[T::PointShare],
    net: &N,
    state_: &mut T::State,
) -> eyre::Result<()> {
    let (xs, ys, _) = T::pointshare_to_field_shares_many(
        &[
            accumulator_trace,
            msm_accumulator_trace,
            intermediate_accumulator_trace,
        ]
        .concat(),
        net,
        state_,
    )?;
    //TODO FLORIN: check sizes
    let len_acc = accumulator_trace.len();
    let len_msm = msm_accumulator_trace.len();
    let (acc_xs, rest) = xs.split_at(len_acc);
    let (msm_xs, int_xs) = rest.split_at(len_msm);
    let (acc_ys, rest) = ys.split_at(len_acc);
    let (msm_ys, int_ys) = rest.split_at(len_msm);

    for i in 0..accumulator_trace.len() {
        let row = &mut transcript_state[i + 1];
        row.accumulator_x = acc_xs[i];
        row.accumulator_y = acc_ys[i];
        row.msm_output_x = msm_xs[i];
        row.msm_output_y = msm_ys[i];
        row.transcript_msm_intermediate_x = int_xs[i];
        row.transcript_msm_intermediate_y = int_ys[i];
        // if !accumulator_trace[i].is_zero() {
        //     row.accumulator_x = accumulator_trace[i]
        //         .x()
        //         .expect("Accumulator x-coordinate should not be zero");
        //     row.accumulator_y = accumulator_trace[i]
        //         .y()
        //         .expect("Accumulator y-coordinate should not be zero");
        // }
        // if !msm_accumulator_trace[i].is_zero() {
        //     row.msm_output_x = msm_accumulator_trace[i]
        //         .x()
        //         .expect("MSM accumulator x-coordinate should not be zero");
        //     row.msm_output_y = msm_accumulator_trace[i]
        //         .y()
        //         .expect("MSM accumulator y-coordinate should not be zero");
        // }
        // if !intermediate_accumulator_trace[i].is_zero() {
        //     row.transcript_msm_intermediate_x = intermediate_accumulator_trace[i]
        //         .x()
        //         .expect("Intermediate accumulator x-coordinate should not be zero");
        //     row.transcript_msm_intermediate_y = intermediate_accumulator_trace[i]
        //         .y()
        //         .expect("Intermediate accumulator y-coordinate should not be zero");
        // }
    }
    Ok(())
}

#[expect(clippy::too_many_arguments)]
fn compute_inverse_trace_coordinates<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirUltraHonkProver<C>,
    N: Network,
>(
    msm_transition: T::BaseFieldArithmeticShare,
    row: &CoTranscriptRow<C, T>,
    intermediate_accumulator_trace_x: T::BaseFieldArithmeticShare,
    intermediate_accumulator_trace_y: T::BaseFieldArithmeticShare,
    transcript_msm_x_inverse_trace: &mut T::BaseFieldArithmeticShare,
    msm_accumulator_trace_x: T::BaseFieldArithmeticShare,
    msm_accumulator_trace_infinity: T::BaseFieldArithmeticShare,
    accumulator_trace_x: T::BaseFieldArithmeticShare,
    accumulator_trace_y: T::BaseFieldArithmeticShare,
    inverse_trace_x: &mut T::BaseFieldArithmeticShare,
    inverse_trace_y: &mut T::BaseFieldArithmeticShare,
    net: &N,
    state_: &mut T::State,
) -> eyre::Result<()> {
    // let msm_output_infinity = intermediate_accumulator_trace.is_zero();
    let row_msm_infinity = row.transcript_msm_infinity;
    //TODO FLORIN: can do this over scalarfield also and remove some of these functions
    let inv_row_msm_infinity = T::add_with_public_basefield(
        C::BaseField::one(),
        T::mul_with_public_basefield(-C::BaseField::one(), row_msm_infinity),
        state_.id(),
    );

    let inv_accumulator_trace_infinity = T::add_with_public_basefield(
        C::BaseField::one(),
        T::mul_with_public_basefield(-C::BaseField::one(), msm_accumulator_trace_infinity),
        state_.id(),
    );

    let bb_infinity_default =
        T::mul_with_public_basefield(C::get_bb_infinity_default(), msm_accumulator_trace_infinity);

    let mul = T::mul_many_basefield(
        &[msm_accumulator_trace_x],
        &[inv_accumulator_trace_infinity],
        net,
        state_,
    )?;
    let mut result = T::add_basefield(mul[0], bb_infinity_default);
    T::add_assign_public_basefield(
        &mut result,
        -offset_generator_scaled::<C>()
            .x()
            .expect("Offset generator x-coordinate should not be zero"),
        state_.id(),
    );
    let inv_msm_transition = T::add_with_public_basefield(
        C::BaseField::one(),
        T::mul_with_public_basefield(-C::BaseField::one(), msm_transition),
        state_.id(),
    );
    let mul = T::mul_many_basefield(
        &[
            result,
            msm_transition,
            msm_transition,
            inv_msm_transition,
            inv_msm_transition,
        ],
        &[
            inv_row_msm_infinity,
            intermediate_accumulator_trace_x,
            intermediate_accumulator_trace_y,
            row.base_x,
            row.base_y,
        ],
        net,
        state_,
    )?;

    *transcript_msm_x_inverse_trace =
        T::mul_many_basefield(&[result], &[inv_row_msm_infinity], net, state_)?[0];

    let res_x = T::add_basefield(mul[1], mul[3]);
    let res_y = T::add_basefield(mul[2], mul[4]);

    // if row_msm_infinity {
    //     C::BaseField::zero()
    // } else {
    //     msm_accumulator_trace
    //         .x()
    //         .unwrap_or(C::get_bb_infinity_default())
    //         - offset_generator_scaled::<C>()
    //             .x()
    //             .expect("Offset generator x-coordinate should not be zero")
    // };

    let (lhsx, lhsy) = (res_x, res_y);

    let (rhsx, rhsy) = (accumulator_trace_x, accumulator_trace_y);

    *inverse_trace_x = T::sub_basefield(lhsx, rhsx); //lhsx - rhsx;
    *inverse_trace_y = T::sub_basefield(lhsy, rhsy); //lhsy - rhsy;

    Ok(())
}

fn compute_lambda_numerator_and_denominator<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirUltraHonkProver<C>,
    N: Network,
>(
    row: &mut CoTranscriptRow<C, T>,
    entry: &CoVMOperation<T, C>,
    intermediate_accumulator_trace: &T::PointShare,
    accumulator_trace: &T::PointShare,
    accumulator_trace_x: T::BaseFieldArithmeticShare,
    accumulator_trace_y: T::BaseFieldArithmeticShare,
    accumulator_trace_infinity: T::BaseFieldArithmeticShare,
    add_lambda_numerator: &mut T::BaseFieldArithmeticShare,
    add_lambda_denominator: &mut T::BaseFieldArithmeticShare,
    vm_point_x: T::BaseFieldArithmeticShare,
    vm_point_y: T::BaseFieldArithmeticShare,
    vm_infinity: T::BaseFieldArithmeticShare,
    net: &N,
    state_: &mut T::State,
) {
    let vm_point = if entry.op_code.add {
        entry.base_point
    } else {
        *intermediate_accumulator_trace
    };

    // let vm_infinity = vm_point.is_zero();
    // let accumulator_infinity = accumulator_trace.is_zero();

    let vm_x = vm_point_x;
    let vm_y = vm_point_y;

    let accumulator_x = accumulator_trace_x;
    let accumulator_y = accumulator_trace_y;

    // We do this outside of the function
    // row.transcript_add_x_equal = (vm_x == accumulator_x) || (vm_infinity && accumulator_infinity);
    // row.transcript_add_y_equal = (vm_y == accumulator_y) || (vm_infinity && accumulator_infinity);

    todo!("Check if we can avoid some of these multiplications");
    // if (accumulator_x == vm_x) && (accumulator_y == vm_y) && !vm_infinity && !accumulator_infinity {
    //     *add_lambda_denominator = vm_y + vm_y;
    //     *add_lambda_numerator = vm_x * vm_x * C::BaseField::from(3u32);
    // } else if (accumulator_x != vm_x) && !vm_infinity && !accumulator_infinity {
    //     *add_lambda_denominator = accumulator_x - vm_x;
    //     *add_lambda_numerator = accumulator_y - vm_y;
    // }
}

struct CoTranscriptRow<C: HonkCurve<TranscriptFieldType>, T: NoirUltraHonkProver<C>> {
    transcript_msm_infinity: T::BaseFieldArithmeticShare, //bool
    accumulator_empty: T::BaseFieldArithmeticShare,
    q_add: bool,
    q_mul: bool,
    q_eq: bool,
    q_reset_accumulator: bool,
    msm_transition: T::BaseFieldArithmeticShare,
    pc: T::BaseFieldArithmeticShare,
    msm_count: T::BaseFieldArithmeticShare,
    msm_count_zero_at_transition: T::BaseFieldArithmeticShare,
    base_x: T::BaseFieldArithmeticShare,
    base_y: T::BaseFieldArithmeticShare,
    base_infinity: T::BaseFieldArithmeticShare,
    z1: T::BaseFieldArithmeticShare,
    z2: T::BaseFieldArithmeticShare,
    z1_zero: T::BaseFieldArithmeticShare,
    z2_zero: T::BaseFieldArithmeticShare,
    opcode: u32,

    accumulator_x: T::BaseFieldArithmeticShare,
    accumulator_y: T::BaseFieldArithmeticShare,
    msm_output_x: T::BaseFieldArithmeticShare,
    msm_output_y: T::BaseFieldArithmeticShare,
    transcript_msm_intermediate_x: T::BaseFieldArithmeticShare,
    transcript_msm_intermediate_y: T::BaseFieldArithmeticShare,

    transcript_add_x_equal: T::BaseFieldArithmeticShare,
    transcript_add_y_equal: T::BaseFieldArithmeticShare,

    base_x_inverse: T::BaseFieldArithmeticShare,
    base_y_inverse: T::BaseFieldArithmeticShare,
    transcript_add_lambda: T::BaseFieldArithmeticShare,
    transcript_msm_x_inverse: T::BaseFieldArithmeticShare,
    msm_count_at_transition_inverse: T::BaseFieldArithmeticShare,
}

impl<C: HonkCurve<TranscriptFieldType>, T: NoirUltraHonkProver<C>> Default
    for CoTranscriptRow<C, T>
{
    fn default() -> Self {
        Self {
            transcript_msm_infinity: T::BaseFieldArithmeticShare::default(),
            accumulator_empty: T::BaseFieldArithmeticShare::default(),
            q_add: false,
            q_mul: false,
            q_eq: false,
            q_reset_accumulator: false,
            msm_transition: T::BaseFieldArithmeticShare::default(),
            pc: T::BaseFieldArithmeticShare::default(),
            msm_count: T::BaseFieldArithmeticShare::default(),
            msm_count_zero_at_transition: T::BaseFieldArithmeticShare::default(),
            base_x: T::BaseFieldArithmeticShare::default(),
            base_y: T::BaseFieldArithmeticShare::default(),
            base_infinity: T::BaseFieldArithmeticShare::default(),
            z1: T::BaseFieldArithmeticShare::default(),
            z2: T::BaseFieldArithmeticShare::default(),
            z1_zero: T::BaseFieldArithmeticShare::default(),
            z2_zero: T::BaseFieldArithmeticShare::default(),
            opcode: 0,
            accumulator_x: T::BaseFieldArithmeticShare::default(),
            accumulator_y: T::BaseFieldArithmeticShare::default(),
            msm_output_x: T::BaseFieldArithmeticShare::default(),
            msm_output_y: T::BaseFieldArithmeticShare::default(),
            transcript_msm_intermediate_x: T::BaseFieldArithmeticShare::default(),
            transcript_msm_intermediate_y: T::BaseFieldArithmeticShare::default(),
            transcript_add_x_equal: T::BaseFieldArithmeticShare::default(),
            transcript_add_y_equal: T::BaseFieldArithmeticShare::default(),
            base_x_inverse: T::BaseFieldArithmeticShare::default(),
            base_y_inverse: T::BaseFieldArithmeticShare::default(),
            transcript_add_lambda: T::BaseFieldArithmeticShare::default(),
            transcript_msm_x_inverse: T::BaseFieldArithmeticShare::default(),
            msm_count_at_transition_inverse: T::BaseFieldArithmeticShare::default(),
        }
    }
}

fn finalize_transcript<C: HonkCurve<TranscriptFieldType>, T: NoirUltraHonkProver<C>, N: Network>(
    updated_state: &CoVMState<C, T>,
    net: &N,
    state_: &mut T::State,
) -> eyre::Result<CoTranscriptRow<C, T>>
where
    <C as CurveGroup>::BaseField: PrimeField,
{
    let mut final_row = CoTranscriptRow::<C, T>::default();

    let (result_x, result_y, _) =
        T::pointshare_to_field_shares(updated_state.accumulator, net, state_)?; //TODO FLORIN: batch this outside?

    final_row.accumulator_x = result_x;
    final_row.accumulator_y = result_y;

    final_row.pc = updated_state.pc;
    final_row.accumulator_empty = updated_state.is_accumulator_empty;
    Ok(final_row)
}

fn compute_rows<C: HonkCurve<TranscriptFieldType>, T: NoirUltraHonkProver<C>, N: Network>(
    vm_operations: &[CoVMOperation<T, C>],
    total_number_of_muls: T::BaseFieldArithmeticShare,
    net: &N,
    state_: &mut T::State,
) -> eyre::Result<Vec<CoTranscriptRow<C, T>>> {
    // TODO FLORIN: REPLACE WITH CMUXES

    let num_vm_entries = vm_operations.len();
    // The transcript contains an extra zero row at the beginning and the accumulated state at the end
    let transcript_size = num_vm_entries + 2;
    let mut transcript_state = Vec::with_capacity(transcript_size);

    // These vectors track quantities that we need to invert.
    // We fill these vectors and then perform batch inversions to amortize the cost of FF inverts
    let mut inverse_trace_x = vec![T::BaseFieldArithmeticShare::default(); num_vm_entries];
    let mut inverse_trace_y = vec![T::BaseFieldArithmeticShare::default(); num_vm_entries];
    let mut transcript_msm_x_inverse_trace =
        vec![T::BaseFieldArithmeticShare::default(); num_vm_entries];
    let mut add_lambda_denominator = vec![T::BaseFieldArithmeticShare::default(); num_vm_entries];
    let mut add_lambda_numerator = vec![T::BaseFieldArithmeticShare::default(); num_vm_entries];
    let mut msm_count_at_transition_inverse_trace =
        vec![T::BaseFieldArithmeticShare::default(); num_vm_entries];

    let mut msm_accumulator_trace: Vec<_> = vec![T::PointShare::default(); num_vm_entries];
    let mut accumulator_trace: Vec<_> = vec![T::PointShare::default(); num_vm_entries];
    let mut intermediate_accumulator_trace: Vec<_> = vec![T::PointShare::default(); num_vm_entries];

    let mut state = CoVMState::<C, T> {
        pc: total_number_of_muls,
        count: T::BaseFieldArithmeticShare::default(),
        accumulator: T::PointShare::default(),
        msm_accumulator: T::promote_to_trivial_point_share(
            state_.id(),
            offset_generator_scaled::<C>().into(),
        ),
        is_accumulator_empty: T::promote_to_trivial_share_basefield(
            state_.id(),
            C::BaseField::one(),
        ), //true
    };

    let mut updated_state = CoVMState::<C, T>::new(state_.id());

    // add an empty row. 1st row all zeroes because of our shiftable polynomials
    transcript_state.push(CoTranscriptRow::<C, T>::default());

    // during the first iteration over the ECCOpQueue, the operations are being performed using Jacobian
    // coordinates and the base point coordinates are recorded in the transcript. at the same time, the transcript
    // logic is being populated
    let mut tmp_z1_is_zero = Vec::new(); // TODO FLORIN
    let mut tmp_z2_is_zero = Vec::new(); // TODO FLORIN
    let mut indices = Vec::new(); // TODO FLORIN
    let mut base_points = Vec::new(); // TODO FLORIN
    let mut entry_z1 = Vec::new(); // TODO FLORIN
    let mut entry_z2 = Vec::new(); // TODO FLORIN
    for (i, entry) in vm_operations.iter().enumerate() {
        entry_z1.push(entry.z1);
        entry_z2.push(entry.z2);
        base_points.push(entry.base_point);
    }
    let is_zero_results = T::is_zero_many_basefield(&[entry_z1, entry_z2].concat(), net, state_)?;
    let (mut z1_zero_results, mut z2_zero_results) = is_zero_results.split_at(tmp_z1_is_zero.len()); // TODO FLORIN SIZES
    let (z1_is_zero_unchanged, z2_is_zero_unchanged) =
        (z1_zero_results.to_vec(), z2_zero_results.to_vec());
    T::scale_many_in_place_basefield(&mut z1_zero_results, -C::BaseField::one());
    T::add_scalar_in_place_basefield(&mut z1_zero_results, C::BaseField::one(), state_.id());
    T::scale_many_in_place_basefield(&mut z2_zero_results, -C::BaseField::one());
    T::add_scalar_in_place_basefield(&mut z2_zero_results, C::BaseField::one(), state_.id());
    let num_mul_partial = T::add_many_basefield(&z1_zero_results, &z2_zero_results);

    let base_points_is_zero = T::point_is_zero_many(&base_points, net, state_)?;
    let mut base_points_is_zero_modified = base_points_is_zero.clone();
    T::scale_many_in_place_basefield(&mut base_points_is_zero_modified, -C::BaseField::one());
    T::add_scalar_in_place_basefield(
        &mut base_points_is_zero_modified,
        C::BaseField::one(),
        state_.id(),
    );
    let num_mul =
        T::mul_many_basefield(&num_mul_partial, &base_points_is_zero_modified, net, state_)?;

    for i in 0..num_vm_entries {
        let mut row = CoTranscriptRow::<C, T>::default();
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
            updated_state.is_accumulator_empty =
                T::promote_to_trivial_share_basefield(state_.id(), C::BaseField::one()); //true;
            updated_state.accumulator = T::PointShare::default();
            updated_state.msm_accumulator = T::promote_to_trivial_point_share(
                state_.id(),
                offset_generator_scaled::<C>().into(),
            );
        }

        let last_row = i == (num_vm_entries - 1);

        // msm transition = current row is doing a lookup to validate output = msm output
        // i.e. next row is not part of MSM and current row is part of MSM
        //   or next row is irrelevant and current row is a straight MUL
        let next_not_msm = last_row || !vm_operations[i + 1].op_code.mul;

        //     // we reset the count in updated state if we are not accumulating and not doing an msm
        let mut msm_transition_public = true;
        let mut is_zero = T::BaseFieldArithmeticShare::default();
        // is_mul && next_not_msm && (state.count + num_muls > 0);
        if !(is_mul && next_not_msm) {
            msm_transition_public = false;
        } else {
            is_zero =
                T::is_zero_many_basefield(&[T::add_basefield(state.count, num_muls)], net, state_)?
                    [0]; //TODO FLORIN BATCH WITH OTHER IS_ZERO
        }
        let msm_transition = T::mul_with_public_basefield(
            C::BaseField::from(entry.op_code.mul && next_not_msm),
            is_zero,
        );
        row.msm_count_zero_at_transition = msm_transition; // This happens in bb inside populate_transcript_row, for simplicity we do it here 
        // we want state.count + num_muls > 0, hence we invert the is_zero result
        is_zero = T::sub_basefield(
            T::promote_to_trivial_share_basefield(state_.id(), C::BaseField::one()),
            is_zero,
        );

        // determine ongoing msm and update the respective counter
        let current_ongoing_msm = is_mul && !next_not_msm;

        updated_state.count = if current_ongoing_msm {
            T::add_basefield(state.count, num_muls)
        } else {
            T::BaseFieldArithmeticShare::default()
        };

        if is_mul {
            CoVMState::<C, T>::process_mul(entry, &mut updated_state, &state, net, state_);
        }

        let old_state_accumulator_is_zero =
            T::is_zero_many_basefield(&[state.is_accumulator_empty], net, state_)?[0];

        if msm_transition_public {
            CoVMState::<C, T>::process_msm_transition(
                &mut row,
                &mut updated_state,
                &state,
                T::convert_fields(&[old_state_accumulator_is_zero])?[0],
                T::convert_fields(&[is_zero])?[0],
                net,
                state_,
            ); //TODO NEED TO MULTYIPLY/CORRECT THIS WITH THE IS_ZEROCHECK
        } else {
            msm_accumulator_trace[i] = T::PointShare::default();
            intermediate_accumulator_trace[i] = T::PointShare::default();
        }

        if is_add {
            CoVMState::<C, T>::process_add(
                entry,
                &mut updated_state,
                &state,
                T::convert_fields(&[old_state_accumulator_is_zero])?[0],
                net,
                state_,
            );
        }

        row.z1_zero = z1_is_zero_unchanged[i]; // We do this already outside of the function
        row.z2_zero = z2_is_zero_unchanged[i]; // We do this already outside of the function

        //     // populate the first group of TranscriptRow entries
        CoVMState::<C, T>::populate_transcript_row(
            &mut row,
            base_points_is_zero[i],
            entry,
            &state,
            msm_transition,
            net,
            state_,
        );

        msm_count_at_transition_inverse_trace[i] = T::add_basefield(state.count, num_muls);

        //      update the accumulators
        accumulator_trace[i] = state.accumulator;
        let msm_transition_as_scalarfield = T::convert_fields(&[msm_transition])?[0];
        let mul = T::scalar_mul_many(
            &[
                updated_state.msm_accumulator,
                T::point_add(
                    &updated_state.msm_accumulator,
                    &T::promote_to_trivial_point_share(
                        state_.id(),
                        -offset_generator_scaled::<C>().into(),
                    ),
                ),
            ],
            &[msm_transition_as_scalarfield, msm_transition_as_scalarfield],
            net,
            state_,
        );

        msm_accumulator_trace[i] = mul[0];
        intermediate_accumulator_trace[i] = mul[1];

        state = updated_state.clone();

        if is_mul && next_not_msm {
            state.msm_accumulator = T::promote_to_trivial_point_share(
                state_.id(),
                offset_generator_scaled::<C>().into(),
            );
        }
        transcript_state.push(row);
    }
    // compute affine coordinates of the accumulated points
    // TODO FLORIN STILL NEED TO DO THIS
    // accumulator_trace = Utils::batch_normalize::<C>(&accumulator_trace);
    // msm_accumulator_trace = Utils::batch_normalize::<C>(&msm_accumulator_trace);
    // intermediate_accumulator_trace = Utils::batch_normalize::<C>(&intermediate_accumulator_trace);

    // add required affine coordinates to the transcript
    // add_affine_coordinates_to_transcript(
    //     &mut transcript_state,
    //     &accumulator_trace,
    //     &msm_accumulator_trace,
    //     &intermediate_accumulator_trace,
    //     net,
    //     state_,
    // );

    let (xs, ys, inf) = T::pointshare_to_field_shares_many(
        &[
            accumulator_trace,
            msm_accumulator_trace,
            intermediate_accumulator_trace,
        ]
        .concat(),
        net,
        state_,
    )?;
    //TODO FLORIN: check sizes
    let len_acc = accumulator_trace.len();
    let len_msm = msm_accumulator_trace.len();
    let (acc_xs, rest) = xs.split_at(len_acc);
    let (msm_xs, int_xs) = rest.split_at(len_msm);
    let (acc_ys, rest) = ys.split_at(len_acc);
    let (msm_ys, int_ys) = rest.split_at(len_msm);
    let (acc_inf, rest) = inf.split_at(len_acc);
    let (msm_inf, int_inf) = rest.split_at(len_msm);

    for i in 0..accumulator_trace.len() {
        let row = &mut transcript_state[i + 1];
        row.accumulator_x = acc_xs[i];
        row.accumulator_y = acc_ys[i];
        row.msm_output_x = msm_xs[i];
        row.msm_output_y = msm_ys[i];
        row.transcript_msm_intermediate_x = int_xs[i];
        row.transcript_msm_intermediate_y = int_ys[i];
        // if !accumulator_trace[i].is_zero() {
        //     row.accumulator_x = accumulator_trace[i]
        //         .x()
        //         .expect("Accumulator x-coordinate should not be zero");
        //     row.accumulator_y = accumulator_trace[i]
        //         .y()
        //         .expect("Accumulator y-coordinate should not be zero");
        // }
        // if !msm_accumulator_trace[i].is_zero() {
        //     row.msm_output_x = msm_accumulator_trace[i]
        //         .x()
        //         .expect("MSM accumulator x-coordinate should not be zero");
        //     row.msm_output_y = msm_accumulator_trace[i]
        //         .y()
        //         .expect("MSM accumulator y-coordinate should not be zero");
        // }
        // if !intermediate_accumulator_trace[i].is_zero() {
        //     row.transcript_msm_intermediate_x = intermediate_accumulator_trace[i]
        //         .x()
        //         .expect("Intermediate accumulator x-coordinate should not be zero");
        //     row.transcript_msm_intermediate_y = intermediate_accumulator_trace[i]
        //         .y()
        //         .expect("Intermediate accumulator y-coordinate should not be zero");
        // }
    }

    // process the slopes when adding points or results of MSMs. to increase efficiency, we use batch inversion
    // after the loop
    // let points = T::pointshare_to_field_shares_many(
    //     &[
    //         &accumulator_trace,
    //         &msm_accumulator_trace,
    //         &intermediate_accumulator_trace,
    //     ]
    //     .concat(),
    //     net,
    //     state_,
    // )?;

    let mut is_zero_vm_point = Vec::new();
    for i in 0..accumulator_trace.len() {
        let entry = &vm_operations[i];
        if entry.op_code.add {
            is_zero_vm_point.push(vm_operations[i].base_point);
        } else {
            is_zero_vm_point.push(intermediate_accumulator_trace[i]);
        }
    }
    //TODO FLORIN: BATCH THESE
    let (vm_points_x, vm_points_y, vm_points_inf) =
        T::pointshare_to_field_shares_many(&is_zero_vm_point, net, state_)?;
    let is_zero_results = T::point_is_zero_many(&is_zero_vm_point, net, state_)?;
    let mul = T::mul_many_basefield(&is_zero_results, &acc_inf, net, state_)?;
    let mul_transcript_add = T::mul_many_basefield(&vm_points_inf, &acc_inf, net, state_)?;
    let to_cmp_x = T::sub_many_basefield(&vm_points_x, &acc_xs);
    let to_cmp_y = T::sub_many_basefield(&vm_points_y, &acc_ys);
    let is_zero_transcript_add =
        T::is_zero_many_basefield(&[to_cmp_x, to_cmp_y].concat(), net, state_)?;
    let transcript_add_values = T::add_many_basefield(
        &is_zero_transcript_add[..num_vm_entries],
        &mul_transcript_add[..num_vm_entries],
    );
    let (transcript_add_x_equal, transcript_add_y_equal) =
        transcript_add_values.split_at(transcript_add_values.len() / 2);
    for i in 0..accumulator_trace.len() {
        let row = &mut transcript_state[i + 1];
        let msm_transition = row.msm_transition;

        let entry = &vm_operations[i];
        let is_add = entry.op_code.add;

        // if is_add {
        // compute the differences between point coordinates
        compute_inverse_trace_coordinates::<C, T, N>(
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
            net,
            state_,
        );

        row.transcript_add_x_equal = transcript_add_x_equal[i]; //(vm_x == accumulator_x) || (vm_infinity && accumulator_infinity);
        row.transcript_add_y_equal = transcript_add_y_equal[i]; //(vm_y == accumulator_y) || (vm_infinity && accumulator_infinity);

        // compute the numerators and denominators of slopes between the points
        compute_lambda_numerator_and_denominator::<C, T, N>(
            row,
            entry,
            &intermediate_accumulator_trace[i],
            &accumulator_trace[i],
            acc_xs[i],
            acc_ys[i],
            acc_inf[i],
            &mut add_lambda_numerator[i],
            &mut add_lambda_denominator[i],
            vm_points_x[i],
            vm_points_y[i],
            vm_points_inf[i],
            net,
            state_,
        );
        // }
        // else if msm_transition ||  //TODO FLORIN
        // else {
        // row.transcript_add_x_equal = T::BaseFieldArithmeticShare::default();
        // row.transcript_add_y_equal = T::BaseFieldArithmeticShare::default();
        // add_lambda_numerator[i] = T::BaseFieldArithmeticShare::default();
        // add_lambda_denominator[i] = T::BaseFieldArithmeticShare::default();
        // inverse_trace_x[i] = T::BaseFieldArithmeticShare::default();
        // inverse_trace_y[i] = T::BaseFieldArithmeticShare::default();
        // }
        // }
    }
    let mut tmp_transcript_add_x_equal = Vec::new(); //TODO FLORIN
    let mut tmp_transcript_add_y_equal = Vec::new(); //TODO FLORIN
    let mut tmp_add_lambda_numerator = Vec::new(); //TODO FLORIN
    let mut tmp_add_lambda_denominator = Vec::new(); //TODO FLORIN
    let mut tmp_inverse_trace_x = Vec::new(); //TODO FLORIN
    let mut tmp_inverse_trace_y = Vec::new(); //TODO FLORIN
    let mut tmp_msm_transition = Vec::new(); //TODO FLORIN
    let mut indices = Vec::new(); //TODO FLORIN
    for i in 0..accumulator_trace.len() {
        let row = &transcript_state[i + 1];
        if vm_operations[i].op_code.add {
            continue;
        } else {
            tmp_transcript_add_x_equal.push(row.transcript_add_x_equal);
            tmp_transcript_add_y_equal.push(row.transcript_add_y_equal);
            tmp_add_lambda_numerator.push(add_lambda_numerator[i]);
            tmp_add_lambda_denominator.push(add_lambda_denominator[i]);
            tmp_inverse_trace_x.push(inverse_trace_x[i]);
            tmp_inverse_trace_y.push(inverse_trace_y[i]);
            tmp_msm_transition.push(row.msm_transition);
            indices.push(i);
        }
    }
    let mul = T::mul_many_basefield(
        &[
            tmp_transcript_add_x_equal,
            tmp_transcript_add_y_equal,
            tmp_add_lambda_numerator,
            tmp_add_lambda_denominator,
            tmp_inverse_trace_x,
            tmp_inverse_trace_y,
        ]
        .concat(),
        &[
            tmp_msm_transition.clone(),
            tmp_msm_transition.clone(),
            tmp_msm_transition.clone(),
            tmp_msm_transition.clone(),
            tmp_msm_transition.clone(),
            tmp_msm_transition.clone(),
        ]
        .concat(),
        net,
        state_,
    )?; //TODO FLORIN is this possible to make nicer
    for (j, i) in indices.iter().enumerate() {
        transcript_state[i + 1].transcript_add_x_equal = mul[j];
        transcript_state[i + 1].transcript_add_y_equal = mul[j + indices.len()];
        add_lambda_numerator[*i] = mul[j + 2 * indices.len()];
        add_lambda_denominator[*i] = mul[j + 3 * indices.len()];
        inverse_trace_x[*i] = mul[j + 4 * indices.len()];
        inverse_trace_y[*i] = mul[j + 5 * indices.len()];
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
    let final_row = finalize_transcript(&updated_state, net, state_)?;
    transcript_state.push(final_row);

    Ok(transcript_state)
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
