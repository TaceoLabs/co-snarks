use std::marker::PhantomData;

use ark_ec::CurveGroup;
use ark_ff::One;
use ark_ff::Zero;
use co_builder::prelude::NUM_DISABLED_ROWS_IN_SUMCHECK;
use co_builder::prelude::NUM_TRANSLATION_EVALUATIONS;
use co_builder::prelude::Polynomial;
use co_builder::{
    HonkProofResult,
    prelude::{HonkCurve, ProverCrs},
};
use co_ultrahonk::prelude::SharedSmallSubgroupIPAProver;
use co_ultrahonk::prelude::SharedUnivariate;
use co_ultrahonk::prelude::SharedUnivariateTrait;
use common::CoUtils;
use common::shared_polynomial::SharedPolynomial;
use common::{
    mpc::NoirUltraHonkProver,
    transcript::{Transcript, TranscriptFieldType, TranscriptHasher},
};
use mpc_net::Network;

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
