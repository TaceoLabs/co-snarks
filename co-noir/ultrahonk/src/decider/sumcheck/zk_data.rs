use crate::Utils;
use crate::plain_prover_flavour::UnivariateTrait;
use crate::prelude::Transcript;
use crate::prelude::TranscriptHasher;
use crate::prelude::Univariate;
use crate::transcript::TranscriptFieldType;
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_ff::One;
use ark_ff::UniformRand;
use ark_ff::Zero;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use co_builder::HonkProofError;
use co_builder::HonkProofResult;
use co_builder::prelude::HonkCurve;
use co_builder::prelude::Polynomial;
use rand::CryptoRng;
use rand::Rng;

pub(crate) struct ZKSumcheckData<P: Pairing> {
    pub(crate) constant_term: P::ScalarField,
    pub(crate) interpolation_domain: Vec<P::ScalarField>,
    pub(crate) libra_concatenated_lagrange_form: Polynomial<P::ScalarField>,
    pub(crate) libra_concatenated_monomial_form: Polynomial<P::ScalarField>,
    pub(crate) libra_univariates: Vec<Polynomial<P::ScalarField>>,
    pub(crate) log_circuit_size: usize,
    pub(crate) libra_scaling_factor: P::ScalarField,
    pub(crate) libra_challenge: P::ScalarField,
    pub(crate) libra_total_sum: P::ScalarField,
    pub(crate) libra_running_sum: P::ScalarField,
    pub(crate) libra_evaluations: Vec<P::ScalarField>,
}

impl<P: HonkCurve<TranscriptFieldType>> ZKSumcheckData<P> {
    pub(crate) fn new<H: TranscriptHasher<TranscriptFieldType>, R: Rng + CryptoRng>(
        multivariate_d: usize,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        commitment_key: &[P::G1Affine],
        rng: &mut R,
    ) -> HonkProofResult<Self> {
        let constant_term = P::ScalarField::rand(rng);
        let libra_challenge = P::ScalarField::default();
        let libra_univariates =
            Self::generate_libra_univariates(multivariate_d, P::LIBRA_UNIVARIATES_LENGTH, rng);
        let log_circuit_size = multivariate_d;

        let mut data = ZKSumcheckData {
            constant_term,
            interpolation_domain: vec![P::ScalarField::zero(); P::SUBGROUP_SIZE],
            libra_concatenated_lagrange_form: Polynomial::new_zero(P::SUBGROUP_SIZE),
            libra_concatenated_monomial_form: Polynomial::new_zero(P::SUBGROUP_SIZE + 2),
            libra_univariates,
            log_circuit_size,
            libra_scaling_factor: P::ScalarField::one(),
            libra_challenge,
            libra_total_sum: P::ScalarField::zero(),
            libra_running_sum: P::ScalarField::zero(),
            libra_evaluations: Vec::new(),
        };

        data.create_interpolation_domain();
        data.compute_concatenated_libra_polynomial(rng)?;
        // If proving_key is provided, commit to the concatenated and masked libra polynomial
        if !commitment_key.is_empty() {
            let libra_commitment = Utils::msm::<P>(
                &data.libra_concatenated_monomial_form.coefficients,
                commitment_key,
            )?;
            transcript.send_point_to_verifier::<P>(
                "Libra:concatenation_commitment".to_string(),
                libra_commitment.into(),
            );
        }

        // Compute the total sum of the Libra polynomials
        data.libra_total_sum = Self::compute_libra_total_sum(
            &data.libra_univariates,
            &mut data.libra_scaling_factor,
            data.constant_term,
        );
        // Send the Libra total sum to the transcript
        transcript.send_fr_to_verifier::<P>("Libra:Sum".to_string(), data.libra_total_sum);
        data.libra_challenge = transcript.get_challenge::<P>("Libra:Challenge".to_string());
        data.libra_running_sum = data.libra_total_sum * data.libra_challenge;
        data.setup_auxiliary_data();

        Ok(data)
    }

    /**
     * @brief Given number of univariate polynomials and the number of their evaluations meant to be hidden, this method
     * produces a vector of univariate polynomials of length Flavor::BATCHED_RELATION_PARTIAL_LENGTH with
     * independent uniformly random coefficients.
     *
     */
    fn generate_libra_univariates<R: Rng + CryptoRng>(
        number_of_polynomials: usize,
        univariate_length: usize,
        rng: &mut R,
    ) -> Vec<Polynomial<P::ScalarField>> {
        (0..number_of_polynomials)
            .map(|_| Polynomial::random(univariate_length, rng))
            .collect()
    }

    /**
     * @brief Compute the sum of the randomly sampled multivariate polynomial \f$ G = \sum_{i=0}^{n-1} g_i(X_i) \f$ over
     * the Boolean hypercube.
     *
     * @param libra_univariates
     * @param scaling_factor
     * @return FF
     */
    fn compute_libra_total_sum(
        libra_univariates: &[Polynomial<P::ScalarField>],
        scaling_factor: &mut P::ScalarField,
        constant_term: P::ScalarField,
    ) -> P::ScalarField {
        let mut total_sum = P::ScalarField::zero();
        let two_inv = P::ScalarField::from(2).inverse().expect("non-zero");
        *scaling_factor *= two_inv;

        for univariate in libra_univariates {
            total_sum += univariate.coefficients[0] + univariate.eval_poly(P::ScalarField::one());
            *scaling_factor += *scaling_factor;
        }
        total_sum *= *scaling_factor;

        total_sum + constant_term * P::ScalarField::from(1 << libra_univariates.len())
    }

    /**
     * @brief Set up Libra book-keeping table that simplifies the computation of Libra Round Univariates
     *
     * @details The array of Libra univariates is getting scaled
     * \f{align}{\texttt{libra_univariates} \gets \texttt{libra_univariates}\cdot \rho \cdot 2^{d-1}\f}
     * We also initialize
     * \f{align}{ \texttt{libra_running_sum} \gets \texttt{libra_total_sum} - \texttt{libra_univariates}_{0,0} -
     * \texttt{libra_univariates}_{0,1} \f}.
     * @param libra_table
     * @param libra_round_factor
     * @param libra_challenge
     */
    fn setup_auxiliary_data(&mut self) {
        let two_inv = P::ScalarField::from(2).inverse().expect("non-zero");
        self.libra_scaling_factor *= self.libra_challenge;
        for univariate in &mut self.libra_univariates {
            *univariate *= self.libra_scaling_factor;
        }
        self.libra_running_sum += -self.libra_univariates[0].coefficients[0]
            - self.libra_univariates[0].eval_poly(P::ScalarField::one());
        self.libra_running_sum *= two_inv;
    }

    /**
     * @brief Create a interpolation domain object and initialize the evaluation domain in the case of BN254 scalar
     * field
     *
     */
    fn create_interpolation_domain(&mut self) {
        self.interpolation_domain[0] = P::ScalarField::one();
        let subgroup_generator = P::get_subgroup_generator();
        for idx in 1..P::SUBGROUP_SIZE {
            self.interpolation_domain[idx] =
                self.interpolation_domain[idx - 1] * subgroup_generator;
        }
    }

    /** @brief  Compute concatenated libra polynomial in lagrange basis, transform to monomial, add masking term Z_H(m_0
     * + m_1
     *
     */
    fn compute_concatenated_libra_polynomial<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> HonkProofResult<()> {
        let mut coeffs_lagrange_subgroup = vec![P::ScalarField::zero(); P::SUBGROUP_SIZE];
        coeffs_lagrange_subgroup[0] = self.constant_term;

        for poly_idx in 0..self.log_circuit_size {
            for idx in 0..P::LIBRA_UNIVARIATES_LENGTH {
                let idx_to_populate = 1 + poly_idx * P::LIBRA_UNIVARIATES_LENGTH + idx;
                coeffs_lagrange_subgroup[idx_to_populate] =
                    self.libra_univariates[poly_idx].coefficients[idx];
            }
        }

        self.libra_concatenated_lagrange_form = Polynomial {
            coefficients: coeffs_lagrange_subgroup,
        };

        let masking_scalars = Univariate::<P::ScalarField, 2>::get_random(rng);

        let domain = GeneralEvaluationDomain::<P::ScalarField>::new(P::SUBGROUP_SIZE)
            .ok_or(HonkProofError::LargeSubgroup)?;

        let coeffs_lagrange_subgroup_ifft =
            domain.ifft(&self.libra_concatenated_lagrange_form.coefficients);
        let libra_concatenated_monomial_form_unmasked = Polynomial::<P::ScalarField> {
            coefficients: coeffs_lagrange_subgroup_ifft,
        };

        for idx in 0..P::SUBGROUP_SIZE {
            self.libra_concatenated_monomial_form.coefficients[idx] =
                libra_concatenated_monomial_form_unmasked.coefficients[idx];
        }

        for idx in 0..masking_scalars.evaluations.len() {
            self.libra_concatenated_monomial_form.coefficients[idx] -=
                masking_scalars.evaluations[idx];
            self.libra_concatenated_monomial_form.coefficients[P::SUBGROUP_SIZE + idx] +=
                masking_scalars.evaluations[idx];
        }
        Ok(())
    }

    /**
    * @brief Upon receiving the challenge \f$u_i\f$, the prover updates Libra data. If \f$ i < d-1\f$

       -  update the table of Libra univariates by multiplying every term by \f$1/2\f$.
       -  computes the value \f$2^{d-i - 2} \cdot \texttt{libra_challenge} \cdot g_0(u_0)\f$ applying \ref
          bb::Univariate::evaluate "evaluate" method to the first univariate in the table \f$\texttt{libra_univariates}\f$
       -  places the value \f$ g_0(u_0)\f$ to the vector \f$ \texttt{libra_evaluations}\f$
       -  update the running sum
          \f{align}{
          \texttt{libra_running_sum} \gets  2^{d-i-2} \cdot \texttt{libra_challenge} \cdot g_0(u_0) +  2^{-1}
          \cdot \left( \texttt{libra_running_sum} - (\texttt{libra_univariates}_{i+1}(0) +
          \texttt{libra_univariates}_{i+1}(1)) \right) \f} If \f$ i = d-1\f$
       -  compute the value \f$ g_{d-1}(u_{d-1})\f$ applying \ref bb::Univariate::evaluate "evaluate" method to the
          last univariate in the table \f$\texttt{libra_univariates}\f$ and dividing the result by \f$
          \texttt{libra_challenge} \f$.
       -  update the table of Libra univariates by multiplying every term by \f$\texttt{libra_challenge}^{-1}\f$.
          @todo Refactor once the Libra univariates are extracted from the Proving Key. Then the prover does not need to
          update the first round_idx - 1 univariates and could release the memory. Also, use batch_invert / reduce
          the number of divisions by 2.
    * @param libra_univariates
    * @param round_challenge
    * @param round_idx
    * @param libra_running_sum
    * @param libra_evaluations
    */
    pub(crate) fn update_zk_sumcheck_data(
        &mut self,
        round_challenge: P::ScalarField,
        round_idx: usize,
    ) {
        let two_inv = P::ScalarField::from(2).inverse().expect("non-zero");
        // when round_idx = d - 1, the update is not needed
        if round_idx < self.log_circuit_size - 1 {
            for univariate in &mut self.libra_univariates {
                *univariate *= two_inv;
            }
            // compute the evaluation \f$ \rho \cdot 2^{d-2-i} \çdot g_i(u_i) \f$
            let libra_evaluation = self.libra_univariates[round_idx].eval_poly(round_challenge);
            let next_libra_univariate = &self.libra_univariates[round_idx + 1];
            // update the running sum by adding g_i(u_i) and subtracting (g_i(0) + g_i(1))
            self.libra_running_sum += -next_libra_univariate.coefficients[0]
                - next_libra_univariate.eval_poly(P::ScalarField::one());
            self.libra_running_sum *= two_inv;

            self.libra_running_sum += libra_evaluation;
            self.libra_scaling_factor *= two_inv;

            self.libra_evaluations
                .push(libra_evaluation / self.libra_scaling_factor);
        } else {
            // compute the evaluation of the last Libra univariate at the challenge u_{d-1}
            let libra_evaluation = self.libra_univariates[round_idx].eval_poly(round_challenge)
                / self.libra_scaling_factor;
            // place the evalution into the vector of Libra evaluations
            self.libra_evaluations.push(libra_evaluation);
            for univariate in &mut self.libra_univariates {
                *univariate *= self.libra_challenge.inverse().expect("non-zero");
            }
        }
    }
}
