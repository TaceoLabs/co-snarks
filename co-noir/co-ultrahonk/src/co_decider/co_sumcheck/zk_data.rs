use crate::CoUtils;
use crate::co_decider::polynomial::SharedPolynomial;
use crate::co_decider::univariates::SharedUnivariate;
use crate::mpc::NoirUltraHonkProver;
use crate::prelude::TranscriptHasher;
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_ff::One;
use ark_ff::Zero;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use co_builder::HonkProofError;
use co_builder::HonkProofResult;
use co_builder::TranscriptFieldType;
use co_builder::prelude::HonkCurve;
use mpc_core::MpcState as _;
use mpc_net::Network;
use ultrahonk::prelude::Transcript;

pub(crate) struct SharedZKSumcheckData<T: NoirUltraHonkProver<P>, P: Pairing> {
    pub(crate) constant_term: T::ArithmeticShare,
    pub(crate) interpolation_domain: Vec<P::ScalarField>,
    pub(crate) libra_concatenated_lagrange_form: SharedPolynomial<T, P>,
    pub(crate) libra_concatenated_monomial_form: SharedPolynomial<T, P>,
    pub(crate) libra_univariates: Vec<SharedPolynomial<T, P>>,
    pub(crate) log_circuit_size: usize,
    pub(crate) libra_scaling_factor: P::ScalarField,
    pub(crate) libra_challenge: P::ScalarField,
    pub(crate) libra_total_sum: P::ScalarField,
    pub(crate) libra_running_sum: T::ArithmeticShare,
    pub(crate) libra_evaluations: Vec<T::ArithmeticShare>,
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>> SharedZKSumcheckData<T, P> {
    pub(crate) fn new<H: TranscriptHasher<TranscriptFieldType>, N: Network>(
        multivariate_d: usize,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        commitment_key: &[P::G1Affine],
        net: &N,
        state: &mut T::State,
    ) -> HonkProofResult<Self> {
        let constant_term = T::rand(net, state)?;
        let libra_univariates = Self::generate_libra_univariates(
            multivariate_d,
            P::LIBRA_UNIVARIATES_LENGTH,
            net,
            state,
        )?;
        let log_circuit_size = multivariate_d;

        let mut data = SharedZKSumcheckData {
            constant_term,
            interpolation_domain: vec![P::ScalarField::zero(); P::SUBGROUP_SIZE],
            libra_concatenated_lagrange_form: SharedPolynomial::new_zero(P::SUBGROUP_SIZE),
            libra_concatenated_monomial_form: SharedPolynomial::new_zero(P::SUBGROUP_SIZE + 2),
            libra_univariates,
            log_circuit_size,
            libra_scaling_factor: P::ScalarField::one(),
            libra_challenge: P::ScalarField::zero(),
            libra_total_sum: P::ScalarField::zero(),
            libra_running_sum: T::ArithmeticShare::default(),
            libra_evaluations: Vec::new(),
        };

        data.create_interpolation_domain();
        data.compute_concatenated_libra_polynomial(net, state)?;
        // If proving_key is provided, commit to the concatenated and masked libra polynomial
        if !commitment_key.is_empty() {
            let libra_commitment_shared = CoUtils::msm::<T, P>(
                data.libra_concatenated_monomial_form.coefficients.as_ref(),
                commitment_key,
            );
            let libra_commitment = T::open_point(libra_commitment_shared, net, state)?;
            transcript.send_point_to_verifier::<P>(
                "Libra:concatenation_commitment".to_string(),
                libra_commitment.into(),
            );
        }

        // Compute the total sum of the Libra polynomials
        let libra_total_sum = Self::compute_libra_total_sum(
            &data.libra_univariates,
            &mut data.libra_scaling_factor,
            data.constant_term,
        );
        // Send the Libra total sum to the transcript
        data.libra_total_sum = T::open_many(&[libra_total_sum], net, state)?[0];
        transcript.send_fr_to_verifier::<P>("Libra:Sum".to_string(), data.libra_total_sum);
        data.libra_challenge = transcript.get_challenge::<P>("Libra:Challenge".to_string());

        data.libra_running_sum =
            T::promote_to_trivial_share(state.id(), data.libra_total_sum * data.libra_challenge);
        data.setup_auxiliary_data();

        Ok(data)
    }

    /**
     * @brief Given number of univariate polynomials and the number of their evaluations meant to be hidden, this method
     * produces a vector of univariate polynomials of length Flavor::BATCHED_RELATION_PARTIAL_LENGTH with
     * independent uniformly random coefficients.
     *
     */
    fn generate_libra_univariates<N: Network>(
        number_of_polynomials: usize,
        univariate_length: usize,
        net: &N,
        state: &mut T::State,
    ) -> eyre::Result<Vec<SharedPolynomial<T, P>>> {
        (0..number_of_polynomials)
            .map(|_| SharedPolynomial::random(univariate_length, net, state))
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
        libra_univariates: &[SharedPolynomial<T, P>],
        scaling_factor: &mut P::ScalarField,
        constant_term: T::ArithmeticShare,
    ) -> T::ArithmeticShare {
        let mut total_sum = T::ArithmeticShare::default();
        let two_inv = P::ScalarField::from(2).inverse().expect("non-zero");
        *scaling_factor *= two_inv;

        for univariate in libra_univariates {
            let eval = T::eval_poly(&univariate.coefficients, P::ScalarField::one());
            let tmp = T::add(univariate.coefficients[0], eval);
            total_sum = T::add(total_sum, tmp);
            *scaling_factor += *scaling_factor;
        }
        total_sum = T::mul_with_public(*scaling_factor, total_sum);
        let mul = T::mul_with_public(
            P::ScalarField::from(1 << libra_univariates.len()),
            constant_term,
        );
        T::add(total_sum, mul)
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
            univariate.mul_assign(self.libra_scaling_factor);
        }
        let eval = T::eval_poly(
            &self.libra_univariates[0].coefficients,
            P::ScalarField::one(),
        );
        let sub = T::add(eval, self.libra_univariates[0].coefficients[0]);
        self.libra_running_sum = T::sub(self.libra_running_sum, sub);
        self.libra_running_sum = T::mul_with_public(two_inv, self.libra_running_sum);
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
    fn compute_concatenated_libra_polynomial<N: Network>(
        &mut self,
        net: &N,
        state: &mut T::State,
    ) -> HonkProofResult<()> {
        let mut coeffs_lagrange_subgroup = vec![T::ArithmeticShare::default(); P::SUBGROUP_SIZE];
        coeffs_lagrange_subgroup[0] = self.constant_term;

        for poly_idx in 0..self.log_circuit_size {
            for idx in 0..P::LIBRA_UNIVARIATES_LENGTH {
                let idx_to_populate = 1 + poly_idx * P::LIBRA_UNIVARIATES_LENGTH + idx;
                coeffs_lagrange_subgroup[idx_to_populate] =
                    self.libra_univariates[poly_idx].coefficients[idx];
            }
        }

        self.libra_concatenated_lagrange_form = SharedPolynomial::<T, P> {
            coefficients: coeffs_lagrange_subgroup,
        };

        let masking_scalars = SharedUnivariate::<T, P, 2>::get_random(net, state)?;

        let domain = GeneralEvaluationDomain::<P::ScalarField>::new(P::SUBGROUP_SIZE)
            .ok_or(HonkProofError::LargeSubgroup)?;

        let coeffs_lagrange_subgroup_ifft =
            T::ifft(&self.libra_concatenated_lagrange_form.coefficients, &domain);
        let libra_concatenated_monomial_form_unmasked = SharedPolynomial::<T, P> {
            coefficients: coeffs_lagrange_subgroup_ifft,
        };

        for idx in 0..P::SUBGROUP_SIZE {
            self.libra_concatenated_monomial_form.coefficients[idx] =
                libra_concatenated_monomial_form_unmasked.coefficients[idx];
        }

        for idx in 0..masking_scalars.evaluations.len() {
            self.libra_concatenated_monomial_form.coefficients[idx] = T::sub(
                self.libra_concatenated_monomial_form.coefficients[idx],
                masking_scalars.evaluations[idx],
            );
            self.libra_concatenated_monomial_form.coefficients[P::SUBGROUP_SIZE + idx] = T::add(
                self.libra_concatenated_monomial_form.coefficients[P::SUBGROUP_SIZE + idx],
                masking_scalars.evaluations[idx],
            );
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
                univariate.mul_assign(two_inv);
            }
            // compute the evaluation \f$ \rho \cdot 2^{d-2-i} \çdot g_i(u_i) \f$
            let libra_evaluation = T::eval_poly(
                &self.libra_univariates[round_idx].coefficients,
                round_challenge,
            );
            let next_libra_univariate = &self.libra_univariates[round_idx + 1];
            // update the running sum by adding g_i(u_i) and subtracting (g_i(0) + g_i(1))
            let eval = T::eval_poly(&next_libra_univariate.coefficients, P::ScalarField::one());
            let add = T::add(next_libra_univariate.coefficients[0], eval);
            self.libra_running_sum = T::sub(self.libra_running_sum, add);
            self.libra_running_sum = T::mul_with_public(two_inv, self.libra_running_sum);

            self.libra_running_sum = T::add(self.libra_running_sum, libra_evaluation);
            self.libra_scaling_factor *= two_inv;

            self.libra_evaluations.push(T::mul_with_public(
                self.libra_scaling_factor.inverse().expect("non-zero"),
                libra_evaluation,
            ));
        } else {
            // compute the evaluation of the last Libra univariate at the challenge u_{d-1}
            let eval = T::eval_poly(
                &self.libra_univariates[round_idx].coefficients,
                round_challenge,
            );
            let libra_evaluation =
                T::mul_with_public(self.libra_scaling_factor.inverse().expect("non-zero"), eval);
            // place the evalution into the vector of Libra evaluations
            self.libra_evaluations.push(libra_evaluation);
            for univariate in &mut self.libra_univariates {
                univariate.mul_assign(self.libra_challenge.inverse().expect("non-zero"));
            }
        }
    }
}
