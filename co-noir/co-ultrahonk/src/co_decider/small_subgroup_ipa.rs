use std::marker::PhantomData;

use crate::mpc::NoirUltraHonkProver;
use crate::prelude::TranscriptHasher;
use crate::CoUtils;
use crate::CONST_PROOF_SIZE_LOG_N;
use ultrahonk::prelude::Transcript;

use super::co_sumcheck::zk_data::SharedZKSumcheckData;
use super::polynomial::SharedPolynomial;
use super::univariates::SharedUnivariate;
use ark_ec::pairing::Pairing;
use ark_ff::One;
use ark_ff::Zero;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use co_builder::prelude::{HonkCurve, Polynomial, ProverCrs};
use co_builder::HonkProofError;
use co_builder::HonkProofResult;
use co_builder::TranscriptFieldType;

pub(crate) struct SharedSmallSubgroupIPAProver<T: NoirUltraHonkProver<P>, P: Pairing> {
    interpolation_domain: Vec<P::ScalarField>,
    concatenated_polynomial: SharedPolynomial<T, P>,
    libra_concatenated_lagrange_form: SharedPolynomial<T, P>,
    challenge_polynomial: Polynomial<P::ScalarField>,
    challenge_polynomial_lagrange: Polynomial<P::ScalarField>,
    big_sum_polynomial_unmasked: SharedPolynomial<T, P>,
    big_sum_polynomial: SharedPolynomial<T, P>,
    big_sum_lagrange_coeffs: Vec<T::ArithmeticShare>,
    batched_polynomial: SharedPolynomial<T, P>,
    batched_quotient: SharedPolynomial<T, P>,
    domain: GeneralEvaluationDomain<P::ScalarField>,
    phantom_data: PhantomData<T>,
}

impl<T: NoirUltraHonkProver<P>, P: HonkCurve<TranscriptFieldType>>
    SharedSmallSubgroupIPAProver<T, P>
{
    const SUBGROUP_SIZE: usize = P::SUBGROUP_SIZE;
    const BATCHED_POLYNOMIAL_LENGTH: usize = 2 * P::SUBGROUP_SIZE + 2;
    const QUOTIENT_LENGTH: usize = Self::SUBGROUP_SIZE + 2;
    pub(crate) fn new<H: TranscriptHasher<TranscriptFieldType>>(
        driver: &mut T,
        zk_sumcheck_data: SharedZKSumcheckData<T, P>,
        multivariate_challenge: &[P::ScalarField],
        claimed_ipa_eval: P::ScalarField,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        commitment_key: &ProverCrs<P>,
    ) -> HonkProofResult<Self> {
        let mut prover = SharedSmallSubgroupIPAProver {
            interpolation_domain: zk_sumcheck_data.interpolation_domain,

            concatenated_polynomial: zk_sumcheck_data.libra_concatenated_monomial_form,
            libra_concatenated_lagrange_form: zk_sumcheck_data.libra_concatenated_lagrange_form,
            challenge_polynomial: Polynomial::new_zero(Self::SUBGROUP_SIZE),
            challenge_polynomial_lagrange: Polynomial::new_zero(Self::SUBGROUP_SIZE),
            big_sum_polynomial_unmasked: SharedPolynomial::<T, P>::new_zero(Self::SUBGROUP_SIZE),
            big_sum_polynomial: SharedPolynomial::<T, P>::new_zero(Self::SUBGROUP_SIZE + 3),
            big_sum_lagrange_coeffs: vec![T::ArithmeticShare::default(); Self::SUBGROUP_SIZE],
            batched_polynomial: SharedPolynomial::<T, P>::new_zero(Self::BATCHED_POLYNOMIAL_LENGTH),
            batched_quotient: SharedPolynomial::<T, P>::new_zero(Self::QUOTIENT_LENGTH),
            domain: GeneralEvaluationDomain::<P::ScalarField>::new(Self::SUBGROUP_SIZE)
                .ok_or(HonkProofError::LargeSubgroup)?,
            phantom_data: PhantomData,
        };
        prover.compute_challenge_polynomial(multivariate_challenge);
        prover.compute_big_sum_polynomial(driver)?;

        let libra_big_sum_commitment_shared = CoUtils::commit::<T, P>(
            prover.big_sum_polynomial.coefficients.as_ref(),
            commitment_key,
        );
        let libra_big_sum_commitment = T::open_point(driver, libra_big_sum_commitment_shared)?;
        transcript.send_point_to_verifier::<P>(
            "Libra:big_sum_commitment".to_string(),
            libra_big_sum_commitment.into(),
        );

        prover.compute_batched_polynomial(claimed_ipa_eval, driver);
        prover.compute_batched_quotient(driver);

        let libra_quotient_commitment_shared = CoUtils::commit::<T, P>(
            prover.batched_quotient.coefficients.as_ref(),
            commitment_key,
        );
        let libra_quotient_commitment = T::open_point(driver, libra_quotient_commitment_shared)?;
        transcript.send_point_to_verifier::<P>(
            "Libra:quotient_commitment".to_string(),
            libra_quotient_commitment.into(),
        );

        Ok(prover)
    }

    /**
     * @brief Computes the challenge polynomial F(X) based on the provided multivariate challenges.
     *
     * This method generates a polynomial in both Lagrange basis and monomial basis from Sumcheck's
     * multivariate_challenge vector. The result is stored in `challenge_polynomial_lagrange` and
     * `challenge_polynomial`. The former is re-used in the computation of the big sum polynomial A(X)
     *
     * ### Lagrange Basis
     * The Lagrange basis polynomial is constructed as follows:
     * - Initialize the first coefficient as `1`.
     * - For each challenge index `idx_poly` in the `CONST_PROOF_SIZE_LOG_N` range, compute a sequence of coefficients
     *   recursively as powers of the corresponding multivariate challenge.
     * - Store these coefficients in `coeffs_lagrange_basis`.
     *   More explicitly,
     *   \f$ F = (1 , 1 , u_0, \ldots, u_0^{LIBRA_UNIVARIATES_LENGTH-1}, \ldots, 1, u_{D-1}, \ldots,
     *   u_{D-1}^{LIBRA_UNIVARIATES_LENGTH-1} ) \f$ in the Lagrange basis over \f$ H \f$.
     *
     * ### Monomial Basis
     * If the curve is not `BN254`, the monomial polynomial is constructed directly using un-optimized Lagrange
     * interpolation. Otherwise, an IFFT is used to convert the Lagrange basis coefficients into monomial basis
     * coefficients.
     *
     * @param multivariate_challenge A vector of field elements used to compute the challenge polynomial.
     */
    fn compute_challenge_polynomial(&mut self, multivariate_challenge: &[P::ScalarField]) {
        let mut coeffs_lagrange_basis = vec![P::ScalarField::zero(); Self::SUBGROUP_SIZE];
        coeffs_lagrange_basis[0] = P::ScalarField::one();

        for (challenge_idx, &challenge) in multivariate_challenge
            .iter()
            .enumerate()
            .take(CONST_PROOF_SIZE_LOG_N)
        {
            // We concatenate 1 with CONST_PROOF_SIZE_LOG_N Libra Univariates of length LIBRA_UNIVARIATES_LENGTH
            let poly_to_concatenate_start = 1 + P::LIBRA_UNIVARIATES_LENGTH * challenge_idx;
            coeffs_lagrange_basis[poly_to_concatenate_start] = P::ScalarField::one();
            for idx in (poly_to_concatenate_start + 1)
                ..(poly_to_concatenate_start + P::LIBRA_UNIVARIATES_LENGTH)
            {
                // Recursively compute the powers of the challenge
                coeffs_lagrange_basis[idx] = coeffs_lagrange_basis[idx - 1] * challenge;
            }
        }

        self.challenge_polynomial_lagrange = Polynomial {
            coefficients: coeffs_lagrange_basis,
        };

        // Compute monomial coefficients
        let challenge_polynomial_ifft = self
            .domain
            .ifft(self.challenge_polynomial_lagrange.coefficients.as_slice());
        self.challenge_polynomial = Polynomial {
            coefficients: challenge_polynomial_ifft,
        };
    }

    /**
     * @brief Computes the big sum polynomial A(X)
     *
     * #### Lagrange Basis
     * - First, we recursively compute the coefficients of the unmasked big sum polynomial, i.e. we set the first
     *   coefficient to `0`.
     * - For each i, the coefficient is updated as:
     *   \f$ \texttt{big_sum_lagrange_coeffs} (g^{i}) =
     *        \texttt{big_sum_lagrange_coeffs} (g^{i-1}) +
     *        \texttt{challenge_polynomial_lagrange[prev_idx]} (g^{i-1}) \cdot
     *        \texttt{libra_concatenated_lagrange_form[prev_idx]} (g^{i-1}) \f$
     * #### Masking Term
     * - A random polynomial of degree 2 is generated and added to the Big Sum Polynomial.
     * - The masking term is applied as \f$ Z_H(X) \cdot \texttt{masking_term} \f$, where \f$ Z_H(X) \f$ is the
     *   vanishing polynomial.
     *
     */
    fn compute_big_sum_polynomial(&mut self, driver: &mut T) -> HonkProofResult<()> {
        self.big_sum_lagrange_coeffs[0] = T::ArithmeticShare::default();

        // Compute the big sum coefficients recursively
        for idx in 1..Self::SUBGROUP_SIZE {
            let prev_idx = idx - 1;
            let mul = T::mul_with_public(
                driver,
                self.challenge_polynomial_lagrange.coefficients[prev_idx],
                self.libra_concatenated_lagrange_form.coefficients[prev_idx],
            );
            self.big_sum_lagrange_coeffs[idx] =
                T::add(driver, mul, self.big_sum_lagrange_coeffs[prev_idx]);
        }

        //  Get the coefficients in the monomial basis
        let big_sum_ifft = T::ifft(&self.big_sum_lagrange_coeffs, &self.domain);
        self.big_sum_polynomial_unmasked = SharedPolynomial {
            coefficients: big_sum_ifft,
        };

        //  Generate random masking_term of degree 2, add Z_H(X) * masking_term
        let masking_term = SharedUnivariate::<T, P, 3>::get_random(driver)?;
        self.big_sum_polynomial.add_assign_slice(
            driver,
            &self.big_sum_polynomial_unmasked.clone().coefficients,
        );

        for idx in 0..masking_term.evaluations.len() {
            self.big_sum_polynomial.coefficients[idx] = T::sub(
                driver,
                self.big_sum_polynomial.coefficients[idx],
                masking_term.evaluations[idx],
            );
            self.big_sum_polynomial.coefficients[idx + Self::SUBGROUP_SIZE] = T::add(
                driver,
                self.big_sum_polynomial.coefficients[idx + Self::SUBGROUP_SIZE],
                masking_term.evaluations[idx],
            );
        }
        Ok(())
    }

    /**
     * @brief   Compute \f$ L_1(X) * A(X) + (X - 1/g) (A(gX) - A(X) - F(X) G(X)) + L_{|H|}(X)(A(X) - s) \f$, where \f$ g
     * \f$ is the fixed generator of \f$ H \f$.
     *
     */
    fn compute_batched_polynomial(&mut self, claimed_evaluation: P::ScalarField, driver: &mut T) {
        // Compute shifted big sum polynomial A(gX)
        let mut shifted_big_sum = SharedPolynomial::<T, P>::new_zero(Self::SUBGROUP_SIZE + 3);

        for idx in 0..(Self::SUBGROUP_SIZE + 3) {
            shifted_big_sum.coefficients[idx] = T::mul_with_public(
                driver,
                self.interpolation_domain[idx % Self::SUBGROUP_SIZE],
                self.big_sum_polynomial.coefficients[idx],
            );
        }

        let (lagrange_first, lagrange_last) = self.compute_lagrange_polynomials();

        // Compute -F(X)*G(X), the negated product of challenge_polynomial and libra_concatenated_monomial_form
        for i in 0..self.concatenated_polynomial.coefficients.len() {
            for j in 0..self.challenge_polynomial.coefficients.len() {
                let mul = T::mul_with_public(
                    driver,
                    self.challenge_polynomial.coefficients[j],
                    self.concatenated_polynomial.coefficients[i],
                );
                self.batched_polynomial.coefficients[i + j] =
                    T::sub(driver, self.batched_polynomial.coefficients[i + j], mul);
            }
        }

        // Compute - F(X) * G(X) + A(gX) - A(X)
        for idx in 0..shifted_big_sum.coefficients.len() {
            let sub = T::sub(
                driver,
                shifted_big_sum.coefficients[idx],
                self.big_sum_polynomial.coefficients[idx],
            );
            self.batched_polynomial.coefficients[idx] =
                T::add(driver, self.batched_polynomial.coefficients[idx], sub);
        }

        // Mutiply - F(X) * G(X) + A(gX) - A(X) by X-g:
        // 1. Multiply by X
        for idx in (1..self.batched_polynomial.coefficients.len()).rev() {
            self.batched_polynomial.coefficients[idx] =
                self.batched_polynomial.coefficients[idx - 1];
        }
        self.batched_polynomial.coefficients[0] = T::ArithmeticShare::default();

        // 2. Subtract  1/g(A(gX) - A(X) - F(X) * G(X))
        for idx in 0..self.batched_polynomial.coefficients.len() - 1 {
            let tmp = self.batched_polynomial.coefficients[idx + 1];
            let mul = T::mul_with_public(
                driver,
                self.interpolation_domain[Self::SUBGROUP_SIZE - 1],
                tmp,
            );
            self.batched_polynomial.coefficients[idx] =
                T::sub(driver, self.batched_polynomial.coefficients[idx], mul);
        }

        // Add (L_1 + L_{|H|}) * A(X) to the result
        for i in 0..self.big_sum_polynomial.coefficients.len() {
            for j in 0..Self::SUBGROUP_SIZE {
                let mul = T::mul_with_public(
                    driver,
                    lagrange_first.coefficients[j] + lagrange_last.coefficients[j],
                    self.big_sum_polynomial.coefficients[i],
                );
                self.batched_polynomial.coefficients[i + j] =
                    T::add(driver, self.batched_polynomial.coefficients[i + j], mul);
            }
        }

        // Subtract L_{|H|} * s
        for idx in 0..Self::SUBGROUP_SIZE {
            self.batched_polynomial.coefficients[idx] = T::add_with_public(
                driver,
                -lagrange_last.coefficients[idx] * claimed_evaluation,
                self.batched_polynomial.coefficients[idx],
            );
        }
    }

    /** @brief Efficiently compute the quotient of batched_polynomial by Z_H = X ^ { | H | } - 1
     */
    fn compute_batched_quotient(&mut self, driver: &mut T) {
        let mut remainder = self.batched_polynomial.clone();
        for idx in (Self::SUBGROUP_SIZE..Self::BATCHED_POLYNOMIAL_LENGTH).rev() {
            self.batched_quotient.coefficients[idx - Self::SUBGROUP_SIZE] =
                remainder.coefficients[idx];

            let tmp = remainder.coefficients[idx];

            remainder.coefficients[idx - Self::SUBGROUP_SIZE] = T::add(
                driver,
                tmp,
                remainder.coefficients[idx - Self::SUBGROUP_SIZE],
            );
        }
        self.batched_polynomial = remainder;
    }

    /**
     * @brief Compute monomial coefficients of the first and last Lagrange polynomials
     *
     * @param interpolation_domain
     * @param bn_evaluation_domain
     * @return std::array<Polynomial<FF>, 2>
     */
    fn compute_lagrange_polynomials(
        &self,
    ) -> (Polynomial<P::ScalarField>, Polynomial<P::ScalarField>) {
        // Compute the monomial coefficients of L_1
        let mut lagrange_coeffs = vec![P::ScalarField::zero(); Self::SUBGROUP_SIZE];
        lagrange_coeffs[0] = P::ScalarField::one();

        let lagrange_first_ifft = self.domain.ifft(&lagrange_coeffs);

        let lagrange_first_monomial = Polynomial {
            coefficients: lagrange_first_ifft,
        };

        // Compute the monomial coefficients of L_{|H|}, the last Lagrange polynomial
        lagrange_coeffs[0] = P::ScalarField::zero();
        lagrange_coeffs[Self::SUBGROUP_SIZE - 1] = P::ScalarField::one();

        let lagrange_last_ifft = self.domain.ifft(&lagrange_coeffs);

        let lagrange_last_monomial = Polynomial {
            coefficients: lagrange_last_ifft,
        };

        (lagrange_first_monomial, lagrange_last_monomial)
    }

    // Getter to pass the witnesses to ShpleminiProver. Big sum polynomial is evaluated at 2 points (and is small)
    pub(crate) fn into_witness_polynomials(self) -> [SharedPolynomial<T, P>; 4] {
        [
            self.concatenated_polynomial,
            self.big_sum_polynomial.to_owned(),
            self.big_sum_polynomial,
            self.batched_quotient,
        ]
    }
}
