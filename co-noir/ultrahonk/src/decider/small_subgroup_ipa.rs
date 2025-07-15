use crate::CONST_PROOF_SIZE_LOG_N;
use crate::Utils;
use crate::plain_prover_flavour::UnivariateTrait;
use crate::prelude::TranscriptHasher;
use crate::prelude::Univariate;
use crate::{prelude::Transcript, transcript::TranscriptFieldType};
use ark_ec::CurveGroup;
use ark_ff::One;
use ark_ff::Zero;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use co_builder::HonkProofError;
use co_builder::HonkProofResult;
use co_builder::prelude::{HonkCurve, Polynomial, ProverCrs};
use rand::{CryptoRng, Rng};

use super::sumcheck::zk_data::ZKSumcheckData;

pub struct SmallSubgroupIPAProver<P: CurveGroup> {
    interpolation_domain: Vec<P::ScalarField>,
    concatenated_polynomial: Polynomial<P::ScalarField>,
    libra_concatenated_lagrange_form: Polynomial<P::ScalarField>,
    challenge_polynomial: Polynomial<P::ScalarField>,
    challenge_polynomial_lagrange: Polynomial<P::ScalarField>,
    grand_sum_polynomial_unmasked: Polynomial<P::ScalarField>,
    grand_sum_polynomial: Polynomial<P::ScalarField>,
    grand_sum_lagrange_coeffs: Vec<P::ScalarField>,
    grand_sum_identity_polynomial: Polynomial<P::ScalarField>,
    grand_sum_identity_quotient: Polynomial<P::ScalarField>,
    domain: GeneralEvaluationDomain<P::ScalarField>,
    claimed_inner_product: P::ScalarField,
    prefix_label: String,
}

impl<P: HonkCurve<TranscriptFieldType>> SmallSubgroupIPAProver<P> {
    const SUBGROUP_SIZE: usize = P::SUBGROUP_SIZE;
    // A masking term of length 2 (degree 1) is required to mask [G] and G(r).
    const WITNESS_MASKING_TERM_LENGTH: usize = 2;
    const MASKED_CONCATENATED_WITNESS_LENGTH: usize =
        Self::SUBGROUP_SIZE + Self::WITNESS_MASKING_TERM_LENGTH;
    const QUOTIENT_LENGTH: usize = Self::SUBGROUP_SIZE + 2;
    // A masking term of length 3 (degree 2) is required to mask [A], A(r), and A(g*r)
    const GRAND_SUM_MASKING_TERM_LENGTH: usize = 3;
    const MASKED_GRAND_SUM_LENGTH: usize =
        Self::SUBGROUP_SIZE + Self::GRAND_SUM_MASKING_TERM_LENGTH;
    // Length of the big sum identity polynomial C. It is equal to the length of the highest degree term X * F(X) * G(X)
    const GRAND_SUM_IDENTITY_LENGTH: usize =
        Self::MASKED_CONCATENATED_WITNESS_LENGTH + Self::SUBGROUP_SIZE;

    pub fn new<H: TranscriptHasher<TranscriptFieldType>>(
        zk_sumcheck_data: ZKSumcheckData<P>,
        claimed_inner_product: P::ScalarField,
        prefix_label: String,
        multivariate_challenge: &[P::ScalarField],
    ) -> HonkProofResult<Self> {
        let mut prover = SmallSubgroupIPAProver {
            interpolation_domain: zk_sumcheck_data.interpolation_domain,
            concatenated_polynomial: zk_sumcheck_data.libra_concatenated_monomial_form,
            libra_concatenated_lagrange_form: zk_sumcheck_data.libra_concatenated_lagrange_form,
            challenge_polynomial: Polynomial::new_zero(Self::SUBGROUP_SIZE),
            challenge_polynomial_lagrange: Polynomial::new_zero(Self::SUBGROUP_SIZE),
            grand_sum_polynomial_unmasked: Polynomial::new_zero(Self::SUBGROUP_SIZE),
            grand_sum_polynomial: Polynomial::new_zero(Self::MASKED_GRAND_SUM_LENGTH),
            grand_sum_lagrange_coeffs: vec![P::ScalarField::zero(); Self::SUBGROUP_SIZE],
            grand_sum_identity_polynomial: Polynomial::new_zero(Self::GRAND_SUM_IDENTITY_LENGTH),
            grand_sum_identity_quotient: Polynomial::new_zero(Self::QUOTIENT_LENGTH),
            // TACEO TODO the ZKSumcheckData also creates the same domain
            domain: GeneralEvaluationDomain::<P::ScalarField>::new(Self::SUBGROUP_SIZE)
                .ok_or(HonkProofError::LargeSubgroup)?,
            claimed_inner_product,
            prefix_label,
        };
        prover.compute_challenge_polynomial(multivariate_challenge);
        Ok(prover)
    }

    pub fn prove<H: TranscriptHasher<TranscriptFieldType>, R: Rng + CryptoRng>(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        commitment_key: &ProverCrs<P>,
        rng: &mut R,
    ) -> HonkProofResult<()> {
        //PROVE STARTS HERE
        self.compute_grand_sum_polynomial(rng);
        let libra_grand_sum_commitment =
            Utils::commit(&self.grand_sum_polynomial.coefficients, commitment_key)?;
        transcript.send_point_to_verifier::<P>(
            self.prefix_label.clone() + "grand_sum_commitment",
            libra_grand_sum_commitment.into(),
        );

        self.compute_grand_sum_identity_polynomial();
        self.compute_batched_quotient();

        let libra_quotient_commitment = Utils::commit(
            &self.grand_sum_identity_quotient.coefficients,
            commitment_key,
        )?;
        transcript.send_point_to_verifier::<P>(
            self.prefix_label.clone() + "quotient_commitment",
            libra_quotient_commitment.into(),
        );

        Ok(())
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
                // Recursively compute the powers of the challenge up to the length of libra univariates
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
     *   \f$ \texttt{grand_sum_lagrange_coeffs} (g^{i}) =
     *   \texttt{grand_sum_lagrange_coeffs} (g^{i-1}) +
     *   \texttt{challenge_polynomial_lagrange[prev_idx]} (g^{i-1}) \cdot
     *   \texttt{libra_concatenated_lagrange_form[prev_idx]} (g^{i-1}) \f$
     * #### Masking Term
     * - A random polynomial of degree 2 is generated and added to the Big Sum Polynomial.
     * - The masking term is applied as \f$ Z_H(X) \cdot \texttt{masking_term} \f$, where \f$ Z_H(X) \f$ is the
     *   vanishing polynomial.
     *
     */
    fn compute_grand_sum_polynomial<R: Rng + CryptoRng>(&mut self, rng: &mut R) {
        self.grand_sum_lagrange_coeffs[0] = P::ScalarField::zero();

        // Compute the big sum coefficients recursively
        for idx in 1..Self::SUBGROUP_SIZE {
            let prev_idx = idx - 1;
            self.grand_sum_lagrange_coeffs[idx] = self.grand_sum_lagrange_coeffs[prev_idx]
                + self.challenge_polynomial_lagrange.coefficients[prev_idx]
                    * self.libra_concatenated_lagrange_form.coefficients[prev_idx];
        }

        //  Get the coefficients in the monomial basis
        let grand_sum_ifft = self.domain.ifft(&self.grand_sum_lagrange_coeffs);
        self.grand_sum_polynomial_unmasked = Polynomial {
            coefficients: grand_sum_ifft,
        };

        //  Generate random masking_term of degree 2, add Z_H(X) * masking_term
        let masking_term = Univariate::<P::ScalarField, 3>::get_random(rng);
        self.grand_sum_polynomial += &self.grand_sum_polynomial_unmasked.coefficients;

        for idx in 0..masking_term.evaluations.len() {
            self.grand_sum_polynomial.coefficients[idx] -= masking_term.evaluations[idx];
            self.grand_sum_polynomial.coefficients[idx + Self::SUBGROUP_SIZE] +=
                masking_term.evaluations[idx];
        }
    }

    /**
     * @brief   Compute \f$ L_1(X) * A(X) + (X - 1/g) (A(gX) - A(X) - F(X) G(X)) + L_{|H|}(X)(A(X) - s) \f$, where \f$ g
     * \f$ is the fixed generator of \f$ H \f$.
     *
     */
    fn compute_grand_sum_identity_polynomial(&mut self) {
        // Compute shifted big sum polynomial A(gX)
        let mut shifted_grand_sum = Polynomial::new_zero(Self::SUBGROUP_SIZE + 3);

        for idx in 0..(Self::SUBGROUP_SIZE + 3) {
            shifted_grand_sum.coefficients[idx] = self.grand_sum_polynomial.coefficients[idx]
                * self.interpolation_domain[idx % Self::SUBGROUP_SIZE];
        }

        let (lagrange_first, lagrange_last) = self.compute_lagrange_first_and_last();

        // Compute -F(X)*G(X), the negated product of challenge_polynomial and libra_concatenated_monomial_form
        for i in 0..self.concatenated_polynomial.coefficients.len() {
            for j in 0..self.challenge_polynomial.coefficients.len() {
                self.grand_sum_identity_polynomial.coefficients[i + j] -=
                    self.concatenated_polynomial.coefficients[i]
                        * self.challenge_polynomial.coefficients[j];
            }
        }

        // Compute - F(X) * G(X) + A(gX) - A(X)
        for idx in 0..shifted_grand_sum.coefficients.len() {
            self.grand_sum_identity_polynomial.coefficients[idx] +=
                shifted_grand_sum.coefficients[idx] - self.grand_sum_polynomial.coefficients[idx];
        }

        // Mutiply - F(X) * G(X) + A(gX) - A(X) by X-g:
        // 1. Multiply by X
        for idx in (1..self.grand_sum_identity_polynomial.coefficients.len()).rev() {
            self.grand_sum_identity_polynomial.coefficients[idx] =
                self.grand_sum_identity_polynomial.coefficients[idx - 1];
        }
        self.grand_sum_identity_polynomial.coefficients[0] = P::ScalarField::zero();

        // 2. Subtract  1/g(A(gX) - A(X) - F(X) * G(X))
        for idx in 0..self.grand_sum_identity_polynomial.coefficients.len() - 1 {
            let tmp = self.grand_sum_identity_polynomial.coefficients[idx + 1];
            self.grand_sum_identity_polynomial.coefficients[idx] -=
                tmp * self.interpolation_domain[Self::SUBGROUP_SIZE - 1];
        }

        // Add (L_1 + L_{|H|}) * A(X) to the result
        for i in 0..self.grand_sum_polynomial.coefficients.len() {
            for j in 0..Self::SUBGROUP_SIZE {
                self.grand_sum_identity_polynomial.coefficients[i + j] +=
                    self.grand_sum_polynomial.coefficients[i]
                        * (lagrange_first.coefficients[j] + lagrange_last.coefficients[j]);
            }
        }

        // Subtract L_{|H|} * s
        for idx in 0..Self::SUBGROUP_SIZE {
            self.grand_sum_identity_polynomial.coefficients[idx] -=
                lagrange_last.coefficients[idx] * self.claimed_inner_product;
        }
    }

    /** @brief Efficiently compute the quotient of batched_polynomial by Z_H = X ^ { | H | } - 1
     */
    fn compute_batched_quotient(&mut self) {
        let mut remainder = self.grand_sum_identity_polynomial.clone();
        for idx in (Self::SUBGROUP_SIZE..Self::GRAND_SUM_IDENTITY_LENGTH).rev() {
            self.grand_sum_identity_quotient.coefficients[idx - Self::SUBGROUP_SIZE] =
                remainder.coefficients[idx];
            let tmp = remainder.coefficients[idx];
            remainder.coefficients[idx - Self::SUBGROUP_SIZE] += tmp;
        }
        self.grand_sum_identity_polynomial = remainder;
    }

    /**
     * @brief Compute monomial coefficients of the first and last Lagrange polynomials
     *
     * @param interpolation_domain
     * @param bn_evaluation_domain
     * @return std::array<Polynomial<FF>, 2>
     */
    fn compute_lagrange_first_and_last(
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
    pub fn into_witness_polynomials(self) -> [Polynomial<P::ScalarField>; 4] {
        [
            self.concatenated_polynomial,
            self.grand_sum_polynomial.to_owned(),
            self.grand_sum_polynomial,
            self.grand_sum_identity_quotient,
        ]
    }
}
