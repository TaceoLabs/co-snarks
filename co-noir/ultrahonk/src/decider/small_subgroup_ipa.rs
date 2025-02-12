use ark_ec::pairing::Pairing;
use ark_ff::One;
use ark_ff::Zero;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use co_builder::prelude::{HonkCurve, Polynomial, ProverCrs};

use crate::prelude::TranscriptHasher;
use crate::prelude::Univariate;
use crate::Utils;
use crate::CONST_PROOF_SIZE_LOG_N;
use crate::{prelude::Transcript, transcript::TranscriptFieldType};

use super::sumcheck::zk_data::ZKSumcheckData;
use super::sumcheck::zk_data::LIBRA_UNIVARIATES_LENGTH;

pub(crate) struct SmallSubgroupIPAProver<P: Pairing> {
    interpolation_domain: Vec<P::ScalarField>,
    concatenated_polynomial: Polynomial<P::ScalarField>,
    libra_concatenated_lagrange_form: Polynomial<P::ScalarField>,
    challenge_polynomial: Polynomial<P::ScalarField>,
    challenge_polynomial_lagrange: Polynomial<P::ScalarField>,
    big_sum_polynomial_unmasked: Polynomial<P::ScalarField>,
    big_sum_polynomial: Polynomial<P::ScalarField>,
    big_sum_lagrange_coeffs: Vec<P::ScalarField>,
    batched_polynomial: Polynomial<P::ScalarField>,
    batched_quotient: Polynomial<P::ScalarField>,
}

impl<P: HonkCurve<TranscriptFieldType>> SmallSubgroupIPAProver<P> {
    const SUBGROUP_SIZE: usize = P::SUBGROUP_SIZE;
    const BATCHED_POLYNOMIAL_LENGTH: usize = 2 * P::SUBGROUP_SIZE + 2;
    const QUOTIENT_LENGTH: usize = Self::SUBGROUP_SIZE + 2;
    pub(crate) fn new<H: TranscriptHasher<TranscriptFieldType>>(
        zk_sumcheck_data: &ZKSumcheckData<P>,
        multivariate_challenge: &[P::ScalarField],
        claimed_ipa_eval: P::ScalarField,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        commitment_key: &ProverCrs<P>,
    ) -> Self {
        let mut prover = SmallSubgroupIPAProver {
            interpolation_domain: zk_sumcheck_data.interpolation_domain.to_vec(),

            concatenated_polynomial: zk_sumcheck_data.libra_concatenated_monomial_form.clone(),
            libra_concatenated_lagrange_form: zk_sumcheck_data
                .libra_concatenated_lagrange_form
                .clone(),
            challenge_polynomial: Polynomial::new_zero(Self::SUBGROUP_SIZE),
            challenge_polynomial_lagrange: Polynomial::new_zero(Self::SUBGROUP_SIZE),
            big_sum_polynomial_unmasked: Polynomial::new_zero(Self::SUBGROUP_SIZE),
            big_sum_polynomial: Polynomial::new_zero(Self::SUBGROUP_SIZE + 3),
            big_sum_lagrange_coeffs: vec![P::ScalarField::zero(); Self::SUBGROUP_SIZE],
            batched_polynomial: Polynomial::new_zero(Self::BATCHED_POLYNOMIAL_LENGTH),
            batched_quotient: Polynomial::new_zero(Self::QUOTIENT_LENGTH),
        };

        // Reallocate the commitment key if necessary. This is an edge case with SmallSubgroupIPA since it has
        // polynomials that may exceed the circuit size.
        // if (commitment_key->dyadic_size < SUBGROUP_SIZE + 3) {
        //     commitment_key = std::make_shared<typename Flavor::CommitmentKey>(Self::SUBGROUP_SIZE + 3);
        // }

        // if P::is_bn254() {
        //     prover.bn_evaluation_domain = zk_sumcheck_data.bn_evaluation_domain.clone();
        // }

        prover.compute_challenge_polynomial(multivariate_challenge);
        prover.compute_big_sum_polynomial();
        let libra_big_sum_commitment =
            Utils::commit(&prover.big_sum_polynomial.coefficients, commitment_key).unwrap();
        transcript.send_point_to_verifier::<P>(
            "Libra:big_sum_commitment".to_string(),
            libra_big_sum_commitment.into(),
        );

        prover.compute_batched_polynomial(claimed_ipa_eval);
        prover.compute_batched_quotient();

        let libra_quotient_commitment =
            Utils::commit(&prover.batched_quotient.coefficients, commitment_key).unwrap();
        transcript.send_point_to_verifier::<P>(
            "Libra:quotient_commitment".to_string(),
            libra_quotient_commitment.into(),
        );

        prover
    }

    fn compute_challenge_polynomial(&mut self, multivariate_challenge: &[P::ScalarField]) {
        let mut coeffs_lagrange_basis = vec![P::ScalarField::zero(); Self::SUBGROUP_SIZE];
        coeffs_lagrange_basis[0] = P::ScalarField::one();

        for (challenge_idx, &challenge) in multivariate_challenge
            .iter()
            .enumerate()
            .take(CONST_PROOF_SIZE_LOG_N)
        {
            let poly_to_concatenate_start = 1 + LIBRA_UNIVARIATES_LENGTH * challenge_idx;
            coeffs_lagrange_basis[poly_to_concatenate_start] = P::ScalarField::one();
            for idx in (poly_to_concatenate_start + 1)
                ..(poly_to_concatenate_start + LIBRA_UNIVARIATES_LENGTH)
            {
                coeffs_lagrange_basis[idx] = coeffs_lagrange_basis[idx - 1] * challenge;
            }
        }

        self.challenge_polynomial_lagrange = Polynomial {
            coefficients: coeffs_lagrange_basis.clone(),
        };

        let domain = GeneralEvaluationDomain::<P::ScalarField>::new(Self::SUBGROUP_SIZE)
            .ok_or(eyre::eyre!("Polynomial Degree too large"))
            .unwrap();
        let challenge_polynomial_ifft = domain.ifft(&coeffs_lagrange_basis);
        self.challenge_polynomial = Polynomial {
            coefficients: challenge_polynomial_ifft,
        };
    }

    fn compute_big_sum_polynomial(&mut self) {
        self.big_sum_lagrange_coeffs[0] = P::ScalarField::zero();

        for idx in 1..Self::SUBGROUP_SIZE {
            let prev_idx = idx - 1;
            self.big_sum_lagrange_coeffs[idx] = self.big_sum_lagrange_coeffs[prev_idx]
                + self.challenge_polynomial_lagrange.coefficients[prev_idx]
                    * self.libra_concatenated_lagrange_form.coefficients[prev_idx];
        }
        let domain = GeneralEvaluationDomain::<P::ScalarField>::new(Self::SUBGROUP_SIZE)
            .ok_or(eyre::eyre!("Polynomial Degree too large"))
            .unwrap();
        let big_sum_ifft = domain.ifft(&self.big_sum_lagrange_coeffs);
        self.big_sum_polynomial_unmasked = Polynomial {
            coefficients: big_sum_ifft,
        };

        let masking_term = Univariate::<P::ScalarField, 3>::get_random();
        self.big_sum_polynomial += &self.big_sum_polynomial_unmasked.clone().coefficients;

        for idx in 0..masking_term.evaluations.len() {
            self.big_sum_polynomial.coefficients[idx] -= masking_term.evaluations[idx];
            self.big_sum_polynomial.coefficients[idx + Self::SUBGROUP_SIZE] +=
                masking_term.evaluations[idx];
        }
    }

    fn compute_batched_polynomial(&mut self, claimed_evaluation: P::ScalarField) {
        let mut shifted_big_sum = Polynomial::new_zero(Self::SUBGROUP_SIZE + 3);

        for idx in 0..(Self::SUBGROUP_SIZE + 3) {
            shifted_big_sum.coefficients[idx] = self.big_sum_polynomial.coefficients[idx]
                * self.interpolation_domain[idx % Self::SUBGROUP_SIZE];
        }

        let (lagrange_first, lagrange_last) = Self::compute_lagrange_polynomials();

        for i in 0..self.concatenated_polynomial.coefficients.len() {
            for j in 0..self.challenge_polynomial.coefficients.len() {
                self.batched_polynomial.coefficients[i + j] -=
                    self.concatenated_polynomial.coefficients[i]
                        * self.challenge_polynomial.coefficients[j];
            }
        }

        for idx in 0..shifted_big_sum.coefficients.len() {
            self.batched_polynomial.coefficients[idx] +=
                shifted_big_sum.coefficients[idx] - self.big_sum_polynomial.coefficients[idx];
        }

        for idx in (1..self.batched_polynomial.coefficients.len()).rev() {
            self.batched_polynomial.coefficients[idx] =
                self.batched_polynomial.coefficients[idx - 1];
        }
        self.batched_polynomial.coefficients[0] = P::ScalarField::zero();
        // 2. Subtract  1/g(A(gX) - A(X) - F(X) * G(X))
        for idx in 0..self.batched_polynomial.coefficients.len() - 1 {
            let tmp = self.batched_polynomial.coefficients[idx + 1];
            self.batched_polynomial.coefficients[idx] -=
                tmp * self.interpolation_domain[Self::SUBGROUP_SIZE - 1];
        }

        for i in 0..self.big_sum_polynomial.coefficients.len() {
            for j in 0..Self::SUBGROUP_SIZE {
                self.batched_polynomial.coefficients[i + j] += self.big_sum_polynomial.coefficients
                    [i]
                    * (lagrange_first.coefficients[j] + lagrange_last.coefficients[j]);
            }
        }

        for idx in 0..Self::SUBGROUP_SIZE {
            self.batched_polynomial.coefficients[idx] -=
                lagrange_last.coefficients[idx] * claimed_evaluation;
        }
    }

    fn compute_batched_quotient(&mut self) {
        let mut remainder = self.batched_polynomial.clone();
        for idx in (Self::SUBGROUP_SIZE..Self::BATCHED_POLYNOMIAL_LENGTH).rev() {
            self.batched_quotient.coefficients[idx - Self::SUBGROUP_SIZE] =
                remainder.coefficients[idx];
            let tmp = remainder.coefficients[idx];
            remainder.coefficients[idx - Self::SUBGROUP_SIZE] += tmp;
        }
        self.batched_polynomial = remainder;
    }

    fn compute_lagrange_polynomials() -> (Polynomial<P::ScalarField>, Polynomial<P::ScalarField>) {
        let mut lagrange_coeffs = vec![P::ScalarField::zero(); Self::SUBGROUP_SIZE];
        lagrange_coeffs[0] = P::ScalarField::one();

        let domain = GeneralEvaluationDomain::<P::ScalarField>::new(Self::SUBGROUP_SIZE)
            .ok_or(eyre::eyre!("Polynomial Degree too large"))
            .unwrap();
        let lagrange_first_ifft = domain.ifft(&lagrange_coeffs);

        let lagrange_first_monomial = Polynomial {
            coefficients: lagrange_first_ifft,
        };

        lagrange_coeffs[0] = P::ScalarField::zero();
        lagrange_coeffs[Self::SUBGROUP_SIZE - 1] = P::ScalarField::one();

        let lagrange_last_ifft = domain.ifft(&lagrange_coeffs);

        let lagrange_last_monomial = Polynomial {
            coefficients: lagrange_last_ifft,
        };

        (lagrange_first_monomial, lagrange_last_monomial)
    }

    pub(crate) fn get_witness_polynomials(&self) -> [Polynomial<P::ScalarField>; 4] {
        [
            self.concatenated_polynomial.clone(),
            self.big_sum_polynomial.clone(),
            self.big_sum_polynomial.clone(),
            self.batched_quotient.clone(),
        ]
    }

    // fn get_batched_polynomial(&self) -> &Polynomial<P::ScalarField> {
    //     &self.batched_polynomial
    // }

    // fn get_challenge_polynomial(&self) -> &Polynomial<P::ScalarField> {
    //     &self.challenge_polynomial
    // }
}
