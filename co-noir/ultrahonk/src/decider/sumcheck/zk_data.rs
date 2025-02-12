use crate::prelude::Transcript;
use crate::prelude::TranscriptHasher;
use crate::prelude::Univariate;
use crate::transcript::TranscriptFieldType;
use crate::Utils;
use ark_ec::pairing::Pairing;
use ark_ff::One;
use ark_ff::UniformRand;
use ark_ff::Zero;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use co_builder::prelude::HonkCurve;
use co_builder::prelude::Polynomial;
use co_builder::prelude::ProverCrs;

const SUBGROUP_SIZE: usize = 256;
pub const LIBRA_UNIVARIATES_LENGTH: usize = 9;

pub(crate) struct ZKSumcheckData<P: Pairing> {
    pub(crate) constant_term: P::ScalarField,
    pub(crate) interpolation_domain: [P::ScalarField; SUBGROUP_SIZE],
    pub(crate) libra_concatenated_lagrange_form: Polynomial<P::ScalarField>,
    pub(crate) libra_concatenated_monomial_form: Polynomial<P::ScalarField>,
    pub(crate) libra_univariates: Vec<Polynomial<P::ScalarField>>,
    pub(crate) log_circuit_size: usize,
    pub(crate) libra_scaling_factor: P::ScalarField,
    pub(crate) libra_challenge: P::ScalarField,
    pub(crate) libra_total_sum: P::ScalarField,
    pub(crate) libra_running_sum: P::ScalarField,
    pub(crate) libra_evaluations: Vec<P::ScalarField>,
    pub(crate) _univariate_length: usize,
}

impl<P: HonkCurve<TranscriptFieldType>> ZKSumcheckData<P> {
    pub(crate) fn new<H: TranscriptHasher<TranscriptFieldType>>(
        multivariate_d: usize,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        commitment_key: &[P::G1Affine],
    ) -> Self {
        let mut rng = rand::thread_rng();
        let constant_term = P::ScalarField::rand(&mut rng);
        let libra_challenge = P::ScalarField::rand(&mut rng);
        let libra_univariates =
            Self::generate_libra_univariates(multivariate_d, LIBRA_UNIVARIATES_LENGTH);
        let log_circuit_size = multivariate_d;
        let univariate_length = LIBRA_UNIVARIATES_LENGTH;

        let mut data = ZKSumcheckData {
            constant_term,
            interpolation_domain: [P::ScalarField::zero(); SUBGROUP_SIZE],
            libra_concatenated_lagrange_form: Polynomial::new_zero(SUBGROUP_SIZE),
            libra_concatenated_monomial_form: Polynomial::new_zero(SUBGROUP_SIZE + 2),
            libra_univariates,
            log_circuit_size,
            libra_scaling_factor: P::ScalarField::one(),
            libra_challenge,
            libra_total_sum: P::ScalarField::zero(),
            libra_running_sum: P::ScalarField::zero(),
            libra_evaluations: Vec::new(),
            _univariate_length: univariate_length,
        };

        data.create_interpolation_domain();
        data.compute_concatenated_libra_polynomial();
        // If proving_key is provided, commit to the concatenated and masked libra polynomial
        if !commitment_key.is_empty() {
            let libra_commitment = Utils::commit(
                &data.libra_concatenated_monomial_form.coefficients,
                &ProverCrs::<P> {
                    monomials: commitment_key.to_vec(),
                },
            )
            .unwrap();
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

        data
    }

    fn generate_libra_univariates(
        number_of_polynomials: usize,
        univariate_length: usize,
    ) -> Vec<Polynomial<P::ScalarField>> {
        (0..number_of_polynomials)
            .map(|_| Polynomial::random(univariate_length))
            .collect()
    }

    fn compute_libra_total_sum(
        libra_univariates: &[Polynomial<P::ScalarField>],
        scaling_factor: &mut P::ScalarField,
        constant_term: P::ScalarField,
    ) -> P::ScalarField {
        let mut total_sum = P::ScalarField::zero();
        let two_inv: P::ScalarField = P::ScalarField::one() / P::ScalarField::from(2);
        *scaling_factor *= two_inv;

        for univariate in libra_univariates {
            total_sum += univariate.coefficients[0] + univariate.eval_poly(P::ScalarField::one());
            *scaling_factor *= P::ScalarField::from(2);
        }
        total_sum *= *scaling_factor;

        total_sum + constant_term * P::ScalarField::from(1 << libra_univariates.len())
    }

    fn setup_auxiliary_data(&mut self) {
        let two_inv: P::ScalarField = P::ScalarField::one() / P::ScalarField::from(2);
        self.libra_scaling_factor *= self.libra_challenge;
        for univariate in &mut self.libra_univariates {
            *univariate *= self.libra_scaling_factor;
        }
        self.libra_running_sum += -self.libra_univariates[0].coefficients[0]
            - self.libra_univariates[0].eval_poly(P::ScalarField::one());
        self.libra_running_sum *= two_inv;
    }

    fn create_interpolation_domain(&mut self) {
        self.interpolation_domain[0] = P::ScalarField::one();
        // TACEO TODO remove unwrap
        let subgroup_generator = P::get_subgroup_generator();
        for idx in 1..SUBGROUP_SIZE {
            self.interpolation_domain[idx] =
                self.interpolation_domain[idx - 1] * subgroup_generator;
        }
    }

    fn compute_concatenated_libra_polynomial(&mut self) {
        let mut coeffs_lagrange_subgroup = [P::ScalarField::zero(); SUBGROUP_SIZE];
        coeffs_lagrange_subgroup[0] = self.constant_term;

        for poly_idx in 0..self.log_circuit_size {
            for idx in 0..LIBRA_UNIVARIATES_LENGTH {
                let idx_to_populate = 1 + poly_idx * LIBRA_UNIVARIATES_LENGTH + idx;
                coeffs_lagrange_subgroup[idx_to_populate] =
                    self.libra_univariates[poly_idx].coefficients[idx];
            }
        }

        self.libra_concatenated_lagrange_form = Polynomial::<P::ScalarField> {
            coefficients: coeffs_lagrange_subgroup.to_vec(),
        };

        let masking_scalars = Univariate::<P::ScalarField, 2>::get_random();

        // if !P::is_bn254() {
        //     libra_concatenated_monomial_form_unmasked = Polynomial::<P::ScalarField> {
        //         coefficients: coeffs_lagrange_subgroup.to_vec(),
        //     };
        // } else {
        // TACEO TODO remove unwrap
        let domain = GeneralEvaluationDomain::<P::ScalarField>::new(SUBGROUP_SIZE)
            .ok_or(eyre::eyre!("Polynomial Degree too large"))
            .unwrap();

        let coeffs_lagrange_subgroup_ifft = domain.ifft(&coeffs_lagrange_subgroup);
        let libra_concatenated_monomial_form_unmasked = Polynomial::<P::ScalarField> {
            coefficients: coeffs_lagrange_subgroup_ifft,
        };
        // }

        for idx in 0..SUBGROUP_SIZE {
            self.libra_concatenated_monomial_form.coefficients[idx] =
                libra_concatenated_monomial_form_unmasked.coefficients[idx];
        }

        for idx in 0..masking_scalars.evaluations.len() {
            self.libra_concatenated_monomial_form.coefficients[idx] -=
                masking_scalars.evaluations[idx];
            self.libra_concatenated_monomial_form.coefficients[SUBGROUP_SIZE + idx] +=
                masking_scalars.evaluations[idx];
        }
    }

    pub(crate) fn update_zk_sumcheck_data(
        &mut self,
        round_challenge: P::ScalarField,
        round_idx: usize,
    ) {
        let two_inv: P::ScalarField = P::ScalarField::one() / P::ScalarField::from(2);

        if round_idx < self.log_circuit_size - 1 {
            for univariate in &mut self.libra_univariates {
                *univariate *= two_inv;
            }

            let libra_evaluation = self.libra_univariates[round_idx].eval_poly(round_challenge);
            let next_libra_univariate = &self.libra_univariates[round_idx + 1];

            self.libra_running_sum += -next_libra_univariate.coefficients[0]
                - next_libra_univariate.eval_poly(P::ScalarField::one());
            self.libra_running_sum *= two_inv;

            self.libra_running_sum += libra_evaluation;
            self.libra_scaling_factor *= two_inv;

            self.libra_evaluations
                .push(libra_evaluation / self.libra_scaling_factor);
        } else {
            let libra_evaluation = self.libra_univariates[round_idx].eval_poly(round_challenge)
                / self.libra_scaling_factor;
            self.libra_evaluations.push(libra_evaluation);
            for univariate in &mut self.libra_univariates {
                *univariate *= P::ScalarField::one() / self.libra_challenge;
            }
        }
    }
}
