use ark_ec::pairing::Pairing;
use ark_ff::{FftField, Field, One};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::{ConstraintMatrices, Matrix};
use eyre::Result;
use mpc_core::MpcState;
use rayon::iter::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use tracing::instrument;

use crate::mpc::CircomGroth16Prover;

use super::root_of_unity_for_groth16;

macro_rules! rayon_join {
    ($t1: expr, $t2: expr, $t3: expr) => {{
        let ((x, y), z) = rayon::join(|| rayon::join($t1, $t2), $t3);
        (x, y, z)
    }};
}
/// This trait is used to convert the secret-shared witness into a secret-shared QAP witness as part of a collaborative Groth16 proof.
/// Refer to <https://docs.rs/ark-groth16/latest/ark_groth16/r1cs_to_qap/trait.R1CSToQAP.html> for more details on the plain version.
/// We do not implement the other methods of the arkworks trait, as we do not need them during proof generation.
pub trait R1CSToQAP {
    /// Computes a QAP witness corresponding to the R1CS witness defined by `private_witness`, using the provided `ConstraintMatrices`.
    /// The provided `driver` is used to perform the necessary operations on the secret-shared witness.
    fn witness_map_from_matrices<P: Pairing, T: CircomGroth16Prover<P>>(
        state: &mut T::State,
        matrices: &ConstraintMatrices<P::ScalarField>,
        public_inputs: &[P::ScalarField],
        private_witness: &[T::ArithmeticShare],
    ) -> Result<Vec<T::ArithmeticHalfShare>>;
}

/// Implements the witness map used by snarkjs. The arkworks witness map calculates the
/// coefficients of H through computing (AB-C)/Z in the evaluation domain and going back to the
/// coefficients domain. snarkjs instead precomputes the Lagrange form of the powers of tau bases
/// in a domain twice as large and the witness map is computed as the odd coefficients of (AB-C)
/// in that domain. This serves as HZ when computing the C proof element.
///
/// Based on <https://github.com/arkworks-rs/circom-compat/>.
pub struct CircomReduction;

impl R1CSToQAP for CircomReduction {
    #[instrument(level = "debug", name = "witness map from matrices", skip_all)]
    fn witness_map_from_matrices<P: Pairing, T: CircomGroth16Prover<P>>(
        state: &mut T::State,
        matrices: &ConstraintMatrices<P::ScalarField>,
        public_inputs: &[P::ScalarField],
        private_witness: &[T::ArithmeticShare],
    ) -> Result<Vec<T::ArithmeticHalfShare>> {
        let num_constraints = matrices.num_constraints;
        let num_inputs = matrices.num_instance_variables;
        let mut domain =
            GeneralEvaluationDomain::<P::ScalarField>::new(num_constraints + num_inputs)
                .ok_or(eyre::eyre!("Polynomial Degree too large"))?;
        let domain_size = domain.size();
        let power = domain_size.ilog2() as usize;
        let id = state.id();
        let eval_constraint_span =
            tracing::debug_span!("evaluate constraints + root of unity computation").entered();
        let (roots_to_power_domain, a, b) = rayon_join!(
            || {
                let root_of_unity_span =
                    tracing::debug_span!("root of unity computation").entered();
                let root_of_unity = root_of_unity_for_groth16(power, &mut domain);
                let mut roots = Vec::with_capacity(domain_size);
                let mut c = P::ScalarField::one();
                for _ in 0..domain_size {
                    roots.push(c);
                    c *= root_of_unity;
                }
                root_of_unity_span.exit();
                roots
            },
            || {
                let eval_constraint_span_a =
                    tracing::debug_span!("evaluate constraints - a").entered();
                let mut result = evaluate_constraint::<P, T>(
                    id,
                    domain_size,
                    &matrices.a,
                    public_inputs,
                    private_witness,
                );
                let promoted_public = T::promote_to_trivial_shares(id, public_inputs);
                result[num_constraints..num_constraints + num_inputs]
                    .clone_from_slice(&promoted_public[..num_inputs]);
                eval_constraint_span_a.exit();
                result
            },
            || {
                let eval_constraint_span_b =
                    tracing::debug_span!("evaluate constraints - a").entered();
                let result = evaluate_constraint::<P, T>(
                    id,
                    domain_size,
                    &matrices.b,
                    public_inputs,
                    private_witness,
                );
                eval_constraint_span_b.exit();
                result
            }
        );

        eval_constraint_span.exit();
        let mut a_result = a.clone();
        let mut b_result = b.clone();
        let ((a, b), c) = rayon::join(
            || {
                rayon::join(
                    || {
                        let a_span =
                            tracing::debug_span!("a: distribute powers mul a (fft/ifft)").entered();
                        domain.ifft_in_place(&mut a_result);
                        T::distribute_powers_and_mul_by_const(
                            &mut a_result,
                            &roots_to_power_domain,
                        );
                        domain.fft_in_place(&mut a_result);
                        a_span.exit();
                        a_result
                    },
                    || {
                        let b_span =
                            tracing::debug_span!("b: distribute powers mul b (fft/ifft)").entered();
                        domain.ifft_in_place(&mut b_result);
                        T::distribute_powers_and_mul_by_const(
                            &mut b_result,
                            &roots_to_power_domain,
                        );
                        domain.fft_in_place(&mut b_result);
                        b_span.exit();
                        b_result
                    },
                )
            },
            || {
                let local_mul_vec_span = tracing::debug_span!("c: local_mul_vec").entered();
                let mut ab = T::local_mul_many(a, b, state);
                local_mul_vec_span.exit();
                let ifft_span = tracing::debug_span!("c: ifft in dist pows").entered();
                domain.ifft_in_place(&mut ab);
                ifft_span.exit();
                let dist_pows_span = tracing::debug_span!("c: dist pows").entered();
                ab.par_iter_mut()
                    .zip_eq(roots_to_power_domain.par_iter())
                    .with_min_len(512)
                    .for_each(|(share, pow): (&mut T::ArithmeticHalfShare, _)| {
                        *share *= *pow;
                    });
                dist_pows_span.exit();
                let fft_span = tracing::debug_span!("c: fft in dist pows").entered();
                domain.fft_in_place(&mut ab);
                fft_span.exit();
                ab
            },
        );

        let local_ab_span = tracing::debug_span!("ab: local_mul_vec").entered();
        // same as above. No IO task is run at the moment.
        let mut ab = T::local_mul_many(a, b, state);
        local_ab_span.exit();
        let compute_ab_span = tracing::debug_span!("compute ab").entered();
        ab.par_iter_mut()
            .zip_eq(c.par_iter())
            .with_min_len(512)
            .for_each(|(a, b): (&mut T::ArithmeticHalfShare, _)| {
                *a -= *b;
            });
        compute_ab_span.exit();
        Ok(ab)
    }
}

fn evaluate_constraint<P: Pairing, T: CircomGroth16Prover<P>>(
    id: <T::State as MpcState>::PartyID,
    domain_size: usize,
    matrix: &Matrix<P::ScalarField>,
    public_inputs: &[P::ScalarField],
    private_witness: &[T::ArithmeticShare],
) -> Vec<T::ArithmeticShare> {
    let mut result = matrix
        .par_iter()
        .with_min_len(256)
        .map(|x| T::evaluate_constraint(id, x, public_inputs, private_witness))
        .collect::<Vec<_>>();
    result.resize(domain_size, T::ArithmeticShare::default());
    result
}

fn evaluate_constraint_half_share<P: Pairing, T: CircomGroth16Prover<P>>(
    id: <T::State as MpcState>::PartyID,
    domain_size: usize,
    matrix: &Matrix<P::ScalarField>,
    public_inputs: &[P::ScalarField],
    private_witness: &[T::ArithmeticShare],
) -> Vec<T::ArithmeticHalfShare> {
    let mut result = matrix
        .par_iter()
        .with_min_len(256)
        .map(|x| T::evaluate_constraint_half_share(id, x, public_inputs, private_witness))
        .collect::<Vec<_>>();
    result.resize(domain_size, T::ArithmeticHalfShare::default());
    result
}

/// Implements the witness map used by libsnark. The arkworks witness map calculates the
/// coefficients of H through computing (AB-C)/Z in the evaluation domain and going back to the
/// coefficients domain.
///
/// Based on <https://github.com/arkworks-rs/groth16/>.
pub struct LibSnarkReduction;

impl R1CSToQAP for LibSnarkReduction {
    #[instrument(level = "debug", name = "witness map from matrices", skip_all)]
    fn witness_map_from_matrices<P: Pairing, T: CircomGroth16Prover<P>>(
        state: &mut T::State,
        matrices: &ConstraintMatrices<P::ScalarField>,
        public_inputs: &[P::ScalarField],
        private_witness: &[T::ArithmeticShare],
    ) -> Result<Vec<T::ArithmeticHalfShare>> {
        let num_constraints = matrices.num_constraints;
        let num_inputs = matrices.num_instance_variables;
        let domain = GeneralEvaluationDomain::<P::ScalarField>::new(num_constraints + num_inputs)
            .ok_or(eyre::eyre!("Polynomial Degree too large"))?;
        let domain_size = domain.size();
        let party_id = state.id();

        let coset_domain = domain.get_coset(P::ScalarField::GENERATOR).unwrap();

        let (mut ab, c) = rayon::join(
            || {
                let (a, b) = rayon::join(
                    || {
                        let mut a = evaluate_constraint::<P, T>(
                            party_id,
                            domain_size,
                            &matrices.a,
                            public_inputs,
                            private_witness,
                        );
                        let promoted_public = T::promote_to_trivial_shares(party_id, public_inputs);
                        a[num_constraints..num_constraints + num_inputs]
                            .clone_from_slice(&promoted_public[..num_inputs]);
                        domain.ifft_in_place(&mut a);
                        coset_domain.fft_in_place(&mut a);
                        a
                    },
                    || {
                        let mut b = evaluate_constraint::<P, T>(
                            party_id,
                            domain_size,
                            &matrices.b,
                            public_inputs,
                            private_witness,
                        );
                        domain.ifft_in_place(&mut b);
                        coset_domain.fft_in_place(&mut b);
                        b
                    },
                );
                T::local_mul_many(a, b, state)
            },
            || {
                let mut c = evaluate_constraint_half_share::<P, T>(
                    party_id,
                    domain_size,
                    &matrices.c,
                    public_inputs,
                    private_witness,
                );
                domain.ifft_in_place(&mut c);
                coset_domain.fft_in_place(&mut c);
                c
            },
        );

        let vanishing_polynomial_over_coset = domain
            .evaluate_vanishing_polynomial(P::ScalarField::GENERATOR)
            .inverse()
            .unwrap();

        ab.par_iter_mut()
            .zip(c.par_iter())
            .with_min_len(512)
            .for_each(|(ab_i, c_i)| {
                *ab_i -= *c_i;
                *ab_i *= vanishing_polynomial_over_coset;
            });

        coset_domain.ifft_in_place(&mut ab);

        Ok(ab)
    }
}
