use ark_ec::pairing::Pairing;
use ark_ff::{FftField, Field, One};
use ark_relations::utils::matrix::Matrix;
use eyre::Result;
use mpc_core::MpcState;
use rayon::iter::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use rayon::slice::ParallelSliceMut;
use taceo_ark_algebra::fft::{Domain, bit_reverse};
use taceo_groth16::ConstraintMatrices;
use tracing::instrument;

use crate::mpc::CircomGroth16Prover;

use super::groth16_roots_of_unity;

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

/// The powers `[shift^0, shift^1, ..., shift^(size - 1)]`, permuted into bit-reversed order.
///
/// Both witness maps shift a polynomial onto a coset while its coefficients sit in bit-reversed
/// order (the output order of [`Domain::ifft_in_to_out`]), so the table has to be permuted the
/// same way. Building the table once and permuting it means the three coset shifts that follow
/// read it sequentially instead of jumping around it.
#[instrument(level = "debug", name = "bit reversed coset table", skip_all)]
fn bit_reversed_coset_table<F: FftField>(shift: F, size: usize) -> Vec<F> {
    let chunk_size = size.div_ceil(rayon::current_num_threads()).max(1);
    let mut table = vec![F::one(); size];
    table
        .par_chunks_mut(chunk_size)
        .enumerate()
        .for_each(|(chunk_index, values)| {
            let mut current = shift.pow([(chunk_index * chunk_size) as u64]);
            for value in values.iter_mut() {
                *value = current;
                current *= shift;
            }
        });
    bit_reverse(&mut table);
    table
}

/// Implements the witness map used by snarkjs. The arkworks witness map calculates the
/// coefficients of H through computing (AB-C)/Z in the evaluation domain and going back to the
/// coefficients domain. snarkjs instead precomputes the Lagrange form of the powers of tau bases
/// in a domain twice as large and the witness map is computed as the odd coefficients of (AB-C)
/// in that domain. This serves as HZ when computing the C proof element.
///
/// Based on <https://github.com/arkworks-rs/circom-compat/>.
///
/// Each coset evaluation is an [`Domain::ifft_in_to_out`] followed by a
/// [`Domain::fft_out_to_in`], so the bit-reversal permutations of the two halves cancel and the
/// result is in the natural order that `h_query` expects.
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
        let domain_size = (num_constraints + num_inputs).next_power_of_two();
        let power = domain_size.ilog2() as usize;
        if power > P::ScalarField::TWO_ADICITY as usize {
            eyre::bail!("Polynomial Degree too large");
        }
        // snarkjs uses its own root of unity for the domain, and the root of unity of the domain
        // of twice the size as the coset shift.
        let (group_gen, coset_shift) = groth16_roots_of_unity::<P::ScalarField>(power);
        let domain = Domain::with_group_gen(domain_size, group_gen)
            .ok_or_else(|| eyre::eyre!("Polynomial Degree too large"))?;
        let id = state.id();

        let eval_constraint_span =
            tracing::debug_span!("evaluate constraints + coset table computation").entered();
        let (coset_table, a, b) = rayon_join!(
            || bit_reversed_coset_table(coset_shift, domain_size),
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
                    tracing::debug_span!("evaluate constraints - b").entered();
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
                        domain.ifft_in_to_out(&mut a_result);
                        T::distribute_powers_and_mul_by_const(&mut a_result, &coset_table);
                        domain.fft_out_to_in(&mut a_result);
                        a_span.exit();
                        a_result
                    },
                    || {
                        let b_span =
                            tracing::debug_span!("b: distribute powers mul b (fft/ifft)").entered();
                        domain.ifft_in_to_out(&mut b_result);
                        T::distribute_powers_and_mul_by_const(&mut b_result, &coset_table);
                        domain.fft_out_to_in(&mut b_result);
                        b_span.exit();
                        b_result
                    },
                )
            },
            || {
                let local_mul_vec_span = tracing::debug_span!("c: local_mul_vec").entered();
                let mut ab = T::local_mul_vec(a, b, state);
                local_mul_vec_span.exit();
                let ifft_span = tracing::debug_span!("c: ifft in dist pows").entered();
                domain.ifft_in_to_out(&mut ab);
                ifft_span.exit();
                let dist_pows_span = tracing::debug_span!("c: dist pows").entered();
                ab.par_iter_mut()
                    .zip_eq(coset_table.par_iter())
                    .with_min_len(512)
                    .for_each(|(share, pow): (&mut T::ArithmeticHalfShare, _)| {
                        *share *= *pow;
                    });
                dist_pows_span.exit();
                let fft_span = tracing::debug_span!("c: fft in dist pows").entered();
                domain.fft_out_to_in(&mut ab);
                fft_span.exit();
                ab
            },
        );

        let local_ab_span = tracing::debug_span!("ab: local_mul_vec").entered();
        // same as above. No IO task is run at the moment.
        let mut ab = T::local_mul_vec(a, b, state);
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
///
/// The three coset evaluations pair an [`Domain::ifft_in_to_out`] with a
/// [`Domain::fft_out_to_in`] and need no permutation. Only the final interpolation does, since
/// `h_query` expects the coefficients of H in natural order.
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
        let domain = Domain::<P::ScalarField>::new(num_constraints + num_inputs)
            .ok_or_else(|| eyre::eyre!("Polynomial Degree too large"))?;
        let domain_size = domain.size();
        let party_id = state.id();

        let coset_table = bit_reversed_coset_table(P::ScalarField::GENERATOR, domain_size);

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
                        domain.ifft_in_to_out(&mut a);
                        T::distribute_powers_and_mul_by_const(&mut a, &coset_table);
                        domain.fft_out_to_in(&mut a);
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
                        domain.ifft_in_to_out(&mut b);
                        T::distribute_powers_and_mul_by_const(&mut b, &coset_table);
                        domain.fft_out_to_in(&mut b);
                        b
                    },
                );
                T::local_mul_vec(a, b, state)
            },
            || {
                let mut c = evaluate_constraint_half_share::<P, T>(
                    party_id,
                    domain_size,
                    &matrices.c,
                    public_inputs,
                    private_witness,
                );
                domain.ifft_in_to_out(&mut c);
                c.par_iter_mut()
                    .zip_eq(coset_table.par_iter())
                    .with_min_len(512)
                    .for_each(|(share, pow): (&mut T::ArithmeticHalfShare, _)| {
                        *share *= *pow;
                    });
                domain.fft_out_to_in(&mut c);
                c
            },
        );

        let vanishing_polynomial_over_coset = (P::ScalarField::GENERATOR.pow([domain_size as u64])
            - P::ScalarField::one())
        .inverse()
        .unwrap();

        ab.par_iter_mut()
            .zip(c.par_iter())
            .with_min_len(512)
            .for_each(|(ab_i, c_i)| {
                *ab_i -= *c_i;
                *ab_i *= vanishing_polynomial_over_coset;
            });

        // Interpolate over the coset and undo the shift. `ifft_in_to_out` leaves the
        // coefficients in bit-reversed order, so permute them back before applying the inverse
        // shift, which then reads its table sequentially.
        domain.ifft_in_to_out(&mut ab);
        bit_reverse(&mut ab);
        let shift_inv = P::ScalarField::GENERATOR.inverse().unwrap();
        let chunk_size = domain_size.div_ceil(rayon::current_num_threads()).max(1);
        ab.par_chunks_mut(chunk_size)
            .enumerate()
            .for_each(|(chunk_index, values)| {
                let mut current = shift_inv.pow([(chunk_index * chunk_size) as u64]);
                for value in values.iter_mut() {
                    *value *= current;
                    current *= shift_inv;
                }
            });

        Ok(ab)
    }
}
