//Copyright (c) 2021 Georgios Konstantopoulos
//
//Permission is hereby granted, free of charge, to any
//person obtaining a copy of this software and associated
//documentation files (the "Software"), to deal in the
//Software without restriction, including without
//limitation the rights to use, copy, modify, merge,
//publish, distribute, sublicense, and/or sell copies of
//the Software, and to permit persons to whom the Software
//is furnished to do so, subject to the following
//conditions:
//
//The above copyright notice and this permission notice
//shall be included in all copies or substantial portions
//of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
//ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
//TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
//PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
//SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
//CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
//OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
//IN CONNECTION WITH THE SOFTWARE O THE USE OR OTHER
//DEALINGS IN THE SOFTWARE.R

// copied from https://github.com/arkworks-rs/circom-compat/blob/170b10fc9ed182b5f72ecf379033dda023d0bf07/src/circom/qap.rs

use ark_ff::PrimeField;
use ark_groth16::r1cs_to_qap::{evaluate_constraint, LibsnarkReduction, R1CSToQAP};
use ark_poly::EvaluationDomain;
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSystemRef, SynthesisError};
use ark_std::{cfg_into_iter, cfg_iter, cfg_iter_mut, vec};

/// Implements the witness map used by snarkjs. The arkworks witness map calculates the
/// coefficients of H through computing (AB-C)/Z in the evaluation domain and going back to the
/// coefficients domain. snarkjs instead precomputes the Lagrange form of the powers of tau bases
/// in a domain twice as large and the witness map is computed as the odd coefficients of (AB-C)
/// in that domain. This serves as HZ when computing the C proof element.
pub struct CircomReduction;

impl R1CSToQAP for CircomReduction {
    #[allow(clippy::type_complexity)]
    fn instance_map_with_evaluation<F: PrimeField, D: EvaluationDomain<F>>(
        cs: ConstraintSystemRef<F>,
        t: &F,
    ) -> Result<(Vec<F>, Vec<F>, Vec<F>, F, usize, usize), SynthesisError> {
        LibsnarkReduction::instance_map_with_evaluation::<F, D>(cs, t)
    }

    fn witness_map_from_matrices<F: PrimeField, D: EvaluationDomain<F>>(
        matrices: &ConstraintMatrices<F>,
        num_inputs: usize,
        num_constraints: usize,
        full_assignment: &[F],
    ) -> Result<Vec<F>, SynthesisError> {
        ///// The number of variables that are "public instances" to the constraint
        ///// system.
        //pub num_instance_variables: usize,
        ///// The number of variables that are "private witnesses" to the constraint
        ///// system.
        //pub num_witness_variables: usize,
        ///// The number of constraints in the constraint system.
        //pub num_constraints: usize,
        ///// The number of non_zero entries in the A matrix.
        //pub a_num_non_zero: usize,
        ///// The number of non_zero entries in the B matrix.
        //pub b_num_non_zero: usize,
        ///// The number of non_zero entries in the C matrix.
        //pub c_num_non_zero: usize,

        ///// The A constraint matrix. This is empty when
        ///// `self.mode == SynthesisMode::Prove { construct_matrices = false }`.
        //pub a: Matrix<F>,
        ///// The B constraint matrix. This is empty when
        ///// `self.mode == SynthesisMode::Prove { construct_matrices = false }`.
        //pub b: Matrix<F>,
        ///// The C constraint matrix. This is empty when
        ///// `self.mode == SynthesisMode::Prove { construct_matrices = false }`.
        //pub c: Matrix<F>,
        //  println!("{}", matrices.num_instance_variables);
        //  println!("{}", matrices.num_witness_variables);
        //  println!("{}", matrices.num_constraints);
        //  println!("{}", matrices.a_num_non_zero);
        //  println!("{}", matrices.b_num_non_zero);
        //  println!("{}", matrices.c_num_non_zero);
        //  for row in matrices.a.iter() {
        //      print!("[");
        //      for col in row.iter() {
        //          print!("({}, {}", col.0, col.1);
        //      }
        //      println!("]");
        //  }
        //  println!();
        //  for row in matrices.b.iter() {
        //      print!("[");
        //      for col in row.iter() {
        //          print!("({}, {}", col.0, col.1);
        //      }
        //      println!("]");
        //  }
        //  println!();
        //  for row in matrices.c.iter() {
        //      print!("[");
        //      for col in row.iter() {
        //          print!("({}, {})", col.0, col.1);
        //      }
        //      println!("]");
        //  }
        //  panic!("hi i am here");
        let zero = F::zero();
        let domain =
            D::new(num_constraints + num_inputs).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_size = domain.size();

        let mut a = vec![zero; domain_size];
        let mut b = vec![zero; domain_size];

        cfg_iter_mut!(a[..num_constraints])
            .zip(cfg_iter_mut!(b[..num_constraints]))
            .zip(cfg_iter!(&matrices.a))
            .zip(cfg_iter!(&matrices.b))
            .for_each(|(((a, b), at_i), bt_i)| {
                println!("evaluating constraint");
                *a = evaluate_constraint(at_i, full_assignment);
                *b = evaluate_constraint(bt_i, full_assignment);
            });

        {
            let start = num_constraints;
            let end = start + num_inputs;
            println!("{start}-{end}");
            a[start..end].clone_from_slice(&full_assignment[..num_inputs]);
        }

        let mut c = vec![zero; domain_size];
        cfg_iter_mut!(c[..num_constraints])
            .zip(&a)
            .zip(&b)
            .for_each(|((c_i, &a), &b)| {
                *c_i = a * b;
            });

        domain.ifft_in_place(&mut a);
        domain.ifft_in_place(&mut b);

        let root_of_unity = {
            let domain_size_double = 2 * domain_size;
            let domain_double =
                D::new(domain_size_double).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
            domain_double.element(1)
        };
        D::distribute_powers_and_mul_by_const(&mut a, root_of_unity, F::one());
        D::distribute_powers_and_mul_by_const(&mut b, root_of_unity, F::one());

        domain.fft_in_place(&mut a);
        domain.fft_in_place(&mut b);

        let mut ab = domain.mul_polynomials_in_evaluation_domain(&a, &b);
        drop(a);
        drop(b);

        domain.ifft_in_place(&mut c);
        D::distribute_powers_and_mul_by_const(&mut c, root_of_unity, F::one());
        domain.fft_in_place(&mut c);

        cfg_iter_mut!(ab)
            .zip(c)
            .for_each(|(ab_i, c_i)| *ab_i -= &c_i);

        Ok(ab)
    }

    fn h_query_scalars<F: PrimeField, D: EvaluationDomain<F>>(
        max_power: usize,
        t: F,
        _: F,
        delta_inverse: F,
    ) -> Result<Vec<F>, SynthesisError> {
        // the usual H query has domain-1 powers. Z has domain powers. So HZ has 2*domain-1 powers.
        let mut scalars = cfg_into_iter!(0..2 * max_power + 1)
            .map(|i| delta_inverse * t.pow([i as u64]))
            .collect::<Vec<_>>();
        let domain_size = scalars.len();
        let domain = D::new(domain_size).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        // generate the lagrange coefficients
        domain.ifft_in_place(&mut scalars);
        Ok(cfg_into_iter!(scalars).skip(1).step_by(2).collect())
    }
}
