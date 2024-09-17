use ark_ff::{PrimeField, Zero};
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use crate::decider::barycentric::Barycentric;

#[derive(Clone, Debug)]
pub struct Univariate<F: PrimeField, const SIZE: usize> {
    pub(crate) evaluations: [F; SIZE],
}

impl<F: PrimeField, const SIZE: usize> Univariate<F, SIZE> {
    pub const SIZE: usize = SIZE;

    pub fn new(evaluations: [F; SIZE]) -> Self {
        Self { evaluations }
    }

    pub fn double(self) -> Self {
        let mut result = self;
        result.double_in_place();
        result
    }

    pub fn double_in_place(&mut self) {
        for i in 0..SIZE {
            self.evaluations[i].double_in_place();
        }
    }

    pub fn sqr(self) -> Self {
        let mut result = self;
        result.square_in_place();
        result
    }

    pub fn square_in_place(&mut self) {
        for i in 0..SIZE {
            self.evaluations[i].square_in_place();
        }
    }

    /**
     * @brief Given a univariate f represented by {f(domain_start), ..., f(domain_end - 1)}, compute the
     * evaluations {f(domain_end),..., f(extended_domain_end -1)} and return the Univariate represented by
     * {f(domain_start),..., f(extended_domain_end -1)}
     *
     * @details Write v_i = f(x_i) on a the domain {x_{domain_start}, ..., x_{domain_end-1}}. To efficiently
     * compute the needed values of f, we use the barycentric formula
     *      - f(x) = B(x) Σ_{i=domain_start}^{domain_end-1} v_i / (d_i*(x-x_i))
     * where
     *      - B(x) = Π_{i=domain_start}^{domain_end-1} (x-x_i)
     *      - d_i  = Π_{j ∈ {domain_start, ..., domain_end-1}, j≠i} (x_i-x_j) for i ∈ {domain_start, ...,
     * domain_end-1}
     *
     * When the domain size is two, extending f = v0(1-X) + v1X to a new value involves just one addition
     * and a subtraction: setting Δ = v1-v0, the values of f(X) are f(0)=v0, f(1)= v0 + Δ, v2 = f(1) + Δ, v3
     * = f(2) + Δ...
     *
     */
    pub(crate) fn extend_from(&mut self, poly: &[F]) {
        assert!(poly.len() <= SIZE);
        self.evaluations[..poly.len()].copy_from_slice(poly);

        if poly.len() == 2 {
            let delta = self.evaluations[1] - self.evaluations[0];
            for i in 2..SIZE {
                self.evaluations[i] = self.evaluations[i - 1] + delta;
            }
        } else if poly.len() == 3 {
            // Based off https://hackmd.io/@aztec-network/SyR45cmOq?type=view
            // The technique used here is the same as the length == 3 case below.
            let inverse_two = F::from(2u64).inverse().unwrap();
            let a = (poly[2] + poly[0]) * inverse_two - poly[1];
            let b = poly[1] - a - poly[0];
            let a2 = a.double();
            let mut a_mul = a2.to_owned();
            for _ in 0..poly.len() - 2 {
                a_mul += a2;
            }
            let mut extra = a_mul + a + b;
            for i in 3..SIZE {
                self.evaluations[i] = self.evaluations[i - 1] + extra;
                extra += a2;
            }
        } else if poly.len() == 4 {
            // To compute a barycentric extension, we can compute the coefficients of the univariate.
            // We have the evaluation of the polynomial at the domain (which is assumed to be 0, 1, 2, 3).
            // Therefore, we have the 4 linear equations from plugging into f(x) = ax^3 + bx^2 + cx + d:
            //          a*0 + b*0 + c*0 + d = f(0)
            //          a*1 + b*1 + c*1 + d = f(1)
            //          a*2^3 + b*2^2 + c*2 + d = f(2)
            //          a*3^3 + b*3^2 + c*3 + d = f(3)
            // These equations can be rewritten as a matrix equation M * [a, b, c, d] = [f(0), f(1), f(2),
            // f(3)], where M is:
            //          0,  0,  0,  1
            //          1,  1,  1,  1
            //          2^3, 2^2, 2,  1
            //          3^3, 3^2, 3,  1
            // We can invert this matrix in order to compute a, b, c, d:
            //      -1/6,	1/2,	-1/2,	1/6
            //      1,	    -5/2,	2,	    -1/2
            //      -11/6,	3,	    -3/2,	1/3
            //      1,	    0,	    0,	    0
            // To compute these values, we can multiply everything by 6 and multiply by inverse_six at the
            // end for each coefficient The resulting computation here does 18 field adds, 6 subtracts, 3
            // muls to compute a, b, c, and d.
            let inverse_six = F::from(6u64).inverse().unwrap();

            let zero_times_3 = poly[0].double() + poly[0];
            let zero_times_6 = zero_times_3.double();
            let zero_times_12 = zero_times_6.double();
            let one_times_3 = poly[1].double() + poly[1];
            let one_times_6 = one_times_3.double();
            let two_times_3 = poly[2].double() + poly[2];
            let three_times_2 = poly[3].double();
            let three_times_3 = three_times_2 + poly[3];

            let one_minus_two_times_3 = one_times_3 - two_times_3;
            let one_minus_two_times_6 = one_minus_two_times_3 + one_minus_two_times_3;
            let one_minus_two_times_12 = one_minus_two_times_6 + one_minus_two_times_6;
            let a = (one_minus_two_times_3 + poly[3] - poly[0]) * inverse_six; // compute a in 1 muls and 4 adds
            let b =
                (zero_times_6 - one_minus_two_times_12 - one_times_3 - three_times_3) * inverse_six;
            let c = (poly[0] - zero_times_12
                + one_minus_two_times_12
                + one_times_6
                + two_times_3
                + three_times_2)
                * inverse_six;

            // Then, outside of the a, b, c, d computation, we need to do some extra precomputation
            // This work is 3 field muls, 8 adds
            let a_plus_b = a + b;
            let a_plus_b_times_2 = a_plus_b + a_plus_b;
            let start_idx_sqr = (poly.len() - 1) * (poly.len() - 1);
            let idx_sqr_three = start_idx_sqr + start_idx_sqr + start_idx_sqr;
            let mut idx_sqr_three_times_a = F::from(idx_sqr_three as u64) * a;
            let mut x_a_term = F::from(6 * (poly.len() - 1) as u64) * a;
            let three_a = a + a + a;
            let six_a = three_a + three_a;

            let three_a_plus_two_b = a_plus_b_times_2 + a;
            let mut linear_term =
                F::from(poly.len() as u64 - 1) * three_a_plus_two_b + (a_plus_b + c);

            // For each new evaluation, we do only 6 field additions and 0 muls.
            for i in 4..SIZE {
                self.evaluations[i] = self.evaluations[i - 1] + idx_sqr_three_times_a + linear_term;

                idx_sqr_three_times_a += x_a_term + three_a;
                x_a_term += six_a;

                linear_term += three_a_plus_two_b;
            }
        } else {
            for k in poly.len()..SIZE {
                self.evaluations[k] = F::zero();

                let big_domain = Barycentric::construct_big_domain(poly.len(), SIZE);
                let lagrange_denominators =
                    Barycentric::construct_lagrange_denominators(poly.len(), &big_domain);
                let dominator_inverses = Barycentric::construct_denominator_inverses(
                    SIZE,
                    &big_domain,
                    &lagrange_denominators,
                );
                let full_numerator_values =
                    Barycentric::construct_full_numerator_values(poly.len(), SIZE, &big_domain);

                // compute each term v_j / (d_j*(x-x_j)) of the sum
                for (j, term) in poly.iter().enumerate() {
                    let mut term = *term;
                    term *= &dominator_inverses[poly.len() * k + j];
                    self.evaluations[k] += term;
                }
                // scale the sum by the value of of B(x)
                self.evaluations[k] *= &full_numerator_values[k];
            }
        }
    }

    pub(crate) fn extend_and_batch_univariates<const SIZE2: usize>(
        &self,
        result: &mut Univariate<F, SIZE2>,
        extended_random_poly: &Univariate<F, SIZE2>,
        partial_evaluation_result: &F,
        linear_independent: bool,
    ) {
        let mut extended = Univariate::<F, SIZE2>::default();
        extended.extend_from(&self.evaluations);

        if linear_independent {
            *result += extended * extended_random_poly * partial_evaluation_result;
        } else {
            *result += extended;
        }
    }
}

impl<F: PrimeField, const SIZE: usize> Default for Univariate<F, SIZE> {
    fn default() -> Self {
        Self {
            evaluations: [F::zero(); SIZE],
        }
    }
}

impl<F: PrimeField, const SIZE: usize> Add for Univariate<F, SIZE> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut result = self;
        result += rhs;
        result
    }
}

impl<F: PrimeField, const SIZE: usize> Add<&Self> for Univariate<F, SIZE> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        let mut result = self;
        result += rhs;
        result
    }
}

impl<F: PrimeField, const SIZE: usize> Add<&F> for Univariate<F, SIZE> {
    type Output = Self;

    fn add(self, rhs: &F) -> Self::Output {
        let mut result = self;
        result += rhs;
        result
    }
}

impl<F: PrimeField, const SIZE: usize> AddAssign for Univariate<F, SIZE> {
    fn add_assign(&mut self, rhs: Self) {
        for i in 0..SIZE {
            self.evaluations[i] += rhs.evaluations[i];
        }
    }
}

impl<F: PrimeField, const SIZE: usize> AddAssign<&Self> for Univariate<F, SIZE> {
    fn add_assign(&mut self, rhs: &Self) {
        for i in 0..SIZE {
            self.evaluations[i] += rhs.evaluations[i];
        }
    }
}

impl<F: PrimeField, const SIZE: usize> AddAssign<&F> for Univariate<F, SIZE> {
    fn add_assign(&mut self, rhs: &F) {
        for i in 0..SIZE {
            self.evaluations[i] += rhs;
        }
    }
}

impl<F: PrimeField, const SIZE: usize> Sub<u64> for Univariate<F, SIZE> {
    type Output = Self;

    fn sub(self, rhs: u64) -> Self::Output {
        let mut result = self;
        let rhs = F::from(rhs);

        result -= rhs;
        result
    }
}

impl<F: PrimeField, const SIZE: usize> Sub<&F> for Univariate<F, SIZE> {
    type Output = Self;

    fn sub(self, rhs: &F) -> Self::Output {
        let mut result = self;
        result -= rhs;
        result
    }
}

impl<F: PrimeField, const SIZE: usize> Sub for Univariate<F, SIZE> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let mut result = self;
        result -= rhs;
        result
    }
}

impl<F: PrimeField, const SIZE: usize> Sub<&Self> for Univariate<F, SIZE> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        let mut result = self;
        result -= rhs;
        result
    }
}

impl<F: PrimeField, const SIZE: usize> SubAssign<&F> for Univariate<F, SIZE> {
    fn sub_assign(&mut self, rhs: &F) {
        for i in 0..SIZE {
            self.evaluations[i] -= rhs;
        }
    }
}

impl<F: PrimeField, const SIZE: usize> SubAssign<F> for Univariate<F, SIZE> {
    fn sub_assign(&mut self, rhs: F) {
        for i in 0..SIZE {
            self.evaluations[i] -= rhs;
        }
    }
}

impl<F: PrimeField, const SIZE: usize> SubAssign for Univariate<F, SIZE> {
    fn sub_assign(&mut self, rhs: Self) {
        for i in 0..SIZE {
            self.evaluations[i] -= rhs.evaluations[i];
        }
    }
}

impl<F: PrimeField, const SIZE: usize> SubAssign<&Self> for Univariate<F, SIZE> {
    fn sub_assign(&mut self, rhs: &Self) {
        for i in 0..SIZE {
            self.evaluations[i] -= rhs.evaluations[i];
        }
    }
}

impl<F: PrimeField, const SIZE: usize> Mul for Univariate<F, SIZE> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut result = self;
        result *= rhs;
        result
    }
}

impl<F: PrimeField, const SIZE: usize> Mul<&Self> for Univariate<F, SIZE> {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        let mut result = self;
        result *= rhs;
        result
    }
}

impl<F: PrimeField, const SIZE: usize> Mul<F> for Univariate<F, SIZE> {
    type Output = Self;

    fn mul(self, rhs: F) -> Self::Output {
        let mut result = self;
        result *= rhs;
        result
    }
}

impl<F: PrimeField, const SIZE: usize> Mul<&F> for Univariate<F, SIZE> {
    type Output = Self;

    fn mul(self, rhs: &F) -> Self::Output {
        let mut result = self;
        result *= rhs;
        result
    }
}

impl<F: PrimeField, const SIZE: usize> MulAssign for Univariate<F, SIZE> {
    fn mul_assign(&mut self, rhs: Self) {
        for i in 0..SIZE {
            self.evaluations[i] *= rhs.evaluations[i];
        }
    }
}

impl<F: PrimeField, const SIZE: usize> MulAssign<&Self> for Univariate<F, SIZE> {
    fn mul_assign(&mut self, rhs: &Self) {
        for i in 0..SIZE {
            self.evaluations[i] *= rhs.evaluations[i];
        }
    }
}

impl<F: PrimeField, const SIZE: usize> MulAssign<F> for Univariate<F, SIZE> {
    fn mul_assign(&mut self, rhs: F) {
        for i in 0..SIZE {
            self.evaluations[i] *= rhs;
        }
    }
}

impl<F: PrimeField, const SIZE: usize> MulAssign<&F> for Univariate<F, SIZE> {
    fn mul_assign(&mut self, rhs: &F) {
        for i in 0..SIZE {
            self.evaluations[i] *= rhs;
        }
    }
}

impl<F: PrimeField, const SIZE: usize> Zero for Univariate<F, SIZE> {
    fn zero() -> Self {
        Self::default()
    }

    fn is_zero(&self) -> bool {
        for val in self.evaluations.iter() {
            if !val.is_zero() {
                return false;
            }
        }
        true
    }
}

impl<F: PrimeField, const SIZE: usize> Neg for Univariate<F, SIZE> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let mut result = self;
        for i in 0..SIZE {
            result.evaluations[i] = -result.evaluations[i];
        }
        result
    }
}
