use crate::utils::Utils;
use ark_ff::PrimeField;
use ark_poly::{DenseUVPolynomial, Polynomial as _, univariate::DensePolynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use num_traits::Zero;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::ops::{AddAssign, Index, IndexMut, MulAssign, SubAssign};

// The number of last rows in ProverPolynomials that are randomized to mask
// 1) witness commitments,
// 2) multilinear evaluations of witness polynomials in Sumcheck
// 3*) multilinear evaluations of shifts of witness polynomials in Sumcheck OR univariate evaluations required in ECCVM
pub const NUM_MASKED_ROWS: u32 = 3;

// To account for the masked entries of witness polynomials in ZK-Sumcheck, we are disabling all relations in the last
// `NUM_MASKED_ROWS + 1` rows, where `+1` is needed for the shifts. Namely, any relation involving a shift of a masked
// polynomial w_shift, can't be satisfied on the row `N - (NUM_MASKED_ROWS + 1)`, as `w_shift.at(N - (NUM_MASKED_ROWS +
// 1))` is equal to the random value `w.at(N - NUM_MASKED_ROWS)`.
pub const NUM_DISABLED_ROWS_IN_SUMCHECK: u32 = NUM_MASKED_ROWS + 1;
pub const NUM_TRANSLATION_EVALUATIONS: u32 = 5;
#[derive(Clone, Debug, Default)]
pub struct Polynomial<F> {
    pub coefficients: Vec<F>,
}

impl<F: CanonicalSerialize> Serialize for Polynomial<F> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        mpc_core::serde_compat::ark_se(&self.coefficients, serializer)
    }
}

impl<'a, F: CanonicalDeserialize> Deserialize<'a> for Polynomial<F> {
    fn deserialize<D: Deserializer<'a>>(deserializer: D) -> Result<Self, D::Error> {
        let coefficients: Vec<F> = mpc_core::serde_compat::ark_de(deserializer)?;
        Ok(Self { coefficients })
    }
}

pub struct ShiftedPoly<'a, F> {
    pub(crate) coefficients: &'a [F],
    zero: F, // TACEO TODO is there a better solution
}

impl<F: Clone> ShiftedPoly<'_, F> {
    pub fn to_vec(&self) -> Vec<F> {
        let mut res = Vec::with_capacity(self.coefficients.len() + 1);
        for c in self.coefficients.iter().cloned() {
            res.push(c);
        }
        res.push(self.zero.clone());
        res
    }

    pub fn as_ref(&self) -> &[F] {
        self.coefficients
    }
}

impl<F: Clone> Index<usize> for ShiftedPoly<'_, F> {
    type Output = F;

    fn index(&self, index: usize) -> &Self::Output {
        if index == self.coefficients.len() {
            &self.zero
        } else {
            &self.coefficients[index]
        }
    }
}

impl<F: Clone> AsRef<[F]> for Polynomial<F> {
    fn as_ref(&self) -> &[F] {
        &self.coefficients
    }
}

impl<F: Clone> AsMut<[F]> for Polynomial<F> {
    fn as_mut(&mut self) -> &mut [F] {
        &mut self.coefficients
    }
}

impl<F: Clone> Polynomial<F> {
    pub fn new(coefficients: Vec<F>) -> Self {
        Self { coefficients }
    }

    pub fn iter(&self) -> impl Iterator<Item = &F> {
        self.coefficients.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut F> {
        self.coefficients.iter_mut()
    }

    pub fn is_empty(&self) -> bool {
        self.coefficients.is_empty()
    }

    pub fn len(&self) -> usize {
        self.coefficients.len()
    }

    pub fn resize(&mut self, size: usize, value: F) {
        self.coefficients.resize(size, value);
    }

    pub fn into_vec(self) -> Vec<F> {
        self.coefficients
    }
}

impl<F: Zero + Clone> Polynomial<F> {
    pub fn new_zero(size: usize) -> Self {
        Self {
            coefficients: vec![F::zero(); size],
        }
    }

    pub fn degree(&self) -> usize {
        let mut len = self.coefficients.len() - 1;
        for c in self.coefficients.iter().rev() {
            if c.is_zero() {
                len -= 1;
            } else {
                break;
            }
        }
        len
    }
}

impl<F: Default + Clone> Polynomial<F> {
    pub fn new_default(size: usize) -> Self {
        Self {
            coefficients: vec![F::default(); size],
        }
    }

    // Can only shift by 1
    pub fn shifted(&'_ self) -> ShiftedPoly<'_, F> {
        assert!(!self.coefficients.is_empty());
        ShiftedPoly {
            coefficients: &self.coefficients[1..],
            zero: F::default(),
        }
    }
}

impl<F: PrimeField> Polynomial<F> {
    /**
     * @brief Divides p(X) by (X-r) in-place.
     */
    pub fn factor_roots(&mut self, root: &F) {
        if root.is_zero() {
            // if one of the roots is 0 after having divided by all other roots,
            // then p(X) = a₁⋅X + ⋯ + aₙ₋₁⋅Xⁿ⁻¹
            // so we shift the array of coefficients to the left
            // and the result is p(X) = a₁ + ⋯ + aₙ₋₁⋅Xⁿ⁻² and we subtract 1 from the size.
            self.coefficients.remove(0);
        } else {
            // assume
            //  • r != 0
            //  • (X−r) | p(X)
            //  • q(X) = ∑ᵢⁿ⁻² bᵢ⋅Xⁱ
            //  • p(X) = ∑ᵢⁿ⁻¹ aᵢ⋅Xⁱ = (X-r)⋅q(X)
            //
            // p(X)         0           1           2       ...     n-2             n-1
            //              a₀          a₁          a₂              aₙ₋₂            aₙ₋₁
            //
            // q(X)         0           1           2       ...     n-2             n-1
            //              b₀          b₁          b₂              bₙ₋₂            0
            //
            // (X-r)⋅q(X)   0           1           2       ...     n-2             n-1
            //              -r⋅b₀       b₀-r⋅b₁     b₁-r⋅b₂         bₙ₋₃−r⋅bₙ₋₂      bₙ₋₂
            //
            // b₀   = a₀⋅(−r)⁻¹
            // b₁   = (a₁ - b₀)⋅(−r)⁻¹
            // b₂   = (a₂ - b₁)⋅(−r)⁻¹
            //      ⋮
            // bᵢ   = (aᵢ − bᵢ₋₁)⋅(−r)⁻¹
            //      ⋮
            // bₙ₋₂ = (aₙ₋₂ − bₙ₋₃)⋅(−r)⁻¹
            // bₙ₋₁ = 0

            // For the simple case of one root we compute (−r)⁻¹ and
            let root_inverse = (-*root).inverse().expect("Root is not zero here");
            // set b₋₁ = 0
            let mut temp = F::zero();
            // We start multiplying lower coefficient by the inverse and subtracting those from highter coefficients
            // Since (x - r) should divide the polynomial cleanly, we can guide division with lower coefficients
            for coeff in self.coefficients.iter_mut() {
                // at the start of the loop, temp = bᵢ₋₁
                // and we can compute bᵢ   = (aᵢ − bᵢ₋₁)⋅(−r)⁻¹
                temp = *coeff - temp;
                temp *= root_inverse;
                *coeff = temp;
            }
            // remove the last (zero) coefficient after synthetic division
            self.coefficients.pop();
        }
    }
    /**
     * @brief Add random values to the coefficients of a polynomial. In practice, this is used for ensuring the
     * commitment and evaluation of a polynomial don't leak information about the coefficients in the context of zero
     * knowledge.
     */
    pub fn mask<R: Rng + CryptoRng>(&mut self, rng: &mut R) {
        let virtual_size = self.coefficients.len();
        assert!(
            virtual_size >= NUM_MASKED_ROWS as usize,
            "Insufficient space for masking"
        );
        for i in (virtual_size - NUM_MASKED_ROWS as usize..virtual_size).rev() {
            self.coefficients[i] = F::rand(rng);
        }
    }

    pub fn add_scaled_slice(&mut self, src: &[F], scalar: &F) {
        // Barrettenberg uses multithreading here
        for (des, src) in self.coefficients.iter_mut().zip(src.iter()) {
            *des += *scalar * src;
        }
    }

    pub fn add_scaled(&mut self, src: &Polynomial<F>, scalar: &F) {
        self.add_scaled_slice(&src.coefficients, scalar);
    }

    pub fn eval_poly(&self, point: F) -> F {
        // TACEO TODO: here we clone...
        let poly = DensePolynomial::from_coefficients_slice(&self.coefficients);
        poly.evaluate(&point)
    }

    pub fn random<R: Rng + CryptoRng>(size: usize, rng: &mut R) -> Self {
        let coefficients = (0..size).map(|_| F::one()).collect(); //TODO FLORIN REMOVE
        Self { coefficients }
    }

    pub fn evaluate_mle(&self, evaluation_points: &[F]) -> F {
        if self.coefficients.is_empty() {
            return F::zero();
        }

        let n = evaluation_points.len();
        let dim = Utils::get_msb64(self.coefficients.len() as u64 - 1) as usize + 1; // Round up to next power of 2

        // To simplify handling of edge cases, we assume that the index space is always a power of 2
        assert_eq!(self.coefficients.len(), 1 << n);

        // We first fold over dim rounds l = 0,...,dim-1.
        // in round l, n_l is the size of the buffer containing the Polynomial partially evaluated
        // at u₀,..., u_l.
        // In round 0, this is half the size of dim
        let mut n_l = 1 << (dim - 1);
        let mut tmp = vec![F::zero(); n_l];

        // Note below: i * 2 + 1 + offset might equal virtual_size. This used to subtlely be handled by extra capacity
        // padding (and there used to be no assert time checks, which this constant helps with).
        for (i, val) in tmp.iter_mut().enumerate().take(n_l) {
            *val = self.coefficients[i * 2]
                + evaluation_points[0] * (self.coefficients[i * 2 + 1] - self.coefficients[i * 2]);
        }

        // partially evaluate the dim-1 remaining points
        for (l, val) in evaluation_points.iter().enumerate().take(dim).skip(1) {
            n_l = 1 << (dim - l - 1);

            for i in 0..n_l {
                tmp[i] = tmp[i * 2] + *val * (tmp[i * 2 + 1] - tmp[i * 2]);
            }
        }

        let mut result = tmp[0];

        // We handle the "trivial" dimensions which are full of zeros.
        for &point in &evaluation_points[dim..n] {
            result *= F::one() - point;
        }

        result
    }
    // Create the degree-(m-1) polynomial T(X) that interpolates the given evaluations.
    pub fn interpolate_from_evals(interpolation_points: &[F], evaluations: &[F], m: usize) -> Self {
        let mut dest = Polynomial::new(vec![F::zero(); m]);
        debug_assert_eq!(m, evaluations.len());
        let mut numerator_polynomial = vec![F::zero(); m + 1];
        {
            let mut scratch_space = interpolation_points.to_vec();

            numerator_polynomial[m] = F::one();
            numerator_polynomial[m - 1] = -scratch_space.iter().copied().sum::<F>();

            let mut temp;
            let mut constant = F::one();
            for i in 0..m - 1 {
                temp = F::zero();
                for j in 0..m - 1 - i {
                    scratch_space[j] = interpolation_points[j]
                        * scratch_space[j + 1..]
                            .iter()
                            .take(m - 1 - i - j)
                            .copied()
                            .sum::<F>();
                    temp += scratch_space[j];
                }
                numerator_polynomial[m - 2 - i] = temp * constant;
                constant *= -F::one();
            }
        }
        let mut roots_and_denominators = vec![F::zero(); 2 * m];
        let mut tmp_src = vec![F::zero(); m];
        for i in 0..m {
            roots_and_denominators[i] = -interpolation_points[i];
            tmp_src[i] = evaluations[i];
            roots_and_denominators[m + i] = F::one();
            for j in 0..m {
                if j != i {
                    roots_and_denominators[m + i] *=
                        interpolation_points[i] - interpolation_points[j];
                }
            }
        }
        ark_ff::batch_inversion(roots_and_denominators.as_mut_slice());

        let mut temp_dest = vec![F::zero(); m];
        let mut idx_zero = 0;
        let mut interpolation_domain_contains_zero: bool = false;
        if numerator_polynomial[0] == F::zero() {
            for (i, pt) in interpolation_points.iter().enumerate() {
                if pt.is_zero() {
                    idx_zero = i;
                    interpolation_domain_contains_zero = true;
                    break;
                }
            }
        }
        if !interpolation_domain_contains_zero {
            for i in 0..m {
                // set z = - 1/x_i for x_i <> 0
                let z = roots_and_denominators[i];
                // temp_src[i] is y_i, it gets multiplied by 1/d_i
                let multiplier = tmp_src[i] * roots_and_denominators[m + i];
                temp_dest[0] = multiplier * numerator_polynomial[0];
                temp_dest[0] *= z;
                dest.coefficients[0] += temp_dest[0];
                for j in 1..m {
                    temp_dest[j] = multiplier * numerator_polynomial[j] - temp_dest[j - 1];
                    temp_dest[j] *= z;
                    dest.coefficients[j] += temp_dest[j];
                }
            }
        } else {
            for i in 0..m {
                if i == idx_zero {
                    // the contribution from the term corresponding to i_0 is computed separately
                    continue;
                }
                // get the next inverted root
                let z = roots_and_denominators[i];
                // compute f(x_i) * d_{x_i}^{-1}
                let multiplier = tmp_src[i] * roots_and_denominators[m + i];
                // get x_i^{-1} * f(x_i) * d_{x_i}^{-1} into the "free" term
                temp_dest[1] = multiplier * numerator_polynomial[1];
                temp_dest[1] *= z;
                // correct the first coefficient as it is now accumulating free terms from
                // f(x_i) d_i^{-1} prod_(X-x_i, x_i != 0) (X-x_i) * 1/(X-x_i)
                dest.coefficients[1] += temp_dest[1];
                // compute the quotient N(X)/(X-x_i) f(x_i)/d_{x_i} and its contribution to the target coefficients
                for j in 2..m {
                    temp_dest[j] = multiplier * numerator_polynomial[j] - temp_dest[j - 1];
                    temp_dest[j] *= z;
                    dest.coefficients[j] += temp_dest[j];
                }
            }
            // correct the target coefficients by the contribution from q_{0} = N(X)/X * d_{i_0}^{-1} * f(0)
            for i in 0..m {
                dest.coefficients[i] += tmp_src[idx_zero]
                    * roots_and_denominators[m + idx_zero]
                    * numerator_polynomial[i + 1];
            }
        }

        dest
    }
}

impl<F> Index<usize> for Polynomial<F> {
    type Output = F;

    fn index(&self, index: usize) -> &Self::Output {
        &self.coefficients[index]
    }
}

impl<F> IndexMut<usize> for Polynomial<F> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.coefficients[index]
    }
}

impl<F: PrimeField> AddAssign<&[F]> for Polynomial<F> {
    fn add_assign(&mut self, rhs: &[F]) {
        if rhs.len() > self.coefficients.len() {
            panic!("Polynomial too large, this should not have happened");
            // self.coefficients.resize(rhs.len(), F::zero());
        }
        for (l, r) in self.coefficients.iter_mut().zip(rhs.iter()) {
            *l += *r;
        }
    }
}

impl<F: PrimeField> SubAssign<&[F]> for Polynomial<F> {
    fn sub_assign(&mut self, rhs: &[F]) {
        if rhs.len() > self.coefficients.len() {
            panic!("Polynomial too large, this should not have happened");
            // self.coefficients.resize(rhs.len(), F::zero());
        }
        for (l, r) in self.coefficients.iter_mut().zip(rhs.iter()) {
            *l -= *r;
        }
    }
}

impl<F: PrimeField> MulAssign<F> for Polynomial<F> {
    fn mul_assign(&mut self, rhs: F) {
        for l in self.coefficients.iter_mut() {
            *l *= rhs;
        }
    }
}

pub struct RowDisablingPolynomial<F: PrimeField> {
    pub eval_at_0: F,
    pub eval_at_1: F,
}

impl<F: PrimeField> Default for RowDisablingPolynomial<F> {
    fn default() -> Self {
        Self {
            eval_at_0: F::one(),
            eval_at_1: F::one(),
        }
    }
}
impl<F: PrimeField> RowDisablingPolynomial<F> {
    pub fn update_evaluations(&mut self, round_challenge: F, round_idx: usize) {
        if round_idx == 1 {
            self.eval_at_0 = F::zero();
        }
        if round_idx >= 2 {
            self.eval_at_1 *= round_challenge;
        }
    }

    pub fn evaluate_at_challenge(multivariate_challenge: &[F], log_circuit_size: usize) -> F {
        let mut evaluation_at_multivariate_challenge = F::one();

        for val in multivariate_challenge.iter().take(log_circuit_size).skip(2) {
            evaluation_at_multivariate_challenge *= val;
        }

        F::one() - evaluation_at_multivariate_challenge
    }
    /**
     * @brief A variant of the above that uses `padding_indicator_array`.
     *
     * @param multivariate_challenge Sumcheck evaluation challenge
     * @param padding_indicator_array An array with first log_n entries equal to 1, and the remaining entries are 0.
     */
    pub fn evaluate_at_challenge_with_padding(
        multivariate_challenge: &[F],
        padding_indicator_array: &[F],
    ) -> F {
        let mut evaluation_at_multivariate_challenge = F::one();

        for (idx, &indicator) in padding_indicator_array.iter().enumerate().skip(2) {
            evaluation_at_multivariate_challenge *=
                F::one() - indicator + indicator * multivariate_challenge[idx];
        }

        F::one() - evaluation_at_multivariate_challenge
    }
}
