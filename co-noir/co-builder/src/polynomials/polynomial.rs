use crate::utils::Utils;
use ark_ff::PrimeField;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial as _};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use num_traits::Zero;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::ops::{AddAssign, Index, IndexMut, MulAssign, SubAssign};

#[derive(Clone, Debug, Default)]
pub struct Polynomial<F> {
    pub coefficients: Vec<F>,
}

impl<F: CanonicalSerialize> Serialize for Polynomial<F> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        mpc_core::ark_se(&self.coefficients, serializer)
    }
}

impl<'a, F: CanonicalDeserialize> Deserialize<'a> for Polynomial<F> {
    fn deserialize<D: Deserializer<'a>>(deserializer: D) -> Result<Self, D::Error> {
        let coefficients: Vec<F> = mpc_core::ark_de(deserializer)?;
        Ok(Self { coefficients })
    }
}

pub struct ShiftedPoly<'a, F> {
    pub(crate) coefficients: &'a [F],
    zero: F, // TACEO TODO is there are better solution
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
    pub fn shifted(&self) -> ShiftedPoly<F> {
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
        }
        self.coefficients.pop();
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
        let coefficients = (0..size).map(|_| F::rand(rng)).collect();
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
}
