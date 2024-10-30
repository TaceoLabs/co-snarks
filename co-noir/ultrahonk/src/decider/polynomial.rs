use ark_ff::PrimeField;
use num_traits::Zero;
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSlice,
};
use std::{
    cmp::max,
    ops::{AddAssign, Index, IndexMut, SubAssign},
};
const MIN_ELEMENTS_PER_THREAD: usize = 16;
#[derive(Clone, Debug, Default)]
pub struct Polynomial<F> {
    pub coefficients: Vec<F>,
}

pub struct ShiftedPoly<'a, F> {
    pub(crate) coefficients: &'a [F],
    zero: F, // TACEO TODO is there are better solution
}

impl<'a, F: Clone> ShiftedPoly<'a, F> {
    pub fn to_vec(&self) -> Vec<F> {
        let mut res = Vec::with_capacity(self.coefficients.len() + 1);
        for c in self.coefficients.iter().cloned() {
            res.push(c);
        }
        res.push(self.zero.clone());
        res
    }

    pub(crate) fn as_ref(&self) -> &[F] {
        self.coefficients
    }
}

impl<'a, F: Clone> Index<usize> for ShiftedPoly<'a, F> {
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
    pub(crate) fn factor_roots(&mut self, root: &F) {
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

    pub(crate) fn add_scaled(&mut self, src: &Polynomial<F>, scalar: &F) {
        self.add_scaled_slice(&src.coefficients, scalar);
    }
    // This is copied from mpc-core/src/protocols/rep3/poly.rs
    // This is copied from
    // https://docs.rs/ark-poly/latest/src/ark_poly/polynomial/univariate/dense.rs.html#56
    //
    // The DensePolynomial implementation expects a Field, therefore we cannot use it.
    // Therefore we copy it and call the respective rep3 operations

    // Horner's method for polynomial evaluation
    fn horner_evaluate(poly_coeffs: &[F], point: F) -> F {
        poly_coeffs
            .iter()
            .rfold(F::zero(), move |result, coeff| result * point + *coeff)
    }
    // This is copied from mpc-core/src/protocols/rep3/poly.rs
    // This is copied from
    // https://docs.rs/ark-poly/latest/src/ark_poly/polynomial/univariate/dense.rs.html#56
    pub fn eval_poly(&mut self, point: F) -> F {
        if point.is_zero() {
            return self.coefficients[0];
        }

        // Horners method - parallel method
        // compute the number of threads we will be using.
        // TODO investigate how this behaves if we are in a rayon scope. Does this return all
        // free threads or also the busy ones? Because then the chunks size is wrong...
        let num_cpus_available = rayon::current_num_threads();
        let num_coeffs = self.coefficients.len();
        let num_elem_per_thread = max(num_coeffs / num_cpus_available, MIN_ELEMENTS_PER_THREAD);

        // run Horners method on each thread as follows:
        // 1) Split up the coefficients across each thread evenly.
        // 2) Do polynomial evaluation via horner's method for the thread's coefficeints
        // 3) Scale the result point^{thread coefficient start index}
        // Then obtain the final polynomial evaluation by summing each threads result.
        let result = self
            .coefficients
            .par_chunks(num_elem_per_thread)
            .enumerate()
            .map(|(i, chunk)| {
                let mut thread_result = Self::horner_evaluate(chunk, point);
                thread_result *= point.pow([(i * num_elem_per_thread) as u64]);
                thread_result
            })
            .sum();
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
