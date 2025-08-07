use ark_ec::CurveGroup;
use ark_ff::{Field, One, Zero};
use co_builder::prelude::{Polynomial, Utils};
use mpc_core::MpcState;
use mpc_net::Network;
use std::{
    fmt::Debug,
    ops::{Index, IndexMut},
};

use crate::mpc::NoirUltraHonkProver;

pub struct SharedPolynomial<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub coefficients: Vec<T::ArithmeticShare>,
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> SharedPolynomial<T, P> {
    pub fn new_zero(size: usize) -> Self {
        Self {
            coefficients: vec![Default::default(); size],
        }
    }

    pub fn new(coefficients: Vec<T::ArithmeticShare>) -> Self {
        Self { coefficients }
    }

    pub fn promote_poly(
        id: <T::State as MpcState>::PartyID,
        poly: Polynomial<P::ScalarField>,
    ) -> Self {
        let coefficients = T::promote_to_trivial_shares(id, poly.as_ref());
        Self { coefficients }
    }

    pub fn add_assign_slice(&mut self, other: &[T::ArithmeticShare]) {
        // Barrettenberg uses multithreading here
        for (des, src) in self.coefficients.iter_mut().zip(other.iter()) {
            *des = T::add(*des, *src);
        }
    }

    pub fn sub_assign_slice(&mut self, other: &[T::ArithmeticShare]) {
        // Barrettenberg uses multithreading here
        for (des, src) in self.coefficients.iter_mut().zip(other.iter()) {
            *des = T::sub(*des, *src);
        }
    }

    pub fn add_scaled_slice(&mut self, src: &[T::ArithmeticShare], scalar: &P::ScalarField) {
        // Barrettenberg uses multithreading here
        for (des, src) in self.coefficients.iter_mut().zip(src.iter()) {
            let tmp = T::mul_with_public(*scalar, *src);
            *des = T::add(*des, tmp);
        }
    }

    pub fn add_scaled(&mut self, src: &SharedPolynomial<T, P>, scalar: &P::ScalarField) {
        self.add_scaled_slice(&src.coefficients, scalar);
    }

    pub fn add_scaled_slice_public(
        &mut self,
        id: <T::State as MpcState>::PartyID,
        src: &[P::ScalarField],
        scalar: &P::ScalarField,
    ) {
        // Barrettenberg uses multithreading here
        for (des, src) in self.coefficients.iter_mut().zip(src.iter()) {
            let tmp = *scalar * src;
            *des = T::add_with_public(tmp, *des, id);
        }
    }

    pub fn len(&self) -> usize {
        self.coefficients.len()
    }

    pub fn is_empty(&self) -> bool {
        self.coefficients.is_empty()
    }

    // Can only shift by 1
    pub fn shifted(&self) -> &[T::ArithmeticShare] {
        assert!(!self.coefficients.is_empty());
        &self.coefficients[1..]
    }

    /**
     * @brief Divides p(X) by (X-r) in-place.
     */
    pub fn factor_roots(&mut self, root: &P::ScalarField) {
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
            let mut temp = Default::default();
            // We start multiplying lower coefficient by the inverse and subtracting those from highter coefficients
            // Since (x - r) should divide the polynomial cleanly, we can guide division with lower coefficients
            for coeff in self.coefficients.iter_mut() {
                // at the start of the loop, temp = bᵢ₋₁
                // and we can compute bᵢ   = (aᵢ − bᵢ₋₁)⋅(−r)⁻¹
                temp = T::sub(*coeff, temp);
                temp = T::mul_with_public(root_inverse, temp);
                *coeff = temp.to_owned();
            }
            // remove the last (zero) coefficient after synthetic division
            self.coefficients.pop();
        }
    }

    pub fn random<N: Network>(size: usize, net: &N, state: &mut T::State) -> eyre::Result<Self> {
        // let coefficients: Result<Vec<_>, _> = (0..size).map(|_| T::rand(net, state)).collect();
        let coefficients: Vec<_> = (0..size)
            .map(|_| T::promote_to_trivial_share(state.id(), P::ScalarField::one())) //TODO FLORIN REMOVE //T::rand(net, state))
            .collect();
        // let coefficients = coefficients?;
        Ok(Self { coefficients })
    }

    pub fn mul_assign(&mut self, rhs: P::ScalarField) {
        for l in self.coefficients.iter_mut() {
            *l = T::mul_with_public(rhs, *l);
        }
    }

    pub fn evaluate_mle(&self, evaluation_points: &[P::ScalarField]) -> T::ArithmeticShare {
        if self.coefficients.is_empty() {
            return T::ArithmeticShare::default();
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
        let mut tmp = vec![T::ArithmeticShare::default(); n_l];

        // Note below: i * 2 + 1 + offset might equal virtual_size. This used to subtlely be handled by extra capacity
        // padding (and there used to be no assert time checks, which this constant helps with).
        for (i, val) in tmp.iter_mut().enumerate().take(n_l) {
            let sub = T::sub(self.coefficients[i * 2 + 1], self.coefficients[i * 2]);
            let mul = T::mul_with_public(evaluation_points[0], sub);
            *val = T::add(self.coefficients[i * 2], mul);
        }

        // partially evaluate the dim-1 remaining points
        for (l, val) in evaluation_points.iter().enumerate().take(dim).skip(1) {
            n_l = 1 << (dim - l - 1);

            for i in 0..n_l {
                let sub = T::sub(tmp[i * 2 + 1], tmp[i * 2]);
                let mul = T::mul_with_public(*val, sub);
                tmp[i] = T::add(tmp[i * 2], mul);
            }
        }

        let mut result = tmp[0];

        // We handle the "trivial" dimensions which are full of zeros.
        for &point in &evaluation_points[dim..n] {
            result = T::mul_with_public(P::ScalarField::ONE - point, result);
        }

        result
    }

    // Create the degree-(m-1) polynomial T(X) that interpolates the given evaluations.
    pub fn interpolate_from_evals(
        interpolation_points: &[P::ScalarField],
        evaluations: &[T::ArithmeticShare],
        m: usize,
    ) -> Self {
        let mut dest = Self::new(vec![T::ArithmeticShare::default(); m]);
        debug_assert_eq!(m, evaluations.len());
        let mut numerator_polynomial = vec![P::ScalarField::zero(); m + 1];
        {
            let mut scratch_space = interpolation_points.to_vec();

            numerator_polynomial[m] = P::ScalarField::one();
            numerator_polynomial[m - 1] = -scratch_space.iter().copied().sum::<P::ScalarField>();

            let mut temp;
            let mut constant = P::ScalarField::one();
            for i in 0..m - 1 {
                temp = P::ScalarField::zero();
                for j in 0..m - 1 - i {
                    scratch_space[j] = interpolation_points[j]
                        * scratch_space[j + 1..]
                            .iter()
                            .take(m - 1 - i - j)
                            .copied()
                            .sum::<P::ScalarField>();
                    temp += scratch_space[j];
                }
                numerator_polynomial[m - 2 - i] = temp * constant;
                constant *= -P::ScalarField::one();
            }
        }
        let mut roots_and_denominators = vec![P::ScalarField::zero(); 2 * m];
        for i in 0..m {
            roots_and_denominators[i] = -interpolation_points[i];
            roots_and_denominators[m + i] = P::ScalarField::one();
            for j in 0..m {
                if j != i {
                    roots_and_denominators[m + i] *=
                        interpolation_points[i] - interpolation_points[j];
                }
            }
        }
        ark_ff::batch_inversion(roots_and_denominators.as_mut_slice());

        let mut temp_dest = vec![T::ArithmeticShare::default(); m];
        let mut idx_zero = 0;
        let mut interpolation_domain_contains_zero: bool = false;
        if numerator_polynomial[0] == P::ScalarField::zero() {
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
                let multiplier = T::mul_with_public(roots_and_denominators[m + i], evaluations[i]);
                temp_dest[0] = T::mul_with_public(numerator_polynomial[0], multiplier);
                T::mul_assign_with_public(&mut temp_dest[0], z);
                T::add_assign(&mut dest.coefficients[0], temp_dest[0]);
                for j in 1..m {
                    temp_dest[j] = T::sub(
                        T::mul_with_public(numerator_polynomial[j], multiplier),
                        temp_dest[j - 1],
                    );
                    T::mul_assign_with_public(&mut temp_dest[j], z);
                    T::add_assign(&mut dest.coefficients[j], temp_dest[j]);
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
                let multiplier = T::mul_with_public(roots_and_denominators[m + i], evaluations[i]);
                // get x_i^{-1} * f(x_i) * d_{x_i}^{-1} into the "free" term
                temp_dest[1] = T::mul_with_public(numerator_polynomial[1], multiplier);
                T::mul_assign_with_public(&mut temp_dest[1], z);
                // correct the first coefficient as it is now accumulating free terms from
                // f(x_i) d_i^{-1} prod_(X-x_i, x_i != 0) (X-x_i) * 1/(X-x_i)
                T::add_assign(&mut dest.coefficients[1], temp_dest[1]);
                // compute the quotient N(X)/(X-x_i) f(x_i)/d_{x_i} and its contribution to the target coefficients
                for j in 2..m {
                    temp_dest[j] = T::sub(
                        T::mul_with_public(numerator_polynomial[j], multiplier),
                        temp_dest[j - 1],
                    );
                    T::mul_assign_with_public(&mut temp_dest[j], z);
                    T::add_assign(&mut dest.coefficients[j], temp_dest[j]);
                }
            }
            // correct the target coefficients by the contribution from q_{0} = N(X)/X * d_{i_0}^{-1} * f(0)
            for i in 0..m {
                let mut tmp =
                    T::mul_with_public(roots_and_denominators[m + idx_zero], evaluations[idx_zero]);
                T::mul_assign_with_public(&mut tmp, numerator_polynomial[i + 1]);
                T::add_assign(&mut dest.coefficients[i], tmp);
            }
        }

        dest
    }
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Clone for SharedPolynomial<T, P> {
    fn clone(&self) -> Self {
        Self {
            coefficients: self.coefficients.clone(),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default for SharedPolynomial<T, P> {
    fn default() -> Self {
        Self {
            coefficients: Default::default(),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Debug for SharedPolynomial<T, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedPolynomial")
            .field("coefficients", &self.coefficients)
            .finish()
    }
}
impl<T: NoirUltraHonkProver<P>, P: CurveGroup> AsRef<[T::ArithmeticShare]>
    for SharedPolynomial<T, P>
{
    fn as_ref(&self) -> &[T::ArithmeticShare] {
        &self.coefficients
    }
}
impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Index<usize> for SharedPolynomial<T, P> {
    type Output = T::ArithmeticShare;

    fn index(&self, index: usize) -> &Self::Output {
        &self.coefficients[index]
    }
}
impl<T: NoirUltraHonkProver<P>, P: CurveGroup> IndexMut<usize> for SharedPolynomial<T, P> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.coefficients[index]
    }
}
