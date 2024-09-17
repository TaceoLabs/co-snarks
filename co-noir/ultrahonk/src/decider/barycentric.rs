use crate::batch_invert;
use ark_ff::PrimeField;

pub(crate) struct Barycentric {}

impl Barycentric {
    /**
     * Methods for computing arrays of precomputable data used for barycentric extension and evaluation
     */

    // build big_domain, currently the set of x_i in {domain_start, ..., big_domain_end - 1 }
    pub(crate) fn construct_big_domain<F: PrimeField>(
        domain_size: usize,
        num_evals: usize,
    ) -> Vec<F> {
        let big_domain_size = std::cmp::max(domain_size, num_evals);
        let mut res = Vec::with_capacity(big_domain_size);
        for i in 0..big_domain_size {
            res.push(F::from(i as u64));
        }
        res
    }

    // build set of lagrange_denominators d_i = \prod_{j!=i} x_i - x_j
    pub(crate) fn construct_lagrange_denominators<F: PrimeField>(
        domain_size: usize,
        big_domain: &[F],
    ) -> Vec<F> {
        let mut res = Vec::with_capacity(domain_size);

        for (i, r) in res.iter_mut().enumerate() {
            *r = F::one();
            for j in 0..domain_size {
                if j != i {
                    *r *= big_domain[i] - big_domain[j];
                }
            }
        }
        res
    }

    // for each x_k in the big domain, build set of domain size-many denominator inverses
    // 1/(d_i*(x_k - x_j)). will multiply against each of these (rather than to divide by something)
    // for each barycentric evaluation
    pub(crate) fn construct_denominator_inverses<F: PrimeField>(
        num_evals: usize,
        big_domain: &[F],
        lagrange_denominators: &[F],
    ) -> Vec<F> {
        let domain_size = lagrange_denominators.len();
        let big_domain_size = big_domain.len();
        assert_eq!(big_domain_size, std::cmp::max(domain_size, num_evals));

        let res_size = domain_size * num_evals;
        let mut res = Vec::with_capacity(res_size);

        for k in domain_size..num_evals {
            for j in 0..domain_size {
                let inv = lagrange_denominators[j] * (big_domain[k] - big_domain[j]);
                res.push(inv);
            }
        }

        batch_invert(&mut res);
        res
    }

    // get full numerator values
    // full numerator is M(x) = \prod_{i} (x-x_i)
    // these will be zero for i < domain_size, but that's ok because
    // at such entries we will already have the evaluations of the polynomial
    pub(crate) fn construct_full_numerator_values<F: PrimeField>(
        domain_size: usize,
        num_evals: usize,
        big_domain: &[F],
    ) -> Vec<F> {
        let big_domain_size = big_domain.len();
        assert_eq!(big_domain_size, std::cmp::max(domain_size, num_evals));
        let mut res = Vec::with_capacity(num_evals);
        for i in 0..num_evals {
            let mut r = F::one();
            let v_i = F::from(i as u64);
            for el in big_domain.iter().take(domain_size) {
                r *= v_i - el;
            }
            res.push(r);
        }

        res
    }
}
