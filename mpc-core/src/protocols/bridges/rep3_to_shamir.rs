use crate::protocols::{
    rep3::{Rep3PointShare, Rep3PrimeFieldShare},
    shamir::{ShamirPointShare, ShamirPrimeFieldShare, ShamirState, network::ShamirNetworkExt},
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use mpc_net::Network;

impl<F: PrimeField> ShamirState<F> {
    /// Translate a Rep3 prime field share into a 3-party Shamir prime field share, where the underlying sharing polynomial is of degree 1 (i.e., the threshold t = 1).
    pub fn translate_primefield_repshare<N: Network>(
        &mut self,
        input: Rep3PrimeFieldShare<F>,
        net: &N,
    ) -> eyre::Result<ShamirPrimeFieldShare<F>> {
        // Essentially, a mul function
        let my_lagrange_coeff = self.open_lagrange_2t[0]
            .inverse()
            .expect("lagrange coeff must be invertible");
        let mul = input.a * my_lagrange_coeff;
        net.degree_reduce(self, mul)
    }

    /// Translate a Rep3 prime field share vector into a 3-party Shamir prime field share vector, where the underlying sharing polynomial is of degree 1 (i.e., the threshold t = 1).
    pub fn translate_primefield_repshare_vec<N: Network>(
        &mut self,
        input: Vec<Rep3PrimeFieldShare<F>>,
        net: &N,
    ) -> eyre::Result<Vec<ShamirPrimeFieldShare<F>>> {
        // Essentially, a mul_vec function
        let my_lagrange_coeff = self.open_lagrange_2t[0]
            .inverse()
            .expect("lagrange coeff must be invertible");
        // TODO maybe we do not collect here? we can just provide the iter
        // to the next function?
        let muls = input
            .into_iter()
            .map(|rep_share| rep_share.a * my_lagrange_coeff)
            .collect::<Vec<_>>();
        net.degree_reduce_many(self, muls)
    }

    /// Translate a 3-party additive prime field share into a 3-party Shamir prime field share, where the underlying sharing polynomial is of degree 1 (i.e., the threshold t = 1).
    pub fn translate_primefield_addshare<N: Network>(
        &mut self,
        input: F,
        net: &N,
    ) -> eyre::Result<ShamirPrimeFieldShare<F>> {
        // Essentially, a mul function
        let my_lagrange_coeff = self.open_lagrange_2t[0]
            .inverse()
            .expect("lagrange coeff must be invertible");
        let mul = input * my_lagrange_coeff;
        net.degree_reduce(self, mul)
    }

    /// Translate a 3-party additive prime field share vector into a 3-party Shamir prime field share vector, where the underlying sharing polynomial is of degree 1 (i.e., the threshold t = 1).
    pub fn translate_primefield_addshare_vec<N: Network>(
        &mut self,
        input: Vec<F>,
        net: &N,
    ) -> eyre::Result<Vec<ShamirPrimeFieldShare<F>>> {
        // Essentially, a mul_vec function
        let my_lagrange_coeff = self.open_lagrange_2t[0]
            .inverse()
            .expect("lagrange coeff must be invertible");
        // TODO maybe we do not collect here? we can just provide the iter
        // to the next function?
        let muls = input
            .into_iter()
            .map(|share| share * my_lagrange_coeff)
            .collect::<Vec<_>>();
        net.degree_reduce_many(self, muls)
    }

    /// Translate a Rep3 point share into a 3-party Shamir point share, where the underlying sharing polynomial is of degree 1 (i.e., the threshold t = 1).
    pub fn translate_point_repshare<C, N: Network>(
        &mut self,
        input: Rep3PointShare<C>,
        net: &N,
    ) -> eyre::Result<ShamirPointShare<C>>
    where
        C: CurveGroup + std::ops::Mul<F, Output = C> + for<'a> std::ops::Mul<&'a F, Output = C>,
    {
        // Essentially, a scalar_mul function
        let my_lagrange_coeff = self.open_lagrange_2t[0]
            .inverse()
            .expect("lagrange coeff must be invertible");
        let mul = input.a * my_lagrange_coeff;
        net.degree_reduce_point(self, mul)
    }
}
