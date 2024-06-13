use super::network::RepToShamirNetwork;
use crate::protocols::{
    rep3::{
        fieldshare::Rep3PrimeFieldShareVec, network::Rep3Network, pointshare::Rep3PointShare,
        Rep3PrimeFieldShare, Rep3Protocol,
    },
    shamir::{
        fieldshare::{ShamirPrimeFieldShare, ShamirPrimeFieldShareVec},
        network::ShamirNetwork,
        pointshare::ShamirPointShare,
        ShamirProtocol,
    },
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use eyre::Report;

impl<F: PrimeField, N: Rep3Network> Rep3Protocol<F, N> {
    pub fn get_shamir_protocol<N2: ShamirNetwork>(self) -> Result<ShamirProtocol<F, N2>, Report>
    where
        N: RepToShamirNetwork<N2>,
    {
        let threshold = 1;
        let network = self.network.to_shamir_net();
        ShamirProtocol::new(threshold, network)
    }
}

impl<F: PrimeField, N: ShamirNetwork> ShamirProtocol<F, N> {
    // Essentially, a mul function
    pub fn translate_primefield_repshare(
        &mut self,
        input: Rep3PrimeFieldShare<F>,
    ) -> std::io::Result<ShamirPrimeFieldShare<F>> {
        let my_lagrange_coeff = self.open_lagrange_2t[0]
            .inverse()
            .expect("lagrange coeff must be invertible");
        let mul = input.a * my_lagrange_coeff;
        self.degree_reduce(mul)
    }

    // Essentially, a mul_vec function
    pub fn translate_primefield_repshare_vec(
        &mut self,
        input: Rep3PrimeFieldShareVec<F>,
    ) -> std::io::Result<ShamirPrimeFieldShareVec<F>> {
        let my_lagrange_coeff = self.open_lagrange_2t[0]
            .inverse()
            .expect("lagrange coeff must be invertible");
        let mut muls = input.a;
        for mul in muls.iter_mut() {
            *mul *= my_lagrange_coeff;
        }
        self.degree_reduce_vec(muls)
    }

    // Essentially, a scalar_mul function
    pub fn translate_point_repshare<C>(
        &mut self,
        input: Rep3PointShare<C>,
    ) -> std::io::Result<ShamirPointShare<C>>
    where
        C: CurveGroup + std::ops::Mul<F, Output = C> + for<'a> std::ops::Mul<&'a F, Output = C>,
    {
        let my_lagrange_coeff = self.open_lagrange_2t[0]
            .inverse()
            .expect("lagrange coeff must be invertible");
        let mul = input.a * my_lagrange_coeff;
        self.degree_reduce_point(mul)
    }
}
