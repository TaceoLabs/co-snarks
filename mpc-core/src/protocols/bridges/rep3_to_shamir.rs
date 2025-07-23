use crate::protocols::{
    rep3::{Rep3PointShare, Rep3PrimeFieldShare, id::PartyID},
    shamir::{ShamirPointShare, ShamirPrimeFieldShare, ShamirState, network::ShamirNetworkExt},
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use mpc_net::Network;

impl<F: PrimeField> ShamirState<F> {
    fn get_translation_points(id: PartyID) -> (F, F) {
        let id: usize = id.into();
        let eval_point = F::from(id as u64 + 1);
        let poly1_x = if id == 0 { 3 } else { id };
        let poly2_x = if id == 2 { 1 } else { id + 2 };

        let f1 =
            crate::protocols::shamir::interpolate_poly_from_secret_and_zeros(&F::one(), &[poly1_x]);
        let f2 =
            crate::protocols::shamir::interpolate_poly_from_secret_and_zeros(&F::one(), &[poly2_x]);

        let x = crate::protocols::shamir::evaluate_poly(&f1, eval_point);
        let y = crate::protocols::shamir::evaluate_poly(&f2, eval_point);
        (x, y)
    }

    /// Translate a Rep3 prime field share into a 3-party Shamir prime field share, where the underlying sharing polynomial is of degree 1 (i.e., the threshold t = 1).
    pub fn translate_primefield_repshare(
        input: Rep3PrimeFieldShare<F>,
        id: PartyID,
    ) -> ShamirPrimeFieldShare<F> {
        let (x, y) = Self::get_translation_points(id);

        ShamirPrimeFieldShare {
            a: input.a * x + input.b * y,
        }
    }

    /// Translate a Rep3 prime field share vector into a 3-party Shamir prime field share vector, where the underlying sharing polynomial is of degree 1 (i.e., the threshold t = 1).
    pub fn translate_primefield_repshare_vec(
        input: Vec<Rep3PrimeFieldShare<F>>,
        id: PartyID,
    ) -> Vec<ShamirPrimeFieldShare<F>> {
        let (x, y) = Self::get_translation_points(id);

        input
            .into_iter()
            .map(|rep_share| ShamirPrimeFieldShare {
                a: rep_share.a * x + rep_share.b * y,
            })
            .collect::<Vec<_>>()
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
    pub fn translate_point_repshare<C>(input: Rep3PointShare<C>, id: PartyID) -> ShamirPointShare<C>
    where
        C: CurveGroup + std::ops::Mul<F, Output = C> + for<'a> std::ops::Mul<&'a F, Output = C>,
    {
        let (x, y) = Self::get_translation_points(id);

        ShamirPointShare {
            a: input.a * x + input.b * y,
        }
    }
}
