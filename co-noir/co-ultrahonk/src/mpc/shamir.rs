use super::NoirUltraHonkProver;
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_ff::PrimeField;
use itertools::izip;
use mpc_core::protocols::shamir::{
    arithmetic, network::ShamirNetwork, pointshare, poly, ShamirPointShare, ShamirPrimeFieldShare,
    ShamirProtocol,
};
use num_traits::Zero;
use rayon::prelude::*;

/// A UltraHonk dirver unsing shamir secret sharing
///
/// Contains two [`ShamirProtocol`]s, `protocol0` for the main execution and `protocol0` for parts that can run concurrently.
// TODO use protocol1?
pub struct ShamirUltraHonkDriver<F: PrimeField, N: ShamirNetwork> {
    protocol0: ShamirProtocol<F, N>,
    _protocol1: ShamirProtocol<F, N>,
}

impl<F: PrimeField, N: ShamirNetwork> ShamirUltraHonkDriver<F, N> {
    /// Create a new [`ShamirUltraHonkDriver`] with two [`ShamirProtocol`]s
    pub fn new(protocol0: ShamirProtocol<F, N>, protocol1: ShamirProtocol<F, N>) -> Self {
        Self {
            protocol0,
            _protocol1: protocol1,
        }
    }

    pub fn into_network(self) -> N {
        self.protocol0.network
    }
}

impl<P: Pairing, N: ShamirNetwork> NoirUltraHonkProver<P>
    for ShamirUltraHonkDriver<P::ScalarField, N>
{
    type ArithmeticShare = ShamirPrimeFieldShare<P::ScalarField>;
    type PointShare = ShamirPointShare<P::G1>;
    type PartyID = usize;

    fn add_assign_public_half_share(
        share: &mut P::ScalarField,
        public: P::ScalarField,
        _: Self::PartyID,
    ) {
        *share += public
    }

    fn mul_with_public_to_half_share(
        public: P::ScalarField,
        shared: Self::ArithmeticShare,
    ) -> P::ScalarField {
        public * shared.inner()
    }

    fn rand(&mut self) -> std::io::Result<Self::ArithmeticShare> {
        self.protocol0.rand()
    }

    fn get_party_id(&self) -> Self::PartyID {
        self.protocol0.network.get_id()
    }

    fn sub(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        arithmetic::sub(a, b)
    }

    fn sub_assign_many(a: &mut [Self::ArithmeticShare], b: &[Self::ArithmeticShare]) {
        arithmetic::sub_vec_assign(a, b);
    }

    fn add(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        arithmetic::add(a, b)
    }

    fn add_assign(a: &mut Self::ArithmeticShare, b: Self::ArithmeticShare) {
        arithmetic::add_assign(a, b);
    }

    fn add_assign_public(
        a: &mut Self::ArithmeticShare,
        b: <P as Pairing>::ScalarField,
        _id: Self::PartyID,
    ) {
        arithmetic::add_assign_public(a, b);
    }

    fn neg(a: Self::ArithmeticShare) -> Self::ArithmeticShare {
        arithmetic::neg(a)
    }

    fn mul_with_public(
        public: P::ScalarField,
        shared: Self::ArithmeticShare,
    ) -> Self::ArithmeticShare {
        arithmetic::mul_public(shared, public)
    }

    fn mul_assign_with_public(shared: &mut Self::ArithmeticShare, public: P::ScalarField) {
        arithmetic::mul_assign_public(shared, public)
    }

    fn local_mul_vec(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> Vec<P::ScalarField> {
        arithmetic::local_mul_vec(a, b)
    }

    fn reshare(&mut self, a: Vec<P::ScalarField>) -> std::io::Result<Vec<Self::ArithmeticShare>> {
        self.protocol0.degree_reduce_vec(a)
    }

    fn mul_many(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> std::io::Result<Vec<Self::ArithmeticShare>> {
        arithmetic::mul_vec(a, b, &mut self.protocol0)
    }

    fn add_with_public(
        public: P::ScalarField,
        shared: Self::ArithmeticShare,
        _id: Self::PartyID,
    ) -> Self::ArithmeticShare {
        arithmetic::add_public(shared, public)
    }

    fn promote_to_trivial_share(
        _id: Self::PartyID,
        public_value: P::ScalarField,
    ) -> Self::ArithmeticShare {
        arithmetic::promote_to_trivial_share(public_value)
    }

    fn promote_to_trivial_shares(
        id: Self::PartyID,
        public_values: &[P::ScalarField],
    ) -> Vec<Self::ArithmeticShare> {
        public_values
            .par_iter()
            .with_min_len(1024)
            .map(|value| <ShamirUltraHonkDriver<P::ScalarField, N> as NoirUltraHonkProver<P>>::promote_to_trivial_share(id, *value))
            .collect()
    }

    fn open_point(&mut self, a: Self::PointShare) -> std::io::Result<P::G1> {
        pointshare::open_point(&a, &mut self.protocol0)
    }

    fn open_point_many(&mut self, a: &[Self::PointShare]) -> std::io::Result<Vec<P::G1>> {
        pointshare::open_point_many(a, &mut self.protocol0)
    }

    fn open_many(&mut self, a: &[Self::ArithmeticShare]) -> std::io::Result<Vec<P::ScalarField>> {
        arithmetic::open_vec(a, &mut self.protocol0)
    }

    fn mul_open_many(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> std::io::Result<Vec<P::ScalarField>> {
        arithmetic::mul_open_vec(a, b, &mut self.protocol0)
    }

    fn inv_many(
        &mut self,
        a: &[Self::ArithmeticShare],
    ) -> std::io::Result<Vec<Self::ArithmeticShare>> {
        arithmetic::inv_vec(a, &mut self.protocol0)
    }

    fn inv_many_in_place(&mut self, a: &mut [Self::ArithmeticShare]) -> std::io::Result<()> {
        let r = (0..a.len())
            .map(|_| {
                <ShamirUltraHonkDriver<P::ScalarField, N> as NoirUltraHonkProver<P>>::rand(self)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let y: Vec<P::ScalarField> =
            <ShamirUltraHonkDriver<P::ScalarField, N> as NoirUltraHonkProver<P>>::mul_open_many(
                self, a, &r,
            )?;
        if y.iter().any(|y| y.is_zero()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "During execution of inverse in MPC: cannot compute inverse of zero",
            ));
        }

        for (a, r, y) in izip!(a.iter_mut(), r, y) {
            *a = r * y.inverse().unwrap();
        }

        Ok(())
    }

    fn inv_many_in_place_leaking_zeros(
        &mut self,
        a: &mut [Self::ArithmeticShare],
    ) -> std::io::Result<()> {
        let r = (0..a.len())
            .map(|_| {
                <ShamirUltraHonkDriver<P::ScalarField, N> as NoirUltraHonkProver<P>>::rand(self)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let y: Vec<P::ScalarField> =
            <ShamirUltraHonkDriver<P::ScalarField, N> as NoirUltraHonkProver<P>>::mul_open_many(
                self, a, &r,
            )?;

        for (a, r, y) in izip!(a.iter_mut(), r, y) {
            if y.is_zero() {
                *a = Self::ArithmeticShare::default();
            } else {
                *a = r * y.inverse().unwrap();
            }
        }

        Ok(())
    }

    fn msm_public_points(
        points: &[P::G1Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShare {
        pointshare::msm_public_points(points, scalars)
    }

    fn eval_poly(
        coeffs: &[Self::ArithmeticShare],
        point: <P as Pairing>::ScalarField,
    ) -> Self::ArithmeticShare {
        poly::eval_poly(coeffs, point)
    }

    fn fft<D: ark_poly::EvaluationDomain<<P as Pairing>::ScalarField>>(
        data: &[Self::ArithmeticShare],
        domain: &D,
    ) -> Vec<Self::ArithmeticShare> {
        domain.fft(data)
    }

    fn ifft<D: ark_poly::EvaluationDomain<<P as Pairing>::ScalarField>>(
        data: &[Self::ArithmeticShare],
        domain: &D,
    ) -> Vec<Self::ArithmeticShare> {
        domain.ifft(data)
    }

    fn open_point_and_field(
        &mut self,
        a: Self::PointShare,
        b: Self::ArithmeticShare,
    ) -> std::io::Result<(<P as Pairing>::G1, <P as Pairing>::ScalarField)> {
        pointshare::open_point_and_field(&a, &b, &mut self.protocol0)
    }
}
