use super::NoirUltraHonkProver;
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use itertools::izip;
use mpc_core::protocols::rep3::{
    arithmetic,
    id::PartyID,
    network::{IoContext, Rep3Network},
    pointshare, poly, Rep3PointShare, Rep3PrimeFieldShare,
};
use num_traits::Zero;
use rayon::prelude::*;

// TODO use io_context1
pub struct Rep3UltraHonkDriver<N: Rep3Network> {
    io_context0: IoContext<N>,
    _io_context1: IoContext<N>,
}

impl<N: Rep3Network> Rep3UltraHonkDriver<N> {
    /// Create a new [`Rep3UltraHonkDriver`] with two [`IoContext`]s
    pub fn new(io_context0: IoContext<N>, io_context1: IoContext<N>) -> Self {
        Self {
            io_context0,
            _io_context1: io_context1,
        }
    }

    pub fn into_network(self) -> N {
        self.io_context0.network
    }
}

impl<P: Pairing, N: Rep3Network> NoirUltraHonkProver<P> for Rep3UltraHonkDriver<N> {
    type ArithmeticShare = Rep3PrimeFieldShare<P::ScalarField>;
    type PointShare = Rep3PointShare<P::G1>;
    type PartyID = PartyID;

    fn rand(&mut self) -> std::io::Result<Self::ArithmeticShare> {
        Ok(Self::ArithmeticShare::rand(&mut self.io_context0))
    }

    fn get_party_id(&self) -> Self::PartyID {
        self.io_context0.id
    }

    // TODO dont take by ref cause impl Copy, remove self
    fn sub(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        arithmetic::sub(a, b)
    }

    fn add(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        arithmetic::add(a, b)
    }

    fn neg(a: Self::ArithmeticShare) -> Self::ArithmeticShare {
        arithmetic::neg(a)
    }

    fn mul_with_public(
        public: <P as Pairing>::ScalarField,
        shared: Self::ArithmeticShare,
    ) -> Self::ArithmeticShare {
        arithmetic::mul_public(shared, public)
    }

    fn mul_many(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> std::io::Result<Vec<Self::ArithmeticShare>> {
        arithmetic::mul_vec(a, b, &mut self.io_context0)
    }

    fn add_with_public(
        public: <P as Pairing>::ScalarField,
        shared: Self::ArithmeticShare,
        id: PartyID,
    ) -> Self::ArithmeticShare {
        arithmetic::add_public(shared, public, id)
    }

    fn promote_to_trivial_share(
        id: Self::PartyID,
        public_value: <P as Pairing>::ScalarField,
    ) -> Self::ArithmeticShare {
        arithmetic::promote_to_trivial_share(id, public_value)
    }

    fn promote_to_trivial_shares(
        id: Self::PartyID,
        public_values: &[<P as Pairing>::ScalarField],
    ) -> Vec<Self::ArithmeticShare> {
        public_values
            .par_iter()
            .with_min_len(1024)
            .map(|value| Self::ArithmeticShare::promote_from_trivial(value, id))
            .collect()
    }

    fn open_point(&mut self, a: Self::PointShare) -> std::io::Result<<P as Pairing>::G1> {
        pointshare::open_point(&a, &mut self.io_context0)
    }

    fn open_point_many(
        &mut self,
        a: &[Self::PointShare],
    ) -> std::io::Result<Vec<<P as Pairing>::G1>> {
        pointshare::open_point_many(a, &mut self.io_context0)
    }

    fn open_many(
        &mut self,
        a: &[Self::ArithmeticShare],
    ) -> std::io::Result<Vec<<P as Pairing>::ScalarField>> {
        arithmetic::open_vec(a, &mut self.io_context0)
    }

    fn mul_open_many(
        &mut self,
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
    ) -> std::io::Result<Vec<<P as Pairing>::ScalarField>> {
        arithmetic::mul_open_vec(a, b, &mut self.io_context0)
    }

    fn inv_many(
        &mut self,
        a: &[Self::ArithmeticShare],
    ) -> std::io::Result<Vec<Self::ArithmeticShare>> {
        arithmetic::inv_vec(a, &mut self.io_context0)
    }

    fn inv_many_in_place(&mut self, a: &mut [Self::ArithmeticShare]) -> std::io::Result<()> {
        let r = (0..a.len())
            .map(|_| <Rep3UltraHonkDriver<N> as NoirUltraHonkProver<P>>::rand(self))
            .collect::<Result<Vec<_>, _>>()?;
        let y: Vec<P::ScalarField> =
            <Rep3UltraHonkDriver<N> as NoirUltraHonkProver<P>>::mul_open_many(self, a, &r)?;

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
            .map(|_| <Rep3UltraHonkDriver<N> as NoirUltraHonkProver<P>>::rand(self))
            .collect::<Result<Vec<_>, _>>()?;
        let y: Vec<P::ScalarField> =
            <Rep3UltraHonkDriver<N> as NoirUltraHonkProver<P>>::mul_open_many(self, a, &r)?;

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
        points: &[<P as Pairing>::G1Affine],
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
        pointshare::open_point_and_field(&a, &b, &mut self.io_context0)
    }
}
