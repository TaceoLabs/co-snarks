use super::{CircomGroth16Prover, IoResult};
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::PrimeField;
use mpc_core::protocols::shamir::{
    arithmetic, core, network::ShamirNetwork, pointshare, ShamirPointShare, ShamirPrimeFieldShare,
    ShamirProtocol,
};
use rayon::prelude::*;

/// A Groth16 dirver unsing shamir secret sharing
///
/// Contains two [`ShamirProtocol`]s, `protocol0` for the main execution and `protocol0` for parts that can run concurrently.
pub struct ShamirGroth16Driver<F: PrimeField, N: ShamirNetwork> {
    protocol0: ShamirProtocol<F, N>,
    protocol1: ShamirProtocol<F, N>,
}

impl<F: PrimeField, N: ShamirNetwork> ShamirGroth16Driver<F, N> {
    /// Create a new [`ShamirGroth16Driver`] with two [`ShamirProtocol`]s
    pub fn new(protocol0: ShamirProtocol<F, N>, protocol1: ShamirProtocol<F, N>) -> Self {
        Self {
            protocol0,
            protocol1,
        }
    }

    /// Get the underlying network
    pub fn get_network(self) -> N {
        self.protocol0.network
    }
}

impl<P: Pairing, N: ShamirNetwork> CircomGroth16Prover<P>
    for ShamirGroth16Driver<P::ScalarField, N>
{
    type ArithmeticShare = ShamirPrimeFieldShare<P::ScalarField>;
    type ArithmeticHalfShare = P::ScalarField;

    type PointShare<C>
        = ShamirPointShare<C>
    where
        C: CurveGroup;

    type PointHalfShare<C>
        = C
    where
        C: CurveGroup;

    type PartyID = usize;

    fn rand(&mut self) -> IoResult<Self::ArithmeticShare> {
        self.protocol0.rand()
    }

    fn get_party_id(&self) -> Self::PartyID {
        self.protocol0.network.get_id()
    }

    fn evaluate_constraint(
        _party_id: Self::PartyID,
        lhs: &[(P::ScalarField, usize)],
        public_inputs: &[P::ScalarField],
        private_witness: &[Self::ArithmeticShare],
    ) -> Self::ArithmeticShare {
        let mut acc = Self::ArithmeticShare::default();
        for (coeff, index) in lhs {
            if index < &public_inputs.len() {
                let val = public_inputs[*index];
                let mul_result = val * coeff;
                arithmetic::add_assign_public(&mut acc, mul_result);
            } else {
                let current_witness = private_witness[*index - public_inputs.len()];
                arithmetic::add_assign(&mut acc, arithmetic::mul_public(current_witness, *coeff));
            }
        }
        acc
    }

    fn promote_to_trivial_shares(
        _id: Self::PartyID,
        public_values: &[P::ScalarField],
    ) -> Vec<Self::ArithmeticShare> {
        arithmetic::promote_to_trivial_shares(public_values)
    }

    fn local_mul_vec(
        &mut self,
        a: Vec<Self::ArithmeticShare>,
        b: Vec<Self::ArithmeticShare>,
    ) -> Vec<P::ScalarField> {
        arithmetic::local_mul_vec(&a, &b)
    }

    fn mul(
        &mut self,
        r: Self::ArithmeticShare,
        s: Self::ArithmeticShare,
    ) -> IoResult<Self::ArithmeticShare> {
        arithmetic::mul(r, s, &mut self.protocol1)
    }

    fn distribute_powers_and_mul_by_const(
        coeffs: &mut [Self::ArithmeticShare],
        roots: &[P::ScalarField],
    ) {
        coeffs
            .par_iter_mut()
            .zip_eq(roots.par_iter())
            .with_min_len(512)
            .for_each(|(c, pow)| {
                arithmetic::mul_assign_public(c, *pow);
            })
    }

    fn msm_public_points<C>(
        points: &[C::Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShare<C>
    where
        C: CurveGroup<ScalarField = P::ScalarField>,
    {
        pointshare::msm_public_points(points, scalars)
    }

    fn scalar_mul_public_point<C>(a: &C, b: Self::ArithmeticShare) -> Self::PointShare<C>
    where
        C: CurveGroup<ScalarField = P::ScalarField>,
    {
        pointshare::scalar_mul_public_point(b, a)
    }

    fn add_assign_points<C: CurveGroup>(a: &mut Self::PointShare<C>, b: &Self::PointShare<C>) {
        pointshare::add_assign(a, b)
    }

    fn add_points_half_share<C: CurveGroup>(a: Self::PointShare<C>, b: &C) -> C {
        a.inner() + b
    }

    fn add_assign_points_public_hs<C: CurveGroup>(
        _id: Self::PartyID,
        a: &mut Self::PointHalfShare<C>,
        b: &C,
    ) {
        *a += b;
    }

    fn open_point<C>(&mut self, a: &Self::PointShare<C>) -> IoResult<C>
    where
        C: CurveGroup<ScalarField = P::ScalarField>,
    {
        pointshare::open_point(a, &mut self.protocol0)
    }

    fn scalar_mul<C>(
        &mut self,
        a: &Self::PointShare<C>,
        b: Self::ArithmeticShare,
    ) -> IoResult<Self::PointShare<C>>
    where
        C: CurveGroup<ScalarField = P::ScalarField>,
    {
        pointshare::scalar_mul(a, b, &mut self.protocol0)
    }

    fn sub_assign_points<C: CurveGroup>(a: &mut Self::PointShare<C>, b: &Self::PointShare<C>) {
        pointshare::sub_assign(a, b);
    }

    fn open_two_half_points(&mut self, a: P::G1, b: P::G2) -> std::io::Result<(P::G1, P::G2)> {
        let s1 = a;
        let s2 = b;
        let (r1, r2) = std::thread::scope(|s| {
            let r1 = s.spawn(|| {
                self.protocol0
                    .network
                    .broadcast_next(s1, self.protocol0.threshold * 2 + 1)
            });
            let r2 = s.spawn(|| {
                self.protocol1
                    .network
                    .broadcast_next(s2, self.protocol0.threshold * 2 + 1)
            });
            (r1.join().expect("can join"), r2.join().expect("can join"))
        });
        let r1 = core::reconstruct_point(&r1?, &self.protocol0.open_lagrange_2t);
        let r2 = core::reconstruct_point(&r2?, &self.protocol0.open_lagrange_2t);
        Ok((r1, r2))
    }

    fn open_point_and_scalar_mul(
        &mut self,
        g_a: &Self::PointHalfShare<P::G1>,
        g1_b: &Self::PointHalfShare<P::G1>,
        r: Self::ArithmeticShare,
    ) -> super::IoResult<(P::G1, Self::PointHalfShare<P::G1>)> {
        std::thread::scope(|s| {
            let opened = s.spawn(|| {
                self.protocol0
                    .network
                    .broadcast_next(*g_a, self.protocol0.threshold * 2 + 1)
            });
            let mul_result = s.spawn(|| {
                self.protocol1
                    .degree_reduce_point(*g1_b)
                    .map(|x| pointshare::scalar_mul_local(&x, r))
            });
            let opened = core::reconstruct_point(
                &opened.join().expect("can join")?,
                &self.protocol0.open_lagrange_2t,
            );
            Ok((opened, mul_result.join().expect("can join")?))
        })
    }

    fn to_half_share(a: Self::ArithmeticShare) -> <P as Pairing>::ScalarField {
        a.inner()
    }

    fn msm_public_points_hs<C>(
        points: &[C::Affine],
        scalars: &[Self::ArithmeticHalfShare],
    ) -> Self::PointHalfShare<C>
    where
        C: CurveGroup<ScalarField = <P as Pairing>::ScalarField>,
    {
        C::msm_unchecked(points, scalars)
    }

    fn scalar_mul_public_point_hs<C>(a: &C, b: Self::ArithmeticHalfShare) -> Self::PointHalfShare<C>
    where
        C: CurveGroup<ScalarField = <P as Pairing>::ScalarField>,
    {
        *a * b
    }
}
