//! Pointshare
//!
//! This module contains operations with point shares

mod ops;
pub(super) mod types;

use ark_ec::CurveGroup;
use mpc_engine::Network;

use super::{core, network, ShamirPointShare, ShamirPrimeFieldShare, ShamirProtocol, ShamirShare};

type FieldShare<C> = ShamirPrimeFieldShare<C>;
type PointShare<C> = ShamirPointShare<C>;

/// Performs addition between two shares.
pub fn add<C: CurveGroup>(a: &PointShare<C>, b: &PointShare<C>) -> PointShare<C> {
    a + b
}

/// Performs subtraction between two shares.
pub fn sub<C: CurveGroup>(a: &PointShare<C>, b: &PointShare<C>) -> PointShare<C> {
    a - b
}

/// Performs addition between two shares and stores the result in `a`.
pub fn add_assign<C: CurveGroup>(a: &mut PointShare<C>, b: &PointShare<C>) {
    *a += b;
}

/// Performs subtraction between two shares and stores the result in `a`.
pub fn sub_assign<C: CurveGroup>(a: &mut PointShare<C>, b: &PointShare<C>) {
    *a -= b;
}

/// Performs addition between a share and a public value and stores the result in `a`.
pub fn add_assign_public<C: CurveGroup>(a: &mut PointShare<C>, b: &C) {
    a.a += b
}

/// Performs subtraction between a share and a public value and stores the result in `a`.
pub fn sub_assign_public<C: CurveGroup>(a: &mut PointShare<C>, b: &C) {
    a.a -= b
}

/// Performs addition between a share and a public affine value and stores the result in `a`.
pub fn add_assign_public_affine<C: CurveGroup>(
    a: &mut PointShare<C>,
    b: &<C as CurveGroup>::Affine,
) {
    a.a += b
}

/// Performs subtraction between a share and a public affine value and stores the result in `a`.
pub fn sub_assign_public_affine<C: CurveGroup>(
    a: &mut PointShare<C>,
    b: &<C as CurveGroup>::Affine,
) {
    a.a -= b
}

/// Performs multiplication between a field share and a public curve group value and stores the result in `a`.
pub fn scalar_mul_public_point<C: CurveGroup>(
    shared: ShamirPrimeFieldShare<C::ScalarField>,
    public: &C,
) -> PointShare<C> {
    PointShare::<C> {
        a: public.mul(shared.a),
    }
}

/// Performs scalar multiplication between a point share and a public scalar.
pub fn scalar_mul_public_scalar<C: CurveGroup>(
    a: &PointShare<C>,
    b: &C::ScalarField,
) -> PointShare<C> {
    a * b
}

/// Performs scalar multiplication between a point share and a field share.
pub fn scalar_mul<C: CurveGroup, N: Network>(
    a: &PointShare<C>,
    b: ShamirShare<C::ScalarField>,
    net: &N,
    state: &mut ShamirProtocol<C::ScalarField>,
) -> eyre::Result<PointShare<C>> {
    let mul = (b * a).a;
    network::degree_reduce_point(net, state, mul)
}

/// Performs opening of a point share.
pub fn open_half_point<C: CurveGroup, N: Network>(
    a: C,
    net: &N,
    state: &mut ShamirProtocol<C::ScalarField>,
) -> eyre::Result<C> {
    let rcv = network::broadcast_next(net, state.num_parties, state.threshold * 2 + 1, a)?;
    let res = core::reconstruct_point(&rcv, &state.open_lagrange_2t);
    Ok(res)
}

/// Performs opening of a point share.
pub fn open_point<C: CurveGroup, N: Network>(
    a: &PointShare<C>,
    net: &N,
    state: &mut ShamirProtocol<C::ScalarField>,
) -> eyre::Result<C> {
    let rcv = network::broadcast_next(net, state.num_parties, state.threshold + 1, a.a)?;
    let res = core::reconstruct_point(&rcv, &state.open_lagrange_t);
    Ok(res)
}

/// Performs opening of a vector of point shares.
pub fn open_point_many<C: CurveGroup, N: Network>(
    a: &[PointShare<C>],
    net: &N,
    state: &mut ShamirProtocol<C::ScalarField>,
) -> eyre::Result<Vec<C>> {
    let a_a = ShamirPointShare::convert_slice(a);

    let rcv = network::broadcast_next(net, state.num_parties, state.threshold + 1, a_a.to_owned())?;

    let mut transposed = vec![vec![C::zero(); state.threshold + 1]; a.len()];

    for (j, r) in rcv.into_iter().enumerate() {
        for (i, val) in r.into_iter().enumerate() {
            transposed[i][j] = val;
        }
    }

    let res = transposed
        .into_iter()
        .map(|r| core::reconstruct_point(&r, &state.open_lagrange_t))
        .collect();
    Ok(res)
}

/// Opens a shared point and a shared field element together
pub fn open_point_and_field<C: CurveGroup, N: Network>(
    a: &PointShare<C>,
    b: &FieldShare<C::ScalarField>,
    net: &N,
    state: &mut ShamirProtocol<C::ScalarField>,
) -> eyre::Result<(C, C::ScalarField)> {
    let rcv = network::broadcast_next(net, state.num_parties, state.threshold + 1, (a.a, b.a))?;
    let (points, fields): (Vec<_>, Vec<_>) = rcv.into_iter().unzip();
    let res_point = core::reconstruct_point(&points, &state.open_lagrange_t);
    let res_field = core::reconstruct(&fields, &state.open_lagrange_t);
    Ok((res_point, res_field))
}

/// Perfoms MSM between curve points and field shares.
pub fn msm_public_points<C: CurveGroup>(
    points: &[C::Affine],
    scalars: &[FieldShare<C::ScalarField>],
) -> PointShare<C> {
    tracing::trace!("> MSM public points for {} elements", points.len());
    debug_assert_eq!(points.len(), scalars.len());
    let res = C::msm_unchecked(points, &scalars.iter().map(|s| s.a).collect::<Vec<_>>());
    tracing::trace!("< MSM public points for {} elements", points.len());
    PointShare::<C> { a: res }
}
