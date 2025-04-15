//! Pointshare
//!
//! This module contains operations with point shares

use super::{
    network::{IoContext, Rep3Network},
    rngs::Rep3CorrelatedRng,
    PartyID, Rep3PointShare, Rep3PrimeFieldShare,
};
use crate::protocols::rep3::{arithmetic, conversion};
use crate::IoResult;
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, Zero};
use itertools::{izip, Itertools};
use rayon::prelude::*;

/// Type alias for a [`Rep3PrimeFieldShare`]
type FieldShare<C> = Rep3PrimeFieldShare<C>;
/// Type alias for a [`Rep3PointShare`]
type PointShare<C> = Rep3PointShare<C>;

/// Performs addition between two shared values.
pub fn add<C: CurveGroup>(a: &PointShare<C>, b: &PointShare<C>) -> PointShare<C> {
    a + b
}

/// Performs subtraction between two shared values.
pub fn sub<C: CurveGroup>(a: &PointShare<C>, b: &PointShare<C>) -> PointShare<C> {
    a - b
}

/// Performs addition between two shared values in place
pub fn add_assign<C: CurveGroup>(a: &mut PointShare<C>, b: &PointShare<C>) {
    *a += b;
}

/// Performs subtraction between two shared values in place
pub fn sub_assign<C: CurveGroup>(a: &mut PointShare<C>, b: &PointShare<C>) {
    *a -= b;
}

/// Performs addition between a shared value and a public value in place.
pub fn add_assign_public<C: CurveGroup>(a: &mut PointShare<C>, b: &C, id: PartyID) {
    match id {
        PartyID::ID0 => a.a += b,
        PartyID::ID1 => a.b += b,
        PartyID::ID2 => {}
    }
}

/// Performs subtraction between a shared value and a public value in place.
pub fn sub_assign_public<C: CurveGroup>(a: &mut PointShare<C>, b: &C, id: PartyID) {
    match id {
        PartyID::ID0 => a.a -= b,
        PartyID::ID1 => a.b -= b,
        PartyID::ID2 => {}
    }
}

/// Perform scalar multiplication of point * shared scalar
pub fn scalar_mul_public_point<C: CurveGroup>(
    a: &C,
    b: FieldShare<C::ScalarField>,
) -> PointShare<C> {
    PointShare {
        a: a.mul(b.a),
        b: a.mul(b.b),
    }
}

/// Perform scalar multiplication of shared point * scalar
pub fn scalar_mul_public_scalar<C: CurveGroup>(
    a: &PointShare<C>,
    b: C::ScalarField,
) -> PointShare<C> {
    a * b
}

/// Perform local part of scalar multiplication
pub fn scalar_mul_local<C: CurveGroup>(
    a: &PointShare<C>,
    b: FieldShare<C::ScalarField>,
    rng: &mut Rep3CorrelatedRng,
) -> C {
    b * a + rng.rand.masking_ec_element::<C>()
}

/// Perform scalar multiplication
pub fn scalar_mul<C: CurveGroup, N: Rep3Network>(
    a: &PointShare<C>,
    b: FieldShare<C::ScalarField>,
    io_context: &mut IoContext<N>,
) -> IoResult<PointShare<C>> {
    let local_a = b * a + io_context.rngs.rand.masking_ec_element::<C>();
    let local_b = io_context.network.reshare(local_a)?;
    Ok(PointShare {
        a: local_a,
        b: local_b,
    })
}

/// Open the shared point
pub fn open_point<C: CurveGroup, N: Rep3Network>(
    a: &PointShare<C>,
    io_context: &mut IoContext<N>,
) -> IoResult<C> {
    let c = io_context.network.reshare(a.b)?;
    Ok(a.a + a.b + c)
}

/// Open the vector of [`Rep3PointShare`]s
pub fn open_point_many<C: CurveGroup, N: Rep3Network>(
    a: &[PointShare<C>],
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<C>> {
    let bs = a.iter().map(|x| x.b).collect_vec();
    let cs = io_context.network.reshare(bs)?;
    Ok(izip!(a, cs).map(|(x, c)| x.a + x.b + c).collect_vec())
}

/// Opens a shared point and a shared field element together
pub fn open_point_and_field<C: CurveGroup, N: Rep3Network>(
    a: &PointShare<C>,
    b: &FieldShare<C::ScalarField>,
    io_context: &mut IoContext<N>,
) -> IoResult<(C, C::ScalarField)> {
    let c = io_context.network.reshare((a.b, b.b))?;
    Ok((a.a + a.b + c.0, b.a + b.b + c.1))
}

/// Perform msm between `points` and `scalars`
pub fn msm_public_points<C: CurveGroup>(
    points: &[C::Affine],
    scalars: &[FieldShare<C::ScalarField>],
) -> PointShare<C> {
    tracing::trace!("> MSM public points for {} elements", points.len());
    debug_assert_eq!(points.len(), scalars.len());
    let (a_bigints, b_bigints) = scalars
        .into_par_iter()
        .with_min_len(1 << 14)
        .map(|share| (share.a.into_bigint(), share.b.into_bigint()))
        .collect::<(Vec<_>, Vec<_>)>();
    let (res_a, res_b) = rayon::join(
        || C::msm_bigint(points, &a_bigints),
        || C::msm_bigint(points, &b_bigints),
    );
    tracing::trace!("< MSM public points for {} elements", points.len());
    PointShare::new(res_a, res_b)
}

/// Checks whether the shared point is zero/infinity.
/// The strategy is that we split the point into two random shares (as for point_share_to_fieldshares) and check for equal x-coordinates. This works, since the two random shares, with overwhelming probability, will have different x-coordinates if the underyling value is not zero.
/// Returns a replicated boolean share in two separate parts.
pub fn is_zero<C: CurveGroup, N: Rep3Network>(
    x: PointShare<C>,
    io_context: &mut IoContext<N>,
) -> IoResult<(bool, bool)>
where
    C::BaseField: PrimeField,
{
    let (a_x, _, b_x, _) = conversion::point_share_to_fieldshares_pre::<C, N>(x, io_context)?;
    let is_equal = arithmetic::eq_bit(a_x, b_x, io_context)?;
    let a = !is_equal.a.is_zero();
    let b = !is_equal.b.is_zero();
    Ok((a, b))
}
