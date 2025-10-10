//! Pointshare
//!
//! This module contains operations with point shares

use ark_ec::CurveGroup;
use ark_ff::{PrimeField, Zero};
use itertools::{Itertools, izip};
use mpc_net::Network;
use rayon::prelude::*;

use super::{
    Rep3PointShare, Rep3PrimeFieldShare, Rep3State, arithmetic, conversion, id::PartyID,
    network::Rep3NetworkExt,
};

mod ops;
pub(super) mod types;

/// Type alias for a [`Rep3PrimeFieldShare`]
pub type FieldShare<C> = Rep3PrimeFieldShare<C>;
/// Type alias for a [`Rep3PointShare`]
pub type PointShare<C> = Rep3PointShare<C>;

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

/// Perform scalar multiplication
pub fn scalar_mul<C: CurveGroup, N: Network>(
    a: &PointShare<C>,
    b: FieldShare<C::ScalarField>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<PointShare<C>> {
    let local_a = b * a + state.rngs.rand.masking_ec_element::<C>();
    let local_b = net.reshare(local_a)?;
    Ok(PointShare {
        a: local_a,
        b: local_b,
    })
}

/// Perform scalar multiplication
pub fn scalar_mul_many<C: CurveGroup, N: Network>(
    a: &[PointShare<C>],
    b: &[FieldShare<C::ScalarField>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<PointShare<C>>> {
    let mut local_a = Vec::with_capacity(a.len());
    for (a, b) in izip!(a, b) {
        local_a.push(*b * a + state.rngs.rand.masking_ec_element::<C>());
    }
    let local_b = net.reshare_many(&local_a)?;
    let result = local_a
        .iter()
        .zip(local_b.iter())
        .map(|(a, b)| PointShare { a: *a, b: *b })
        .collect();
    Ok(result)
}

/// Perform local part of scalar multiplication
pub fn scalar_mul_local<C: CurveGroup>(
    a: &PointShare<C>,
    b: FieldShare<C::ScalarField>,
    state: &mut Rep3State,
) -> C {
    b * a + state.rngs.rand.masking_ec_element::<C>()
}

/// Transforms a public value into a shared value: \[a\] = a.
/// We do it this way since it otherwise causes problems in the point_share_to_fieldshares conversion. (TACEO TODO: fix that)
pub fn promote_to_trivial_share<C: CurveGroup>(id: PartyID, a: &C) -> PointShare<C> {
    if a.is_zero() {
        match id {
            PartyID::ID0 => PointShare::new(C::generator(), C::generator()),
            PartyID::ID1 => PointShare::new(-C::generator() - C::generator(), C::generator()),
            PartyID::ID2 => PointShare::new(C::generator(), -C::generator() - C::generator()),
        }
    } else {
        match id {
            PartyID::ID0 => PointShare::new(*a, C::generator()),
            PartyID::ID1 => PointShare::new(-C::generator(), *a),
            PartyID::ID2 => PointShare::new(C::generator(), -C::generator()),
        }
    }
}

/// Open the shared point
pub fn open_point<C: CurveGroup, N: Network>(a: &PointShare<C>, net: &N) -> eyre::Result<C> {
    let c = net.reshare(a.b)?;
    Ok(a.a + a.b + c)
}

/// Open the shared point
pub fn open_half_point<C: CurveGroup, N: Network>(a: C, net: &N) -> eyre::Result<C> {
    let (b, c) = net.broadcast(a)?;
    Ok(a + b + c)
}

/// Open the vector of [`Rep3PointShare`]s
pub fn open_point_many<C: CurveGroup, N: Network>(
    a: &[PointShare<C>],
    net: &N,
) -> eyre::Result<Vec<C>> {
    let bs = a.iter().map(|x| x.b).collect_vec();
    let cs = net.reshare(bs)?;
    Ok(izip!(a, cs).map(|(x, c)| x.a + x.b + c).collect_vec())
}

/// Opens a vector shared points and a vector of shared field elements together
pub fn open_point_and_field_many<C: CurveGroup, N: Network>(
    a: &[PointShare<C>],
    b: &[FieldShare<C::ScalarField>],
    net: &N,
) -> eyre::Result<(Vec<C>, Vec<C::ScalarField>)> {
    let a_bs = a.iter().map(|x| x.b).collect_vec();
    let b_bs = b.iter().map(|x| x.b).collect_vec();

    let (c1, c2) = net.reshare((a_bs, b_bs))?;
    let mut res_a = Vec::with_capacity(a.len());
    let mut res_b = Vec::with_capacity(b.len());
    for (x, c1) in izip!(a, c1) {
        res_a.push(x.a + x.b + c1);
    }
    for (y, c2) in izip!(b, c2) {
        res_b.push(y.a + y.b + c2);
    }
    debug_assert_eq!(res_a.len(), a.len());
    debug_assert_eq!(res_b.len(), b.len());
    Ok((res_a, res_b))
}

/// Opens a shared point and a shared field element together
pub fn open_point_and_field<C: CurveGroup, N: Network>(
    a: &PointShare<C>,
    b: &FieldShare<C::ScalarField>,
    net: &N,
) -> eyre::Result<(C, C::ScalarField)> {
    let c = net.reshare((a.b, b.b))?;
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
pub fn is_zero<C: CurveGroup, N: Network>(
    x: PointShare<C>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<(bool, bool)>
where
    C::BaseField: PrimeField,
{
    let (a_x, _, b_x, _) = conversion::point_share_to_fieldshares_pre::<C, N>(x, net, state)?;
    let is_equal = arithmetic::eq_bit(a_x, b_x, net, state)?;
    let a = !is_equal.a.is_zero();
    let b = !is_equal.b.is_zero();
    Ok((a, b))
}

/// Checks whether the shared point is zero/infinity.
/// The strategy is that we split the point into two random shares (as for point_share_to_fieldshares) and check for equal x-coordinates. This works, since the two random shares, with overwhelming probability, will have different x-coordinates if the underyling value is not zero.
/// Returns a replicated boolean share in two separate parts.
pub fn is_zero_many<C: CurveGroup, N: Network>(
    x: &[PointShare<C>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<(bool, bool)>>
where
    C::BaseField: PrimeField,
{
    let input_len = x.len();
    let (a_x, _, b_x, _) = conversion::point_share_to_fieldshares_pre_many::<C, N>(x, net, state)?;
    let is_equal = arithmetic::eq_bit_many(&a_x, &b_x, net, state)?;
    if is_equal.len() != input_len {
        eyre::bail!("Expected {input_len} elements, got {}", is_equal.len());
    }
    let mut res = Vec::with_capacity(input_len);
    for is_equal in is_equal {
        res.push((!is_equal.a.is_zero(), !is_equal.b.is_zero()));
    }
    Ok(res)
}
