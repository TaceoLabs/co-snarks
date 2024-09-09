mod ops;
mod types;

use ark_ec::CurveGroup;
use itertools::{izip, Itertools};
pub use types::Rep3PointShare;

use super::{
    id::PartyID,
    network::{IoContext, Rep3Network},
    IoResult, Rep3PrimeFieldShare,
};

type FieldShare<C> = Rep3PrimeFieldShare<C>;
type PointShare<C> = Rep3PointShare<C>;

pub fn add<C: CurveGroup>(a: &PointShare<C>, b: &PointShare<C>) -> PointShare<C> {
    a + b
}

pub fn sub<C: CurveGroup>(a: &PointShare<C>, b: &PointShare<C>) -> PointShare<C> {
    a - b
}

pub fn add_assign<C: CurveGroup>(a: &mut PointShare<C>, b: &PointShare<C>) {
    *a += b;
}

pub fn sub_assign<C: CurveGroup>(a: &mut PointShare<C>, b: &PointShare<C>) {
    *a -= b;
}

pub fn add_assign_public<C: CurveGroup>(a: &mut PointShare<C>, b: &C, id: PartyID) {
    match id {
        PartyID::ID0 => a.a += b,
        PartyID::ID1 => a.b += b,
        PartyID::ID2 => {}
    }
}

pub fn sub_assign_public<C: CurveGroup>(a: &mut PointShare<C>, b: &C, id: PartyID) {
    match id {
        PartyID::ID0 => a.a -= b,
        PartyID::ID1 => a.b -= b,
        PartyID::ID2 => {}
    }
}

pub fn add_assign_public_affine<C: CurveGroup>(a: &mut PointShare<C>, b: &C::Affine, id: PartyID) {
    match id {
        PartyID::ID0 => a.a += b,
        PartyID::ID1 => a.b += b,
        PartyID::ID2 => {}
    }
}

pub fn sub_assign_public_affine<C: CurveGroup>(a: &mut PointShare<C>, b: &C::Affine, id: PartyID) {
    match id {
        PartyID::ID0 => a.a -= b,
        PartyID::ID1 => a.b -= b,
        PartyID::ID2 => {}
    }
}

pub fn scalar_mul_public_point<C: CurveGroup>(
    a: &C,
    b: FieldShare<C::ScalarField>,
) -> PointShare<C> {
    PointShare {
        a: a.mul(b.a),
        b: a.mul(b.b),
    }
}

pub fn scalar_mul_public_scalar<C: CurveGroup>(
    a: &PointShare<C>,
    b: C::ScalarField,
) -> PointShare<C> {
    a * b
}

pub async fn scalar_mul<C: CurveGroup, N: Rep3Network>(
    a: &PointShare<C>,
    b: FieldShare<C::ScalarField>,
    io_context: &mut IoContext<N>,
) -> IoResult<PointShare<C>> {
    let local_a = b * a + io_context.rngs.rand.masking_ec_element::<C>();
    let local_b = io_context.network.reshare(local_a).await?;
    Ok(PointShare {
        a: local_a,
        b: local_b,
    })
}

pub async fn open_point<C: CurveGroup, N: Rep3Network>(
    a: &PointShare<C>,
    io_context: &mut IoContext<N>,
) -> IoResult<C> {
    let c = io_context.network.reshare(a.b).await?;
    Ok(a.a + a.b + c)
}

pub async fn open_point_many<C: CurveGroup, N: Rep3Network>(
    a: &[PointShare<C>],
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<C>> {
    let bs = a.iter().map(|x| x.b).collect_vec();
    let cs = io_context.network.reshare(bs).await?;
    Ok(izip!(a, cs).map(|(x, c)| x.a + x.b + c).collect_vec())
}
