mod ops;
pub(super) mod types;

use ark_ec::CurveGroup;

use super::{
    core, network::ShamirNetwork, IoResult, ShamirPrimeFieldShare, ShamirProtocol, ShamirShare,
};

pub use types::ShamirPointShare;
type PointShare<C> = types::ShamirPointShare<C>;

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

pub fn add_assign_public<C: CurveGroup>(a: &mut PointShare<C>, b: &C) {
    a.a += b
}

pub fn sub_assign_public<C: CurveGroup>(a: &mut PointShare<C>, b: &C) {
    a.a -= b
}

pub fn add_assign_public_affine<C: CurveGroup>(
    a: &mut PointShare<C>,
    b: &<C as CurveGroup>::Affine,
) {
    a.a += b
}

pub fn sub_assign_public_affine<C: CurveGroup>(
    a: &mut PointShare<C>,
    b: &<C as CurveGroup>::Affine,
) {
    a.a -= b
}

pub fn scalar_mul_public_point<C: CurveGroup>(
    shared: ShamirPrimeFieldShare<C::ScalarField>,
    public: &C,
) -> PointShare<C> {
    PointShare::<C> {
        a: public.mul(shared.a),
    }
}

pub fn scalar_mul_public_scalar<C: CurveGroup>(
    a: &PointShare<C>,
    b: &C::ScalarField,
) -> PointShare<C> {
    a * b
}

pub async fn scalar_mul<C: CurveGroup, N: ShamirNetwork>(
    a: &PointShare<C>,
    b: ShamirShare<C::ScalarField>,
    shamir: &mut ShamirProtocol<C::ScalarField, N>,
) -> IoResult<PointShare<C>> {
    let mul = (b * a).a;
    shamir.degree_reduce_point(mul).await
}

pub async fn open_point<C: CurveGroup, N: ShamirNetwork>(
    a: &PointShare<C>,
    shamir: &mut ShamirProtocol<C::ScalarField, N>,
) -> IoResult<C> {
    let rcv = shamir
        .network
        .broadcast_next(a.a, shamir.threshold + 1)
        .await?;
    let res = core::reconstruct_point(&rcv, &shamir.open_lagrange_t);
    Ok(res)
}

pub async fn open_point_many<C: CurveGroup, N: ShamirNetwork>(
    a: &[PointShare<C>],
    shamir: &mut ShamirProtocol<C::ScalarField, N>,
) -> IoResult<Vec<C>> {
    let a_a = ShamirPointShare::convert_slice(a);

    let rcv = shamir
        .network
        .broadcast_next(a_a.to_owned(), shamir.threshold + 1)
        .await?;

    let mut transposed = vec![vec![C::zero(); shamir.threshold + 1]; a.len()];

    for (j, r) in rcv.into_iter().enumerate() {
        for (i, val) in r.into_iter().enumerate() {
            transposed[i][j] = val;
        }
    }

    let res = transposed
        .into_iter()
        .map(|r| core::reconstruct_point(&r, &shamir.open_lagrange_t))
        .collect();
    Ok(res)
}
