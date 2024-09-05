use ark_ff::PrimeField;
use itertools::{izip, Itertools};
use types::Rep3PrimeFieldShare;

use crate::protocols::rep3new::{id::PartyID, network::Rep3Network};

use super::{network::IoContext, IoResult};

type FieldShare<F> = Rep3PrimeFieldShare<F>;

mod ops;
pub(super) mod types;

pub fn add<F: PrimeField>(a: FieldShare<F>, b: FieldShare<F>) -> FieldShare<F> {
    a + b
}

pub fn add_public<F: PrimeField>(shared: FieldShare<F>, public: F, id: PartyID) -> FieldShare<F> {
    let mut res = shared;
    match id {
        PartyID::ID0 => res.a += public,
        PartyID::ID1 => res.b += public,
        PartyID::ID2 => {}
    }
    res
}

pub fn sub<F: PrimeField>(a: FieldShare<F>, b: FieldShare<F>) -> FieldShare<F> {
    a - b
}

pub fn sub_public<F: PrimeField>(shared: FieldShare<F>, public: F, id: PartyID) -> FieldShare<F> {
    add_public(shared, -public, id)
}

pub async fn mul<F: PrimeField, N: Rep3Network>(
    a: FieldShare<F>,
    b: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    let local_a = a * b + io_context.rngs.rand.masking_field_element::<F>();
    let local_b = io_context.network.reshare(local_a).await?;
    Ok(FieldShare {
        a: local_a,
        b: local_b,
    })
}

/// Multiply a share b by a public value a: c = a * \[b\].
pub fn mul_with_public<F: PrimeField>(shared: FieldShare<F>, public: F) -> FieldShare<F> {
    shared * public
}

pub async fn mul_vec<F: PrimeField, N: Rep3Network>(
    lhs: &Vec<FieldShare<F>>,
    rhs: &Vec<FieldShare<F>>,
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<FieldShare<F>>> {
    debug_assert_eq!(lhs.len(), rhs.len());
    let local_a = izip!(lhs.iter(), rhs.iter())
        .map(|(lhs, rhs)| {
            lhs.a * rhs.a
                + lhs.a * rhs.b
                + lhs.b * rhs.a
                + io_context.rngs.rand.masking_field_element::<F>()
        })
        .collect_vec();
    let local_b = io_context.network.reshare_many(&local_a).await?;
    if local_b.len() != local_a.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "During execution of mul_vec in MPC: Invalid number of elements received",
        ));
    }
    Ok(izip!(local_a, local_b)
        .map(|(a, b)| FieldShare::new(a, b))
        .collect())
}

/// Negates a shared value: \[b\] = -\[a\].
pub fn neg<F: PrimeField>(a: &FieldShare<F>) -> FieldShare<F> {
    -a
}

pub async fn inv<F: PrimeField, N: Rep3Network>(
    a: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    let r = FieldShare::rand(&mut io_context.rngs);
    let y = mul_open(a, r, io_context).await?;
    if y.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "During execution of inverse in MPC: cannot compute inverse of zero",
        ));
    }
    let y_inv = y
        .inverse()
        .expect("we checked if y is zero. Must be possible to inverse.");
    Ok(r * y_inv)
}

pub async fn open<F: PrimeField, N: Rep3Network>(
    a: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<F> {
    let c = io_context.network.reshare(a.b).await?;
    Ok(a.a + a.b + c)
}

/// Computes a CMUX: If cond is 1, returns truthy, otherwise returns falsy.
/// Implementations should not overwrite this method.
pub async fn cmux<F: PrimeField, N: Rep3Network>(
    cond: FieldShare<F>,
    truthy: FieldShare<F>,
    falsy: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    let b_min_a = sub(truthy, falsy);
    let d = mul(cond, b_min_a, io_context).await?;
    Ok(add(falsy, d))
}

/// Convenience method for \[a\] + \[b\] * c
pub fn add_mul_public<F: PrimeField>(a: FieldShare<F>, b: FieldShare<F>, c: F) -> FieldShare<F> {
    add(a, mul_with_public(b, c))
}

/// Convenience method for \[a\] + \[b\] * \[c\]
pub async fn add_mul<F: PrimeField, N: Rep3Network>(
    a: FieldShare<F>,
    b: FieldShare<F>,
    c: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    let mul = mul(c, b, io_context).await?;
    Ok(add(a, mul))
}

/// Transforms a public value into a shared value: \[a\] = a.
pub fn promote_to_trivial_share<F: PrimeField>(id: PartyID, public_value: F) -> FieldShare<F> {
    match id {
        PartyID::ID0 => Rep3PrimeFieldShare::new(public_value, F::zero()),
        PartyID::ID1 => Rep3PrimeFieldShare::new(F::zero(), public_value),
        PartyID::ID2 => Rep3PrimeFieldShare::zero_share(),
    }
}

/// This function performs a multiplication directly followed by an opening. This safes one round of communication in some MPC protocols compared to calling `mul` and `open` separately.
pub async fn mul_open<F: PrimeField, N: Rep3Network>(
    a: FieldShare<F>,
    b: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<F> {
    let a = a * b + io_context.rngs.rand.masking_field_element::<F>();
    let (b, c) = io_context.network.broadcast(a).await?;
    Ok(a + b + c)
}
