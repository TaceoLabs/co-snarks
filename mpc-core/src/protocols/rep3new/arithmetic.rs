use ark_ff::PrimeField;
use itertools::{izip, Itertools};
use num_bigint::BigUint;
use num_traits::Zero;
use types::Rep3PrimeFieldShare;

use crate::protocols::rep3new::{id::PartyID, network::Rep3Network};

use super::{binary, conversion, network::IoContext, IoResult, Rep3BigUintShare};

type FieldShare<F> = Rep3PrimeFieldShare<F>;
type BinaryShare<F> = Rep3BigUintShare<F>;

mod ops;
pub(super) mod types;

/// Some computations return a shared value or a public value.
pub enum FieldShareOrPublic<F: PrimeField> {
    Share(FieldShare<F>),
    Public(F),
}

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
pub fn mul_public<F: PrimeField>(shared: FieldShare<F>, public: F) -> FieldShare<F> {
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

pub async fn div<F: PrimeField, N: Rep3Network>(
    a: FieldShare<F>,
    b: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    mul(a, inv(b, io_context).await?, io_context).await
}

pub fn div_by_public<F: PrimeField>(
    shared: FieldShare<F>,
    public: F,
) -> eyre::Result<FieldShare<F>> {
    if public.is_zero() {
        eyre::bail!("Cannot invert zero");
    }
    let b_inv = public.inverse().unwrap();
    Ok(mul_public(shared, b_inv))
}

pub async fn div_public_by_shared<F: PrimeField, N: Rep3Network>(
    public: F,
    shared: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    Ok(mul_public(inv(shared, io_context).await?, public))
}

/// Negates a shared value: \[b\] = -\[a\].
pub fn neg<F: PrimeField>(a: FieldShare<F>) -> FieldShare<F> {
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
    add(a, mul_public(b, c))
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

pub async fn equals<F: PrimeField, N: Rep3Network>(
    lhs: FieldShare<F>,
    rhs: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3PrimeFieldShare<F>> {
    let _is_zero_bit = equals_bit(lhs, rhs, io_context).await?;
    todo!("add bit inject if it is done")
    //Ok(self.bit_inject(is_zero_bit)?)
}

// Checks whether to prime field shares are equal and return a binary share of 0 or 1. 1 means they are equal.
pub async fn equals_bit<F: PrimeField, N: Rep3Network>(
    lhs: FieldShare<F>,
    rhs: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<BinaryShare<F>> {
    let diff = sub(lhs, rhs);
    let bits = conversion::a2b(diff, io_context).await?;
    let is_zero = binary::is_zero(bits, io_context).await?;
    Ok(is_zero)
}

pub async fn sqrt<F: PrimeField, N: Rep3Network>(
    _share: FieldShare<F>,
    _io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    todo!()
}

pub async fn pow_public<F: PrimeField, N: Rep3Network>(
    shared: &FieldShare<F>,
    public: F,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShareOrPublic<F>> {
    if public.is_zero() {
        return Ok(FieldShareOrPublic::Public(F::one()));
    }
    // TODO: are negative exponents allowed in circom?
    let mut res = promote_to_trivial_share(io_context.id, F::one());
    let mut public: BigUint = public.into_bigint().into();
    let mut shared: FieldShare<F> = shared.to_owned();
    while !public.is_zero() {
        if public.bit(0) {
            public -= 1u64;
            res = mul(res, shared, io_context).await?;
        }
        shared = mul(shared, shared, io_context).await?;
        public >>= 1;
    }
    Ok(FieldShareOrPublic::Share(
        mul(res, shared, io_context).await?,
    ))
}

pub async fn lt<F: PrimeField, N: Rep3Network>(
    _lhs: FieldShare<F>,
    _rhs: FieldShare<F>,
    _io_context: &mut IoContext<N>,
) -> IoResult<BinaryShare<F>> {
    todo!()
}

pub async fn lt_public<F: PrimeField, N: Rep3Network>(
    _lhs: FieldShare<F>,
    _rhs: F,
    _io_context: &mut IoContext<N>,
) -> IoResult<BinaryShare<F>> {
    todo!()
}

pub async fn le<F: PrimeField, N: Rep3Network>(
    _lhs: FieldShare<F>,
    _rhs: FieldShare<F>,
    _io_context: &mut IoContext<N>,
) -> IoResult<BinaryShare<F>> {
    todo!()
}

pub async fn le_public<F: PrimeField, N: Rep3Network>(
    _lhs: FieldShare<F>,
    _rhs: F,
    _io_context: &mut IoContext<N>,
) -> IoResult<BinaryShare<F>> {
    todo!()
}

pub async fn gt<F: PrimeField, N: Rep3Network>(
    _lhs: FieldShare<F>,
    _rhs: FieldShare<F>,
    _io_context: &mut IoContext<N>,
) -> IoResult<BinaryShare<F>> {
    todo!()
}

pub async fn gt_public<F: PrimeField, N: Rep3Network>(
    _lhs: FieldShare<F>,
    _rhs: F,
    _io_context: &mut IoContext<N>,
) -> IoResult<BinaryShare<F>> {
    todo!()
}

pub async fn ge<F: PrimeField, N: Rep3Network>(
    _lhs: FieldShare<F>,
    _rhs: FieldShare<F>,
    _io_context: &mut IoContext<N>,
) -> IoResult<BinaryShare<F>> {
    todo!()
}

pub async fn ge_public<F: PrimeField, N: Rep3Network>(
    _lhs: FieldShare<F>,
    _rhs: F,
    _io_context: &mut IoContext<N>,
) -> IoResult<BinaryShare<F>> {
    todo!()
}
