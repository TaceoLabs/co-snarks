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

/// Performs addition between two shared values.
pub fn add<F: PrimeField>(a: FieldShare<F>, b: FieldShare<F>) -> FieldShare<F> {
    a + b
}

pub fn add_assign<F: PrimeField>(shared: &mut FieldShare<F>, b: FieldShare<F>) {
    *shared += b;
}

/// Performs addition between a shared value and a public value.
pub fn add_public<F: PrimeField>(shared: FieldShare<F>, public: F, id: PartyID) -> FieldShare<F> {
    let mut res = shared;
    match id {
        PartyID::ID0 => res.a += public,
        PartyID::ID1 => res.b += public,
        PartyID::ID2 => {}
    }
    res
}

pub fn add_assign_public<F: PrimeField>(shared: &mut FieldShare<F>, public: F, id: PartyID) {
    match id {
        PartyID::ID0 => shared.a += public,
        PartyID::ID1 => shared.b += public,
        PartyID::ID2 => {}
    }
}

/// Performs subtraction between two shared values, returning a - b.
pub fn sub<F: PrimeField>(a: FieldShare<F>, b: FieldShare<F>) -> FieldShare<F> {
    a - b
}

pub fn sub_assign<F: PrimeField>(shared: &mut FieldShare<F>, b: FieldShare<F>) {
    *shared -= b;
}

/// Performs subtraction between a shared value and a public value, returning shared - public.
pub fn sub_shared_by_public<F: PrimeField>(
    shared: FieldShare<F>,
    public: F,
    id: PartyID,
) -> FieldShare<F> {
    add_public(shared, -public, id)
}

/// Performs subtraction between a shared value and a public value, returning public - shared.
pub fn sub_public_by_shared<F: PrimeField>(
    public: F,
    shared: FieldShare<F>,
    id: PartyID,
) -> FieldShare<F> {
    add_public(-shared, public, id)
}

/// Performs multiplication of two shared values.
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

/// Performs multiplication of a shared value and a public value.
pub fn mul_public<F: PrimeField>(shared: FieldShare<F>, public: F) -> FieldShare<F> {
    shared * public
}

/// Performs multiplication of a shared value and a public value.
pub fn mul_assign_public<F: PrimeField>(shared: &mut FieldShare<F>, public: F) {
    *shared *= public;
}

/// Performs element-wise multiplication of two vectors of shared values.
pub async fn mul_vec<F: PrimeField, N: Rep3Network>(
    lhs: &[FieldShare<F>],
    rhs: &[FieldShare<F>],
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

/// Performs division of two shared values, returning a / b.
pub async fn div<F: PrimeField, N: Rep3Network>(
    a: FieldShare<F>,
    b: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    mul(a, inv(b, io_context).await?, io_context).await
}

/// Performs division of a shared value by a public value, returning shared / public.
pub fn div_shared_by_public<F: PrimeField>(
    shared: FieldShare<F>,
    public: F,
) -> eyre::Result<FieldShare<F>> {
    if public.is_zero() {
        eyre::bail!("Cannot invert zero");
    }
    let b_inv = public.inverse().unwrap();
    Ok(mul_public(shared, b_inv))
}

/// Performs division of a public value by a shared value, returning public / shared.
pub async fn div_public_by_shared<F: PrimeField, N: Rep3Network>(
    public: F,
    shared: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    Ok(mul_public(inv(shared, io_context).await?, public))
}

/// Negates a shared value.
pub fn neg<F: PrimeField>(a: FieldShare<F>) -> FieldShare<F> {
    -a
}

/// Computes the inverse of a shared value.
pub async fn inv<F: PrimeField, N: Rep3Network>(
    a: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    let r = FieldShare::rand(io_context);
    let y = mul_open(a, r, io_context).await?;
    if y.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "During execution of inverse in MPC: cannot compute inverse of zero",
        ));
    }
    let y_inv = y
        .inverse()
        .expect("we checked if y is zero. Must be possible to invert.");
    Ok(r * y_inv)
}

/// Performs the opening of a shared value and returns the equivalent public value.
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

async fn rand<F: PrimeField, N: Rep3Network>(io_context: &mut IoContext<N>) -> FieldShare<F> {
    let (a, b) = io_context.random_fes().await;
    FieldShare::new(a, b)
}

pub async fn sqrt<F: PrimeField, N: Rep3Network>(
    share: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    let r_squ = rand(io_context).await;
    let r_inv = rand(io_context).await;

    let rr = mul(r_squ, r_squ, io_context).await?;

    // parallel mul of rr with a and r_squ with r_inv
    let lhs = vec![rr, r_squ];
    let rhs = vec![share, r_inv];
    let mul = mul_vec(&lhs, &rhs, io_context).await?;

    // Open mul
    io_context.network.send_next_many(&mul).await?;
    let c = io_context.network.recv_prev::<Vec<F>>().await?;
    if c.len() != 2 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "During execution of square root in MPC: invalid number of elements received",
        ));
    }
    let y_sq = (mul[0].a + mul[0].b + c[0]).sqrt();
    let y_inv = mul[1].a + mul[1].b + c[1];

    // postprocess the square and inverse
    let y_sq = match y_sq {
        Some(y) => y,
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "During execution of square root in MPC: cannot compute square root",
            ));
        }
    };

    if y_inv.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "During execution of square root in MPC: cannot compute inverse of zero",
        ));
    }
    let y_inv = y_inv.inverse().unwrap();

    let r_squ_inv = r_inv * y_inv;
    let a_sqrt = r_squ_inv * y_sq;

    Ok(a_sqrt)
}

/// Performs a pow operation using a shared value as base and a public value as exponent.
pub async fn pow_public<F: PrimeField, N: Rep3Network>(
    shared: FieldShare<F>,
    public: F,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3PrimeFieldShare<F>> {
    // TODO: are negative exponents allowed in circom?
    let mut res = promote_to_trivial_share(io_context.id, F::one());
    let mut public: BigUint = public.into_bigint().into();
    let mut shared: FieldShare<F> = shared;
    while !public.is_zero() {
        if public.bit(0) {
            public -= 1u64;
            res = mul(res, shared, io_context).await?;
        }
        shared = mul(shared, shared, io_context).await?;
        public >>= 1;
    }
    Ok(mul(res, shared, io_context).await?)
}

pub async fn lt<F: PrimeField, N: Rep3Network>(
    _lhs: FieldShare<F>,
    _rhs: FieldShare<F>,
    _io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    todo!()
}

pub async fn lt_public<F: PrimeField, N: Rep3Network>(
    _lhs: FieldShare<F>,
    _rhs: F,
    _io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    todo!()
}

pub async fn le<F: PrimeField, N: Rep3Network>(
    _lhs: FieldShare<F>,
    _rhs: FieldShare<F>,
    _io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    todo!()
}

pub async fn le_public<F: PrimeField, N: Rep3Network>(
    _lhs: FieldShare<F>,
    _rhs: F,
    _io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    todo!()
}

pub async fn gt<F: PrimeField, N: Rep3Network>(
    _lhs: FieldShare<F>,
    _rhs: FieldShare<F>,
    _io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    todo!()
}

pub async fn gt_public<F: PrimeField, N: Rep3Network>(
    _lhs: FieldShare<F>,
    _rhs: F,
    _io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    todo!()
}

pub async fn ge<F: PrimeField, N: Rep3Network>(
    _lhs: FieldShare<F>,
    _rhs: FieldShare<F>,
    _io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    todo!()
}

pub async fn ge_public<F: PrimeField, N: Rep3Network>(
    _lhs: FieldShare<F>,
    _rhs: F,
    _io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    todo!()
}

//TODO FN REMARK - I think we can skip the bit_inject.
//Circom has dedicated op codes for bool ops so we would know
//for bool_and/bool_or etc that we are a boolean value (and therefore
//bit len 1).
//
//We leave it like that and come back to that later. Maybe it doesn't matter...

/// Checks if two shared values are equal. The result is a shared value that has value 1 if the two shared values are equal and 0 otherwise.
pub async fn eq<F: PrimeField, N: Rep3Network>(
    a: FieldShare<F>,
    b: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    let diff = sub(a, b);
    let bits = conversion::a2b(diff, io_context).await?;
    let is_zero = binary::is_zero(&bits, io_context).await?;
    let res = conversion::bit_inject(&is_zero, io_context).await?;
    Ok(res)
}

/// Checks if a shared value is equal to a public value. The result is a shared value that has value 1 if the two values are equal and 0 otherwise.
pub async fn eq_public<F: PrimeField, N: Rep3Network>(
    shared: FieldShare<F>,
    public: F,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    let public = promote_to_trivial_share(io_context.id, public);
    eq(shared, public, io_context).await
}

/// Same as eq but without using bit_inject on the result. Checks whether two prime field shares are equal and return a binary share of 0 or 1. 1 means they are equal.
pub async fn eq_bit<F: PrimeField, N: Rep3Network>(
    a: FieldShare<F>,
    b: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<BinaryShare<F>> {
    let diff = sub(a, b);
    let bits = conversion::a2b(diff, io_context).await?;
    let is_zero = binary::is_zero(&bits, io_context).await?;
    Ok(is_zero)
}

/// Checks if two shared values are not equal. The result is a shared value that has value 1 if the two values are not equal and 0 otherwise.
pub async fn neq<F: PrimeField, N: Rep3Network>(
    a: FieldShare<F>,
    b: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    let eq = eq(a, b, io_context).await?;
    Ok(sub_public_by_shared(F::one(), eq, io_context.id))
}

/// Checks if a shared value is not equal to a public value. The result is a shared value that has value 1 if the two values are not equal and 0 otherwise.
pub async fn neq_public<F: PrimeField, N: Rep3Network>(
    shared: FieldShare<F>,
    public: F,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    let public = promote_to_trivial_share(io_context.id, public);
    neq(shared, public, io_context).await
}

/// Outputs whether a shared value is zero (true) or not (false).
pub async fn is_zero<F: PrimeField, N: Rep3Network>(
    a: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<bool> {
    let zero_share = FieldShare::default();
    let res = eq(zero_share, a, io_context).await?;
    let x = open(res, io_context).await?;
    Ok(x.is_one())
}
