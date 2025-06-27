//! Arithmetic
//!
//! This module contains operations with arithmetic shares

use core::panic;
use num_traits::cast::ToPrimitive;

use ark_ff::PrimeField;
use itertools::{Itertools, izip};
use num_bigint::BigUint;
use num_traits::One;
use num_traits::Zero;

use crate::IoResult;
use crate::protocols::rep3::{PartyID, detail, network::Rep3Network};
use rayon::prelude::*;

use super::{
    Rep3BigUintShare, Rep3PrimeFieldShare, binary, conversion, network::IoContext,
    rngs::Rep3CorrelatedRng,
};

/// Type alias for a [`Rep3PrimeFieldShare`]
pub type FieldShare<F> = Rep3PrimeFieldShare<F>;
/// Type alias for a [`Rep3BigUintShare`]
pub type BinaryShare<F> = Rep3BigUintShare<F>;

/// Performs addition between two shared values.
pub fn add<F: PrimeField>(a: FieldShare<F>, b: FieldShare<F>) -> FieldShare<F> {
    a + b
}

/// Performs addition between two shared values in place
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

/// Performs addition between a shared value and a public value in place.
pub fn add_assign_public<F: PrimeField>(shared: &mut FieldShare<F>, public: F, id: PartyID) {
    match id {
        PartyID::ID0 => shared.a += public,
        PartyID::ID1 => shared.b += public,
        PartyID::ID2 => {}
    }
}

/// Performs element-wise addition of two vectors of shared values in place.
pub fn add_vec_assign<F: PrimeField>(lhs: &mut [FieldShare<F>], rhs: &[FieldShare<F>]) {
    for (a, b) in izip!(lhs.iter_mut(), rhs.iter()) {
        *a += b;
    }
}

/// Performs subtraction between two shared values, returning a - b.
pub fn sub<F: PrimeField>(a: FieldShare<F>, b: FieldShare<F>) -> FieldShare<F> {
    a - b
}

/// Performs subtraction between two shared values in place.
pub fn sub_assign<F: PrimeField>(shared: &mut FieldShare<F>, b: FieldShare<F>) {
    *shared -= b;
}

/// Performs element-wise subtraction of two vectors of shared values in place.
pub fn sub_vec_assign<F: PrimeField>(lhs: &mut [FieldShare<F>], rhs: &[FieldShare<F>]) {
    for (a, b) in izip!(lhs.iter_mut(), rhs.iter()) {
        *a -= *b;
    }
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
pub fn mul<F: PrimeField, N: Rep3Network>(
    a: FieldShare<F>,
    b: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    let local_a = a * b + io_context.rngs.rand.masking_field_element::<F>();
    let local_b = io_context.network.reshare(local_a)?;
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

/// Performs element-wise multiplication of two vectors of shared values. *DOES NOT PERFORM RESHARE*
///
/// # Security
/// If you want to perform additional non-linear operations on the result of this function,
/// you *MUST* call [`reshare_vec`] first. Only then, a reshare is performed.
pub fn local_mul_vec<F: PrimeField>(
    lhs: &[FieldShare<F>],
    rhs: &[FieldShare<F>],
    rngs: &mut Rep3CorrelatedRng,
) -> Vec<F> {
    //squeeze all random elements at once in beginning for determinismus
    let masking_fes = rngs.rand.masking_field_elements_vec::<F>(lhs.len());
    (lhs, rhs, masking_fes)
        .into_par_iter()
        .with_min_len(1024)
        .map(|(lhs, rhs, masking)| lhs * rhs + masking)
        .collect()
}

/// Performs a reshare on all shares in the vector.
pub fn reshare_vec<F: PrimeField, N: Rep3Network>(
    local_a: Vec<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<FieldShare<F>>> {
    let local_b = io_context.network.reshare_many(&local_a)?;
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

/// Performs element-wise multiplication of two vectors of shared values.
///
/// Use this function for small vecs. For large vecs see [`local_mul_vec`] and [`reshare_vec`]
pub fn mul_vec<F: PrimeField, N: Rep3Network>(
    lhs: &[FieldShare<F>],
    rhs: &[FieldShare<F>],
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<FieldShare<F>>> {
    debug_assert_eq!(lhs.len(), rhs.len());
    let local_a = izip!(lhs.iter(), rhs.iter())
        .map(|(lhs, rhs)| lhs * rhs + io_context.rngs.rand.masking_field_element::<F>())
        .collect_vec();
    reshare_vec(local_a, io_context)
}

/// Performs division of two shared values, returning a / b.
pub fn div<F: PrimeField, N: Rep3Network>(
    a: FieldShare<F>,
    b: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    mul(a, inv(b, io_context)?, io_context)
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
pub fn div_public_by_shared<F: PrimeField, N: Rep3Network>(
    public: F,
    shared: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    Ok(mul_public(inv(shared, io_context)?, public))
}

/// Negates a shared value.
pub fn neg<F: PrimeField>(a: FieldShare<F>) -> FieldShare<F> {
    -a
}

/// Computes the inverse of a shared value.
pub fn inv<F: PrimeField, N: Rep3Network>(
    a: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    let r = rand(io_context);
    let y = mul_open(a, r, io_context)?;
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

/// Computes the inverse of a vector of shared field elements
pub fn inv_vec<F: PrimeField, N: Rep3Network>(
    a: &[FieldShare<F>],
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<FieldShare<F>>> {
    let r = (0..a.len()).map(|_| rand(io_context)).collect_vec();
    let y = mul_open_vec(a, &r, io_context)?;
    if y.iter().any(|y| y.is_zero()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "During execution of inverse in MPC: cannot compute inverse of zero",
        ));
    }

    // we can unwrap as we checked that none of the y is zero
    Ok(izip!(r, y).map(|(r, y)| r * y.inverse().unwrap()).collect())
}

/// Performs the opening of a shared value and returns the equivalent public value.
pub fn open<F: PrimeField, N: Rep3Network>(
    a: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<F> {
    let c = io_context.network.reshare(a.b)?;
    Ok(a.a + a.b + c)
}

/// Performs the opening of a shared value and returns the equivalent public value.
pub fn open_bit<F: PrimeField, N: Rep3Network>(
    a: Rep3BigUintShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<BigUint> {
    let c = io_context.network.reshare(a.b.to_owned())?;
    Ok(a.a ^ a.b ^ c)
}

/// Performs the opening of a shared value and returns the equivalent public value.
pub fn open_vec<F: PrimeField, N: Rep3Network>(
    a: &[FieldShare<F>],
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<F>> {
    // TODO think about something better... it is not so bad
    // because we use it exactly once in PLONK where we do it for 4
    // shares..
    let (a, b) = a
        .iter()
        .map(|share| (share.a, share.b))
        .collect::<(Vec<F>, Vec<F>)>();
    let c = io_context.network.reshare_many(&b)?;
    Ok(izip!(a, b, c).map(|(a, b, c)| a + b + c).collect_vec())
}

/// Computes a CMUX: If cond is 1, returns truthy, otherwise returns falsy.
/// Implementations should not overwrite this method.
pub fn cmux<F: PrimeField, N: Rep3Network>(
    cond: FieldShare<F>,
    truthy: FieldShare<F>,
    falsy: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    let b_min_a = sub(truthy, falsy);
    let d = mul(cond, b_min_a, io_context)?;
    Ok(add(falsy, d))
}

/// Computes a CMUX: If cond is 1, returns truthy, otherwise returns falsy.
/// Implementations should not overwrite this method.
pub fn cmux_vec<F: PrimeField, N: Rep3Network>(
    cond: FieldShare<F>,
    truthy: &[FieldShare<F>],
    falsy: &[FieldShare<F>],
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<FieldShare<F>>> {
    debug_assert_eq!(truthy.len(), falsy.len());
    let result_a = truthy
        .iter()
        .zip(falsy.iter())
        .map(|(t, f)| sub(*t, *f) * cond + f.a + io_context.rngs.rand.masking_field_element::<F>())
        .collect_vec();
    reshare_vec(result_a, io_context)
}

/// Convenience method for \[a\] + \[b\] * c
pub fn add_mul_public<F: PrimeField>(a: FieldShare<F>, b: FieldShare<F>, c: F) -> FieldShare<F> {
    add(a, mul_public(b, c))
}

/// Convenience method for \[a\] + \[b\] * \[c\]
pub fn add_mul<F: PrimeField, N: Rep3Network>(
    a: FieldShare<F>,
    b: FieldShare<F>,
    c: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    let mul = mul(c, b, io_context)?;
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
pub fn mul_open<F: PrimeField, N: Rep3Network>(
    a: FieldShare<F>,
    b: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<F> {
    let a = a * b + io_context.rngs.rand.masking_field_element::<F>();
    let (b, c) = io_context.network.broadcast(a)?;
    Ok(a + b + c)
}

/// This function performs a multiplication directly followed by an opening. This safes one round of communication in some MPC protocols compared to calling `mul` and `open` separately.
pub fn mul_open_vec<F: PrimeField, N: Rep3Network>(
    a: &[FieldShare<F>],
    b: &[FieldShare<F>],
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<F>> {
    let mut a = izip!(a, b)
        .map(|(a, b)| a * b + io_context.rngs.rand.masking_field_element::<F>())
        .collect_vec();
    let (b, c) = io_context.network.broadcast_many(&a)?;
    izip!(a.iter_mut(), b, c).for_each(|(a, b, c)| *a += b + c);
    Ok(a)
}

/// Generate a random [`FieldShare`].
pub fn rand<F: PrimeField, N: Rep3Network>(io_context: &mut IoContext<N>) -> FieldShare<F> {
    let (a, b) = io_context.rngs.rand.random_fes();
    FieldShare::new(a, b)
}

/// Computes the square root of a shared value.
pub fn sqrt<F: PrimeField, N: Rep3Network>(
    share: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    let r_squ = rand(io_context);
    let r_inv = rand(io_context);

    let rr = mul(r_squ, r_squ, io_context)?;

    // parallel mul of rr with a and r_squ with r_inv
    let lhs = vec![rr, r_squ];
    let rhs = vec![share, r_inv];
    let mul = mul_vec(&lhs, &rhs, io_context)?;

    // Open mul
    io_context
        .network
        .send_next_many(&mul.iter().map(|s| s.b.to_owned()).collect_vec())?;
    let c = io_context.network.recv_prev_many::<F>()?;
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
pub fn pow_public<F: PrimeField, N: Rep3Network>(
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
            res = mul(res, shared, io_context)?;
        }
        shared = mul(shared, shared, io_context)?;
        public >>= 1;
    }
    mul(res, shared, io_context)
}

/// Returns 1 if lhs < rhs and 0 otherwise. Checks if one shared value is less than another shared value. The result is a shared value that has value 1 if the first shared value is less than the second shared value and 0 otherwise.
pub fn lt<F: PrimeField, N: Rep3Network>(
    lhs: FieldShare<F>,
    rhs: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    // a < b is equivalent to !(a >= b)
    let tmp = ge(lhs, rhs, io_context)?;
    Ok(sub_public_by_shared(F::one(), tmp, io_context.id))
}

/// Returns 1 if lhs < rhs and 0 otherwise. Checks if a shared value is less than the public value. The result is a shared value that has value 1 if the shared value is less than the public value and 0 otherwise.
pub fn lt_public<F: PrimeField, N: Rep3Network>(
    lhs: FieldShare<F>,
    rhs: F,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    // a < b is equivalent to !(a >= b)
    let tmp = ge_public(lhs, rhs, io_context)?;
    Ok(sub_public_by_shared(F::one(), tmp, io_context.id))
}

/// Returns 1 if lhs <= rhs and 0 otherwise. Checks if one shared value is less than or equal to another shared value. The result is a shared value that has value 1 if the first shared value is less than or equal to the second shared value and 0 otherwise.
pub fn le<F: PrimeField, N: Rep3Network>(
    lhs: FieldShare<F>,
    rhs: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    // a <= b is equivalent to b >= a
    ge(rhs, lhs, io_context)
}

/// Returns 1 if lhs <= rhs and 0 otherwise. Checks if a shared value is less than or equal to a public value. The result is a shared value that has value 1 if the shared value is less than or equal to the public value and 0 otherwise.
pub fn le_public<F: PrimeField, N: Rep3Network>(
    lhs: FieldShare<F>,
    rhs: F,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    let res = le_public_bit(lhs, rhs, io_context)?;
    conversion::bit_inject(&res, io_context)
}

/// Same as le_public but without using bit_inject on the result. Returns 1 if lhs <= rhs and 0 otherwise. Checks if a shared value is less than or equal to a public value. The result is a shared value that has value 1 if the shared value is less than or equal to the public value and 0 otherwise.
pub fn le_public_bit<F: PrimeField, N: Rep3Network>(
    lhs: FieldShare<F>,
    rhs: F,
    io_context: &mut IoContext<N>,
) -> IoResult<BinaryShare<F>> {
    detail::unsigned_ge_const_lhs(rhs, lhs, io_context)
}

/// Returns 1 if lhs > rhs and 0 otherwise. Checks if one shared value is greater than another shared value. The result is a shared value that has value 1 if the first shared value is greater than the second shared value and 0 otherwise.
pub fn gt<F: PrimeField, N: Rep3Network>(
    lhs: FieldShare<F>,
    rhs: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    // a > b is equivalent to !(a <= b)
    let tmp = le(lhs, rhs, io_context)?;
    Ok(sub_public_by_shared(F::one(), tmp, io_context.id))
}

/// Returns 1 if lhs > rhs and 0 otherwise. Checks if a shared value is greater than the public value. The result is a shared value that has value 1 if the shared value is greater than the public value and 0 otherwise.
pub fn gt_public<F: PrimeField, N: Rep3Network>(
    lhs: FieldShare<F>,
    rhs: F,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    // a > b is equivalent to !(a <= b)
    let tmp = le_public(lhs, rhs, io_context)?;
    Ok(sub_public_by_shared(F::one(), tmp, io_context.id))
}

/// Returns 1 if lhs >= rhs and 0 otherwise. Checks if one shared value is greater than or equal to another shared value. The result is a shared value that has value 1 if the first shared value is greater than or equal to the second shared value and 0 otherwise.
pub fn ge<F: PrimeField, N: Rep3Network>(
    lhs: FieldShare<F>,
    rhs: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    let res = ge_bit(lhs, rhs, io_context)?;
    conversion::bit_inject(&res, io_context)
}

/// Same as ge but without using bit_inject on the result. Returns 1 if lhs >= rhs and 0 otherwise. Checks if one shared value is greater than or equal to another shared value. The result is a shared value that has value 1 if the first shared value is greater than or equal to the second shared value and 0 otherwise.
pub fn ge_bit<F: PrimeField, N: Rep3Network>(
    lhs: FieldShare<F>,
    rhs: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<BinaryShare<F>> {
    detail::unsigned_ge(lhs, rhs, io_context)
}

/// Returns 1 if lhs >= rhs and 0 otherwise. Checks if a shared value is greater than or equal to a public value. The result is a shared value that has value 1 if the shared value is greater than or equal to the public value and 0 otherwise.
pub fn ge_public<F: PrimeField, N: Rep3Network>(
    lhs: FieldShare<F>,
    rhs: F,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    let res = ge_public_bit(lhs, rhs, io_context)?;
    conversion::bit_inject(&res, io_context)
}

/// Same as ge_public but without using bit_inject on the result. Returns 1 if lhs >= rhs and 0 otherwise. Checks if a shared value is greater than or equal to a public value. The result is a shared value that has value 1 if the shared value is greater than or equal to the public value and 0 otherwise.
pub fn ge_public_bit<F: PrimeField, N: Rep3Network>(
    lhs: FieldShare<F>,
    rhs: F,
    io_context: &mut IoContext<N>,
) -> IoResult<BinaryShare<F>> {
    detail::unsigned_ge_const_rhs(lhs, rhs, io_context)
}

//TODO FN REMARK - I think we can skip the bit_inject.
//Circom has dedicated op codes for bool ops so we would know
//for bool_and/bool_or etc that we are a boolean value (and therefore
//bit len 1).
//
//We leave it like that and come back to that later. Maybe it doesn't matter...

/// Checks if two shared values are equal. The result is a shared value that has value 1 if the two shared values are equal and 0 otherwise.
pub fn eq<F: PrimeField, N: Rep3Network>(
    a: FieldShare<F>,
    b: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    let is_zero = eq_bit(a, b, io_context)?;
    conversion::bit_inject(&is_zero, io_context)
}

/// Checks if a shared value is equal to a public value. The result is a shared value that has value 1 if the two values are equal and 0 otherwise.
pub fn eq_public<F: PrimeField, N: Rep3Network>(
    shared: FieldShare<F>,
    public: F,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    let is_zero = eq_bit_public(shared, public, io_context)?;
    conversion::bit_inject(&is_zero, io_context)
}

/// Same as eq_bit but without using bit_inject on the result. Checks if a shared value is equal to a public value. The result is a shared value that has value 1 if the two values are equal and 0 otherwise.
pub fn eq_bit_public<F: PrimeField, N: Rep3Network>(
    shared: FieldShare<F>,
    public: F,
    io_context: &mut IoContext<N>,
) -> IoResult<BinaryShare<F>> {
    let public = promote_to_trivial_share(io_context.id, public);
    eq_bit(shared, public, io_context)
}

/// Same as eq but without using bit_inject on the result. Checks whether two prime field shares are equal and return a binary share of 0 or 1. 1 means they are equal.
pub fn eq_bit<F: PrimeField, N: Rep3Network>(
    a: FieldShare<F>,
    b: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<BinaryShare<F>> {
    let diff = sub(a, b);
    let bits = conversion::a2b_selector(diff, io_context)?;
    let is_zero = binary::is_zero(&bits, io_context)?;
    Ok(is_zero)
}

/// Checks if two shared values are not equal. The result is a shared value that has value 1 if the two values are not equal and 0 otherwise.
pub fn neq<F: PrimeField, N: Rep3Network>(
    a: FieldShare<F>,
    b: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    let eq = eq(a, b, io_context)?;
    Ok(sub_public_by_shared(F::one(), eq, io_context.id))
}

/// Checks if a shared value is not equal to a public value. The result is a shared value that has value 1 if the two values are not equal and 0 otherwise.
pub fn neq_public<F: PrimeField, N: Rep3Network>(
    shared: FieldShare<F>,
    public: F,
    io_context: &mut IoContext<N>,
) -> IoResult<FieldShare<F>> {
    let public = promote_to_trivial_share(io_context.id, public);
    neq(shared, public, io_context)
}

/// Outputs whether a shared value is zero (true) or not (false).
pub fn is_zero<F: PrimeField, N: Rep3Network>(
    a: FieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<bool> {
    let zero_share = FieldShare::default();
    let res = eq_bit(zero_share, a, io_context)?;
    let x = open_bit(res, io_context)?;
    Ok(x.is_one())
}

/// Computes `shared*2^public`. This is the same as `shared << public`.
///
/// #Panics
/// If public is larger than the bit size of the modulus of the underlying `PrimeField`.
pub fn pow_2_public<F: PrimeField>(shared: FieldShare<F>, public: F) -> FieldShare<F> {
    if public.is_zero() {
        shared
    } else {
        let shift: BigUint = public.into();
        let shift = shift.to_u32().expect("can cast shift operand to u32");
        if shift >= F::MODULUS_BIT_SIZE {
            panic!(
                "Expected left shift to be maximal {}, but was {}",
                F::MODULUS_BIT_SIZE,
                shift
            );
        } else {
            mul_public(shared, F::from(2u64).pow(public.into_bigint()))
        }
    }
}

/// computes XOR using arithmetic operations, only valid when x and y are known to be 0 or 1.
pub(crate) fn arithmetic_xor<F: PrimeField, N: Rep3Network>(
    x: Rep3PrimeFieldShare<F>,
    y: Rep3PrimeFieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3PrimeFieldShare<F>> {
    let mut d = x * y + io_context.rngs.rand.masking_field_element::<F>();
    d.double_in_place();
    let e = x.a + y.a;
    let res_a = e - d;

    let res_b = io_context.network.reshare(res_a)?;
    Ok(FieldShare { a: res_a, b: res_b })
}

pub(crate) fn arithmetic_xor_many<F: PrimeField, N: Rep3Network>(
    x: &[Rep3PrimeFieldShare<F>],
    y: &[Rep3PrimeFieldShare<F>],
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<Rep3PrimeFieldShare<F>>> {
    debug_assert_eq!(x.len(), y.len());

    let mut a = Vec::with_capacity(x.len());
    for (x, y) in x.iter().zip(y.iter()) {
        let mut d = x * y + io_context.rngs.rand.masking_field_element::<F>();
        d.double_in_place();
        let e = x.a + y.a;
        let res_a = e - d;
        a.push(res_a);
    }

    let b = io_context.network.reshare_many(&a)?;
    let res = a
        .into_iter()
        .zip(b)
        .map(|(a, b)| FieldShare { a, b })
        .collect();
    Ok(res)
}

/// Reshares the shared valuse from two parties to one other
/// Assumes seeds are set up correctly already
pub fn reshare_from_2_to_3_parties<F: PrimeField, N: Rep3Network>(
    input: Option<Vec<Rep3PrimeFieldShare<F>>>,
    len: usize,
    recipient: PartyID,
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<Rep3PrimeFieldShare<F>>> {
    if io_context.id == recipient {
        let mut result = Vec::with_capacity(len);
        for _ in 0..len {
            let (a, b) = io_context.random_fes::<F>();
            result.push(Rep3PrimeFieldShare::new(a, b));
        }
        return Ok(result);
    }

    if input.is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "During execution of reshare_from_2_to_3_parties in MPC: input is None",
        ));
    }

    let input = input.unwrap();
    if input.len() != len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "During execution of reshare_from_2_to_3_parties in MPC: input length does not match",
        ));
    }

    let mut rand = Vec::with_capacity(len);
    let mut result = Vec::with_capacity(len);
    if io_context.id == recipient.next_id() {
        for inp in input {
            let beta = inp.a + inp.b;
            let b = io_context.rngs.rand.random_field_element_rng2();
            let r = beta - b;
            rand.push(r);
            result.push(Rep3PrimeFieldShare::new(r, b));
        }
        let comm_id = io_context.id.next_id();
        io_context.network.send_many(comm_id, &rand)?;
        let rcv = io_context.network.recv_many::<F>(comm_id)?;
        for (res, r) in result.iter_mut().zip(rcv) {
            res.a += r;
        }
    } else {
        for inp in input {
            let beta = inp.a;
            let a = io_context.rngs.rand.random_field_element_rng1();
            let r = beta - a;
            rand.push(r);
            result.push(Rep3PrimeFieldShare::new(a, r));
        }
        let comm_id = io_context.id.prev_id();
        io_context.network.send_many(comm_id, &rand)?;
        let rcv = io_context.network.recv_many::<F>(comm_id)?;
        for (res, r) in result.iter_mut().zip(rcv) {
            res.b += r;
        }
    }
    Ok(result)
}
