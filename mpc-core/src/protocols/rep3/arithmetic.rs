//! Arithmetic
//!
//! This module contains operations with arithmetic shares

use core::panic;
use mpc_net::Network;
use num_traits::cast::ToPrimitive;

use ark_ff::PrimeField;
use itertools::{Itertools, izip};
use num_bigint::BigUint;
use num_traits::One;
use num_traits::Zero;

use crate::protocols::rep3::detail;
use rayon::prelude::*;

use super::PartyID;
use super::Rep3State;
use super::network;
use super::{Rep3BigUintShare, Rep3PrimeFieldShare, binary, conversion};

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
pub fn mul<F: PrimeField, N: Network>(
    a: FieldShare<F>,
    b: FieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<FieldShare<F>> {
    let local_a = a * b + state.rngs.rand.masking_field_element::<F>();
    let local_b = network::reshare(net, local_a)?;
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
    state: &mut Rep3State,
) -> Vec<F> {
    //squeeze all random elements at once in beginning for determinismus
    let masking_fes = state.rngs.rand.masking_field_elements_vec::<F>(lhs.len());

    lhs.par_iter()
        .zip_eq(rhs.par_iter())
        .zip_eq(masking_fes.par_iter())
        .with_min_len(1024)
        .map(|((lhs, rhs), masking)| lhs * rhs + masking)
        .collect()
}

/// Performs a reshare on all shares in the vector.
pub fn reshare_vec<F: PrimeField, N: Network>(
    local_a: Vec<F>,
    net: &N,
) -> eyre::Result<Vec<FieldShare<F>>> {
    let local_b = network::reshare_many(net, &local_a)?;
    if local_b.len() != local_a.len() {
        eyre::bail!("During execution of mul_vec in MPC: Invalid number of elements received",);
    }
    Ok(izip!(local_a, local_b)
        .map(|(a, b)| FieldShare::new(a, b))
        .collect())
}

/// Performs element-wise multiplication of two vectors of shared values.
///
/// Use this function for small vecs. For large vecs see [`local_mul_vec`] and [`reshare_vec`]
pub fn mul_vec<F: PrimeField, N: Network>(
    lhs: &[FieldShare<F>],
    rhs: &[FieldShare<F>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<FieldShare<F>>> {
    debug_assert_eq!(lhs.len(), rhs.len());
    let local_a = izip!(lhs.iter(), rhs.iter())
        .map(|(lhs, rhs)| lhs * rhs + state.rngs.rand.masking_field_element::<F>())
        .collect_vec();
    reshare_vec(local_a, net)
}

/// Performs division of two shared values, returning a / b.
pub fn div<F: PrimeField, N: Network>(
    a: FieldShare<F>,
    b: FieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<FieldShare<F>> {
    mul(a, inv(b, net, state)?, net, state)
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
pub fn div_public_by_shared<F: PrimeField, N: Network>(
    public: F,
    shared: FieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<FieldShare<F>> {
    Ok(mul_public(inv(shared, net, state)?, public))
}

/// Negates a shared value.
pub fn neg<F: PrimeField>(a: FieldShare<F>) -> FieldShare<F> {
    -a
}

/// Computes the inverse of a shared value.
pub fn inv<F: PrimeField, N: Network>(
    a: FieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<FieldShare<F>> {
    let r = rand(state);
    let y = mul_open(a, r, net, state)?;
    if y.is_zero() {
        eyre::bail!("During execution of inverse in MPC: cannot compute inverse of zero",);
    }
    let y_inv = y
        .inverse()
        .expect("we checked if y is zero. Must be possible to invert.");
    Ok(r * y_inv)
}

/// Computes the inverse of a vector of shared field elements
pub fn inv_vec<F: PrimeField, N: Network>(
    a: &[FieldShare<F>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<FieldShare<F>>> {
    let r = (0..a.len()).map(|_| rand(state)).collect_vec();
    let y = mul_open_vec(a, &r, net, state)?;
    if y.iter().any(|y| y.is_zero()) {
        eyre::bail!("During execution of inverse in MPC: cannot compute inverse of zero",);
    }

    // we can unwrap as we checked that none of the y is zero
    Ok(izip!(r, y).map(|(r, y)| r * y.inverse().unwrap()).collect())
}

/// Performs the opening of a shared value and returns the equivalent public value.
pub fn open<F: PrimeField, N: Network>(a: FieldShare<F>, net: &N) -> eyre::Result<F> {
    let c = network::reshare(net, a.b)?;
    Ok(a.a + a.b + c)
}

/// Performs the opening of a shared value and returns the equivalent public value.
pub fn open_bit<F: PrimeField, N: Network>(
    a: Rep3BigUintShare<F>,
    net: &N,
) -> eyre::Result<BigUint> {
    let c = network::reshare(net, a.b.to_owned())?;
    Ok(a.a ^ a.b ^ c)
}

/// Performs the opening of a shared value and returns the equivalent public value.
pub fn open_vec<F: PrimeField, N: Network>(a: &[FieldShare<F>], net: &N) -> eyre::Result<Vec<F>> {
    // TODO think about something better... it is not so bad
    // because we use it exactly once in PLONK where we do it for 4
    // shares..
    let (a, b) = a
        .iter()
        .map(|share| (share.a, share.b))
        .collect::<(Vec<F>, Vec<F>)>();
    let c = network::reshare_many(net, &b)?;
    Ok(izip!(a, b, c).map(|(a, b, c)| a + b + c).collect_vec())
}

/// Computes a CMUX: If cond is 1, returns truthy, otherwise returns falsy.
/// Implementations should not overwrite this method.
pub fn cmux<F: PrimeField, N: Network>(
    cond: FieldShare<F>,
    truthy: FieldShare<F>,
    falsy: FieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<FieldShare<F>> {
    let b_min_a = sub(truthy, falsy);
    let d = mul(cond, b_min_a, net, state)?;
    Ok(add(falsy, d))
}

/// Computes a CMUX: If cond is 1, returns truthy, otherwise returns falsy.
/// Implementations should not overwrite this method.
pub fn cmux_vec<F: PrimeField, N: Network>(
    cond: FieldShare<F>,
    truthy: &[FieldShare<F>],
    falsy: &[FieldShare<F>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<FieldShare<F>>> {
    debug_assert_eq!(truthy.len(), falsy.len());
    let result_a = truthy
        .iter()
        .zip(falsy.iter())
        .map(|(t, f)| sub(*t, *f) * cond + f.a + state.rngs.rand.masking_field_element::<F>())
        .collect_vec();
    reshare_vec(result_a, net)
}

/// Convenience method for \[a\] + \[b\] * c
pub fn add_mul_public<F: PrimeField>(a: FieldShare<F>, b: FieldShare<F>, c: F) -> FieldShare<F> {
    add(a, mul_public(b, c))
}

/// Convenience method for \[a\] + \[b\] * \[c\]
pub fn add_mul<F: PrimeField, N: Network>(
    a: FieldShare<F>,
    b: FieldShare<F>,
    c: FieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<FieldShare<F>> {
    let mul = mul(c, b, net, state)?;
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
pub fn mul_open<F: PrimeField, N: Network>(
    a: FieldShare<F>,
    b: FieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<F> {
    let a = a * b + state.rngs.rand.masking_field_element::<F>();
    let (b, c) = network::broadcast(net, a)?;
    Ok(a + b + c)
}

/// This function performs a multiplication directly followed by an opening. This safes one round of communication in some MPC protocols compared to calling `mul` and `open` separately.
pub fn mul_open_vec<F: PrimeField, N: Network>(
    a: &[FieldShare<F>],
    b: &[FieldShare<F>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<F>> {
    let mut a = izip!(a, b)
        .map(|(a, b)| a * b + state.rngs.rand.masking_field_element::<F>())
        .collect_vec();
    let (b, c) = network::broadcast_many(net, &a)?;
    izip!(a.iter_mut(), b, c).for_each(|(a, b, c)| *a += b + c);
    Ok(a)
}

/// Generate a random [`FieldShare`].
pub fn rand<F: PrimeField>(state: &mut Rep3State) -> FieldShare<F> {
    let (a, b) = state.rngs.rand.random_fes();
    FieldShare::new(a, b)
}

/// Computes the square root of a shared value.
pub fn sqrt<F: PrimeField, N: Network>(
    share: FieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<FieldShare<F>> {
    let r_squ = rand(state);
    let r_inv = rand(state);

    let rr = mul(r_squ, r_squ, net, state)?;

    // parallel mul of rr with a and r_squ with r_inv
    let lhs = vec![rr, r_squ];
    let rhs = vec![share, r_inv];
    let mul = mul_vec(&lhs, &rhs, net, state)?;

    // Open mul
    let c = network::reshare_many(net, &mul.iter().map(|s| s.b.to_owned()).collect_vec())?;
    if c.len() != 2 {
        eyre::bail!("During execution of square root in MPC: invalid number of elements received",);
    }
    let y_sq = (mul[0].a + mul[0].b + c[0]).sqrt();
    let y_inv = mul[1].a + mul[1].b + c[1];

    // postprocess the square and inverse
    let y_sq = match y_sq {
        Some(y) => y,
        None => {
            eyre::bail!("During execution of square root in MPC: cannot compute square root",);
        }
    };

    if y_inv.is_zero() {
        eyre::bail!("During execution of square root in MPC: cannot compute inverse of zero",);
    }
    let y_inv = y_inv.inverse().unwrap();

    let r_squ_inv = r_inv * y_inv;
    let a_sqrt = r_squ_inv * y_sq;

    Ok(a_sqrt)
}

/// Performs a pow operation using a shared value as base and a public value as exponent.
pub fn pow_public<F: PrimeField, N: Network>(
    shared: FieldShare<F>,
    public: F,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3PrimeFieldShare<F>> {
    // TODO: are negative exponents allowed in circom?
    let mut res = promote_to_trivial_share(state.id, F::one());
    let mut public: BigUint = public.into_bigint().into();
    let mut shared: FieldShare<F> = shared;
    while !public.is_zero() {
        if public.bit(0) {
            res = mul(res, shared, net, state)?;
        }
        shared = mul(shared, shared, net, state)?;
        public >>= 1;
    }
    mul(res, shared, net, state)
}

/// Returns 1 if lhs < rhs and 0 otherwise. Checks if one shared value is less than another shared value. The result is a shared value that has value 1 if the first shared value is less than the second shared value and 0 otherwise.
pub fn lt<F: PrimeField, N: Network>(
    lhs: FieldShare<F>,
    rhs: FieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<FieldShare<F>> {
    // a < b is equivalent to !(a >= b)
    let tmp = ge(lhs, rhs, net, state)?;
    Ok(sub_public_by_shared(F::one(), tmp, state.id))
}

/// Returns 1 if lhs < rhs and 0 otherwise. Checks if a shared value is less than the public value. The result is a shared value that has value 1 if the shared value is less than the public value and 0 otherwise.
pub fn lt_public<F: PrimeField, N: Network>(
    lhs: FieldShare<F>,
    rhs: F,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<FieldShare<F>> {
    // a < b is equivalent to !(a >= b)
    let tmp = ge_public(lhs, rhs, net, state)?;
    Ok(sub_public_by_shared(F::one(), tmp, state.id))
}

/// Returns 1 if lhs <= rhs and 0 otherwise. Checks if one shared value is less than or equal to another shared value. The result is a shared value that has value 1 if the first shared value is less than or equal to the second shared value and 0 otherwise.
pub fn le<F: PrimeField, N: Network>(
    lhs: FieldShare<F>,
    rhs: FieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<FieldShare<F>> {
    // a <= b is equivalent to b >= a
    ge(rhs, lhs, net, state)
}

/// Returns 1 if lhs <= rhs and 0 otherwise. Checks if a shared value is less than or equal to a public value. The result is a shared value that has value 1 if the shared value is less than or equal to the public value and 0 otherwise.
pub fn le_public<F: PrimeField, N: Network>(
    lhs: FieldShare<F>,
    rhs: F,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<FieldShare<F>> {
    let res = le_public_bit(lhs, rhs, net, state)?;
    conversion::bit_inject(&res, net, state)
}

/// Same as le_public but without using bit_inject on the result. Returns 1 if lhs <= rhs and 0 otherwise. Checks if a shared value is less than or equal to a public value. The result is a shared value that has value 1 if the shared value is less than or equal to the public value and 0 otherwise.
pub fn le_public_bit<F: PrimeField, N: Network>(
    lhs: FieldShare<F>,
    rhs: F,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<BinaryShare<F>> {
    detail::unsigned_ge_const_lhs(rhs, lhs, net, state)
}

/// Returns 1 if lhs > rhs and 0 otherwise. Checks if one shared value is greater than another shared value. The result is a shared value that has value 1 if the first shared value is greater than the second shared value and 0 otherwise.
pub fn gt<F: PrimeField, N: Network>(
    lhs: FieldShare<F>,
    rhs: FieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<FieldShare<F>> {
    // a > b is equivalent to !(a <= b)
    let tmp = le(lhs, rhs, net, state)?;
    Ok(sub_public_by_shared(F::one(), tmp, state.id))
}

/// Returns 1 if lhs > rhs and 0 otherwise. Checks if a shared value is greater than the public value. The result is a shared value that has value 1 if the shared value is greater than the public value and 0 otherwise.
pub fn gt_public<F: PrimeField, N: Network>(
    lhs: FieldShare<F>,
    rhs: F,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<FieldShare<F>> {
    // a > b is equivalent to !(a <= b)
    let tmp = le_public(lhs, rhs, net, state)?;
    Ok(sub_public_by_shared(F::one(), tmp, state.id))
}

/// Returns 1 if lhs >= rhs and 0 otherwise. Checks if one shared value is greater than or equal to another shared value. The result is a shared value that has value 1 if the first shared value is greater than or equal to the second shared value and 0 otherwise.
pub fn ge<F: PrimeField, N: Network>(
    lhs: FieldShare<F>,
    rhs: FieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<FieldShare<F>> {
    let res = ge_bit(lhs, rhs, net, state)?;
    conversion::bit_inject(&res, net, state)
}

/// Same as ge but without using bit_inject on the result. Returns 1 if lhs >= rhs and 0 otherwise. Checks if one shared value is greater than or equal to another shared value. The result is a shared value that has value 1 if the first shared value is greater than or equal to the second shared value and 0 otherwise.
pub fn ge_bit<F: PrimeField, N: Network>(
    lhs: FieldShare<F>,
    rhs: FieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<BinaryShare<F>> {
    detail::unsigned_ge(lhs, rhs, net, state)
}

/// Returns 1 if lhs >= rhs and 0 otherwise. Checks if a shared value is greater than or equal to a public value. The result is a shared value that has value 1 if the shared value is greater than or equal to the public value and 0 otherwise.
pub fn ge_public<F: PrimeField, N: Network>(
    lhs: FieldShare<F>,
    rhs: F,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<FieldShare<F>> {
    let res = ge_public_bit(lhs, rhs, net, state)?;
    conversion::bit_inject(&res, net, state)
}

/// Same as ge_public but without using bit_inject on the result. Returns 1 if lhs >= rhs and 0 otherwise. Checks if a shared value is greater than or equal to a public value. The result is a shared value that has value 1 if the shared value is greater than or equal to the public value and 0 otherwise.
pub fn ge_public_bit<F: PrimeField, N: Network>(
    lhs: FieldShare<F>,
    rhs: F,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<BinaryShare<F>> {
    detail::unsigned_ge_const_rhs(lhs, rhs, net, state)
}

//TODO FN REMARK - I think we can skip the bit_inject.
//Circom has dedicated op codes for bool ops so we would know
//for bool_and/bool_or etc that we are a boolean value (and therefore
//bit len 1).
//
//We leave it like that and come back to that later. Maybe it doesn't matter...

/// Checks if two shared values are equal. The result is a shared value that has value 1 if the two shared values are equal and 0 otherwise.
pub fn eq<F: PrimeField, N: Network>(
    a: FieldShare<F>,
    b: FieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<FieldShare<F>> {
    let is_zero = eq_bit(a, b, net, state)?;
    conversion::bit_inject(&is_zero, net, state)
}

/// Checks if two slices of shared values are equal element-wise.
/// Returns a vector of shared values, where each element is 1 if the corresponding elements are equal and 0 otherwise.
pub fn eq_many<F: PrimeField, N: Network>(
    a: &[FieldShare<F>],
    b: &[FieldShare<F>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<FieldShare<F>>> {
    if a.len() != b.len() {
        eyre::bail!(
            "During execution of eq_many: Invalid number of elements received. Length of a : {} and length of b: {}",
            a.len(),
            b.len()
        );
    }
    let is_zero = eq_bit_many(a, b, net, state)?;
    conversion::bit_inject_many(&is_zero, net, state)
}

/// Checks if a shared value is equal to a public value. The result is a shared value that has value 1 if the two values are equal and 0 otherwise.
pub fn eq_public<F: PrimeField, N: Network>(
    shared: FieldShare<F>,
    public: F,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<FieldShare<F>> {
    let is_zero = eq_bit_public(shared, public, net, state)?;
    conversion::bit_inject(&is_zero, net, state)
}

/// Checks if a slice of shared values is equal to a slice of public values element-wise.
/// Returns a vector of shared values, where each element is 1 if the corresponding elements are equal and 0 otherwise.
pub fn eq_public_many<F: PrimeField, N: Network>(
    shared: &[FieldShare<F>],
    public: &[F],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<FieldShare<F>>> {
    if shared.len() != public.len() {
        eyre::bail!(
            "During execution of eq_public_many: Invalid number of elements received. Length of shared : {} and length of public: {}",
            shared.len(),
            public.len()
        );
    }
    let is_zero = eq_bit_public_many(shared, public, net, state)?;
    conversion::bit_inject_many(&is_zero, net, state)
}

/// Same as eq_bit but without using bit_inject on the result. Checks if a shared value is equal to a public value. The result is a shared value that has value 1 if the two values are equal and 0 otherwise.
pub fn eq_bit_public<F: PrimeField, N: Network>(
    shared: FieldShare<F>,
    public: F,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<BinaryShare<F>> {
    let public = promote_to_trivial_share(state.id, public);
    eq_bit(shared, public, net, state)
}

/// Same as eq_bit_many but without using bit_inject on the result. Checks if a slice of shared values is equal to a slice of public values element-wise.
/// Returns a vector of shared values, where each element is 1 if the corresponding elements are equal and 0 otherwise.
pub fn eq_bit_public_many<F: PrimeField, N: Network>(
    shared: &[FieldShare<F>],
    public: &[F],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<BinaryShare<F>>> {
    if shared.len() != public.len() {
        eyre::bail!(
            "During execution of eq_bit_public_many: Invalid number of elements received. Length of shared : {} and length of public: {}",
            shared.len(),
            public.len()
        );
    }
    let public = public
        .iter()
        .map(|&p| promote_to_trivial_share(state.id, p))
        .collect::<Vec<_>>();
    eq_bit_many(shared, &public, net, state)
}

/// Same as eq but without using bit_inject on the result. Checks whether two prime field shares are equal and return a binary share of 0 or 1. 1 means they are equal.
pub fn eq_bit<F: PrimeField, N: Network>(
    a: FieldShare<F>,
    b: FieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<BinaryShare<F>> {
    let diff = sub(a, b);
    let bits = conversion::a2b_selector(diff, net, state)?;
    let is_zero = binary::is_zero(&bits, net, state)?;
    Ok(is_zero)
}

/// Same as eq_many but without using bit_inject on the result. Checks whether two slice of prime field shares are equal and returns a Vec of binary shares of 0 or 1. 1 means they are equal.
pub fn eq_bit_many<F: PrimeField, N: Network>(
    a: &[FieldShare<F>],
    b: &[FieldShare<F>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<BinaryShare<F>>> {
    if a.len() != b.len() {
        eyre::bail!(
            "During execution of eq_bit_many: Invalid number of elements received. Length of a : {} and length of b: {}",
            a.len(),
            b.len()
        );
    }
    let mut diff = Vec::with_capacity(a.len());
    for (a_, b_) in izip!(a.iter(), b.iter()) {
        diff.push(sub(*a_, *b_));
    }
    let bits = conversion::a2b_many(&diff, net, state)?;
    let is_zero = binary::is_zero_many(bits, net, state)?;
    Ok(is_zero)
}

/// Checks if two shared values are not equal. The result is a shared value that has value 1 if the two values are not equal and 0 otherwise.
pub fn neq<F: PrimeField, N: Network>(
    a: FieldShare<F>,
    b: FieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<FieldShare<F>> {
    let eq = eq(a, b, net, state)?;
    Ok(sub_public_by_shared(F::one(), eq, state.id))
}

/// Checks if a shared value is not equal to a public value. The result is a shared value that has value 1 if the two values are not equal and 0 otherwise.
pub fn neq_public<F: PrimeField, N: Network>(
    shared: FieldShare<F>,
    public: F,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<FieldShare<F>> {
    let public = promote_to_trivial_share(state.id, public);
    neq(shared, public, net, state)
}

/// Outputs whether a shared value is zero (true) or not (false).
pub fn is_zero<F: PrimeField, N: Network>(
    a: FieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<bool> {
    let zero_share = FieldShare::default();
    let res = eq_bit(zero_share, a, net, state)?;
    let x = open_bit(res, net)?;
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
pub(crate) fn arithmetic_xor<F: PrimeField, N: Network>(
    x: Rep3PrimeFieldShare<F>,
    y: Rep3PrimeFieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3PrimeFieldShare<F>> {
    let mut d = x * y + state.rngs.rand.masking_field_element::<F>();
    d.double_in_place();
    let e = x.a + y.a;
    let res_a = e - d;

    let res_b = network::reshare(net, res_a)?;
    Ok(FieldShare { a: res_a, b: res_b })
}

pub(crate) fn arithmetic_xor_many<F: PrimeField, N: Network>(
    x: &[Rep3PrimeFieldShare<F>],
    y: &[Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    debug_assert_eq!(x.len(), y.len());

    let mut a = Vec::with_capacity(x.len());
    for (x, y) in x.iter().zip(y.iter()) {
        let mut d = x * y + state.rngs.rand.masking_field_element::<F>();
        d.double_in_place();
        let e = x.a + y.a;
        let res_a = e - d;
        a.push(res_a);
    }

    let b = network::reshare_many(net, &a)?;
    let res = a
        .into_iter()
        .zip(b)
        .map(|(a, b)| FieldShare { a, b })
        .collect();
    Ok(res)
}

/// Reshares the shared valuse from two parties to one other
/// Assumes seeds are set up correctly already
pub fn reshare_from_2_to_3_parties<F: PrimeField, N: Network>(
    input: Option<Vec<Rep3PrimeFieldShare<F>>>,
    len: usize,
    recipient: PartyID,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    if state.id == recipient {
        let mut result = Vec::with_capacity(len);
        for _ in 0..len {
            let (a, b) = state.rngs.rand.random_fes::<F>();
            result.push(Rep3PrimeFieldShare::new(a, b));
        }
        return Ok(result);
    }

    if input.is_none() {
        eyre::bail!("During execution of reshare_from_2_to_3_parties in MPC: input is None");
    }

    let input = input.unwrap();
    if input.len() != len {
        eyre::bail!(
            "During execution of reshare_from_2_to_3_parties in MPC: input length does not match"
        );
    }

    let mut rand = Vec::with_capacity(len);
    let mut result = Vec::with_capacity(len);
    if state.id == recipient.next() {
        for inp in input {
            let beta = inp.a + inp.b;
            let b = state.rngs.rand.random_field_element_rng2();
            let r = beta - b;
            rand.push(r);
            result.push(Rep3PrimeFieldShare::new(r, b));
        }
        let comm_id = state.id.next();
        let rcv = network::send_and_recv_many::<_, F>(net, comm_id, &rand, comm_id)?;
        for (res, r) in result.iter_mut().zip(rcv) {
            res.a += r;
        }
    } else {
        for inp in input {
            let beta = inp.a;
            let a = state.rngs.rand.random_field_element_rng1();
            let r = beta - a;
            rand.push(r);
            result.push(Rep3PrimeFieldShare::new(a, r));
        }
        let comm_id = state.id.prev();
        let rcv = network::send_and_recv_many::<_, F>(net, comm_id, &rand, comm_id)?;
        for (res, r) in result.iter_mut().zip(rcv) {
            res.b += r;
        }
    }
    Ok(result)
}
