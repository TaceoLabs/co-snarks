//! Arithmetic
//!
//! This module contains operations with arithmetic shares

use crate::protocols::rep3::{
    id::PartyID,
    network::{IoContext, Rep3Network},
    rngs::Rep3CorrelatedRng,
    IoResult,
};
use itertools::{izip, Itertools};
use num_traits::{One, Zero};
use rand::{distributions::Standard, prelude::Distribution};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use types::Rep3RingShare;

use super::{
    binary, conversion, detail,
    ring::{bit::Bit, int_ring::IntRing2k, ring_impl::RingElement},
};

pub(super) mod ops;
pub(super) mod types;

/// Type alias for a [`Rep3RingShare`] which is used for both arithmetic and binary shares.
pub type RingShare<F> = Rep3RingShare<F>;

/// Performs addition between two shared values.
pub fn add<T: IntRing2k>(a: RingShare<T>, b: RingShare<T>) -> RingShare<T> {
    a + b
}

/// Performs addition between two shared values in place
pub fn add_assign<T: IntRing2k>(shared: &mut RingShare<T>, b: RingShare<T>) {
    *shared += b;
}

/// Performs addition between a shared value and a public value.
pub fn add_public<T: IntRing2k>(
    shared: RingShare<T>,
    public: RingElement<T>,
    id: PartyID,
) -> RingShare<T> {
    let mut res = shared;
    match id {
        PartyID::ID0 => res.a += public,
        PartyID::ID1 => res.b += public,
        PartyID::ID2 => {}
    }
    res
}

/// Performs addition between a shared value and a public value in place.
pub fn add_assign_public<T: IntRing2k>(
    shared: &mut RingShare<T>,
    public: RingElement<T>,
    id: PartyID,
) {
    match id {
        PartyID::ID0 => shared.a += public,
        PartyID::ID1 => shared.b += public,
        PartyID::ID2 => {}
    }
}

/// Performs element-wise addition of two vectors of shared values in place.
pub fn add_vec_assign<T: IntRing2k>(lhs: &mut [RingShare<T>], rhs: &[RingShare<T>]) {
    for (a, b) in izip!(lhs.iter_mut(), rhs.iter()) {
        *a += b;
    }
}

/// Performs subtraction between two shared values, returning a - b.
pub fn sub<T: IntRing2k>(a: RingShare<T>, b: RingShare<T>) -> RingShare<T> {
    a - b
}

/// Performs subtraction between two shared values in place.
pub fn sub_assign<T: IntRing2k>(shared: &mut RingShare<T>, b: RingShare<T>) {
    *shared -= b;
}

/// Performs element-wise subtraction of two vectors of shared values in place.
pub fn sub_vec_assign<T: IntRing2k>(lhs: &mut [RingShare<T>], rhs: &[RingShare<T>]) {
    for (a, b) in izip!(lhs.iter_mut(), rhs.iter()) {
        *a -= *b;
    }
}

/// Performs subtraction between a shared value and a public value, returning shared - public.
pub fn sub_shared_by_public<T: IntRing2k>(
    shared: RingShare<T>,
    public: RingElement<T>,
    id: PartyID,
) -> RingShare<T> {
    add_public(shared, -public, id)
}

/// Performs subtraction between a shared value and a public value, returning public - shared.
pub fn sub_public_by_shared<T: IntRing2k>(
    public: RingElement<T>,
    shared: RingShare<T>,
    id: PartyID,
) -> RingShare<T> {
    add_public(-shared, public, id)
}

/// Performs multiplication of two shared values.
pub fn mul<T: IntRing2k, N: Rep3Network>(
    a: RingShare<T>,
    b: RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<RingShare<T>>
where
    Standard: Distribution<T>,
{
    let local_a = a * b + io_context.rngs.rand.masking_element::<RingElement<T>>();
    let local_b = io_context.network.reshare(local_a)?;
    Ok(RingShare {
        a: local_a,
        b: local_b,
    })
}

/// Performs multiplication of a shared value and a public value.
pub fn mul_public<T: IntRing2k>(shared: RingShare<T>, public: RingElement<T>) -> RingShare<T> {
    shared * public
}

/// Performs multiplication of a shared value and a public value.
pub fn mul_assign_public<T: IntRing2k>(shared: &mut RingShare<T>, public: RingElement<T>) {
    *shared *= public;
}

/// Performs element-wise multiplication of two vectors of shared values. *DOES NOT PERFORM RESHARE*
///
/// # Security
/// If you want to perform additional non-linear operations on the result of this function,
/// you *MUST* call [`io_mul_vec`] first. Only then, a reshare is performed.
pub fn local_mul_vec<T: IntRing2k>(
    lhs: &[RingShare<T>],
    rhs: &[RingShare<T>],
    rngs: &mut Rep3CorrelatedRng,
) -> Vec<RingElement<T>>
where
    Standard: Distribution<T>,
{
    //squeeze all random elements at once in beginning for determinismus
    let masking_fes = rngs.rand.masking_elements_vec::<RingElement<T>>(lhs.len());

    lhs.par_iter()
        .zip_eq(rhs.par_iter())
        .zip_eq(masking_fes.par_iter())
        .with_min_len(1024)
        .map(|((lhs, rhs), masking)| lhs * rhs + masking)
        .collect()
}

/// Performs a reshare on all shares in the vector.
pub fn io_mul_vec<T: IntRing2k, N: Rep3Network>(
    local_a: Vec<RingElement<T>>,
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<RingShare<T>>> {
    let local_b = io_context.network.reshare_many(&local_a)?;
    if local_b.len() != local_a.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "During execution of mul_vec in MPC: Invalid number of elements received",
        ));
    }
    Ok(izip!(local_a, local_b)
        .map(|(a, b)| RingShare::new_ring(a, b))
        .collect())
}

/// Performs element-wise multiplication of two vectors of shared values.
///
/// Use this function for small vecs. For large vecs see [`local_mul_vec`] and [`io_mul_vec`]
pub fn mul_vec<T: IntRing2k, N: Rep3Network>(
    lhs: &[RingShare<T>],
    rhs: &[RingShare<T>],
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<RingShare<T>>>
where
    Standard: Distribution<T>,
{
    // do not use local_mul_vec here!!! We are , this means we
    // run on a tokio runtime. local_mul_vec uses rayon and starves the
    // runtime. This method is for small multiplications of vecs.
    // If you want a larger one use local_mul_vec and then io_mul_vec.
    debug_assert_eq!(lhs.len(), rhs.len());
    let local_a = izip!(lhs.iter(), rhs.iter())
        .map(|(lhs, rhs)| lhs * rhs + io_context.rngs.rand.masking_element::<RingElement<T>>())
        .collect_vec();
    io_mul_vec(local_a, io_context)
}

/// Negates a shared value.
pub fn neg<T: IntRing2k>(a: RingShare<T>) -> RingShare<T> {
    -a
}

/// Performs the opening of a shared value and returns the equivalent public value.
pub fn open<T: IntRing2k, N: Rep3Network>(
    a: RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<RingElement<T>> {
    let c = io_context.network.reshare(a.b)?;
    Ok(a.a + a.b + c)
}

/// Performs the opening of a shared value and returns the equivalent public value.
pub fn open_bit<T: IntRing2k, N: Rep3Network>(
    a: RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<RingElement<T>> {
    let c = io_context.network.reshare(a.b.to_owned())?;
    Ok(a.a ^ a.b ^ c)
}

/// Performs the opening of a shared value and returns the equivalent public value.
pub fn open_vec<T: IntRing2k, N: Rep3Network>(
    a: &[RingShare<T>],
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<RingElement<T>>> {
    // TODO think about something better... it is not so bad
    // because we use it exactly once in PLONK where we do it for 4
    // shares..
    let (a, b) = a
        .iter()
        .map(|share| (share.a, share.b))
        .collect::<(Vec<RingElement<T>>, Vec<RingElement<T>>)>();
    let c = io_context.network.reshare_many(&b)?;
    Ok(izip!(a, b, c).map(|(a, b, c)| a + b + c).collect_vec())
}

/// Computes a CMUX: If cond is 1, returns truthy, otherwise returns falsy.
/// Implementations should not overwrite this method.
pub fn cmux<T: IntRing2k, N: Rep3Network>(
    cond: RingShare<T>,
    truthy: RingShare<T>,
    falsy: RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<RingShare<T>>
where
    Standard: Distribution<T>,
{
    let b_min_a = sub(truthy, falsy);
    let d = mul(cond, b_min_a, io_context)?;
    Ok(add(falsy, d))
}

/// Convenience method for \[a\] + \[b\] * c
pub fn add_mul_public<T: IntRing2k>(
    a: RingShare<T>,
    b: RingShare<T>,
    c: RingElement<T>,
) -> RingShare<T> {
    add(a, mul_public(b, c))
}

/// Convenience method for \[a\] + \[b\] * \[c\]
pub fn add_mul<T: IntRing2k, N: Rep3Network>(
    a: RingShare<T>,
    b: RingShare<T>,
    c: RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<RingShare<T>>
where
    Standard: Distribution<T>,
{
    let mul = mul(c, b, io_context)?;
    Ok(add(a, mul))
}

/// Transforms a public value into a shared value: \[a\] = a.
pub fn promote_to_trivial_share<T: IntRing2k>(
    id: PartyID,
    public_value: RingElement<T>,
) -> RingShare<T> {
    match id {
        PartyID::ID0 => Rep3RingShare::new_ring(public_value, RingElement::zero()),
        PartyID::ID1 => Rep3RingShare::new_ring(RingElement::zero(), public_value),
        PartyID::ID2 => Rep3RingShare::zero_share(),
    }
}

/// This function performs a multiplication directly followed by an opening. This safes one round of communication in some MPC protocols compared to calling `mul` and `open` separately.
pub fn mul_open<T: IntRing2k, N: Rep3Network>(
    a: RingShare<T>,
    b: RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<RingElement<T>>
where
    Standard: Distribution<T>,
{
    let a = a * b + io_context.rngs.rand.masking_element::<RingElement<T>>();
    let (b, c) = io_context.network.broadcast(a)?;
    Ok(a + b + c)
}

/// This function performs a multiplication directly followed by an opening. This safes one round of communication in some MPC protocols compared to calling `mul` and `open` separately.
pub fn mul_open_vec<T: IntRing2k, N: Rep3Network>(
    a: &[RingShare<T>],
    b: &[RingShare<T>],
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<RingElement<T>>>
where
    Standard: Distribution<T>,
{
    let mut a = izip!(a, b)
        .map(|(a, b)| a * b + io_context.rngs.rand.masking_element::<RingElement<T>>())
        .collect_vec();
    let (b, c) = io_context.network.broadcast_many(&a)?;
    izip!(a.iter_mut(), b, c).for_each(|(a, b, c)| *a += b + c);
    Ok(a)
}

/// Generate a random [`RingShare`].
pub fn rand<T: IntRing2k, N: Rep3Network>(io_context: &mut IoContext<N>) -> RingShare<T>
where
    Standard: Distribution<T>,
{
    let (a, b) = io_context.rngs.rand.random_elements();
    RingShare::new(a, b)
}

/// Performs a pow operation using a shared value as base and a public value as exponent.
pub fn pow_public<T: IntRing2k, N: Rep3Network>(
    shared: RingShare<T>,
    mut public: RingElement<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<RingShare<T>>
where
    Standard: Distribution<T>,
{
    // TODO: are negative exponents allowed in circom?
    let mut res = promote_to_trivial_share(io_context.id, RingElement::one());
    let mut shared: RingShare<T> = shared;
    while !public.is_zero() {
        if public.get_bit(0) == RingElement::one() {
            public -= RingElement::one();
            res = mul(res, shared, io_context)?;
        }
        shared = mul(shared, shared, io_context)?;
        public >>= 1;
    }
    mul(res, shared, io_context)
}

/// Returns 1 if lhs < rhs and 0 otherwise. Checks if one shared value is less than another shared value. The result is a shared value that has value 1 if the first shared value is less than the second shared value and 0 otherwise.
pub fn lt<T: IntRing2k, N: Rep3Network>(
    lhs: RingShare<T>,
    rhs: RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<RingShare<Bit>>
where
    Standard: Distribution<T>,
{
    // a < b is equivalent to !(a >= b)
    let tmp = ge(lhs, rhs, io_context)?;
    Ok(sub_public_by_shared(RingElement::one(), tmp, io_context.id))
}

/// Returns 1 if lhs < rhs and 0 otherwise. Checks if a shared value is less than the public value. The result is a shared value that has value 1 if the shared value is less than the public value and 0 otherwise.
pub fn lt_public<T: IntRing2k, N: Rep3Network>(
    lhs: RingShare<T>,
    rhs: RingElement<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<RingShare<Bit>>
where
    Standard: Distribution<T>,
{
    // a < b is equivalent to !(a >= b)
    let tmp = ge_public(lhs, rhs, io_context)?;
    Ok(!tmp)
}

/// Returns 1 if lhs <= rhs and 0 otherwise. Checks if one shared value is less than or equal to another shared value. The result is a shared value that has value 1 if the first shared value is less than or equal to the second shared value and 0 otherwise.
pub fn le<T: IntRing2k, N: Rep3Network>(
    lhs: RingShare<T>,
    rhs: RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<RingShare<Bit>>
where
    Standard: Distribution<T>,
{
    // a <= b is equivalent to b >= a
    ge(rhs, lhs, io_context)
}

/// Returns 1 if lhs <= rhs and 0 otherwise. Checks if a shared value is less than or equal to a public value. The result is a shared value that has value 1 if the shared value is less than or equal to the public value and 0 otherwise.
pub fn le_public<T: IntRing2k, N: Rep3Network>(
    lhs: RingShare<T>,
    rhs: RingElement<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<RingShare<Bit>>
where
    Standard: Distribution<T>,
{
    detail::unsigned_ge_const_lhs(rhs, lhs, io_context)
}

/// Returns 1 if lhs > rhs and 0 otherwise. Checks if one shared value is greater than another shared value. The result is a shared value that has value 1 if the first shared value is greater than the second shared value and 0 otherwise.
pub fn gt<T: IntRing2k, N: Rep3Network>(
    lhs: RingShare<T>,
    rhs: RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<RingShare<Bit>>
where
    Standard: Distribution<T>,
{
    // a > b is equivalent to !(a <= b)
    let tmp = le(lhs, rhs, io_context)?;
    Ok(!tmp)
}

/// Returns 1 if lhs > rhs and 0 otherwise. Checks if a shared value is greater than the public value. The result is a shared value that has value 1 if the shared value is greater than the public value and 0 otherwise.
pub fn gt_public<T: IntRing2k, N: Rep3Network>(
    lhs: RingShare<T>,
    rhs: RingElement<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<RingShare<Bit>>
where
    Standard: Distribution<T>,
{
    // a > b is equivalent to !(a <= b)
    let tmp = le_public(lhs, rhs, io_context)?;
    Ok(!tmp)
}

/// Returns 1 if lhs >= rhs and 0 otherwise. Checks if one shared value is greater than or equal to another shared value. The result is a shared value that has value 1 if the first shared value is greater than or equal to the second shared value and 0 otherwise.
pub fn ge<T: IntRing2k, N: Rep3Network>(
    lhs: RingShare<T>,
    rhs: RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<RingShare<Bit>>
where
    Standard: Distribution<T>,
{
    detail::unsigned_ge(lhs, rhs, io_context)
}

/// Returns 1 if lhs >= rhs and 0 otherwise. Checks if a shared value is greater than or equal to a public value. The result is a shared value that has value 1 if the shared value is greater than or equal to the public value and 0 otherwise.
pub fn ge_public<T: IntRing2k, N: Rep3Network>(
    lhs: RingShare<T>,
    rhs: RingElement<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<RingShare<Bit>>
where
    Standard: Distribution<T>,
{
    detail::unsigned_ge_const_rhs(lhs, rhs, io_context)
}

/// Checks if a shared value is equal to a public value. The result is a shared value that has value 1 if the two values are equal and 0 otherwise.
pub fn eq_public<T: IntRing2k, N: Rep3Network>(
    shared: RingShare<T>,
    public: RingElement<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<RingShare<Bit>>
where
    Standard: Distribution<T>,
{
    let public = promote_to_trivial_share(io_context.id, public);
    eq(shared, public, io_context)
}

/// Checks if two shared values are equal. The result is a shared value that has value 1 if the two shared values are equal and 0 otherwise.
pub fn eq<T: IntRing2k, N: Rep3Network>(
    a: RingShare<T>,
    b: RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<RingShare<Bit>>
where
    Standard: Distribution<T>,
{
    let diff = sub(a, b);
    let bits = conversion::a2b_selector(diff, io_context)?;
    let is_zero = binary::is_zero(&bits, io_context)?;
    Ok(is_zero)
}

/// Checks if two shared values are not equal. The result is a shared value that has value 1 if the two values are not equal and 0 otherwise.
pub fn neq<T: IntRing2k, N: Rep3Network>(
    a: RingShare<T>,
    b: RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<RingShare<Bit>>
where
    Standard: Distribution<T>,
{
    let eq = eq(a, b, io_context)?;
    Ok(!eq)
}

/// Checks if a shared value is not equal to a public value. The result is a shared value that has value 1 if the two values are not equal and 0 otherwise.
pub fn neq_public<T: IntRing2k, N: Rep3Network>(
    shared: RingShare<T>,
    public: RingElement<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<RingShare<Bit>>
where
    Standard: Distribution<T>,
{
    let public = promote_to_trivial_share(io_context.id, public);
    neq(shared, public, io_context)
}

/// Outputs whether a shared value is zero (true) or not (false).
pub fn is_zero<T: IntRing2k, N: Rep3Network>(
    a: RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<bool>
where
    Standard: Distribution<T>,
{
    let zero_share = RingShare::default();
    let res = eq(zero_share, a, io_context)?;
    let x = open_bit(res, io_context)?;
    Ok(x.0.convert())
}

/// Computes `shared*2^public`. This is the same as `shared << public`.
///
/// #Panics
/// If public is larger than the bit size of the modulus of the underlying ring.
pub fn pow_2_public<T: IntRing2k>(shared: RingShare<T>, public: RingElement<T>) -> RingShare<T> {
    if public.is_zero() {
        shared
    } else {
        let shift: usize = public.0.try_into().unwrap_or_else(|_| {
            panic!(
                "Expected left shift to be maximal {}, but was {}",
                T::K,
                public.0
            )
        });
        if shift >= T::K {
            panic!(
                "Expected left shift to be maximal {}, but was {}",
                T::K,
                shift
            );
        } else {
            mul_public(shared, RingElement::one() << shift.try_into().unwrap())
        }
    }
}

/// computes XOR using arithmetic operations, only valid when x and y are known to be 0 or 1.
pub(crate) fn arithmetic_xor<T: IntRing2k, N: Rep3Network>(
    x: RingShare<T>,
    y: RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<RingShare<T>>
where
    Standard: Distribution<T>,
{
    let mut d = x * y + io_context.rngs.rand.masking_element::<RingElement<T>>();
    d <<= 1;
    let e = x.a + y.a;
    let res_a = e - d;

    let res_b = io_context.network.reshare(res_a)?;
    Ok(RingShare { a: res_a, b: res_b })
}

pub(crate) fn arithmetic_xor_many<T: IntRing2k, N: Rep3Network>(
    x: &[RingShare<T>],
    y: &[RingShare<T>],
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<RingShare<T>>>
where
    Standard: Distribution<T>,
{
    debug_assert_eq!(x.len(), y.len());

    let mut a = Vec::with_capacity(x.len());
    for (x, y) in x.iter().zip(y.iter()) {
        let mut d = x * y + io_context.rngs.rand.masking_element::<RingElement<T>>();
        d <<= 1;
        let e = x.a + y.a;
        let res_a = e - d;
        a.push(res_a);
    }

    let b = io_context.network.reshare_many(&a)?;
    let res = a
        .into_iter()
        .zip(b)
        .map(|(a, b)| RingShare { a, b })
        .collect();
    Ok(res)
}
