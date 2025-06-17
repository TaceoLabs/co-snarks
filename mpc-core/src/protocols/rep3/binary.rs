//! Binary
//!
//! This module contains operations with binary shares

use ark_ff::{One, PrimeField};
use itertools::{Itertools as _, izip};
use mpc_net::Network;
use num_bigint::BigUint;

use super::{PartyID, Rep3BigUintShare, Rep3PrimeFieldShare, Rep3State, arithmetic, conversion};
use crate::protocols::rep3::network::{self};
use num_traits::cast::ToPrimitive;

type ArithmeticShare<F> = Rep3PrimeFieldShare<F>;
type BinaryShare<F> = Rep3BigUintShare<F>;

/// Performs a bitwise XOR operation on two shared values.
pub fn xor<F: PrimeField>(a: &BinaryShare<F>, b: &BinaryShare<F>) -> BinaryShare<F> {
    a ^ b
}

/// Performs a bitwise XOR operation on a shared value and a public value.
pub fn xor_public<F: PrimeField>(
    shared: &BinaryShare<F>,
    public: &BigUint,
    id: PartyID,
) -> BinaryShare<F> {
    let mut res = shared.to_owned();
    match id {
        PartyID::ID0 => res.a ^= public,
        PartyID::ID1 => res.b ^= public,
        PartyID::ID2 => {}
    }
    res
}

/// Performs element-wise bitwise XOR operation on the provided public and shared values.
pub fn xor_public_vec<F: PrimeField>(
    shared: &[BinaryShare<F>],
    public: &[BigUint],
    id: PartyID,
) -> Vec<BinaryShare<F>> {
    shared
        .iter()
        .zip(public)
        .map(|(shared, public)| {
            let mut res = shared.to_owned();
            match id {
                PartyID::ID0 => res.a ^= public,
                PartyID::ID1 => res.b ^= public,
                PartyID::ID2 => {}
            }
            res
        })
        .collect()
}

/// Performs a bitwise OR operation on two shared values.
pub fn or<F: PrimeField, N: Network>(
    a: &BinaryShare<F>,
    b: &BinaryShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<BinaryShare<F>> {
    let xor = a ^ b;
    let and = and(a, b, net, state)?;
    Ok(xor ^ and)
}

/// Performs a bitwise OR operation on a shared value and a public value.
pub fn or_public<F: PrimeField>(
    shared: &BinaryShare<F>,
    public: &BigUint,
    id: PartyID,
) -> BinaryShare<F> {
    let tmp = shared & public;
    let xor = xor_public(shared, public, id);
    xor ^ tmp
}

/// Performs a bitwise AND operation on two shared values.
pub fn and<F: PrimeField, N: Network>(
    a: &BinaryShare<F>,
    b: &BinaryShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<BinaryShare<F>> {
    debug_assert!(a.a.bits() <= u64::from(F::MODULUS_BIT_SIZE));
    debug_assert!(b.a.bits() <= u64::from(F::MODULUS_BIT_SIZE));
    let (mut mask, mask_b) = state
        .rngs
        .rand
        .random_biguint(usize::try_from(F::MODULUS_BIT_SIZE).expect("u32 fits into usize"));
    mask ^= mask_b;
    let local_a = (a & b) ^ mask;
    let local_b = network::reshare(net, local_a.clone())?;
    Ok(BinaryShare::new(local_a, local_b))
}

/// Performs element-wise bitwise AND operation on the provided shared values.
pub fn and_vec<F: PrimeField, N: Network>(
    a: &[BinaryShare<F>],
    b: &[BinaryShare<F>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<BinaryShare<F>>> {
    let local_a = izip!(a, b)
        .map(|(a, b)| {
            let (mut mask, mask_b) = state
                .rngs
                .rand
                .random_biguint(usize::try_from(F::MODULUS_BIT_SIZE).expect("u32 fits into usize"));

            mask ^= mask_b;
            (a & b) ^ mask
        })
        .collect_vec();
    let local_b = network::reshare(net, local_a.clone())?;
    Ok(izip!(local_a, local_b)
        .map(|(a, b)| BinaryShare::new(a, b))
        .collect_vec())
}

/// Performs a bitwise AND operation on a shared value and a public value.
pub fn and_with_public<F: PrimeField>(shared: &BinaryShare<F>, public: &BigUint) -> BinaryShare<F> {
    shared & public
}

/// Shifts a share by a public value `F` to the right.
///
/// # Panics
/// This method panics if `public` is larger than the of bits of
/// the underlying `PrimeField`'s modulus'.
pub fn shift_r_public<F: PrimeField>(shared: &BinaryShare<F>, public: F) -> BinaryShare<F> {
    // some special casing
    if public.is_zero() {
        return shared.to_owned();
    }
    let shift: BigUint = public.into();
    let shift = shift.to_usize().expect("can cast shift operand to usize");
    shared >> shift
}

/// Shifts a share by a public value `F` to the left.
///
/// # Panics
/// This method panics if `public` is larger than the of bits of
/// the underlying `PrimeField`'s modulus'.
pub fn shift_l_public<F: PrimeField>(shared: &BinaryShare<F>, public: F) -> BinaryShare<F> {
    // some special casing
    if public.is_zero() {
        return shared.to_owned();
    }
    let shift: BigUint = public.into();
    let shift = shift.to_usize().expect("can cast shift operand to usize");
    shared << shift
}

/// Shifts a public value `F` by a share to the left.
pub fn shift_l_public_by_shared<F: PrimeField, N: Network>(
    public: F,
    shared: &BinaryShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<ArithmeticShare<F>> {
    // This case is equivalent to a*2^b
    // Strategy: limit size of b to k bits
    // bit-decompose b into bits b_i
    let mut individual_bit_shares = Vec::with_capacity(8);
    for i in 0..8 {
        let bit = Rep3BigUintShare::new(
            (shared.a.clone() >> i) & BigUint::one(),
            (shared.b.clone() >> i) & BigUint::one(),
        );
        individual_bit_shares.push(conversion::b2a_selector(&bit, net, state)?);
    }
    // v_i = 2^2^i * <b_i> + 1 - <b_i>
    let mut vs: Vec<_> = individual_bit_shares
        .into_iter()
        .enumerate()
        .map(|(i, b_i)| {
            let two = F::from(2u64);
            // i is 8 at most there `as u32` is ok
            let two_to_two_to_i = two.pow([2u64.pow(i as u32)]);
            let v = arithmetic::mul_public(b_i, two_to_two_to_i);
            let v = arithmetic::add_public(v, F::one(), state.id);
            arithmetic::sub(v, b_i)
        })
        .collect();

    // v = \prod v_i
    // TODO: This should be done in a multiplication tree
    let mut v = vs.pop().unwrap();
    for v_i in vs {
        v = arithmetic::mul(v, v_i, net, state)?;
    }
    Ok(arithmetic::mul_public(v, public))
}

/// Performs the opening of a shared value and returns the equivalent public value.
pub fn open<F: PrimeField, N: Network>(a: &BinaryShare<F>, net: &N) -> eyre::Result<BigUint> {
    let c = network::reshare(net, a.b.clone())?;
    Ok(&a.a ^ &a.b ^ c)
}

/// Transforms a public value into a shared value: \[a\] = a.
pub fn promote_to_trivial_share<F: PrimeField>(
    id: PartyID,
    public_value: &BigUint,
) -> BinaryShare<F> {
    match id {
        PartyID::ID0 => BinaryShare::new(public_value.to_owned(), BigUint::ZERO),
        PartyID::ID1 => BinaryShare::new(BigUint::ZERO, public_value.to_owned()),
        PartyID::ID2 => BinaryShare::zero_share(),
    }
}

/// Computes a CMUX: If `c` is `1`, returns `x_t`, otherwise returns `x_f`.
pub fn cmux<F: PrimeField, N: Network>(
    c: &BinaryShare<F>,
    x_t: &BinaryShare<F>,
    x_f: &BinaryShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<BinaryShare<F>> {
    let xor = x_f ^ x_t;
    let mut and = and(c, &xor, net, state)?;
    and ^= x_f;
    Ok(and)
}

/// Computes an element-wise CMUX: If `$c_i$` is `1`, returns `$x^t_i$`, otherwise returns `$x^f_i$`.
pub fn cmux_many<F: PrimeField, N: Network>(
    c: &[BinaryShare<F>],
    x_t: &[BinaryShare<F>],
    x_f: &[BinaryShare<F>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<BinaryShare<F>>> {
    assert_eq!(c.len(), x_t.len());
    assert_eq!(c.len(), x_f.len());
    let xor = izip!(x_f, x_t).map(|(x_f, x_t)| x_f ^ x_t).collect_vec();
    let mut and = and_vec(c, &xor, net, state)?;
    for (and, x_f) in izip!(and.iter_mut(), x_f) {
        *and ^= x_f;
    }
    Ok(and)
}

//TODO most likely the inputs here are only one bit therefore we
//do not have to perform an or over the whole length of prime field
//but only one bit.
//Do we want that to be configurable? Semms like a waste?
/// Compute a OR tree of the input vec
pub fn or_tree<F: PrimeField, N: Network>(
    mut inputs: Vec<BinaryShare<F>>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<BinaryShare<F>> {
    let mut num = inputs.len();

    tracing::debug!("starting or tree over {} elements", inputs.len());
    while num > 1 {
        tracing::trace!("binary tree still has {} elements", num);
        let mod_ = num & 1;
        num >>= 1;

        let (a_vec, tmp) = inputs.split_at(num);
        let (b_vec, leftover) = tmp.split_at(num);

        let mut res = Vec::with_capacity(num);
        // TODO WE WANT THIS BATCHED!!!
        // THIS IS SUPER BAD
        for (a, b) in izip!(a_vec.iter(), b_vec.iter()) {
            res.push(or(a, b, net, state)?);
        }

        res.extend_from_slice(leftover);
        inputs = res;

        num += mod_;
    }
    let result = inputs[0].clone();
    tracing::debug!("we did it!");
    Ok(result)
}

/// Computes a binary circuit to check whether the replicated binary-shared input x is zero or not. The output is a binary sharing of one bit.
pub fn is_zero<F: PrimeField, N: Network>(
    x: &BinaryShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<BinaryShare<F>> {
    let bit_len = F::MODULUS_BIT_SIZE as usize;
    let mask = (BigUint::from(1u64) << bit_len) - BigUint::one();

    // negate
    let mut x = x ^ &mask;

    // do ands in a tree
    // TODO: Make and tree more communication efficient, ATM we send the full element for each level, even though they halve in size
    let mut len = bit_len;
    while len > 1 {
        if len % 2 == 1 {
            len += 1;
            // pad with a 1 (= 1 xor 1 xor 1) in MSB position
            // since this is publicly known we just set the bit in each party's share and its replication
            x.a.set_bit(len as u64 - 1, true);
            x.b.set_bit(len as u64 - 1, true);
        }
        len /= 2;
        let mask = (BigUint::from(1u64) << len) - BigUint::one();
        let y = &x >> len;
        x = and(&(&x & &mask), &(&y & &mask), net, state)?;
    }
    // extract LSB
    Ok(x & BigUint::one())
}

/// Computes a binary circuit to check whether each of the replicated binary-shared inputs in the vector x is zero or not. The output is a vector of binary sharings of one bit.
pub(crate) fn is_zero_many<F: PrimeField, N: Network>(
    mut x: Vec<Rep3BigUintShare<F>>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3BigUintShare<F>>> {
    let bit_len = F::MODULUS_BIT_SIZE as usize;
    let mask = (BigUint::from(1u64) << bit_len) - BigUint::one();

    // mask negate
    for x_ in x.iter_mut() {
        *x_ ^= &mask; // Negate bits
        *x_ &= &mask; // remove additional bits
    }
    let mut y = x.clone();

    // do ands in a tree
    // TODO: Make and tree more communication efficient, ATM we send the full element for each level, even though they halve in size
    let mut len = bit_len;
    while len > 1 {
        if len % 2 == 1 {
            len += 1;
            // pad with a 1 (= 1 xor 1 xor 1) in MSB position
            // since this is publicly known we just set the bit in each party's share and its replication
            for x in x.iter_mut() {
                x.a.set_bit(len as u64 - 1, true);
                x.b.set_bit(len as u64 - 1, true);
            }
        }
        len /= 2;
        let mask = (BigUint::from(1u64) << len) - BigUint::one();
        for (x_, y_) in izip!(x.iter_mut(), y.iter_mut()) {
            y_.a = (&x_.a >> len) & &mask;
            y_.b = (&x_.b >> len) & &mask;
            x_.a &= &mask;
            x_.b &= &mask;
        }
        x = and_vec(&x, &y, net, state)?;
    }
    // extract LSB
    for x_ in x.iter_mut() {
        *x_ &= BigUint::one();
    }
    Ok(x)
}
