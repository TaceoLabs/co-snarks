//! Binary
//!
//! This module contains operations with binary shares

use ark_ff::One;
use itertools::{Itertools as _, izip};
use mpc_net::Network;
use num_traits::Zero;

use super::{PartyID, Rep3PrimeFieldShare, Rep3State, Rep3UintShare, arithmetic, conversion};
use crate::protocols::rep3::network::Rep3NetworkExt;
use crate::uint::{FieldUint, UintBackend};

mod ops;
pub(super) mod types;

type ArithmeticShare<F> = Rep3PrimeFieldShare<F>;
type BinaryShare<F> = Rep3UintShare<F>;

/// Performs a bitwise XOR operation on two shared values.
pub fn xor<F: FieldUint>(a: &BinaryShare<F>, b: &BinaryShare<F>) -> BinaryShare<F> {
    a ^ b
}

/// Performs a bitwise XOR operation on a shared value and a public value.
pub fn xor_public<F: FieldUint>(
    shared: &BinaryShare<F>,
    public: &F::Uint,
    id: PartyID,
) -> BinaryShare<F> {
    let mut res = shared.to_owned();
    match id {
        PartyID::ID0 => res.a ^= *public,
        PartyID::ID1 => res.b ^= *public,
        PartyID::ID2 => {}
    }
    res
}

/// Performs element-wise bitwise XOR operation on the provided public and shared values.
pub fn xor_public_vec<F: FieldUint>(
    shared: &[BinaryShare<F>],
    public: &[F::Uint],
    id: PartyID,
) -> Vec<BinaryShare<F>> {
    shared
        .iter()
        .zip(public)
        .map(|(shared, public)| {
            let mut res = shared.to_owned();
            match id {
                PartyID::ID0 => res.a ^= *public,
                PartyID::ID1 => res.b ^= *public,
                PartyID::ID2 => {}
            }
            res
        })
        .collect()
}

/// Performs a bitwise OR operation on two shared values.
pub fn or<F: FieldUint, N: Network>(
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
pub fn or_public<F: FieldUint>(
    shared: &BinaryShare<F>,
    public: &F::Uint,
    id: PartyID,
) -> BinaryShare<F> {
    let tmp = shared.and_mask(public);
    let xor = xor_public(shared, public, id);
    xor ^ tmp
}

/// Performs a bitwise AND operation on two shared values.
pub fn and<F: FieldUint, N: Network>(
    a: &BinaryShare<F>,
    b: &BinaryShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<BinaryShare<F>> {
    let (mut mask, mask_b) = state.rngs.rand.random_uint::<F::Uint>(F::Uint::BITS);
    mask ^= mask_b;
    let local_a = (a & b) ^ mask;
    let local_b = net.reshare(local_a)?;
    Ok(BinaryShare::new(local_a, local_b))
}

/// Performs element-wise bitwise AND operation on the provided shared values.
pub fn and_vec<F: FieldUint, N: Network>(
    a: &[BinaryShare<F>],
    b: &[BinaryShare<F>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<BinaryShare<F>>> {
    let local_a = izip!(a, b)
        .map(|(a, b)| {
            let (mut mask, mask_b) = state.rngs.rand.random_uint::<F::Uint>(F::Uint::BITS);

            mask ^= mask_b;
            (a & b) ^ mask
        })
        .collect_vec();
    let local_b = net.reshare(local_a.clone())?;
    Ok(izip!(local_a, local_b)
        .map(|(a, b)| BinaryShare::new(a, b))
        .collect_vec())
}

/// Performs a bitwise AND operation on a shared value and a public value.
pub fn and_with_public<F: FieldUint>(shared: &BinaryShare<F>, public: &F::Uint) -> BinaryShare<F> {
    shared.and_mask(public)
}

/// Shifts a share by a public value `F` to the right.
///
/// Shifts of at least `F::Uint::BITS` saturate to zero (in contrast to [`shift_l_public`],
/// which panics for shifts >= `F::MODULUS_BIT_SIZE`).
///
/// # Panics
/// This method panics if `public` does not fit into a `usize`.
pub fn shift_r_public<F: FieldUint>(shared: &BinaryShare<F>, public: F) -> BinaryShare<F> {
    let shift: usize = public
        .to_uint()
        .try_to_usize()
        .expect("shift is in usize range");
    shared >> shift
}

/// Shifts a share by a public value `F` to the left.
///
/// # Panics
/// This method panics if `public` is larger than the number of bits of
/// the underlying `PrimeField`'s modulus.
pub fn shift_l_public<F: FieldUint>(shared: &BinaryShare<F>, public: F) -> BinaryShare<F> {
    let shift: usize = public
        .to_uint()
        .try_to_usize()
        .expect("shift is in usize range");
    assert!(
        (shift as u32) < F::MODULUS_BIT_SIZE,
        "shifting by {shift} >= MODULUS_BIT_SIZE is not supported"
    );
    shared << shift
}

/// Shifts a public value `F` by a share to the left.
pub fn shift_l_public_by_shared<F: FieldUint, N: Network>(
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
        let bit = Rep3UintShare::new(
            (shared.a >> i) & F::Uint::one(),
            (shared.b >> i) & F::Uint::one(),
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
pub fn open<F: FieldUint, N: Network>(a: &BinaryShare<F>, net: &N) -> eyre::Result<F::Uint> {
    let c = net.reshare(a.b)?;
    Ok(a.a ^ a.b ^ c)
}

/// Transforms a public value into a shared value: \[a\] = a.
pub fn promote_to_trivial_share<F: FieldUint>(
    id: PartyID,
    public_value: &F::Uint,
) -> BinaryShare<F> {
    match id {
        PartyID::ID0 => BinaryShare::new(*public_value, F::Uint::zero()),
        PartyID::ID1 => BinaryShare::new(F::Uint::zero(), *public_value),
        PartyID::ID2 => BinaryShare::zero_share(),
    }
}

/// Computes a CMUX: If `c` is `1`, returns `x_t`, otherwise returns `x_f`.
pub fn cmux<F: FieldUint, N: Network>(
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
pub fn cmux_many<F: FieldUint, N: Network>(
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
pub fn or_tree<F: FieldUint, N: Network>(
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
    let result = inputs[0];
    tracing::debug!("we did it!");
    Ok(result)
}

/// Computes a binary circuit to check whether the replicated binary-shared input x is zero or not. The output is a binary sharing of one bit.
pub fn is_zero<F: FieldUint, N: Network>(
    x: &BinaryShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<BinaryShare<F>> {
    let bit_len = F::MODULUS_BIT_SIZE as usize;
    let mask = F::Uint::mask(bit_len);

    // negate
    let mut x = x.xor_mask(&mask);

    // do AND operations in a tree
    // TODO: Make AND tree more communication efficient, ATM we send the full element for each level, even though they halve in size
    let mut len = bit_len;
    while len > 1 {
        if len % 2 == 1 {
            len += 1;
            // pad with a 1 (= 1 xor 1 xor 1) in MSB position
            // since this is publicly known we just set the bit in each party's share and its replication
            x.a.set_bit(len - 1, true);
            x.b.set_bit(len - 1, true);
        }
        len /= 2;
        let mask = F::Uint::mask(len);
        let y = x >> len;
        x = and(&x.and_mask(&mask), &y.and_mask(&mask), net, state)?;
    }
    // extract LSB
    Ok(x.and_mask(&F::Uint::one()))
}

/// Computes a binary circuit to check whether each of the replicated binary-shared inputs in the vector x is zero or not. The output is a vector of binary sharings of one bit.
pub fn is_zero_many<F: FieldUint, N: Network>(
    mut x: Vec<Rep3UintShare<F>>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3UintShare<F>>> {
    let bit_len = F::MODULUS_BIT_SIZE as usize;
    let mask = F::Uint::mask(bit_len);

    // mask negate
    for x_ in x.iter_mut() {
        x_.xor_mask_assign(&mask); // Negate bits
        x_.and_mask_assign(&mask); // remove additional bits
    }
    let mut y = x.clone();

    // do AND operations in a tree
    // TODO: Make AND tree more communication efficient, ATM we send the full element for each level, even though they halve in size
    let mut len = bit_len;
    while len > 1 {
        if len % 2 == 1 {
            len += 1;
            // pad with a 1 (= 1 xor 1 xor 1) in MSB position
            // since this is publicly known we just set the bit in each party's share and its replication
            for x in x.iter_mut() {
                x.a.set_bit(len - 1, true);
                x.b.set_bit(len - 1, true);
            }
        }
        len /= 2;
        let mask = F::Uint::mask(len);
        for (x_, y_) in izip!(x.iter_mut(), y.iter_mut()) {
            y_.a = (x_.a >> len) & mask;
            y_.b = (x_.b >> len) & mask;
            x_.a &= mask;
            x_.b &= mask;
        }
        x = and_vec(&x, &y, net, state)?;
    }
    // extract LSB
    for x_ in x.iter_mut() {
        x_.and_mask_assign(&F::Uint::one());
    }
    Ok(x)
}
