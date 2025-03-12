use std::marker::PhantomData;

use ark_ff::One;
use ark_ff::PrimeField;
use ark_ff::Zero;
use mpc_engine::Network;
use num_bigint::BigUint;

use crate::protocols::rep3::network;

use super::binary;
use super::conversion;
use super::Rep3BigUintShare;
use super::Rep3PrimeFieldShare;
use super::Rep3State;

pub(super) fn low_depth_binary_add_mod_p<F: PrimeField, N: Network>(
    x1: &Rep3BigUintShare<F>,
    x2: &Rep3BigUintShare<F>,
    net: &N,
    state: &mut Rep3State,
    bitlen: usize,
) -> eyre::Result<Rep3BigUintShare<F>> {
    let x = low_depth_binary_add(x1, x2, net, state, bitlen)?;
    low_depth_sub_p_cmux::<F, N>(&x, net, state, bitlen + 1)
}

fn low_depth_binary_add<F: PrimeField, N: Network>(
    x1: &Rep3BigUintShare<F>,
    x2: &Rep3BigUintShare<F>,
    net: &N,
    state: &mut Rep3State,
    bitlen: usize,
) -> eyre::Result<Rep3BigUintShare<F>> {
    // Add x1 + x2 via a packed Kogge-Stone adder
    let p = x1 ^ x2;
    let g = binary::and(x1, x2, net, state)?;
    kogge_stone_inner(&p, &g, net, state, bitlen)
}

fn kogge_stone_inner<F: PrimeField, N: Network>(
    p: &Rep3BigUintShare<F>,
    g: &Rep3BigUintShare<F>,
    net: &N,
    state: &mut Rep3State,
    bitlen: usize,
) -> eyre::Result<Rep3BigUintShare<F>> {
    let d = ceil_log2(bitlen);
    let s_ = p;
    let mut p = s_.to_owned();
    let mut g = g.to_owned();
    for i in 0..d {
        // The loop looks slightly different to the one for rep3 rings to have the and gates at the LSBs of the storage
        let shift = 1 << i;
        let mask = (BigUint::from(1u64) << (bitlen - shift)) - BigUint::one();
        let p_ = &p & &mask;
        let g_ = &g & &mask;
        let p_shift = &p >> shift;

        // TODO: Make and more communication efficient, ATM we send the full element for each level, even though they reduce in size
        // maybe just input the mask into AND?
        let (r1, r2) = and_twice(&p_shift, &g_, &p_, net, state, bitlen - shift)?;
        p = r2 << shift;
        g ^= &(r1 << shift);
    }
    g <<= 1;
    g ^= s_;
    Ok(g)
}

fn low_depth_sub_p_cmux<F: PrimeField, N: Network>(
    x: &Rep3BigUintShare<F>,
    net: &N,
    state: &mut Rep3State,
    bitlen: usize,
) -> eyre::Result<Rep3BigUintShare<F>> {
    let original_bitlen = bitlen - 1; // before the potential overflow after an addition
    let mask = (BigUint::from(1u64) << original_bitlen) - BigUint::one();
    let mut y = low_depth_binary_sub_p::<F, N>(x, net, state, bitlen)?;
    let x = x & &mask;
    let y_msb = &y >> (bitlen);
    y &= &mask;

    // Spread the ov share to the whole biguint
    let ov_a = y_msb.a.iter_u64_digits().next().unwrap_or_default() & 1;
    let ov_b = y_msb.b.iter_u64_digits().next().unwrap_or_default() & 1;

    let ov_a = if ov_a == 1 {
        mask.to_owned()
    } else {
        BigUint::zero()
    };
    let ov_b = if ov_b == 1 { mask } else { BigUint::zero() };
    let ov = Rep3BigUintShare::<F>::new(ov_a, ov_b);

    // one big multiplexer
    let res = binary::cmux(&ov, &y, &x, net, state)?;
    Ok(res)
}

// Calculates 2^k + x1 - x2
fn low_depth_binary_sub<F: PrimeField, N: Network>(
    x1: &Rep3BigUintShare<F>,
    x2: &Rep3BigUintShare<F>,
    net: &N,
    state: &mut Rep3State,
    bitlen: usize,
) -> eyre::Result<Rep3BigUintShare<F>> {
    // Let x2' = be the bit_not of x2
    // Add x1 + x2' via a packed Kogge-Stone adder, where carry_in = 1
    // This is equivalent to x1 - x2 = x1 + two's complement of x2
    let mask = (BigUint::from(1u64) << bitlen) - BigUint::one();
    // bitnot of x2
    let x2 = binary::xor_public(x2, &mask, net.id());
    // Now start the Kogge-Stone adder
    let p = x1 ^ &x2;
    let mut g = binary::and(x1, &x2, net, state)?;
    // Since carry_in = 1, we need to XOR the LSB of x1 and x2 to g (i.e., xor the LSB of p)
    g ^= &(&p & &BigUint::one());

    let res = kogge_stone_inner(&p, &g, net, state, bitlen)?;
    let res = binary::xor_public(&res, &BigUint::one(), net.id()); // cin=1
    Ok(res)
}

fn ceil_log2(x: usize) -> usize {
    let mut y = 0;
    let mut x = x - 1;
    while x > 0 {
        x >>= 1;
        y += 1;
    }
    y
}

fn and_twice<F: PrimeField, N: Network>(
    a: &Rep3BigUintShare<F>,
    b1: &Rep3BigUintShare<F>,
    b2: &Rep3BigUintShare<F>,
    net: &N,
    state: &mut Rep3State,
    bitlen: usize,
) -> eyre::Result<(Rep3BigUintShare<F>, Rep3BigUintShare<F>)> {
    debug_assert!(a.a.bits() <= bitlen as u64);
    debug_assert!(b1.a.bits() <= bitlen as u64);
    debug_assert!(b2.a.bits() <= bitlen as u64);
    let (mut mask1, mask_b) = state.rngs.rand.random_biguint(bitlen);
    mask1 ^= mask_b;

    let (mut mask2, mask_b) = state.rngs.rand.random_biguint(bitlen);
    mask2 ^= mask_b;

    let local_a1 = (b1 & a) ^ mask1;
    let local_a2 = (a & b2) ^ mask2;
    let [local_b1, local_b2] = network::reshare(net, [local_a1.to_owned(), local_a2.to_owned()])?;

    let r1 = Rep3BigUintShare {
        a: local_a1,
        b: local_b1,
        phantom: PhantomData,
    };
    let r2 = Rep3BigUintShare {
        a: local_a2,
        b: local_b2,
        phantom: PhantomData,
    };

    Ok((r1, r2))
}

fn low_depth_binary_sub_p<F: PrimeField, N: Network>(
    x: &Rep3BigUintShare<F>,
    net: &N,
    state: &mut Rep3State,
    bitlen: usize,
) -> eyre::Result<Rep3BigUintShare<F>> {
    let p_ = (BigUint::from(1u64) << bitlen) - F::MODULUS.into();

    // Add x1 + p_ via a packed Kogge-Stone adder
    let g = x & &p_;
    let p = binary::xor_public(x, &p_, net.id());
    kogge_stone_inner(&p, &g, net, state, bitlen)
}

/// Computes a binary circuit to compare two shared values \[x\] > \[y\]. Thus, the inputs x and y are transformed from arithmetic to binary sharings using [Rep3Protocol::a2b] first. The output is a binary sharing of one bit.
pub(crate) fn unsigned_ge<F: PrimeField, N: Network>(
    x: Rep3PrimeFieldShare<F>,
    y: Rep3PrimeFieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3BigUintShare<F>> {
    let a_bits = conversion::a2b_selector(x, net, state)?;
    let b_bits = conversion::a2b_selector(y, net, state)?;
    let diff = low_depth_binary_sub(&a_bits, &b_bits, net, state, F::MODULUS_BIT_SIZE as usize)?;

    Ok(&(&diff >> F::MODULUS_BIT_SIZE as usize) & &BigUint::one())
}

/// Computes a binary circuit to compare the shared value y to the public value x, i.e., x > \[y\]. Thus, the input y is transformed from arithmetic to binary sharings using [Rep3Protocol::a2b] first. The output is a binary sharing of one bit.
pub(crate) fn unsigned_ge_const_lhs<F: PrimeField, N: Network>(
    x: F,
    y: Rep3PrimeFieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3BigUintShare<F>> {
    let b_bits = conversion::a2b_selector(y, net, state)?;
    let diff = low_depth_binary_sub_from_const(&x.into(), &b_bits, net, state)?;

    Ok(&(&diff >> F::MODULUS_BIT_SIZE as usize) & &BigUint::one())
}

/// Computes a binary circuit to compare the shared value x to the public value y, i.e., \[x\] > y. Thus, the input x is transformed from arithmetic to binary sharings using [Rep3Protocol::a2b] first. The output is a binary sharing of one bit.
pub(crate) fn unsigned_ge_const_rhs<F: PrimeField, N: Network>(
    x: Rep3PrimeFieldShare<F>,
    y: F,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3BigUintShare<F>> {
    let a_bits = conversion::a2b_selector(x, net, state)?;
    let diff = low_depth_binary_sub_by_const(&a_bits, &y.into(), net, state)?;

    Ok(&(&diff >> F::MODULUS_BIT_SIZE as usize) & &BigUint::one())
}

// Calculates 2^k + x1 - x2
fn low_depth_binary_sub_by_const<F: PrimeField, N: Network>(
    x1: &Rep3BigUintShare<F>,
    x2: &BigUint,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3BigUintShare<F>> {
    // two's complement
    let x2_ = (BigUint::from(1u64) << F::MODULUS_BIT_SIZE as usize) - x2;

    // Add x1 + x2_ via a packed Kogge-Stone adder
    let p = binary::xor_public(x1, &x2_, net.id());
    let g = x1 & &x2_;

    let res = kogge_stone_inner(&p, &g, net, state, F::MODULUS_BIT_SIZE as usize)?;
    Ok(res)
}

// Calculates 2^k + x1 - x2
fn low_depth_binary_sub_from_const<F: PrimeField, N: Network>(
    x1: &BigUint,
    x2: &Rep3BigUintShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3BigUintShare<F>> {
    // Let x2' = be the bit_not of x2
    // Add x1 + x2' via a packed Kogge-Stone adder, where carry_in = 1
    // This is equivalent to x1 - x2 = x1 + two's complement of x2
    let mask = (BigUint::from(1u64) << F::MODULUS_BIT_SIZE as usize) - BigUint::one();
    // bitnot of x2
    let x2 = binary::xor_public(x2, &mask, net.id());
    // Now start the Kogge-Stone adder
    let p = binary::xor_public(&x2, x1, net.id());
    let mut g = &x2 & x1;
    // Since carry_in = 1, we need to XOR the LSB of x1 and x2 to g (i.e., xor the LSB of p)
    g ^= &p & &BigUint::one();

    let res = kogge_stone_inner(&p, &g, net, state, F::MODULUS_BIT_SIZE as usize)?;
    let res = binary::xor_public(&res, &BigUint::one(), net.id());
    Ok(res)
}
