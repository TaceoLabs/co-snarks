use super::{
    arithmetic::types::Rep3RingShare,
    binary, conversion,
    ring::{bit::Bit, int_ring::IntRing2k, ring_impl::RingElement},
};
use crate::protocols::rep3::{
    network::{IoContext, Rep3Network},
    IoResult,
};
use num_traits::{One, Zero};
use rand::{distributions::Standard, prelude::Distribution};

pub(super) fn low_depth_binary_add<T: IntRing2k, N: Rep3Network>(
    x1: &Rep3RingShare<T>,
    x2: &Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    // Add x1 + x2 via a packed Kogge-Stone adder
    let p = x1 ^ x2;
    let g = binary::and(x1, x2, io_context)?;
    kogge_stone_inner(&p, &g, io_context)
}

fn kogge_stone_inner<T: IntRing2k, N: Rep3Network>(
    p: &Rep3RingShare<T>,
    g: &Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    let mut g = kogge_stone_loop(p.to_owned(), g.to_owned(), io_context)?;
    g <<= 1;
    g ^= p;
    Ok(g)
}

fn kogge_stone_inner_with_carry<T: IntRing2k, N: Rep3Network>(
    p: &Rep3RingShare<T>,
    g: &Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<(Rep3RingShare<T>, Rep3RingShare<Bit>)>
where
    Standard: Distribution<T>,
{
    let mut g = kogge_stone_loop(p.to_owned(), g.to_owned(), io_context)?;
    let c = g.get_bit(T::K - 1);
    g <<= 1;
    g ^= p;
    Ok((g, c))
}

fn kogge_stone_loop<T: IntRing2k, N: Rep3Network>(
    mut p: Rep3RingShare<T>,
    mut g: Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    let bitlen = T::K;
    let d: u32 = bitlen.ilog2(); // T is a ring with 2^k elements
    debug_assert!(bitlen.is_power_of_two());

    for i in 0..d {
        let shift = 1 << i;
        let p_ = p << shift;
        let g_ = g << shift;
        // TODO: Make and more communication efficient, ATM we send the full element for each level, even though they reduce in size
        // maybe just input the mask into AND?
        let (r1, r2) = and_twice(&p, &g_, &p_, io_context)?;
        p = r2;
        g ^= r1;
    }
    Ok(g)
}

fn and_twice<T: IntRing2k, N: Rep3Network>(
    a: &Rep3RingShare<T>,
    b1: &Rep3RingShare<T>,
    b2: &Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<(Rep3RingShare<T>, Rep3RingShare<T>)>
where
    Standard: Distribution<T>,
{
    let (mut mask1, mask_b) = io_context.rngs.rand.random_elements::<RingElement<T>>();
    mask1 ^= mask_b;

    let (mut mask2, mask_b) = io_context.rngs.rand.random_elements::<RingElement<T>>();
    mask2 ^= mask_b;

    let local_a1 = (b1 & a) ^ mask1;
    let local_a2 = (a & b2) ^ mask2;
    io_context
        .network
        .send_next([local_a1.to_owned(), local_a2.to_owned()])?;
    let [local_b1, local_b2] = io_context.network.recv_prev()?;

    let r1 = Rep3RingShare {
        a: local_a1,
        b: local_b1,
    };
    let r2 = Rep3RingShare {
        a: local_a2,
        b: local_b2,
    };

    Ok((r1, r2))
}

// Calculates 2^k + x1 - x2
fn low_depth_binary_sub_with_carry<T: IntRing2k, N: Rep3Network>(
    x1: &Rep3RingShare<T>,
    x2: &Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<(Rep3RingShare<T>, Rep3RingShare<Bit>)>
where
    Standard: Distribution<T>,
{
    // Let x2' = be the bit_not of x2
    // Add x1 + x2' via a packed Kogge-Stone adder, where carry_in = 1
    // This is equivalent to x1 - x2 = x1 + two's complement of x2

    // bitnot of x2
    let x2 = !x2;
    // Now start the Kogge-Stone adder
    let p = x1 ^ &x2;
    let mut g = binary::and(x1, &x2, io_context)?;
    // Since carry_in = 1, we need to XOR the LSB of x1 and x2 to g (i.e., xor the LSB of p)
    g ^= p & RingElement::one();

    let (res, c) = kogge_stone_inner_with_carry(&p, &g, io_context)?;
    let res = binary::xor_public(&res, &RingElement::one(), io_context.id); // cin=1
    Ok((res, c))
}

// Calculates 2^k + x1 - x2
fn low_depth_binary_sub_by_const_with_carry<T: IntRing2k, N: Rep3Network>(
    x1: &Rep3RingShare<T>,
    x2: &RingElement<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<(Rep3RingShare<T>, Rep3RingShare<Bit>)>
where
    Standard: Distribution<T>,
{
    // two's complement
    let x2_ = !x2 + RingElement::one();

    // Add x1 + x2_ via a packed Kogge-Stone adder
    let p = binary::xor_public(x1, &x2_, io_context.id);
    let g = x1 & &x2_;

    let (res, mut c) = kogge_stone_inner_with_carry(&p, &g, io_context)?;
    if x2.is_zero() {
        // We cut off the carry in the two's complement, so we have to xor in the end
        c = !c;
    }
    Ok((res, c))
}

// Calculates 2^k + x1 - x2
fn low_depth_binary_sub_from_const_with_carry<T: IntRing2k, N: Rep3Network>(
    x1: &RingElement<T>,
    x2: &Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<(Rep3RingShare<T>, Rep3RingShare<Bit>)>
where
    Standard: Distribution<T>,
{
    // Let x2' = be the bit_not of x2
    // Add x1 + x2' via a packed Kogge-Stone adder, where carry_in = 1
    // This is equivalent to x1 - x2 = x1 + two's complement of x2

    // bitnot of x2
    let x2 = !x2;
    // Now start the Kogge-Stone adder
    let p = binary::xor_public(&x2, x1, io_context.id);
    let mut g = &x2 & x1;
    // Since carry_in = 1, we need to XOR the LSB of x1 and x2 to g (i.e., xor the LSB of p)
    g ^= p & RingElement::one();

    let (res, c) = kogge_stone_inner_with_carry(&p, &g, io_context)?;
    let res = binary::xor_public(&res, &RingElement::one(), io_context.id);
    Ok((res, c))
}

/// Computes a binary circuit to compare two shared values \[x\] > \[y\]. Thus, the inputs x and y are transformed from arithmetic to binary sharings using [Rep3Protocol::a2b] first. The output is a binary sharing of one bit.
pub(crate) fn unsigned_ge<T: IntRing2k, N: Rep3Network>(
    x: Rep3RingShare<T>,
    y: Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3RingShare<Bit>>
where
    Standard: Distribution<T>,
{
    let a_bits = conversion::a2b_selector(x, io_context)?;
    let b_bits = conversion::a2b_selector(y, io_context)?;
    let (_, r) = low_depth_binary_sub_with_carry(&a_bits, &b_bits, io_context)?;
    Ok(r)
}

/// Computes a binary circuit to compare the shared value y to the public value x, i.e., x > \[y\]. Thus, the input y is transformed from arithmetic to binary sharings using [Rep3Protocol::a2b] first. The output is a binary sharing of one bit.
pub(crate) fn unsigned_ge_const_lhs<T: IntRing2k, N: Rep3Network>(
    x: RingElement<T>,
    y: Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3RingShare<Bit>>
where
    Standard: Distribution<T>,
{
    let b_bits = conversion::a2b_selector(y, io_context)?;
    let (_, r) = low_depth_binary_sub_from_const_with_carry(&x, &b_bits, io_context)?;
    Ok(r)
}

/// Computes a binary circuit to compare the shared value x to the public value y, i.e., \[x\] > y. Thus, the input x is transformed from arithmetic to binary sharings using [Rep3Protocol::a2b] first. The output is a binary sharing of one bit.
pub(crate) fn unsigned_ge_const_rhs<T: IntRing2k, N: Rep3Network>(
    x: Rep3RingShare<T>,
    y: RingElement<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3RingShare<Bit>>
where
    Standard: Distribution<T>,
{
    let a_bits = conversion::a2b_selector(x, io_context)?;
    let (_, r) = low_depth_binary_sub_by_const_with_carry(&a_bits, &y, io_context)?;
    Ok(r)
}
