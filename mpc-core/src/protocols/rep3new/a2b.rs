use std::marker::PhantomData;

use ark_ff::One;
use ark_ff::PrimeField;
use ark_ff::Zero;
use num_bigint::BigUint;

use crate::protocols::rep3::id::PartyID;
use crate::protocols::rep3::network::Rep3Network;

use super::binary;
use super::network::IoContext;
use super::Rep3BigUintShare;
use super::Rep3PrimeFieldShare;

type IoResult<T> = std::io::Result<T>;

/// Transforms the replicated shared value x from an arithmetic sharing to a binary sharing. I.e., x = x_1 + x_2 + x_3 gets transformed into x = x'_1 xor x'_2 xor x'_3.
pub async fn a2b<F: PrimeField, N: Rep3Network>(
    x: &Rep3PrimeFieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3BigUintShare<F>> {
    let mut x01 = Rep3BigUintShare::zero_share();
    let mut x2 = Rep3BigUintShare::zero_share();

    let bitlen = usize::try_from(F::MODULUS_BIT_SIZE).expect("u32 fits into usize");

    let (mut r, r2) = io_context.rngs.rand.random_biguint(bitlen);
    r ^= r2;

    match io_context.id {
        PartyID::ID0 => {
            x01.a = r;
            x2.b = x.b.into();
        }
        PartyID::ID1 => {
            let val: BigUint = (x.a + x.b).into();
            x01.a = val ^ r;
        }
        PartyID::ID2 => {
            x01.a = r;
            x2.a = x.a.into();
        }
    }

    // Reshare x01
    io_context.network.send_next(x01.a.to_owned()).await?;
    let local_b = io_context.network.recv_prev().await?;
    x01.b = local_b;

    low_depth_binary_add_mod_p::<F, N>(x01, x2, io_context, bitlen).await
}

pub(super) async fn low_depth_binary_add_mod_p<F: PrimeField, N: Rep3Network>(
    x1: Rep3BigUintShare<F>,
    x2: Rep3BigUintShare<F>,
    io_context: &mut IoContext<N>,
    bitlen: usize,
) -> IoResult<Rep3BigUintShare<F>> {
    let x = low_depth_binary_add(x1, x2, io_context, bitlen).await?;
    low_depth_sub_p_cmux::<F, N>(x, io_context, bitlen).await
}

async fn low_depth_binary_add<F: PrimeField, N: Rep3Network>(
    x1: Rep3BigUintShare<F>,
    x2: Rep3BigUintShare<F>,
    io_context: &mut IoContext<N>,
    bitlen: usize,
) -> IoResult<Rep3BigUintShare<F>> {
    // Add x1 + x2 via a packed Kogge-Stone adder
    let p = &x1 ^ &x2;
    let g = binary::and(&x1, &x2, io_context).await?;
    kogge_stone_inner(p, g, io_context, bitlen).await
}

async fn kogge_stone_inner<F: PrimeField, N: Rep3Network>(
    mut p: Rep3BigUintShare<F>,
    mut g: Rep3BigUintShare<F>,
    io_context: &mut IoContext<N>,
    bitlen: usize,
) -> IoResult<Rep3BigUintShare<F>> {
    let d = ceil_log2(bitlen);
    let s_ = p.to_owned();

    for i in 0..d {
        let shift = 1 << i;
        let mut p_ = p.to_owned();
        let mut g_ = g.to_owned();
        let mask = (BigUint::from(1u64) << (bitlen - shift)) - BigUint::one();
        p_ &= &mask;
        g_ &= &mask;
        let p_shift = &p >> shift;

        // TODO: Make and more communication efficient, ATM we send the full element for each level, even though they reduce in size
        // maybe just input the mask into AND?
        let (r1, r2) = and_twice(p_shift, g_, p_, io_context, bitlen - shift).await?;
        p = r2 << shift;
        g ^= &(r1 << shift);
    }
    g <<= 1;
    g ^= &s_;
    Ok(g)
}

async fn low_depth_sub_p_cmux<F: PrimeField, N: Rep3Network>(
    mut x: Rep3BigUintShare<F>,
    io_context: &mut IoContext<N>,
    bitlen: usize,
) -> IoResult<Rep3BigUintShare<F>> {
    let mask = (BigUint::from(1u64) << bitlen) - BigUint::one();
    let x_msb = &x >> bitlen;
    x &= &mask;
    let mut y = low_depth_binary_sub_p::<F, N>(&x, io_context, bitlen).await?;
    let y_msb = &y >> (bitlen + 1);
    y &= &mask;

    // Spread the ov share to the whole biguint
    let ov_a = (x_msb.a.iter_u64_digits().next().unwrap_or_default()
        ^ y_msb.a.iter_u64_digits().next().unwrap_or_default())
        & 1;
    let ov_b = (x_msb.b.iter_u64_digits().next().unwrap_or_default()
        ^ y_msb.b.iter_u64_digits().next().unwrap_or_default())
        & 1;

    let ov_a = if ov_a == 1 {
        mask.to_owned()
    } else {
        BigUint::zero()
    };
    let ov_b = if ov_b == 1 { mask } else { BigUint::zero() };
    let ov = Rep3BigUintShare::<F>::new(ov_a, ov_b);

    // one big multiplexer
    let res = binary::cmux(&ov, &y, &x, io_context).await?;
    Ok(res)
}

// Calculates 2^k + x1 - x2
async fn low_depth_binary_sub<F: PrimeField, N: Rep3Network>(
    x1: Rep3BigUintShare<F>,
    x2: Rep3BigUintShare<F>,
    io_context: &mut IoContext<N>,
    bitlen: usize,
) -> IoResult<Rep3BigUintShare<F>> {
    // Let x2' = be the bit_not of x2
    // Add x1 + x2' via a packed Kogge-Stone adder, where carry_in = 1
    // This is equivalent to x1 - x2 = x1 + two's complement of x2
    let mask = (BigUint::from(1u64) << bitlen) - BigUint::one();
    // bitnot of x2
    let x2 = binary::xor_public(&x2, &mask, io_context.id);
    // Now start the Kogge-Stone adder
    let p = &x1 ^ &x2;
    let mut g = binary::and(&x1, &x2, io_context).await?;
    // Since carry_in = 1, we need to XOR the LSB of x1 and x2 to g (i.e., xor the LSB of p)
    g ^= &(&p & &BigUint::one());

    let res = kogge_stone_inner(p, g, io_context, bitlen).await?;
    let res = binary::xor_public(&res, &BigUint::one(), io_context.id); // cin=1
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

async fn and_twice<F: PrimeField, N: Rep3Network>(
    a: Rep3BigUintShare<F>,
    b1: Rep3BigUintShare<F>,
    b2: Rep3BigUintShare<F>,
    io_context: &mut IoContext<N>,
    bitlen: usize,
) -> IoResult<(Rep3BigUintShare<F>, Rep3BigUintShare<F>)> {
    debug_assert!(a.a.bits() <= bitlen as u64);
    debug_assert!(b1.a.bits() <= bitlen as u64);
    debug_assert!(b2.a.bits() <= bitlen as u64);
    let (mut mask1, mask_b) = io_context.rngs.rand.random_biguint(bitlen);
    mask1 ^= mask_b;

    let (mut mask2, mask_b) = io_context.rngs.rand.random_biguint(bitlen);
    mask2 ^= mask_b;

    let local_a1 = (&b1 & &a) ^ mask1;
    let local_a2 = (&a & &b2) ^ mask2;
    io_context.network.send_next(local_a1.to_owned()).await?;
    io_context.network.send_next(local_a2.to_owned()).await?;
    let local_b1 = io_context.network.recv_prev().await?;
    let local_b2 = io_context.network.recv_prev().await?;

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

async fn low_depth_binary_sub_p<F: PrimeField, N: Rep3Network>(
    x: &Rep3BigUintShare<F>,
    io_context: &mut IoContext<N>,
    bitlen: usize,
) -> IoResult<Rep3BigUintShare<F>> {
    let p_ = (BigUint::from(1u64) << (bitlen + 1)) - F::MODULUS.into();

    // Add x1 + p_ via a packed Kogge-Stone adder
    let p = binary::xor_public(&x, &p_, io_context.id);
    let g = x & &p_;
    kogge_stone_inner(p, g, io_context, bitlen + 1).await
}
