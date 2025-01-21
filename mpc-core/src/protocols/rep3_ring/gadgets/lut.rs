//! Lut
//!
//! This module contains some oblivious lookup table algorithms for the Rep3 protocol.

use crate::protocols::{
    rep3::{
        network::{IoContext, Rep3Network},
        IoResult, Rep3BigUintShare,
    },
    rep3_ring::{binary, gadgets, ring::int_ring::IntRing2k, Rep3RingShare},
};
use ark_ff::PrimeField;
use num_bigint::BigUint;
use rand::{distributions::Standard, prelude::Distribution};

macro_rules! join {
    ($t1: expr, $t2: expr) => {{
        std::thread::scope(|s| {
            let t1 = s.spawn(|| $t1);
            let t2 = $t2;
            (t1.join().expect("can join"), t2)
        })
    }};
}

/// Takes a public lookup table (size must be a power of two) containing field elements, and a replicated binary share of an index and returns a replicated binary sharing of the looked up value lut`\[`index`\]`.
/// The algorithm is a rewrite of Protocol 4 from [https://eprint.iacr.org/2024/1317.pdf](https://eprint.iacr.org/2024/1317.pdf) for rep3.
pub fn lut<F: PrimeField, T: IntRing2k, N: Rep3Network>(
    lut: &[F],
    index: Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3BigUintShare<F>>
where
    Standard: Distribution<T>,
{
    let n = lut.len();
    assert!(n.is_power_of_two());
    let k = n.ilog2() as usize;
    assert!(k <= T::K);

    let (r, e) = gadgets::ohv::rand_ohv::<T, _>(k, io_context)?;

    // Open the xor of the index and r
    let c = binary::open(&(r ^ index), io_context)?;
    let c: usize =
        c.0.try_into()
            .expect("This transformation should work, otherwise we have another issue");

    let mut t = Rep3BigUintShare::<F>::default();
    for (j, e) in e.into_iter().enumerate() {
        let index = j ^ c;
        let lut_val: BigUint = lut[index].into();
        if e.a.0.convert() {
            t.a ^= &lut_val;
        }
        if e.b.0.convert() {
            t.b ^= lut_val;
        }
    }
    Ok(t)
}

/// Takes a public lookup table (size must be a power of two) containing field elements, and a replicated binary share of an index and returns a non-replicated binary sharing of the looked up value lut`\[`index`\]`. The size of the lookup table must be a perfect square.
/// The algorithm is a rewrite of Protocol 10 from [https://eprint.iacr.org/2024/1317.pdf](https://eprint.iacr.org/2024/1317.pdf) for rep3.
pub fn lut_low_depth<F: PrimeField, T: IntRing2k, N: Rep3Network>(
    lut: &[F],
    index: Rep3RingShare<T>,
    io_context0: &mut IoContext<N>,
    io_context1: &mut IoContext<N>,
) -> IoResult<BigUint>
where
    Standard: Distribution<T>,
{
    let n = lut.len();
    assert!(n.is_power_of_two());
    let k = n.ilog2() as usize;
    assert_eq!(k & 1, 0);
    assert!(k <= T::K);
    let k2 = k >> 1;
    let nsq = 1 << k2;

    // create two ohv's with half the bitsize in parallel
    let (a, b) = join!(
        gadgets::ohv::rand_ohv::<T, _>(k2, io_context0),
        gadgets::ohv::rand_ohv::<T, _>(k2, io_context1)
    );
    let (mut r, e) = a?;
    let (r_, e_) = b?;

    // Combine r and r_;
    r <<= k2;
    r += r_;

    // Open the xor of the index and r
    let c = binary::open(&(r ^ index), io_context0)?;
    let c: usize =
        c.0.try_into()
            .expect("This transformation should work, otherwise we have another issue");

    // Start the result with a random mask
    let (mut t, mask_b) = io_context0
        .rngs
        .rand
        .random_biguint(usize::try_from(F::MODULUS_BIT_SIZE).expect("u32 fits into usize"));
    t ^= mask_b;
    for j in 0..n {
        let index = j ^ c;
        let lut_val: BigUint = lut[index].into();
        let mut g = Rep3BigUintShare::<F>::default();
        let ei = &e[j / nsq];
        if ei.a.0.convert() {
            g.a ^= &lut_val;
        }
        if ei.b.0.convert() {
            g.b ^= lut_val;
        }
        let fi = &e_[j % nsq];
        if fi.a.0.convert() {
            t ^= &g.a;
            t ^= g.b;
        }
        if fi.b.0.convert() {
            t ^= g.a;
        }
    }

    Ok(t)
}
