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

/// Takes a public lookup table (size must be a power of two) containing field elements, and a replicated binary share of an index and returns a replicated binary sharing of the looked up value lut[index].
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
