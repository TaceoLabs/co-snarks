//! OHV
//!
//! This module contains some algorithms to create a random one-hot encoded vector for the Rep3 protocol.

use ark_ff::One;
use rand::{distributions::Standard, prelude::Distribution};

use crate::protocols::{
    rep3::{
        network::{IoContext, Rep3Network},
        IoResult,
    },
    rep3_ring::{
        binary,
        ring::{bit::Bit, int_ring::IntRing2k, ring_impl::RingElement},
        Rep3RingShare,
    },
};

/// Generates a random one-hot-encoded vector of size k bits.
/// The output is (r, e), where r is a binary sharing of the index of the set bit, wheras e is a vector of size 2^k with all bits zero except at index r.
/// The algorithm is a rewrite of Protocol 5 from [https://eprint.iacr.org/2024/1317.pdf](https://eprint.iacr.org/2024/1317.pdf) for rep3.
pub fn rand_ohv<T: IntRing2k, N: Rep3Network>(
    k: usize,
    io_context: &mut IoContext<N>,
) -> IoResult<(Rep3RingShare<T>, Vec<Rep3RingShare<Bit>>)>
where
    Standard: Distribution<T>,
{
    debug_assert!(k > 1);
    debug_assert!(k <= T::K); // Make sure datatype is large enough for bitsize
    let (mut a, mut b) = io_context.random_elements::<T>();
    if k != T::K {
        let mask = (T::one() << k) - T::one();
        a &= mask;
        b &= mask
    }

    let bits = Rep3RingShare::new(a, b);
    let e = ohv(k, bits, io_context)?;

    Ok((bits, e))
}

fn ohv<T: IntRing2k, N: Rep3Network>(
    k: usize,
    mut bits: Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<Rep3RingShare<Bit>>> {
    debug_assert!(k > 0);
    debug_assert!(k <= T::K); // Make sure datatype is large enough for bitsize

    let new_k = k - 1;
    let vk = bits.get_bit(new_k);

    if new_k == 0 {
        return Ok(vec![!vk, vk]);
    }

    let mask = (RingElement::one() << new_k) - RingElement::one();
    bits &= mask; // Remove the vk

    let mut f = ohv(new_k, bits, io_context)?; // ohv is recursively called k - 1 times
    let mut e = pack_and(&f[..f.len() - 1], &vk, io_context)?; // This has communication (new_k bits)
    e.push(e.iter().fold(vk, |a, b| &a ^ b));

    for (e, f) in e.iter().zip(f.iter_mut()) {
        *f ^= e;
    }
    f.extend(e);
    Ok(f)
}

// TODO pack and send at once
fn pack_and<N: Rep3Network>(
    input: &[Rep3RingShare<Bit>],
    rhs: &Rep3RingShare<Bit>,
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<Rep3RingShare<Bit>>> {
    let len = input.len();
    debug_assert!(len >= 1);
    let mut result = Vec::with_capacity(len);

    // TODO THIS IS BAD, OPTIMIZE THIS WITH A PACKED SENDING
    for el in input.iter() {
        result.push(binary::and(el, rhs, io_context)?);
    }

    Ok(result)
}
