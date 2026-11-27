//! Lut
//!
//! This module contains some oblivious lookup table algorithms for the Rep3 protocol.

use crate::protocols::{
    rep3::{Rep3PrimeFieldShare, Rep3State, Rep3UintShare, network::Rep3NetworkExt},
    rep3_ring::{
        Rep3RingShare, binary, conversion, gadgets,
        ring::{int_ring::IntRing2k, ring_impl::RingElement},
    },
};
use crate::uint::FieldUint;
use ark_ff::PrimeField;
use mpc_net::Network;
use num_traits::One;
use rand::{distributions::Standard, prelude::Distribution};

/// Masks the shared `index` with the random `r` for opening it, keeping only the `k` least significant bits.
///
/// `r` is only random in its `k` least significant bits. The higher bits of the result are therefore cleared, since they would be opened unmasked otherwise. They are zero for an index within the bounds of the lookup table, but not for an index that is out of bounds.
fn mask_index<T: IntRing2k>(
    r: Rep3RingShare<T>,
    index: Rep3RingShare<T>,
    k: usize,
) -> Rep3RingShare<T> {
    let mut masked = r ^ index;
    if k < T::K {
        masked &= (RingElement::one() << k) - RingElement::one();
    }
    masked
}

/// Takes a public lookup table containing field elements, and a replicated binary share of an index and returns a replicated binary sharing of the looked up value lut`\[`index`\]`. The table size needs to be a power of two. If this is not the case, the table is implicitly padded with 0.
/// The algorithm is a rewrite of Protocol 4 from [https://eprint.iacr.org/2024/1317.pdf](https://eprint.iacr.org/2024/1317.pdf) for rep3.
pub fn read_public_lut<F: FieldUint, T: IntRing2k, N: Network>(
    lut: &[F],
    index: Rep3RingShare<T>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3UintShare<F>>
where
    Standard: Distribution<T>,
{
    let n = lut.len();
    let k = n.next_power_of_two().ilog2() as usize;

    assert!(k <= T::K);

    let (r, e) = gadgets::ohv::rand_ohv::<T, _>(k, net, state)?;

    // Open the xor of the index and r
    let c = binary::open(&mask_index(r, index, k), net)?;
    let c: usize =
        c.0.try_into()
            .expect("This transformation should work, otherwise we have another issue");

    let mut t = Rep3UintShare::<F>::default();
    for (j, e) in e.into_iter().enumerate() {
        let index = j ^ c;
        if index >= n {
            // The pad with 0 case
            continue;
        }
        let lut_val = lut[index].to_uint();
        if e.a.0.convert() {
            t.a ^= lut_val;
        }
        if e.b.0.convert() {
            t.b ^= lut_val;
        }
    }
    Ok(t)
}

/// Takes a public lookup table containing field elements, and a replicated binary share of an index and returns a non-replicated binary sharing of the looked up value lut`\[`index`\]`. The table size needs to be a power of two where the power is even. If this is not the case, the table is implicitly padded with 0.
/// The algorithm is a rewrite of Protocol 10 from [https://eprint.iacr.org/2024/1317.pdf](https://eprint.iacr.org/2024/1317.pdf) for rep3.
pub fn read_public_lut_low_depth<F: FieldUint, T: IntRing2k, N: Network>(
    lut: &[F],
    index: Rep3RingShare<T>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<F::Uint>
where
    Standard: Distribution<T>,
{
    let n = lut.len();
    let mut k = n.next_power_of_two().ilog2() as usize;

    if k & 1 == 1 {
        k += 1; // Make even
        // TODO is it possible to not needing to do that?
    }
    assert!(k <= T::K);
    let k2 = k >> 1;

    // TODO add a `rand_ohv_many` function to generate both OHVs together
    // create two ohv's with half the bitsize
    let (mut r, e) = gadgets::ohv::rand_ohv::<T, _>(k2, net, state)?;
    let (r_, e_) = gadgets::ohv::rand_ohv::<T, _>(k2, net, state)?;

    // Combine r and r_;
    r <<= k2;
    r += r_;

    // Open the xor of the index and r
    let c = binary::open(&mask_index(r, index, k), net)?;
    let c: usize =
        c.0.try_into()
            .expect("This transformation should work, otherwise we have another issue");

    // Start the result with a random mask (for potential resharing later)
    let (mut t, mask_b) = state
        .rngs
        .rand
        .random_uint::<F::Uint>(usize::try_from(F::MODULUS_BIT_SIZE).expect("u32 fits into usize"));
    t ^= mask_b;
    let mut j = 0;
    for f0 in e.into_iter() {
        for f1 in e_.iter() {
            let index = j ^ c;
            j += 1;
            if index >= n {
                // The pad with 0 case
                continue;
            }
            let lut_val = lut[index].to_uint();
            let mut g = Rep3UintShare::<F>::default();
            if f0.a.0.convert() {
                g.a ^= lut_val;
            }
            if f0.b.0.convert() {
                g.b ^= lut_val;
            }
            if f1.a.0.convert() {
                t ^= g.a;
                t ^= g.b;
            }
            if f1.b.0.convert() {
                t ^= g.a;
            }
        }
    }
    Ok(t)
}

/// Takes many public lookup tables containing field elements, and a replicated binary share of an index and returns a non-replicated binary sharing of the looked up value lut`\[`index`\]`. The table sizes needs to be a power of two where the power is even. If this is not the case, the table is implicitly padded with 0.
/// The algorithm is a rewrite of Protocol 10 from [https://eprint.iacr.org/2024/1317.pdf](https://eprint.iacr.org/2024/1317.pdf) for rep3.
pub fn read_multiple_public_lut_low_depth<F: FieldUint, T: IntRing2k, N: Network>(
    luts: &[Vec<F>],
    index: Rep3RingShare<T>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<F::Uint>>
where
    Standard: Distribution<T>,
{
    let n = luts.iter().map(|l| l.len()).max().unwrap();
    let mut k = n.next_power_of_two().ilog2() as usize;

    if k & 1 == 1 {
        k += 1; // Make even
        // TODO is it possible to not needing to do that?
    }
    assert!(k <= T::K);
    let k2 = k >> 1;

    // create two ohv's with half the bitsize
    let (mut r, e) = gadgets::ohv::rand_ohv::<T, _>(k2, net, state)?;
    let (r_, e_) = gadgets::ohv::rand_ohv::<T, _>(k2, net, state)?;

    // Combine r and r_;
    r <<= k2;
    r += r_;

    // Open the xor of the index and r
    let c = binary::open(&mask_index(r, index, k), net)?;
    let c: usize =
        c.0.try_into()
            .expect("This transformation should work, otherwise we have another issue");

    let mut results = Vec::with_capacity(luts.len());
    for lut in luts {
        // Start the result with a random mask (for potential resharing later)
        let (mut t, mask_b) = state.rngs.rand.random_uint::<F::Uint>(
            usize::try_from(F::MODULUS_BIT_SIZE).expect("u32 fits into usize"),
        );
        t ^= mask_b;
        let mut j = 0;
        for f0 in e.iter().cloned() {
            for f1 in e_.iter() {
                let index = j ^ c;
                j += 1;
                if index >= n {
                    // The pad with 0 case
                    continue;
                }
                let lut_val = lut[index].to_uint();
                let mut g = Rep3UintShare::<F>::default();
                if f0.a.0.convert() {
                    g.a ^= lut_val;
                }
                if f0.b.0.convert() {
                    g.b ^= lut_val;
                }
                if f1.a.0.convert() {
                    t ^= g.a;
                    t ^= g.b;
                }
                if f1.b.0.convert() {
                    t ^= g.a;
                }
            }
        }
        results.push(t);
    }
    Ok(results)
}

/// Takes a secret-shared lookup table containing field elements, and a replicated binary share of an index and returns a non-replicated additive sharing of the looked up value lut`\[`index`\]`.
/// The algorithm is inspired by Protocol 4 from [https://eprint.iacr.org/2024/1317.pdf](https://eprint.iacr.org/2024/1317.pdf).
pub fn read_shared_lut<F: FieldUint, T: IntRing2k, N: Network>(
    lut: &[Rep3PrimeFieldShare<F>],
    index: Rep3RingShare<T>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<F>
where
    Standard: Distribution<T>,
{
    let n = lut.len();
    let k = n.next_power_of_two().ilog2() as usize;
    assert!(k <= T::K);
    let e = gadgets::ohv::ohv::<T, _>(k, index, net, state)?;
    let injected = conversion::bit_inject_from_bits_to_field_many::<F, _>(&e, net, state)?;

    // Start the result with a random mask (for potential resharing later)
    let mut t = state.rngs.rand.masking_field_element::<F>();
    for (l, e) in lut.iter().zip(injected) {
        let mul = &e * l;
        t += mul;
    }
    Ok(t)
}

/// Takes a secret-shared lookup table containing field elements, and a replicated binary share of an index and puts another secret-shared field element (value) and puts it at lut`\[`index`\]`.
/// The algorithm is inspired by Protocol 4 from [https://eprint.iacr.org/2024/1317.pdf](https://eprint.iacr.org/2024/1317.pdf).
pub fn write_lut<F: FieldUint, T: IntRing2k, N: Network>(
    value: &Rep3PrimeFieldShare<F>,
    lut: &mut [Rep3PrimeFieldShare<F>],
    index: Rep3RingShare<T>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<()>
where
    Standard: Distribution<T>,
{
    let n = lut.len();
    let k = n.next_power_of_two().ilog2() as usize;
    assert!(k <= T::K);

    let e = gadgets::ohv::ohv::<T, _>(k, index, net, state)?;
    let injected = conversion::bit_inject_from_bits_to_field_many::<F, _>(&e, net, state)?;

    write_lut_from_ohv(value, lut, &injected, net, state)
}

/// The second part of writing to a shared lookup table, i.e, takes the shared value, the shared LUT and and one_hot_vector (all elements 0 except for the index to write to which is set to one) and writes to the shared LUT.
pub fn write_lut_from_ohv<F: PrimeField, N: Network>(
    value: &Rep3PrimeFieldShare<F>,
    lut: &mut [Rep3PrimeFieldShare<F>],
    ohv: &[Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<()> {
    let n = lut.len();
    assert!(n <= ohv.len());
    let mut local_a = Vec::with_capacity(n);
    for (l, e) in lut.iter().zip(ohv.iter()) {
        local_a.push(e * &(value - l) + l.a + state.rngs.rand.masking_field_element::<F>());
    }
    let local_b = net.reshare_many(&local_a)?;

    for (des, (src_a, src_b)) in lut.iter_mut().zip(local_a.into_iter().zip(local_b)) {
        des.a = src_a;
        des.b = src_b;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::Zero;
    use rand::{Rng, thread_rng};

    // The value that is opened must not contain any bits of the index beyond the k masked ones
    #[test]
    fn mask_index_clears_the_bits_above_k() {
        fn check<T: IntRing2k>()
        where
            Standard: Distribution<T>,
        {
            let mut rng = thread_rng();
            for k in 1..=T::K {
                let mask = if k < T::K {
                    (RingElement::<T>::one() << k) - RingElement::one()
                } else {
                    !RingElement::<T>::zero()
                };
                for _ in 0..10 {
                    // r is random in its k least significant bits, the index in all of its bits
                    let r = Rep3RingShare::<T>::new(rng.r#gen::<T>(), rng.r#gen::<T>()) & mask;
                    let index = Rep3RingShare::<T>::new(rng.r#gen::<T>(), rng.r#gen::<T>());
                    let masked = mask_index(r, index, k);
                    assert_eq!(masked.a & mask, masked.a);
                    assert_eq!(masked.b & mask, masked.b);
                    // the k least significant bits are unchanged
                    assert_eq!(masked.a, (r.a ^ index.a) & mask);
                    assert_eq!(masked.b, (r.b ^ index.b) & mask);
                }
            }
        }
        check::<u8>();
        check::<u16>();
        check::<u32>();
        check::<u64>();
    }
}
