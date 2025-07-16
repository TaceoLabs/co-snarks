//! Lut
//!
//! This module contains some oblivious lookup table algorithms for the Rep3 protocol.

use crate::protocols::{
    rep3::{Rep3BigUintShare, Rep3PrimeFieldShare, Rep3State, network::Rep3NetworkExt},
    rep3_ring::{Rep3RingShare, binary, conversion, gadgets, ring::int_ring::IntRing2k},
};
use ark_ff::PrimeField;
use mpc_net::Network;
use num_bigint::BigUint;
use rand::{distributions::Standard, prelude::Distribution};

/// Takes a public lookup table containing field elements, and a replicated binary share of an index and returns a replicated binary sharing of the looked up value lut`\[`index`\]`. The table size needs to be a power of two. If this is not the case, the table is implicitly padded with 0.
/// The algorithm is a rewrite of Protocol 4 from [https://eprint.iacr.org/2024/1317.pdf](https://eprint.iacr.org/2024/1317.pdf) for rep3.
pub fn read_public_lut<F: PrimeField, T: IntRing2k, N: Network>(
    lut: &[F],
    index: Rep3RingShare<T>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3BigUintShare<F>>
where
    Standard: Distribution<T>,
{
    let n = lut.len();
    let k = n.next_power_of_two().ilog2() as usize;

    assert!(k <= T::K);

    let (r, e) = gadgets::ohv::rand_ohv::<T, _>(k, net, state)?;

    // Open the xor of the index and r
    let c = binary::open(&(r ^ index), net)?;
    let c: usize =
        c.0.try_into()
            .expect("This transformation should work, otherwise we have another issue")
            & ((1 << k) - 1); // Mask potential overflows from non-well-defined input

    let mut t = Rep3BigUintShare::<F>::default();
    for (j, e) in e.into_iter().enumerate() {
        let index = j ^ c;
        if index >= n {
            // The pad with 0 case
            continue;
        }
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

/// Takes a public lookup table containing field elements, and a replicated binary share of an index and returns a non-replicated binary sharing of the looked up value lut`\[`index`\]`. The table size needs to be a power of two where the power is even. If this is not the case, the table is implicitly padded with 0.
/// The algorithm is a rewrite of Protocol 10 from [https://eprint.iacr.org/2024/1317.pdf](https://eprint.iacr.org/2024/1317.pdf) for rep3.
pub fn read_public_lut_low_depth<F: PrimeField, T: IntRing2k, N: Network>(
    lut: &[F],
    index: Rep3RingShare<T>,
    net0: &N,
    net1: &N,
    state0: &mut Rep3State,
    state1: &mut Rep3State,
) -> eyre::Result<BigUint>
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

    // create two ohv's with half the bitsize in parallel
    let (a, b) = mpc_net::join(
        || gadgets::ohv::rand_ohv::<T, _>(k2, net0, state0),
        || gadgets::ohv::rand_ohv::<T, _>(k2, net1, state1),
    );
    let (mut r, e) = a?;
    let (r_, e_) = b?;

    // Combine r and r_;
    r <<= k2;
    r += r_;

    // Open the xor of the index and r
    let c = binary::open(&(r ^ index), net0)?;
    let c: usize =
        c.0.try_into()
            .expect("This transformation should work, otherwise we have another issue")
            & ((1 << k) - 1); // Mask potential overflows from non-well-defined input

    // Start the result with a random mask (for potential resharing later)
    let (mut t, mask_b) = state0
        .rngs
        .rand
        .random_biguint(usize::try_from(F::MODULUS_BIT_SIZE).expect("u32 fits into usize"));
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
            let lut_val: BigUint = lut[index].into();
            let mut g = Rep3BigUintShare::<F>::default();
            if f0.a.0.convert() {
                g.a ^= &lut_val;
            }
            if f0.b.0.convert() {
                g.b ^= lut_val;
            }
            if f1.a.0.convert() {
                t ^= &g.a;
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
pub fn read_multiple_public_lut_low_depth<F: PrimeField, T: IntRing2k, N: Network>(
    luts: &[Vec<F>],
    index: Rep3RingShare<T>,
    net0: &N,
    net1: &N,
    state0: &mut Rep3State,
    state1: &mut Rep3State,
) -> eyre::Result<Vec<BigUint>>
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

    // create two ohv's with half the bitsize in parallel
    let (a, b) = mpc_net::join(
        || gadgets::ohv::rand_ohv::<T, _>(k2, net0, state0),
        || gadgets::ohv::rand_ohv::<T, _>(k2, net1, state1),
    );
    let (mut r, e) = a?;
    let (r_, e_) = b?;

    // Combine r and r_;
    r <<= k2;
    r += r_;

    // Open the xor of the index and r
    let c = binary::open(&(r ^ index), net0)?;
    let c: usize =
        c.0.try_into()
            .expect("This transformation should work, otherwise we have another issue")
            & ((1 << k) - 1); // Mask potential overflows from non-well-defined input

    let mut results = Vec::with_capacity(luts.len());
    for lut in luts {
        // Start the result with a random mask (for potential resharing later)
        let (mut t, mask_b) = state0
            .rngs
            .rand
            .random_biguint(usize::try_from(F::MODULUS_BIT_SIZE).expect("u32 fits into usize"));
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
                let lut_val: BigUint = lut[index].into();
                let mut g = Rep3BigUintShare::<F>::default();
                if f0.a.0.convert() {
                    g.a ^= &lut_val;
                }
                if f0.b.0.convert() {
                    g.b ^= lut_val;
                }
                if f1.a.0.convert() {
                    t ^= &g.a;
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
pub fn read_shared_lut<F: PrimeField, T: IntRing2k, N: Network>(
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
    for (l, e) in lut.iter().zip(injected.into_iter()) {
        let mul = &e * l;
        t += mul;
    }
    Ok(t)
}

/// Takes a secret-shared lookup table containing field elements, and a replicated binary share of an index and puts another secret-shared field element (value) and puts it at lut`\[`index`\]`.
/// The algorithm is inspired by Protocol 4 from [https://eprint.iacr.org/2024/1317.pdf](https://eprint.iacr.org/2024/1317.pdf).
pub fn write_lut<F: PrimeField, T: IntRing2k, N: Network>(
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
