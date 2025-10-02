//! Lut
//!
//! This module contains some oblivious lookup table algorithms for the Rep3 protocol.

use crate::protocols::{
    rep3::{Rep3PointShare, Rep3PrimeFieldShare, Rep3State, network::Rep3NetworkExt, pointshare},
    rep3_ring::{Rep3RingShare, conversion, gadgets, ring::int_ring::IntRing2k},
};
use ark_ec::CurveGroup;
use mpc_net::Network;
use rand::{distributions::Standard, prelude::Distribution};

/// Takes a public lookup table containing curve points, and a replicated binary share of an index and returns a replicated binary sharing of the looked up value lut`\[`index`\]`. The table size needs to be a power of two. If this is not the case, the table is implicitly padded with 0.
/// The algorithm is a rewrite of Protocol 4 from [https://eprint.iacr.org/2024/1317.pdf](https://eprint.iacr.org/2024/1317.pdf) for rep3.
pub fn read_public_lut<C: CurveGroup, T: IntRing2k, N: Network>(
    lut: &[C],
    index: Rep3RingShare<T>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3PointShare<C>>
where
    Standard: Distribution<T>,
{
    let n = lut.len();
    let k = n.next_power_of_two().ilog2() as usize;

    assert!(k <= T::K);
    let e = gadgets::ohv::ohv::<T, _>(k, index, net, state)?;

    // TACEO TODO: is there a better way to do this?
    let injected =
        conversion::bit_inject_from_bits_to_field_many::<C::ScalarField, _>(&e, net, state)?;

    let mut t = Rep3PointShare::default();
    for (l, e) in lut.iter().zip(injected.into_iter()) {
        let mul = pointshare::scalar_mul_public_point(l, e);
        t += &mul;
    }

    Ok(t)
}

/// Takes many public lookup tables containing curve points, and a replicated binary share of an index and returns a replicated binary sharing of the looked up value lut`\[`index`\]`. The table size needs to be a power of two. If this is not the case, the table is implicitly padded with 0.
/// The algorithm is a rewrite of Protocol 4 from [https://eprint.iacr.org/2024/1317.pdf](https://eprint.iacr.org/2024/1317.pdf) for rep3.
pub fn read_public_luts<C: CurveGroup, T: IntRing2k, N: Network>(
    luts: &[Vec<C>],
    index: Rep3RingShare<T>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3PointShare<C>>>
where
    Standard: Distribution<T>,
{
    let n = luts.len();
    let k = n.next_power_of_two().ilog2() as usize;

    assert!(k <= T::K);
    let e = gadgets::ohv::ohv::<T, _>(k, index, net, state)?;

    // TACEO TODO: is there a better way to do this?
    let injected =
        conversion::bit_inject_from_bits_to_field_many::<C::ScalarField, _>(&e, net, state)?;

    let mut results = Vec::with_capacity(luts.len());
    for lut in luts {
        let mut res = Rep3PointShare::default();
        for (l, e) in lut.iter().zip(injected.iter()) {
            let mul = pointshare::scalar_mul_public_point(l, *e);
            res += &mul;
        }
        results.push(res);
    }

    Ok(results)
}

/// Takes a secret-shared lookup table containing curve points, and a replicated binary share of an index and returns a non-replicated additive sharing of the looked up value lut`\[`index`\]`.
/// The algorithm is inspired by Protocol 4 from [https://eprint.iacr.org/2024/1317.pdf](https://eprint.iacr.org/2024/1317.pdf).
pub fn read_shared_lut<C: CurveGroup, T: IntRing2k, N: Network>(
    lut: &[Rep3PointShare<C>],
    index: Rep3RingShare<T>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<C>
where
    Standard: Distribution<T>,
{
    let n = lut.len();
    let k = n.next_power_of_two().ilog2() as usize;
    assert!(k <= T::K);

    let e = gadgets::ohv::ohv::<T, _>(k, index, net, state)?;

    let injected =
        conversion::bit_inject_from_bits_to_field_many::<C::ScalarField, _>(&e, net, state)?;

    // Start the result with a random mask (for potential resharing later)
    let mut t = state.rngs.rand.masking_ec_element::<C>();
    for (l, e) in lut.iter().zip(injected.into_iter()) {
        let mul = e * l;
        t += &mul;
    }
    Ok(t)
}

/// Takes a secret-shared lookup table containing curve points, and a replicated binary share of an index and puts another secret-shared curve point (value) and puts it at lut`\[`index`\]`.
/// The algorithm is inspired by Protocol 4 from [https://eprint.iacr.org/2024/1317.pdf](https://eprint.iacr.org/2024/1317.pdf).
pub fn write_lut<C: CurveGroup, T: IntRing2k, N: Network>(
    value: &Rep3PointShare<C>,
    lut: &mut [Rep3PointShare<C>],
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
    let injected =
        conversion::bit_inject_from_bits_to_field_many::<C::ScalarField, _>(&e, net, state)?;

    write_lut_from_ohv(value, lut, &injected, net, state)
}

/// The second part of writing to a shared lookup table, i.e, takes the shared value, the shared LUT and and one_hot_vector (all elements 0 except for the index to write to which is set to one) and writes to the shared LUT.
pub fn write_lut_from_ohv<C: CurveGroup, N: Network>(
    value: &Rep3PointShare<C>,
    lut: &mut [Rep3PointShare<C>],
    ohv: &[Rep3PrimeFieldShare<C::ScalarField>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<()> {
    let n = lut.len();
    assert!(n <= ohv.len());
    let mut local_a = Vec::with_capacity(n);
    for (l, e) in lut.iter().zip(ohv.iter()) {
        local_a.push(*e * &(value - l) + l.a + state.rngs.rand.masking_ec_element::<C>());
    }
    let local_b = net.reshare_many(&local_a)?;

    for (des, (src_a, src_b)) in lut.iter_mut().zip(local_a.into_iter().zip(local_b)) {
        des.a = src_a;
        des.b = src_b;
    }
    Ok(())
}
