//! Casts
//!
//! Implements casts for sharings of different datatypes

use super::{Rep3RingShare, conversion, ring::int_ring::IntRing2k, yao};
use crate::protocols::{
    rep3::{self, Rep3BigUintShare, Rep3PrimeFieldShare, Rep3State, conversion::A2BType},
    rep3_ring::ring::{bit::Bit, ring_impl::RingElement},
};
use ark_ff::PrimeField;
use mpc_net::Network;
use num_bigint::BigUint;
use num_traits::AsPrimitive;
use rand::{distributions::Standard, prelude::Distribution};
use std::any::TypeId;

/// Depending on the `A2BType` of the state, this function selects the appropriate implementation for the ring cast. In case of a downcast, the excess bits are just truncated.
pub fn ring_cast_selector<T, U, N>(
    x: Rep3RingShare<T>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3RingShare<U>>
where
    T: IntRing2k + AsPrimitive<U>,
    U: IntRing2k,
    N: Network,
    Standard: Distribution<T> + Distribution<U>,
{
    match state.a2b_type {
        A2BType::Direct => cast_a2b(x, net, state),
        A2BType::Yao => cast_gc(x, net, state),
    }
}

/// Depending on the `A2BType` of the state, this function selects the appropriate implementation for the ring_to_field cast.
pub fn ring_to_field_selector<T: IntRing2k, F: PrimeField, N: Network>(
    x: Rep3RingShare<T>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3PrimeFieldShare<F>>
where
    Standard: Distribution<T>,
{
    match state.a2b_type {
        A2BType::Direct => ring_to_field_a2b(x, net, state),
        A2BType::Yao => Ok(yao::ring_to_field_many(&[x], net, state)?[0]),
    }
}

/// Depending on the `A2BType` of the state, this function selects the appropriate implementation for the field_to_ring cast.
pub fn field_to_ring_selector<F: PrimeField, T: IntRing2k, N: Network>(
    x: Rep3PrimeFieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    match state.a2b_type {
        A2BType::Direct => field_to_ring_a2b(x, net, state),
        A2BType::Yao => Ok(yao::field_to_ring_many(&[x], net, state)?[0]),
    }
}

/// A downcast of a Rep3RingShare from a larger ring to a smaller ring, truncating the excess bits.
/// Does not require network interaction
pub fn downcast<T, U>(share: Rep3RingShare<T>) -> Rep3RingShare<U>
where
    T: IntRing2k + AsPrimitive<U>,
    U: IntRing2k,
{
    assert!(T::K >= U::K);

    Rep3RingShare {
        a: RingElement(share.a.0.as_()),
        b: RingElement(share.b.0.as_()),
    }
}

/// An upcast of a Rep3RingShare from a smaller ring to a larger ring
/// Does require network interaction
pub fn upcast_a2b<T, U, N>(
    share: Rep3RingShare<T>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3RingShare<U>>
where
    T: IntRing2k + AsPrimitive<U>,
    U: IntRing2k,
    N: Network,
    Standard: Distribution<T> + Distribution<U>,
{
    assert!(T::K < U::K);

    // A special case for Bit
    if TypeId::of::<T>() == TypeId::of::<Bit>() {
        let share = crate::downcast(&share).expect("We already checked types");
        return conversion::bit_inject_from_bit(share, net, state);
    }

    let binary = conversion::a2b(share, net, state)?;
    let binary = Rep3RingShare {
        a: RingElement(binary.a.0.as_()),
        b: RingElement(binary.b.0.as_()),
    };
    conversion::b2a(&binary, net, state)
}

/// A cast of a Rep3RingShare from a ring to another ring. In case of a downcast, the excess bits are just truncated.
pub fn cast_a2b<T, U, N>(
    share: Rep3RingShare<T>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3RingShare<U>>
where
    T: IntRing2k + AsPrimitive<U>,
    U: IntRing2k,
    N: Network,
    Standard: Distribution<T> + Distribution<U>,
{
    if T::K >= U::K {
        Ok(downcast(share))
    } else {
        upcast_a2b(share, net, state)
    }
}

/// A cast of a Rep3RingShare from a ring to another ring. In case of a downcast, the excess bits are just truncated.
pub fn cast_gc<T, U, N>(
    share: Rep3RingShare<T>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3RingShare<U>>
where
    T: IntRing2k + AsPrimitive<U>,
    U: IntRing2k,
    N: Network,
    Standard: Distribution<T> + Distribution<U>,
{
    if T::K >= U::K {
        Ok(downcast(share))
    } else {
        Ok(yao::upcast_many(&[share], net, state)?[0])
    }
}

/// A cast of a Rep3PrimeFieldShare to a Rep3RingShare. Truncates the excess bits.
pub fn field_to_ring_a2b<F: PrimeField, T: IntRing2k, N: Network>(
    share: Rep3PrimeFieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    let binary = rep3::conversion::a2b(share, net, state)?;
    let ring_share = Rep3RingShare {
        a: RingElement(T::cast_from_biguint(&binary.a)),
        b: RingElement(T::cast_from_biguint(&binary.b)),
    };
    conversion::b2a(&ring_share, net, state)
}

/// A cast of a Rep3PrimeFieldShare to a Rep3RingShare. Truncates the excess bits.
pub fn field_to_ring_a2b_many<F: PrimeField, T: IntRing2k, N: Network>(
    shares: &[Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3RingShare<T>>>
where
    Standard: Distribution<T>,
{
    let binary = rep3::conversion::a2b_many(shares, net, state)?;
    let ring_shares = binary
        .into_iter()
        .map(|binary| Rep3RingShare {
            a: RingElement(T::cast_from_biguint(&binary.a)),
            b: RingElement(T::cast_from_biguint(&binary.b)),
        })
        .collect::<Vec<_>>();
    conversion::b2a_many(&ring_shares, net, state)
}

/// A cast of a Rep3RingShare to a Rep3PrimeFieldShare
pub fn ring_to_field_a2b<T: IntRing2k, F: PrimeField, N: Network>(
    share: Rep3RingShare<T>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3PrimeFieldShare<F>>
where
    Standard: Distribution<T>,
{
    // A special case for Bit
    if TypeId::of::<T>() == TypeId::of::<Bit>() {
        let share =
            crate::downcast::<_, Rep3RingShare<Bit>>(&share).expect("We already checked types");
        let biguint_share = Rep3BigUintShare::new(
            BigUint::from(share.a.0.convert() as u64),
            BigUint::from(share.b.0.convert() as u64),
        );

        return rep3::conversion::bit_inject(&biguint_share, net, state);
    }

    let binary = conversion::a2b(share, net, state)?;
    let biguint_share = Rep3BigUintShare::new(
        T::cast_to_biguint(&binary.a.0),
        T::cast_to_biguint(&binary.b.0),
    );
    rep3::conversion::b2a(&biguint_share, net, state)
}

/// A cast of a Rep3RingShare to a Rep3PrimeFieldShare
pub fn ring_to_field_a2b_many<T: IntRing2k, F: PrimeField, N: Network>(
    shares: &[Rep3RingShare<T>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>>
where
    Standard: Distribution<T>,
{
    // A special case for Bit
    if TypeId::of::<T>() == TypeId::of::<Bit>() {
        let bit_shares = shares
            .iter()
            .map(|share| {
                crate::downcast::<_, Rep3RingShare<Bit>>(share).expect("We already checked types")
            })
            .collect::<Vec<_>>();

        let biguint_shares = bit_shares
            .into_iter()
            .map(|share| Rep3BigUintShare::new(
                BigUint::from(share.a.0.convert() as u64),
                BigUint::from(share.b.0.convert() as u64),
            ))
            .collect::<Vec<_>>();

        return rep3::conversion::bit_inject_many(&biguint_shares, net, state);
    }

    let binary = conversion::a2b_many(shares, net, state)?;
    let biguint_shares = binary
        .into_iter()
        .map(|binary| Rep3BigUintShare::new(
            T::cast_to_biguint(&binary.a.0),
            T::cast_to_biguint(&binary.b.0),
        ))
        .collect::<Vec<_>>();
    rep3::conversion::b2a_many(&biguint_shares, net, state)
}