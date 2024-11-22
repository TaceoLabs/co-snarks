//! Casts
//!
//! Implements casts for sharings of different datatypes

use super::{
    arithmetic::types::Rep3RingShare,
    conversion,
    ring::{bit::Bit, int_ring::IntRing2k},
    yao,
};
use crate::protocols::{
    rep3::{
        self,
        conversion::A2BType,
        network::{IoContext, Rep3Network},
        Rep3BigUintShare, Rep3PrimeFieldShare,
    },
    rep3_ring::ring::ring_impl::RingElement,
};
use ark_ff::PrimeField;
use num_bigint::BigUint;
use num_traits::AsPrimitive;
use rand::{distributions::Standard, prelude::Distribution};
use std::any::TypeId;

/// Depending on the `A2BType` of the io_context, this function selects the appropriate implementation for the ring cast.
pub fn ring_cast_selector<T, U, N>(
    x: Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> std::io::Result<Rep3RingShare<U>>
where
    T: IntRing2k + AsPrimitive<U>,
    U: IntRing2k,
    N: Rep3Network,
    Standard: Distribution<T> + Distribution<U>,
{
    match io_context.a2b_type {
        A2BType::Direct => cast_a2b(x, io_context),
        A2BType::Yao => cast_gc(x, io_context),
        A2BType::StreamingYao => {
            tracing::warn!("StreamingYao not implemented for ring casts, falling back to Yao");
            cast_gc(x, io_context)
        }
    }
}

/// Depending on the `A2BType` of the io_context, this function selects the appropriate implementation for the ring_to_field cast.
pub fn ring_to_field_selector<T: IntRing2k, F: PrimeField, N: Rep3Network>(
    x: Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> std::io::Result<Rep3PrimeFieldShare<F>>
where
    Standard: Distribution<T>,
{
    match io_context.a2b_type {
        A2BType::Direct => ring_to_field_a2b(x, io_context),
        A2BType::Yao => Ok(yao::ring_to_field_many(&[x], io_context)?[0]),
        A2BType::StreamingYao => {
            tracing::warn!(
                "StreamingYao not implemented for ring_to_field casts, falling back to Yao"
            );
            Ok(yao::ring_to_field_many(&[x], io_context)?[0])
        }
    }
}

/// Depending on the `A2BType` of the io_context, this function selects the appropriate implementation for the field_to_ring cast.
pub fn field_to_ring_selector<F: PrimeField, T: IntRing2k, N: Rep3Network>(
    x: Rep3PrimeFieldShare<F>,
    io_context: &mut IoContext<N>,
) -> std::io::Result<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    match io_context.a2b_type {
        A2BType::Direct => field_to_ring_a2b(x, io_context),
        A2BType::Yao => Ok(yao::field_to_ring_many(&[x], io_context)?[0]),
        A2BType::StreamingYao => {
            tracing::warn!(
                "StreamingYao not implemented for field_to_ring casts, falling back to Yao"
            );
            Ok(yao::field_to_ring_many(&[x], io_context)?[0])
        }
    }
}

/// A downcast of a Rep3RingShare from a larger ring to a smaller ring
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
    io_context: &mut IoContext<N>,
) -> std::io::Result<Rep3RingShare<U>>
where
    T: IntRing2k + AsPrimitive<U>,
    U: IntRing2k,
    N: Rep3Network,
    Standard: Distribution<T> + Distribution<U>,
{
    assert!(T::K < U::K);

    // A special case for Bit
    if TypeId::of::<T>() == TypeId::of::<Bit>() {
        // SAFTEY: We already checked that the type matches
        let share = unsafe { &*(&share as *const Rep3RingShare<T> as *const Rep3RingShare<Bit>) };
        return conversion::bit_inject_from_bit(share, io_context);
    }

    let binary = conversion::a2b(share, io_context)?;
    let binary = Rep3RingShare {
        a: RingElement(binary.a.0.as_()),
        b: RingElement(binary.b.0.as_()),
    };
    conversion::b2a(&binary, io_context)
}

/// A cast of a Rep3RingShare from a ring to another ring
pub fn cast_a2b<T, U, N>(
    share: Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> std::io::Result<Rep3RingShare<U>>
where
    T: IntRing2k + AsPrimitive<U>,
    U: IntRing2k,
    N: Rep3Network,
    Standard: Distribution<T> + Distribution<U>,
{
    if T::K >= U::K {
        Ok(downcast(share))
    } else {
        upcast_a2b(share, io_context)
    }
}

/// A cast of a Rep3RingShare from a ring to another ring
pub fn cast_gc<T, U, N>(
    share: Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> std::io::Result<Rep3RingShare<U>>
where
    T: IntRing2k + AsPrimitive<U>,
    U: IntRing2k,
    N: Rep3Network,
    Standard: Distribution<T> + Distribution<U>,
{
    if T::K >= U::K {
        Ok(downcast(share))
    } else {
        Ok(yao::upcast_many(&[share], io_context)?[0])
    }
}

/// A cast of a Rep3PrimeFieldShare to a Rep3RingShare
pub fn field_to_ring_a2b<F: PrimeField, T: IntRing2k, N: Rep3Network>(
    share: Rep3PrimeFieldShare<F>,
    io_context: &mut IoContext<N>,
) -> std::io::Result<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    let binary = rep3::conversion::a2b(share, io_context)?;
    let ring_share = Rep3RingShare {
        a: RingElement(T::cast_from_biguint(&binary.a)),
        b: RingElement(T::cast_from_biguint(&binary.b)),
    };
    conversion::b2a(&ring_share, io_context)
}

/// A cast of a Rep3RingShare to a Rep3PrimeFieldShare
pub fn ring_to_field_a2b<T: IntRing2k, F: PrimeField, N: Rep3Network>(
    share: Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> std::io::Result<Rep3PrimeFieldShare<F>>
where
    Standard: Distribution<T>,
{
    // A special case for Bit
    if TypeId::of::<T>() == TypeId::of::<Bit>() {
        // SAFTEY: We already checked that the type matches
        let share = unsafe { &*(&share as *const Rep3RingShare<T> as *const Rep3RingShare<Bit>) };
        let biguint_share = Rep3BigUintShare::new(
            BigUint::from(share.a.0.convert() as u64),
            BigUint::from(share.b.0.convert() as u64),
        );

        return rep3::conversion::bit_inject(&biguint_share, io_context);
    }

    let binary = conversion::a2b(share, io_context)?;
    let biguint_share = Rep3BigUintShare::new(
        T::cast_to_biguint(&binary.a.0),
        T::cast_to_biguint(&binary.b.0),
    );
    rep3::conversion::b2a(&biguint_share, io_context)
}
