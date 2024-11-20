//! Conversions
//!
//! This module contains conversions between share types

use super::{
    arithmetic::types::Rep3RingShare,
    ring::{bit::Bit, int_ring::IntRing2k, ring_impl::RingElement},
};
use crate::protocols::{
    rep3::{
        id::PartyID,
        network::{IoContext, Rep3Network},
        IoResult,
    },
    rep3_ring::arithmetic,
};
use itertools::izip;
use rand::{distributions::Standard, prelude::Distribution};

/// Translates one shared bit into an arithmetic sharing of the same bit. I.e., the shared bit x = x_1 xor x_2 xor x_3 gets transformed into x = x'_1 + x'_2 + x'_3, with x being either 0 or 1.
pub fn bit_inject<T: IntRing2k, N: Rep3Network>(
    x: &Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    // standard bit inject
    assert!(x.a.bits() <= 1);

    let mut b0 = Rep3RingShare::default();
    let mut b1 = Rep3RingShare::default();
    let mut b2 = Rep3RingShare::default();

    match io_context.id {
        PartyID::ID0 => {
            b0.a = x.a.to_owned();
            b2.b = x.b.to_owned();
        }
        PartyID::ID1 => {
            b1.a = x.a.to_owned();
            b0.b = x.b.to_owned();
        }
        PartyID::ID2 => {
            b2.a = x.a.to_owned();
            b1.b = x.b.to_owned();
        }
    };

    let d = arithmetic::arithmetic_xor(b0, b1, io_context)?;
    let e = arithmetic::arithmetic_xor(d, b2, io_context)?;
    Ok(e)
}

/// Translates a vector of shared bits into a vector of arithmetic sharings of the same bits. See [bit_inject] for details.
pub fn bit_inject_many<T: IntRing2k, N: Rep3Network>(
    x: &[Rep3RingShare<T>],
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<Rep3RingShare<T>>>
where
    Standard: Distribution<T>,
{
    // standard bit inject
    assert!(x.iter().all(|a| a.a.bits() <= 1));

    let mut b0 = vec![Rep3RingShare::default(); x.len()];
    let mut b1 = vec![Rep3RingShare::default(); x.len()];
    let mut b2 = vec![Rep3RingShare::default(); x.len()];

    match io_context.id {
        PartyID::ID0 => {
            for (b0, b2, x) in izip!(&mut b0, &mut b2, x.iter().cloned()) {
                b0.a = x.a;
                b2.b = x.b;
            }
        }
        PartyID::ID1 => {
            for (b1, b0, x) in izip!(&mut b1, &mut b0, x.iter().cloned()) {
                b1.a = x.a;
                b0.b = x.b;
            }
        }
        PartyID::ID2 => {
            for (b2, b1, x) in izip!(&mut b2, &mut b1, x.iter().cloned()) {
                b2.a = x.a;
                b1.b = x.b;
            }
        }
    };

    let d = arithmetic::arithmetic_xor_many(&b0, &b1, io_context)?;
    let e = arithmetic::arithmetic_xor_many(&d, &b2, io_context)?;
    Ok(e)
}

/// Translates one shared bit into an arithmetic sharing of the same bit. I.e., the shared bit x = x_1 xor x_2 xor x_3 gets transformed into x = x'_1 + x'_2 + x'_3, with x being either 0 or 1.
pub fn bit_inject_from_bit<T: IntRing2k, N: Rep3Network>(
    x: &Rep3RingShare<Bit>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    // standard bit inject
    assert!(x.a.bits() <= 1);

    let mut b0 = Rep3RingShare::default();
    let mut b1 = Rep3RingShare::default();
    let mut b2 = Rep3RingShare::default();

    match io_context.id {
        PartyID::ID0 => {
            b0.a = RingElement(T::from(x.a.0.convert()));
            b2.b = RingElement(T::from(x.b.0.convert()));
        }
        PartyID::ID1 => {
            b1.a = RingElement(T::from(x.a.0.convert()));
            b0.b = RingElement(T::from(x.b.0.convert()));
        }
        PartyID::ID2 => {
            b2.a = RingElement(T::from(x.a.0.convert()));
            b1.b = RingElement(T::from(x.b.0.convert()));
        }
    };

    let d = arithmetic::arithmetic_xor(b0, b1, io_context)?;
    let e = arithmetic::arithmetic_xor(d, b2, io_context)?;
    Ok(e)
}

/// Translates a vector of shared bits into a vector of arithmetic sharings of the same bits. See [bit_inject] for details.
pub fn bit_inject_from_bits_many<T: IntRing2k, N: Rep3Network>(
    x: &[Rep3RingShare<Bit>],
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<Rep3RingShare<T>>>
where
    Standard: Distribution<T>,
{
    let mut b0 = vec![Rep3RingShare::default(); x.len()];
    let mut b1 = vec![Rep3RingShare::default(); x.len()];
    let mut b2 = vec![Rep3RingShare::default(); x.len()];

    match io_context.id {
        PartyID::ID0 => {
            for (b0, b2, x) in izip!(&mut b0, &mut b2, x.iter().cloned()) {
                b0.a = RingElement(T::from(x.a.0.convert()));
                b2.b = RingElement(T::from(x.b.0.convert()));
            }
        }
        PartyID::ID1 => {
            for (b1, b0, x) in izip!(&mut b1, &mut b0, x.iter().cloned()) {
                b1.a = RingElement(T::from(x.a.0.convert()));
                b0.b = RingElement(T::from(x.b.0.convert()));
            }
        }
        PartyID::ID2 => {
            for (b2, b1, x) in izip!(&mut b2, &mut b1, x.iter().cloned()) {
                b2.a = RingElement(T::from(x.a.0.convert()));
                b1.b = RingElement(T::from(x.b.0.convert()));
            }
        }
    };

    let d = arithmetic::arithmetic_xor_many(&b0, &b1, io_context)?;
    let e = arithmetic::arithmetic_xor_many(&d, &b2, io_context)?;
    Ok(e)
}
