//! # REP3 Ring
//!
//! This module implements the rep3 share and combine operations for rings

use rand::{distributions::Standard, prelude::Distribution, CryptoRng, Rng};
use ring::{int_ring::IntRing2k, ring_impl::RingElement};

pub mod arithmetic;
pub mod binary;
pub mod ring;

/// Shorthand type for a secret shared bit.
pub type Rep3BitShare = Rep3RingShare<ring::bit::Bit>;
pub use arithmetic::types::Rep3RingShare;

/// Secret shares a ring element using replicated secret sharing and the provided random number generator. The ring element is split into three additive shares, where each party holds two. The outputs are of type [`Rep3RingShare`].
pub fn share_ring_element<T: IntRing2k, R: Rng + CryptoRng>(
    val: RingElement<T>,
    rng: &mut R,
) -> [Rep3RingShare<T>; 3]
where
    Standard: Distribution<T>,
{
    let a = rng.gen::<RingElement<T>>();
    let b = rng.gen::<RingElement<T>>();

    let c = val - a - b;
    let share1 = Rep3RingShare::new_ring(a, c);
    let share2 = Rep3RingShare::new_ring(b, a);
    let share3 = Rep3RingShare::new_ring(c, b);
    [share1, share2, share3]
}

/// Secret shares a vector of ring elements using replicated secret sharing and the provided random number generator. The ring elements are split into three additive shares each, where each party holds two. The outputs are of type [`Rep3RingShare`].
pub fn share_ring_elements<T: IntRing2k, R: Rng + CryptoRng>(
    vals: &[RingElement<T>],
    rng: &mut R,
) -> [Vec<Rep3RingShare<T>>; 3]
where
    Standard: Distribution<T>,
{
    let mut shares1 = Vec::with_capacity(vals.len());
    let mut shares2 = Vec::with_capacity(vals.len());
    let mut shares3 = Vec::with_capacity(vals.len());
    for val in vals {
        let [share1, share2, share3] = share_ring_element(val.to_owned(), rng);
        shares1.push(share1);
        shares2.push(share2);
        shares3.push(share3);
    }
    [shares1, shares2, shares3]
}

/// Secret shares a ring element using replicated secret sharing and the provided random number generator. The ring element is split into three binary shares, where each party holds two. The outputs are of type [`Rep3RingShare`].
pub fn share_ring_element_binary<T: IntRing2k, R: Rng + CryptoRng>(
    val: RingElement<T>,
    rng: &mut R,
) -> [Rep3RingShare<T>; 3]
where
    Standard: Distribution<T>,
{
    let a = rng.gen::<RingElement<T>>();
    let b = rng.gen::<RingElement<T>>();
    let c = val ^ a ^ b;
    let share1 = Rep3RingShare::new_ring(a, c);
    let share2 = Rep3RingShare::new_ring(b, a);
    let share3 = Rep3RingShare::new_ring(c, b);
    [share1, share2, share3]
}

/// Secret shares a vector of ring elements using replicated secret sharing and the provided random number generator. The ring elements are split into three binary shares each, where each party holds two. The outputs are of type [`Rep3RingShare`].
pub fn share_ring_elements_binary<T: IntRing2k, R: Rng + CryptoRng>(
    vals: &[RingElement<T>],
    rng: &mut R,
) -> [Vec<Rep3RingShare<T>>; 3]
where
    Standard: Distribution<T>,
{
    let mut shares1 = Vec::with_capacity(vals.len());
    let mut shares2 = Vec::with_capacity(vals.len());
    let mut shares3 = Vec::with_capacity(vals.len());
    for val in vals {
        let [share1, share2, share3] = share_ring_element_binary(val.to_owned(), rng);
        shares1.push(share1);
        shares2.push(share2);
        shares3.push(share3);
    }
    [shares1, shares2, shares3]
}

/// Reconstructs a ring element from its arithmetic replicated shares.
pub fn combine_ring_element<T: IntRing2k>(
    share1: Rep3RingShare<T>,
    share2: Rep3RingShare<T>,
    share3: Rep3RingShare<T>,
) -> RingElement<T> {
    share1.a + share2.a + share3.a
}

/// Reconstructs a vector of ring elements from its arithmetic replicated shares.
/// # Panics
/// Panics if the provided `Vec` sizes do not match.
pub fn combine_ring_elements<T: IntRing2k>(
    share1: &[Rep3RingShare<T>],
    share2: &[Rep3RingShare<T>],
    share3: &[Rep3RingShare<T>],
) -> Vec<RingElement<T>> {
    assert_eq!(share1.len(), share2.len());
    assert_eq!(share2.len(), share3.len());

    itertools::multizip((share1, share2, share3))
        .map(|(x1, x2, x3)| x1.a + x2.a + x3.a)
        .collect::<Vec<_>>()
}

/// Reconstructs a ring element from its binary replicated shares.
pub fn combine_ring_element_binary<T: IntRing2k>(
    share1: Rep3RingShare<T>,
    share2: Rep3RingShare<T>,
    share3: Rep3RingShare<T>,
) -> RingElement<T> {
    share1.a ^ share2.a ^ share3.a
}
