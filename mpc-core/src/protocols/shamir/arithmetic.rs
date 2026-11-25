//! Arithmetic
//!
//! This module contains operations with arithmetic shares

use ark_ff::PrimeField;
use itertools::izip;
use mpc_net::Network;
use rayon::prelude::*;

use super::{
    ShamirPrimeFieldShare, ShamirState,
    network::{MIN_PAR_LEN, ShamirNetworkExt},
};

mod ops;
pub(super) mod types;

type ShamirShare<F> = ShamirPrimeFieldShare<F>;

/// Performs addition between two shares.
pub fn add<F: PrimeField>(a: ShamirShare<F>, b: ShamirShare<F>) -> ShamirShare<F> {
    a + b
}

/// Performs addition between two shares where the result is stored in `a`.
pub fn add_assign<F: PrimeField>(a: &mut ShamirShare<F>, b: ShamirShare<F>) {
    *a += b;
}

/// Performs subtraction between two shares.
pub fn sub<F: PrimeField>(a: ShamirShare<F>, b: ShamirShare<F>) -> ShamirShare<F> {
    a - b
}

/// Performs subtraction between two shares where the result is stored in `a`.
pub fn sub_assign<F: PrimeField>(a: &mut ShamirShare<F>, b: ShamirShare<F>) {
    *a -= b;
}

/// Performs element-wise subtraction of two slices of shares and stores the result in `lhs`.
pub fn sub_vec_assign<F: PrimeField>(lhs: &mut [ShamirShare<F>], rhs: &[ShamirShare<F>]) {
    for (a, b) in izip!(lhs.iter_mut(), rhs.iter()) {
        *a -= *b;
    }
}

/// Performs addition between a share and a public value.
pub fn add_public<F: PrimeField>(shared: ShamirShare<F>, public: F) -> ShamirShare<F> {
    shared + public
}

/// Performs addition between a share and a public value where the result is stored in `shared`.
pub fn add_assign_public<F: PrimeField>(shared: &mut ShamirShare<F>, public: F) {
    *shared += public;
}

/// Performs element-wise addition of two slices of shares and stores the result in `lhs`.
pub fn add_vec_assign<F: PrimeField>(lhs: &mut [ShamirShare<F>], rhs: &[ShamirShare<F>]) {
    for (a, b) in izip!(lhs.iter_mut(), rhs.iter()) {
        *a += b;
    }
}

/// Performs multiplication between two shares.
pub fn mul<F: PrimeField, N: Network>(
    a: ShamirShare<F>,
    b: ShamirShare<F>,
    net: &N,
    state: &mut ShamirState<F>,
) -> eyre::Result<ShamirShare<F>> {
    let mul = a.a * b.a;
    net.degree_reduce(state, mul)
}

/// Performs multiplication between two shares. *DOES NOT REDUCE DEGREE*
pub fn local_mul_vec<F: PrimeField>(a: &[ShamirShare<F>], b: &[ShamirShare<F>]) -> Vec<F> {
    a.par_iter()
        .zip_eq(b.par_iter())
        .with_min_len(1024)
        .map(|(a, b)| a.a * b.a)
        .collect::<Vec<_>>()
}

/// Performs element-wise multiplication of two slices of shares.
pub fn mul_vec<F: PrimeField, N: Network>(
    a: &[ShamirShare<F>],
    b: &[ShamirShare<F>],
    net: &N,
    state: &mut ShamirState<F>,
) -> eyre::Result<Vec<ShamirShare<F>>> {
    //do not use local_mul_vec as it uses rayon and this method runs on
    //the tokio runtime. This method is for smaller vecs, local_mul_vec and then
    //degree_reduce for larger vecs.
    let mul = a
        .iter()
        .zip(b.iter())
        .map(|(a, b)| a.a * b.a)
        .collect::<Vec<_>>();
    net.degree_reduce_many(state, mul)
}

/// Performs multiplication between a share and a public value.
pub fn mul_public<F: PrimeField>(shared: ShamirShare<F>, public: F) -> ShamirShare<F> {
    shared * public
}

/// Performs multiplication between a share and a public value where the result is stored in `shared`.
pub fn mul_assign_public<F: PrimeField>(shared: &mut ShamirShare<F>, public: F) {
    *shared *= public;
}

/// Performs division of two shared values, returning a / b.
pub fn div<F: PrimeField, N: Network>(
    a: ShamirShare<F>,
    b: ShamirShare<F>,
    net: &N,
    state: &mut ShamirState<F>,
) -> eyre::Result<ShamirShare<F>> {
    mul(a, inv(b, net, state)?, net, state)
}

/// Performs division of a shared value by a public value, returning shared / public.
pub fn div_shared_by_public<F: PrimeField>(
    shared: ShamirShare<F>,
    public: F,
) -> eyre::Result<ShamirShare<F>> {
    if public.is_zero() {
        eyre::bail!("Cannot invert zero");
    }
    let b_inv = public.inverse().unwrap();
    Ok(mul_public(shared, b_inv))
}

/// Performs division of a public value by a shared value, returning public / shared.
pub fn div_public_by_shared<F: PrimeField, N: Network>(
    public: F,
    shared: ShamirShare<F>,
    net: &N,
    state: &mut ShamirState<F>,
) -> eyre::Result<ShamirShare<F>> {
    Ok(mul_public(inv(shared, net, state)?, public))
}

/// Computes the inverse of a shared field element
pub fn inv<F: PrimeField, N: Network>(
    a: ShamirShare<F>,
    net: &N,
    state: &mut ShamirState<F>,
) -> eyre::Result<ShamirShare<F>> {
    let r = state.rand(net)?;
    let y = mul_open(a, r, net, state)?;
    if y.is_zero() {
        eyre::bail!("Cannot compute inverse of zero");
    }
    let y_inv = y.inverse().unwrap();
    Ok(r * y_inv)
}

/// Computes the inverse of a vector of shared field elements
pub fn inv_vec<F: PrimeField, N: Network>(
    a: &[ShamirShare<F>],
    net: &N,
    state: &mut ShamirState<F>,
) -> eyre::Result<Vec<ShamirShare<F>>> {
    let r = state.rand_vec(net, a.len())?;
    let y = mul_open_vec(a, &r, net, state)?;
    if y.iter().any(|y| y.is_zero()) {
        eyre::bail!("Cannot compute inverse of zero");
    }

    // we can unwrap as we checked that none of the y is zero
    Ok(izip!(r, y).map(|(r, y)| r * y.inverse().unwrap()).collect())
}

/// Performs negation of a share
pub fn neg<F: PrimeField>(a: ShamirShare<F>) -> ShamirShare<F> {
    -a
}

/// Opens a shared value and returns the corresponding field element.
pub fn open<F: PrimeField, N: Network>(
    a: ShamirShare<F>,
    net: &N,
    state: &mut ShamirState<F>,
) -> eyre::Result<F> {
    let rcv = net.broadcast_next(state.num_parties, state.threshold + 1, a.a)?;
    let res = super::reconstruct(&rcv, &state.open_lagrange_t);
    Ok(res)
}

/// Opens a vector of shared values and returns the corresponding field elements.
pub fn open_vec<F: PrimeField, N: Network>(
    a: &[ShamirShare<F>],
    net: &N,
    state: &mut ShamirState<F>,
) -> eyre::Result<Vec<F>> {
    let a_a = ShamirShare::convert_slice(a);

    let rcv = net.broadcast_next(state.num_parties, state.threshold + 1, a_a.to_owned())?;
    reconstruct_vec(a.len(), &rcv, &state.open_lagrange_t)
}

/// Reconstructs `len` values, where `shares[j]` are all shares which belong to `lagrange[j]`.
fn reconstruct_vec<F: PrimeField>(
    len: usize,
    shares: &[Vec<F>],
    lagrange: &[F],
) -> eyre::Result<Vec<F>> {
    debug_assert_eq!(shares.len(), lagrange.len());
    if shares.iter().any(|s| s.len() != len) {
        eyre::bail!("During execution of open in MPC: Invalid number of elements received");
    }
    let reconstruct = |i: usize| {
        shares
            .iter()
            .zip(lagrange.iter())
            .map(|(s, l)| s[i] * l)
            .sum::<F>()
    };
    let res = if len < MIN_PAR_LEN {
        (0..len).map(reconstruct).collect()
    } else {
        (0..len)
            .into_par_iter()
            .with_min_len(MIN_PAR_LEN)
            .map(reconstruct)
            .collect()
    };
    Ok(res)
}

/*
fn neg_vec_in_place(vec: &mut ShamirShare<F>Vec) {
    for a in vec.a.iter_mut() {
        a.neg_in_place();
    }
}
*/

/// Promotes a public value to a trivial share.
pub fn promote_to_trivial_share<F: PrimeField>(public_value: F) -> ShamirShare<F> {
    ShamirShare::<F>::new(public_value)
}

/// Promotes a vector of public values to trivial shares.
pub fn promote_to_trivial_shares<F: PrimeField>(public_values: &[F]) -> Vec<ShamirShare<F>> {
    ShamirShare::convert_vec_rev(public_values.to_owned())
}

/*
fn clone_from_slice(
    &self,
    dst: &mut ShamirShare<F>Vec,
    src: &ShamirShare<F>Vec,
    dst_offset: usize,
    src_offset: usize,
    len: usize,
) {
    assert!(dst.a.len() >= dst_offset + len);
    assert!(src.a.len() >= src_offset + len);
    assert!(len > 0);
    dst.a[dst_offset..dst_offset + len].clone_from_slice(&src.a[src_offset..src_offset + len]);
}
*/

/// This function performs a multiplication directly followed by an opening. This is preferred over Open(Mul(\[x\], \[y\])), since Mul performs resharing of the result for degree reduction. Thus, mul_open(\[x\], \[y\]) requires less communication in fewer rounds compared to Open(Mul(\[x\], \[y\])).
///
/// Consumes one correlated randomness pair to randomize the degree-2t sharing before it is opened.
fn mul_open<F: PrimeField, N: Network>(
    a: ShamirShare<F>,
    b: ShamirShare<F>,
    net: &N,
    state: &mut ShamirState<F>,
) -> eyre::Result<F> {
    // The product share must be masked with a degree-2t sharing of zero, otherwise the
    // opened shares reveal the product of the two sharing polynomials and thus the inputs.
    let mul = (a * b).a + state.zero_share_2t(net)?;
    let rcv = net.broadcast_next(state.num_parties, 2 * state.threshold + 1, mul)?;
    Ok(super::reconstruct(&rcv, &state.open_lagrange_2t))
}

/// This function performs a multiplication directly followed, by an opening. This is preferred over Open(Mul(\[x\], \[y\])), since Mul performs resharing of the result for degree reduction. Thus, mul_open(\[x\], \[y\]) requires less communication in fewer rounds compared to Open(Mul(\[x\], \[y\])).
///
/// Consumes one correlated randomness pair per element to randomize the degree-2t sharings before they are opened.
pub fn mul_open_vec<F: PrimeField, N: Network>(
    a: &[ShamirShare<F>],
    b: &[ShamirShare<F>],
    net: &N,
    state: &mut ShamirState<F>,
) -> eyre::Result<Vec<F>> {
    if a.len() != b.len() {
        eyre::bail!("mul_open_vec: length mismatch ({} != {})", a.len(), b.len());
    }
    // The product shares must be masked with degree-2t sharings of zero, otherwise the
    // opened shares reveal the product of the two sharing polynomials and thus the inputs.
    let zeros = state.zero_shares_2t(net, a.len())?;
    let mul = izip!(a, b, zeros)
        .map(|(a, b, zero)| a.a * b.a + zero)
        .collect::<Vec<F>>();

    let rcv = net.broadcast_next(state.num_parties, 2 * state.threshold + 1, mul)?;

    reconstruct_vec(a.len(), &rcv, &state.open_lagrange_2t)
}
