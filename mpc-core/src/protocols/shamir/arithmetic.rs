//! Arithmetic
//!
//! This module contains operations with arithmetic shares

use ark_ff::PrimeField;
use itertools::izip;
use mpc_engine::Network;

use super::{
    core,
    network::{self},
    ShamirProtocol,
};
use rayon::prelude::*;

mod ops;
pub(super) mod types;

type ShamirShare<F> = types::ShamirPrimeFieldShare<F>;

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
    state: &mut ShamirProtocol<F>,
) -> eyre::Result<ShamirShare<F>> {
    let mul = a.a * b.a;
    network::degree_reduce(net, state, mul)
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
    state: &mut ShamirProtocol<F>,
) -> eyre::Result<Vec<ShamirShare<F>>> {
    //do not use local_mul_vec as it uses rayon and this method runs on
    //the tokio runtime. This method is for smaller vecs, local_mul_vec and then
    //degree_reduce for larger vecs.
    let mul = a
        .iter()
        .zip(b.iter())
        .map(|(a, b)| a.a * b.a)
        .collect::<Vec<_>>();
    network::degree_reduce_many(net, state, mul)
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
    state: &mut ShamirProtocol<F>,
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
    state: &mut ShamirProtocol<F>,
) -> eyre::Result<ShamirShare<F>> {
    Ok(mul_public(inv(shared, net, state)?, public))
}

/// Computes the inverse of a shared field element
pub fn inv<F: PrimeField, N: Network>(
    a: ShamirShare<F>,
    net: &N,
    state: &mut ShamirProtocol<F>,
) -> eyre::Result<ShamirShare<F>> {
    let r = state.rand(net)?;
    let y = mul_open(a, r, net, state)?;
    if y.is_zero() {
        eyre::bail!("During execution of inverse in MPC: cannot compute inverse of zero");
    }
    let y_inv = y.inverse().unwrap();
    Ok(r * y_inv)
}

/// Computes the inverse of a vector of shared field elements
pub fn inv_vec<F: PrimeField, N: Network>(
    a: &[ShamirShare<F>],
    net: &N,
    state: &mut ShamirProtocol<F>,
) -> eyre::Result<Vec<ShamirShare<F>>> {
    let r = (0..a.len())
        .map(|_| state.rand(net))
        .collect::<eyre::Result<Vec<_>>>()?;
    let y = mul_open_vec(a, &r, net, state)?;
    if y.iter().any(|y| y.is_zero()) {
        eyre::bail!("During execution of inverse in MPC: cannot compute inverse of zero");
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
    state: &mut ShamirProtocol<F>,
) -> eyre::Result<F> {
    let rcv = network::broadcast_next(net, state.num_parties, state.threshold + 1, a.a)?;
    let res = core::reconstruct(&rcv, &state.open_lagrange_t);
    Ok(res)
}

/// Opens a vector of shared values and returns the corresponding field elements.
pub fn open_vec<F: PrimeField, N: Network>(
    a: &[ShamirShare<F>],
    net: &N,
    state: &mut ShamirProtocol<F>,
) -> eyre::Result<Vec<F>> {
    let a_a = ShamirShare::convert_slice(a);

    let rcv = network::broadcast_next(net, state.num_parties, state.threshold + 1, a_a.to_owned())?;

    let mut transposed = vec![vec![F::zero(); state.threshold + 1]; a.len()];

    for (j, r) in rcv.into_iter().enumerate() {
        for (i, val) in r.into_iter().enumerate() {
            transposed[i][j] = val;
        }
    }

    let res = transposed
        .into_iter()
        .map(|r| core::reconstruct(&r, &state.open_lagrange_t))
        .collect();
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

/// This function performs a multiplication directly follonet, stateby an net, state. This is preferred over Open(Mul(\[x\], \[y\])), since Mul performs resharing of the result for degree reduction. Thus, mul_open(\[x\], \[y\]) requires less communication in fewer rounds compared to Open(Mul(\[x\], \[y\])).
fn mul_open<F: PrimeField, N: Network>(
    a: ShamirShare<F>,
    b: ShamirShare<F>,
    net: &N,
    state: &mut ShamirProtocol<F>,
) -> eyre::Result<F> {
    let mul = a * b;
    let rcv = network::broadcast_next(net, state.num_parties, 2 * state.threshold + 1, mul.a)?;
    Ok(core::reconstruct(&rcv, &state.open_lagrange_2t))
}

/// This function performs a multiplication directly follonet, stateby an net, state. This is preferred over Open(Mul(\[x\], \[y\])), since Mul performs resharing of the result for degree reduction. Thus, mul_open(\[x\], \[y\]) requires less communication in fewer rounds compared to Open(Mul(\[x\], \[y\])).
pub fn mul_open_vec<F: PrimeField, N: Network>(
    a: &[ShamirShare<F>],
    b: &[ShamirShare<F>],
    net: &N,
    state: &mut ShamirProtocol<F>,
) -> eyre::Result<Vec<F>> {
    let mul = a
        .iter()
        .zip(b.iter())
        .map(|(a, b)| a * b)
        .collect::<Vec<_>>();
    let mul = ShamirShare::convert_vec(mul);

    let rcv = network::broadcast_next(net, state.num_parties, 2 * state.threshold + 1, mul)?;

    let mut transposed = vec![vec![F::zero(); 2 * state.threshold + 1]; a.len()];

    for (j, r) in rcv.into_iter().enumerate() {
        for (i, val) in r.into_iter().enumerate() {
            transposed[i][j] = val;
        }
    }

    let res = transposed
        .into_iter()
        .map(|r| core::reconstruct(&r, &state.open_lagrange_2t))
        .collect();
    Ok(res)
}
