//! Elliptic curve operations for SPDZ shared values.
//!
//! Shared point representation: each coordinate (x, y) is SPDZ-shared.
//! Operations use shared arithmetic to work on coordinates directly.

use ark_ff::PrimeField;
use mpc_net::Network;

use crate::arithmetic;
use crate::types::SpdzPrimeFieldShare;
use crate::SpdzState;

/// Compute shared embedded curve addition from coordinate shares.
///
/// Takes two points as (x, y, is_infinity) tuples where each component
/// is a shared field element. Returns the sum point.
///
/// Uses the standard affine addition formulas:
///   lambda = (y2 - y1) / (x2 - x1)
///   x3 = lambda^2 - x1 - x2
///   y3 = lambda * (x1 - x3) - y1
pub fn embedded_curve_add<F: PrimeField, N: Network>(
    x1: &SpdzPrimeFieldShare<F>,
    y1: &SpdzPrimeFieldShare<F>,
    _inf1: &SpdzPrimeFieldShare<F>,
    x2: &SpdzPrimeFieldShare<F>,
    y2: &SpdzPrimeFieldShare<F>,
    _inf2: &SpdzPrimeFieldShare<F>,
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<(SpdzPrimeFieldShare<F>, SpdzPrimeFieldShare<F>, SpdzPrimeFieldShare<F>)> {
    // lambda = (y2 - y1) / (x2 - x1)
    let dy = *y2 - *y1;
    let dx = *x2 - *x1;
    let dx_inv = arithmetic::inv(&dx, net, state)?;
    let lambda = arithmetic::mul(&dy, &dx_inv, net, state)?;

    // x3 = lambda^2 - x1 - x2
    let lambda_sq = arithmetic::mul(&lambda, &lambda, net, state)?;
    let x3 = lambda_sq - *x1 - *x2;

    // y3 = lambda * (x1 - x3) - y1
    let x1_minus_x3 = *x1 - x3;
    let lambda_times = arithmetic::mul(&lambda, &x1_minus_x3, net, state)?;
    let y3 = lambda_times - *y1;

    // is_infinity = 0 (result of addition of non-infinity points)
    let inf3 = SpdzPrimeFieldShare::zero_share();

    Ok((x3, y3, inf3))
}
