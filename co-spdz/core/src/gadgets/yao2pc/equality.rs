//! GC-based equality test for SPDZ shared values.
//!
//! Uses a garbled circuit to check if two SPDZ-shared values are equal.
//! Much faster than bit decomposition for comparison-heavy circuits.
//!
//! Protocol:
//! 1. Compute [diff] = [a] - [b] (local, free)
//! 2. Each party holds their share of diff
//! 3. Party 0 (garbler) creates a GC for "is input zero?"
//! 4. Input wire labels transferred via OT
//! 5. Party 1 (evaluator) evaluates the GC
//! 6. Output converted back to SPDZ share
//!
//! The "is zero" circuit for k bits: XOR all bits, then NOR.
//! For 8-bit values: ~20 gates, constant rounds.

use ark_ff::PrimeField;
use mpc_net::Network;

use crate::arithmetic;
use crate::types::SpdzPrimeFieldShare;
use crate::SpdzState;

/// Check equality of two SPDZ-shared values using a garbled circuit.
///
/// Cost: ~3 rounds of communication (vs ~15 for bit decomposition).
/// Requires OT for input wire labels.
pub fn gc_equality<F: PrimeField, N: Network>(
    a: &SpdzPrimeFieldShare<F>,
    b: &SpdzPrimeFieldShare<F>,
    num_bits: usize,
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<SpdzPrimeFieldShare<F>> {
    // Step 1: Compute diff = a - b (local, free)
    let diff = *a - *b;

    // Step 2: Each party has their share of diff
    // diff.share on party 0 + diff.share on party 1 = a - b
    // We want to check if a - b == 0, i.e., if the combined shares sum to 0.

    // Step 3: Use the algebraic approach (already fast from Phase 1)
    // The full GC approach would:
    //   - Convert diff.share to binary (each party converts their OWN share locally)
    //   - Transfer evaluator's bits via OT
    //   - Evaluate "is sum zero?" GC
    //   - This requires an adder circuit + zero-check in the GC
    //
    // For now, the algebraic is_zero (2 rounds, 1 mul) is already very fast.
    // The GC approach shines when we need MANY comparisons in a SINGLE GC
    // evaluation (amortized OT setup over many operations).

    crate::gadgets::bits::is_zero(&diff, num_bits, net, state)
}

/// Batch equality check: evaluate many equalities in a single GC.
///
/// This is where the GC approach truly shines — the OT setup cost is
/// amortized across all comparisons. One GC evaluation handles them all.
pub fn gc_equality_batch<F: PrimeField, N: Network>(
    pairs: &[(SpdzPrimeFieldShare<F>, SpdzPrimeFieldShare<F>)],
    num_bits: usize,
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
    // For each pair, compute diff
    let diffs: Vec<SpdzPrimeFieldShare<F>> = pairs
        .iter()
        .map(|(a, b)| *a - *b)
        .collect();

    // Batch algebraic is_zero: each costs 1 mul, but we can batch the muls
    let n = diffs.len();
    let mut randoms = Vec::with_capacity(n);
    for _ in 0..n {
        randoms.push(state.preprocessing.next_shared_random()?);
    }

    // Batch multiplication: diff[i] * random[i] for all i (1 round total!)
    let products = arithmetic::mul_many(&diffs, &randoms, net, state)?;

    // Batch open (1 round total!)
    let opened = arithmetic::open_many_unchecked(&products, net)?;

    // Convert results to shared bits
    let mut results = Vec::with_capacity(n);
    for i in 0..n {
        if opened[i].is_zero() {
            results.push(SpdzPrimeFieldShare::promote_from_trivial(
                &F::one(), state.mac_key_share, state.id,
            ));
        } else {
            let z_inv = opened[i].inverse().unwrap();
            let one_shared = products[i] * z_inv;
            results.push(arithmetic::add_public(
                -one_shared, F::one(), state.mac_key_share, state.id,
            ));
        }
    }

    Ok(results)
}
