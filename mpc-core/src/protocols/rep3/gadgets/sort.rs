//! Sort
//!
//! This module contains some oblivious sorting algorithms for the Rep3 protocol.

use crate::protocols::rep3::{
    Rep3State,
    arithmetic::FieldShare,
    yao::{self, circuits::GarbledCircuits},
};
use ark_ff::PrimeField;
use mpc_net::Network;

/// Sorts the inputs using the Batcher's odd-even merge sort algorithm. Thereby, only the lowest `bitsize` bits are considered. The final results also only have bitsize bits each.
pub fn batcher_odd_even_merge_sort_yao<F: PrimeField, N: Network>(
    inputs: &[FieldShare<F>],
    net: &N,
    state: &mut Rep3State,
    bitsize: usize,
) -> eyre::Result<Vec<FieldShare<F>>> {
    if bitsize > F::MODULUS_BIT_SIZE as usize {
        eyre::bail!("Bit size is larger than field size");
    }
    let num_inputs = inputs.len();

    yao::decompose_circuit_compose_blueprint!(
        inputs,
        net,
        state,
        num_inputs,
        GarbledCircuits::batcher_odd_even_merge_sort::<_, F>,
        (bitsize)
    )
}
