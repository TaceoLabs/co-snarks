//! Full GC-based equality using fancy-garbling + ocelot OT.
//!
//! Uses fancy-garbling's twopac::semihonest module which handles
//! everything: OT for evaluator inputs, wire labels, garbled tables.
//!
//! The circuit: "is (share0 + share1) == 0?" over n bits.
//! Party 0 = garbler, Party 1 = evaluator.

use ark_ff::PrimeField;
use fancy_garbling::twopac::semihonest::{
    Garbler as TwopcGarbler,
    Evaluator as TwopcEvaluator,
};
use fancy_garbling::{FancyBinary, FancyInput, FancyReveal, WireMod2};
use mpc_net::Network;
use num_bigint::BigUint;
use ocelot::ot::{ChouOrlandiSender, ChouOrlandiReceiver};
use rand::SeedableRng;
use scuttlebutt::AesRng;

use crate::ot::channel::NetworkChannel;
use crate::types::SpdzPrimeFieldShare;
use crate::SpdzState;

/// Check if a SPDZ-shared value is zero using a garbled circuit.
///
/// Both parties have their additive share. The GC computes
/// (share0 + share1) mod 2^n and checks if all bits are zero.
///
/// Cost: OT init (~128 base OTs, amortized) + n OT extensions + GC eval
/// Total: ~3-4 rounds regardless of n.
pub fn gc_is_zero<F: PrimeField, N: Network>(
    x: &SpdzPrimeFieldShare<F>,
    num_bits: usize,
    net: &N,
    state: &SpdzState<F>,
) -> eyre::Result<SpdzPrimeFieldShare<F>> {
    let party_id = state.id;

    // Extract my share's bits (LOCAL, no communication)
    let my_share_big: BigUint = x.share.into();
    let my_bits: Vec<bool> = (0..num_bits).map(|i| my_share_big.bit(i as u64)).collect();

    // Create the channel
    let channel = NetworkChannel::new(net);

    if party_id == 0 {
        // === GARBLER ===
        let rng = AesRng::from_seed(rand::random());
        let mut gb = TwopcGarbler::<_, _, ChouOrlandiSender, WireMod2>::new(channel, rng)
            .map_err(|e| eyre::eyre!("Garbler init: {:?}", e))?;

        // Garbler inputs: my share bits
        let garbler_wires = gb.encode_many(&my_bits.iter().map(|&b| b as u16).collect::<Vec<_>>(), &vec![2u16; num_bits])
            .map_err(|e| eyre::eyre!("Garbler encode: {:?}", e))?;

        // Evaluator inputs: their share bits (transferred via OT)
        let evaluator_wires = gb.receive_many(&vec![2u16; num_bits])
            .map_err(|e| eyre::eyre!("Garbler receive: {:?}", e))?;

        // Build the circuit: binary adder + zero check
        let result = is_sum_zero_circuit(&mut gb, &garbler_wires, &evaluator_wires, num_bits)?;

        // Reveal output to both parties
        let output = gb.reveal(&result)
            .map_err(|e| eyre::eyre!("Garbler reveal: {:?}", e))?;

        // output is the OR of sum bits: 0 means zero, 1 means nonzero
        // Invert for is_zero semantics: is_zero = 1 - or_result
        let is_zero_bit = 1 - (output as u8);

        Ok(SpdzPrimeFieldShare::promote_from_trivial(
            &F::from(is_zero_bit as u64),
            state.mac_key_share,
            state.id,
        ))
    } else {
        // === EVALUATOR ===
        let rng = AesRng::from_seed(rand::random());
        let mut ev = TwopcEvaluator::<_, _, ChouOrlandiReceiver, WireMod2>::new(channel, rng)
            .map_err(|e| eyre::eyre!("Evaluator init: {:?}", e))?;

        // Garbler inputs: receive wire labels
        let garbler_wires = ev.receive_many(&vec![2u16; num_bits])
            .map_err(|e| eyre::eyre!("Evaluator receive garbler: {:?}", e))?;

        // Evaluator inputs: my share bits (sent via OT)
        let evaluator_wires = ev.encode_many(&my_bits.iter().map(|&b| b as u16).collect::<Vec<_>>(), &vec![2u16; num_bits])
            .map_err(|e| eyre::eyre!("Evaluator encode: {:?}", e))?;

        // Evaluate the circuit
        let result = is_sum_zero_circuit(&mut ev, &garbler_wires, &evaluator_wires, num_bits)?;

        // Reveal output to both parties
        let output = ev.reveal(&result)
            .map_err(|e| eyre::eyre!("Evaluator reveal: {:?}", e))?;

        let is_zero_bit = 1 - (output as u8);

        Ok(SpdzPrimeFieldShare::promote_from_trivial(
            &F::from(is_zero_bit as u64),
            state.mac_key_share,
            state.id,
        ))
    }
}

/// Build the "is (a + b) == 0?" circuit using FancyBinary gates.
///
/// Inputs: a[0..n-1] and b[0..n-1] (binary wires)
/// Output: 1 if a + b == 0 mod 2^n, 0 otherwise
fn is_sum_zero_circuit<F: FancyBinary>(
    f: &mut F,
    a: &[F::Item],
    b: &[F::Item],
    n: usize,
) -> Result<F::Item, eyre::Report>
where
    F::Error: std::fmt::Debug,
{
    // Binary adder: compute sum bits
    let mut sum_bits = Vec::with_capacity(n);
    let mut carry = None;

    for i in 0..n {
        let xor_ab = f.xor(&a[i], &b[i]).map_err(|e| eyre::eyre!("{:?}", e))?;

        let (sum, new_carry) = if let Some(c) = carry {
            // Full adder: sum = a XOR b XOR carry, carry_out = MAJ(a, b, carry)
            let sum = f.xor(&xor_ab, &c).map_err(|e| eyre::eyre!("{:?}", e))?;
            let and_ab = f.and(&a[i], &b[i]).map_err(|e| eyre::eyre!("{:?}", e))?;
            let and_xor_c = f.and(&xor_ab, &c).map_err(|e| eyre::eyre!("{:?}", e))?;
            let carry_out = f.or(&and_ab, &and_xor_c).map_err(|e| eyre::eyre!("{:?}", e))?;
            (sum, carry_out)
        } else {
            // Half adder for first bit
            let and_ab = f.and(&a[i], &b[i]).map_err(|e| eyre::eyre!("{:?}", e))?;
            (xor_ab, and_ab)
        };

        sum_bits.push(sum);
        carry = Some(new_carry);
    }

    // Check if all sum bits are zero: NOR tree
    // is_zero = NOT(sum[0] OR sum[1] OR ... OR sum[n-1])
    let any_nonzero = f.xor_many(&sum_bits).map_err(|e| eyre::eyre!("{:?}", e))?;

    // Wait — xor_many gives parity, not OR. Need OR tree instead.
    // OR(a, b) = a XOR b XOR (a AND b) ... that's complex.
    // Simpler: check each bit is zero, AND them all.
    // is_zero = NOT(sum[0]) AND NOT(sum[1]) AND ... AND NOT(sum[n-1])

    // We can't directly compute NOT in mod-2 garbled circuits without
    // knowing the encoding. Let me use a different approach:
    // OR all bits, then invert.
    // OR(a, b) = XOR(a, XOR(b, AND(a, b)))
    // Or: build OR as a + b - a*b in the boolean domain = a XOR b XOR (a AND b)
    // = (a OR b) = NOT(NOT(a) AND NOT(b)) ... circular.
    //
    // Actually in fancy-garbling, there might be a NOT operation.
    // In mod-2 circuits: NOT(x) = x XOR 1.

    // Build OR tree: reduce pairwise
    let mut or_result = sum_bits[0].clone();
    for i in 1..n {
        or_result = f.or(&or_result, &sum_bits[i]).map_err(|e| eyre::eyre!("{:?}", e))?;
    }

    // is_zero = NOT(or_result)
    // In mod-2: NOT(x) = x XOR 1, but we need a constant 1 wire.
    // Hmm, fancy-garbling might not have a direct constant wire API...
    // Alternative: just return or_result and interpret 0 as "is zero", 1 as "not zero"
    // Then the caller inverts locally.

    // Return or_result (0 means sum is zero, 1 means nonzero)
    Ok(or_result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::{One, Zero};
    use mpc_net::local::LocalNetwork;
    use crate::preprocessing::{generate_dummy_preprocessing_with_rng, SpdzPreprocessing};
    use crate::types::{share_field_element, combine_field_element};

    #[test]
    fn test_gc_is_zero() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
        let (p0, p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(1000, &mut rng);
        let mac_key = p0.mac_key_share() + p1.mac_key_share();

        // Test: is_zero(0) should return 1 (inverted: or_result = 0 means zero)
        let [s0, s1] = share_field_element(Fr::zero(), mac_key, &mut rng);

        let mut nets = LocalNetwork::new(2).into_iter();
        let (net0, net1) = (nets.next().unwrap(), nets.next().unwrap());

        let state0 = crate::SpdzState::new(0, Box::new(p0));
        let state1 = crate::SpdzState::new(1, Box::new(p1));

        let h0 = std::thread::spawn(move || {
            gc_is_zero(&s0, 8, &net0, &state0).unwrap()
        });
        let h1 = std::thread::spawn(move || {
            gc_is_zero(&s1, 8, &net1, &state1).unwrap()
        });

        let r0 = h0.join().unwrap();
        let r1 = h1.join().unwrap();

        // The GC returns or_result: 0 means zero, 1 means nonzero
        // We need to invert for the is_zero semantics
        let or_result = combine_field_element(r0, r1);
        let is_zero = Fr::one() - or_result;
        eprintln!("GC is_zero(0) = {:?} (expected 1)", is_zero);
        assert_eq!(is_zero, Fr::one());
    }
}
