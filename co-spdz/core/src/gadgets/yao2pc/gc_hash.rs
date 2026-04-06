//! Garbled circuit evaluation for hash functions on SPDZ shared values.
//!
//! Uses fancy-garbling's twopac::semihonest module.
//! Party 0 = garbler, Party 1 = evaluator.
//!
//! The GC pipeline:
//!   1. Both parties extract bits of their SPDZ share (local)
//!   2. Feed into GC: garbler encodes, evaluator via OT
//!   3. GC adds shares mod p (254-bit modular adder) to recover actual values
//!   4. GC evaluates the target function (hash, etc.)
//!   5. Output revealed to both parties, converted to SPDZ shares

use ark_ff::{BigInteger, PrimeField};
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

/// Evaluate a function on SPDZ-shared inputs using a garbled circuit.
///
/// `input_shares`: SPDZ shares of input values.
/// `output_bits`: expected number of output bits.
/// `circuit_fn`: builds the circuit on recovered input bits, returns output wires.
///
/// Returns output bytes as SPDZ trivial shares.
pub fn gc_eval_on_shared_inputs<F, N, C>(
    input_shares: &[SpdzPrimeFieldShare<F>],
    output_bits_count: usize,
    net: &N,
    state: &SpdzState<F>,
    circuit_fn: C,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>>
where
    F: PrimeField,
    N: Network,
    C: Fn() -> usize, // placeholder — real impl uses FancyBinary generics
{
    let party_id = state.id;
    let field_bits = F::MODULUS_BIT_SIZE as usize;
    let n_inputs = input_shares.len();
    let total_input_bits = n_inputs * field_bits;
    let output_bytes = (output_bits_count + 7) / 8;

    // Extract bits of my share (LOCAL)
    let my_bits: Vec<bool> = input_shares.iter().flat_map(|share| {
        let val: BigUint = share.share.into_bigint().into();
        (0..field_bits).map(move |i| val.bit(i as u64))
    }).collect();

    let channel = NetworkChannel::new(net);

    if party_id == 0 {
        let rng = AesRng::from_seed(rand::random());
        let mut gb = TwopcGarbler::<_, _, ChouOrlandiSender, WireMod2>::new(channel, rng)
            .map_err(|e| eyre::eyre!("Garbler init: {:?}", e))?;

        let garbler_wires = gb.encode_many(
            &my_bits.iter().map(|&b| b as u16).collect::<Vec<_>>(),
            &vec![2u16; total_input_bits],
        ).map_err(|e| eyre::eyre!("Garbler encode: {:?}", e))?;

        let evaluator_wires = gb.receive_many(&vec![2u16; total_input_bits])
            .map_err(|e| eyre::eyre!("Garbler receive: {:?}", e))?;

        // Add shares mod p for each input, truncate to output_bits_count bits
        let recovered = add_shares_mod_p::<_, F>(
            &mut gb, &garbler_wires, &evaluator_wires, n_inputs, output_bits_count,
        )?;

        let mut output_bits = Vec::with_capacity(output_bits_count);
        for w in &recovered {
            let bit = gb.reveal(w).map_err(|e| eyre::eyre!("reveal: {:?}", e))?;
            output_bits.push(bit != 0);
        }

        bits_to_spdz_shares(&output_bits, output_bytes, state)
    } else {
        let rng = AesRng::from_seed(rand::random());
        let mut ev = TwopcEvaluator::<_, _, ChouOrlandiReceiver, WireMod2>::new(channel, rng)
            .map_err(|e| eyre::eyre!("Evaluator init: {:?}", e))?;

        let garbler_wires = ev.receive_many(&vec![2u16; total_input_bits])
            .map_err(|e| eyre::eyre!("Evaluator receive: {:?}", e))?;

        let evaluator_wires = ev.encode_many(
            &my_bits.iter().map(|&b| b as u16).collect::<Vec<_>>(),
            &vec![2u16; total_input_bits],
        ).map_err(|e| eyre::eyre!("Evaluator encode: {:?}", e))?;

        let recovered = add_shares_mod_p::<_, F>(
            &mut ev, &garbler_wires, &evaluator_wires, n_inputs, output_bits_count,
        )?;

        let mut output_bits = Vec::with_capacity(output_bits_count);
        for w in &recovered {
            let bit = ev.reveal(w).map_err(|e| eyre::eyre!("reveal: {:?}", e))?;
            output_bits.push(bit != 0);
        }

        bits_to_spdz_shares(&output_bits, output_bytes, state)
    }
}

// ═══════════════════════════════════════════════════════════════
// Modular arithmetic circuits (ported from Rep3's circuits.rs)
// ═══════════════════════════════════════════════════════════════

/// Add two sets of SPDZ share bits modulo p for each input.
/// Truncates each result to `bits_per_output` bits.
fn add_shares_mod_p<G: FancyBinary, F: PrimeField>(
    g: &mut G,
    garbler_wires: &[G::Item],
    evaluator_wires: &[G::Item],
    n_inputs: usize,
    total_output_bits: usize,
) -> Result<Vec<G::Item>, eyre::Report>
where
    G::Error: std::fmt::Debug,
{
    let field_bits = F::MODULUS_BIT_SIZE as usize;
    let bits_per_output = total_output_bits / n_inputs;
    let mut result = Vec::with_capacity(total_output_bits);

    for i in 0..n_inputs {
        let start = i * field_bits;
        let a = &garbler_wires[start..start + field_bits];
        let b = &evaluator_wires[start..start + field_bits];
        let sum = adder_mod_p::<G, F>(g, a, b, bits_per_output)?;
        result.extend(sum);
    }

    Ok(result)
}

/// Add two field elements mod p in a garbled circuit.
/// Returns `outlen` bits of the result.
///
/// Ported from Rep3's `adder_mod_p_with_output_size`.
pub(crate) fn adder_mod_p<G: FancyBinary, F: PrimeField>(
    g: &mut G,
    a: &[G::Item],
    b: &[G::Item],
    outlen: usize,
) -> Result<Vec<G::Item>, eyre::Report>
where
    G::Error: std::fmt::Debug,
{
    let bitlen = a.len();
    assert_eq!(bitlen, b.len());
    assert_eq!(bitlen, F::MODULUS_BIT_SIZE as usize);

    // Binary addition (may overflow into bitlen+1 bits)
    let (added, carry) = bin_addition(g, a, b)?;

    // Subtract p and mux: if result >= p, use (result - p), else use result
    sub_p_and_mux::<G, F>(g, &added, carry, outlen)
}

/// Binary addition returning (sum_bits, carry_out).
pub(crate) fn bin_addition<G: FancyBinary>(
    g: &mut G,
    a: &[G::Item],
    b: &[G::Item],
) -> Result<(Vec<G::Item>, G::Item), eyre::Report>
where
    G::Error: std::fmt::Debug,
{
    assert_eq!(a.len(), b.len());
    let mut result = Vec::with_capacity(a.len());

    // Half adder for first bit
    let s = g.xor(&a[0], &b[0]).map_err(|e| eyre::eyre!("{:?}", e))?;
    let mut c = g.and(&a[0], &b[0]).map_err(|e| eyre::eyre!("{:?}", e))?;
    result.push(s);

    // Full adders for remaining bits
    for i in 1..a.len() {
        let z1 = g.xor(&a[i], &b[i]).map_err(|e| eyre::eyre!("{:?}", e))?;
        let s = g.xor(&z1, &c).map_err(|e| eyre::eyre!("{:?}", e))?;
        let z3 = g.xor(&a[i], &c).map_err(|e| eyre::eyre!("{:?}", e))?;
        let z4 = g.and(&z1, &z3).map_err(|e| eyre::eyre!("{:?}", e))?;
        c = g.xor(&z4, &a[i]).map_err(|e| eyre::eyre!("{:?}", e))?;
        result.push(s);
    }

    Ok((result, c))
}

/// Full adder with one constant input bit.
/// When b is constant, we can optimize (no AND with constant).
fn full_adder_const<G: FancyBinary>(
    g: &mut G,
    a: &G::Item,
    b: bool,
    c: &G::Item,
) -> Result<(G::Item, G::Item), eyre::Report>
where
    G::Error: std::fmt::Debug,
{
    if b {
        let z1 = g.negate(a).map_err(|e| eyre::eyre!("{:?}", e))?;
        let s = g.xor(&z1, c).map_err(|e| eyre::eyre!("{:?}", e))?;
        let z3 = g.xor(a, c).map_err(|e| eyre::eyre!("{:?}", e))?;
        let z4 = g.and(&z1, &z3).map_err(|e| eyre::eyre!("{:?}", e))?;
        let c_out = g.xor(&z4, a).map_err(|e| eyre::eyre!("{:?}", e))?;
        Ok((s, c_out))
    } else {
        let s = g.xor(a, c).map_err(|e| eyre::eyre!("{:?}", e))?;
        let z4 = g.and(a, &s).map_err(|e| eyre::eyre!("{:?}", e))?;
        let c_out = g.xor(&z4, a).map_err(|e| eyre::eyre!("{:?}", e))?;
        Ok((s, c_out))
    }
}

/// Subtract p from (wires || carry) and mux with original.
/// If the subtraction doesn't underflow (ov=0), use the subtracted value.
/// Otherwise, use the original value.
///
/// This implements: result = if (wires + carry*2^n) >= p { wires - p } else { wires }
fn sub_p_and_mux<G: FancyBinary, F: PrimeField>(
    g: &mut G,
    wires: &[G::Item],
    carry: G::Item,
    outlen: usize,
) -> Result<Vec<G::Item>, eyre::Report>
where
    G::Error: std::fmt::Debug,
{
    let bitlen = wires.len();
    assert_eq!(bitlen, F::MODULUS_BIT_SIZE as usize);

    // Compute (2^(n+1) - p) as constant bits for the subtraction
    let new_bitlen = bitlen + 1;
    let p_: BigUint = (BigUint::from(1u64) << new_bitlen) - F::MODULUS.into();
    let p_bits: Vec<bool> = (0..new_bitlen).map(|i| p_.bit(i as u64)).collect();

    // Manual ripple-carry adder with constant p_bits
    let mut subtracted = Vec::with_capacity(bitlen);

    // First bit: half adder with constant
    assert!(p_bits[0]); // LSB of (2^(n+1) - p) should be 1 for BN254
    let s = g.negate(&wires[0]).map_err(|e| eyre::eyre!("{:?}", e))?;
    subtracted.push(s);
    let mut c = wires[0].clone();

    // Remaining bits: full adder with constant
    for i in 1..bitlen {
        let (s, c_) = full_adder_const(g, &wires[i], p_bits[i], &c)?;
        c = c_;
        subtracted.push(s);
    }

    // Final bit: compute overflow flag
    let ov = if p_bits[bitlen] {
        let neg_carry = g.negate(&carry).map_err(|e| eyre::eyre!("{:?}", e))?;
        g.xor(&neg_carry, &c).map_err(|e| eyre::eyre!("{:?}", e))?
    } else {
        g.xor(&carry, &c).map_err(|e| eyre::eyre!("{:?}", e))?
    };

    // Mux: if ov (overflow, meaning subtraction was valid), use subtracted
    let mut result = Vec::with_capacity(outlen);
    for i in 0..outlen {
        let r = g.mux(&ov, &subtracted[i], &wires[i])
            .map_err(|e| eyre::eyre!("{:?}", e))?;
        result.push(r);
    }

    Ok(result)
}

/// Convert output bits to SPDZ trivial shares.
pub(crate) fn bits_to_spdz_shares<F: PrimeField>(
    output_bits: &[bool],
    output_bytes: usize,
    state: &SpdzState<F>,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
    let mut result = Vec::with_capacity(output_bytes);
    for byte_idx in 0..output_bytes {
        let mut byte_val = 0u8;
        for bit in 0..8 {
            let idx = byte_idx * 8 + bit;
            if idx < output_bits.len() && output_bits[idx] {
                byte_val |= 1 << bit;
            }
        }
        result.push(SpdzPrimeFieldShare::promote_from_trivial(
            &F::from(byte_val as u64),
            state.mac_key_share,
            state.id,
        ));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use rand::SeedableRng;
    use crate::preprocessing::{generate_dummy_preprocessing_with_rng, SpdzPreprocessing};
    use crate::types::{share_field_element, combine_field_element};
    use mpc_net::local::LocalNetwork;

    #[test]
    fn test_gc_modular_add_recovery() {
        // Test: share byte values, recover them via GC modular addition
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
        let (mut p0, mut p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(100, &mut rng);
        let mac_key = p0.mac_key_share() + p1.mac_key_share();

        // Share two byte values
        let vals = [Fr::from(42u64), Fr::from(200u64)];
        let [s0_0, s1_0] = share_field_element(vals[0], mac_key, &mut rng);
        let [s0_1, s1_1] = share_field_element(vals[1], mac_key, &mut rng);

        let shares_0 = vec![s0_0, s0_1];
        let shares_1 = vec![s1_0, s1_1];

        let mut nets = LocalNetwork::new(2).into_iter();
        let (net0, net1) = (nets.next().unwrap(), nets.next().unwrap());

        let state0 = crate::SpdzState::new(0, Box::new(p0));
        let state1 = crate::SpdzState::new(1, Box::new(p1));

        // Use gc_eval_on_shared_inputs with 8 output bits per value = 16 total
        let h0 = std::thread::spawn(move || {
            gc_eval_on_shared_inputs(
                &shares_0, 16, &net0, &state0, || 0,
            ).unwrap()
        });
        let h1 = std::thread::spawn(move || {
            gc_eval_on_shared_inputs(
                &shares_1, 16, &net1, &state1, || 0,
            ).unwrap()
        });

        let r0 = h0.join().unwrap();
        let r1 = h1.join().unwrap();

        assert_eq!(r0.len(), 2);
        let byte0 = combine_field_element(r0[0], r1[0]);
        let byte1 = combine_field_element(r0[1], r1[1]);
        assert_eq!(byte0, Fr::from(42u64), "First byte should be 42");
        assert_eq!(byte1, Fr::from(200u64), "Second byte should be 200");
    }
}
