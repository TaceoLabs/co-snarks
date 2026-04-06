//! Blake2s hash via garbled circuit on SPDZ shares.
//!
//! Architecture:
//!   1. Garbler encodes: share bits + ALL Blake2s constants (IV, counters, flags)
//!   2. Evaluator receives: share wires via OT, constant wires from garbler
//!   3. GC circuit: modular-add shares → Blake2s rounds → output
//!   4. Output revealed, converted to SPDZ shares

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
use super::gc_hash::{adder_mod_p, bits_to_spdz_shares};

pub(crate) const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// Compute Blake2s on SPDZ-shared input bytes via garbled circuit.
/// Returns 32 output bytes as SPDZ trivial shares.
pub fn gc_blake2s<F: PrimeField, N: Network>(
    input_shares: &[SpdzPrimeFieldShare<F>],
    num_bits: usize,
    net: &N,
    state: &SpdzState<F>,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
    let party_id = state.id;
    let field_bits = F::MODULUS_BIT_SIZE as usize;
    let n_inputs = input_shares.len();
    let total_input_bits = n_inputs * field_bits;

    // Precompute all constant bits:
    // Per compression call we need: IV[0..7], and state init values (IV^t, IV^f)
    // Total constants: depends on number of blocks
    let num_input_bytes = n_inputs;
    let blocks = num_input_bytes.max(1).div_ceil(64);
    let const_bits = precompute_blake2s_constants(num_input_bytes, blocks);
    let n_const = const_bits.len();

    let my_bits: Vec<bool> = input_shares.iter().flat_map(|share| {
        let val: BigUint = share.share.into_bigint().into();
        (0..field_bits).map(move |i| val.bit(i as u64))
    }).collect();

    let channel = NetworkChannel::new(net);

    if party_id == 0 {
        let rng = AesRng::from_seed(rand::random());
        let mut gb = TwopcGarbler::<_, _, ChouOrlandiSender, WireMod2>::new(channel, rng)
            .map_err(|e| eyre::eyre!("Garbler init: {:?}", e))?;

        // Garbler encodes: share bits + constant bits
        let mut all_bits: Vec<u16> = my_bits.iter().map(|&b| b as u16).collect();
        all_bits.extend(const_bits.iter().map(|&b| b as u16));

        let all_wires = gb.encode_many(
            &all_bits, &vec![2u16; total_input_bits + n_const],
        ).map_err(|e| eyre::eyre!("Garbler encode: {:?}", e))?;

        let evaluator_wires = gb.receive_many(&vec![2u16; total_input_bits])
            .map_err(|e| eyre::eyre!("Garbler receive: {:?}", e))?;

        let share_wires = &all_wires[..total_input_bits];
        let const_wires = &all_wires[total_input_bits..];

        let output = blake2s_circuit::<_, F>(
            &mut gb, share_wires, &evaluator_wires, const_wires,
            n_inputs, num_bits, blocks,
        )?;

        let mut output_bits = Vec::with_capacity(256);
        for w in &output {
            let bit = gb.reveal(w).map_err(|e| eyre::eyre!("reveal: {:?}", e))?;
            output_bits.push(bit != 0);
        }
        bits_to_spdz_shares(&output_bits, 32, state)
    } else {
        let rng = AesRng::from_seed(rand::random());
        let mut ev = TwopcEvaluator::<_, _, ChouOrlandiReceiver, WireMod2>::new(channel, rng)
            .map_err(|e| eyre::eyre!("Evaluator init: {:?}", e))?;

        let all_garbler_wires = ev.receive_many(&vec![2u16; total_input_bits + n_const])
            .map_err(|e| eyre::eyre!("Evaluator receive: {:?}", e))?;

        let evaluator_wires = ev.encode_many(
            &my_bits.iter().map(|&b| b as u16).collect::<Vec<_>>(),
            &vec![2u16; total_input_bits],
        ).map_err(|e| eyre::eyre!("Evaluator encode: {:?}", e))?;

        let share_wires = &all_garbler_wires[..total_input_bits];
        let const_wires = &all_garbler_wires[total_input_bits..];

        let output = blake2s_circuit::<_, F>(
            &mut ev, share_wires, &evaluator_wires, const_wires,
            n_inputs, num_bits, blocks,
        )?;

        let mut output_bits = Vec::with_capacity(256);
        for w in &output {
            let bit = ev.reveal(w).map_err(|e| eyre::eyre!("reveal: {:?}", e))?;
            output_bits.push(bit != 0);
        }
        bits_to_spdz_shares(&output_bits, 32, state)
    }
}

/// Pre-compute all constant bits for Blake2s.
/// Layout: [IV_words × 8, zero_word, param_word, per-compression constants...]
/// Per compression: IV[0..3](for v[8..11]) + IV[4]^t0 + IV[5]^t1 + IV[6]^f0 + IV[7]^f1
fn precompute_blake2s_constants(num_input_bytes: usize, blocks: usize) -> Vec<bool> {
    let mut bits = Vec::new();

    // Initial h: IV[0..7] (256 bits)
    for &iv in &IV {
        bits.extend(u32_to_bits(iv));
    }

    // Parameter word: 0x01010020 (32 bits)
    bits.extend(u32_to_bits(0x01010020));

    // Zero word (32 bits)
    bits.extend(vec![false; 32]);

    // Per-compression round constants
    let mut counter: u64 = 0;
    let total_compressions = blocks;

    for block_idx in 0..total_compressions {
        let is_last = block_idx == total_compressions - 1;

        if is_last {
            let mut bytes = num_input_bytes % 64;
            if num_input_bytes > 0 && bytes == 0 { bytes = 64; }
            counter += bytes as u64;
        } else {
            counter += 64;
        }

        let t0 = counter as u32;
        let t1 = (counter >> 32) as u32;
        let f0 = if is_last { 0xFFFFFFFFu32 } else { 0 };
        let f1 = 0u32;

        // v[8..11] = IV[0..3]
        for i in 0..4 {
            bits.extend(u32_to_bits(IV[i]));
        }
        // v[12] = IV[4] ^ t0
        bits.extend(u32_to_bits(IV[4] ^ t0));
        // v[13] = IV[5] ^ t1
        bits.extend(u32_to_bits(IV[5] ^ t1));
        // v[14] = IV[6] ^ f0
        bits.extend(u32_to_bits(IV[6] ^ f0));
        // v[15] = IV[7] ^ f1
        bits.extend(u32_to_bits(IV[7] ^ f1));
    }

    bits
}

pub(crate) fn u32_to_bits(v: u32) -> Vec<bool> {
    (0..32).map(|i| (v >> i) & 1 == 1).collect()
}

/// The full Blake2s circuit inside the GC.
fn blake2s_circuit<G: FancyBinary, F: PrimeField>(
    g: &mut G,
    garbler_share_wires: &[G::Item],
    evaluator_share_wires: &[G::Item],
    const_wires: &[G::Item],
    num_inputs: usize,
    num_bits: usize,
    blocks: usize,
) -> Result<Vec<G::Item>, eyre::Report>
where
    G::Error: std::fmt::Debug,
{
    let field_bits = F::MODULUS_BIT_SIZE as usize;
    let bits_per_byte = (num_bits + 7) / 8 * 8;

    // Step 1: Recover input bytes via modular addition
    let mut input_bytes: Vec<Vec<G::Item>> = Vec::new();
    for i in 0..num_inputs {
        let start = i * field_bits;
        let a = &garbler_share_wires[start..start + field_bits];
        let b = &evaluator_share_wires[start..start + field_bits];
        let recovered = adder_mod_p::<G, F>(g, a, b, bits_per_byte)?;
        for chunk in recovered.chunks(8) {
            input_bytes.push(chunk.to_vec());
        }
    }

    // Step 2: Parse constants
    let mut co = 0; // constant offset
    let mut h: Vec<Vec<G::Item>> = Vec::with_capacity(8);
    for _ in 0..8 {
        h.push(const_wires[co..co + 32].to_vec());
        co += 32;
    }
    let param = const_wires[co..co + 32].to_vec();
    co += 32;
    let zero_word: Vec<G::Item> = const_wires[co..co + 32].to_vec();
    co += 32;

    // h[0] ^= param
    h[0] = xor_words(g, &h[0], &param)?;

    // Step 3: Process blocks
    for block_idx in 0..blocks {
        // Pack bytes into 16 message words
        let mut msg: Vec<Vec<G::Item>> = vec![zero_word.clone(); 16];
        let block_start = block_idx * 64;
        for (i, byte) in input_bytes.iter().skip(block_start).take(64).enumerate() {
            let word_idx = i / 4;
            let byte_in_word = i % 4;
            let shift = byte_in_word * 8;
            for bit in 0..byte.len().min(8) {
                msg[word_idx][shift + bit] = byte[bit].clone();
            }
        }

        // Get compression constants for this block
        let v8_11: Vec<Vec<G::Item>> = (0..4).map(|i| {
            const_wires[co + i * 32..co + (i + 1) * 32].to_vec()
        }).collect();
        let v12 = const_wires[co + 128..co + 160].to_vec();
        let v13 = const_wires[co + 160..co + 192].to_vec();
        let v14 = const_wires[co + 192..co + 224].to_vec();
        let v15 = const_wires[co + 224..co + 256].to_vec();
        co += 256;

        // Initialize compression state
        let mut v: Vec<Vec<G::Item>> = Vec::with_capacity(16);
        for hi in &h { v.push(hi.clone()); }
        v.extend(v8_11);
        v.push(v12);
        v.push(v13);
        v.push(v14);
        v.push(v15);

        // 10 rounds of mixing
        for r in 0..10 {
            let s = &SIGMA[r];
            blake2s_g(g, &mut v, 0, 4, 8, 12, &msg[s[0]], &msg[s[1]])?;
            blake2s_g(g, &mut v, 1, 5, 9, 13, &msg[s[2]], &msg[s[3]])?;
            blake2s_g(g, &mut v, 2, 6, 10, 14, &msg[s[4]], &msg[s[5]])?;
            blake2s_g(g, &mut v, 3, 7, 11, 15, &msg[s[6]], &msg[s[7]])?;
            blake2s_g(g, &mut v, 0, 5, 10, 15, &msg[s[8]], &msg[s[9]])?;
            blake2s_g(g, &mut v, 1, 6, 11, 12, &msg[s[10]], &msg[s[11]])?;
            blake2s_g(g, &mut v, 2, 7, 8, 13, &msg[s[12]], &msg[s[13]])?;
            blake2s_g(g, &mut v, 3, 4, 9, 14, &msg[s[14]], &msg[s[15]])?;
        }

        // Finalize: h[i] = h[i] ^ v[i] ^ v[i+8]
        for i in 0..8 {
            let tmp = xor_words(g, &v[i], &v[i + 8])?;
            h[i] = xor_words(g, &h[i], &tmp)?;
        }
    }

    // Step 4: Output bytes (little-endian u32 words → bytes)
    let mut output = Vec::with_capacity(256);
    for word in &h {
        output.extend_from_slice(word);
    }
    output.truncate(256);
    Ok(output)
}

/// Blake2s G mixing function.
fn blake2s_g<G: FancyBinary>(
    g: &mut G,
    v: &mut [Vec<G::Item>],
    a: usize, b: usize, c: usize, d: usize,
    x: &[G::Item], y: &[G::Item],
) -> Result<(), eyre::Report>
where
    G::Error: std::fmt::Debug,
{
    v[a] = add32(g, &v[a], &v[b])?;
    v[a] = add32(g, &v[a], x)?;
    v[d] = xor_words(g, &v[d], &v[a])?;
    v[d].rotate_left(16);
    v[c] = add32(g, &v[c], &v[d])?;
    v[b] = xor_words(g, &v[b], &v[c])?;
    v[b].rotate_left(12);
    v[a] = add32(g, &v[a], &v[b])?;
    v[a] = add32(g, &v[a], y)?;
    v[d] = xor_words(g, &v[d], &v[a])?;
    v[d].rotate_left(8);
    v[c] = add32(g, &v[c], &v[d])?;
    v[b] = xor_words(g, &v[b], &v[c])?;
    v[b].rotate_left(7);
    Ok(())
}

/// 32-bit binary addition (no carry out — mod 2^32).
pub(crate) fn add32<G: FancyBinary>(g: &mut G, a: &[G::Item], b: &[G::Item]) -> Result<Vec<G::Item>, eyre::Report>
where G::Error: std::fmt::Debug {
    assert_eq!(a.len(), 32);
    assert_eq!(b.len(), 32);
    let (result, _carry) = super::gc_hash::bin_addition(g, a, b)?;
    Ok(result)
}

pub(crate) fn xor_words<G: FancyBinary>(g: &mut G, a: &[G::Item], b: &[G::Item]) -> Result<Vec<G::Item>, eyre::Report>
where G::Error: std::fmt::Debug {
    a.iter().zip(b.iter())
        .map(|(x, y)| g.xor(x, y).map_err(|e| eyre::eyre!("{:?}", e)))
        .collect()
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
    fn test_gc_blake2s_empty() {
        // Test: Blake2s of empty input
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
        let (mut p0, mut p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(100, &mut rng);
        let mac_key = p0.mac_key_share() + p1.mac_key_share();

        // Empty input (0 bytes)
        let shares_0: Vec<SpdzPrimeFieldShare<Fr>> = vec![];
        let shares_1: Vec<SpdzPrimeFieldShare<Fr>> = vec![];

        let mut nets = LocalNetwork::new(2).into_iter();
        let (net0, net1) = (nets.next().unwrap(), nets.next().unwrap());
        let state0 = crate::SpdzState::new(0, Box::new(p0));
        let state1 = crate::SpdzState::new(1, Box::new(p1));

        let h0 = std::thread::spawn(move || {
            gc_blake2s(&shares_0, 8, &net0, &state0).unwrap()
        });
        let h1 = std::thread::spawn(move || {
            gc_blake2s(&shares_1, 8, &net1, &state1).unwrap()
        });

        let r0 = h0.join().unwrap();
        let r1 = h1.join().unwrap();

        // Reconstruct and compare with reference
        let output: Vec<u8> = r0.iter().zip(r1.iter())
            .map(|(a, b)| {
                let val = combine_field_element(*a, *b);
                let big: BigUint = val.into_bigint().into();
                big.to_u32_digits().first().copied().unwrap_or(0) as u8
            })
            .collect();

        // Reference: blake2s of empty input
        use blake2::Digest;
        let expected: Vec<u8> = blake2::Blake2s256::digest(&[]).to_vec();

        assert_eq!(output.len(), 32);
        assert_eq!(output, expected, "Blake2s hash of empty input should match reference");
    }
}
