//! Blake3 hash via garbled circuit on SPDZ shares.
//! Reuses the same G mixing function as Blake2s (same rotation constants).
//! Differences: 7 rounds (vs 10), different sigma, chunk chaining.

use ark_ff::{BigInteger, PrimeField};
use fancy_garbling::twopac::semihonest::{
    Garbler as TwopcGarbler, Evaluator as TwopcEvaluator,
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
use super::gc_blake2s::{IV, u32_to_bits, xor_words, add32};
use super::gc_hash::{adder_mod_p, bits_to_spdz_shares};

const SIGMA_BLAKE3: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

/// Evaluate Blake3 on SPDZ-shared input bytes via garbled circuit.
pub fn gc_blake3<F: PrimeField, N: Network>(
    input_shares: &[SpdzPrimeFieldShare<F>],
    num_bits: usize,
    net: &N,
    state: &SpdzState<F>,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
    let party_id = state.id;
    let field_bits = F::MODULUS_BIT_SIZE as usize;
    let n_inputs = input_shares.len();
    let total_input_bits = n_inputs * field_bits;

    // Blake3 for single chunk (<=1024 bytes) only for now
    assert!(n_inputs <= 1024, "GC Blake3: multi-chunk not yet implemented");

    let const_bits = precompute_blake3_constants(n_inputs);
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

        let mut all_bits: Vec<u16> = my_bits.iter().map(|&b| b as u16).collect();
        all_bits.extend(const_bits.iter().map(|&b| b as u16));

        let all_wires = gb.encode_many(&all_bits, &vec![2u16; total_input_bits + n_const])
            .map_err(|e| eyre::eyre!("encode: {:?}", e))?;
        let eval_wires = gb.receive_many(&vec![2u16; total_input_bits])
            .map_err(|e| eyre::eyre!("receive: {:?}", e))?;

        let (share_w, const_w) = all_wires.split_at(total_input_bits);
        let output = blake3_circuit::<_, F>(&mut gb, share_w, &eval_wires, const_w, n_inputs, num_bits)?;

        let mut out_bits = Vec::with_capacity(256);
        for w in &output {
            out_bits.push(gb.reveal(w).map_err(|e| eyre::eyre!("reveal: {:?}", e))? != 0);
        }
        bits_to_spdz_shares(&out_bits, 32, state)
    } else {
        let rng = AesRng::from_seed(rand::random());
        let mut ev = TwopcEvaluator::<_, _, ChouOrlandiReceiver, WireMod2>::new(channel, rng)
            .map_err(|e| eyre::eyre!("Evaluator init: {:?}", e))?;

        let all_garbler = ev.receive_many(&vec![2u16; total_input_bits + n_const])
            .map_err(|e| eyre::eyre!("receive: {:?}", e))?;
        let eval_wires = ev.encode_many(
            &my_bits.iter().map(|&b| b as u16).collect::<Vec<_>>(),
            &vec![2u16; total_input_bits],
        ).map_err(|e| eyre::eyre!("encode: {:?}", e))?;

        let (share_w, const_w) = all_garbler.split_at(total_input_bits);
        let output = blake3_circuit::<_, F>(&mut ev, share_w, &eval_wires, const_w, n_inputs, num_bits)?;

        let mut out_bits = Vec::with_capacity(256);
        for w in &output {
            out_bits.push(ev.reveal(w).map_err(|e| eyre::eyre!("reveal: {:?}", e))? != 0);
        }
        bits_to_spdz_shares(&out_bits, 32, state)
    }
}

fn precompute_blake3_constants(num_inputs: usize) -> Vec<bool> {
    let mut bits = Vec::new();
    // IV: 8 words
    for &iv in &IV { bits.extend(u32_to_bits(iv)); }
    // Zero word
    bits.extend(vec![false; 32]);

    // Per-compression constants: IV[0..3], t0, t1, blocklen, flags
    let blocks = num_inputs.max(1).div_ceil(64);
    let chunk_start: u32 = 1;
    let chunk_end: u32 = 2;
    let root_flag: u32 = 8;

    let mut used_flag = chunk_start;
    let mut counter: u64 = 0;

    for block_idx in 0..blocks {
        let is_last = block_idx == blocks - 1;
        let mut flags = if is_last { used_flag | chunk_end | root_flag } else { used_flag };
        if !is_last { used_flag = 0; }

        let blocklen = if is_last {
            let b = num_inputs % 64;
            if num_inputs > 0 && b == 0 { 64u32 } else { b as u32 }
        } else { 64 };

        // IV[0..3] for v[8..11]
        for i in 0..4 { bits.extend(u32_to_bits(IV[i])); }
        // t0, t1
        bits.extend(u32_to_bits(counter as u32));
        bits.extend(u32_to_bits((counter >> 32) as u32));
        // blocklen, flags
        bits.extend(u32_to_bits(blocklen));
        bits.extend(u32_to_bits(flags));
    }

    bits
}

fn blake3_circuit<G: FancyBinary, F: PrimeField>(
    g: &mut G,
    garbler_wires: &[G::Item],
    eval_wires: &[G::Item],
    const_wires: &[G::Item],
    n_inputs: usize,
    num_bits: usize,
) -> Result<Vec<G::Item>, eyre::Report>
where G::Error: std::fmt::Debug {
    let field_bits = F::MODULUS_BIT_SIZE as usize;
    let bits = (num_bits + 7) / 8 * 8;

    // Recover input bytes
    let mut input_bytes: Vec<Vec<G::Item>> = Vec::new();
    for i in 0..n_inputs {
        let start = i * field_bits;
        let a = &garbler_wires[start..start + field_bits];
        let b = &eval_wires[start..start + field_bits];
        let recovered = adder_mod_p::<G, F>(g, a, b, bits)?;
        for chunk in recovered.chunks(8) {
            input_bytes.push(chunk.to_vec());
        }
    }

    // Parse constants
    let mut co = 0;
    let mut h: Vec<Vec<G::Item>> = (0..8).map(|_| {
        let w = const_wires[co..co + 32].to_vec(); co += 32; w
    }).collect();
    let zero_word = const_wires[co..co + 32].to_vec(); co += 32;

    // Process blocks (single chunk)
    let blocks = input_bytes.len().max(1).div_ceil(64);
    for block_idx in 0..blocks {
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

        // Parse per-compression constants: IV[0..3], t0, t1, blocklen, flags
        let v8_11: Vec<Vec<G::Item>> = (0..4).map(|i| {
            const_wires[co + i * 32..co + (i + 1) * 32].to_vec()
        }).collect();
        let t0 = const_wires[co + 128..co + 160].to_vec();
        let t1 = const_wires[co + 160..co + 192].to_vec();
        let blocklen_w = const_wires[co + 192..co + 224].to_vec();
        let flags_w = const_wires[co + 224..co + 256].to_vec();
        co += 256;

        let mut v: Vec<Vec<G::Item>> = Vec::with_capacity(16);
        for hi in &h { v.push(hi.clone()); }
        v.extend(v8_11);
        v.push(t0);
        v.push(t1);
        v.push(blocklen_w);
        v.push(flags_w);

        // 7 rounds
        for r in 0..7 {
            let s = &SIGMA_BLAKE3[r];
            blake3_g(g, &mut v, 0, 4, 8, 12, &msg[s[0]], &msg[s[1]])?;
            blake3_g(g, &mut v, 1, 5, 9, 13, &msg[s[2]], &msg[s[3]])?;
            blake3_g(g, &mut v, 2, 6, 10, 14, &msg[s[4]], &msg[s[5]])?;
            blake3_g(g, &mut v, 3, 7, 11, 15, &msg[s[6]], &msg[s[7]])?;
            blake3_g(g, &mut v, 0, 5, 10, 15, &msg[s[8]], &msg[s[9]])?;
            blake3_g(g, &mut v, 1, 6, 11, 12, &msg[s[10]], &msg[s[11]])?;
            blake3_g(g, &mut v, 2, 7, 8, 13, &msg[s[12]], &msg[s[13]])?;
            blake3_g(g, &mut v, 3, 4, 9, 14, &msg[s[14]], &msg[s[15]])?;
        }

        // Finalize: h[i] = v[i] ^ v[i+8]
        for i in 0..8 {
            h[i] = xor_words(g, &v[i], &v[i + 8])?;
        }
    }

    let mut output = Vec::with_capacity(256);
    for word in &h { output.extend_from_slice(word); }
    output.truncate(256);
    Ok(output)
}

fn blake3_g<G: FancyBinary>(
    g: &mut G, v: &mut [Vec<G::Item>],
    a: usize, b: usize, c: usize, d: usize,
    x: &[G::Item], y: &[G::Item],
) -> Result<(), eyre::Report>
where G::Error: std::fmt::Debug {
    // Same mixing as Blake2s — same rotation constants
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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use rand::SeedableRng;
    use crate::preprocessing::{generate_dummy_preprocessing_with_rng, SpdzPreprocessing};
    use crate::types::{share_field_element, combine_field_element};
    use mpc_net::local::LocalNetwork;

    #[test]
    fn test_gc_blake3_empty() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
        let (mut p0, mut p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(100, &mut rng);
        let mac_key = p0.mac_key_share() + p1.mac_key_share();

        let shares_0: Vec<SpdzPrimeFieldShare<Fr>> = vec![];
        let shares_1: Vec<SpdzPrimeFieldShare<Fr>> = vec![];

        let mut nets = LocalNetwork::new(2).into_iter();
        let (net0, net1) = (nets.next().unwrap(), nets.next().unwrap());
        let state0 = crate::SpdzState::new(0, Box::new(p0));
        let state1 = crate::SpdzState::new(1, Box::new(p1));

        let h0 = std::thread::spawn(move || gc_blake3(&shares_0, 8, &net0, &state0).unwrap());
        let h1 = std::thread::spawn(move || gc_blake3(&shares_1, 8, &net1, &state1).unwrap());

        let r0 = h0.join().unwrap();
        let r1 = h1.join().unwrap();

        let output: Vec<u8> = r0.iter().zip(r1.iter())
            .map(|(a, b)| {
                let val = combine_field_element(*a, *b);
                let big: BigUint = val.into_bigint().into();
                big.to_u32_digits().first().copied().unwrap_or(0) as u8
            }).collect();

        let expected: Vec<u8> = blake3::hash(&[]).as_bytes().to_vec();
        assert_eq!(output, expected, "Blake3 of empty input should match reference");
    }
}
