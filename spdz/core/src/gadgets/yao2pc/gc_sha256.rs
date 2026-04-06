//! SHA256 compression via garbled circuit on SPDZ shares.
//!
//! Implements the SHA256 round function using FancyBinary gates.
//! Uses the same GC pipeline as Blake2s/Blake3: modular-add shares,
//! evaluate hash, reveal output.

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
use super::gc_blake2s::{u32_to_bits, xor_words, add32};
use super::gc_hash::{adder_mod_p, bits_to_spdz_shares};

/// SHA256 round constants K[0..63]
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA256 initial hash values
const H_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Evaluate SHA256 compression on SPDZ-shared state + message via GC.
/// Takes 8 state words + 16 message words (24 shared u32 values).
/// Returns 8 output state words as SPDZ trivial shares.
pub fn gc_sha256_compression<F: PrimeField, N: Network>(
    state_shares: &[SpdzPrimeFieldShare<F>],
    message_shares: &[SpdzPrimeFieldShare<F>],
    net: &N,
    spdz_state: &SpdzState<F>,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
    assert_eq!(state_shares.len(), 8);
    assert_eq!(message_shares.len(), 16);

    let party_id = spdz_state.id;
    let field_bits = F::MODULUS_BIT_SIZE as usize;
    let n_inputs = 24; // 8 state + 16 message
    let total_input_bits = n_inputs * field_bits;

    // All inputs concatenated
    let all_shares: Vec<_> = state_shares.iter().chain(message_shares.iter()).collect();
    let my_bits: Vec<bool> = all_shares.iter().flat_map(|share| {
        let val: BigUint = share.share.into_bigint().into();
        (0..field_bits).map(move |i| val.bit(i as u64))
    }).collect();

    // Precompute constants: K[0..63] + initial state isn't needed here since
    // state comes as input. We just need K for the 64 rounds.
    let const_bits = precompute_sha256_constants();
    let n_const = const_bits.len();

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
        let output = sha256_circuit::<_, F>(&mut gb, share_w, &eval_wires, const_w)?;

        let mut out_bits = Vec::with_capacity(256);
        for w in &output {
            out_bits.push(gb.reveal(w).map_err(|e| eyre::eyre!("reveal: {:?}", e))? != 0);
        }
        bits_to_spdz_u32_shares(&out_bits, spdz_state)
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
        let output = sha256_circuit::<_, F>(&mut ev, share_w, &eval_wires, const_w)?;

        let mut out_bits = Vec::with_capacity(256);
        for w in &output {
            out_bits.push(ev.reveal(w).map_err(|e| eyre::eyre!("reveal: {:?}", e))? != 0);
        }
        bits_to_spdz_u32_shares(&out_bits, spdz_state)
    }
}

fn precompute_sha256_constants() -> Vec<bool> {
    let mut bits = Vec::new();
    // 64 round constants K[0..63], 32 bits each = 2048 bits
    for &k in &K {
        bits.extend(u32_to_bits(k));
    }
    bits
}

fn sha256_circuit<G: FancyBinary, F: PrimeField>(
    g: &mut G,
    garbler_wires: &[G::Item],
    eval_wires: &[G::Item],
    const_wires: &[G::Item],
) -> Result<Vec<G::Item>, eyre::Report>
where G::Error: std::fmt::Debug {
    let field_bits = F::MODULUS_BIT_SIZE as usize;

    // Recover 24 u32 words via modular addition (8 state + 16 message)
    let mut words: Vec<Vec<G::Item>> = Vec::with_capacity(24);
    for i in 0..24 {
        let start = i * field_bits;
        let a = &garbler_wires[start..start + field_bits];
        let b = &eval_wires[start..start + field_bits];
        words.push(adder_mod_p::<G, F>(g, a, b, 32)?);
    }

    let state_words = &words[0..8];
    let msg_words = &words[8..24];

    // Parse K constants
    let k_words: Vec<Vec<G::Item>> = (0..64).map(|i| {
        const_wires[i * 32..(i + 1) * 32].to_vec()
    }).collect();

    // Message schedule: W[0..15] = message, W[16..63] computed
    let mut w: Vec<Vec<G::Item>> = msg_words.to_vec();
    for i in 16..64 {
        // W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16]
        let s1 = small_sigma1(g, &w[i - 2])?;
        let s0 = small_sigma0(g, &w[i - 15])?;
        let mut t = add32(g, &s1, &w[i - 7])?;
        t = add32(g, &t, &s0)?;
        t = add32(g, &t, &w[i - 16])?;
        w.push(t);
    }

    // Initialize working variables
    let mut a = state_words[0].clone();
    let mut b = state_words[1].clone();
    let mut c = state_words[2].clone();
    let mut d = state_words[3].clone();
    let mut e = state_words[4].clone();
    let mut f = state_words[5].clone();
    let mut gv = state_words[6].clone();
    let mut h = state_words[7].clone();

    // 64 rounds
    for i in 0..64 {
        // T1 = h + Sigma1(e) + Ch(e,f,g) + K[i] + W[i]
        let sig1 = big_sigma1(g, &e)?;
        let ch = ch(g, &e, &f, &gv)?;
        let mut t1 = add32(g, &h, &sig1)?;
        t1 = add32(g, &t1, &ch)?;
        t1 = add32(g, &t1, &k_words[i])?;
        t1 = add32(g, &t1, &w[i])?;

        // T2 = Sigma0(a) + Maj(a,b,c)
        let sig0 = big_sigma0(g, &a)?;
        let mj = maj(g, &a, &b, &c)?;
        let t2 = add32(g, &sig0, &mj)?;

        h = gv;
        gv = f;
        f = e;
        e = add32(g, &d, &t1)?;
        d = c;
        c = b;
        b = a;
        a = add32(g, &t1, &t2)?;
    }

    // Add to original state
    let mut output = Vec::with_capacity(256);
    let results = [
        add32(g, &state_words[0], &a)?,
        add32(g, &state_words[1], &b)?,
        add32(g, &state_words[2], &c)?,
        add32(g, &state_words[3], &d)?,
        add32(g, &state_words[4], &e)?,
        add32(g, &state_words[5], &f)?,
        add32(g, &state_words[6], &gv)?,
        add32(g, &state_words[7], &h)?,
    ];
    for word in &results {
        output.extend_from_slice(word);
    }
    Ok(output)
}

// SHA256 functions

/// Ch(x, y, z) = (x AND y) XOR (NOT x AND z)
fn ch<G: FancyBinary>(g: &mut G, x: &[G::Item], y: &[G::Item], z: &[G::Item]) -> Result<Vec<G::Item>, eyre::Report>
where G::Error: std::fmt::Debug {
    let mut result = Vec::with_capacity(32);
    for i in 0..32 {
        let xy = g.and(&x[i], &y[i]).map_err(|e| eyre::eyre!("{:?}", e))?;
        let nx = g.negate(&x[i]).map_err(|e| eyre::eyre!("{:?}", e))?;
        let nxz = g.and(&nx, &z[i]).map_err(|e| eyre::eyre!("{:?}", e))?;
        let r = g.xor(&xy, &nxz).map_err(|e| eyre::eyre!("{:?}", e))?;
        result.push(r);
    }
    Ok(result)
}

/// Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
fn maj<G: FancyBinary>(g: &mut G, x: &[G::Item], y: &[G::Item], z: &[G::Item]) -> Result<Vec<G::Item>, eyre::Report>
where G::Error: std::fmt::Debug {
    let mut result = Vec::with_capacity(32);
    for i in 0..32 {
        let xy = g.and(&x[i], &y[i]).map_err(|e| eyre::eyre!("{:?}", e))?;
        let xz = g.and(&x[i], &z[i]).map_err(|e| eyre::eyre!("{:?}", e))?;
        let yz = g.and(&y[i], &z[i]).map_err(|e| eyre::eyre!("{:?}", e))?;
        let t = g.xor(&xy, &xz).map_err(|e| eyre::eyre!("{:?}", e))?;
        let r = g.xor(&t, &yz).map_err(|e| eyre::eyre!("{:?}", e))?;
        result.push(r);
    }
    Ok(result)
}

/// Sigma0(x) = ROTR(2, x) XOR ROTR(13, x) XOR ROTR(22, x)
fn big_sigma0<G: FancyBinary>(g: &mut G, x: &[G::Item]) -> Result<Vec<G::Item>, eyre::Report>
where G::Error: std::fmt::Debug {
    let r2 = rotate_right_copy(x, 2);
    let r13 = rotate_right_copy(x, 13);
    let r22 = rotate_right_copy(x, 22);
    let t = xor_words(g, &r2, &r13)?;
    xor_words(g, &t, &r22)
}

/// Sigma1(x) = ROTR(6, x) XOR ROTR(11, x) XOR ROTR(25, x)
fn big_sigma1<G: FancyBinary>(g: &mut G, x: &[G::Item]) -> Result<Vec<G::Item>, eyre::Report>
where G::Error: std::fmt::Debug {
    let r6 = rotate_right_copy(x, 6);
    let r11 = rotate_right_copy(x, 11);
    let r25 = rotate_right_copy(x, 25);
    let t = xor_words(g, &r6, &r11)?;
    xor_words(g, &t, &r25)
}

/// sigma0(x) = ROTR(7, x) XOR ROTR(18, x) XOR SHR(3, x)
fn small_sigma0<G: FancyBinary>(g: &mut G, x: &[G::Item]) -> Result<Vec<G::Item>, eyre::Report>
where G::Error: std::fmt::Debug {
    let r7 = rotate_right_copy(x, 7);
    let r18 = rotate_right_copy(x, 18);
    // SHR(3): shift right by 3, fill with zeros
    // In LSB-first: drop first 3 bits, shift remaining left, pad 3 zeros at end
    let mut s3 = x[3..].to_vec();
    // Need zero wires. Use XOR(x[0], x[0]) = 0
    let zero = g.xor(&x[0], &x[0]).map_err(|e| eyre::eyre!("{:?}", e))?;
    while s3.len() < 32 { s3.push(zero.clone()); }
    let t = xor_words(g, &r7, &r18)?;
    xor_words(g, &t, &s3)
}

/// sigma1(x) = ROTR(17, x) XOR ROTR(19, x) XOR SHR(10, x)
fn small_sigma1<G: FancyBinary>(g: &mut G, x: &[G::Item]) -> Result<Vec<G::Item>, eyre::Report>
where G::Error: std::fmt::Debug {
    let r17 = rotate_right_copy(x, 17);
    let r19 = rotate_right_copy(x, 19);
    let mut s10 = x[10..].to_vec();
    let zero = g.xor(&x[0], &x[0]).map_err(|e| eyre::eyre!("{:?}", e))?;
    while s10.len() < 32 { s10.push(zero.clone()); }
    let t = xor_words(g, &r17, &r19)?;
    xor_words(g, &t, &s10)
}

/// Right-rotate a 32-bit word (LSB-first encoding).
/// ROTR(n, x) in LSB-first = left-rotate the bit array by n positions.
/// Returns a new Vec (non-mutating).
fn rotate_right_copy<T: Clone>(bits: &[T], n: usize) -> Vec<T> {
    let len = bits.len();
    let n = n % len;
    // Right rotate the VALUE = left rotate the LSB-first array
    let mut result = Vec::with_capacity(len);
    result.extend_from_slice(&bits[n..]);
    result.extend_from_slice(&bits[..n]);
    result
}

/// Convert output bits (8 × 32-bit words) to SPDZ trivial shares of u32.
fn bits_to_spdz_u32_shares<F: PrimeField>(
    output_bits: &[bool],
    state: &SpdzState<F>,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
    let mut result = Vec::with_capacity(8);
    for word_idx in 0..8 {
        let mut val = 0u64;
        for bit in 0..32 {
            let idx = word_idx * 32 + bit;
            if idx < output_bits.len() && output_bits[idx] {
                val |= 1 << bit;
            }
        }
        result.push(SpdzPrimeFieldShare::promote_from_trivial(
            &F::from(val),
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
    fn test_gc_sha256_compression() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
        let (mut p0, mut p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(100, &mut rng);
        let mac_key = p0.mac_key_share() + p1.mac_key_share();

        // Test: SHA256 compression of all-zero state + all-zero message
        let state_vals: Vec<Fr> = H_INIT.iter().map(|&h| Fr::from(h as u64)).collect();
        let msg_vals: Vec<Fr> = vec![Fr::from(0u64); 16];

        let mut s0 = Vec::new();
        let mut s1 = Vec::new();
        for val in state_vals.iter().chain(msg_vals.iter()) {
            let [sh0, sh1] = share_field_element(*val, mac_key, &mut rng);
            s0.push(sh0);
            s1.push(sh1);
        }

        let (state0_s, msg0_s) = s0.split_at(8);
        let (state1_s, msg1_s) = s1.split_at(8);
        let state0: Vec<_> = state0_s.to_vec();
        let msg0: Vec<_> = msg0_s.to_vec();
        let state1: Vec<_> = state1_s.to_vec();
        let msg1: Vec<_> = msg1_s.to_vec();

        let mut nets = LocalNetwork::new(2).into_iter();
        let (net0, net1) = (nets.next().unwrap(), nets.next().unwrap());
        let st0 = crate::SpdzState::new(0, Box::new(p0));
        let st1 = crate::SpdzState::new(1, Box::new(p1));

        let h0 = std::thread::spawn(move || {
            gc_sha256_compression(&state0, &msg0, &net0, &st0).unwrap()
        });
        let h1 = std::thread::spawn(move || {
            gc_sha256_compression(&state1, &msg1, &net1, &st1).unwrap()
        });

        let r0 = h0.join().unwrap();
        let r1 = h1.join().unwrap();

        // Reconstruct and compare with reference
        let output: Vec<u32> = r0.iter().zip(r1.iter()).map(|(a, b)| {
            let val = combine_field_element(*a, *b);
            let big: BigUint = val.into_bigint().into();
            big.to_u32_digits().first().copied().unwrap_or(0)
        }).collect();

        // Reference: SHA256 compression(H_INIT, all-zero message)
        // Computed offline:
        let expected: [u32; 8] = [
            0xda5698be, 0x17b9b469, 0x62335799, 0x779fbeca,
            0x8ce5d491, 0xc0d26243, 0xbafef9ea, 0x1837a9d8,
        ];

        assert_eq!(output.len(), 8);
        for i in 0..8 {
            assert_eq!(output[i], expected[i], "SHA256 word {i} mismatch: got 0x{:08x}, expected 0x{:08x}", output[i], expected[i]);
        }
    }
}
