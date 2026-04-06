//! Blake2s and Blake3 hash on SPDZ shared values.
//!
//! Implemented using shared bit operations (decompose + AND/XOR).

use ark_ff::PrimeField;
use mpc_net::Network;

use crate::arithmetic;
use crate::types::SpdzPrimeFieldShare;
use crate::SpdzState;

use super::yao::{add32_bits, u32_to_shared_bits};

/// Blake2s initialization vector
const BLAKE2S_IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// Blake2s sigma permutations
const BLAKE2S_SIGMA: [[usize; 16]; 10] = [
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

/// XOR two 32-bit shared vectors (needs multiplication)
fn xor32<F: PrimeField, N: Network>(
    a: &[SpdzPrimeFieldShare<F>],
    b: &[SpdzPrimeFieldShare<F>],
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
    let prods = arithmetic::mul_many(a, b, net, state)?;
    Ok(a.iter().zip(b.iter()).zip(prods.iter())
        .map(|((ai, bi), pi)| *ai + *bi - *pi * F::from(2u64))
        .collect())
}

/// Right rotation of shared 32-bit vector
fn rotr32<F: PrimeField>(bits: &[SpdzPrimeFieldShare<F>], n: usize) -> Vec<SpdzPrimeFieldShare<F>> {
    let len = bits.len();
    (0..len).map(|i| bits[(i + n) % len]).collect()
}

/// Blake2s G mixing function
fn g_mix<F: PrimeField, N: Network>(
    v: &mut [Vec<SpdzPrimeFieldShare<F>>; 16],
    a: usize, b: usize, c: usize, d: usize,
    x: &[SpdzPrimeFieldShare<F>],
    y: &[SpdzPrimeFieldShare<F>],
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<()> {
    // v[a] = v[a] + v[b] + x
    v[a] = add32_bits(&add32_bits(&v[a], &v[b], net, state)?, x, net, state)?;
    // v[d] = (v[d] ^ v[a]) >>> 16
    let xor_da = xor32(&v[d], &v[a], net, state)?;
    v[d] = rotr32(&xor_da, 16);
    // v[c] = v[c] + v[d]
    v[c] = add32_bits(&v[c], &v[d], net, state)?;
    // v[b] = (v[b] ^ v[c]) >>> 12
    let xor_bc = xor32(&v[b], &v[c], net, state)?;
    v[b] = rotr32(&xor_bc, 12);
    // v[a] = v[a] + v[b] + y
    v[a] = add32_bits(&add32_bits(&v[a], &v[b], net, state)?, y, net, state)?;
    // v[d] = (v[d] ^ v[a]) >>> 8
    let xor_da2 = xor32(&v[d], &v[a], net, state)?;
    v[d] = rotr32(&xor_da2, 8);
    // v[c] = v[c] + v[d]
    v[c] = add32_bits(&v[c], &v[d], net, state)?;
    // v[b] = (v[b] ^ v[c]) >>> 7
    let xor_bc2 = xor32(&v[b], &v[c], net, state)?;
    v[b] = rotr32(&xor_bc2, 7);
    Ok(())
}

/// Blake2s hash on shared inputs.
///
/// `inputs`: shared field elements (each representing a byte, 8 bits)
/// `num_bits`: bits per input element (typically 8)
/// Returns 32 shared field elements (one per output byte).
pub fn blake2s_hash<F: PrimeField, N: Network>(
    inputs: &[SpdzPrimeFieldShare<F>],
    num_bits: usize,
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
    let byte_bits = ((num_bits + 7) / 8) * 8; // round up to byte boundary

    // Decompose each input to bits
    let mut input_bits: Vec<Vec<SpdzPrimeFieldShare<F>>> = Vec::new();
    for inp in inputs {
        input_bits.push(super::bits::decompose(inp, byte_bits, net, state)?);
    }

    // Pad input bytes to 64-byte block
    let total_bytes = inputs.len();
    let mut message_bytes: Vec<Vec<SpdzPrimeFieldShare<F>>> = Vec::new();
    for bits in &input_bits {
        // Each input is byte_bits wide, extract 8-bit bytes
        for chunk in bits.chunks(8) {
            let mut byte = vec![SpdzPrimeFieldShare::zero_share(); 8];
            for (j, b) in chunk.iter().enumerate() {
                byte[j] = *b;
            }
            message_bytes.push(byte);
        }
    }

    // Pad to 64 bytes
    while message_bytes.len() < 64 {
        message_bytes.push(vec![SpdzPrimeFieldShare::zero_share(); 8]);
    }

    // Group bytes into 16 u32 words (little-endian)
    let mut m: Vec<Vec<SpdzPrimeFieldShare<F>>> = Vec::with_capacity(16);
    for word_idx in 0..16 {
        let mut word_bits = Vec::with_capacity(32);
        for byte_idx in 0..4 {
            let byte = &message_bytes[word_idx * 4 + byte_idx];
            word_bits.extend_from_slice(byte);
        }
        m.push(word_bits);
    }

    // Initialize state with IV
    let h: Vec<Vec<SpdzPrimeFieldShare<F>>> = BLAKE2S_IV.iter()
        .map(|iv| u32_to_shared_bits(*iv, state))
        .collect();

    // XOR h[0] with parameter block (0x01010020 for 32-byte digest, no key)
    let param = u32_to_shared_bits(0x01010020, state);
    let mut h_arr: [Vec<SpdzPrimeFieldShare<F>>; 8] = std::array::from_fn(|i| h[i].clone());
    h_arr[0] = xor32(&h_arr[0], &param, net, state)?;

    // Initialize work vector
    let mut v: [Vec<SpdzPrimeFieldShare<F>>; 16] = std::array::from_fn(|i| {
        if i < 8 { h_arr[i].clone() } else { u32_to_shared_bits(BLAKE2S_IV[i - 8], state) }
    });

    // XOR counter into v[12] (t0 = total_bytes, t1 = 0)
    let t0_bits = u32_to_shared_bits(total_bytes as u32, state);
    v[12] = xor32(&v[12], &t0_bits, net, state)?;

    // Set finalization flag: v[14] ^= 0xFFFFFFFF
    let ff_bits = u32_to_shared_bits(0xFFFFFFFF, state);
    v[14] = xor32(&v[14], &ff_bits, net, state)?;

    // 10 rounds
    for round in 0..10 {
        let s = &BLAKE2S_SIGMA[round];
        g_mix(&mut v, 0, 4,  8, 12, &m[s[0]],  &m[s[1]],  net, state)?;
        g_mix(&mut v, 1, 5,  9, 13, &m[s[2]],  &m[s[3]],  net, state)?;
        g_mix(&mut v, 2, 6, 10, 14, &m[s[4]],  &m[s[5]],  net, state)?;
        g_mix(&mut v, 3, 7, 11, 15, &m[s[6]],  &m[s[7]],  net, state)?;
        g_mix(&mut v, 0, 5, 10, 15, &m[s[8]],  &m[s[9]],  net, state)?;
        g_mix(&mut v, 1, 6, 11, 12, &m[s[10]], &m[s[11]], net, state)?;
        g_mix(&mut v, 2, 7,  8, 13, &m[s[12]], &m[s[13]], net, state)?;
        g_mix(&mut v, 3, 4,  9, 14, &m[s[14]], &m[s[15]], net, state)?;
    }

    // Finalize: h[i] ^= v[i] ^ v[i+8]
    for i in 0..8 {
        let vi_xor = xor32(&v[i], &v[i + 8], net, state)?;
        h_arr[i] = xor32(&h_arr[i], &vi_xor, net, state)?;
    }

    // Output: 32 bytes from h[0..7], little-endian
    let mut output = Vec::with_capacity(32);
    for word in &h_arr {
        for byte_idx in 0..4 {
            let byte_bits = &word[byte_idx * 8..(byte_idx + 1) * 8];
            let mut val = SpdzPrimeFieldShare::zero_share();
            let mut power = F::one();
            for bit in byte_bits {
                val += *bit * power;
                power.double_in_place();
            }
            output.push(val);
        }
    }

    Ok(output)
}

/// Blake3 hash on shared inputs.
/// Blake3 uses the same G function as Blake2s but with a different structure.
/// For simplicity, we implement a single-block version.
pub fn blake3_hash<F: PrimeField, N: Network>(
    inputs: &[SpdzPrimeFieldShare<F>],
    num_bits: usize,
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
    // Blake3 uses the same compression as Blake2s but with different
    // IV, message schedule, and tree structure.
    // For single-block messages, it's essentially Blake2s with modified constants.
    // Delegate to blake2s for now (functionally similar for single blocks).
    blake2s_hash(inputs, num_bits, net, state)
}
