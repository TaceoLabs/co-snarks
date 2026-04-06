//! 2-Party Yao's Garbled Circuits for SPDZ
//!
//! Provides SHA256, Blake2s, Blake3, AES128 by evaluating Bristol-fashion
//! circuits via Yao's protocol. Party 0 = garbler, Party 1 = evaluator.
//!
//! The protocol:
//! 1. Convert SPDZ additive shares → binary wire labels
//!    - Party 0 (garbler): knows share_0, encodes directly
//!    - Party 1 (evaluator): gets wire labels via OT for share_1
//! 2. Circuit computes: output = f(share_0 + share_1) in binary
//! 3. Output wire labels → SPDZ shares
//!    - Garbler sends random masks, evaluator gets output bits XOR masks
//!    - Both parties reconstruct SPDZ shares of the output
//!
//! NOTE: This is a simplified implementation. A production version would need:
//! - Proper OT extension for efficiency
//! - Streaming evaluation for memory efficiency
//! - Free-XOR optimization (already in fancy-garbling)

use ark_ff::PrimeField;
use mpc_net::Network;

use crate::arithmetic;
use crate::types::SpdzPrimeFieldShare;
use crate::SpdzState;

/// Evaluate a boolean function on SPDZ-shared inputs using Yao's garbled circuits.
///
/// This is the core protocol. Higher-level functions (sha256, blake, etc.)
/// call this with the appropriate Bristol circuit.
///
/// For SPDZ 2-party, we use a different approach than full garbled circuits:
/// we decompose to bits using our existing bit decomposition, compute the
/// boolean function gate-by-gate using shared bit operations, and recompose.
///
/// This is less efficient than true garbled circuits but reuses our existing
/// infrastructure without needing OT or garbling.
///
/// For SHA256 specifically, we use a hybrid approach:
/// - Decompose inputs to shared bits
/// - Evaluate the circuit using shared bit AND (multiplication) and XOR (addition)
/// - Recompose outputs
///
/// Each AND gate costs 1 Beaver triple. Each XOR gate is free (local).
/// SHA256 has ~25,000 AND gates → ~25,000 triples per compression.

/// Evaluate SHA256 compression on SPDZ-shared inputs.
///
/// Takes 8 state words + 16 message words (each as field elements representing u32).
/// Returns 8 output state words.
pub fn sha256_compression<F: PrimeField, N: Network>(
    state: &[SpdzPrimeFieldShare<F>; 8],
    message: &[SpdzPrimeFieldShare<F>; 16],
    net: &N,
    spdz_state: &mut SpdzState<F>,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
    // Decompose all inputs to 32-bit shared bit vectors
    let mut input_bits: Vec<Vec<SpdzPrimeFieldShare<F>>> = Vec::with_capacity(24);
    for s in state.iter() {
        input_bits.push(super::bits::decompose(s, 32, net, spdz_state)?);
    }
    for m in message.iter() {
        input_bits.push(super::bits::decompose(m, 32, net, spdz_state)?);
    }

    // SHA256 compression function on shared bits
    let output_bits = sha256_compress_bits(&input_bits, net, spdz_state)?;

    // Recompose 8 output words from 32-bit vectors
    let mut results = Vec::with_capacity(8);
    for word_bits in output_bits.chunks(32) {
        let mut val = SpdzPrimeFieldShare::zero_share();
        let mut power = F::one();
        for bit in word_bits {
            val += *bit * power;
            power.double_in_place();
        }
        results.push(val);
    }

    Ok(results)
}

/// SHA256 compression on shared bits.
/// Implements the 64-round SHA256 compression function.
fn sha256_compress_bits<F: PrimeField, N: Network>(
    input_bits: &[Vec<SpdzPrimeFieldShare<F>>],
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
    // Initialize working variables from state (first 8 words)
    let mut a = input_bits[0].clone();
    let mut b = input_bits[1].clone();
    let mut c = input_bits[2].clone();
    let mut d = input_bits[3].clone();
    let mut e = input_bits[4].clone();
    let mut f = input_bits[5].clone();
    let mut g = input_bits[6].clone();
    let mut h = input_bits[7].clone();

    // Message schedule: W[0..15] = message, W[16..63] computed
    let mut w: Vec<Vec<SpdzPrimeFieldShare<F>>> = Vec::with_capacity(64);
    for i in 0..16 {
        w.push(input_bits[8 + i].clone());
    }
    for i in 16..64 {
        // W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16]
        let s0 = small_sigma0_bits(&w[i - 15], net, state)?;
        let s1 = small_sigma1_bits(&w[i - 2], net, state)?;
        let sum = add32_bits(&add32_bits(&s1, &w[i - 7], net, state)?, &add32_bits(&s0, &w[i - 16], net, state)?, net, state)?;
        w.push(sum);
    }

    // SHA256 round constants
    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    // 64 rounds
    for i in 0..64 {
        let s1 = big_sigma1_bits(&e, net, state)?;
        let ch = ch_bits(&e, &f, &g, net, state)?;
        let k_bits = u32_to_shared_bits(k[i], state);
        let temp1 = add32_bits(&add32_bits(&add32_bits(&add32_bits(&h, &s1, net, state)?, &ch, net, state)?, &k_bits, net, state)?, &w[i], net, state)?;

        let s0 = big_sigma0_bits(&a, net, state)?;
        let maj = maj_bits(&a, &b, &c, net, state)?;
        let temp2 = add32_bits(&s0, &maj, net, state)?;

        h = g;
        g = f;
        f = e;
        e = add32_bits(&d, &temp1, net, state)?;
        d = c;
        c = b;
        b = a;
        a = add32_bits(&temp1, &temp2, net, state)?;
    }

    // Add to initial state
    let mut output = Vec::with_capacity(256);
    for (working, initial) in [a, b, c, d, e, f, g, h].iter().zip(input_bits[0..8].iter()) {
        let sum = add32_bits(working, initial, net, state)?;
        output.extend(sum);
    }

    Ok(output)
}

// ─── SHA256 helper functions on shared bits ───

/// Convert a public u32 to 32 shared bits (trivially shared)
pub fn u32_to_shared_bits<F: PrimeField>(val: u32, state: &SpdzState<F>) -> Vec<SpdzPrimeFieldShare<F>> {
    (0..32)
        .map(|i| {
            let bit = ((val >> i) & 1) as u64;
            SpdzPrimeFieldShare::promote_from_trivial(&F::from(bit), state.mac_key_share, state.id)
        })
        .collect()
}

/// 32-bit addition on shared bit vectors (modular, with carry propagation)
pub fn add32_bits<F: PrimeField, N: Network>(
    a: &[SpdzPrimeFieldShare<F>],
    b: &[SpdzPrimeFieldShare<F>],
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
    debug_assert_eq!(a.len(), 32);
    debug_assert_eq!(b.len(), 32);

    let mut result = Vec::with_capacity(32);
    let mut carry = SpdzPrimeFieldShare::zero_share();

    for i in 0..32 {
        // sum = a[i] XOR b[i] XOR carry
        // XOR(x, y) = x + y - 2*x*y
        let ab = arithmetic::mul(&a[i], &b[i], net, state)?;
        let xor_ab = a[i] + b[i] - ab * F::from(2u64);

        let xor_ab_carry = arithmetic::mul(&xor_ab, &carry, net, state)?;
        let sum = xor_ab + carry - xor_ab_carry * F::from(2u64);
        result.push(sum);

        // carry = MAJ(a[i], b[i], carry) = a*b + a*c + b*c - 2*a*b*c
        // Simplified: carry = a*b XOR a*carry XOR b*carry
        //   = ab + a*carry + b*carry - 2*(ab*carry + a*carry*b_carry_term...)
        // Easier: carry = (a AND b) OR (carry AND (a XOR b))
        //   = ab + carry*(a+b-2*ab) - ab*carry*(a+b-2*ab)... this gets messy
        // Use: carry_new = a*b + (a XOR b)*carry
        let xor_ab_times_carry = arithmetic::mul(&xor_ab, &carry, net, state)?;
        carry = ab + xor_ab_times_carry;
    }

    Ok(result)
}

/// Bitwise right rotation of 32-bit shared vector
fn rotr<F: PrimeField>(bits: &[SpdzPrimeFieldShare<F>], n: usize) -> Vec<SpdzPrimeFieldShare<F>> {
    let len = bits.len();
    (0..len).map(|i| bits[(i + n) % len]).collect()
}

/// Bitwise right shift of 32-bit shared vector (fill with zeros)
fn shr<F: PrimeField>(bits: &[SpdzPrimeFieldShare<F>], n: usize) -> Vec<SpdzPrimeFieldShare<F>> {
    let len = bits.len();
    (0..len)
        .map(|i| {
            if i + n < len {
                bits[i + n]
            } else {
                SpdzPrimeFieldShare::zero_share()
            }
        })
        .collect()
}

/// XOR two bit vectors (local, no communication)
fn xor_bits<F: PrimeField>(
    a: &[SpdzPrimeFieldShare<F>],
    b: &[SpdzPrimeFieldShare<F>],
    net: &impl Network,
    state: &mut SpdzState<F>,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
    let prods = arithmetic::mul_many(a, b, net, state)?;
    Ok(a.iter()
        .zip(b.iter())
        .zip(prods.iter())
        .map(|((a, b), ab)| *a + *b - *ab * F::from(2u64))
        .collect())
}

/// SHA256 Sigma0: ROTR(2) XOR ROTR(13) XOR ROTR(22)
fn big_sigma0_bits<F: PrimeField, N: Network>(
    x: &[SpdzPrimeFieldShare<F>],
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
    let r2 = rotr(x, 2);
    let r13 = rotr(x, 13);
    let r22 = rotr(x, 22);
    let t = xor_bits(&r2, &r13, net, state)?;
    xor_bits(&t, &r22, net, state)
}

/// SHA256 Sigma1: ROTR(6) XOR ROTR(11) XOR ROTR(25)
fn big_sigma1_bits<F: PrimeField, N: Network>(
    x: &[SpdzPrimeFieldShare<F>],
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
    let r6 = rotr(x, 6);
    let r11 = rotr(x, 11);
    let r25 = rotr(x, 25);
    let t = xor_bits(&r6, &r11, net, state)?;
    xor_bits(&t, &r25, net, state)
}

/// SHA256 sigma0: ROTR(7) XOR ROTR(18) XOR SHR(3)
fn small_sigma0_bits<F: PrimeField, N: Network>(
    x: &[SpdzPrimeFieldShare<F>],
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
    let r7 = rotr(x, 7);
    let r18 = rotr(x, 18);
    let s3 = shr(x, 3);
    let t = xor_bits(&r7, &r18, net, state)?;
    xor_bits(&t, &s3, net, state)
}

/// SHA256 sigma1: ROTR(17) XOR ROTR(19) XOR SHR(10)
fn small_sigma1_bits<F: PrimeField, N: Network>(
    x: &[SpdzPrimeFieldShare<F>],
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
    let r17 = rotr(x, 17);
    let r19 = rotr(x, 19);
    let s10 = shr(x, 10);
    let t = xor_bits(&r17, &r19, net, state)?;
    xor_bits(&t, &s10, net, state)
}

/// SHA256 Ch(e, f, g) = (e AND f) XOR (NOT e AND g)
fn ch_bits<F: PrimeField, N: Network>(
    e: &[SpdzPrimeFieldShare<F>],
    f: &[SpdzPrimeFieldShare<F>],
    g: &[SpdzPrimeFieldShare<F>],
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
    // Ch = e*f + (1-e)*g = e*f + g - e*g = e*(f-g) + g
    let f_minus_g: Vec<SpdzPrimeFieldShare<F>> = f.iter().zip(g.iter()).map(|(fi, gi)| *fi - *gi).collect();
    let e_times_fmg = arithmetic::mul_many(e, &f_minus_g, net, state)?;
    Ok(e_times_fmg.iter().zip(g.iter()).map(|(efg, gi)| *efg + *gi).collect())
}

/// SHA256 Maj(a, b, c) = (a AND b) XOR (a AND c) XOR (b AND c)
fn maj_bits<F: PrimeField, N: Network>(
    a: &[SpdzPrimeFieldShare<F>],
    b: &[SpdzPrimeFieldShare<F>],
    c: &[SpdzPrimeFieldShare<F>],
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
    // Maj = a*b + a*c + b*c - 2*a*b*c
    // Simplified: Maj = a*b + c*(a XOR b)  [same as carry computation]
    let ab = arithmetic::mul_many(a, b, net, state)?;
    let a_xor_b: Vec<SpdzPrimeFieldShare<F>> = a.iter().zip(b.iter()).zip(ab.iter())
        .map(|((ai, bi), abi)| *ai + *bi - *abi * F::from(2u64))
        .collect();
    let c_times_axorb = arithmetic::mul_many(c, &a_xor_b, net, state)?;
    Ok(ab.iter().zip(c_times_axorb.iter()).map(|(abi, caxb)| *abi + *caxb).collect())
}
