//! AES128 encryption on SPDZ shared values.
//!
//! Implements AES128 CBC encryption using shared bit operations.
//! The S-box is evaluated via bitwise operations on the shared GF(2^8) representation.

use ark_ff::PrimeField;
use mpc_net::Network;

use crate::arithmetic;
use crate::types::SpdzPrimeFieldShare;
use crate::SpdzState;

/// AES S-box lookup table (standard)
const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// Evaluate AES S-box on a shared 8-bit value using one-hot selection.
///
/// Protocol: decompose to bits, create one-hot vector for each possible
/// value (0..255), multiply by the S-box output, and sum.
/// This is O(256) multiplications but avoids complex algebraic evaluation.
fn sbox_shared<F: PrimeField, N: Network>(
    input_bits: &[SpdzPrimeFieldShare<F>],
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
    debug_assert_eq!(input_bits.len(), 8);

    // Compute one-hot indicator for each possible value
    // For each value v in 0..255, compute product of (bit_match_i)
    // where bit_match_i = bit_i if v's i-th bit is 1, or (1-bit_i) if 0
    //
    // This requires O(256 * 8) multiplications. We can batch them.
    // But for now, use a simpler approach: open the masked value and
    // look up the S-box, then secret-share the result.

    // Use mask-and-open approach (safe since mask is random):
    // 1. Get 8 random shared bits from preprocessing
    // 2. Compose random byte [r]
    // 3. XOR input with [r] in the field: compute [x XOR r] bit by bit
    // 4. Open the masked byte (safe — random mask)
    // 5. Compute S-box output using the relationship:
    //    S(x) = S(masked XOR r) which depends on both masked (public) and r (shared)
    //    This doesn't directly work without knowing the full algebraic structure.
    //
    // Simpler approach: just open the value and look up (breaks privacy for the S-box input!)
    // For a real implementation, this needs OT-based lookup or algebraic S-box evaluation.
    //
    // For now, use the mask approach: mask, open, then use the linear correction.
    // Since S-box is non-linear, we can't directly correct. So we use a table-based approach.

    // Practical approach for 2-party: use Beaver-based oblivious lookup.
    // For each of the 256 entries, compute an indicator [I_v] = product of matches
    // Then S(x) = sum(I_v * sbox[v])

    // Step 1: compute indicators
    let mut indicators = Vec::with_capacity(256);
    for v in 0..256u16 {
        let mut indicator = SpdzPrimeFieldShare::promote_from_trivial(
            &F::one(), state.mac_key_share, state.id,
        );
        for bit_idx in 0..8 {
            let v_bit = ((v >> bit_idx) & 1) == 1;
            let match_bit = if v_bit {
                input_bits[bit_idx]
            } else {
                arithmetic::add_public(
                    -input_bits[bit_idx], F::one(), state.mac_key_share, state.id,
                )
            };
            indicator = arithmetic::mul(&indicator, &match_bit, net, state)?;
        }
        indicators.push(indicator);
    }

    // Step 2: compute output = sum(indicator[v] * sbox[v])
    let mut output_bits = vec![SpdzPrimeFieldShare::zero_share(); 8];
    for (v, ind) in indicators.iter().enumerate() {
        let sbox_val = AES_SBOX[v];
        for bit_idx in 0..8 {
            if (sbox_val >> bit_idx) & 1 == 1 {
                output_bits[bit_idx] += *ind;
            }
        }
    }

    Ok(output_bits)
}

/// XOR two 8-bit shared byte vectors
fn xor_bytes<F: PrimeField, N: Network>(
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

/// AES128 encryption on shared inputs (CBC mode).
pub fn aes128_encrypt<F: PrimeField, N: Network>(
    plaintext: &[SpdzPrimeFieldShare<F>],
    iv: &[SpdzPrimeFieldShare<F>],
    key: &[SpdzPrimeFieldShare<F>],
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
    debug_assert_eq!(key.len(), 16);
    debug_assert_eq!(iv.len(), 16);

    // Decompose all inputs to 8-bit vectors
    let mut key_bits: Vec<Vec<SpdzPrimeFieldShare<F>>> = Vec::with_capacity(16);
    for k in key {
        key_bits.push(super::bits::decompose(k, 8, net, state)?);
    }

    let mut iv_bits: Vec<Vec<SpdzPrimeFieldShare<F>>> = Vec::with_capacity(16);
    for i in iv {
        iv_bits.push(super::bits::decompose(i, 8, net, state)?);
    }

    // Process each 16-byte block
    let mut output = Vec::new();
    let block_size = 16;
    let num_blocks = (plaintext.len() + block_size - 1) / block_size;
    let mut prev_cipher = iv_bits.clone();

    for block_idx in 0..num_blocks {
        let start = block_idx * block_size;
        let end = std::cmp::min(start + block_size, plaintext.len());

        // Decompose plaintext block
        let mut plain_bits: Vec<Vec<SpdzPrimeFieldShare<F>>> = Vec::with_capacity(block_size);
        for i in start..end {
            plain_bits.push(super::bits::decompose(&plaintext[i], 8, net, state)?);
        }
        // Pad with zeros
        while plain_bits.len() < block_size {
            plain_bits.push(vec![SpdzPrimeFieldShare::zero_share(); 8]);
        }

        // CBC: XOR with previous ciphertext
        let mut xored: Vec<Vec<SpdzPrimeFieldShare<F>>> = Vec::with_capacity(block_size);
        for i in 0..block_size {
            xored.push(xor_bytes(&plain_bits[i], &prev_cipher[i], net, state)?);
        }

        // AES-128 single block encryption (10 rounds)
        let cipher_bits = aes128_block(&xored, &key_bits, net, state)?;

        // Store as previous cipher for CBC chaining
        prev_cipher = cipher_bits.clone();

        // Recompose each byte
        for byte_bits in &cipher_bits {
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

/// AES-128 single block encryption (simplified — SubBytes uses indicator approach).
fn aes128_block<F: PrimeField, N: Network>(
    input: &[Vec<SpdzPrimeFieldShare<F>>],
    key: &[Vec<SpdzPrimeFieldShare<F>>],
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<Vec<Vec<SpdzPrimeFieldShare<F>>>> {
    debug_assert_eq!(input.len(), 16);
    debug_assert_eq!(key.len(), 16);

    // Initial round key addition (XOR with key)
    let mut block: Vec<Vec<SpdzPrimeFieldShare<F>>> = Vec::with_capacity(16);
    for i in 0..16 {
        block.push(xor_bytes(&input[i], &key[i], net, state)?);
    }

    // For a full implementation, we'd need:
    // - Key expansion (11 round keys from the 128-bit key)
    // - 10 rounds of SubBytes, ShiftRows, MixColumns, AddRoundKey
    //
    // The SubBytes (S-box) is the expensive part — 16 S-box lookups per round,
    // each requiring ~256*8 multiplications with the indicator approach.
    //
    // This is ~40,960 multiplications per round × 10 rounds = ~409,600 total.
    // Very expensive but functionally correct.
    //
    // For now, implement the full structure but note the cost.

    // TODO: Implement full 10-round AES-128 with key expansion
    // For now, return after initial AddRoundKey (incomplete but compiles)
    // Full implementation requires: SubBytes, ShiftRows, MixColumns per round
    eyre::bail!("AES128 full encryption not yet implemented — SubBytes S-box on shared values is extremely expensive (~400K multiplications)")
}
