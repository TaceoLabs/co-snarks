//! Poseidon2 permutation for SPDZ shared values.
//!
//! Uses the mask-and-evaluate technique: mask each S-box input with a
//! precomputed random [r], open the masked value y = x - r (safe: y is random),
//! then evaluate (y+r)^5 using the binomial expansion with precomputed
//! powers [r], [r^2], [r^3], [r^4], [r^5].

use ark_ff::PrimeField;
use mpc_core::gadgets::poseidon2::Poseidon2;
use mpc_net::Network;

use crate::arithmetic;
use crate::types::SpdzPrimeFieldShare;
use crate::SpdzState;

/// Precomputed S-box masking data for SPDZ Poseidon2.
///
/// Stores `[r], [r^2], [r^3], [r^4], [r^5]` for each S-box.
pub struct SpdzPoseidon2Precomp<F: PrimeField> {
    r: Vec<SpdzPrimeFieldShare<F>>,
    r2: Vec<SpdzPrimeFieldShare<F>>,
    r3: Vec<SpdzPrimeFieldShare<F>>,
    r4: Vec<SpdzPrimeFieldShare<F>>,
    r5: Vec<SpdzPrimeFieldShare<F>>,
    offset: usize,
}

impl<F: PrimeField> SpdzPoseidon2Precomp<F> {
    pub fn get(&self, idx: usize) -> (&SpdzPrimeFieldShare<F>, &SpdzPrimeFieldShare<F>, &SpdzPrimeFieldShare<F>, &SpdzPrimeFieldShare<F>, &SpdzPrimeFieldShare<F>) {
        (&self.r[idx], &self.r2[idx], &self.r3[idx], &self.r4[idx], &self.r5[idx])
    }
    pub fn get_r(&self, idx: usize) -> &SpdzPrimeFieldShare<F> { &self.r[idx] }
    pub fn get_offset(&self) -> usize { self.offset }
    pub fn increment_offset(&mut self, n: usize) { self.offset += n; }
}

// ─────────────────────── Precomputation ───────────────────────

/// Precompute powers of random masking values for Poseidon2 S-boxes.
pub fn precompute<F: PrimeField, const T: usize, const D: u64, N: Network>(
    poseidon: &Poseidon2<F, T, D>,
    num_poseidon: usize,
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<SpdzPoseidon2Precomp<F>> {
    let num_sbox = poseidon.num_sbox() * num_poseidon;

    let mut r = Vec::with_capacity(num_sbox);
    for _ in 0..num_sbox {
        r.push(state.preprocessing.next_shared_random()?);
    }

    let r2 = arithmetic::mul_many(&r, &r, net, state)?;
    let r4 = arithmetic::mul_many(&r2, &r2, net, state)?;

    let mut lhs = Vec::with_capacity(num_sbox * 2);
    let mut rhs = Vec::with_capacity(num_sbox * 2);
    for i in 0..num_sbox {
        lhs.push(r[i]);
        rhs.push(r2[i]);
    }
    for i in 0..num_sbox {
        lhs.push(r[i]);
        rhs.push(r4[i]);
    }
    let mut r3_r5 = arithmetic::mul_many(&lhs, &rhs, net, state)?;
    let r5 = r3_r5.split_off(num_sbox);
    let r3 = r3_r5;

    Ok(SpdzPoseidon2Precomp { r, r2, r3, r4, r5, offset: 0 })
}

// ─────────────────────── S-box Evaluation ───────────────────────

/// Evaluate x^5 on a single SPDZ-shared value using precomputed masks.
///
/// Protocol:
/// 1. Mask: y_share = x - r
/// 2. Open: y = x - r (y is random, safe to reveal)
/// 3. Evaluate: (y+r)^5 using binomial expansion
fn sbox_single<F: PrimeField, N: Network>(
    input: &mut SpdzPrimeFieldShare<F>,
    precomp: &mut SpdzPoseidon2Precomp<F>,
    net: &N,
    state: &SpdzState<F>,
) -> eyre::Result<()> {
    let idx = precomp.get_offset();

    // Mask and open
    let masked = *input - *precomp.get_r(idx);
    let y = arithmetic::open_unchecked(&masked, net)?;

    // Evaluate (y + r)^5 via binomial expansion:
    // (y+r)^5 = y^5 + 5*y^4*[r] + 10*y^3*[r^2] + 10*y^2*[r^3] + 5*y*[r^4] + [r^5]
    let y2 = y.square();
    let y3 = y2 * y;
    let y4 = y2.square();
    let y5 = y4 * y;
    let five = F::from(5u64);
    let ten = F::from(10u64);

    let (r, r2, r3, r4, r5) = precomp.get(idx);

    let mut res = *r5;
    res += *r4 * (five * y);
    res += *r3 * (ten * y2);
    res += *r2 * (ten * y3);
    res += *r * (five * y4);
    // y^5 is public — add to party 0's share only
    res = arithmetic::add_public(res, y5, state.mac_key_share, state.id);

    *input = res;
    precomp.increment_offset(1);
    Ok(())
}

/// Evaluate x^5 on multiple SPDZ-shared values in parallel.
fn sbox_batch<F: PrimeField, N: Network>(
    input: &mut [SpdzPrimeFieldShare<F>],
    precomp: &mut SpdzPoseidon2Precomp<F>,
    net: &N,
    state: &SpdzState<F>,
) -> eyre::Result<()> {
    let base = precomp.get_offset();
    let n = input.len();

    // Mask all inputs
    let masked: Vec<SpdzPrimeFieldShare<F>> = input
        .iter()
        .enumerate()
        .map(|(i, x)| *x - *precomp.get_r(base + i))
        .collect();

    // Open all masked values in one round
    let ys = arithmetic::open_many_unchecked(&masked, net)?;

    // Evaluate all S-boxes
    for (i, (inp, y)) in input.iter_mut().zip(ys.iter()).enumerate() {
        let y2 = y.square();
        let y3 = y2 * *y;
        let y4 = y2.square();
        let y5 = y4 * *y;
        let five = F::from(5u64);
        let ten = F::from(10u64);

        let (r, r2, r3, r4, r5) = precomp.get(base + i);
        let mut res = *r5;
        res += *r4 * (five * *y);
        res += *r3 * (ten * y2);
        res += *r2 * (ten * y3);
        res += *r * (five * y4);
        res = arithmetic::add_public(res, y5, state.mac_key_share, state.id);
        *inp = res;
    }

    precomp.increment_offset(n);
    Ok(())
}

// ─────────────────────── Matrix Multiplication ───────────────────────

/// External MDS matrix multiplication (same as Rep3 — purely local, linear).
pub fn matmul_external<F: PrimeField, const T: usize>(
    input: &mut [SpdzPrimeFieldShare<F>; T],
) {
    // Delegate to the Poseidon2 crate's matmul — it works on any type
    // implementing Add + Double. We manually implement the 4x4 case.
    match T {
        2 => {
            let sum = input[0] + input[1];
            input[0] += sum;
            input[1] += sum;
        }
        3 => {
            let sum = input[0] + input[1] + input[2];
            input[0] += sum;
            input[1] += sum;
            input[2] += sum;
        }
        4 => matmul_m4(input.as_mut_slice().try_into().unwrap()),
        t if t % 4 == 0 => {
            // Apply m4 to each chunk of 4, then add across chunks
            for chunk in input.chunks_mut(4) {
                let arr: &mut [SpdzPrimeFieldShare<F>; 4] = chunk.try_into().unwrap();
                matmul_m4(arr);
            }
            // Cross-chunk addition
            let mut sums = [SpdzPrimeFieldShare::zero_share(); 4];
            for chunk in input.chunks(4) {
                for j in 0..4 {
                    sums[j] += chunk[j];
                }
            }
            for chunk in input.chunks_mut(4) {
                for j in 0..4 {
                    chunk[j] += sums[j];
                }
            }
        }
        _ => panic!("Unsupported Poseidon2 state size {T}"),
    }
}

fn matmul_m4<F: PrimeField>(input: &mut [SpdzPrimeFieldShare<F>; 4]) {
    let t_0 = input[0] + input[1];
    let t_1 = input[2] + input[3];
    let t_2 = input[1].double() + t_1;
    let t_3 = input[3].double() + t_0;
    let t_4 = t_1.double().double() + t_3;
    let t_5 = t_0.double().double() + t_2;
    let t_6 = t_3 + t_5;
    let t_7 = t_2 + t_4;
    input[0] = t_6;
    input[1] = t_5;
    input[2] = t_7;
    input[3] = t_4;
}

/// Internal MDS matrix multiplication.
pub fn matmul_internal<F: PrimeField, const T: usize, const D: u64>(
    poseidon: &Poseidon2<F, T, D>,
    input: &mut [SpdzPrimeFieldShare<F>; T],
) {
    // sum = sum of all elements
    let mut sum = SpdzPrimeFieldShare::zero_share();
    for x in input.iter() {
        sum += *x;
    }
    // x'[i] = x[i] * (diag[i] - 1) + sum
    for (i, x) in input.iter_mut().enumerate() {
        let diag_minus_1 = poseidon.params.mat_internal_diag_m_1[i];
        *x = *x * diag_minus_1 + sum;
    }
}

// ─────────────────────── Full Permutation ───────────────────────

/// Run the full Poseidon2 permutation on SPDZ-shared state.
pub fn permutation_in_place<F: PrimeField, const T: usize, const D: u64, N: Network>(
    poseidon: &Poseidon2<F, T, D>,
    state_arr: &mut [SpdzPrimeFieldShare<F>; T],
    precomp: &mut SpdzPoseidon2Precomp<F>,
    net: &N,
    state: &SpdzState<F>,
) -> eyre::Result<()> {
    // Initial linear layer
    matmul_external(state_arr);

    // External rounds (beginning)
    for r in 0..poseidon.params.rounds_f_beginning {
        external_round(poseidon, state_arr, r, precomp, net, state)?;
    }

    // Internal rounds
    for r in 0..poseidon.params.rounds_p {
        internal_round(poseidon, state_arr, r, precomp, net, state)?;
    }

    // External rounds (end)
    for r in poseidon.params.rounds_f_beginning
        ..poseidon.params.rounds_f_beginning + poseidon.params.rounds_f_end
    {
        external_round(poseidon, state_arr, r, precomp, net, state)?;
    }

    Ok(())
}

pub fn external_round<F: PrimeField, const T: usize, const D: u64, N: Network>(
    poseidon: &Poseidon2<F, T, D>,
    state_arr: &mut [SpdzPrimeFieldShare<F>; T],
    r: usize,
    precomp: &mut SpdzPoseidon2Precomp<F>,
    net: &N,
    state: &SpdzState<F>,
) -> eyre::Result<()> {
    // Add round constants (public values — party 0 adds)
    for (i, x) in state_arr.iter_mut().enumerate() {
        let rc = poseidon.params.round_constants_external[r][i];
        *x = arithmetic::add_public(*x, rc, state.mac_key_share, state.id);
    }

    // S-box on all T elements
    sbox_batch(state_arr.as_mut_slice(), precomp, net, state)?;

    // MDS matrix
    matmul_external(state_arr);
    Ok(())
}

pub fn internal_round<F: PrimeField, const T: usize, const D: u64, N: Network>(
    poseidon: &Poseidon2<F, T, D>,
    state_arr: &mut [SpdzPrimeFieldShare<F>; T],
    r: usize,
    precomp: &mut SpdzPoseidon2Precomp<F>,
    net: &N,
    state: &SpdzState<F>,
) -> eyre::Result<()> {
    // Add round constant to first element only
    let rc = poseidon.params.round_constants_internal[r];
    state_arr[0] = arithmetic::add_public(state_arr[0], rc, state.mac_key_share, state.id);

    // S-box on first element only
    sbox_single(&mut state_arr[0], precomp, net, state)?;

    // Internal MDS matrix
    matmul_internal(poseidon, state_arr);
    Ok(())
}

#[cfg(test)]
mod noir_compat_test {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::{PrimeField, BigInteger};

    /// Replicate the Noir poseidon2 sponge hash: T=4, rate=3, capacity=1.
    /// hash([a, b], 2) = permute([a, b, 0, 2*2^64])[0]
    fn noir_poseidon2_hash(inputs: &[Fr], msg_len: u64) -> Fr {
        let p4: Poseidon2<Fr, 4, 5> = Poseidon2::default();
        let two_pow_64 = Fr::from(18446744073709551616u128);
        let iv = Fr::from(msg_len) * two_pow_64;

        // Sponge: rate=3, capacity=1 (state[3] = iv)
        let mut state = [Fr::from(0u64); 4];
        state[3] = iv;

        // Absorb (rate=3, so duplex when cache fills to 3)
        let rate = 3usize;
        let mut cache = [Fr::from(0u64); 3];
        let mut cache_size = 0usize;

        for &inp in inputs {
            if cache_size == rate {
                // duplex: add cache to state, permute
                for j in 0..rate { state[j] += cache[j]; }
                state = p4.permutation(&state);
                cache[0] = inp;
                cache_size = 1;
            } else {
                cache[cache_size] = inp;
                cache_size += 1;
            }
        }

        // Squeeze: add remaining cache, permute, return state[0]
        for j in 0..cache_size { state[j] += cache[j]; }
        state = p4.permutation(&state);
        state[0]
    }

    #[test]
    fn check_poseidon2_noir_values() {
        // hash([12345, 0], 2) from Noir = 0x029e2c00fc7c630e4a1744e736f7db4c7e7dc5db9e9408a978928cab9c2a9188
        let result = noir_poseidon2_hash(&[Fr::from(12345u64), Fr::from(0u64)], 2);
        let big: num_bigint::BigUint = result.into_bigint().into();
        let hex = format!("{:064x}", big);
        eprintln!("Rust sponge hash([12345,0],2) = 0x{}", hex);
        assert_eq!(hex, "029e2c00fc7c630e4a1744e736f7db4c7e7dc5db9e9408a978928cab9c2a9188");

        // hash([67890, 0], 2) from Noir = 0x301d3196b8253b469649f5c92426858467ff77b88ed8759bec5a4bf856089ba6
        let result2 = noir_poseidon2_hash(&[Fr::from(67890u64), Fr::from(0u64)], 2);
        let big2: num_bigint::BigUint = result2.into_bigint().into();
        let hex2 = format!("{:064x}", big2);
        eprintln!("Rust sponge hash([67890,0],2) = 0x{}", hex2);
        assert_eq!(hex2, "301d3196b8253b469649f5c92426858467ff77b88ed8759bec5a4bf856089ba6");
    }
}
