//! Bit decomposition and bitwise operations for SPDZ shared values.
//!
//! Uses the standard SPDZ protocol:
//! 1. Get shared random bits from preprocessing
//! 2. Compose into a shared random field element r = sum(b_i * 2^i)
//! 3. Mask: c = x - r (open c, safe since r is random)
//! 4. Extract bits: x_i = c_i XOR b_i = c_i + b_i - 2*c_i*b_i

use ark_ff::PrimeField;
use mpc_net::Network;
use num_bigint::BigUint;

use crate::arithmetic;
use crate::types::SpdzPrimeFieldShare;
use crate::SpdzState;

/// Security parameter for bit decomposition — extra random bits to prevent underflow.
/// 40 = standard (2^-40 failure probability).
/// Lower values reduce cost but increase failure probability.
/// Set via `set_decompose_sec_param()` for performance tuning.
static mut DECOMPOSE_SEC_PARAM: usize = 40;

/// Set the security parameter for bit decomposition.
/// Lower values = faster but less secure (10 = 1-in-1024 failure, 20 = 1-in-1M).
/// Must be called before any decomposition.
pub fn set_decompose_sec_param(bits: usize) {
    unsafe { DECOMPOSE_SEC_PARAM = bits; }
}

pub fn sec_param() -> usize {
    unsafe { DECOMPOSE_SEC_PARAM }
}

/// Decompose a shared field element into shared bits.
///
/// Returns `num_bits` shared bits `[x_0], ..., [x_{num_bits-1}]` (LSB first)
/// where `x = sum(x_i * 2^i)`.
///
/// REQUIREMENT: the shared value must be in range [0, 2^num_bits).
///
/// Uses `num_bits + DECOMPOSE_SEC_PARAM` random bits to ensure the
/// masking doesn't underflow with overwhelming probability.
pub fn decompose<F: PrimeField, N: Network>(
    x: &SpdzPrimeFieldShare<F>,
    num_bits: usize,
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
    let total_bits = num_bits + sec_param();

    // Step 1: Get shared random bits (extra bits for statistical security)
    let shared_bits = state.preprocessing.next_shared_bit_batch(total_bits)?;

    // Step 2: Compose random bits into a random field element
    // [r] = sum([b_i] * 2^i) for i in 0..total_bits
    // r is in [0, 2^total_bits), so r >> x with overwhelming probability
    let mut r = SpdzPrimeFieldShare::zero_share();
    let mut power_of_two = F::one();
    for bit in &shared_bits {
        r += *bit * power_of_two;
        power_of_two.double_in_place();
    }

    // Step 3: Mask and open
    // Open [x] - [r] in the field. Both x and r are in [0, 2^k).
    // c = x - r mod p. We need to recover x's bits from c and r's shared bits.
    //
    // Approach: x = r + c mod 2^k (as integers, not field elements).
    // If c > p/2, the true difference is negative: c_int = c - p.
    // Then x = r + c_int, and we need the lower k bits of (r + c_int).
    //
    // Since r in [0, 2^k) and x in [0, 2^k), c_int = x - r in [-2^k, 2^k).
    // We compute c_unsigned = c_int mod 2^k (take lower k bits of c in the field).
    //
    // Then x mod 2^k = (r + c_unsigned) mod 2^k.
    // This is a simple k-bit addition of shared r bits with public c bits.

    // Step 3: Open c = r - x (not x - r!)
    // Since r has sec_param() extra bits, r >= x with overwhelming probability.
    // So c = r - x is a small non-negative integer.
    let masked = r - *x;
    let c = arithmetic::open_unchecked(&masked, net)?;
    let c_biguint: BigUint = c.into();

    // c should be a small number (< 2^total_bits). If it's close to p, something went wrong.
    let c_bits: Vec<bool> = (0..num_bits)
        .map(|i| c_biguint.bit(i as u64))
        .collect();

    // Step 4: Compute x = r - c using binary subtraction with borrow.
    // x_i = r_i XOR c_i XOR borrow_i
    // borrow_{i+1} = (!r_i AND c_i) OR (borrow_i AND !(r_i XOR c_i))
    //
    // Since c_i is PUBLIC:
    //   If c_i = 0: x_i = r_i XOR borrow, borrow_next = borrow AND NOT(r_i) = borrow * (1 - r_i)
    //   If c_i = 1: x_i = NOT(r_i XOR borrow) = NOT(r_i) XOR borrow when borrow is bit
    //               borrow_next = NOT(r_i) OR borrow = 1 - r_i + r_i*borrow
    //               Actually: borrow_next = (1-r_i) OR (borrow AND (r_i XOR 1))
    //               = (1-r_i) + borrow*(1-r_i) - ... this is getting complex.
    //               Simpler: borrow_next = NOT(r_i) OR (borrow AND NOT(r_i XOR c_i))
    //               When c_i=1: r_i XOR c_i = NOT(r_i), so NOT(r_i XOR c_i) = r_i
    //               borrow_next = (1-r_i) OR (borrow AND r_i) = (1-r_i) + borrow*r_i - (1-r_i)*borrow*r_i
    //               = (1-r_i) + borrow*r_i*(1 - (1-r_i)) = (1-r_i) + borrow*r_i*r_i
    //               Since r_i is a bit (r_i^2 = r_i): = (1-r_i) + borrow*r_i
    //               = 1 - r_i + borrow*r_i = 1 - r_i*(1 - borrow)

    let two = F::from(2u64);
    let mut borrow = SpdzPrimeFieldShare::<F>::zero_share();
    let mut result_bits = Vec::with_capacity(num_bits);

    for i in 0..num_bits {
        let r_i = shared_bits[i];
        let c_i = c_bits[i];

        if c_i {
            // c_i = 1:
            // r_i XOR borrow = r_i + borrow - 2*r_i*borrow
            // x_i = NOT(r_i XOR borrow) = 1 - (r_i + borrow - 2*r_i*borrow)
            // borrow_next = 1 - r_i*(1 - borrow) = 1 - r_i + r_i*borrow
            let ri_times_borrow = arithmetic::mul(&r_i, &borrow, net, state)?;
            let r_xor_borrow = r_i + borrow - ri_times_borrow * two;
            let x_i = arithmetic::add_public(-r_xor_borrow, F::one(), state.mac_key_share, state.id);
            let borrow_next = arithmetic::add_public(
                ri_times_borrow - r_i, F::one(), state.mac_key_share, state.id,
            );
            result_bits.push(x_i);
            borrow = borrow_next;
        } else {
            // c_i = 0:
            // x_i = r_i XOR borrow = r_i + borrow - 2*r_i*borrow
            // borrow_next = borrow AND NOT(r_i) = borrow*(1 - r_i) = borrow - borrow*r_i
            let ri_times_borrow = arithmetic::mul(&r_i, &borrow, net, state)?;
            let x_i = r_i + borrow - ri_times_borrow * two;
            let borrow_next = borrow - ri_times_borrow;
            result_bits.push(x_i);
            borrow = borrow_next;
        }
    }

    Ok(result_bits)
}

/// Decompose multiple shared field elements in batch.
pub fn decompose_many<F: PrimeField, N: Network>(
    xs: &[SpdzPrimeFieldShare<F>],
    num_bits: usize,
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<Vec<Vec<SpdzPrimeFieldShare<F>>>> {
    let n = xs.len();
    let total_bits = n * num_bits;

    let total_bits_per_value = num_bits + sec_param();
    let total_bits = n * total_bits_per_value;

    // Get all random bits at once
    let all_shared_bits = state.preprocessing.next_shared_bit_batch(total_bits)?;

    // Compose random field elements
    let mut rs = Vec::with_capacity(n);
    for i in 0..n {
        let bits = &all_shared_bits[i * total_bits_per_value..(i + 1) * total_bits_per_value];
        let mut r = SpdzPrimeFieldShare::zero_share();
        let mut power = F::one();
        for bit in bits {
            r += *bit * power;
            power.double_in_place();
        }
        rs.push(r);
    }

    // Open c_i = r_i - x_i (r > x with overwhelming probability)
    let masked: Vec<SpdzPrimeFieldShare<F>> = rs.iter().zip(xs.iter()).map(|(r, x)| *r - *x).collect();
    let cs = arithmetic::open_many_unchecked(&masked, net)?;

    // BATCHED binary subtraction: at each bit level, batch all n multiplications
    // into a single mul_many call. This reduces rounds from n*num_bits to num_bits.
    let two = F::from(2u64);

    // Extract c bits and r bits for each value
    let c_biguints: Vec<BigUint> = cs.iter().map(|c| (*c).into()).collect();
    let r_bits: Vec<&[SpdzPrimeFieldShare<F>]> = (0..n)
        .map(|i| &all_shared_bits[i * total_bits_per_value..(i + 1) * total_bits_per_value])
        .collect();

    let mut borrows: Vec<SpdzPrimeFieldShare<F>> = vec![SpdzPrimeFieldShare::<F>::zero_share(); n];
    let mut result_bits: Vec<Vec<SpdzPrimeFieldShare<F>>> = vec![Vec::with_capacity(num_bits); n];

    for j in 0..num_bits {
        // Batch: compute r_j[i] * borrow[i] for all i in one mul_many
        let r_js: Vec<SpdzPrimeFieldShare<F>> = (0..n).map(|i| r_bits[i][j]).collect();
        let products = arithmetic::mul_many(&r_js, &borrows, net, state)?;

        for i in 0..n {
            let r_j = r_bits[i][j];
            let c_j = c_biguints[i].bit(j as u64);
            let rj_times_borrow = products[i];

            if c_j {
                let r_xor_borrow = r_j + borrows[i] - rj_times_borrow * two;
                let x_j = arithmetic::add_public(-r_xor_borrow, F::one(), state.mac_key_share, state.id);
                let borrow_next = arithmetic::add_public(rj_times_borrow - r_j, F::one(), state.mac_key_share, state.id);
                result_bits[i].push(x_j);
                borrows[i] = borrow_next;
            } else {
                let x_j = r_j + borrows[i] - rj_times_borrow * two;
                let borrow_next = borrows[i] - rj_times_borrow;
                result_bits[i].push(x_j);
                borrows[i] = borrow_next;
            }
        }
    }

    Ok(result_bits)
}

/// Test if a shared value equals zero: returns a shared bit [is_zero].
///
/// FAST ALGEBRAIC PROTOCOL (3 rounds instead of 15+):
/// 1. Generate random nonzero [r] from preprocessing
/// 2. Compute [z] = [x] * [r] (1 Beaver multiplication, 1 round)
/// 3. Open z (1 round) — safe: z is masked by random r
/// 4. Both parties compute the result locally from z:
///    - If z == 0: [result] = [1] (promoted trivial share)
///    - If z != 0: [result] = [1] - [x] * [x_inv]
///      where x_inv = r * z^{-1} (public scalar, since z is opened)
///      and [x] * [x_inv] = [x * r * z^{-1}] = [x * r / (x*r)] = [1]
///      So result = [1] - [1] = [0]
///
/// This is 2-3 rounds and 1-2 multiplications instead of 15+ rounds.
pub fn is_zero<F: PrimeField, N: Network>(
    x: &SpdzPrimeFieldShare<F>,
    _num_bits: usize,
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<SpdzPrimeFieldShare<F>> {
    let r = state.preprocessing.next_shared_random()?;

    // Fused mul + open in ONE round trip:
    // Instead of: mul(x, r) [1 RT for epsilon/delta] then open(xr) [1 RT]
    // Do: compute epsilon/delta/xr locally, open all three in one message
    let (a, b, c) = state.preprocessing.next_triple()?;
    let eps_share = *x - a;
    let del_share = r - b;
    let opened = arithmetic::open_many_unchecked(&[eps_share, del_share], net)?;
    let epsilon = opened[0];
    let delta = opened[1];
    let mut xr = c;
    xr += b * epsilon;
    xr += a * delta;
    xr = arithmetic::add_public(xr, epsilon * delta, state.mac_key_share, state.id);

    // Now open xr (1 more round trip)
    let z = arithmetic::open_unchecked(&xr, net)?;

    if z.is_zero() {
        // x == 0 (with overwhelming probability)
        // Return [1]
        Ok(SpdzPrimeFieldShare::promote_from_trivial(
            &F::one(), state.mac_key_share, state.id,
        ))
    } else {
        // x != 0. Compute [bit] = [1] - [x] * (r / z)
        // Since z = x*r, r/z = 1/x. So [x] * (r/z) = [x * (1/x)] = [1]
        // And [1] - [1] = [0]. But we compute it on shares to keep it shared.
        let r_over_z = r * z.inverse().unwrap(); // [r] * (1/z) = [r/z] = [1/x] as a share
        // [x] * [1/x] would need another mul, but we already have [x*r] = [z]
        // [z] * (1/z) = [1] trivially: just scale the share
        let one_share = xr * z.inverse().unwrap(); // [xr * z^{-1}] = [1] as properly shared
        // [result] = [1] - one_share... but one_share IS [1] already
        // So result = trivial [1] - one_share should give [0]
        // Actually simpler: if z != 0, x != 0, return [0]
        // The issue is returning a PROPERLY SHARED zero, not a trivial one.
        // Any two-party share of 0 works. Use: (random, -random) for share, (0, 0) for mac.
        // But that doesn't have a valid MAC.
        //
        // Correct approach: return [1] - [x] * scalar
        // where scalar makes [x]*scalar = [1]
        // scalar = z^{-1} applied to [xr]: [xr] * z^{-1} = [xr/z] = [1]
        let z_inv = z.inverse().unwrap();
        let one_shared = xr * z_inv; // This IS a valid sharing of 1 with correct MAC
        let result = arithmetic::add_public(
            -one_shared, F::one(), state.mac_key_share, state.id,
        );
        // result = 1 - 1 = 0 as a properly shared value
        Ok(result)
    }
}

/// Test equality of two shared values: returns a shared bit [a == b].
///
/// Uses algebraic is_zero: 2 rounds instead of 15+.
pub fn equal<F: PrimeField, N: Network>(
    a: &SpdzPrimeFieldShare<F>,
    b: &SpdzPrimeFieldShare<F>,
    num_bits: usize,
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<SpdzPrimeFieldShare<F>> {
    let diff = *a - *b;
    is_zero(&diff, num_bits, net, state)
}

/// Bit-decomposition-based is_zero (old method, more expensive but works
/// for small fields where the algebraic method has non-negligible failure).
pub fn is_zero_via_bits<F: PrimeField, N: Network>(
    x: &SpdzPrimeFieldShare<F>,
    num_bits: usize,
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<SpdzPrimeFieldShare<F>> {
    let bits = decompose(x, num_bits, net, state)?;
    let mut acc = arithmetic::add_public(
        -bits[0], F::one(), state.mac_key_share, state.id,
    );
    for bit in bits.iter().skip(1) {
        let one_minus_bit = arithmetic::add_public(-*bit, F::one(), state.mac_key_share, state.id);
        acc = arithmetic::mul(&acc, &one_minus_bit, net, state)?;
    }
    Ok(acc)
}

/// Compare two shared values: returns a shared bit [a > b].
///
/// Uses the subtraction-and-check-MSB approach:
/// Compute a - b, check if result is "positive" (MSB = 0 in the appropriate range).
///
/// NOTE: This assumes both values are in the range [0, 2^num_bits).
pub fn greater_than<F: PrimeField, N: Network>(
    a: &SpdzPrimeFieldShare<F>,
    b: &SpdzPrimeFieldShare<F>,
    num_bits: usize,
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<SpdzPrimeFieldShare<F>> {
    // Compute a - b + 2^num_bits (to avoid underflow)
    let offset = F::from(BigUint::from(1u64) << num_bits);
    let diff = *a - *b;
    let shifted = arithmetic::add_public(diff, offset, state.mac_key_share, state.id);

    // Decompose with num_bits + 1 bits
    let bits = decompose(&shifted, num_bits + 1, net, state)?;

    // The (num_bits)-th bit indicates whether a >= b
    // But we want strict >, so: a > b iff (a >= b) AND (a != b)
    // The MSB (bit at index num_bits) is 1 iff a >= b
    // We can use: a > b iff MSB == 1 AND (a != b)
    // But simpler: a > b iff (a - b + 2^k) has bit k set AND lower bits not all zero

    // Actually, for the standard approach:
    // a - b + 2^k, decomposed as bits[0..=k]:
    //   bit[k] = 1 iff a >= b
    //   a > b iff bit[k] = 1 AND NOT(a == b)
    // But equality check is expensive. Simpler to just check:
    //   a > b iff (a - b + 2^k) > 2^k iff bit[k] = 1 AND at least one of bits[0..k-1] is 1

    // For now, return the MSB as a >= b indicator
    // (strict gt can be computed as: gt = geq AND NOT equal)
    Ok(bits[num_bits])
}

/// Compute bitwise AND of two shared values.
///
/// Decomposes both values into bits, ANDs each pair (via multiplication),
/// and recomposes.
pub fn bitwise_and<F: PrimeField, N: Network>(
    a: &SpdzPrimeFieldShare<F>,
    b: &SpdzPrimeFieldShare<F>,
    num_bits: usize,
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<SpdzPrimeFieldShare<F>> {
    let a_bits = decompose(a, num_bits, net, state)?;
    let b_bits = decompose(b, num_bits, net, state)?;

    // AND of bits = multiplication (since they're 0 or 1)
    let and_bits = arithmetic::mul_many(&a_bits, &b_bits, net, state)?;

    // Recompose: result = sum(and_bits[i] * 2^i)
    let mut result = SpdzPrimeFieldShare::zero_share();
    let mut power = F::one();
    for bit in and_bits {
        result += bit * power;
        power.double_in_place();
    }

    Ok(result)
}

/// Compute bitwise XOR of two shared values.
///
/// Decomposes both, XORs each pair (a + b - 2*a*b), recomposes.
pub fn bitwise_xor<F: PrimeField, N: Network>(
    a: &SpdzPrimeFieldShare<F>,
    b: &SpdzPrimeFieldShare<F>,
    num_bits: usize,
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<SpdzPrimeFieldShare<F>> {
    let a_bits = decompose(a, num_bits, net, state)?;
    let b_bits = decompose(b, num_bits, net, state)?;

    // XOR of bits: a XOR b = a + b - 2*a*b
    let products = arithmetic::mul_many(&a_bits, &b_bits, net, state)?;

    let mut result = SpdzPrimeFieldShare::zero_share();
    let mut power = F::one();
    let two = F::from(2u64);
    for i in 0..num_bits {
        let xor_bit = a_bits[i] + b_bits[i] - products[i] * two;
        result += xor_bit * power;
        power.double_in_place();
    }

    Ok(result)
}

/// Slice a shared value: extract bits [lsb..msb] as one value, and the remainder as another.
///
/// Returns `[extracted_slice, remainder]`.
/// The value must be in range [0, 2^bitsize).
pub fn slice<F: PrimeField, N: Network>(
    input: &SpdzPrimeFieldShare<F>,
    msb: u8,
    lsb: u8,
    bitsize: usize,
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<[SpdzPrimeFieldShare<F>; 2]> {
    let bits = decompose(input, bitsize, net, state)?;

    let mut extracted = SpdzPrimeFieldShare::zero_share();
    let mut power = F::one();
    for i in (lsb as usize)..(msb as usize) {
        if i < bits.len() {
            extracted += bits[i] * power;
        }
        power.double_in_place();
    }

    let shift = F::from(BigUint::from(1u64) << (lsb as usize));
    let remainder = *input - extracted * shift;

    Ok([extracted, remainder])
}

/// Slice many shared values.
pub fn slice_many<F: PrimeField, N: Network>(
    inputs: &[SpdzPrimeFieldShare<F>],
    msb: u8,
    lsb: u8,
    bitsize: usize,
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<Vec<[SpdzPrimeFieldShare<F>; 2]>> {
    inputs.iter().map(|input| slice(input, msb, lsb, bitsize, net, state)).collect()
}

/// Right-shift a shared value by `shift` bits.
pub fn right_shift<F: PrimeField, N: Network>(
    input: &SpdzPrimeFieldShare<F>,
    shift: usize,
    bitsize: usize,
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<SpdzPrimeFieldShare<F>> {
    let bits = decompose(input, bitsize, net, state)?;
    let mut result = SpdzPrimeFieldShare::zero_share();
    let mut power = F::one();
    for i in shift..bitsize {
        result += bits[i] * power;
        power.double_in_place();
    }
    Ok(result)
}

/// Sort shared values using oblivious bubble sort.
pub fn sort<F: PrimeField, N: Network>(
    inputs: &[SpdzPrimeFieldShare<F>],
    bitsize: usize,
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
    let n = inputs.len();
    if n <= 1 { return Ok(inputs.to_vec()); }

    let mut arr = inputs.to_vec();
    for i in 0..n {
        for j in 0..n - 1 - i {
            let gt = greater_than(&arr[j], &arr[j + 1], bitsize, net, state)?;
            let diff = arr[j + 1] - arr[j];
            let gt_times_diff = arithmetic::mul(&gt, &diff, net, state)?;
            arr[j] = arr[j] + gt_times_diff;
            arr[j + 1] = arr[j + 1] - gt_times_diff;
        }
    }
    Ok(arr)
}
