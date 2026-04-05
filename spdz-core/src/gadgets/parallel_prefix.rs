// Parallel prefix carry computation for SPDZ bit decomposition.
//
// Reduces borrow chain from O(n) sequential rounds to O(log n) rounds
// of batched multiplications.
//
// For subtraction x = r - c where r has shared bits and c is public:
//   generate_i = NOT(r_i) AND c_i = (1 - r_i) * c_i
//   propagate_i = NOT(r_i XOR c_i) = 1 - r_i - c_i + 2*r_i*c_i (for borrow propagation)
//
// With borrow_i = g_i OR (p_i AND borrow_{i-1}):
//   Using Kogge-Stone: compute all borrows in log2(n) rounds.

use ark_ff::PrimeField;
use mpc_net::Network;

use crate::arithmetic;
use crate::types::SpdzPrimeFieldShare;
use crate::SpdzState;

/// Compute all borrow bits for r - c using parallel prefix.
///
/// Returns borrow[0..num_bits] where borrow[i] = 1 if there's a borrow
/// INTO position i from positions 0..i-1.
///
/// Rounds: O(log2(num_bits)) batched multiplications.
pub fn parallel_prefix_borrow<F: PrimeField, N: Network>(
    r_bits: &[SpdzPrimeFieldShare<F>],
    c_bits: &[bool],
    num_bits: usize,
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
    // Step 1: Compute generate and propagate for each bit position (LOCAL)
    // For subtraction r - c:
    //   generate_i = NOT(r_i) AND c_i
    //     if c_i = 0: g_i = 0 (no borrow generated)
    //     if c_i = 1: g_i = 1 - r_i (borrow if r_i = 0)
    //   propagate_i = r_i XNOR c_i = NOT(r_i XOR c_i)
    //     if c_i = 0: p_i = r_i (propagate if r_i = 1... wait, for borrows)

    // Actually for borrow propagation in subtraction:
    //   borrow into bit i+1 = 1 if (r[0..i] as integer) < (c[0..i] as integer)
    //   This is: borrow_{i+1} = (NOT r_i AND c_i) OR (borrow_i AND NOT(r_i XOR c_i))
    //
    //   generate: g_i = NOT(r_i) AND c_i = c_i * (1 - r_i)
    //   propagate: p_i = NOT(r_i XOR c_i) = r_i XNOR c_i
    //     if c_i = 0: p_i = r_i       (borrow propagates when r_i = 0... no, when equal)
    //     if c_i = 1: p_i = 1 - r_i   (r_i XNOR 1 = NOT r_i)
    //
    // Wait, let me recheck. For borrow (subtraction):
    //   borrow_{i+1} = (c_i > r_i) ? 1 : (c_i == r_i) ? borrow_i : 0
    //   generate: c_i AND NOT(r_i) → c_i * (1 - r_i) when c_i is public
    //   propagate: c_i == r_i → c_i XNOR r_i
    //     c_i = 0: propagate = NOT(r_i)... no, XNOR(0, r_i) = NOT(r_i)
    //     c_i = 1: propagate = r_i
    //
    // Hmm, let me just use the standard formulation:
    //   For each bit: g_i, p_i are computed locally from r_i (shared) and c_i (public)
    //   Then parallel prefix combines them using: (g, p) o (g', p') = (g OR (p AND g'), p AND p')
    //   The OR and AND on shared bits each cost 1 mul.

    let mut g: Vec<SpdzPrimeFieldShare<F>> = Vec::with_capacity(num_bits);
    let mut p: Vec<SpdzPrimeFieldShare<F>> = Vec::with_capacity(num_bits);

    for i in 0..num_bits {
        let r_i = r_bits[i];
        if c_bits[i] {
            // c_i = 1: g_i = 1 - r_i, p_i = r_i
            g.push(arithmetic::add_public(-r_i, F::one(), state.mac_key_share, state.id));
            p.push(r_i);
        } else {
            // c_i = 0: g_i = 0, p_i = 1 - r_i
            g.push(SpdzPrimeFieldShare::zero_share());
            p.push(arithmetic::add_public(-r_i, F::one(), state.mac_key_share, state.id));
        }
    }

    // Step 2: Parallel prefix (Kogge-Stone)
    // In each round k, combine pairs that are 2^k apart:
    //   g_new[i] = g[i] OR (p[i] AND g[i - 2^k])
    //   p_new[i] = p[i] AND p[i - 2^k]
    //
    // OR(a, b) = a + b - a*b (for bits, 1 mul)
    // AND(a, b) = a * b (1 mul)
    //
    // Each round: batch all the muls together

    let mut stride = 1;
    while stride < num_bits {
        // Collect all operations for this round
        let mut and_lhs = Vec::new(); // p[i] for the AND in generate
        let mut and_rhs = Vec::new(); // g[i - stride] for the AND
        let mut p_and_lhs = Vec::new(); // p[i] for propagate AND
        let mut p_and_rhs = Vec::new(); // p[i - stride] for propagate AND
        let mut indices = Vec::new();

        for i in stride..num_bits {
            if i >= stride {
                and_lhs.push(p[i]);
                and_rhs.push(g[i - stride]);
                p_and_lhs.push(p[i]);
                p_and_rhs.push(p[i - stride]);
                indices.push(i);
            }
        }

        if and_lhs.is_empty() {
            break;
        }

        // Batch ALL multiplications for this round in ONE mul_many call
        let mut all_lhs = Vec::with_capacity(and_lhs.len() * 2);
        let mut all_rhs = Vec::with_capacity(and_rhs.len() * 2);
        all_lhs.extend_from_slice(&and_lhs);
        all_lhs.extend_from_slice(&p_and_lhs);
        all_rhs.extend_from_slice(&and_rhs);
        all_rhs.extend_from_slice(&p_and_rhs);

        let products = arithmetic::mul_many(&all_lhs, &all_rhs, net, state)?;

        let n = indices.len();
        let p_and_g = &products[..n];     // p[i] * g[i-stride]
        let p_and_p = &products[n..];     // p[i] * p[i-stride]

        // Update g and p
        // g_new[i] = g[i] + p[i]*g[i-stride] - g[i]*p[i]*g[i-stride]
        // But for bits, OR(a, b) = a + b - a*b
        // g_new[i] = g[i] OR (p[i] AND g[i-stride]) = g[i] + p_and_g[j] - g[i] * p_and_g[j]
        //
        // This needs ANOTHER mul for the OR. To avoid it:
        // Since g[i] and p_and_g[j] are both bits (0 or 1):
        // g[i] OR p_and_g[j] = g[i] + p_and_g[j] - g[i] * p_and_g[j]
        //
        // We need g[i] * p_and_g[j]. That's another batch of muls...
        // OR: use the identity for bits: OR(a, b) = a + b - a*b
        // We need one more mul_many for the OR step.

        let mut or_lhs = Vec::with_capacity(n);
        let mut or_rhs = Vec::with_capacity(n);
        for (j, &i) in indices.iter().enumerate() {
            or_lhs.push(g[i]);
            or_rhs.push(p_and_g[j]);
        }
        let or_products = arithmetic::mul_many(&or_lhs, &or_rhs, net, state)?;

        for (j, &i) in indices.iter().enumerate() {
            // g[i] = g[i] + p_and_g[j] - g[i]*p_and_g[j]
            g[i] = g[i] + p_and_g[j] - or_products[j];
            // p[i] = p[i] * p[i-stride] (already computed)
            p[i] = p_and_p[j];
        }

        stride *= 2;
    }

    // Step 3: Borrows are the generate values
    // borrow[0] = 0 (no borrow into the least significant bit)
    // borrow[i] = g[i-1] after prefix computation (borrow from positions 0..i-1)
    let mut borrows = Vec::with_capacity(num_bits);
    borrows.push(SpdzPrimeFieldShare::zero_share()); // no borrow into bit 0
    for i in 1..num_bits {
        borrows.push(g[i - 1]);
    }

    Ok(borrows)
}

/// Decompose using parallel prefix borrow computation.
/// Reduces from O(num_bits) rounds to O(log(num_bits)) rounds.
pub fn decompose_parallel<F: PrimeField, N: Network>(
    x: &SpdzPrimeFieldShare<F>,
    num_bits: usize,
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
    use num_bigint::BigUint;

    let total_bits = num_bits + super::bits::sec_param();

    // Get shared random bits
    let shared_bits = state.preprocessing.next_shared_bit_batch(total_bits)?;

    // Compose r
    let mut r = SpdzPrimeFieldShare::zero_share();
    let mut power = F::one();
    for bit in &shared_bits[..total_bits] {
        r += *bit * power;
        power.double_in_place();
    }

    // Open c = r - x
    let masked = r - *x;
    let c = arithmetic::open_unchecked(&masked, net)?;
    let c_biguint: BigUint = c.into();
    let c_bits: Vec<bool> = (0..num_bits).map(|i| c_biguint.bit(i as u64)).collect();

    // Compute borrows using parallel prefix (log(n) rounds instead of n!)
    let r_bits = &shared_bits[..num_bits];
    let borrows = parallel_prefix_borrow(r_bits, &c_bits, num_bits, net, state)?;

    // Compute result bits: x_i = r_i XOR c_i XOR borrow_i
    let two = F::from(2u64);
    let mut result_bits = Vec::with_capacity(num_bits);
    for i in 0..num_bits {
        let r_i = shared_bits[i];
        let borrow = borrows[i];

        // r_i XOR borrow (both shared)
        // Need mul for XOR: a XOR b = a + b - 2*a*b
        // But we'll batch these below
        let r_xor_borrow_needs_mul = true;

        if c_bits[i] {
            // x_i = NOT(r_i XOR borrow)
            // We need r_i * borrow first, then 1 - (r_i + borrow - 2*r_i*borrow)
            result_bits.push((r_i, borrow, true)); // (a, b, negate)
        } else {
            // x_i = r_i XOR borrow
            result_bits.push((r_i, borrow, false));
        }
    }

    // Batch all the XOR multiplications
    let xor_as: Vec<SpdzPrimeFieldShare<F>> = result_bits.iter().map(|(a, _, _)| *a).collect();
    let xor_bs: Vec<SpdzPrimeFieldShare<F>> = result_bits.iter().map(|(_, b, _)| *b).collect();
    let products = arithmetic::mul_many(&xor_as, &xor_bs, net, state)?;

    let mut final_bits = Vec::with_capacity(num_bits);
    for i in 0..num_bits {
        let (a, b, negate) = result_bits[i];
        let ab = products[i];
        let xor_val = a + b - ab * two;
        if negate {
            final_bits.push(arithmetic::add_public(-xor_val, F::one(), state.mac_key_share, state.id));
        } else {
            final_bits.push(xor_val);
        }
    }

    Ok(final_bits)
}
