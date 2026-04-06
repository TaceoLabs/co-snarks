//! Beaver Triple Generation via Oblivious Transfer
//!
//! Implements the Gilboa multiplication technique using KOS OT extension:
//!
//! To compute a shared product c = a*b where a = a0+a1, b = b0+b1:
//!   Each party knows their own (a_i, b_i). Need shares of a*b.
//!   a*b = a0*b0 + a0*b1 + a1*b0 + a1*b1
//!   Party i computes a_i*b_i locally.
//!   Cross terms (a0*b1, a1*b0) use Gilboa OT multiplication.
//!
//! Gilboa OT multiplication of x (sender's value) * y (receiver's bits):
//!   For each bit j of y:
//!     Sender offers (r_j, r_j + x * 2^j)
//!     Receiver selects message based on y[j]
//!     Receiver gets: r_j + y[j] * x * 2^j
//!   Sender's share: -sum(r_j)
//!   Receiver's share: sum(r_j + y[j] * x * 2^j) = sum(r_j) + x*y
//!   Combined: x*y ✓
//!
//! MAC generation uses the same technique: mac_i = alpha_i * v
//! where alpha = alpha0 + alpha1 is the global MAC key.

use ark_ff::{BigInteger, PrimeField};
use mpc_net::Network;
use ocelot::ot::{ChouOrlandiReceiver, ChouOrlandiSender, Receiver as OtReceiver, Sender as OtSender};
use rand::SeedableRng;
use scuttlebutt::{AesRng, Block};

use crate::network::SpdzNetworkExt;
use crate::types::SpdzPrimeFieldShare;
use super::channel::NetworkChannel;

/// Perform Gilboa OT multiplication: sender has `x`, receiver has `y`.
/// Returns additive shares of x*y.
///
/// sender_share + receiver_share = x * y (in the field)
///
/// The sender doesn't learn y, the receiver doesn't learn x.
fn gilboa_mul<F: PrimeField, N: Network>(
    party_id: usize,
    my_value: F,       // sender's x or receiver's y
    net: &N,
) -> eyre::Result<F> {
    let field_bits = F::MODULUS_BIT_SIZE as usize;
    let mut channel = NetworkChannel::new(net);
    let mut rng = AesRng::from_seed(rand::random());

    // Each field element = 2 Blocks (lo + hi halves).
    // For each bit of y, we need 2 OT messages (one per half).
    // Total: 2 * field_bits OT instances per Gilboa multiplication.

    if party_id == 0 {
        // Party 0 = OT Sender
        let mut sender = ChouOrlandiSender::init(&mut channel, &mut rng)
            .map_err(|e| eyre::eyre!("OT sender init: {:?}", e))?;

        let mut my_share = F::zero();
        let mut pairs = Vec::with_capacity(2 * field_bits);

        let mut pow = F::one();
        for _j in 0..field_bits {
            let r_j = F::rand(&mut rng);
            let val0 = r_j;
            let val1 = r_j + my_value * pow;

            // Encode each as two blocks
            let (lo0, hi0) = field_to_block_pair::<F>(val0);
            let (lo1, hi1) = field_to_block_pair::<F>(val1);
            pairs.push((lo0, lo1));
            pairs.push((hi0, hi1));

            my_share -= r_j;
            pow.double_in_place();
        }

        sender.send(&mut channel, &pairs, &mut rng)
            .map_err(|e| eyre::eyre!("OT send: {:?}", e))?;

        Ok(my_share)
    } else {
        // Party 1 = OT Receiver
        let mut receiver = ChouOrlandiReceiver::init(&mut channel, &mut rng)
            .map_err(|e| eyre::eyre!("OT receiver init: {:?}", e))?;

        let y_big = my_value.into_bigint();
        // Each bit needs 2 OT calls (lo + hi), same choice bit for both
        let mut choices = Vec::with_capacity(2 * field_bits);
        for j in 0..field_bits {
            let bit = y_big.get_bit(j as usize);
            choices.push(bit); // for lo half
            choices.push(bit); // for hi half
        }

        let received = receiver.receive(&mut channel, &choices, &mut rng)
            .map_err(|e| eyre::eyre!("OT receive: {:?}", e))?;

        // Reconstruct: each consecutive pair of blocks is one field element
        let mut my_share = F::zero();
        for chunk in received.chunks(2) {
            my_share += block_pair_to_field::<F>(chunk[0], chunk[1]);
        }

        Ok(my_share)
    }
}

/// Generate `count` Beaver triples using OT-based Gilboa multiplication.
///
/// Each triple (a, b, c) satisfies: a*b = c (when shares are combined).
/// All values are authenticated with MAC key alpha = alpha0 + alpha1.
///
/// Protocol:
/// 1. Each party generates random a_i, b_i locally
/// 2. Cross-products computed via Gilboa OT (no values revealed)
/// 3. MACs computed via Gilboa OT (mac_i = alpha_i * value)
pub fn generate_triples_via_ot<F: PrimeField, N: Network>(
    count: usize,
    party_id: usize,
    net: &N,
) -> eyre::Result<(Vec<(SpdzPrimeFieldShare<F>, SpdzPrimeFieldShare<F>, SpdzPrimeFieldShare<F>)>, F)>
{
    let mut rng = rand_chacha::ChaCha20Rng::from_entropy();

    // Step 1: MAC key — each party picks a random share
    let mac_key_share = F::rand(&mut rng);

    // Step 2: Generate random a_i, b_i locally
    let a_shares: Vec<F> = (0..count).map(|_| F::rand(&mut rng)).collect();
    let b_shares: Vec<F> = (0..count).map(|_| F::rand(&mut rng)).collect();

    // Step 3: Compute cross-product shares via Gilboa OT
    // c = a*b = (a0+a1)(b0+b1) = a0*b0 + a0*b1 + a1*b0 + a1*b1
    // Party i computes a_i*b_i locally.
    // Cross term a_i*b_j (i≠j) via OT: one party has a_i (sender), other has b_j (receiver).
    //
    // We need TWO Gilboa multiplications per triple:
    //   cross1 = a0 * b1 (Party 0 sends a0, Party 1 selects with b1)
    //   cross2 = a1 * b0 (Party 1 sends a1, Party 0 selects with b0)
    //
    // For efficiency, batch all triples:
    //   Round 1: Party 0 is sender (sends a0_i values), Party 1 is receiver (uses b1_i)
    //   Round 2: Party 1 is sender (sends a1_i values), Party 0 is receiver (uses b0_i)

    let mut cross1_shares = Vec::with_capacity(count);
    let mut cross2_shares = Vec::with_capacity(count);

    // Round 1: compute shares of a0 * b1
    for i in 0..count {
        let my_val = if party_id == 0 { a_shares[i] } else { b_shares[i] };
        let share = gilboa_mul::<F, N>(party_id, my_val, net)?;
        cross1_shares.push(share);
    }

    // Round 2: compute shares of a1 * b0 (swap roles)
    for i in 0..count {
        let my_val = if party_id == 0 { b_shares[i] } else { a_shares[i] };
        // Swap roles: Party 0 is now receiver, Party 1 is sender
        let share = gilboa_mul::<F, N>(1 - party_id, my_val, net)?;
        cross2_shares.push(share);
    }

    // Combine: c_i = a_i*b_i + cross1_i + cross2_i
    let c_shares: Vec<F> = (0..count)
        .map(|i| a_shares[i] * b_shares[i] + cross1_shares[i] + cross2_shares[i])
        .collect();

    // Step 4: Authenticate with MACs via OT
    // For each value v with shares (v0, v1), need mac_i = alpha_i * (v0+v1).
    // mac_i = alpha_i * v_i + alpha_i * v_j (cross-term via OT)
    //
    // For each value, one Gilboa mul: alpha_i * v_j
    // Total: 3 * count Gilboa muls (for a, b, c values)

    let mut triples = Vec::with_capacity(count);
    for i in 0..count {
        let a_mac = compute_mac_share(party_id, mac_key_share, a_shares[i], net)?;
        let b_mac = compute_mac_share(party_id, mac_key_share, b_shares[i], net)?;
        let c_mac = compute_mac_share(party_id, mac_key_share, c_shares[i], net)?;

        triples.push((
            SpdzPrimeFieldShare::new(a_shares[i], a_mac),
            SpdzPrimeFieldShare::new(b_shares[i], b_mac),
            SpdzPrimeFieldShare::new(c_shares[i], c_mac),
        ));
    }

    Ok((triples, mac_key_share))
}

/// Compute MAC share for a value.
/// MAC = alpha * v where alpha = alpha0 + alpha1, v = v0 + v1.
/// Party i's MAC share = alpha_i * v_i + share_of(alpha_i * v_j) + share_of(alpha_j * v_i)
///
/// Cross terms computed via Gilboa OT:
///   Round 1: Party 0 sends alpha_0 (sender), Party 1 uses v_1 (receiver) → shares of alpha_0 * v_1
///   Round 2: Party 0 uses v_0 (receiver), Party 1 sends alpha_1 (sender) → shares of alpha_1 * v_0
fn compute_mac_share<F: PrimeField, N: Network>(
    party_id: usize,
    mac_key_share: F,
    my_value_share: F,
    net: &N,
) -> eyre::Result<F> {
    // Local part
    let local_mac = mac_key_share * my_value_share;

    // Round 1: Party 0 sends alpha_0, Party 1 selects with v_1
    // This gives shares of alpha_0 * v_1
    let cross1 = if party_id == 0 {
        gilboa_mul::<F, N>(0, mac_key_share, net)?  // sender: alpha_0
    } else {
        gilboa_mul::<F, N>(1, my_value_share, net)?  // receiver: v_1
    };

    // Round 2: Party 1 sends alpha_1, Party 0 selects with v_0
    // This gives shares of alpha_1 * v_0
    let cross2 = if party_id == 0 {
        gilboa_mul::<F, N>(1, my_value_share, net)?  // receiver: v_0
    } else {
        gilboa_mul::<F, N>(0, mac_key_share, net)?  // sender: alpha_1
    };

    Ok(local_mac + cross1 + cross2)
}

// Helper: convert Field element to bytes and back.
// BN254 is 254 bits = 32 bytes. We split into 16-byte halves for Block encoding.
fn field_to_bytes<F: PrimeField>(f: F) -> Vec<u8> {
    f.into_bigint().to_bytes_le()
}

fn field_from_bytes<F: PrimeField>(bytes: &[u8]) -> F {
    F::from_le_bytes_mod_order(bytes)
}

fn field_to_block_pair<F: PrimeField>(f: F) -> (Block, Block) {
    let bytes = field_to_bytes(f);
    let mut lo = [0u8; 16];
    let mut hi = [0u8; 16];
    let mid = bytes.len().min(16);
    lo[..mid].copy_from_slice(&bytes[..mid]);
    if bytes.len() > 16 {
        let hi_len = (bytes.len() - 16).min(16);
        hi[..hi_len].copy_from_slice(&bytes[16..16 + hi_len]);
    }
    (Block::from(lo), Block::from(hi))
}

fn block_pair_to_field<F: PrimeField>(lo: Block, hi: Block) -> F {
    let lo_bytes: [u8; 16] = lo.into();
    let hi_bytes: [u8; 16] = hi.into();
    let mut bytes = Vec::with_capacity(32);
    bytes.extend_from_slice(&lo_bytes);
    bytes.extend_from_slice(&hi_bytes);
    F::from_le_bytes_mod_order(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use crate::types::combine_field_element;
    use mpc_net::local::LocalNetwork;

    #[test]
    fn test_ot_triple_generation() {
        let mut nets = LocalNetwork::new(2).into_iter();
        let net0 = nets.next().unwrap();
        let net1 = nets.next().unwrap();

        let count = 5;

        let h0 = std::thread::spawn(move || {
            generate_triples_via_ot::<Fr, _>(count, 0, &net0).unwrap()
        });
        let h1 = std::thread::spawn(move || {
            generate_triples_via_ot::<Fr, _>(count, 1, &net1).unwrap()
        });

        let (triples0, mk0) = h0.join().unwrap();
        let (triples1, mk1) = h1.join().unwrap();
        let mac_key = mk0 + mk1;

        for i in 0..count {
            let (a0, b0, c0) = &triples0[i];
            let (a1, b1, c1) = &triples1[i];

            let a = combine_field_element(*a0, *a1);
            let b = combine_field_element(*b0, *b1);
            let c = combine_field_element(*c0, *c1);

            // Verify: a * b = c
            assert_eq!(a * b, c, "Triple {i}: a*b must equal c");

            // Verify MACs
            assert_eq!(a0.mac + a1.mac, mac_key * a, "Triple {i}: MAC(a) correct");
            assert_eq!(b0.mac + b1.mac, mac_key * b, "Triple {i}: MAC(b) correct");
            assert_eq!(c0.mac + c1.mac, mac_key * c, "Triple {i}: MAC(c) correct");
        }
    }
}
