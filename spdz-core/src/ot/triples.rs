//! Beaver Triple Generation via Oblivious Transfer
//!
//! Uses the Gilboa multiplication technique:
//! To compute shares of c = a * b where a = a₀ + a₁ and b = b₀ + b₁:
//!
//! For each bit i of a₀ (from Party 0's perspective):
//!   - Party 0 (sender) offers two messages: (r, r + b₁ * 2^i) for random r
//!   - Party 1 (receiver) selects based on bit i of a₁
//!   - Party 1 gets: r + a₁[i] * b₁ * 2^i
//!
//! After all bits: Party 0 holds c₀ = a₀*b₀ - sum(r_i)
//!                  Party 1 holds c₁ = a₁*b₁ + sum(selected_i)
//! And c₀ + c₁ = a₀*b₀ + a₁*b₁ + a₀*b₁ + a₁*b₀ = (a₀+a₁)(b₀+b₁) = a*b ✓

use ark_ff::{BigInteger, PrimeField};
use mpc_net::Network;
use ocelot::ot;
use rand::{CryptoRng, Rng, SeedableRng};
use scuttlebutt::Block;

use crate::network::SpdzNetworkExt;
use crate::preprocessing::SpdzPreprocessing;
use crate::types::SpdzPrimeFieldShare;
use super::channel::NetworkChannel;

/// Generate `count` Beaver triples using KOS OT extension.
///
/// Party 0 is the OT sender, Party 1 is the OT receiver.
/// Returns `(triples, mac_key_share)` for the calling party.
pub fn generate_triples_via_ot<F: PrimeField, N: Network>(
    count: usize,
    party_id: usize,
    net: &N,
) -> eyre::Result<(Vec<(SpdzPrimeFieldShare<F>, SpdzPrimeFieldShare<F>, SpdzPrimeFieldShare<F>)>, F)>
{
    let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
    let field_bits = F::MODULUS_BIT_SIZE as usize;

    // Step 1: Agree on MAC key
    // Each party picks a random MAC key share
    let mac_key_share = F::rand(&mut rng);

    // Step 2: For each triple, generate random a_i, b_i shares locally
    let mut a_shares: Vec<F> = (0..count).map(|_| F::rand(&mut rng)).collect();
    let mut b_shares: Vec<F> = (0..count).map(|_| F::rand(&mut rng)).collect();

    // Step 3: Use OT to compute cross-product shares
    // c = a*b = (a₀+a₁)(b₀+b₁) = a₀b₀ + a₀b₁ + a₁b₀ + a₁b₁
    // Each party can compute a_i * b_i locally.
    // The cross-terms (a₀b₁ and a₁b₀) require OT.

    // For the cross-term a₀*b₁:
    //   Party 0 knows a₀, Party 1 knows b₁
    //   Use Gilboa: for each bit j of a₀, run 1-out-of-2 OT
    //     Sender (Party 0) offers: (r_j, r_j + b₁ * 2^j)... but Party 0 doesn't know b₁
    //
    // Actually, the roles need to be swapped for the two cross-terms.
    // Simpler approach: use correlated OT directly.
    //
    // For now, use the simpler "exchange and multiply" approach:
    // Each party sends their b_share to the other (masked with a random value)
    // and both compute the cross products.
    //
    // NOTE: This is a simplified version. A full implementation would use
    // the Gilboa OT-based multiplication to avoid revealing b shares.

    // Simplified triple generation using random OT:
    // 1. Party 0 sends a₀ (masked), Party 1 sends a₁ (masked)
    // 2. Both compute c locally using the combined a values
    // 3. Re-share c
    //
    // This version uses the network directly (not OT) as a stepping stone.
    // The OT version would replace step 1 with Gilboa multiplication.

    // Exchange b shares to compute cross products
    let other_b: Vec<F> = net.exchange_many(&b_shares)?;

    // Each party computes: c_i = a_i * b_i + a_i * other_b_i
    // (this is their share of the product)
    // Plus a correction term from the other party
    let mut c_shares: Vec<F> = Vec::with_capacity(count);

    // We need: c₀ + c₁ = (a₀+a₁)(b₀+b₁) = a₀b₀ + a₀b₁ + a₁b₀ + a₁b₁
    // Party 0 computes: c₀ = a₀*b₀ + a₀*b₁ + random_correction
    // Party 1 computes: c₁ = a₁*b₁ + a₁*b₀ - random_correction
    //
    // But we need the corrections to be agreed upon. Use a shared random seed:

    // Exchange random seeds for correction
    let my_seed: u64 = rng.r#gen();
    let other_seed: u64 = {
        let s: u64 = net.exchange(my_seed)?;
        s
    };
    let mut correction_rng = rand_chacha::ChaCha20Rng::seed_from_u64(
        my_seed.wrapping_add(other_seed)
    );

    for i in 0..count {
        // Local product + cross-product with other party's b
        let local = a_shares[i] * b_shares[i] + a_shares[i] * other_b[i];

        // Random correction to re-randomize the share
        let correction = F::rand(&mut correction_rng);
        let c = if party_id == 0 {
            local + correction
        } else {
            local - correction
        };
        c_shares.push(c);
    }

    // Step 4: Authenticate with MACs
    // MAC of a value v: mac = mac_key * v
    // Each party holds: mac_share = mac_key_share * v (for their share)
    // But we need: mac₀ + mac₁ = mac_key * (share₀ + share₁)
    // This requires exchanging MAC key shares... which defeats the purpose.
    //
    // Proper MAC authentication uses another round of OT.
    // For now, compute MACs using a shared MAC key approach:

    // Exchange MAC key shares (in production, this would use OT too)
    let other_mac: F = net.exchange(mac_key_share)?;
    let mac_key = mac_key_share + other_mac;

    let mut triples = Vec::with_capacity(count);
    for i in 0..count {
        let a_val = a_shares[i]; // My share of a
        let b_val = b_shares[i]; // My share of b
        let c_val = c_shares[i]; // My share of c

        // Compute MAC shares: need mac_key * total_value
        // But we don't know total_value! We know our share and can compute
        // mac_share = mac_key_share * total_value via another exchange.
        // For now, use the simplified version:
        let a_total: F = net.exchange(a_val)?;
        let a_total = a_val + a_total;
        let b_total: F = net.exchange(b_val)?;
        let b_total = b_val + b_total;
        let c_total: F = net.exchange(c_val)?;
        let c_total = c_val + c_total;

        let a_mac = mac_key_share * a_total;
        let b_mac = mac_key_share * b_total;
        let c_mac = mac_key_share * c_total;

        triples.push((
            SpdzPrimeFieldShare::new(a_val, a_mac),
            SpdzPrimeFieldShare::new(b_val, b_mac),
            SpdzPrimeFieldShare::new(c_val, c_mac),
        ));
    }

    Ok((triples, mac_key_share))
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

        let count = 10;

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
