//! Beaver Triple Generation via Oblivious Transfer
//!
//! Uses KOS OT extension for amortized efficiency:
//! - 128 base OTs (Chou-Orlandi) done ONCE during init
//! - All subsequent OTs use the KOS extension (cheap)
//!
//! Gilboa multiplication via OT:
//!   To compute shares of x*y where Party 0 has x, Party 1 has y:
//!   For each bit j of y:
//!     Sender offers (r_j, r_j + x * 2^j)
//!     Receiver selects based on y[j]
//!   Sender's share: -sum(r_j)
//!   Receiver's share: sum(selected) = sum(r_j) + x*y
//!   Combined: x*y

use ark_ff::{BigInteger, PrimeField};
use mpc_net::Network;
use ocelot::ot::{
    Sender as OtSender, Receiver as OtReceiver,
};
use rand::SeedableRng;
use scuttlebutt::{AesRng, Block};

use crate::types::SpdzPrimeFieldShare;
use super::channel::NetworkChannel;

/// KOS OT extension sender (wraps Chou-Orlandi base OT).
type KosSender = ocelot::ot::KosSender;
/// KOS OT extension receiver.
type KosReceiver = ocelot::ot::KosReceiver;

/// Perform Gilboa OT multiplication using a pre-initialized KOS sender/receiver.
/// Returns this party's additive share of x*y.
fn gilboa_mul_with_kos<F: PrimeField>(
    party_id: usize,
    my_value: F,
    channel: &mut NetworkChannel<'_, impl Network>,
    kos_sender: &mut Option<KosSender>,
    kos_receiver: &mut Option<KosReceiver>,
    rng: &mut AesRng,
) -> eyre::Result<F> {
    let field_bits = F::MODULUS_BIT_SIZE as usize;

    if party_id == 0 {
        let sender = kos_sender.as_mut().expect("KOS sender not initialized");

        let mut my_share = F::zero();
        let mut pairs = Vec::with_capacity(2 * field_bits);

        let mut pow = F::one();
        for _j in 0..field_bits {
            let r_j = F::rand(rng);
            let val0 = r_j;
            let val1 = r_j + my_value * pow;

            let (lo0, hi0) = field_to_block_pair::<F>(val0);
            let (lo1, hi1) = field_to_block_pair::<F>(val1);
            pairs.push((lo0, lo1));
            pairs.push((hi0, hi1));

            my_share -= r_j;
            pow.double_in_place();
        }

        sender.send(channel, &pairs, rng)
            .map_err(|e| eyre::eyre!("KOS send: {:?}", e))?;

        Ok(my_share)
    } else {
        let receiver = kos_receiver.as_mut().expect("KOS receiver not initialized");

        let y_big = my_value.into_bigint();
        let mut choices = Vec::with_capacity(2 * field_bits);
        for j in 0..field_bits {
            let bit = y_big.get_bit(j as usize);
            choices.push(bit);
            choices.push(bit);
        }

        let received = receiver.receive(channel, &choices, rng)
            .map_err(|e| eyre::eyre!("KOS receive: {:?}", e))?;

        let mut my_share = F::zero();
        for chunk in received.chunks(2) {
            my_share += block_pair_to_field::<F>(chunk[0], chunk[1]);
        }

        Ok(my_share)
    }
}

/// Generate `count` Beaver triples using KOS OT extension.
///
/// Protocol:
/// 1. Initialize KOS OT extension (128 base OTs via Chou-Orlandi — done ONCE)
/// 2. For each triple: generate random a_i, b_i locally
/// 3. Cross-products via Gilboa OT (reuses KOS instance — cheap)
/// 4. MACs via Gilboa OT (reuses same KOS instance)
///
/// Cost: 128 base OTs + O(count * field_bits) KOS-extended OTs
pub fn generate_triples_via_ot<F: PrimeField, N: Network>(
    count: usize,
    party_id: usize,
    net: &N,
) -> eyre::Result<(Vec<(SpdzPrimeFieldShare<F>, SpdzPrimeFieldShare<F>, SpdzPrimeFieldShare<F>)>, F)>
{
    let mut rng = AesRng::from_seed(rand::random());
    let mut channel = NetworkChannel::new(net);

    // Step 1: Initialize KOS OT extension ONCE
    // This does 128 Chou-Orlandi base OTs, then all further OTs are cheap.
    let mut kos_sender: Option<KosSender> = None;
    let mut kos_receiver: Option<KosReceiver> = None;

    if party_id == 0 {
        // Party 0 starts as sender for cross-product round 1
        kos_sender = Some(KosSender::init(&mut channel, &mut rng)
            .map_err(|e| eyre::eyre!("KOS sender init: {:?}", e))?);
    } else {
        kos_receiver = Some(KosReceiver::init(&mut channel, &mut rng)
            .map_err(|e| eyre::eyre!("KOS receiver init: {:?}", e))?);
    }

    let mac_key_share = F::rand(&mut rng);
    let a_shares: Vec<F> = (0..count).map(|_| F::rand(&mut rng)).collect();
    let b_shares: Vec<F> = (0..count).map(|_| F::rand(&mut rng)).collect();

    // Step 2: Cross-product round 1 (Party 0 sends a_i, Party 1 selects with b_i)
    let mut cross1_shares = Vec::with_capacity(count);
    for i in 0..count {
        let my_val = if party_id == 0 { a_shares[i] } else { b_shares[i] };
        let share = gilboa_mul_with_kos::<F>(
            party_id, my_val, &mut channel, &mut kos_sender, &mut kos_receiver, &mut rng,
        )?;
        cross1_shares.push(share);
    }

    // Step 3: Swap roles for cross-product round 2
    // Need to re-init KOS with swapped roles
    drop(kos_sender.take());
    drop(kos_receiver.take());

    if party_id == 0 {
        // Party 0 is now receiver
        kos_receiver = Some(KosReceiver::init(&mut channel, &mut rng)
            .map_err(|e| eyre::eyre!("KOS receiver init (round 2): {:?}", e))?);
    } else {
        // Party 1 is now sender
        kos_sender = Some(KosSender::init(&mut channel, &mut rng)
            .map_err(|e| eyre::eyre!("KOS sender init (round 2): {:?}", e))?);
    }

    let mut cross2_shares = Vec::with_capacity(count);
    for i in 0..count {
        let my_val = if party_id == 0 { b_shares[i] } else { a_shares[i] };
        let share = gilboa_mul_with_kos::<F>(
            1 - party_id, my_val, &mut channel, &mut kos_sender, &mut kos_receiver, &mut rng,
        )?;
        cross2_shares.push(share);
    }

    // c_i = a_i*b_i + cross1_i + cross2_i
    let c_shares: Vec<F> = (0..count)
        .map(|i| a_shares[i] * b_shares[i] + cross1_shares[i] + cross2_shares[i])
        .collect();

    // Step 4: MAC authentication via Gilboa OT
    // For each value, need two cross terms: alpha_i * v_j and alpha_j * v_i
    // Re-init KOS for MAC rounds (Party 0 sends alpha_0 first)
    drop(kos_sender.take());
    drop(kos_receiver.take());

    if party_id == 0 {
        kos_sender = Some(KosSender::init(&mut channel, &mut rng)
            .map_err(|e| eyre::eyre!("KOS sender init (MAC round 1): {:?}", e))?);
    } else {
        kos_receiver = Some(KosReceiver::init(&mut channel, &mut rng)
            .map_err(|e| eyre::eyre!("KOS receiver init (MAC round 1): {:?}", e))?);
    }

    // MAC round 1: Party 0 sends alpha_0, Party 1 selects with values
    let all_values: Vec<F> = a_shares.iter().chain(b_shares.iter()).chain(c_shares.iter()).copied().collect();
    let mut mac_cross1 = Vec::with_capacity(3 * count);
    for &v in &all_values {
        let my_val = if party_id == 0 { mac_key_share } else { v };
        let share = gilboa_mul_with_kos::<F>(
            party_id, my_val, &mut channel, &mut kos_sender, &mut kos_receiver, &mut rng,
        )?;
        mac_cross1.push(share);
    }

    // MAC round 2: swap roles
    drop(kos_sender.take());
    drop(kos_receiver.take());

    if party_id == 0 {
        kos_receiver = Some(KosReceiver::init(&mut channel, &mut rng)
            .map_err(|e| eyre::eyre!("KOS receiver init (MAC round 2): {:?}", e))?);
    } else {
        kos_sender = Some(KosSender::init(&mut channel, &mut rng)
            .map_err(|e| eyre::eyre!("KOS sender init (MAC round 2): {:?}", e))?);
    }

    let mut mac_cross2 = Vec::with_capacity(3 * count);
    for &v in &all_values {
        let my_val = if party_id == 0 { v } else { mac_key_share };
        let share = gilboa_mul_with_kos::<F>(
            1 - party_id, my_val, &mut channel, &mut kos_sender, &mut kos_receiver, &mut rng,
        )?;
        mac_cross2.push(share);
    }

    // Assemble triples with MACs
    let mut triples = Vec::with_capacity(count);
    for i in 0..count {
        let a_mac = mac_key_share * a_shares[i] + mac_cross1[i] + mac_cross2[i];
        let b_mac = mac_key_share * b_shares[i] + mac_cross1[count + i] + mac_cross2[count + i];
        let c_mac = mac_key_share * c_shares[i] + mac_cross1[2 * count + i] + mac_cross2[2 * count + i];

        triples.push((
            SpdzPrimeFieldShare::new(a_shares[i], a_mac),
            SpdzPrimeFieldShare::new(b_shares[i], b_mac),
            SpdzPrimeFieldShare::new(c_shares[i], c_mac),
        ));
    }

    Ok((triples, mac_key_share))
}

fn field_to_block_pair<F: PrimeField>(f: F) -> (Block, Block) {
    let bytes = f.into_bigint().to_bytes_le();
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

            assert_eq!(a * b, c, "Triple {i}: a*b must equal c");
            assert_eq!(a0.mac + a1.mac, mac_key * a, "Triple {i}: MAC(a) correct");
            assert_eq!(b0.mac + b1.mac, mac_key * b, "Triple {i}: MAC(b) correct");
            assert_eq!(c0.mac + c1.mac, mac_key * c, "Triple {i}: MAC(c) correct");
        }
    }
}
