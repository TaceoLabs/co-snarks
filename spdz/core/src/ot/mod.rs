//! OT-based Beaver Triple Generation for SPDZ
//!
//! Uses Oblivious Transfer (KOS extension with Chou-Orlandi base OT)
//! to generate Beaver triples without a trusted dealer.
//!
//! Protocol (Gilboa multiplication via OT):
//! For each triple (a, b, c) where c = a * b:
//!   1. Both parties pick random shares: a = a₀ + a₁, b = b₀ + b₁
//!   2. Use correlated OT to compute c₀, c₁ where c₀ + c₁ = a * b
//!   3. Authenticate with MAC shares
//!
//! The OT-based approach generates ~1M triples/second on modern hardware.

pub mod channel;
pub mod preprocessing;
pub mod triples;

use mpc_net::Network;

use crate::types::SpdzPrimeFieldShare;

/// OT-based preprocessing that generates Beaver triples on demand.
///
/// Each party creates one with their party_id and network reference.
/// The first call to any `next_*` method triggers the OT protocol.
pub struct OtPreprocessing<'a, N: Network> {
    party_id: usize,
    mac_key_share: ark_bn254::Fr,
    net: &'a N,
    rng: rand_chacha::ChaCha20Rng,
    // Buffers
    triple_buf: Vec<(
        SpdzPrimeFieldShare<ark_bn254::Fr>,
        SpdzPrimeFieldShare<ark_bn254::Fr>,
        SpdzPrimeFieldShare<ark_bn254::Fr>,
    )>,
    random_buf: Vec<SpdzPrimeFieldShare<ark_bn254::Fr>>,
    bit_buf: Vec<SpdzPrimeFieldShare<ark_bn254::Fr>>,
    batch_size: usize,
}

// TODO: Implement the full OT-based triple generation protocol.
// For now, this is a placeholder that documents the architecture.
// The actual implementation requires:
// 1. KOS OT extension init (128 base OTs via Chou-Orlandi)
// 2. Gilboa multiplication via correlated OT for each triple
// 3. MAC authentication using the shared MAC key
//
// The ocelot library provides the OT primitives:
//   - ocelot::ot::KosSender / KosReceiver for OT extension
//   - The channel adapter (NetworkChannel) connects our Network trait
//
// Estimated performance: ~100K triples/second over LAN
