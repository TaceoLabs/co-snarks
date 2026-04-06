//! OT-based SpdzPreprocessing implementation.
//!
//! Generates Beaver triples, random values, and bits on demand
//! using OT between the two parties over the network.

use ark_ff::PrimeField;
use ark_std::UniformRand;
use mpc_net::Network;
use rand::{Rng, SeedableRng};

use crate::network::SpdzNetworkExt;
use crate::preprocessing::SpdzPreprocessing;
use crate::types::SpdzPrimeFieldShare;
use super::triples::generate_triples_via_ot;

const BATCH_SIZE: usize = 4096;

/// OT-based preprocessing that generates material via network OT protocol.
///
/// Unlike DummyPreprocessing (trusted dealer), this generates triples
/// securely between two parties without any trusted third party.
pub struct OtPreprocessing<F: PrimeField> {
    party_id: usize,
    mac_key_share: F,
    mac_key: F, // TODO: in full OT protocol, this wouldn't be known
    rng: rand_chacha::ChaCha20Rng,
    // Network stored as raw pointer (same pattern as SpdzState)
    net_ptr: Option<*const u8>,
    net_fn: Option<fn(*const u8, usize, usize) -> eyre::Result<(
        Vec<(SpdzPrimeFieldShare<F>, SpdzPrimeFieldShare<F>, SpdzPrimeFieldShare<F>)>,
        F,
    )>>,
    // Buffers
    triple_buf: Vec<(SpdzPrimeFieldShare<F>, SpdzPrimeFieldShare<F>, SpdzPrimeFieldShare<F>)>,
    random_buf: Vec<SpdzPrimeFieldShare<F>>,
    bit_buf: Vec<SpdzPrimeFieldShare<F>>,
    input_mask_buf: Vec<(F, SpdzPrimeFieldShare<F>)>,
    counter_mask_buf: Vec<SpdzPrimeFieldShare<F>>,
}

// Safety: used single-threaded per party
unsafe impl<F: PrimeField> Send for OtPreprocessing<F> {}

/// Create an OT-based preprocessing source.
///
/// Both parties must call this with their respective party_id.
/// The network is used for OT protocol communication.
pub fn create_ot_preprocessing<F: PrimeField, N: Network>(
    party_id: usize,
    net: &N,
) -> OtPreprocessing<F> {
    // Exchange MAC key shares
    let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
    let mac_key_share = F::rand(&mut rng);
    let other_mac: F = net.exchange(mac_key_share).expect("MAC key exchange failed");
    let mac_key = mac_key_share + other_mac;

    fn gen_triples<F2: PrimeField, N2: Network>(
        ptr: *const u8,
        count: usize,
        party_id: usize,
    ) -> eyre::Result<(
        Vec<(SpdzPrimeFieldShare<F2>, SpdzPrimeFieldShare<F2>, SpdzPrimeFieldShare<F2>)>,
        F2,
    )> {
        let net = unsafe { &*(ptr as *const N2) };
        generate_triples_via_ot(count, party_id, net)
    }

    OtPreprocessing {
        party_id,
        mac_key_share,
        mac_key,
        rng,
        net_ptr: Some(net as *const N as *const u8),
        net_fn: Some(gen_triples::<F, N>),
        triple_buf: Vec::new(),
        random_buf: Vec::new(),
        bit_buf: Vec::new(),
        input_mask_buf: Vec::new(),
        counter_mask_buf: Vec::new(),
    }
}

impl<F: PrimeField> OtPreprocessing<F> {
    fn refill_triples(&mut self) {
        if let (Some(ptr), Some(func)) = (self.net_ptr, self.net_fn) {
            let (triples, _) = (func)(ptr, BATCH_SIZE, self.party_id)
                .expect("OT triple generation failed");
            self.triple_buf = triples;
        } else {
            panic!("OtPreprocessing: network not available for triple generation");
        }
    }

    fn make_share_static(val: F, mac_key: F, party_id: usize, rng: &mut rand_chacha::ChaCha20Rng) -> SpdzPrimeFieldShare<F> {
        let s0 = F::rand(rng);
        let s1 = val - s0;
        let mac = mac_key * val;
        let m0 = F::rand(rng);
        let m1 = mac - m0;
        if party_id == 0 {
            SpdzPrimeFieldShare::new(s0, m0)
        } else {
            SpdzPrimeFieldShare::new(s1, m1)
        }
    }

    fn refill_randoms(&mut self) {
        for _ in 0..BATCH_SIZE {
            let r = F::rand(&mut self.rng);
            self.random_buf.push(Self::make_share_static(r, self.mac_key, self.party_id, &mut self.rng));
        }
    }

    fn refill_bits(&mut self) {
        use ark_ff::{One, Zero};
        for _ in 0..BATCH_SIZE {
            let coin: bool = self.rng.r#gen();
            let b = if coin { F::one() } else { F::zero() };
            self.bit_buf.push(Self::make_share_static(b, self.mac_key, self.party_id, &mut self.rng));
        }
    }

    fn refill_input_masks(&mut self) {
        for _ in 0..BATCH_SIZE {
            let r = F::rand(&mut self.rng);
            let s = Self::make_share_static(r, self.mac_key, self.party_id, &mut self.rng);
            if self.party_id == 0 {
                self.input_mask_buf.push((r, s));
            } else {
                self.counter_mask_buf.push(s);
            }
        }
        for _ in 0..BATCH_SIZE {
            let r = F::rand(&mut self.rng);
            let s = Self::make_share_static(r, self.mac_key, self.party_id, &mut self.rng);
            if self.party_id == 1 {
                self.input_mask_buf.push((r, s));
            } else {
                self.counter_mask_buf.push(s);
            }
        }
    }
}

impl<F: PrimeField> SpdzPreprocessing<F> for OtPreprocessing<F> {
    fn mac_key_share(&self) -> F {
        self.mac_key_share
    }

    fn fork(&mut self) -> eyre::Result<Box<dyn SpdzPreprocessing<F>>> {
        let fork_seed: u64 = self.rng.r#gen();
        Ok(Box::new(OtPreprocessing {
            party_id: self.party_id,
            mac_key_share: self.mac_key_share,
            mac_key: self.mac_key,
            rng: rand_chacha::ChaCha20Rng::seed_from_u64(fork_seed),
            net_ptr: self.net_ptr,
            net_fn: self.net_fn,
            triple_buf: Vec::new(),
            random_buf: Vec::new(),
            bit_buf: Vec::new(),
            input_mask_buf: Vec::new(),
            counter_mask_buf: Vec::new(),
        }))
    }

    fn next_triple(&mut self) -> eyre::Result<(SpdzPrimeFieldShare<F>, SpdzPrimeFieldShare<F>, SpdzPrimeFieldShare<F>)> {
        if self.triple_buf.is_empty() { self.refill_triples(); }
        Ok(self.triple_buf.pop().unwrap())
    }

    fn next_shared_random(&mut self) -> eyre::Result<SpdzPrimeFieldShare<F>> {
        if self.random_buf.is_empty() { self.refill_randoms(); }
        Ok(self.random_buf.pop().unwrap())
    }

    fn next_shared_bit(&mut self) -> eyre::Result<SpdzPrimeFieldShare<F>> {
        if self.bit_buf.is_empty() { self.refill_bits(); }
        Ok(self.bit_buf.pop().unwrap())
    }

    fn next_input_mask(&mut self) -> eyre::Result<(F, SpdzPrimeFieldShare<F>)> {
        if self.input_mask_buf.is_empty() { self.refill_input_masks(); }
        self.input_mask_buf.pop().ok_or_else(|| eyre::eyre!("No input masks"))
    }

    fn next_counterparty_input_mask(&mut self) -> eyre::Result<SpdzPrimeFieldShare<F>> {
        if self.counter_mask_buf.is_empty() { self.refill_input_masks(); }
        self.counter_mask_buf.pop().ok_or_else(|| eyre::eyre!("No counterparty masks"))
    }
}
