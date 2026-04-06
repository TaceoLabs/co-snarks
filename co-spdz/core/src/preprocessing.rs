use ark_ff::PrimeField;
use rand::{CryptoRng, Rng, SeedableRng};

use crate::types::SpdzPrimeFieldShare;

/// Trait for SPDZ preprocessing (offline phase).
///
/// Provides Beaver triples, shared random values, shared random bits,
/// and input masks consumed by the online phase.
pub trait SpdzPreprocessing<F: PrimeField>: Send {
    /// This party's additive share of the global MAC key alpha.
    fn mac_key_share(&self) -> F;

    /// Get the next Beaver triple `([a], [b], [c])` where `a * b = c`.
    fn next_triple(&mut self) -> eyre::Result<(SpdzPrimeFieldShare<F>, SpdzPrimeFieldShare<F>, SpdzPrimeFieldShare<F>)>;

    /// Get a batch of Beaver triples.
    fn next_triple_batch(
        &mut self,
        n: usize,
    ) -> eyre::Result<(Vec<SpdzPrimeFieldShare<F>>, Vec<SpdzPrimeFieldShare<F>>, Vec<SpdzPrimeFieldShare<F>>)> {
        let mut a_vec = Vec::with_capacity(n);
        let mut b_vec = Vec::with_capacity(n);
        let mut c_vec = Vec::with_capacity(n);
        for _ in 0..n {
            let (a, b, c) = self.next_triple()?;
            a_vec.push(a);
            b_vec.push(b);
            c_vec.push(c);
        }
        Ok((a_vec, b_vec, c_vec))
    }

    /// Get the next shared random value.
    fn next_shared_random(&mut self) -> eyre::Result<SpdzPrimeFieldShare<F>>;

    /// Get a batch of shared random values.
    fn next_shared_random_batch(&mut self, n: usize) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
        (0..n).map(|_| self.next_shared_random()).collect()
    }

    /// Get the next shared random bit (value is 0 or 1).
    fn next_shared_bit(&mut self) -> eyre::Result<SpdzPrimeFieldShare<F>>;

    /// Get a batch of shared random bits.
    fn next_shared_bit_batch(&mut self, n: usize) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
        (0..n).map(|_| self.next_shared_bit()).collect()
    }

    /// Get an input mask for this party: returns `(r, [r])` where this party
    /// knows the cleartext `r` and both parties hold shares of `[r]`.
    fn next_input_mask(&mut self) -> eyre::Result<(F, SpdzPrimeFieldShare<F>)>;

    /// Get an input mask for the counterparty: returns only `[r]` (the share).
    /// The counterparty knows the cleartext `r`.
    fn next_counterparty_input_mask(&mut self) -> eyre::Result<SpdzPrimeFieldShare<F>>;

    /// Fork the preprocessing source, splitting off material for a sub-protocol.
    /// The default implementation creates an empty source that will error on use.
    fn fork(&mut self) -> eyre::Result<Box<dyn SpdzPreprocessing<F>>> {
        eyre::bail!("This preprocessing source does not support forking")
    }
}

// ────────────────────────── Dummy Preprocessing ──────────────────────────

/// A trusted-dealer preprocessing source for development and testing.
///
/// Generates all preprocessing material locally (as if a trusted dealer
/// produced it). NOT suitable for production — both parties' material is
/// generated in a single process.
pub struct DummyPreprocessing<F: PrimeField> {
    mac_key_share: F,
    triples: Vec<(SpdzPrimeFieldShare<F>, SpdzPrimeFieldShare<F>, SpdzPrimeFieldShare<F>)>,
    randoms: Vec<SpdzPrimeFieldShare<F>>,
    bits: Vec<SpdzPrimeFieldShare<F>>,
    input_masks: Vec<(F, SpdzPrimeFieldShare<F>)>,
    counterparty_input_masks: Vec<SpdzPrimeFieldShare<F>>,
}

impl<F: PrimeField> DummyPreprocessing<F> {
    /// Default number of triples/randoms/bits to pre-generate.
    pub const DEFAULT_BATCH_SIZE: usize = 1024;
}

/// Generate preprocessing material for both parties from a trusted dealer.
///
/// Returns `(prep_party_0, prep_party_1)`.
pub fn generate_dummy_preprocessing<F: PrimeField>(
    batch_size: usize,
) -> (DummyPreprocessing<F>, DummyPreprocessing<F>) {
    let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
    generate_dummy_preprocessing_with_rng(batch_size, &mut rng)
}

/// Generate preprocessing with a specific RNG (useful for deterministic tests).
pub fn generate_dummy_preprocessing_with_rng<F: PrimeField, R: Rng + CryptoRng>(
    batch_size: usize,
    rng: &mut R,
) -> (DummyPreprocessing<F>, DummyPreprocessing<F>) {
    use ark_ff::UniformRand;

    // Generate global MAC key and split it
    let mac_key = F::rand(rng);
    let mac_key_0 = F::rand(rng);
    let mac_key_1 = mac_key - mac_key_0;

    // Helper to create SPDZ shares of a value
    let share = |val: F, rng: &mut R| -> [SpdzPrimeFieldShare<F>; 2] {
        let s0 = F::rand(rng);
        let s1 = val - s0;
        let mac = mac_key * val;
        let m0 = F::rand(rng);
        let m1 = mac - m0;
        [
            SpdzPrimeFieldShare::new(s0, m0),
            SpdzPrimeFieldShare::new(s1, m1),
        ]
    };

    // Generate Beaver triples
    let mut triples_0 = Vec::with_capacity(batch_size);
    let mut triples_1 = Vec::with_capacity(batch_size);
    for _ in 0..batch_size {
        let a = F::rand(rng);
        let b = F::rand(rng);
        let c = a * b;
        let [a0, a1] = share(a, rng);
        let [b0, b1] = share(b, rng);
        let [c0, c1] = share(c, rng);
        triples_0.push((a0, b0, c0));
        triples_1.push((a1, b1, c1));
    }

    // Generate shared random values
    let mut randoms_0 = Vec::with_capacity(batch_size);
    let mut randoms_1 = Vec::with_capacity(batch_size);
    for _ in 0..batch_size {
        let r = F::rand(rng);
        let [r0, r1] = share(r, rng);
        randoms_0.push(r0);
        randoms_1.push(r1);
    }

    // Generate shared random bits
    let mut bits_0 = Vec::with_capacity(batch_size);
    let mut bits_1 = Vec::with_capacity(batch_size);
    for _ in 0..batch_size {
        let b = if bool::rand(rng) { F::one() } else { F::zero() };
        let [b0, b1] = share(b, rng);
        bits_0.push(b0);
        bits_1.push(b1);
    }

    // Generate input masks for party 0 (party 0 knows cleartext r)
    let mut input_masks_0 = Vec::with_capacity(batch_size);
    let mut counterparty_masks_1 = Vec::with_capacity(batch_size);
    for _ in 0..batch_size {
        let r = F::rand(rng);
        let [r0, r1] = share(r, rng);
        input_masks_0.push((r, r0));
        counterparty_masks_1.push(r1);
    }

    // Generate input masks for party 1 (party 1 knows cleartext r)
    let mut input_masks_1 = Vec::with_capacity(batch_size);
    let mut counterparty_masks_0 = Vec::with_capacity(batch_size);
    for _ in 0..batch_size {
        let r = F::rand(rng);
        let [r0, r1] = share(r, rng);
        input_masks_1.push((r, r1));
        counterparty_masks_0.push(r0);
    }

    (
        DummyPreprocessing {
            mac_key_share: mac_key_0,
            triples: triples_0,
            randoms: randoms_0,
            bits: bits_0,
            input_masks: input_masks_0,
            counterparty_input_masks: counterparty_masks_0,
        },
        DummyPreprocessing {
            mac_key_share: mac_key_1,
            triples: triples_1,
            randoms: randoms_1,
            bits: bits_1,
            input_masks: input_masks_1,
            counterparty_input_masks: counterparty_masks_1,
        },
    )
}

impl<F: PrimeField> SpdzPreprocessing<F> for DummyPreprocessing<F> {
    fn mac_key_share(&self) -> F {
        self.mac_key_share
    }

    fn fork(&mut self) -> eyre::Result<Box<dyn SpdzPreprocessing<F>>> {
        // Split off half the material for the forked instance.
        // This matches Shamir's pattern where fork() gives material to sub-protocols.
        let mid_t = self.triples.len() / 2;
        let mid_r = self.randoms.len() / 2;
        let mid_b = self.bits.len() / 2;
        let mid_im = self.input_masks.len() / 2;
        let mid_cm = self.counterparty_input_masks.len() / 2;

        let forked = DummyPreprocessing {
            mac_key_share: self.mac_key_share,
            triples: self.triples.split_off(mid_t),
            randoms: self.randoms.split_off(mid_r),
            bits: self.bits.split_off(mid_b),
            input_masks: self.input_masks.split_off(mid_im),
            counterparty_input_masks: self.counterparty_input_masks.split_off(mid_cm),
        };
        Ok(Box::new(forked))
    }

    fn next_triple(
        &mut self,
    ) -> eyre::Result<(SpdzPrimeFieldShare<F>, SpdzPrimeFieldShare<F>, SpdzPrimeFieldShare<F>)> {
        self.triples
            .pop()
            .ok_or_else(|| eyre::eyre!("Ran out of preprocessing triples"))
    }

    fn next_shared_random(&mut self) -> eyre::Result<SpdzPrimeFieldShare<F>> {
        self.randoms
            .pop()
            .ok_or_else(|| eyre::eyre!("Ran out of preprocessing random values"))
    }

    fn next_shared_bit(&mut self) -> eyre::Result<SpdzPrimeFieldShare<F>> {
        self.bits
            .pop()
            .ok_or_else(|| eyre::eyre!("Ran out of preprocessing random bits"))
    }

    fn next_input_mask(&mut self) -> eyre::Result<(F, SpdzPrimeFieldShare<F>)> {
        self.input_masks
            .pop()
            .ok_or_else(|| eyre::eyre!("Ran out of preprocessing input masks"))
    }

    fn next_counterparty_input_mask(&mut self) -> eyre::Result<SpdzPrimeFieldShare<F>> {
        self.counterparty_input_masks
            .pop()
            .ok_or_else(|| eyre::eyre!("Ran out of preprocessing counterparty input masks"))
    }
}

// ─────────────────── Lazy Dummy Preprocessing ───────────────────

/// A lazy preprocessing source that generates material on demand.
///
/// Unlike `DummyPreprocessing` which pre-allocates everything,
/// this generates triples/randoms/bits in small batches as needed.
/// Memory usage is O(batch_size) instead of O(total_needed).
///
/// Both parties MUST use the same seed and party_id for correlated output.
pub struct LazyDummyPreprocessing<F: PrimeField> {
    mac_key: F,
    mac_key_share: F,
    party_id: usize, // 0 or 1
    rng: rand_chacha::ChaCha20Rng,
    // Buffers (refilled on demand)
    triple_buf: Vec<(SpdzPrimeFieldShare<F>, SpdzPrimeFieldShare<F>, SpdzPrimeFieldShare<F>)>,
    random_buf: Vec<SpdzPrimeFieldShare<F>>,
    bit_buf: Vec<SpdzPrimeFieldShare<F>>,
    input_mask_buf: Vec<(F, SpdzPrimeFieldShare<F>)>,
    counter_mask_buf: Vec<SpdzPrimeFieldShare<F>>,
    batch_size: usize,
}

const LAZY_BATCH: usize = 4096;

impl<F: PrimeField> LazyDummyPreprocessing<F> {
    fn make_share(val: F, mac_key: F, party_id: usize, rng: &mut rand_chacha::ChaCha20Rng) -> SpdzPrimeFieldShare<F> {
        use ark_ff::UniformRand;
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

    fn refill_triples(&mut self) {
        use ark_ff::UniformRand;
        for _ in 0..self.batch_size {
            let a = F::rand(&mut self.rng);
            let b = F::rand(&mut self.rng);
            let c = a * b;
            let as_ = Self::make_share(a, self.mac_key, self.party_id, &mut self.rng);
            let bs_ = Self::make_share(b, self.mac_key, self.party_id, &mut self.rng);
            let cs_ = Self::make_share(c, self.mac_key, self.party_id, &mut self.rng);
            self.triple_buf.push((as_, bs_, cs_));
        }
    }

    fn refill_randoms(&mut self) {
        use ark_ff::UniformRand;
        for _ in 0..self.batch_size {
            let r = F::rand(&mut self.rng);
            self.random_buf.push(Self::make_share(r, self.mac_key, self.party_id, &mut self.rng));
        }
    }

    fn refill_bits(&mut self) {
        use ark_ff::{UniformRand, Zero, One};
        for _ in 0..self.batch_size {
            let b = if bool::rand(&mut self.rng) { F::one() } else { F::zero() };
            self.bit_buf.push(Self::make_share(b, self.mac_key, self.party_id, &mut self.rng));
        }
    }

    fn refill_input_masks(&mut self) {
        use ark_ff::UniformRand;
        // Party 0's input masks
        for _ in 0..self.batch_size {
            let r = F::rand(&mut self.rng);
            let s = Self::make_share(r, self.mac_key, self.party_id, &mut self.rng);
            if self.party_id == 0 {
                self.input_mask_buf.push((r, s));
            } else {
                self.counter_mask_buf.push(s);
            }
        }
        // Party 1's input masks
        for _ in 0..self.batch_size {
            let r = F::rand(&mut self.rng);
            let s = Self::make_share(r, self.mac_key, self.party_id, &mut self.rng);
            if self.party_id == 1 {
                self.input_mask_buf.push((r, s));
            } else {
                self.counter_mask_buf.push(s);
            }
        }
    }
}

/// Create a pair of lazy preprocessing sources from a shared seed.
///
/// Both parties must use the same seed. Each party passes their party_id (0 or 1).
/// The RNG is deterministic, so both parties generate correlated material.
pub fn create_lazy_preprocessing<F: PrimeField>(
    seed: u64,
    party_id: usize,
) -> LazyDummyPreprocessing<F> {
    use ark_ff::UniformRand;
    use rand::SeedableRng;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
    let mac_key = F::rand(&mut rng);
    let mac_key_0 = F::rand(&mut rng);
    let mac_key_1 = mac_key - mac_key_0;

    LazyDummyPreprocessing {
        mac_key,
        mac_key_share: if party_id == 0 { mac_key_0 } else { mac_key_1 },
        party_id,
        rng,
        triple_buf: Vec::new(),
        random_buf: Vec::new(),
        bit_buf: Vec::new(),
        input_mask_buf: Vec::new(),
        counter_mask_buf: Vec::new(),
        batch_size: LAZY_BATCH,
    }
}

impl<F: PrimeField> SpdzPreprocessing<F> for LazyDummyPreprocessing<F> {
    fn mac_key_share(&self) -> F {
        self.mac_key_share
    }

    fn fork(&mut self) -> eyre::Result<Box<dyn SpdzPreprocessing<F>>> {
        use rand::SeedableRng;
        use ark_ff::UniformRand;
        // Create a new RNG by advancing the current one
        let fork_seed = u64::rand(&mut self.rng);
        Ok(Box::new(LazyDummyPreprocessing {
            mac_key: self.mac_key,
            mac_key_share: self.mac_key_share,
            party_id: self.party_id,
            rng: rand_chacha::ChaCha20Rng::seed_from_u64(fork_seed),
            triple_buf: Vec::new(),
            random_buf: Vec::new(),
            bit_buf: Vec::new(),
            input_mask_buf: Vec::new(),
            counter_mask_buf: Vec::new(),
            batch_size: self.batch_size,
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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::{One, UniformRand, Zero};
    use rand::SeedableRng;

    fn test_rng() -> rand_chacha::ChaCha12Rng {
        rand_chacha::ChaCha12Rng::seed_from_u64(42)
    }

    #[test]
    fn test_mac_key_shares_sum_to_key() {
        let mut rng = test_rng();
        let (p0, p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(10, &mut rng);
        // We can't directly check the sum equals the key, but we can verify
        // that triples have correct MACs
        let mac_key = p0.mac_key_share + p1.mac_key_share;

        // Take a triple from each party and verify
        let (mut p0, mut p1) = (p0, p1);
        let (a0, b0, c0) = p0.next_triple().unwrap();
        let (a1, b1, c1) = p1.next_triple().unwrap();

        // Shares reconstruct correctly
        let a = a0.share + a1.share;
        let b = b0.share + b1.share;
        let c = c0.share + c1.share;
        assert_eq!(a * b, c, "Beaver triple: a*b should equal c");

        // MACs are correct
        assert_eq!(a0.mac + a1.mac, mac_key * a);
        assert_eq!(b0.mac + b1.mac, mac_key * b);
        assert_eq!(c0.mac + c1.mac, mac_key * c);
    }

    #[test]
    fn test_shared_random_has_correct_mac() {
        let mut rng = test_rng();
        let (mut p0, mut p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(10, &mut rng);
        let mac_key = p0.mac_key_share + p1.mac_key_share;

        let r0 = p0.next_shared_random().unwrap();
        let r1 = p1.next_shared_random().unwrap();

        let r = r0.share + r1.share;
        assert_eq!(r0.mac + r1.mac, mac_key * r);
    }

    #[test]
    fn test_shared_bit_is_zero_or_one() {
        let mut rng = test_rng();
        let (mut p0, mut p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(100, &mut rng);

        let mut saw_zero = false;
        let mut saw_one = false;
        for _ in 0..100 {
            let b0 = p0.next_shared_bit().unwrap();
            let b1 = p1.next_shared_bit().unwrap();
            let b = b0.share + b1.share;
            assert!(b == Fr::zero() || b == Fr::one(), "Bit should be 0 or 1");
            if b == Fr::zero() {
                saw_zero = true;
            } else {
                saw_one = true;
            }
        }
        assert!(saw_zero && saw_one, "Should see both 0 and 1 bits");
    }

    #[test]
    fn test_input_masks_consistent() {
        let mut rng = test_rng();
        let (mut p0, mut p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(10, &mut rng);
        let mac_key = p0.mac_key_share + p1.mac_key_share;

        // Party 0's input mask: p0 knows cleartext r, both hold shares
        let (r_clear, r0_share) = p0.next_input_mask().unwrap();
        let r1_share = p1.next_counterparty_input_mask().unwrap();

        assert_eq!(r0_share.share + r1_share.share, r_clear);
        assert_eq!(r0_share.mac + r1_share.mac, mac_key * r_clear);
    }

    #[test]
    fn test_exhaustion_error() {
        let (mut p0, _) = generate_dummy_preprocessing_with_rng::<Fr, _>(1, &mut test_rng());
        assert!(p0.next_triple().is_ok());
        assert!(p0.next_triple().is_err());
    }
}
