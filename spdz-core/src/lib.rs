pub mod arithmetic;
pub mod gadgets;
pub mod mac;
pub mod network;
pub mod ot;
pub mod preprocessing;
pub mod types;

pub use types::{SpdzPointShare, SpdzPrimeFieldShare};

use ark_ff::PrimeField;
use mpc_core::MpcState;

use crate::preprocessing::SpdzPreprocessing;

/// SPDZ party identifier that carries the MAC key share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpdzPartyID<F: PrimeField> {
    pub id: usize,
    pub mac_key_share: F,
}

/// SPDZ protocol state for one party.
pub struct SpdzState<F: PrimeField> {
    pub id: usize,
    pub mac_key_share: F,
    pub preprocessing: Box<dyn SpdzPreprocessing<F>>,
    pub beaver_buffer: Option<arithmetic::BeaverBuffer<F>>,
    /// Whether to verify MACs on open (default: true).
    /// Set to false for semi-honest mode (faster, no cheating detection).
    pub verify_macs: bool,
    /// Raw pointer to the network, used by local_mul_vec for Beaver multiplication.
    /// Safety: set via `set_network` and valid for the duration of the proving call.
    net_ptr: Option<(*const u8, fn(*const u8, &[SpdzPrimeFieldShare<F>], &[SpdzPrimeFieldShare<F>], &mut Box<dyn SpdzPreprocessing<F>>, F, usize) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>>)>,
}

// Safety: SpdzState is used single-threaded within each party's thread.
unsafe impl<F: PrimeField> Send for SpdzState<F> {}

impl<F: PrimeField> SpdzState<F> {
    pub fn new(id: usize, preprocessing: Box<dyn SpdzPreprocessing<F>>) -> Self {
        assert!(id < 2, "SPDZ is a 2-party protocol, party ID must be 0 or 1");
        let mac_key_share = preprocessing.mac_key_share();
        Self { id, mac_key_share, preprocessing, beaver_buffer: None, verify_macs: true, net_ptr: None }
    }

    /// Create a new SPDZ state with MAC verification disabled (semi-honest mode).
    pub fn new_semi_honest(id: usize, preprocessing: Box<dyn SpdzPreprocessing<F>>) -> Self {
        let mut state = Self::new(id, preprocessing);
        state.verify_macs = false;
        state
    }

    /// Store a network reference for use by `local_mul_vec`.
    /// The network must remain valid for the lifetime of this state.
    pub fn set_network<N: mpc_net::Network>(&mut self, net: &N) {
        fn do_mul<F2: PrimeField, N2: mpc_net::Network>(
            ptr: *const u8,
            a: &[SpdzPrimeFieldShare<F2>],
            b: &[SpdzPrimeFieldShare<F2>],
            preprocessing: &mut Box<dyn SpdzPreprocessing<F2>>,
            mac_key_share: F2,
            party_id: usize,
        ) -> eyre::Result<Vec<SpdzPrimeFieldShare<F2>>> {
            let net = unsafe { &*(ptr as *const N2) };
            // Inline Beaver multiplication to avoid borrowing SpdzState
            let n = a.len();
            assert_eq!(n, b.len());
            if n == 0 { return Ok(vec![]); }
            let (a_trip, b_trip, c_trip) = preprocessing.next_triple_batch(n)?;
            let mut eps_shares = Vec::with_capacity(n);
            let mut del_shares = Vec::with_capacity(n);
            for i in 0..n {
                eps_shares.push(a[i] - a_trip[i]);
                del_shares.push(b[i] - b_trip[i]);
            }
            let mut to_open = Vec::with_capacity(2 * n);
            to_open.extend_from_slice(&eps_shares);
            to_open.extend_from_slice(&del_shares);
            let opened = crate::arithmetic::open_many_unchecked(&to_open, net)?;
            let (epsilons, deltas) = opened.split_at(n);
            let mut results = Vec::with_capacity(n);
            for i in 0..n {
                let eps = epsilons[i];
                let del = deltas[i];
                let mut z = c_trip[i];
                z += b_trip[i] * eps;
                z += a_trip[i] * del;
                z = crate::arithmetic::add_public(z, eps * del, mac_key_share, party_id);
                results.push(z);
            }
            Ok(results)
        }

        self.net_ptr = Some((
            net as *const N as *const u8,
            do_mul::<F, N>,
        ));
    }

    /// Run Beaver multiplication using the stored network. Panics if network not set.
    pub fn mul_via_net(
        &mut self,
        a: &[SpdzPrimeFieldShare<F>],
        b: &[SpdzPrimeFieldShare<F>],
    ) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
        let (ptr, func) = self.net_ptr.expect("Network not set — call set_network before proving");
        (func)(ptr, a, b, &mut self.preprocessing, self.mac_key_share, self.id)
    }

    /// Exchange field elements via the stored network for reshare.
    pub fn exchange_via_net(&self, data: &[F]) -> eyre::Result<Vec<F>> {
        // We need the network for exchange too. Store a separate exchange function.
        // For now, use the net_ptr with a specialized function.
        panic!("exchange_via_net: use the network parameter from reshare instead")
    }

    pub fn other_id(&self) -> usize { 1 - self.id }
}

impl<F: PrimeField> MpcState for SpdzState<F> {
    type PartyID = SpdzPartyID<F>;

    fn id(&self) -> Self::PartyID {
        SpdzPartyID { id: self.id, mac_key_share: self.mac_key_share }
    }

    fn fork(&mut self, _n: usize) -> eyre::Result<Self> {
        let forked_prep = self.preprocessing.fork()?;
        Ok(Self {
            id: self.id,
            mac_key_share: self.mac_key_share,
            preprocessing: forked_prep,
            beaver_buffer: None,
            verify_macs: self.verify_macs,
            net_ptr: self.net_ptr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::preprocessing::generate_dummy_preprocessing_with_rng;
    use ark_bn254::Fr;
    use rand::SeedableRng;

    #[test]
    fn test_spdz_state_creation() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
        let (p0, p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(10, &mut rng);

        let state0 = SpdzState::new(0, Box::new(p0));
        let state1 = SpdzState::new(1, Box::new(p1));

        assert_eq!(state0.id().id, 0);
        assert_eq!(state1.id().id, 1);
        assert_eq!(state0.other_id(), 1);
        assert_eq!(state1.other_id(), 0);
        assert_eq!(state0.id().mac_key_share, state0.mac_key_share);
        assert_eq!(state1.id().mac_key_share, state1.mac_key_share);
    }

    #[test]
    #[should_panic(expected = "SPDZ is a 2-party protocol")]
    fn test_invalid_party_id() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
        let (p0, _) = generate_dummy_preprocessing_with_rng::<Fr, _>(10, &mut rng);
        let _ = SpdzState::new(2, Box::new(p0));
    }
}
