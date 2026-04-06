//! MAC Verification for SPDZ
//!
//! Implements the commitment-based MAC checking protocol from
//! "A Pragmatic Introduction to Secure Multi-Party Computation" (Section 6.6.2).
//!
//! Protocol for authenticated open:
//! 1. Both parties open the underlying value (exchange share components)
//! 2. Each party computes sigma_i = mac_key_share_i * opened_value - mac_share_i
//! 3. Each party commits to sigma_i: commitment_i = H(sigma_i || blinder_i)
//! 4. Exchange commitments (binding before reveal)
//! 5. Exchange sigma values and blinders
//! 6. Verify: peer's commitment opens correctly AND sigma_0 + sigma_1 == 0

use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use mpc_net::Network;
use sha3::{Digest, Sha3_256};

use crate::network::SpdzNetworkExt;
use crate::types::SpdzPrimeFieldShare;

/// Error indicating MAC verification failed — a party may have cheated.
#[derive(Debug, Clone)]
pub struct MacCheckError;

impl std::fmt::Display for MacCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SPDZ MAC check failed — possible cheating detected")
    }
}

impl std::error::Error for MacCheckError {}

/// Hash commitment: H(values || blinder)
fn compute_commitment<F: PrimeField>(values: &[F], blinder: F) -> F {
    let mut hasher = Sha3_256::new();

    // Hash each value
    for v in values {
        let mut buf = Vec::new();
        v.serialize_uncompressed(&mut buf).expect("serialization failed");
        hasher.update(&buf);
    }

    // Hash the blinder
    let mut buf = Vec::new();
    blinder.serialize_uncompressed(&mut buf).expect("serialization failed");
    hasher.update(&buf);

    // Squeeze and convert to field element
    let hash_bytes = hasher.finalize();
    F::from_be_bytes_mod_order(&hash_bytes)
}

/// Verify a hash commitment opens correctly.
fn verify_commitment<F: PrimeField>(values: &[F], blinder: F, commitment: F) -> bool {
    compute_commitment(values, blinder) == commitment
}

/// Open a single shared value with MAC verification.
///
/// Returns the opened value if MAC check passes, or `MacCheckError` if
/// verification fails (indicating the other party may have cheated).
pub fn open_authenticated<F: PrimeField, N: Network>(
    share: &SpdzPrimeFieldShare<F>,
    mac_key_share: F,
    net: &N,
) -> eyre::Result<F> {
    let results = open_authenticated_many(&[*share], mac_key_share, net)?;
    Ok(results[0])
}

/// Open multiple shared values with MAC verification.
///
/// This is more efficient than opening one at a time because the
/// commitment and MAC check are batched.
pub fn open_authenticated_many<F: PrimeField, N: Network>(
    shares: &[SpdzPrimeFieldShare<F>],
    mac_key_share: F,
    net: &N,
) -> eyre::Result<Vec<F>> {
    let n = shares.len();
    if n == 0 {
        return Ok(vec![]);
    }

    // Step 1: Open underlying values (exchange share components)
    let my_shares: Vec<F> = shares.iter().map(|s| s.share).collect();
    let other_shares: Vec<F> = net.exchange_many(&my_shares)?;
    let opened_values: Vec<F> = my_shares
        .iter()
        .zip(other_shares.iter())
        .map(|(a, b)| *a + *b)
        .collect();

    // Step 2: Compute MAC check values
    // sigma_i = mac_key_share * opened_value - mac_share
    // If shares are correct: sigma_0 + sigma_1 = alpha * v - (mac_0 + mac_1) = 0
    let sigmas: Vec<F> = shares
        .iter()
        .zip(opened_values.iter())
        .map(|(share, value)| mac_key_share * value - share.mac)
        .collect();

    // Step 3: Commit to sigma values
    let mut rng = rand::thread_rng();
    let blinder: F = F::rand(&mut rng);
    let my_commitment = compute_commitment(&sigmas, blinder);

    // Step 4: Exchange commitments (must be binding before revealing sigma)
    let peer_commitment: F = net.exchange(my_commitment)?;

    // Step 5: Exchange sigma values and blinders
    // Send sigmas as a flat vector, then the blinder
    let mut my_reveal = sigmas.clone();
    my_reveal.push(blinder);
    let peer_reveal: Vec<F> = net.exchange_many(&my_reveal)?;

    let (peer_sigmas, peer_blinder_slice) = peer_reveal.split_at(n);
    let peer_blinder = peer_blinder_slice[0];

    // Step 6: Verify peer's commitment opens correctly
    if !verify_commitment(peer_sigmas, peer_blinder, peer_commitment) {
        eyre::bail!(MacCheckError);
    }

    // Step 7: Verify sigma_0 + sigma_1 == 0 for each value
    for i in 0..n {
        if sigmas[i] + peer_sigmas[i] != F::zero() {
            eyre::bail!(MacCheckError);
        }
    }

    Ok(opened_values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::preprocessing::{generate_dummy_preprocessing_with_rng, SpdzPreprocessing};
    use crate::types::share_field_element;
    use crate::SpdzState;
    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use mpc_net::local::LocalNetwork;
    use rand::SeedableRng;

    fn run_two_party<F0, F1, R0, R1>(f0: F0, f1: F1) -> (R0, R1)
    where
        F0: FnOnce(&LocalNetwork) -> R0 + Send + 'static,
        F1: FnOnce(&LocalNetwork) -> R1 + Send + 'static,
        R0: Send + 'static,
        R1: Send + 'static,
    {
        let mut nets = LocalNetwork::new(2).into_iter();
        let net0 = nets.next().unwrap();
        let net1 = nets.next().unwrap();

        let h0 = std::thread::spawn(move || f0(&net0));
        let h1 = std::thread::spawn(move || f1(&net1));

        (h0.join().unwrap(), h1.join().unwrap())
    }

    #[test]
    fn test_authenticated_open_honest() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
        let (p0, p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(10, &mut rng);
        let mac_key = p0.mac_key_share() + p1.mac_key_share();
        let mac_key_0 = p0.mac_key_share();
        let mac_key_1 = p1.mac_key_share();

        let val = Fr::rand(&mut rng);
        let [s0, s1] = share_field_element(val, mac_key, &mut rng);

        let (r0, r1) = run_two_party(
            move |net| open_authenticated(&s0, mac_key_0, net).unwrap(),
            move |net| open_authenticated(&s1, mac_key_1, net).unwrap(),
        );

        assert_eq!(r0, val);
        assert_eq!(r1, val);
    }

    #[test]
    fn test_authenticated_open_batch() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
        let (p0, p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(10, &mut rng);
        let mac_key = p0.mac_key_share() + p1.mac_key_share();
        let mac_key_0 = p0.mac_key_share();
        let mac_key_1 = p1.mac_key_share();

        let vals: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut rng)).collect();
        let mut shares_0 = Vec::new();
        let mut shares_1 = Vec::new();
        for &v in &vals {
            let [s0, s1] = share_field_element(v, mac_key, &mut rng);
            shares_0.push(s0);
            shares_1.push(s1);
        }

        let (r0, r1) = run_two_party(
            move |net| open_authenticated_many(&shares_0, mac_key_0, net).unwrap(),
            move |net| open_authenticated_many(&shares_1, mac_key_1, net).unwrap(),
        );

        assert_eq!(r0, vals);
        assert_eq!(r1, vals);
    }

    #[test]
    fn test_authenticated_open_detects_corrupted_share() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
        let (p0, p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(10, &mut rng);
        let mac_key = p0.mac_key_share() + p1.mac_key_share();
        let mac_key_0 = p0.mac_key_share();
        let mac_key_1 = p1.mac_key_share();

        let val = Fr::rand(&mut rng);
        let [mut s0, s1] = share_field_element(val, mac_key, &mut rng);

        // Corrupt party 0's share (simulate cheating)
        s0.share += Fr::from(1u64);

        let (r0, r1) = run_two_party(
            move |net| open_authenticated(&s0, mac_key_0, net),
            move |net| open_authenticated(&s1, mac_key_1, net),
        );

        // At least one party should detect the corruption
        assert!(
            r0.is_err() || r1.is_err(),
            "MAC check should detect corrupted share"
        );
    }

    #[test]
    fn test_authenticated_open_detects_corrupted_mac() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
        let (p0, p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(10, &mut rng);
        let mac_key = p0.mac_key_share() + p1.mac_key_share();
        let mac_key_0 = p0.mac_key_share();
        let mac_key_1 = p1.mac_key_share();

        let val = Fr::rand(&mut rng);
        let [mut s0, s1] = share_field_element(val, mac_key, &mut rng);

        // Corrupt party 0's MAC (simulate cheating)
        s0.mac += Fr::from(1u64);

        let (r0, r1) = run_two_party(
            move |net| open_authenticated(&s0, mac_key_0, net),
            move |net| open_authenticated(&s1, mac_key_1, net),
        );

        assert!(
            r0.is_err() || r1.is_err(),
            "MAC check should detect corrupted MAC"
        );
    }
}
