//! SPDZ Arithmetic Operations
//!
//! Core MPC operations for 2-party SPDZ: addition with public values,
//! Beaver triple multiplication, opening (reconstruction), inversion, etc.

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use mpc_net::Network;

use crate::network::SpdzNetworkExt;
use crate::types::{SpdzPointShare, SpdzPrimeFieldShare};
use crate::SpdzState;

// ────────────────────────── Public Value Operations ──────────────────────────

/// Add a public value to a SPDZ share.
///
/// Only party 0 adds the value to their share component.
/// Both parties add `mac_key_share * public` to their MAC component.
pub fn add_public<F: PrimeField>(
    shared: SpdzPrimeFieldShare<F>,
    public: F,
    mac_key_share: F,
    party_id: usize,
) -> SpdzPrimeFieldShare<F> {
    let share = if party_id == 0 {
        shared.share + public
    } else {
        shared.share
    };
    let mac = shared.mac + mac_key_share * public;
    SpdzPrimeFieldShare::new(share, mac)
}

/// Subtract a public value from a SPDZ share.
pub fn sub_public<F: PrimeField>(
    shared: SpdzPrimeFieldShare<F>,
    public: F,
    mac_key_share: F,
    party_id: usize,
) -> SpdzPrimeFieldShare<F> {
    add_public(shared, -public, mac_key_share, party_id)
}

// ────────────────────────── Open (Reconstruct) ──────────────────────────

/// Open a single shared value with optional MAC verification.
///
/// If `mac_key_share` is `Some`, performs commitment-based MAC checking
/// (malicious security). If `None`, skips MAC check (semi-honest mode).
pub fn open<F: PrimeField, N: Network>(
    share: &SpdzPrimeFieldShare<F>,
    net: &N,
    mac_key_share: Option<F>,
) -> eyre::Result<F> {
    match mac_key_share {
        Some(mk) => crate::mac::open_authenticated(share, mk, net),
        None => open_unchecked(share, net),
    }
}

/// Open multiple shared values with optional MAC verification.
pub fn open_many<F: PrimeField, N: Network>(
    shares: &[SpdzPrimeFieldShare<F>],
    net: &N,
    mac_key_share: Option<F>,
) -> eyre::Result<Vec<F>> {
    match mac_key_share {
        Some(mk) => crate::mac::open_authenticated_many(shares, mk, net),
        None => open_many_unchecked(shares, net),
    }
}

/// Open without MAC verification (semi-honest mode).
pub fn open_unchecked<F: PrimeField, N: Network>(
    share: &SpdzPrimeFieldShare<F>,
    net: &N,
) -> eyre::Result<F> {
    let other_share: F = net.exchange(share.share)?;
    Ok(share.share + other_share)
}

/// Open many without MAC verification (semi-honest mode).
pub fn open_many_unchecked<F: PrimeField, N: Network>(
    shares: &[SpdzPrimeFieldShare<F>],
    net: &N,
) -> eyre::Result<Vec<F>> {
    let my_shares: Vec<F> = shares.iter().map(|s| s.share).collect();
    let other_shares: Vec<F> = net.exchange_many(&my_shares)?;
    Ok(my_shares
        .iter()
        .zip(other_shares.iter())
        .map(|(a, b)| *a + *b)
        .collect())
}

/// Open a point share (no MAC verification for points yet).
pub fn open_point<C: CurveGroup, N: Network>(
    share: &SpdzPointShare<C>,
    net: &N,
) -> eyre::Result<C> {
    let other_share: C = net.exchange(share.share)?;
    Ok(share.share + other_share)
}

// ────────────────────────── Beaver Multiplication ──────────────────────────

/// Multiply two SPDZ shares using a Beaver triple.
///
/// Protocol:
/// 1. Get triple `([a], [b], [c])` where `a * b = c`
/// 2. Compute `[epsilon] = [x] - [a]` and `[delta] = [y] - [b]`
/// 3. Open epsilon and delta (1 round of communication)
/// 4. Result `[z] = [c] + epsilon * [b] + delta * [a] + epsilon * delta`
pub fn mul<F: PrimeField, N: Network>(
    x: &SpdzPrimeFieldShare<F>,
    y: &SpdzPrimeFieldShare<F>,
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<SpdzPrimeFieldShare<F>> {
    let (a, b, c) = state.preprocessing.next_triple()?;

    let epsilon_share = *x - a;
    let delta_share = *y - b;

    // Open both epsilon and delta in ONE round trip (not two!)
    let opened = open_many_unchecked(&[epsilon_share, delta_share], net)?;
    let epsilon = opened[0];
    let delta = opened[1];

    // [z] = [c] + epsilon * [b] + delta * [a] + epsilon * delta (public term)
    let mut z = c;
    z += b * epsilon;
    z += a * delta;
    z = add_public(z, epsilon * delta, state.mac_key_share, state.id);

    Ok(z)
}

/// Multiply many pairs of SPDZ shares using Beaver triples.
/// All opens are batched into a single communication round.
pub fn mul_many<F: PrimeField, N: Network>(
    xs: &[SpdzPrimeFieldShare<F>],
    ys: &[SpdzPrimeFieldShare<F>],
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
    assert_eq!(xs.len(), ys.len());
    let n = xs.len();
    if n == 0 {
        return Ok(vec![]);
    }

    let (a_vec, b_vec, c_vec) = state.preprocessing.next_triple_batch(n)?;

    // Compute masked differences
    let mut eps_shares = Vec::with_capacity(n);
    let mut del_shares = Vec::with_capacity(n);
    for i in 0..n {
        eps_shares.push(xs[i] - a_vec[i]);
        del_shares.push(ys[i] - b_vec[i]);
    }

    // Batch open: concatenate eps and del, open in one round
    let mut to_open: Vec<SpdzPrimeFieldShare<F>> = Vec::with_capacity(2 * n);
    to_open.extend_from_slice(&eps_shares);
    to_open.extend_from_slice(&del_shares);
    // Open masked values — random, no MAC check needed
    let opened = open_many_unchecked(&to_open, net)?;
    let (epsilons, deltas) = opened.split_at(n);

    // Compute results
    let mut results = Vec::with_capacity(n);
    for i in 0..n {
        let eps = epsilons[i];
        let del = deltas[i];
        let mut z = c_vec[i];
        z += b_vec[i] * eps;
        z += a_vec[i] * del;
        z = add_public(z, eps * del, state.mac_key_share, state.id);
        results.push(z);
    }

    Ok(results)
}

/// The "local" part of multiplication — computes `a_i.share * b_i.share`
/// and prepares Beaver masks for the reshare step.
///
/// Returns `(local_products, buffered_state)` where `buffered_state`
/// contains the Beaver triple data needed by `reshare`.
///
/// This matches co-snarks' `local_mul_vec` / `reshare` split pattern.
pub fn local_mul_vec<F: PrimeField>(
    a: &[SpdzPrimeFieldShare<F>],
    b: &[SpdzPrimeFieldShare<F>],
    state: &mut SpdzState<F>,
) -> eyre::Result<(Vec<F>, BeaverBuffer<F>)> {
    let n = a.len();
    assert_eq!(n, b.len());

    let (a_triples, b_triples, c_triples) = state.preprocessing.next_triple_batch(n)?;

    // Compute masked values (epsilon = x - a, delta = y - b)
    let mut eps_shares = Vec::with_capacity(n);
    let mut del_shares = Vec::with_capacity(n);
    let mut local_products = Vec::with_capacity(n);

    for i in 0..n {
        eps_shares.push(a[i] - a_triples[i]);
        del_shares.push(b[i] - b_triples[i]);
        // The "local product" that co-snarks expects is just share * share
        local_products.push(a[i].share * b[i].share);
    }

    Ok((
        local_products,
        BeaverBuffer {
            eps_shares,
            del_shares,
            a_triples,
            b_triples,
            c_triples,
        },
    ))
}

/// Buffered Beaver triple state from `local_mul_vec`, consumed by `reshare`.
pub struct BeaverBuffer<F: PrimeField> {
    pub(crate) eps_shares: Vec<SpdzPrimeFieldShare<F>>,
    pub(crate) del_shares: Vec<SpdzPrimeFieldShare<F>>,
    pub(crate) a_triples: Vec<SpdzPrimeFieldShare<F>>,
    pub(crate) b_triples: Vec<SpdzPrimeFieldShare<F>>,
    pub(crate) c_triples: Vec<SpdzPrimeFieldShare<F>>,
}

impl<F: PrimeField> BeaverBuffer<F> {
    /// Create a new BeaverBuffer.
    pub fn new(
        eps_shares: Vec<SpdzPrimeFieldShare<F>>,
        del_shares: Vec<SpdzPrimeFieldShare<F>>,
        a_triples: Vec<SpdzPrimeFieldShare<F>>,
        b_triples: Vec<SpdzPrimeFieldShare<F>>,
        c_triples: Vec<SpdzPrimeFieldShare<F>>,
    ) -> Self {
        Self { eps_shares, del_shares, a_triples, b_triples, c_triples }
    }

    /// Number of buffered triples.
    pub fn len(&self) -> usize {
        self.eps_shares.len()
    }
}

/// The "reshare" step — exchanges Beaver masks and produces final SPDZ shares.
///
/// Consumes the `BeaverBuffer` from `local_mul_vec`.
pub fn reshare<F: PrimeField, N: Network>(
    buffer: BeaverBuffer<F>,
    net: &N,
    state: &SpdzState<F>,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
    let n = buffer.eps_shares.len();

    // Batch open epsilon and delta
    let mut to_open = Vec::with_capacity(2 * n);
    to_open.extend_from_slice(&buffer.eps_shares);
    to_open.extend_from_slice(&buffer.del_shares);
    let opened = open_many_unchecked(&to_open, net)?;
    let (epsilons, deltas) = opened.split_at(n);

    let mut results = Vec::with_capacity(n);
    for i in 0..n {
        let eps = epsilons[i];
        let del = deltas[i];
        let mut z = buffer.c_triples[i];
        z += buffer.b_triples[i] * eps;
        z += buffer.a_triples[i] * del;
        z = add_public(z, eps * del, state.mac_key_share, state.id);
        results.push(z);
    }

    Ok(results)
}

// ────────────────────────── Inversion ──────────────────────────

/// Invert a shared value: compute `[x^{-1}]` from `[x]`.
///
/// Protocol: mask with random `[r]`, open `x*r`, invert in clear,
/// scale `[r]` by the inverse.
pub fn inv<F: PrimeField, N: Network>(
    x: &SpdzPrimeFieldShare<F>,
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<SpdzPrimeFieldShare<F>> {
    let r = state.preprocessing.next_shared_random()?;
    let xr = mul(x, &r, net, state)?;
    // Opening a masked value — random, no MAC check needed
    let xr_open = open_unchecked(&xr, net)?;

    if xr_open.is_zero() {
        eyre::bail!("Cannot invert zero");
    }

    let xr_inv = xr_open.inverse().expect("nonzero");
    Ok(r * xr_inv)
}

/// Invert multiple shared values.
pub fn inv_many<F: PrimeField, N: Network>(
    xs: &[SpdzPrimeFieldShare<F>],
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<Vec<SpdzPrimeFieldShare<F>>> {
    let n = xs.len();
    let mut rs = Vec::with_capacity(n);
    for _ in 0..n {
        rs.push(state.preprocessing.next_shared_random()?);
    }

    let xrs = mul_many(xs, &rs, net, state)?;
    // Opening masked values — random, no MAC check needed
    let xr_opens = open_many_unchecked(&xrs, net)?;

    let mut results = Vec::with_capacity(n);
    for i in 0..n {
        if xr_opens[i].is_zero() {
            eyre::bail!("Cannot invert zero (element {})", i);
        }
        let xr_inv = xr_opens[i].inverse().expect("nonzero");
        results.push(rs[i] * xr_inv);
    }

    Ok(results)
}

// ────────────────────────── Input Sharing ──────────────────────────

/// Share a private input from one party.
///
/// The `sender` party has the cleartext `value` and uses an input mask `(r, [r])`
/// to share it. They broadcast `value - r` and both parties compute
/// `[value] = [r] + (value - r)`.
pub fn share_input<F: PrimeField, N: Network>(
    value: Option<F>,
    sender: usize,
    net: &N,
    state: &mut SpdzState<F>,
) -> eyre::Result<SpdzPrimeFieldShare<F>> {
    if state.id == sender {
        let val = value.ok_or_else(|| eyre::eyre!("Sender must provide a value"))?;
        let (r_clear, r_share) = state.preprocessing.next_input_mask()?;
        let masked = val - r_clear;
        // Broadcast masked value
        net.send_to_other(masked)?;
        // [value] = [r] + (value - r)
        Ok(add_public(r_share, masked, state.mac_key_share, state.id))
    } else {
        let r_share = state.preprocessing.next_counterparty_input_mask()?;
        // Receive masked value
        let masked: F = net.recv_from_other()?;
        // [value] = [r] + (value - r)
        Ok(add_public(r_share, masked, state.mac_key_share, state.id))
    }
}

// ────────────────────────── MSM on Point Shares ──────────────────────────

/// Multi-scalar multiplication with public points and shared scalars.
///
/// Computes `sum_i(points[i] * scalars[i])` where points are public
/// and scalars are SPDZ-shared. The result is a point share.
///
/// This is purely local — no communication needed.
pub fn msm_public_points<C: CurveGroup>(
    points: &[C::Affine],
    scalars: &[SpdzPrimeFieldShare<C::ScalarField>],
) -> SpdzPointShare<C> {
    let shares: Vec<C::ScalarField> = scalars.iter().map(|s| s.share).collect();
    let macs: Vec<C::ScalarField> = scalars.iter().map(|s| s.mac).collect();

    let share = C::msm_unchecked(points, &shares);
    let mac = C::msm_unchecked(points, &macs);

    SpdzPointShare::new(share, mac)
}

// ────────────────────────── FFT / IFFT ──────────────────────────

/// Compute FFT of SPDZ shares.
///
/// Applies FFT independently to the share and MAC components.
/// This is purely local — no communication needed.
pub fn fft<F: PrimeField>(
    data: &[SpdzPrimeFieldShare<F>],
    domain: &impl ark_poly::EvaluationDomain<F>,
) -> Vec<SpdzPrimeFieldShare<F>> {
    let shares: Vec<F> = data.iter().map(|s| s.share).collect();
    let macs: Vec<F> = data.iter().map(|s| s.mac).collect();

    let fft_shares = domain.fft(&shares);
    let fft_macs = domain.fft(&macs);

    fft_shares
        .into_iter()
        .zip(fft_macs)
        .map(|(s, m)| SpdzPrimeFieldShare::new(s, m))
        .collect()
}

/// Compute inverse FFT of SPDZ shares.
pub fn ifft<F: PrimeField>(
    data: &[SpdzPrimeFieldShare<F>],
    domain: &impl ark_poly::EvaluationDomain<F>,
) -> Vec<SpdzPrimeFieldShare<F>> {
    let shares: Vec<F> = data.iter().map(|s| s.share).collect();
    let macs: Vec<F> = data.iter().map(|s| s.mac).collect();

    let ifft_shares = domain.ifft(&shares);
    let ifft_macs = domain.ifft(&macs);

    ifft_shares
        .into_iter()
        .zip(ifft_macs)
        .map(|(s, m)| SpdzPrimeFieldShare::new(s, m))
        .collect()
}

// ────────────────────────── Polynomial Evaluation ──────────────────────────

/// Evaluate a polynomial (given as shared coefficients) at a public point.
///
/// Uses Horner's method. Purely local — no communication needed.
pub fn eval_poly<F: PrimeField>(
    coeffs: &[SpdzPrimeFieldShare<F>],
    point: F,
) -> SpdzPrimeFieldShare<F> {
    if coeffs.is_empty() {
        return SpdzPrimeFieldShare::zero_share();
    }
    let mut result = *coeffs.last().unwrap();
    for c in coeffs.iter().rev().skip(1) {
        result = result * point; // mul by public scalar
        result += *c;
    }
    result
}

// ────────────────────────── Scalar-Point Multiplication ──────────────────────────

/// Multiply a public curve point by a shared scalar.
/// Returns a point share. Purely local.
pub fn scalar_mul_public_point<C: CurveGroup>(
    point: &C,
    scalar: &SpdzPrimeFieldShare<C::ScalarField>,
) -> SpdzPointShare<C> {
    SpdzPointShare::new(*point * scalar.share, *point * scalar.mac)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::preprocessing::{SpdzPreprocessing, generate_dummy_preprocessing_with_rng};
    use crate::types::combine_field_element;
    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use mpc_net::local::LocalNetwork;
    use rand::SeedableRng;
    use std::thread;

    fn run_two_party<F0, F1, R0, R1>(f0: F0, f1: F1) -> (R0, R1)
    where
        F0: FnOnce(&LocalNetwork) -> R0 + Send + 'static,
        F1: FnOnce(&LocalNetwork) -> R1 + Send + 'static,
        R0: Send + 'static,
        R1: Send + 'static,
    {
        let networks = LocalNetwork::new(2);
        let mut nets = networks.into_iter();
        let net0 = nets.next().unwrap();
        let net1 = nets.next().unwrap();

        let h0 = thread::spawn(move || f0(&net0));
        let h1 = thread::spawn(move || f1(&net1));

        (h0.join().unwrap(), h1.join().unwrap())
    }

    #[test]
    fn test_open_with_mac_check() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
        let (p0, p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(10, &mut rng);
        let mac_key_0 = p0.mac_key_share();
        let mac_key_1 = p1.mac_key_share();
        let mac_key = mac_key_0 + mac_key_1;
        let val = Fr::rand(&mut rng);
        let [s0, s1] = crate::types::share_field_element(val, mac_key, &mut rng);

        // Default: MAC verification enabled
        let (r0, r1) = run_two_party(
            move |net| open(&s0, net, Some(mac_key_0)).unwrap(),
            move |net| open(&s1, net, Some(mac_key_1)).unwrap(),
        );
        assert_eq!(r0, val);
        assert_eq!(r1, val);
    }

    #[test]
    fn test_open_unchecked() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
        let (p0, p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(10, &mut rng);
        let mac_key = p0.mac_key_share() + p1.mac_key_share();
        let val = Fr::rand(&mut rng);
        let [s0, s1] = crate::types::share_field_element(val, mac_key, &mut rng);

        // Semi-honest: no MAC verification
        let (r0, r1) = run_two_party(
            move |net| open(&s0, net, None).unwrap(),
            move |net| open(&s1, net, None).unwrap(),
        );
        assert_eq!(r0, val);
        assert_eq!(r1, val);
    }

    #[test]
    fn test_beaver_mul() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
        let (p0, p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(100, &mut rng);
        let mac_key = p0.mac_key_share() + p1.mac_key_share();

        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);
        let [a0, a1] = crate::types::share_field_element(a, mac_key, &mut rng);
        let [b0, b1] = crate::types::share_field_element(b, mac_key, &mut rng);

        let (c0, c1) = run_two_party(
            move |net| {
                let mut state = SpdzState::new(0, Box::new(p0));
                let result = mul(&a0, &b0, net, &mut state).unwrap();
                result
            },
            move |net| {
                let mut state = SpdzState::new(1, Box::new(p1));
                let result = mul(&a1, &b1, net, &mut state).unwrap();
                result
            },
        );

        let product = combine_field_element(c0, c1);
        assert_eq!(product, a * b);

        // Verify MAC correctness
        assert_eq!(c0.mac + c1.mac, mac_key * (a * b));
    }

    #[test]
    fn test_mul_many() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
        let (p0, p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(200, &mut rng);
        let mac_key = p0.mac_key_share() + p1.mac_key_share();

        let n = 5;
        let as_plain: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let bs_plain: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

        let mut a0s = Vec::new();
        let mut a1s = Vec::new();
        let mut b0s = Vec::new();
        let mut b1s = Vec::new();
        for i in 0..n {
            let [a0, a1] = crate::types::share_field_element(as_plain[i], mac_key, &mut rng);
            let [b0, b1] = crate::types::share_field_element(bs_plain[i], mac_key, &mut rng);
            a0s.push(a0);
            a1s.push(a1);
            b0s.push(b0);
            b1s.push(b1);
        }

        let (c0s, c1s) = run_two_party(
            move |net| {
                let mut state = SpdzState::new(0, Box::new(p0));
                mul_many(&a0s, &b0s, net, &mut state).unwrap()
            },
            move |net| {
                let mut state = SpdzState::new(1, Box::new(p1));
                mul_many(&a1s, &b1s, net, &mut state).unwrap()
            },
        );

        for i in 0..n {
            let product = combine_field_element(c0s[i], c1s[i]);
            assert_eq!(product, as_plain[i] * bs_plain[i]);
        }
    }

    #[test]
    fn test_inv() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
        let (p0, p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(200, &mut rng);
        let mac_key = p0.mac_key_share() + p1.mac_key_share();

        let a = Fr::rand(&mut rng);
        let [a0, a1] = crate::types::share_field_element(a, mac_key, &mut rng);

        let (inv0, inv1) = run_two_party(
            move |net| {
                let mut state = SpdzState::new(0, Box::new(p0));
                inv(&a0, net, &mut state).unwrap()
            },
            move |net| {
                let mut state = SpdzState::new(1, Box::new(p1));
                inv(&a1, net, &mut state).unwrap()
            },
        );

        let a_inv = combine_field_element(inv0, inv1);
        assert_eq!(a * a_inv, Fr::from(1u64));
    }

    #[test]
    fn test_share_input() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
        let (p0, p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(100, &mut rng);
        let mac_key = p0.mac_key_share() + p1.mac_key_share();

        let secret = Fr::rand(&mut rng);

        let (s0, s1) = run_two_party(
            move |net| {
                let mut state = SpdzState::new(0, Box::new(p0));
                share_input(Some(secret), 0, net, &mut state).unwrap()
            },
            move |net| {
                let mut state = SpdzState::new(1, Box::new(p1));
                share_input(None, 0, net, &mut state).unwrap()
            },
        );

        let reconstructed = combine_field_element(s0, s1);
        assert_eq!(reconstructed, secret);
        assert_eq!(s0.mac + s1.mac, mac_key * secret);
    }

    #[test]
    fn test_add_public() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
        let mac_key = Fr::rand(&mut rng);
        let mac_key_0 = Fr::rand(&mut rng);
        let mac_key_1 = mac_key - mac_key_0;

        let a = Fr::rand(&mut rng);
        let public = Fr::rand(&mut rng);
        let [a0, a1] = crate::types::share_field_element(a, mac_key, &mut rng);

        let c0 = add_public(a0, public, mac_key_0, 0);
        let c1 = add_public(a1, public, mac_key_1, 1);

        assert_eq!(combine_field_element(c0, c1), a + public);
        assert_eq!(c0.mac + c1.mac, mac_key * (a + public));
    }

    #[test]
    fn test_fft_ifft_roundtrip() {
        use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
        let mac_key = Fr::rand(&mut rng);
        let n = 8;
        let domain = Radix2EvaluationDomain::<Fr>::new(n).unwrap();

        // Create shared values
        let vals: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let shares: Vec<SpdzPrimeFieldShare<Fr>> = vals
            .iter()
            .map(|v| {
                let [s, _] = crate::types::share_field_element(*v, mac_key, &mut rng);
                s
            })
            .collect();

        // FFT then IFFT should roundtrip
        let fft_result = fft(&shares, &domain);
        let roundtrip = ifft(&fft_result, &domain);

        for i in 0..n {
            assert_eq!(roundtrip[i].share, shares[i].share);
            assert_eq!(roundtrip[i].mac, shares[i].mac);
        }
    }

    #[test]
    fn test_eval_poly() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
        let mac_key = Fr::rand(&mut rng);

        // Polynomial p(x) = c0 + c1*x + c2*x^2
        let coeffs_plain: Vec<Fr> = (0..3).map(|_| Fr::rand(&mut rng)).collect();
        let point = Fr::rand(&mut rng);

        // Expected result
        let expected = coeffs_plain[0] + coeffs_plain[1] * point + coeffs_plain[2] * point * point;

        // Share coefficients (party 0 shares only)
        let coeffs: Vec<SpdzPrimeFieldShare<Fr>> = coeffs_plain
            .iter()
            .map(|c| {
                let [s, _] = crate::types::share_field_element(*c, mac_key, &mut rng);
                s
            })
            .collect();
        let coeffs_1: Vec<SpdzPrimeFieldShare<Fr>> = coeffs_plain
            .iter()
            .map(|c| {
                // Reconstruct party 1 shares from the same values
                // For this test we just verify party 0's share evaluation
                let [_, s] = crate::types::share_field_element(*c, mac_key, &mut rng);
                s
            })
            .collect();

        let result_0 = eval_poly(&coeffs, point);
        let result_1 = eval_poly(&coeffs_1, point);

        // Note: we can't directly check result_0 + result_1 == expected because
        // we used different rng calls for the two parties. Let's do it properly:
        let mut rng2 = rand_chacha::ChaCha12Rng::seed_from_u64(99);
        let coeffs_pairs: Vec<[SpdzPrimeFieldShare<Fr>; 2]> = coeffs_plain
            .iter()
            .map(|c| crate::types::share_field_element(*c, mac_key, &mut rng2))
            .collect();

        let c0: Vec<_> = coeffs_pairs.iter().map(|[s, _]| *s).collect();
        let c1: Vec<_> = coeffs_pairs.iter().map(|[_, s]| *s).collect();

        let r0 = eval_poly(&c0, point);
        let r1 = eval_poly(&c1, point);

        assert_eq!(r0.share + r1.share, expected);
        assert_eq!(r0.mac + r1.mac, mac_key * expected);
    }
}
