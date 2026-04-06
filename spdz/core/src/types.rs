use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use mpc_core::serde_compat::{ark_de, ark_se};
use serde::{Deserialize, Serialize};

// ────────────────────────────── Field Share ──────────────────────────────

/// SPDZ additive share of a prime field element.
///
/// Each party holds `(share, mac)` where:
///   - `share_0 + share_1 = value`
///   - `mac_0 + mac_1 = alpha * value` (alpha is the global MAC key)
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Hash,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct SpdzPrimeFieldShare<F: PrimeField> {
    /// Additive share of the value
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub share: F,
    /// Additive share of MAC(value) = alpha * value
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub mac: F,
}

impl<F: PrimeField> Default for SpdzPrimeFieldShare<F> {
    fn default() -> Self {
        Self::zero_share()
    }
}

impl<F: PrimeField> SpdzPrimeFieldShare<F> {
    /// Construct from share and mac components.
    pub fn new(share: F, mac: F) -> Self {
        Self { share, mac }
    }

    /// Zero share (both components zero).
    pub fn zero_share() -> Self {
        Self {
            share: F::zero(),
            mac: F::zero(),
        }
    }

    /// Unwrap into (share, mac) tuple.
    pub fn parts(self) -> (F, F) {
        (self.share, self.mac)
    }

    /// Double in place.
    pub fn double_in_place(&mut self) {
        self.share.double_in_place();
        self.mac.double_in_place();
    }

    /// Double.
    pub fn double(&self) -> Self {
        Self {
            share: self.share.double(),
            mac: self.mac.double(),
        }
    }

    /// Promote a public value to a trivial SPDZ share.
    ///
    /// Party 0 holds the value in their share; party 1 holds zero.
    /// Both parties hold `mac_key_share * value` as their MAC component.
    pub fn promote_from_trivial(val: &F, mac_key_share: F, party_id: usize) -> Self {
        let share = if party_id == 0 { *val } else { F::zero() };
        let mac = mac_key_share * val;
        Self { share, mac }
    }
}

// ── Operator impls: all linear ops work component-wise on (share, mac) ──

impl<F: PrimeField> std::ops::Add for SpdzPrimeFieldShare<F> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self {
            share: self.share + rhs.share,
            mac: self.mac + rhs.mac,
        }
    }
}

impl<F: PrimeField> std::ops::Add<&SpdzPrimeFieldShare<F>> for &SpdzPrimeFieldShare<F> {
    type Output = SpdzPrimeFieldShare<F>;
    fn add(self, rhs: &SpdzPrimeFieldShare<F>) -> SpdzPrimeFieldShare<F> {
        SpdzPrimeFieldShare {
            share: self.share + rhs.share,
            mac: self.mac + rhs.mac,
        }
    }
}

impl<F: PrimeField> std::ops::AddAssign for SpdzPrimeFieldShare<F> {
    fn add_assign(&mut self, rhs: Self) {
        self.share += rhs.share;
        self.mac += rhs.mac;
    }
}

impl<F: PrimeField> std::ops::AddAssign<&SpdzPrimeFieldShare<F>> for SpdzPrimeFieldShare<F> {
    fn add_assign(&mut self, rhs: &Self) {
        self.share += rhs.share;
        self.mac += rhs.mac;
    }
}

impl<F: PrimeField> std::ops::Sub for SpdzPrimeFieldShare<F> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self {
            share: self.share - rhs.share,
            mac: self.mac - rhs.mac,
        }
    }
}

impl<F: PrimeField> std::ops::Sub<&SpdzPrimeFieldShare<F>> for &SpdzPrimeFieldShare<F> {
    type Output = SpdzPrimeFieldShare<F>;
    fn sub(self, rhs: &SpdzPrimeFieldShare<F>) -> SpdzPrimeFieldShare<F> {
        SpdzPrimeFieldShare {
            share: self.share - rhs.share,
            mac: self.mac - rhs.mac,
        }
    }
}

impl<F: PrimeField> std::ops::SubAssign for SpdzPrimeFieldShare<F> {
    fn sub_assign(&mut self, rhs: Self) {
        self.share -= rhs.share;
        self.mac -= rhs.mac;
    }
}

impl<F: PrimeField> std::ops::SubAssign<&SpdzPrimeFieldShare<F>> for SpdzPrimeFieldShare<F> {
    fn sub_assign(&mut self, rhs: &Self) {
        self.share -= rhs.share;
        self.mac -= rhs.mac;
    }
}

impl<F: PrimeField> std::ops::Neg for SpdzPrimeFieldShare<F> {
    type Output = Self;
    fn neg(self) -> Self {
        Self {
            share: -self.share,
            mac: -self.mac,
        }
    }
}

/// Scalar multiplication by a public field element.
/// Multiplies both the share and MAC components.
impl<F: PrimeField> std::ops::Mul<F> for SpdzPrimeFieldShare<F> {
    type Output = Self;
    fn mul(self, rhs: F) -> Self {
        Self {
            share: self.share * rhs,
            mac: self.mac * rhs,
        }
    }
}

impl<F: PrimeField> std::ops::Mul<F> for &SpdzPrimeFieldShare<F> {
    type Output = SpdzPrimeFieldShare<F>;
    fn mul(self, rhs: F) -> SpdzPrimeFieldShare<F> {
        SpdzPrimeFieldShare {
            share: self.share * rhs,
            mac: self.mac * rhs,
        }
    }
}

impl<F: PrimeField> std::ops::MulAssign<F> for SpdzPrimeFieldShare<F> {
    fn mul_assign(&mut self, rhs: F) {
        self.share *= rhs;
        self.mac *= rhs;
    }
}

impl<F: PrimeField> ark_ff::Zero for SpdzPrimeFieldShare<F> {
    fn zero() -> Self {
        Self::zero_share()
    }

    fn is_zero(&self) -> bool {
        // Cannot determine if a share is zero without combining all shares.
        // This is only meaningful for the zero_share sentinel value.
        self.share.is_zero() && self.mac.is_zero()
    }
}

// ────────────────────────────── Point Share ──────────────────────────────

/// SPDZ additive share of an elliptic curve point.
///
/// Same structure as field shares: `(share, mac)` where shares sum to the
/// point and MACs sum to `alpha * point` (scalar multiplication).
#[derive(Debug, Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Default, Copy)]
pub struct SpdzPointShare<C: CurveGroup> {
    /// Additive share of the point
    pub share: C,
    /// Additive share of MAC(point) = alpha * point
    pub mac: C,
}

impl<C: CurveGroup> SpdzPointShare<C> {
    /// Construct from share and mac components.
    pub fn new(share: C, mac: C) -> Self {
        Self { share, mac }
    }

    /// Zero share (identity points).
    pub fn zero_share() -> Self {
        Self {
            share: C::zero(),
            mac: C::zero(),
        }
    }

    /// Unwrap into (share, mac) tuple.
    pub fn parts(self) -> (C, C) {
        (self.share, self.mac)
    }
}

impl<C: CurveGroup> std::ops::Add for SpdzPointShare<C> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self {
            share: self.share + rhs.share,
            mac: self.mac + rhs.mac,
        }
    }
}

impl<C: CurveGroup> std::ops::Add<&SpdzPointShare<C>> for &SpdzPointShare<C> {
    type Output = SpdzPointShare<C>;
    fn add(self, rhs: &SpdzPointShare<C>) -> SpdzPointShare<C> {
        SpdzPointShare {
            share: self.share + rhs.share,
            mac: self.mac + rhs.mac,
        }
    }
}

impl<C: CurveGroup> std::ops::AddAssign for SpdzPointShare<C> {
    fn add_assign(&mut self, rhs: Self) {
        self.share += rhs.share;
        self.mac += rhs.mac;
    }
}

impl<C: CurveGroup> std::ops::Sub for SpdzPointShare<C> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self {
            share: self.share - rhs.share,
            mac: self.mac - rhs.mac,
        }
    }
}

impl<C: CurveGroup> std::ops::Neg for SpdzPointShare<C> {
    type Output = Self;
    fn neg(self) -> Self {
        Self {
            share: -self.share,
            mac: -self.mac,
        }
    }
}

// ────────────────────────────── Share/Combine ──────────────────────────────

/// Split a field element into SPDZ shares for 2 parties.
///
/// Returns `[share_0, share_1]` where both carry correct MAC components.
pub fn share_field_element<F: PrimeField, R: rand::Rng + rand::CryptoRng>(
    val: F,
    mac_key: F,
    rng: &mut R,
) -> [SpdzPrimeFieldShare<F>; 2] {
    let share_0: F = F::rand(rng);
    let share_1 = val - share_0;

    let mac = mac_key * val;
    let mac_0: F = F::rand(rng);
    let mac_1 = mac - mac_0;

    [
        SpdzPrimeFieldShare::new(share_0, mac_0),
        SpdzPrimeFieldShare::new(share_1, mac_1),
    ]
}

/// Combine two SPDZ shares to reconstruct the original field element.
pub fn combine_field_element<F: PrimeField>(
    share_0: SpdzPrimeFieldShare<F>,
    share_1: SpdzPrimeFieldShare<F>,
) -> F {
    share_0.share + share_1.share
}

/// Split multiple field elements into SPDZ shares for 2 parties.
pub fn share_field_elements<F: PrimeField, R: rand::Rng + rand::CryptoRng>(
    vals: &[F],
    mac_key: F,
    rng: &mut R,
) -> [Vec<SpdzPrimeFieldShare<F>>; 2] {
    let mut shares_0 = Vec::with_capacity(vals.len());
    let mut shares_1 = Vec::with_capacity(vals.len());
    for val in vals {
        let [s0, s1] = share_field_element(*val, mac_key, rng);
        shares_0.push(s0);
        shares_1.push(s1);
    }
    [shares_0, shares_1]
}

/// Combine vectors of SPDZ shares to reconstruct the original field elements.
pub fn combine_field_elements<F: PrimeField>(
    shares_0: &[SpdzPrimeFieldShare<F>],
    shares_1: &[SpdzPrimeFieldShare<F>],
) -> Vec<F> {
    shares_0
        .iter()
        .zip(shares_1.iter())
        .map(|(s0, s1)| s0.share + s1.share)
        .collect()
}

/// Split a curve point into SPDZ shares for 2 parties.
pub fn share_curve_point<C: CurveGroup, R: rand::Rng + rand::CryptoRng>(
    val: C,
    mac_key: C::ScalarField,
    rng: &mut R,
) -> [SpdzPointShare<C>; 2] {
    let share_0 = C::rand(rng);
    let share_1 = val - share_0;

    let mac = val * mac_key;
    let mac_0 = C::rand(rng);
    let mac_1 = mac - mac_0;

    [
        SpdzPointShare::new(share_0, mac_0),
        SpdzPointShare::new(share_1, mac_1),
    ]
}

/// Combine two SPDZ point shares to reconstruct the original curve point.
pub fn combine_curve_point<C: CurveGroup>(
    share_0: SpdzPointShare<C>,
    share_1: SpdzPointShare<C>,
) -> C {
    share_0.share + share_1.share
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use rand::SeedableRng;

    fn test_rng() -> rand_chacha::ChaCha12Rng {
        rand_chacha::ChaCha12Rng::seed_from_u64(0)
    }

    #[test]
    fn test_share_combine_field_element() {
        let mut rng = test_rng();
        let mac_key = Fr::rand(&mut rng);
        let val = Fr::rand(&mut rng);

        let [s0, s1] = share_field_element(val, mac_key, &mut rng);

        // Shares reconstruct the value
        assert_eq!(combine_field_element(s0, s1), val);

        // MACs are correct: mac_0 + mac_1 = alpha * value
        assert_eq!(s0.mac + s1.mac, mac_key * val);
    }

    #[test]
    fn test_share_combine_batch() {
        let mut rng = test_rng();
        let mac_key = Fr::rand(&mut rng);
        let vals: Vec<Fr> = (0..10).map(|_| Fr::rand(&mut rng)).collect();

        let [s0, s1] = share_field_elements(&vals, mac_key, &mut rng);
        let reconstructed = combine_field_elements(&s0, &s1);

        assert_eq!(reconstructed, vals);
    }

    #[test]
    fn test_add_shares() {
        let mut rng = test_rng();
        let mac_key = Fr::rand(&mut rng);
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);

        let [a0, a1] = share_field_element(a, mac_key, &mut rng);
        let [b0, b1] = share_field_element(b, mac_key, &mut rng);

        let c0 = a0 + b0;
        let c1 = a1 + b1;

        // Addition of shares gives share of sum
        assert_eq!(combine_field_element(c0, c1), a + b);
        // MACs are preserved
        assert_eq!(c0.mac + c1.mac, mac_key * (a + b));
    }

    #[test]
    fn test_sub_shares() {
        let mut rng = test_rng();
        let mac_key = Fr::rand(&mut rng);
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);

        let [a0, a1] = share_field_element(a, mac_key, &mut rng);
        let [b0, b1] = share_field_element(b, mac_key, &mut rng);

        let c0 = a0 - b0;
        let c1 = a1 - b1;

        assert_eq!(combine_field_element(c0, c1), a - b);
        assert_eq!(c0.mac + c1.mac, mac_key * (a - b));
    }

    #[test]
    fn test_mul_public() {
        let mut rng = test_rng();
        let mac_key = Fr::rand(&mut rng);
        let a = Fr::rand(&mut rng);
        let public = Fr::rand(&mut rng);

        let [a0, a1] = share_field_element(a, mac_key, &mut rng);

        let c0 = a0 * public;
        let c1 = a1 * public;

        assert_eq!(combine_field_element(c0, c1), a * public);
        assert_eq!(c0.mac + c1.mac, mac_key * (a * public));
    }

    #[test]
    fn test_neg() {
        let mut rng = test_rng();
        let mac_key = Fr::rand(&mut rng);
        let a = Fr::rand(&mut rng);

        let [a0, a1] = share_field_element(a, mac_key, &mut rng);

        let c0 = -a0;
        let c1 = -a1;

        assert_eq!(combine_field_element(c0, c1), -a);
        assert_eq!(c0.mac + c1.mac, mac_key * (-a));
    }

    #[test]
    fn test_promote_from_trivial() {
        let mut rng = test_rng();
        let mac_key = Fr::rand(&mut rng);
        let mac_key_0 = Fr::rand(&mut rng);
        let mac_key_1 = mac_key - mac_key_0;
        let val = Fr::rand(&mut rng);

        let s0 = SpdzPrimeFieldShare::promote_from_trivial(&val, mac_key_0, 0);
        let s1 = SpdzPrimeFieldShare::promote_from_trivial(&val, mac_key_1, 1);

        assert_eq!(combine_field_element(s0, s1), val);
        assert_eq!(s0.mac + s1.mac, mac_key * val);
    }

    #[test]
    fn test_point_share_combine() {
        use ark_bn254::G1Projective;

        let mut rng = test_rng();
        let mac_key = Fr::rand(&mut rng);
        let point = G1Projective::rand(&mut rng);

        let [s0, s1] = share_curve_point(point, mac_key, &mut rng);
        assert_eq!(combine_curve_point(s0, s1), point);
    }

    #[test]
    fn test_point_share_add() {
        use ark_bn254::G1Projective;

        let mut rng = test_rng();
        let mac_key = Fr::rand(&mut rng);
        let p1 = G1Projective::rand(&mut rng);
        let p2 = G1Projective::rand(&mut rng);

        let [a0, a1] = share_curve_point(p1, mac_key, &mut rng);
        let [b0, b1] = share_curve_point(p2, mac_key, &mut rng);

        let c0 = a0 + b0;
        let c1 = a1 + b1;

        assert_eq!(combine_curve_point(c0, c1), p1 + p2);
    }
}
