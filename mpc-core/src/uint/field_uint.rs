//! Maps prime fields to a wide-enough stack-allocated uint backend.

use crate::uint::{U256, U320, U384, UintBackend};
use ark_ff::PrimeField;

/// Associates a prime field with the fixed-width uint used for its
/// binary-domain shares.
///
/// # Width contract
///
/// `Self::Uint::BITS >= Self::MODULUS_BIT_SIZE + 2`. The two extra bits are
/// required by the binary add/sub-p pipeline: the Kogge–Stone carry-out
/// (`g <<= 1`) runs inside the `bitlen + 1` sub-p CMUX used by every
/// a2b/b2a conversion. Enforced at compile time for every impl.
pub trait FieldUint: PrimeField {
    /// The uint backend for this field.
    type Uint: UintBackend;

    /// Converts the field element to its integer representation
    /// (a cheap limb copy of `into_bigint()`).
    fn to_uint(&self) -> Self::Uint;

    /// Converts an integer to a field element, reducing modulo `p`
    /// (replaces `F::from(BigUint)`).
    fn from_uint_reduced(u: &Self::Uint) -> Self;

    /// Converts an integer known to be `< p` to a field element.
    ///
    /// The caller must guarantee the value is reduced. Unreduced values that
    /// fit in the field's `BigInt` width panic; values with set limbs beyond
    /// that width panic only in debug builds — release builds silently
    /// truncate them, which can yield a wrong field element.
    fn from_uint_unchecked(u: &Self::Uint) -> Self;

    /// The field modulus `p` as a uint.
    fn modulus_uint() -> Self::Uint;
}

/// Reduces an integer of arbitrary width modulo `p` via Horner evaluation
/// over its 64-bit limbs. The ruint ark-ff bridge only converts values `< p`,
/// so full reduction (the `F::from(BigUint)` replacement) stays hand-rolled.
fn reduce_from_limbs<F: PrimeField, U: UintBackend>(u: &U) -> F {
    let shift = F::from(u64::MAX) + F::ONE;
    let mut acc = F::ZERO;
    for limb in u.as_limbs().iter().rev() {
        acc = acc * shift + F::from(*limb);
    }
    acc
}

macro_rules! impl_field_uint {
    // Backend with the same limb count as the field's `BigInt`: conversions
    // delegate to ruint's `ark-ff-06` bridge.
    ($field:ty, $uint:ty) => {
        // Width contract: BITS >= MODULUS_BIT_SIZE + 2 (see trait docs).
        const _: () = assert!(
            <$uint as UintBackend>::BITS >= <$field as PrimeField>::MODULUS_BIT_SIZE as usize + 2
        );

        impl FieldUint for $field {
            type Uint = $uint;

            fn to_uint(&self) -> Self::Uint {
                (*self).into()
            }

            fn from_uint_reduced(u: &Self::Uint) -> Self {
                reduce_from_limbs(u)
            }

            fn from_uint_unchecked(u: &Self::Uint) -> Self {
                (*u).try_into().expect("value is smaller than the modulus")
            }

            fn modulus_uint() -> Self::Uint {
                <Self as PrimeField>::MODULUS.into()
            }
        }
    };
    // Backend wider (more limbs) than the field's `BigInt`: the limb-matched
    // bridge impls do not apply, so widen/narrow via limb slices.
    ($field:ty, $uint:ty, widened) => {
        // Width contract: BITS >= MODULUS_BIT_SIZE + 2 (see trait docs).
        const _: () = assert!(
            <$uint as UintBackend>::BITS >= <$field as PrimeField>::MODULUS_BIT_SIZE as usize + 2
        );

        impl FieldUint for $field {
            type Uint = $uint;

            fn to_uint(&self) -> Self::Uint {
                Self::Uint::from_limbs_truncating(&self.into_bigint().0)
            }

            fn from_uint_reduced(u: &Self::Uint) -> Self {
                reduce_from_limbs(u)
            }

            fn from_uint_unchecked(u: &Self::Uint) -> Self {
                let mut bigint = <Self as PrimeField>::BigInt::default();
                let n = bigint.0.len();
                debug_assert!(
                    u.as_limbs()[n..].iter().all(|l| *l == 0),
                    "value has limbs beyond the field's BigInt width"
                );
                bigint.0.copy_from_slice(&u.as_limbs()[..n]);
                Self::from_bigint(bigint).expect("value is smaller than the modulus")
            }

            fn modulus_uint() -> Self::Uint {
                Self::Uint::from_limbs_truncating(&<Self as PrimeField>::MODULUS.0)
            }
        }
    };
}

impl_field_uint!(ark_bn254::Fr, U256);
impl_field_uint!(ark_bn254::Fq, U256);
impl_field_uint!(ark_bls12_377::Fr, U256);
impl_field_uint!(ark_bls12_381::Fr, U320, widened);
impl_field_uint!(ark_bls12_377::Fq, U384);
impl_field_uint!(ark_bls12_381::Fq, U384);

// Note: `ark_grumpkin::Fr`/`Fq` are re-exports of `ark_bn254::Fq`/`Fr`
// respectively, so they are already covered by the impls above. Adding an
// `impl_field_uint!(ark_grumpkin::Fr, ...)` here would be a conflicting
// impl and fail to compile.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uint::UintBackend;
    use ark_ff::{PrimeField, UniformRand, Zero};
    use num_bigint::BigUint;
    use paste::paste;
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    macro_rules! field_uint_tests {
        ($($field:ty => $name:ident),* $(,)?) => {$( paste! {
            #[test]
            fn [<field_uint_roundtrip_ $name>]() {
                let mut rng = ChaCha12Rng::seed_from_u64(46);
                for _ in 0..50 {
                    let x = <$field>::rand(&mut rng);
                    let u = x.to_uint();
                    assert_eq!(<$field>::from_uint_unchecked(&u), x);
                    assert_eq!(<$field>::from_uint_reduced(&u), x);
                }
            }

            #[test]
            fn [<field_uint_reduced_matches_biguint_ $name>]() {
                let mut rng = ChaCha12Rng::seed_from_u64(47);
                for _ in 0..50 {
                    // random full-width value, possibly >= p
                    let u = <$field as FieldUint>::Uint::random_bits(
                        &mut rng,
                        <$field as FieldUint>::Uint::BITS,
                    );
                    let mut bytes = vec![0u8; <$field as FieldUint>::Uint::BYTES];
                    u.to_le_bytes_into(&mut bytes);
                    let expected = <$field>::from(BigUint::from_bytes_le(&bytes));
                    assert_eq!(<$field>::from_uint_reduced(&u), expected);
                }
            }

            #[test]
            fn [<field_uint_modulus_ $name>]() {
                let m = <$field>::modulus_uint();
                let expected: BigUint = <$field>::MODULUS.into();
                let mut bytes = vec![0u8; <$field as FieldUint>::Uint::BYTES];
                m.to_le_bytes_into(&mut bytes);
                assert_eq!(BigUint::from_bytes_le(&bytes), expected);
                // reducing the modulus itself gives zero
                assert!(<$field>::from_uint_reduced(&m).is_zero());
            }
        })*};
    }

    field_uint_tests!(
        ark_bn254::Fr => bn254_fr,
        ark_bn254::Fq => bn254_fq,
        ark_bls12_377::Fr => bls12_377_fr,
        ark_bls12_381::Fr => bls12_381_fr,
        ark_bls12_377::Fq => bls12_377_fq,
        ark_bls12_381::Fq => bls12_381_fq,
    );
}
