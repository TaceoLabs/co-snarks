//! Raw wire format for prime-field elements.
//!
//! Serializes slices of field elements as their internal representation:
//! `N` little-endian `u64` limbs per element (the Montgomery form), with no
//! headers. This avoids the Montgomery reduction (`into_bigint`) on
//! serialization and the multiplication by R² (`from_bigint`) on
//! deserialization that the canonical ark format performs per element.
//!
//! The encoding is stable across platforms and arkworks versions: the
//! Montgomery representation is mathematically determined by the modulus and
//! limb count (R = 2^(64·N) mod p), and the byte order is normatively
//! little-endian.
//!
//! # Compatibility
//!
//! The format is not self-describing and is **not** interoperable with
//! ark-serialize: a message sent with [`to_bytes`] must be received with
//! [`from_bytes`]. A mismatch fails loudly for any element size larger than
//! 8 bytes (every field in this workspace): ark's slice encoding carries an
//! 8-byte count prefix, which is then never a multiple of the element size.
//!
//! # Validation
//!
//! [`from_bytes`] rejects any element whose representation is not below the
//! modulus, mirroring ark's behavior of rejecting out-of-range field elements.

use ark_ff::{BigInt, Fp, MontBackend, MontConfig, PrimeField};
use bytes::Bytes;

/// A fixed-size raw wire encoding for values exchanged between MPC parties.
///
/// Implementations must be symmetric: [`read_wire`](WireFormat::read_wire)
/// applied to the output of [`write_wire`](WireFormat::write_wire)
/// reconstructs the value. Both parties must use the same type on both ends;
/// the encoding carries no type or length information of its own.
///
/// This trait is for fixed-size encodings only: variable-size types (e.g.
/// `BigUint`) need a different mechanism and must not fake a `WIRE_SIZE`.
pub trait WireFormat: Sized {
    /// The byte size of one serialized element.
    const WIRE_SIZE: usize;

    /// Appends the wire encoding of `self` to `out`.
    fn write_wire(&self, out: &mut Vec<u8>);

    /// Decodes one element from a [`WIRE_SIZE`](WireFormat::WIRE_SIZE)-byte chunk.
    fn read_wire(bytes: &[u8]) -> eyre::Result<Self>;
}

impl<T: MontConfig<N>, const N: usize> WireFormat for Fp<MontBackend<T, N>, N> {
    const WIRE_SIZE: usize = N * 8;

    fn write_wire(&self, out: &mut Vec<u8>) {
        // The limbs of the Montgomery representation, via the public field.
        // `to_le_bytes` is a no-op on little-endian targets.
        for limb in &self.0.0 {
            out.extend_from_slice(&limb.to_le_bytes());
        }
    }

    fn read_wire(bytes: &[u8]) -> eyre::Result<Self> {
        eyre::ensure!(
            bytes.len() == Self::WIRE_SIZE,
            "expected {} bytes, got {}",
            Self::WIRE_SIZE,
            bytes.len()
        );
        let mut repr = BigInt::<N>([0u64; N]);
        for (limb, chunk) in repr.0.iter_mut().zip(bytes.chunks_exact(8)) {
            *limb = u64::from_le_bytes(chunk.try_into().expect("chunk has 8 bytes"));
        }
        // Every valid element's Montgomery representation lies in [0, p).
        if repr >= <Self as PrimeField>::MODULUS {
            eyre::bail!("out of range: representation is >= the modulus");
        }
        // Safe const constructor for "an integer already in Montgomery form" —
        // deliberately NOT `from_bigint`, which would multiply by R^2 and
        // reintroduce the conversion this module exists to avoid.
        Ok(Fp::new_unchecked(repr))
    }
}

/// Serializes a slice of elements into the raw wire format.
pub fn to_bytes<T: WireFormat>(data: &[T]) -> Bytes {
    let mut out = Vec::with_capacity(data.len() * T::WIRE_SIZE);
    for el in data {
        el.write_wire(&mut out);
    }
    Bytes::from(out)
}

/// Deserializes elements from the raw wire format.
///
/// Fails if the length is not a multiple of [`WireFormat::WIRE_SIZE`] (e.g.
/// because the peer sent the ark format) or if any element is rejected by
/// [`WireFormat::read_wire`].
pub fn from_bytes<T: WireFormat>(data: Bytes) -> eyre::Result<Vec<T>> {
    if !data.len().is_multiple_of(T::WIRE_SIZE) {
        eyre::bail!(
            "invalid length {}: not a multiple of the element size {} (sent with the ark format?)",
            data.len(),
            T::WIRE_SIZE
        );
    }
    let mut res = Vec::with_capacity(data.len() / T::WIRE_SIZE);
    for (i, chunk) in data.chunks_exact(T::WIRE_SIZE).enumerate() {
        let el = T::read_wire(chunk).map_err(|err| eyre::eyre!("element {i}: {err}"))?;
        res.push(el);
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{AdditiveGroup, One as _};
    use ark_serialize::CanonicalSerialize as _;
    use ark_std::UniformRand as _;

    fn roundtrip<F: PrimeField + WireFormat>() {
        let mut rng = rand::thread_rng();
        let data: Vec<F> = (0..137).map(|_| F::rand(&mut rng)).collect();
        let bytes = to_bytes(&data);
        assert_eq!(bytes.len(), 137 * F::WIRE_SIZE);
        let back: Vec<F> = from_bytes(bytes).unwrap();
        assert_eq!(data, back);
    }

    #[test]
    fn roundtrip_bn254_fr() {
        roundtrip::<ark_bn254::Fr>();
    }

    #[test]
    fn roundtrip_bn254_fq() {
        roundtrip::<ark_bn254::Fq>();
    }

    #[test]
    fn roundtrip_bls12_381_fq() {
        // 6 limbs, unlike the 4-limb bn254 fields
        roundtrip::<ark_bls12_381::Fq>();
    }

    #[test]
    fn roundtrip_edge_elements() {
        type F = ark_bn254::Fr;
        let data = vec![F::ZERO, F::one(), -F::one()];
        let back: Vec<F> = from_bytes(to_bytes(&data)).unwrap();
        assert_eq!(data, back);
    }

    #[test]
    fn roundtrip_empty() {
        type F = ark_bn254::Fr;
        let bytes = to_bytes::<F>(&[]);
        assert!(bytes.is_empty());
        let back: Vec<F> = from_bytes(bytes).unwrap();
        assert!(back.is_empty());
    }

    #[test]
    fn rejects_indivisible_length() {
        let bytes = Bytes::copy_from_slice(&[0u8; 33]);
        assert!(from_bytes::<ark_bn254::Fr>(bytes).is_err());
    }

    #[test]
    fn rejects_ark_encoding() {
        // ark's slice encoding is 8 (count prefix) + WIRE_SIZE·n bytes, never a
        // multiple of WIRE_SIZE — the mismatch must be detected, not decoded.
        let mut rng = rand::thread_rng();
        let data: Vec<ark_bn254::Fr> = (0..10).map(|_| ark_bn254::Fr::rand(&mut rng)).collect();
        let mut ser = Vec::new();
        data.serialize_uncompressed(&mut ser).unwrap();
        assert!(from_bytes::<ark_bn254::Fr>(Bytes::from(ser)).is_err());
    }

    #[test]
    fn rejects_representation_equal_to_modulus() {
        type F = ark_bn254::Fr;
        let mut bytes = Vec::new();
        for limb in <F as PrimeField>::MODULUS.0 {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }
        assert!(from_bytes::<F>(Bytes::from(bytes)).is_err());
    }

    #[test]
    fn read_wire_rejects_wrong_length() {
        type F = ark_bn254::Fr;
        assert_eq!(F::WIRE_SIZE, 32);

        let short = [0u8; 31];
        assert!(F::read_wire(&short).is_err());

        let oversized = [0u8; 33];
        assert!(F::read_wire(&oversized).is_err());
    }

    #[test]
    fn accepts_representation_modulus_minus_one() {
        // The largest valid internal representation. The bn254 modulus is odd,
        // so decrementing the lowest limb cannot borrow.
        type F = ark_bn254::Fr;
        let mut limbs = <F as PrimeField>::MODULUS.0;
        limbs[0] -= 1;
        let mut bytes = Vec::new();
        for limb in limbs {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }
        let decoded: Vec<F> = from_bytes(Bytes::from(bytes)).unwrap();
        assert_eq!(decoded.len(), 1);
        // Whatever element that representation denotes, it must round-trip.
        let again: Vec<F> = from_bytes(to_bytes(&decoded)).unwrap();
        assert_eq!(decoded, again);
    }
}
