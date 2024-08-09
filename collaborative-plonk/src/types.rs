use ark_ec::AffineRepr;
use std::marker::PhantomData;

use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use mpc_core::traits::PrimeFieldMpcProtocol;
use sha3::{Digest, Keccak256};

use crate::FieldShareVec;

pub(crate) type Keccak256Transcript<P> = Transcript<Keccak256, P>;

pub(crate) struct Transcript<D, P>
where
    D: Digest,
    P: Pairing,
{
    digest: D,
    phantom_data: PhantomData<P>,
}

impl<P: Pairing> Default for Keccak256Transcript<P> {
    fn default() -> Self {
        Self {
            digest: Default::default(),
            phantom_data: Default::default(),
        }
    }
}

impl<D, P> Transcript<D, P>
where
    D: Digest,
    P: Pairing,
{
    pub(crate) fn add_scalar(&mut self, scalar: P::ScalarField) {
        let mut buf = vec![];
        scalar
            .serialize_uncompressed(&mut buf)
            .expect("Can Fr write into Vec<u8>");
        buf.reverse();
        self.digest.update(&buf);
    }

    pub(crate) fn add_point(&mut self, point: P::G1Affine) {
        let byte_len: usize = P::BaseField::MODULUS_BIT_SIZE
            .div_ceil(8)
            .try_into()
            .expect("u32 fits into usize");
        let mut buf = Vec::with_capacity(byte_len);
        if let Some((x, y)) = point.xy() {
            x.serialize_uncompressed(&mut buf)
                .expect("Can write Fq into Vec<u8>");
            buf.reverse();
            self.digest.update(&buf);
            buf.clear();
            y.serialize_uncompressed(&mut buf)
                .expect("Can write Fq into Vec<u8>");
            buf.reverse();
            self.digest.update(&buf);
        } else {
            // we are at infinity - in this case, snarkjs writes (MODULUS_BIT_SIZE / 8) Zero-bytes
            // to the input buffer. If we serialize with arkworks, we would
            // get (MODULUS_BIT_SIZE / 8 - 1) Zero-bytes with a trailing byte indicating the length of
            // the serialized group element, resulting in an incompatible hash. Therefore we simple resize
            // the buffer with Zeros and write it to the hash instance.
            buf.resize(byte_len * 2, 0);
            self.digest.update(&buf);
        }
    }

    pub(crate) fn get_challenge(self) -> P::ScalarField {
        let bytes = self.digest.finalize();
        P::ScalarField::from_be_bytes_mod_order(&bytes)
    }
}

pub(crate) struct PolyEval<T, P: Pairing>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    pub(crate) poly: FieldShareVec<T, P>,
    pub(crate) eval: FieldShareVec<T, P>,
}

#[cfg(test)]
mod tests {
    use super::Keccak256Transcript;
    use ark_bn254::Bn254;
    use ark_ec::pairing::Pairing;
    use ark_serialize::CanonicalSerialize;
    use std::str::FromStr;

    //this is copied from circom-type/groth16/mod/test_utils. Maybe we can
    //create a test-utils crate where we gather such definitions
    macro_rules! to_g1_bn254 {
        ($x: expr, $y: expr) => {
            <ark_bn254::Bn254 as Pairing>::G1Affine::new(
                ark_bn254::Fq::from_str($x).unwrap(),
                ark_bn254::Fq::from_str($y).unwrap(),
            )
        };
    }

    #[test]
    fn test_keccak_transcript() {
        let mut transcript = Keccak256Transcript::<Bn254>::default();
        transcript.add_point(to_g1_bn254!(
            "20825949499069110345561489838956415747250622568151984013116057026259498945798",
            "4633888776580597789536778273539625207986785465104156818397550354894072332743"
        ));
        transcript.add_point(to_g1_bn254!(
            "13502414797941204782598195942532580786194839256223737894432362681935424485706",
            "18673738305240077401477088441313771484023070622513584695135539045403188608753"
        ));
        transcript.add_point(ark_bn254::G1Affine::identity());
        transcript.add_scalar(
            ark_bn254::Fr::from_str(
                "18493166935391704183319420574241503914733913248159936156014286513312199455",
            )
            .unwrap(),
        );
        transcript.add_point(to_g1_bn254!(
            "20825949499069110345561489838956415747250622568151984013116057026259498945798",
            "17254354095258677432709627471717649880709525692193666844291487539751153875840"
        ));
        transcript.add_scalar(
            ark_bn254::Fr::from_str(
                "18493166935391704183319420574241503914733913248159936156014286513312199455",
            )
            .unwrap(),
        );
        let is_challenge = transcript.get_challenge();
        assert_eq!(
            ark_bn254::Fr::from_str(
                "16679357168864952869972350724842033299710155825088243463992129238972103889312",
            )
            .unwrap(),
            is_challenge
        );
    }
}
