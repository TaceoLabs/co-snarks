use ark_ec::AffineRepr;
use std::marker::PhantomData;

use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use circom_types::traits::{CircomArkworksPairingBridge, CircomArkworksPrimeFieldBridge};
use mpc_core::traits::{MontgomeryField, PrimeFieldMpcProtocol};
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
    P::ScalarField: MontgomeryField,
{
    pub(crate) fn add_scalar(&mut self, scalar: P::ScalarField) {
        let mut buf = vec![];
        scalar
            //.lift_montgomery() Check if we need this or not. For round2 we do not need it
            .serialize_uncompressed(&mut buf)
            .expect("Can Fr write into Vec<u8>");
        buf.reverse();
        self.digest.update(&buf);
    }

    pub(crate) fn add_montgomery_scalar(&mut self, scalar: P::ScalarField) {
        self.add_scalar(scalar.lift_montgomery())
    }
    pub(crate) fn add_point(&mut self, point: P::G1Affine) {
        let bits: usize = P::BaseField::MODULUS_BIT_SIZE
            .try_into()
            .expect("u32 fits into usize");
        let mut buf = Vec::with_capacity(bits);
        if let Some((x, y)) = point.xy() {
            x.serialize_uncompressed(&mut buf)
                .expect("Can Fq write into Vec<u8>");
            buf.reverse();
            self.digest.update(&buf);
            buf.clear();
            y.serialize_uncompressed(&mut buf)
                .expect("Can Fq write into Vec<u8>");
            buf.reverse();
            self.digest.update(&buf);
        } else {
            // we are at infinity
            buf.resize(((bits + 7) / 8) * 2, 0);
            self.digest.update(&buf);
        }
    }

    pub(crate) fn get_challenge(self) -> P::ScalarField {
        let bytes = self.digest.finalize();
        P::ScalarField::from_be_bytes_mod_order(&bytes).into_montgomery()
    }
}

pub(crate) struct PolyEval<T, P: Pairing>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    pub(crate) poly: FieldShareVec<T, P>,
    pub(crate) eval: FieldShareVec<T, P>,
}

pub(crate) struct WirePolyOutput<T, P: Pairing>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    pub(crate) buffer_a: FieldShareVec<T, P>,
    pub(crate) buffer_b: FieldShareVec<T, P>,
    pub(crate) buffer_c: FieldShareVec<T, P>,
    pub(crate) poly_eval_a: PolyEval<T, P>,
    pub(crate) poly_eval_b: PolyEval<T, P>,
    pub(crate) poly_eval_c: PolyEval<T, P>,
}

pub(crate) struct TPoly<T, P: Pairing>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    t1: FieldShareVec<T, P>,
    t2: FieldShareVec<T, P>,
    t3: FieldShareVec<T, P>,
}

#[cfg(test)]
mod tests {
    use super::Keccak256Transcript;
    use ark_bn254::Bn254;
    use ark_ec::pairing::Pairing;
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
        transcript.add_montgomery_scalar(
            ark_bn254::Fr::from_str(
                "18493166935391704183319420574241503914733913248159936156014286513312199455",
            )
            .unwrap(),
        );
        let is_challenge = transcript.get_challenge();
        assert_eq!(
            ark_bn254::Fr::from_str(
                "17217611606783903786519756581064691877765084316359051724941375688886751695364",
            )
            .unwrap(),
            is_challenge
        );
    }
}
