//! A Plonk proof protocol that uses a collaborative MPC protocol to generate the proof.

use crate::groth16::SharedWitness;
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::SynthesisError;
use ark_serialize::CanonicalSerialize;
use circom_types::groth16::public_input;
use circom_types::plonk::ZKey;
use circom_types::traits::CircomArkworksPairingBridge;
use circom_types::traits::CircomArkworksPrimeFieldBridge;
use eyre::Result;
use mpc_core::traits::{
    EcMpcProtocol, FFTProvider, MSMProvider, PairingEcMpcProtocol, PrimeFieldMpcProtocol,
};
use sha3::digest::FixedOutputReset;
use sha3::Keccak256;
use std::io::Cursor;
use std::marker::PhantomData;

type Keccak256Transcript<P> = Transcript<Keccak256, P>;
type FieldShare<T, P> = <T as PrimeFieldMpcProtocol<<P as Pairing>::ScalarField>>::FieldShare;
type FieldShareVec<T, P> = <T as PrimeFieldMpcProtocol<<P as Pairing>::ScalarField>>::FieldShareVec;
type PointShare<T, C> = <T as EcMpcProtocol<C>>::PointShare;

struct Transcript<D, P>
where
    D: FixedOutputReset,
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
    D: FixedOutputReset,
    P: Pairing + CircomArkworksPairingBridge,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    fn add_scalar(&mut self, scalar: P::ScalarField) {
        let mut buf = vec![];
        scalar
            .lift_montgomery()
            .serialize_uncompressed(&mut buf)
            .expect("Can Fr write into Vec<u8>");
        buf.reverse();
        self.digest.update(&buf);
    }
    fn add_poly_commitment(&mut self, point: P::G1Affine) {
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

    fn get_challenge(&mut self) -> P::ScalarField {
        let bytes = self.digest.finalize_fixed_reset();
        let bytes = bytes.to_vec();
        println!("{bytes:?}");
        P::ScalarField::from_reader_unchecked_for_zkey(Cursor::new(bytes)).unwrap()
    }

    fn reset(&mut self) {
        self.digest.reset();
    }
}

struct Proof<P: Pairing> {
    commit_a: P::G1,
    commit_b: P::G1,
    commit_c: P::G1,
    commit_z: P::G1,
    commit_t1: P::G1,
    commit_t2: P::G1,
    commit_t3: P::G1,
    eval_a: P::ScalarField,
    eval_b: P::ScalarField,
    eval_c: P::ScalarField,
    eval_s1: P::ScalarField,
    eval_s2: P::ScalarField,
    eval_zw: P::ScalarField,
    commit_wxi: P::G1,
    commit_wxiw: P::G1,
}

struct Challenges<T, P: Pairing>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    b: [T::FieldShare; 10],
    alpha: P::ScalarField,
    beta: P::ScalarField,
    gamma: P::ScalarField,
    xi: P::ScalarField,
    v: [P::ScalarField; 5],
}

struct WirePolyOutput<T, P: Pairing>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    poly_a: FieldShareVec<T, P>,
    poly_b: FieldShareVec<T, P>,
    poly_c: FieldShareVec<T, P>,
    eval_a: FieldShareVec<T, P>,
    eval_b: FieldShareVec<T, P>,
    eval_c: FieldShareVec<T, P>,
}

impl<T, P: Pairing> Challenges<T, P>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    fn new() -> Self {
        Self {
            b: core::array::from_fn(|_| T::FieldShare::default()),
            alpha: P::ScalarField::default(),
            beta: P::ScalarField::default(),
            gamma: P::ScalarField::default(),
            xi: P::ScalarField::default(),
            v: core::array::from_fn(|_| P::ScalarField::default()),
        }
    }

    fn random_b(&mut self, driver: &mut T) -> Result<()> {
        for mut b in self.b.iter_mut() {
            *b = driver.rand()?;
        }

        Ok(())
    }
}

/// A Plonk proof protocol that uses a collaborative MPC protocol to generate the proof.
pub struct CollaborativePlonk<T, P: Pairing>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>
        + MSMProvider<P::G1>
        + MSMProvider<P::G2>,
    P::ScalarField: mpc_core::traits::FFTPostProcessing,
{
    pub(crate) driver: T,
    phantom_data: PhantomData<P>,
}

impl<T, P: Pairing> CollaborativePlonk<T, P>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>
        + MSMProvider<P::G1>
        + MSMProvider<P::G2>,
    P::ScalarField: mpc_core::traits::FFTPostProcessing,
{
    /// Creates a new [CollaborativePlonk] protocol with a given MPC driver.
    pub fn new(driver: T) -> Self {
        Self {
            driver,
            phantom_data: PhantomData,
        }
    }

    fn blind_coefficients(
        &mut self,
        poly: &FieldShareVec<T, P>,
        coeff: &[FieldShare<T, P>],
    ) -> Vec<FieldShare<T, P>> {
        let mut res = poly.clone().into_iter().collect::<Vec<_>>();
        for (p, c) in res.iter_mut().zip(coeff.iter()) {
            *p = self.driver.sub(p, c);
        }
        res.extend_from_slice(coeff);
        res
    }

    // TODO check if this is correct
    fn get_witness(
        &mut self,
        private_witness: &SharedWitness<T, P>,
        zkey: &ZKey<P>,
        index: usize,
    ) -> FieldShare<T, P> {
        if index < zkey.n_public {
            self.driver
                .promote_to_trivial_share(private_witness.public_inputs[index])
        } else {
            T::index_sharevec(&private_witness.witness, index - zkey.n_public)
        }
    }

    fn compute_wire_polynomials(
        &mut self,
        challenges: &Challenges<T, P>,
        zkey: &ZKey<P>,
        private_witness: &SharedWitness<T, P>,
    ) -> Result<WirePolyOutput<T, P>> {
        let num_constraints = zkey.n_constraints;

        let mut buffer_a = Vec::with_capacity(num_constraints);
        let mut buffer_b = Vec::with_capacity(num_constraints);
        let mut buffer_c = Vec::with_capacity(num_constraints);

        for i in 0..num_constraints {
            buffer_a.push(self.get_witness(&private_witness, zkey, zkey.map_a[i]));
            buffer_b.push(self.get_witness(&private_witness, zkey, zkey.map_b[i]));
            buffer_c.push(self.get_witness(&private_witness, zkey, zkey.map_c[i]));
        }

        // TODO batch to montgomery in MPC?

        let buffer_a = FieldShareVec::<T, P>::from(buffer_a);
        let buffer_b = FieldShareVec::<T, P>::from(buffer_b);
        let buffer_c = FieldShareVec::<T, P>::from(buffer_c);

        // Compute the coefficients of the wire polynomials a(X), b(X) and c(X) from A,B & C buffers
        let domain1 = GeneralEvaluationDomain::<P::ScalarField>::new(num_constraints)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let poly_a = self.driver.ifft(&buffer_a, &domain1);
        let poly_b = self.driver.ifft(&buffer_b, &domain1);
        let poly_c = self.driver.ifft(&buffer_c, &domain1);

        // Compute extended evaluations of a(X), b(X) and c(X) polynomials
        let domain2 = GeneralEvaluationDomain::<P::ScalarField>::new(num_constraints * 4)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let eval_a = self.driver.fft(poly_a.to_owned(), &domain2);
        let eval_b = self.driver.fft(poly_b.to_owned(), &domain2);
        let eval_c = self.driver.fft(poly_c.to_owned(), &domain2);

        let poly_a = self.blind_coefficients(&poly_a, &challenges.b[..2]);
        let poly_b = self.blind_coefficients(&poly_b, &challenges.b[2..4]);
        let poly_c = self.blind_coefficients(&poly_c, &challenges.b[4..6]);

        if poly_a.len() > zkey.domain_size + 2
            || poly_b.len() > zkey.domain_size + 2
            || poly_c.len() > zkey.domain_size + 2
        {
            return Err(SynthesisError::PolynomialDegreeTooLarge.into());
        }

        Ok(WirePolyOutput {
            poly_a: poly_a.into(),
            poly_b: poly_b.into(),
            poly_c: poly_c.into(),
            eval_a,
            eval_b,
            eval_c,
        })
    }

    fn round1(
        &mut self,
        challenges: &mut Challenges<T, P>,
        proof: &mut Proof<P>,
        zkey: &ZKey<P>,
        private_witness: &SharedWitness<T, P>,
    ) -> Result<WirePolyOutput<T, P>> {
        // STEP 1.1 - Generate random blinding scalars (b0, ..., b10) \in F_p
        challenges.random_b(&mut self.driver)?;

        // STEP 1.2 - Compute wire polynomials a(X), b(X) and c(X)
        let outp = self.compute_wire_polynomials(challenges, zkey, private_witness)?;

        // STEP 1.3 - Compute [a]_1, [b]_1, [c]_1
        let commit_a =
            MSMProvider::<P::G1>::msm_public_points(&mut self.driver, &zkey.p_tau, &outp.poly_a);
        let commit_b =
            MSMProvider::<P::G1>::msm_public_points(&mut self.driver, &zkey.p_tau, &outp.poly_b);
        let commit_c =
            MSMProvider::<P::G1>::msm_public_points(&mut self.driver, &zkey.p_tau, &outp.poly_c);

        // TODO parallelize
        proof.commit_a = self.driver.open_point(&commit_a)?;
        proof.commit_b = self.driver.open_point(&commit_b)?;
        proof.commit_c = self.driver.open_point(&commit_c)?;

        Ok(outp)
    }

    fn compute_z(&mut self) -> Result<FieldShareVec<T, P>> {
        todo!()
    }

    fn round2(
        &mut self,
        transcript: &mut Keccak256Transcript<P>,
        challenges: &mut Challenges<T, P>,
        proof: &mut Proof<P>,
        zkey: &ZKey<P>,
        private_witness: &SharedWitness<T, P>,
    ) -> Result<()>
    where
        P: Pairing + CircomArkworksPairingBridge,
        P::BaseField: CircomArkworksPrimeFieldBridge,
        P::ScalarField: CircomArkworksPrimeFieldBridge,
    {
        // STEP 2.1 - Compute permutation challenge beta and gamma \in F_p

        // Compute permutation challenge beta
        transcript.reset();
        transcript.add_poly_commitment(zkey.verifying_key.qm);
        transcript.add_poly_commitment(zkey.verifying_key.ql);
        transcript.add_poly_commitment(zkey.verifying_key.qr);
        transcript.add_poly_commitment(zkey.verifying_key.qo);
        transcript.add_poly_commitment(zkey.verifying_key.qc);
        transcript.add_poly_commitment(zkey.verifying_key.s1);
        transcript.add_poly_commitment(zkey.verifying_key.s2);
        transcript.add_poly_commitment(zkey.verifying_key.s3);

        for val in private_witness.public_inputs.iter().cloned() {
            transcript.add_scalar(val);
        }

        transcript.add_poly_commitment(proof.commit_a.into());
        transcript.add_poly_commitment(proof.commit_b.into());
        transcript.add_poly_commitment(proof.commit_c.into());

        challenges.beta = transcript.get_challenge();

        // Compute permutation challenge gamma
        transcript.reset();
        transcript.add_scalar(challenges.beta);
        challenges.gamma = transcript.get_challenge();

        // STEP 2.2 - Compute permutation polynomial z(X)
        let poly_z = self.compute_z()?;

        // STEP 2.3 - Compute permutation [z]_1
        let commit_z =
            MSMProvider::<P::G1>::msm_public_points(&mut self.driver, &zkey.p_tau, &poly_z);

        proof.commit_z = self.driver.open_point(&commit_z)?;

        Ok(())
    }

    fn round3(&mut self) -> Result<()> {
        todo!();
        Ok(())
    }
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

    macro_rules! to_g2_bn254 {
        ({$x1: expr, $x2: expr}, {$y1: expr, $y2: expr}) => {
            <ark_bn254::Bn254 as Pairing>::G2Affine::new(
                ark_bn254::Fq2::new(
                    ark_bn254::Fq::from_str($x1).unwrap(),
                    ark_bn254::Fq::from_str($x2).unwrap(),
                ),
                ark_bn254::Fq2::new(
                    ark_bn254::Fq::from_str($y1).unwrap(),
                    ark_bn254::Fq::from_str($y2).unwrap(),
                ),
            )
        };
    }
    use ark_serialize::CanonicalSerialize;
    #[test]
    fn test_keccak_transcript() {
        let mut transcript = Keccak256Transcript::<Bn254>::default();
        transcript.add_poly_commitment(to_g1_bn254!(
            "20825949499069110345561489838956415747250622568151984013116057026259498945798",
            "4633888776580597789536778273539625207986785465104156818397550354894072332743"
        ));
        transcript.add_poly_commitment(to_g1_bn254!(
            "13502414797941204782598195942532580786194839256223737894432362681935424485706",
            "18673738305240077401477088441313771484023070622513584695135539045403188608753"
        ));
        transcript.add_poly_commitment(ark_bn254::G1Affine::identity());
        transcript.add_scalar(
            ark_bn254::Fr::from_str(
                "18493166935391704183319420574241503914733913248159936156014286513312199455",
            )
            .unwrap(),
        );
        transcript.add_poly_commitment(to_g1_bn254!(
            "20825949499069110345561489838956415747250622568151984013116057026259498945798",
            "17254354095258677432709627471717649880709525692193666844291487539751153875840"
        ));
        transcript.add_scalar(
            ark_bn254::Fr::from_str(
                "18493166935391704183319420574241503914733913248159936156014286513312199455",
            )
            .unwrap(),
        );
        let mut buf = vec![];
        let test = transcript.get_challenge();
        test.serialize_uncompressed(&mut buf).unwrap();
        println!("{:?}", buf);
        println!("{}", test);
    }
}
