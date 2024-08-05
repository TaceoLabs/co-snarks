//! A Plonk proof protocol that uses a collaborative MPC protocol to generate the proof.

use crate::groth16::CollaborativeGroth16;
use crate::groth16::SharedWitness;
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ff::Field;
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::SynthesisError;
use ark_serialize::CanonicalSerialize;
use circom_types::groth16::zkey;
use circom_types::plonk::Polynomial;
use circom_types::plonk::ZKey;
use circom_types::traits::CircomArkworksPairingBridge;
use circom_types::traits::CircomArkworksPrimeFieldBridge;
use eyre::Result;
use mpc_core::traits::{
    EcMpcProtocol, FFTProvider, MSMProvider, PairingEcMpcProtocol, PrimeFieldMpcProtocol,
};
use num_traits::ops::inv;
use num_traits::One;
use num_traits::Zero;
use sha3::Digest;
use sha3::Keccak256;
use std::marker::PhantomData;
use std::ops::MulAssign;

type Keccak256Transcript<P> = Transcript<Keccak256, P>;
type FieldShare<T, P> = <T as PrimeFieldMpcProtocol<<P as Pairing>::ScalarField>>::FieldShare;
type FieldShareVec<T, P> = <T as PrimeFieldMpcProtocol<<P as Pairing>::ScalarField>>::FieldShareVec;
type PointShare<T, C> = <T as EcMpcProtocol<C>>::PointShare;

macro_rules! mul4 {
    ($driver: expr, $a: expr,$b: expr,$c: expr,$d: expr,$ap: expr,$bp: expr,$cp: expr,$dp: expr, $domain: expr, $mod_i:expr) => {{
        let a_b = $driver.mul($a, $b)?;
        let a_bp = $driver.mul($a, $bp)?;
        let ap_b = $driver.mul($ap, $b)?;
        let ap_bp = $driver.mul($ap, $bp)?;

        let c_d = $driver.mul($c, $d)?;
        let c_dp = $driver.mul($c, $dp)?;
        let cp_d = $driver.mul($cp, $d)?;
        let cp_dp = $driver.mul($cp, $dp)?;

        let r = $driver.mul(&a_b, &c_d)?;

        let mut a0 = $driver.mul(&ap_b, &c_d)?;
        a0 = $driver.add_mul(&a0, &a_bp, &c_d)?;
        a0 = $driver.add_mul(&a0, &a_b, &cp_d)?;
        a0 = $driver.add_mul(&a0, &a_b, &c_dp)?;

        let mut a1 = $driver.mul(&ap_bp, &c_d)?;
        a1 = $driver.add_mul(&a1, &ap_b, &cp_d)?;
        a1 = $driver.add_mul(&a1, &ap_b, &c_dp)?;
        a1 = $driver.add_mul(&a1, &a_bp, &cp_d)?;
        a1 = $driver.add_mul(&a1, &a_bp, &c_dp)?;
        a1 = $driver.add_mul(&a1, &a_b, &cp_dp)?;

        let mut a2 = $driver.mul(&a_bp, &cp_dp)?;
        a2 = $driver.add_mul(&a2, &ap_b, &cp_dp)?;
        a2 = $driver.add_mul(&a2, &ap_bp, &c_dp)?;
        a2 = $driver.add_mul(&a2, &ap_bp, &cp_d)?;

        let a3 = $driver.mul(&ap_bp, &cp_dp)?;

        let mut rz = a0;
        if $mod_i != 0 {
            let tmp = $driver.mul_with_public(&Self::get_z1($domain)[$mod_i], &a1);
            rz = $driver.add(&rz, &tmp);
            let tmp = $driver.mul_with_public(&Self::get_z2($domain)[$mod_i], &a2);
            rz = $driver.add(&rz, &tmp);
            let tmp = $driver.mul_with_public(&Self::get_z3($domain)[$mod_i], &a3);
            rz = $driver.add(&rz, &tmp);
        }
        [r, rz]
    }};
}
struct Transcript<D, P>
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
        let mut digest = D::new();
        std::mem::swap(&mut self.digest, &mut digest);
        let bytes = digest.finalize();
        P::ScalarField::from_be_bytes_mod_order(&bytes).to_montgomery()
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
    b: [T::FieldShare; 11],
    alpha: P::ScalarField,
    alpha2: P::ScalarField,
    beta: P::ScalarField,
    gamma: P::ScalarField,
    xi: P::ScalarField,
    v: [P::ScalarField; 5],
}

impl<T, P: Pairing> Challenges<T, P>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    fn new() -> Self {
        Self {
            b: core::array::from_fn(|_| T::FieldShare::default()),
            alpha: P::ScalarField::default(),
            alpha2: P::ScalarField::default(),
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

struct PolyEval<T, P: Pairing>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    poly: FieldShareVec<T, P>,
    eval: FieldShareVec<T, P>,
}

struct WirePolyOutput<T, P: Pairing>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    buffer_a: FieldShareVec<T, P>,
    buffer_b: FieldShareVec<T, P>,
    buffer_c: FieldShareVec<T, P>,
    poly_eval_a: PolyEval<T, P>,
    poly_eval_b: PolyEval<T, P>,
    poly_eval_c: PolyEval<T, P>,
}

struct TPoly<T, P: Pairing>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    t1: FieldShareVec<T, P>,
    t2: FieldShareVec<T, P>,
    t3: FieldShareVec<T, P>,
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

impl<T, P> CollaborativePlonk<T, P>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>
        + MSMProvider<P::G1>
        + MSMProvider<P::G2>,
    P::ScalarField: mpc_core::traits::FFTPostProcessing + CircomArkworksPrimeFieldBridge,
    P: Pairing + CircomArkworksPairingBridge,
    P::BaseField: CircomArkworksPrimeFieldBridge,
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
            buffer_a.push(self.get_witness(private_witness, zkey, zkey.map_a[i]));
            buffer_b.push(self.get_witness(private_witness, zkey, zkey.map_b[i]));
            buffer_c.push(self.get_witness(private_witness, zkey, zkey.map_c[i]));
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
            buffer_a,
            buffer_b,
            buffer_c,
            poly_eval_a: PolyEval {
                poly: poly_a.into(),
                eval: eval_a,
            },
            poly_eval_b: PolyEval {
                poly: poly_b.into(),
                eval: eval_b,
            },
            poly_eval_c: PolyEval {
                poly: poly_c.into(),
                eval: eval_c,
            },
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
        let commit_a = MSMProvider::<P::G1>::msm_public_points(
            &mut self.driver,
            &zkey.p_tau,
            &outp.poly_eval_a.poly,
        );
        let commit_b = MSMProvider::<P::G1>::msm_public_points(
            &mut self.driver,
            &zkey.p_tau,
            &outp.poly_eval_b.poly,
        );
        let commit_c = MSMProvider::<P::G1>::msm_public_points(
            &mut self.driver,
            &zkey.p_tau,
            &outp.poly_eval_c.poly,
        );

        // TODO parallelize
        proof.commit_a = self.driver.open_point(&commit_a)?;
        proof.commit_b = self.driver.open_point(&commit_b)?;
        proof.commit_c = self.driver.open_point(&commit_c)?;

        Ok(outp)
    }

    // TODO parallelize
    fn compute_t(
        &mut self,
        challenges: &Challenges<T, P>,
        zkey: &ZKey<P>,
        z_poly: &PolyEval<T, P>,
        wire_poly: &WirePolyOutput<T, P>,
        round1_out: &WirePolyOutput<T, P>,
    ) -> Result<[FieldShareVec<T, P>; 3]> {
        // TODO Check if this root_of_unity is the one we need
        //TODO ALSO CACHE IT SO WE DO NOT NEED IT MULTIPLE TIMES
        let num_constraints = zkey.n_constraints;
        let domain1 = GeneralEvaluationDomain::<P::ScalarField>::new(num_constraints)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)
            .unwrap();
        let root_of_unity = CollaborativeGroth16::<T, P>::root_of_unity(&domain1);

        let mut w = P::ScalarField::one();
        let mut t_vec = Vec::with_capacity(zkey.domain_size * 4);
        let mut tz_vec = Vec::with_capacity(zkey.domain_size * 4);
        for i in 0..zkey.domain_size * 4 {
            //let a = zkey.
            let a = T::index_sharevec(&wire_poly.poly_eval_a.eval, i);
            let b = T::index_sharevec(&wire_poly.poly_eval_b.eval, i);
            let c = T::index_sharevec(&wire_poly.poly_eval_c.eval, i);
            let z = T::index_sharevec(&z_poly.eval, i);
            //const zw = evaluations.Z.getEvaluation((zkey.domainSize * 4 + 4 + i) % (zkey.domainSize * 4));
            let zw = T::index_sharevec(
                &z_poly.eval,
                (zkey.domain_size * 4 + 4 + i) % (zkey.domain_size * 4),
            );

            let qm = zkey.qm_poly.evaluations[i];
            let ql = zkey.ql_poly.evaluations[i];
            let qr = zkey.qr_poly.evaluations[i];
            let qo = zkey.qo_poly.evaluations[i];
            let qc = zkey.qc_poly.evaluations[i];
            let s1 = zkey.s1_poly.evaluations[i];
            let s2 = zkey.s2_poly.evaluations[i];
            let s3 = zkey.s3_poly.evaluations[i];

            let ap = self.driver.mul_with_public(&w, &challenges.b[0]);
            let ap = self.driver.add(&challenges.b[1], &ap);

            let bp = self.driver.mul_with_public(&w, &challenges.b[2]);
            let bp = self.driver.add(&challenges.b[3], &bp);

            let cp = self.driver.mul_with_public(&w, &challenges.b[4]);
            let cp = self.driver.add(&challenges.b[5], &cp);

            let w2 = w.square();
            //const zp = Fr.add(Fr.add(Fr.mul(challenges.b[7], w2), Fr.mul(challenges.b[8], w)), challenges.b[9]);
            let zp_lhs = self.driver.mul_with_public(&w2, &challenges.b[6]);
            let zp_rhs = self.driver.mul_with_public(&w, &challenges.b[7]);
            let zp = self.driver.add(&zp_lhs, &zp_rhs);
            let zp = self.driver.add(&challenges.b[8], &zp);
            let wW = w * root_of_unity;
            let wW2 = wW.square();
            let zWp_lhs = self.driver.mul_with_public(&wW2, &challenges.b[6]);
            let zWp_rhs = self.driver.mul_with_public(&wW, &challenges.b[7]);
            let zWp = self.driver.add(&zWp_lhs, &zWp_rhs);
            let zp = self.driver.add(&challenges.b[8], &zWp);

            let mut pi = self.driver.zero_share();
            for (j, lagrange) in zkey.lagrange.iter().enumerate() {
                let l_eval = lagrange.evaluations[i];
                let a_val = T::index_sharevec(&round1_out.buffer_a, j);
                let tmp = self.driver.mul_with_public(&l_eval, &a_val);
                pi = self.driver.sub(&pi, &tmp);
            }
            //todo
            let a_b = self.driver.mul(&a, &b)?;
            let a_bp = self.driver.mul(&a, &bp)?;
            let ap_b = self.driver.mul(&ap, &b)?;
            let ap_bp = self.driver.mul(&ap, &bp)?;
            let mut a0 = self.driver.add(&a_bp, &ap_b);
            let mod_i = i % 4;
            if mod_i != 0 {
                let z1 = Self::get_z1(&domain1)[mod_i];
                let tmp = self.driver.mul_with_public(&z1, &ap_bp);
                a0 = self.driver.add(&a0, &tmp);
            }
            let (mut e1, mut e1z) = (a_b, a0);
            e1 = self.driver.mul_with_public(&qm, &e1);
            e1z = self.driver.mul_with_public(&qm, &e1z);

            e1 = self.driver.add_mul_public(&e1, &a, &ql);
            e1z = self.driver.add_mul_public(&e1z, &ap, &ql);

            e1 = self.driver.add_mul_public(&e1, &b, &qr);
            e1z = self.driver.add_mul_public(&e1z, &bp, &qr);

            e1 = self.driver.add_mul_public(&e1, &c, &qo);
            e1z = self.driver.add_mul_public(&e1z, &cp, &qo);

            e1 = self.driver.add(&e1, &pi);
            e1 = self.driver.add_with_public(&qc, &e1);

            let betaw = challenges.beta * w; //self.driver.mul(challenges.beta, &w);
            let mut e2a = a.clone();
            e2a = self.driver.add_with_public(&betaw, &e2a);
            e2a = self.driver.add_with_public(&challenges.gamma, &e2a);

            let mut e2b = b.clone();
            e2b = self
                .driver
                .add_with_public(&(betaw + zkey.verifying_key.k1), &e2b);
            e2b = self.driver.add_with_public(&challenges.gamma, &e2b);

            let mut e2c = c.clone();
            e2c = self
                .driver
                .add_with_public(&(betaw + zkey.verifying_key.k2), &e2c);
            e2c = self.driver.add_with_public(&challenges.gamma, &e2c);

            let e2d = z.clone();

            let [mut e2, mut e2z] = mul4!(
                self.driver,
                &e2a,
                &e2b,
                &e2c,
                &e2d,
                &ap,
                &bp,
                &cp,
                &zp,
                &domain1,
                mod_i
            );

            e2 = self.driver.mul_with_public(&challenges.alpha, &e2);
            e2z = self.driver.mul_with_public(&challenges.alpha, &e2z);

            let mut e3a = a;
            e3a = self.driver.add_with_public(&(s1 * challenges.beta), &e3a);
            e3a = self.driver.add_with_public(&challenges.gamma, &e3a);

            let mut e3b = b;
            e3b = self.driver.add_with_public(&(s2 * challenges.beta), &e3b);
            e3b = self.driver.add_with_public(&challenges.gamma, &e3b);

            let mut e3c = c;
            e3c = self.driver.add_with_public(&(s3 * challenges.beta), &e3c);
            e3c = self.driver.add_with_public(&challenges.gamma, &e3c);

            let e3d = zw;
            let [mut e3, mut e3z] = mul4!(
                self.driver,
                &e3a,
                &e3b,
                &e3c,
                &e3d,
                &ap,
                &bp,
                &cp,
                &zWp,
                &domain1,
                mod_i
            );

            e3 = self.driver.mul_with_public(&challenges.alpha, &e3);
            e3z = self.driver.mul_with_public(&challenges.alpha, &e3z);

            let mut e4 = self.driver.add_with_public(&-P::ScalarField::one(), &z);
            //THIS IS MOST LIKELY WRONG
            e4 = self
                .driver
                .mul_with_public(&zkey.lagrange[0].evaluations[i], &e4);
            e4 = self.driver.mul_with_public(&challenges.alpha2, &e4);

            //THIS IS MOST LIKELY WRONG
            let mut e4z = self
                .driver
                .mul_with_public(&zkey.lagrange[0].evaluations[i], &zp);
            e4 = self.driver.mul_with_public(&challenges.alpha2, &e4z);

            let mut t = self.driver.add(&e1, &e2);
            t = self.driver.sub(&t, &e3);
            t = self.driver.add(&t, &e4);

            let mut tz = self.driver.add(&e1z, &e2z);
            tz = self.driver.sub(&tz, &e3z);
            tz = self.driver.add(&tz, &e4z);

            t_vec.push(t);
            tz_vec.push(tz);
            w *= root_of_unity;
        }
        let domain2 = GeneralEvaluationDomain::<P::ScalarField>::new(num_constraints * 4)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let mut coefficients_t = self.driver.ifft(&t_vec.into(), &domain2);
        self.driver.neg_vec_in_place(&mut coefficients_t);

        for i in zkey.domain_size..zkey.domain_size * 4 {
            let a_lhs = T::index_sharevec(&coefficients_t, i - zkey.domain_size);
            let a_rhs = T::index_sharevec(&coefficients_t, i);
            let a = self.driver.sub(&a_lhs, &a_rhs);
            T::set_index_sharevec(&mut coefficients_t, a, i);
            /*
            set check if poly is divisible here!
             */
        }

        let coefficients_tz = self.driver.ifft(&tz_vec.into(), &domain2);
        let t_final = self.driver.add_vec(&coefficients_t, &coefficients_tz);
        let mut t_final = t_final.into_iter();
        let mut t1 = Vec::with_capacity(zkey.domain_size);
        let mut t2 = Vec::with_capacity(zkey.domain_size);
        for _ in 0..zkey.domain_size {
            t1.push(t_final.next().unwrap());
        }
        for _ in 0..zkey.domain_size {
            t2.push(t_final.next().unwrap());
        }
        let mut t3 = t_final.collect::<Vec<_>>();
        t1.push(challenges.b[9].to_owned());

        t2[0] = self.driver.sub(&t2[0], &challenges.b[9]);
        t2.push(challenges.b[10].to_owned());

        t3[0] = self.driver.sub(&t3[0], &challenges.b[10]);

        Ok([t1.into(), t2.into(), t3.into()])
    }

    fn get_z1(domain: &GeneralEvaluationDomain<P::ScalarField>) -> [P::ScalarField; 4] {
        //TODO MOVE THIS THIS MUST BE A CONSTANT
        let zero = P::ScalarField::zero();
        let neg_1 = zero - P::ScalarField::one();
        let neg_2 = neg_1 - P::ScalarField::one();
        let root_of_unity = CollaborativeGroth16::<T, P>::root_of_unity(domain);
        [
            zero,
            neg_1.to_montgomery() + root_of_unity,
            neg_2.to_montgomery(),
            neg_1.to_montgomery() - root_of_unity,
        ]
    }

    fn get_z2(domain: &GeneralEvaluationDomain<P::ScalarField>) -> [P::ScalarField; 4] {
        //TODO MOVE THIS THIS MUST BE A CONSTANT
        let zero = P::ScalarField::zero();
        let two = P::ScalarField::one() + P::ScalarField::one();
        let four = two.square();
        let neg_2 = zero - two;
        let root_of_unity = CollaborativeGroth16::<T, P>::root_of_unity(domain);
        let neg2_root_unity = neg_2.to_montgomery() * root_of_unity;
        [
            zero,
            neg2_root_unity,
            four.to_montgomery(),
            P::ScalarField::zero() - neg2_root_unity,
        ]
    }

    fn get_z3(domain: &GeneralEvaluationDomain<P::ScalarField>) -> [P::ScalarField; 4] {
        //TODO MOVE THIS THIS MUST BE A CONSTANT
        let zero = P::ScalarField::zero();
        let two = P::ScalarField::one() + P::ScalarField::one();
        let neg_eight = -(two.square() * two);
        let root_of_unity = CollaborativeGroth16::<T, P>::root_of_unity(domain);
        let two_mont = two.to_montgomery();
        let two_root_unity = two_mont * root_of_unity;
        [
            zero,
            two_mont + two_root_unity,
            neg_eight.to_montgomery(),
            two_mont - two_root_unity,
        ]
    }

    // TODO parallelize
    fn compute_z(
        &mut self,
        challenges: &Challenges<T, P>,
        zkey: &ZKey<P>,
        round1_out: &WirePolyOutput<T, P>,
    ) -> Result<PolyEval<T, P>> {
        let mut num_arr = Vec::with_capacity(zkey.domain_size);
        let mut den_arr = Vec::with_capacity(zkey.domain_size);

        num_arr.push(self.driver.promote_to_trivial_share(P::ScalarField::one()));
        den_arr.push(self.driver.promote_to_trivial_share(P::ScalarField::one()));

        // TODO Check if this root_of_unity is the one we need
        let num_constraints = zkey.n_constraints;
        let domain1 = GeneralEvaluationDomain::<P::ScalarField>::new(num_constraints)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let root_of_unity = CollaborativeGroth16::<T, P>::root_of_unity(&domain1);

        let mut w = P::ScalarField::one();
        for i in 0..zkey.domain_size {
            let a = T::index_sharevec(&round1_out.buffer_a, i);
            let b = T::index_sharevec(&round1_out.buffer_b, i);
            let c = T::index_sharevec(&round1_out.buffer_c, i);

            // Z(X) := numArr / denArr
            // numArr := (a + beta·ω + gamma)(b + beta·ω·k1 + gamma)(c + beta·ω·k2 + gamma)
            let betaw = challenges.beta * w;

            let n1 = self.driver.add_with_public(&betaw, &a);
            let n1 = self.driver.add_with_public(&challenges.gamma, &n1);

            let tmp = zkey.verifying_key.k1 * betaw;
            let n2 = self.driver.add_with_public(&tmp, &b);
            let n2 = self.driver.add_with_public(&challenges.gamma, &n2);

            let tmp = zkey.verifying_key.k2 * betaw;
            let n3 = self.driver.add_with_public(&tmp, &c);
            let n3 = self.driver.add_with_public(&challenges.gamma, &n3);

            let num = self.driver.mul(&n1, &n2)?;
            let mut num = self.driver.mul(&num, &n3)?;

            // denArr := (a + beta·sigma1 + gamma)(b + beta·sigma2 + gamma)(c + beta·sigma3 + gamma)
            let d1 = self
                .driver
                .add_with_public(&(challenges.beta * zkey.s1_poly.evaluations[i * 4]), &a);
            let d1 = self.driver.add_with_public(&challenges.gamma, &d1);

            let d2 = self
                .driver
                .add_with_public(&(challenges.beta * zkey.s2_poly.evaluations[i * 4]), &b);
            let d2 = self.driver.add_with_public(&challenges.gamma, &d2);

            let d3 = self
                .driver
                .add_with_public(&(challenges.beta * zkey.s3_poly.evaluations[i * 4]), &c);
            let d3 = self.driver.add_with_public(&challenges.gamma, &d3);

            // TODO parallelize with num above
            let den = self.driver.mul(&d1, &d2)?;
            let mut den = self.driver.mul(&den, &d3)?;

            // Multiply current num value with the previous one saved in num_arr/den_arr
            if i != 0 {
                // TODO parallelize
                num = self.driver.mul(&num, &num_arr[i])?;
                den = self.driver.mul(&den, &den_arr[i])?;
            }

            if i == zkey.domain_size - 1 {
                num_arr[0] = num;
                den_arr[0] = den;
            } else {
                num_arr.push(num);
                den_arr.push(den);
            }

            w.mul_assign(&root_of_unity);
        }

        // Compute the inverse of denArr to compute in the next command the
        // division numArr/denArr by multiplying num · 1/denArr
        for den_arr in den_arr.iter_mut() {
            // TODO parallerlize
            *den_arr = self.driver.inv(den_arr)?;
        }
        let buffer_z = self.driver.mul_vec(&num_arr.into(), &den_arr.into())?;

        // Compute polynomial coefficients z(X) from buffer_z
        let poly_z = self.driver.ifft(&buffer_z, &domain1);

        // Compute extended evaluations of z(X) polynomial
        let domain2 = GeneralEvaluationDomain::<P::ScalarField>::new(num_constraints * 4)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let eval_z = self.driver.fft(poly_z.to_owned(), &domain2);

        let poly_z = self.blind_coefficients(&poly_z, &challenges.b[6..9]);

        if poly_z.len() > zkey.domain_size + 3 {
            return Err(SynthesisError::PolynomialDegreeTooLarge.into());
        }

        Ok(PolyEval {
            poly: poly_z.into(),
            eval: eval_z,
        })
    }

    fn compute_r(
        &mut self,
        challenges: &Challenges<T, P>,
        proof: &Proof<P>,
        zkey: &ZKey<P>,
        private_witness: &SharedWitness<T, P>,
        poly_z: &PolyEval<T, P>,
        poly_t: &TPoly<T, P>,
    ) -> FieldShareVec<T, P> {
        let mut xin = challenges.xi;
        let power = usize::ilog2(zkey.domain_size); // TODO check if true
        for _ in 0..power {
            xin.square_in_place();
        }
        let zh = xin - P::ScalarField::one();

        // TODO Check if this root_of_unity is the one we need
        // TODO this is duplicate from compute_z
        let num_constraints = zkey.n_constraints;
        let domain1 = GeneralEvaluationDomain::<P::ScalarField>::new(num_constraints)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)
            .unwrap(); // TODO There is an unwrap here
        let root_of_unity = CollaborativeGroth16::<T, P>::root_of_unity(&domain1);

        let l_length = usize::max(1, zkey.n_public);
        let mut l = Vec::with_capacity(l_length);

        let n = P::ScalarField::from(zkey.domain_size as u64);
        let mut w = P::ScalarField::one();
        for _ in 0..l_length {
            l.push((w * zh) / (n * (challenges.xi - w)));
            w *= root_of_unity;
        }

        let eval_l1 = (xin - P::ScalarField::one()) / (n * (challenges.xi - P::ScalarField::one()));

        let mut eval_pi = P::ScalarField::zero();
        for (val, l) in private_witness.public_inputs.iter().zip(l) {
            eval_pi -= l * val;
        }

        let coef_ab = proof.eval_a * proof.eval_b;
        let betaxi = challenges.beta * challenges.xi;
        let e2a = proof.eval_a + betaxi + challenges.gamma;
        let e2b = proof.eval_b + betaxi * zkey.verifying_key.k1 + challenges.gamma;
        let e2c = proof.eval_c + betaxi * zkey.verifying_key.k2 + challenges.gamma;
        let e2 = e2a * e2b * e2c * challenges.alpha;

        let e3a = proof.eval_a + challenges.beta * proof.eval_s1 + challenges.gamma;
        let e3b = proof.eval_b + challenges.beta * proof.eval_s2 + challenges.gamma;
        let e3 = e3a * e3b * proof.eval_zw * challenges.alpha;

        let e4 = eval_l1 * challenges.alpha.square();
        let e24 = e2 + e4;

        let mut poly_r = zkey.qm_poly.coeffs.clone();
        for coeff in poly_r.iter_mut() {
            *coeff *= coef_ab;
        }
        Self::add_factor_poly(&mut poly_r, &zkey.ql_poly.coeffs, proof.eval_a);
        Self::add_factor_poly(&mut poly_r, &zkey.qr_poly.coeffs, proof.eval_b);
        Self::add_factor_poly(&mut poly_r, &zkey.qo_poly.coeffs, proof.eval_c);
        Self::add_poly(&mut poly_r, &zkey.qc_poly.coeffs);
        Self::add_factor_poly(&mut poly_r, &zkey.s3_poly.coeffs, -(e3 * challenges.beta));

        let len = usize::max(T::sharevec_len(&poly_z.poly), poly_r.len());
        let len = usize::max(len, T::sharevec_len(&poly_t.t1));
        let len = usize::max(len, T::sharevec_len(&poly_t.t2));
        let len = usize::max(len, T::sharevec_len(&poly_t.t3));

        let mut poly_r_shared = vec![FieldShare::<T, P>::default(); len];

        for (inout, add) in poly_r_shared
            .iter_mut()
            .zip(poly_z.poly.clone().into_iter())
        {
            *inout = self.driver.mul_with_public(&e24, &add)
        }

        for (inout, add) in poly_r_shared.iter_mut().zip(poly_r.iter()) {
            *inout = self.driver.add_with_public(add, inout);
        }

        let mut tmp_poly = vec![FieldShare::<T, P>::default(); len];
        let xin2 = xin.square();
        for (inout, add) in tmp_poly.iter_mut().zip(poly_t.t3.clone().into_iter()) {
            *inout = self.driver.mul_with_public(&xin2, &add);
        }
        for (inout, add) in tmp_poly.iter_mut().zip(poly_t.t2.clone().into_iter()) {
            let tmp = self.driver.mul_with_public(&xin, &add);
            *inout = self.driver.add(&tmp, inout);
        }
        for (inout, add) in tmp_poly.iter_mut().zip(poly_t.t1.clone().into_iter()) {
            *inout = self.driver.add(inout, &add);
        }
        for inout in tmp_poly.iter_mut() {
            *inout = self.driver.mul_with_public(&zh, inout);
        }

        for (inout, sub) in poly_r_shared.iter_mut().zip(tmp_poly.iter()) {
            *inout = self.driver.sub(inout, sub);
        }

        let r0 = eval_pi - (e3 * (proof.eval_c + challenges.gamma)) - e4;

        poly_r_shared[0] = self.driver.add_with_public(&r0, &poly_r_shared[0]);
        poly_r_shared.into()
    }

    fn compute_wxi(
        &mut self,
        challenges: &Challenges<T, P>,
        proof: &Proof<P>,
        zkey: &ZKey<P>,
        round1_out: &WirePolyOutput<T, P>,
        poly_r: &FieldShareVec<T, P>,
    ) -> FieldShareVec<T, P> {
        let len = usize::max(
            T::sharevec_len(poly_r),
            T::sharevec_len(&round1_out.poly_eval_a.poly),
        );
        let len = usize::max(len, T::sharevec_len(&round1_out.poly_eval_b.poly));
        let len = usize::max(len, T::sharevec_len(&round1_out.poly_eval_c.poly));
        let len = usize::max(len, zkey.s1_poly.coeffs.len());
        let len = usize::max(len, zkey.s2_poly.coeffs.len());

        let mut res = vec![FieldShare::<T, P>::default(); len];

        // R
        for (inout, add) in res.iter_mut().zip(poly_r.clone().into_iter()) {
            *inout = add;
        }
        // A
        for (inout, add) in res
            .iter_mut()
            .zip(round1_out.poly_eval_a.poly.clone().into_iter())
        {
            let tmp = self.driver.mul_with_public(&challenges.v[0], &add);
            *inout = self.driver.add(&tmp, inout);
        }
        // B
        for (inout, add) in res
            .iter_mut()
            .zip(round1_out.poly_eval_b.poly.clone().into_iter())
        {
            let tmp = self.driver.mul_with_public(&challenges.v[1], &add);
            *inout = self.driver.add(&tmp, inout);
        }
        // C
        for (inout, add) in res
            .iter_mut()
            .zip(round1_out.poly_eval_c.poly.clone().into_iter())
        {
            let tmp = self.driver.mul_with_public(&challenges.v[2], &add);
            *inout = self.driver.add(&tmp, inout);
        }
        // Sigma1
        for (inout, add) in res.iter_mut().zip(zkey.s1_poly.coeffs.iter()) {
            *inout = self.driver.add_with_public(&(challenges.v[3] * add), inout);
        }
        // Sigma2
        for (inout, add) in res.iter_mut().zip(zkey.s2_poly.coeffs.iter()) {
            *inout = self.driver.add_with_public(&(challenges.v[4] * add), inout);
        }

        res[0] = self
            .driver
            .add_with_public(&-(challenges.v[0] * proof.eval_a), &res[0]);
        res[0] = self
            .driver
            .add_with_public(&-(challenges.v[1] * proof.eval_b), &res[0]);
        res[0] = self
            .driver
            .add_with_public(&-(challenges.v[2] * proof.eval_c), &res[0]);
        res[0] = self
            .driver
            .add_with_public(&-(challenges.v[3] * proof.eval_s1), &res[0]);
        res[0] = self
            .driver
            .add_with_public(&-(challenges.v[4] * proof.eval_s2), &res[0]);

        self.div_by_zerofier(&mut res, 1, challenges.xi);

        res.into()
    }

    fn compute_wxiw(
        &mut self,
        challenges: &Challenges<T, P>,
        proof: &Proof<P>,
        zkey: &ZKey<P>,
        poly_z: &PolyEval<T, P>,
    ) -> FieldShareVec<T, P> {
        // TODO Check if this root_of_unity is the one we need
        // TODO this is duplicate from compute_z
        let num_constraints = zkey.n_constraints;
        let domain1 = GeneralEvaluationDomain::<P::ScalarField>::new(num_constraints)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)
            .unwrap(); // TODO unrwap here
        let root_of_unity = CollaborativeGroth16::<T, P>::root_of_unity(&domain1);

        let xiw = challenges.xi * root_of_unity;

        let mut res = poly_z.poly.clone().into_iter().collect::<Vec<_>>();
        res[0] = self.driver.add_with_public(&-proof.eval_zw, &res[0]);
        self.div_by_zerofier(&mut res, 1, xiw);

        res.into()
    }

    fn evaluate_poly(
        &mut self,
        poly: &FieldShareVec<T, P>,
        x: &P::ScalarField,
    ) -> FieldShare<T, P> {
        let mut res = FieldShare::<T, P>::default();
        let mut x_pow = P::ScalarField::one();
        for coeff in poly.clone().into_iter() {
            let tmp = self.driver.mul_with_public(&x_pow, &coeff);
            res = self.driver.add(&res, &tmp);
            x_pow *= x;
        }
        res
    }

    fn add_poly(inout: &mut Vec<P::ScalarField>, add_poly: &[P::ScalarField]) {
        if add_poly.len() > inout.len() {
            inout.resize(add_poly.len(), P::ScalarField::zero());
        }

        for (inout, add) in inout.iter_mut().zip(add_poly.iter()) {
            *inout += *add;
        }
    }

    fn add_factor_poly(
        inout: &mut Vec<P::ScalarField>,
        add_poly: &[P::ScalarField],
        factor: P::ScalarField,
    ) {
        if add_poly.len() > inout.len() {
            inout.resize(add_poly.len(), P::ScalarField::zero());
        }

        for (inout, add) in inout.iter_mut().zip(add_poly.iter()) {
            *inout += *add * factor;
        }
    }

    fn div_by_zerofier(
        &mut self,
        inout: &mut Vec<FieldShare<T, P>>,
        n: usize,
        beta: P::ScalarField,
    ) {
        let inv_beta = beta.inverse().expect("Highly unlikely to be zero");
        let inv_beta_neg = -inv_beta;

        let mut is_one = inv_beta_neg.is_one();
        let mut is_negone = inv_beta.is_one();

        if !is_one {
            for el in inout.iter_mut().take(n) {
                if is_negone {
                    *el = self.driver.neg(el);
                } else {
                    *el = self.driver.mul_with_public(&inv_beta_neg, el);
                }
            }
        }

        std::mem::swap(&mut is_negone, &mut is_one);

        for i in n..inout.len() {
            let element = self.driver.sub(&inout[i - n], &inout[i]);

            if !is_one {
                if is_negone {
                    inout[i] = self.driver.neg(&element);
                } else {
                    inout[i] = self.driver.mul_with_public(&inv_beta, &element);
                }
            }
        }
        // We cannot check whether the polyonmial is divisible by the zerofier, but we resize accordingly
        inout.resize(inout.len() - n, FieldShare::<T, P>::default());
    }

    fn round2(
        &mut self,
        transcript: &mut Keccak256Transcript<P>,
        challenges: &mut Challenges<T, P>,
        proof: &mut Proof<P>,
        zkey: &ZKey<P>,
        private_witness: &SharedWitness<T, P>,
        round1_out: &WirePolyOutput<T, P>,
    ) -> Result<PolyEval<T, P>> {
        // STEP 2.1 - Compute permutation challenge beta and gamma \in F_p

        // Compute permutation challenge beta
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
        transcript.add_scalar(challenges.beta);
        challenges.gamma = transcript.get_challenge();

        // STEP 2.2 - Compute permutation polynomial z(X)
        let poly_eval_z = self.compute_z(challenges, zkey, round1_out)?;

        // STEP 2.3 - Compute permutation [z]_1
        let commit_z = MSMProvider::<P::G1>::msm_public_points(
            &mut self.driver,
            &zkey.p_tau,
            &poly_eval_z.poly,
        );

        proof.commit_z = self.driver.open_point(&commit_z)?;

        Ok(poly_eval_z)
    }

    fn round3(
        &mut self,
        transcript: &mut Keccak256Transcript<P>,
        challenges: &mut Challenges<T, P>,
        proof: &mut Proof<P>,
        zkey: &ZKey<P>,
        z_poly: &PolyEval<T, P>,
        wire_poly: &WirePolyOutput<T, P>,
        round1_out: &WirePolyOutput<T, P>,
    ) -> Result<TPoly<T, P>> {
        // STEP 3.1 - Compute evaluation challenge alpha ∈ F
        transcript.add_scalar(challenges.beta);
        transcript.add_scalar(challenges.gamma);
        transcript.add_poly_commitment(proof.commit_z.into());

        challenges.alpha = transcript.get_challenge();
        challenges.alpha2 = challenges.alpha.square();

        // Compute quotient polynomial T(X)
        let [t1, t2, t3] = self.compute_t(challenges, zkey, z_poly, wire_poly, round1_out)?;

        // Compute [T1]_1, [T2]_1, [T3]_1
        let commit_a = MSMProvider::<P::G1>::msm_public_points(&mut self.driver, &zkey.p_tau, &t1);
        let commit_b = MSMProvider::<P::G1>::msm_public_points(&mut self.driver, &zkey.p_tau, &t2);
        let commit_c = MSMProvider::<P::G1>::msm_public_points(&mut self.driver, &zkey.p_tau, &t3);

        // TODO parallelize
        proof.commit_a = self.driver.open_point(&commit_a)?;
        proof.commit_b = self.driver.open_point(&commit_b)?;
        proof.commit_c = self.driver.open_point(&commit_c)?;
        Ok(TPoly { t1, t2, t3 })
    }

    fn round4(
        &mut self,
        transcript: &mut Keccak256Transcript<P>,
        challenges: &mut Challenges<T, P>,
        proof: &mut Proof<P>,
        zkey: &ZKey<P>,
        round1_out: &WirePolyOutput<T, P>,
        poly_z: &PolyEval<T, P>,
    ) -> Result<()> {
        // STEP 4.1 - Compute evaluation challenge xi \in F_p
        transcript.add_scalar(challenges.alpha);
        transcript.add_poly_commitment(proof.commit_t1.into());
        transcript.add_poly_commitment(proof.commit_t2.into());
        transcript.add_poly_commitment(proof.commit_t3.into());

        challenges.xi = transcript.get_challenge();

        // TODO Check if this root_of_unity is the one we need
        // TODO this is duplicate from compute_z
        let num_constraints = zkey.n_constraints;
        let domain1 = GeneralEvaluationDomain::<P::ScalarField>::new(num_constraints)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let root_of_unity = CollaborativeGroth16::<T, P>::root_of_unity(&domain1);

        let xiw = challenges.xi * root_of_unity;

        let eval_a = self.evaluate_poly(&round1_out.poly_eval_a.poly, &challenges.xi);
        let eval_b = self.evaluate_poly(&round1_out.poly_eval_b.poly, &challenges.xi);
        let eval_c = self.evaluate_poly(&round1_out.poly_eval_c.poly, &challenges.xi);
        let eval_z = self.evaluate_poly(&poly_z.poly, &xiw);

        // TODO parallelize
        proof.eval_a = self.driver.open(&eval_a)?;
        proof.eval_b = self.driver.open(&eval_b)?;
        proof.eval_c = self.driver.open(&eval_c)?;
        proof.eval_zw = self.driver.open(&eval_z)?;

        proof.eval_s1 = zkey.s1_poly.evaluate(&challenges.xi);
        proof.eval_s2 = zkey.s2_poly.evaluate(&challenges.xi);
        Ok(())
    }

    fn round5(
        &mut self,
        transcript: &mut Keccak256Transcript<P>,
        challenges: &mut Challenges<T, P>,
        proof: &mut Proof<P>,
        zkey: &ZKey<P>,
        private_witness: &SharedWitness<T, P>,
        round1_out: &WirePolyOutput<T, P>,
        poly_z: &PolyEval<T, P>,
        poly_t: &TPoly<T, P>,
    ) -> Result<()> {
        // STEP 5.1 - Compute evaluation challenge v \in F_p
        transcript.add_scalar(challenges.xi);
        transcript.add_scalar(proof.eval_a);
        transcript.add_scalar(proof.eval_b);
        transcript.add_scalar(proof.eval_c);
        transcript.add_scalar(proof.eval_s1);
        transcript.add_scalar(proof.eval_s2);
        transcript.add_scalar(proof.eval_zw);

        challenges.v[0] = transcript.get_challenge();
        for i in 1..5 {
            challenges.v[i] = challenges.v[i - 1] * challenges.v[0];
        }

        // STEP 5.2 Compute linearisation polynomial r(X)
        let poly_r = self.compute_r(challenges, proof, zkey, private_witness, poly_z, poly_t);

        //STEP 5.3 Compute opening proof polynomial Wxi(X)
        let poly_wxi = self.compute_wxi(challenges, proof, zkey, round1_out, &poly_r);

        //STEP 5.4 Compute opening proof polynomial Wxiw(X)
        let poly_wxiw = self.compute_wxiw(challenges, proof, zkey, poly_z);

        // Fifth output of the prover is ([Wxi]_1, [Wxiw]_1)
        let commit_wxi =
            MSMProvider::<P::G1>::msm_public_points(&mut self.driver, &zkey.p_tau, &poly_wxi);
        let commit_wxiw =
            MSMProvider::<P::G1>::msm_public_points(&mut self.driver, &zkey.p_tau, &poly_wxiw);

        // TODO parallelize
        proof.commit_wxi = self.driver.open_point(&commit_wxi)?;
        proof.commit_wxiw = self.driver.open_point(&commit_wxiw)?;
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
        let is_challenge = transcript.get_challenge();
        assert_eq!(
            ark_bn254::Fr::from_str(
                "21571066717628871486594124342047303120063887347042301886903413955514057146987",
            )
            .unwrap(),
            is_challenge
        );
    }
}
