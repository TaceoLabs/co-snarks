use crate::{
    round2::{Round2Challenges, Round2Polys, Round2Proof},
    round4::Round4,
    types::{Keccak256Transcript, PolyEval},
    Domains, FieldShareVec, PlonkData, PlonkProofResult,
};
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use circom_types::plonk::ZKey;
use mpc_core::traits::{
    FFTPostProcessing, FFTProvider, FieldShareVecTrait, MSMProvider, PairingEcMpcProtocol,
    PrimeFieldMpcProtocol,
};
use num_traits::One;
use num_traits::Zero;

// TODO parallelize these?
macro_rules! mul4vec {
    ($driver: expr, $a: expr,$b: expr,$c: expr,$d: expr,$ap: expr,$bp: expr,$cp: expr,$dp: expr, $domain: expr) => {{
        let a_b = $driver.mul_vec($a, $b)?;
        let a_bp = $driver.mul_vec($a, $bp)?;
        let ap_b = $driver.mul_vec($ap, $b)?;
        let ap_bp = $driver.mul_vec($ap, $bp)?;

        let c_d = $driver.mul_vec($c, $d)?;
        let c_dp = $driver.mul_vec($c, $dp)?;
        let cp_d = $driver.mul_vec($cp, $d)?;
        let cp_dp = $driver.mul_vec($cp, $dp)?;

        let r = $driver.mul_vec(&a_b, &c_d)?;

        let mut a0 = $driver.mul_vec(&ap_b, &c_d)?;
        a0 = $driver.add_mul_vec(&a0, &a_bp, &c_d)?;
        a0 = $driver.add_mul_vec(&a0, &a_b, &cp_d)?;
        a0 = $driver.add_mul_vec(&a0, &a_b, &c_dp)?;

        let mut a1 = $driver.mul_vec(&ap_bp, &c_d)?;
        a1 = $driver.add_mul_vec(&a1, &ap_b, &cp_d)?;
        a1 = $driver.add_mul_vec(&a1, &ap_b, &c_dp)?;
        a1 = $driver.add_mul_vec(&a1, &a_bp, &cp_d)?;
        a1 = $driver.add_mul_vec(&a1, &a_bp, &c_dp)?;
        a1 = $driver.add_mul_vec(&a1, &a_b, &cp_dp)?;

        let mut a2 = $driver.mul_vec(&a_bp, &cp_dp)?;
        a2 = $driver.add_mul_vec(&a2, &ap_b, &cp_dp)?;
        a2 = $driver.add_mul_vec(&a2, &ap_bp, &c_dp)?;
        a2 = $driver.add_mul_vec(&a2, &ap_bp, &cp_d)?;

        let a3 = $driver.mul_vec(&ap_bp, &cp_dp)?;
        [r, a0, a1, a2, a3]
    }};
}

macro_rules! mul4vec_post {
    ($driver: expr, $a: expr,$b: expr,$c: expr,$d: expr,$i: expr, $z1: expr, $z2: expr, $z3: expr) => {{
        let mod_i = $i % 4;
        let mut rz = $a.index($i);
        if mod_i != 0 {
            let b = $b.index($i);
            let c = $c.index($i);
            let d = $d.index($i);
            let tmp = $driver.mul_with_public(&$z1[mod_i], &b);
            rz = $driver.add(&rz, &tmp);
            let tmp = $driver.mul_with_public(&$z2[mod_i], &c);
            rz = $driver.add(&rz, &tmp);
            let tmp = $driver.mul_with_public(&$z3[mod_i], &d);
            rz = $driver.add(&rz, &tmp);
        }
        rz
    }};
}

pub(super) struct Round3<T, P: Pairing>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>
        + MSMProvider<P::G1>
        + MSMProvider<P::G2>,
    P::ScalarField: mpc_core::traits::FFTPostProcessing,
{
    pub(super) driver: T,
    pub(super) domains: Domains<P::ScalarField>,
    pub(super) challenges: Round2Challenges<T, P>,
    pub(super) proof: Round2Proof<P>,
    pub(super) polys: Round2Polys<T, P>,
    pub(super) data: PlonkData<T, P>,
}

pub(super) struct Round3Proof<P: Pairing> {
    pub(super) commit_a: P::G1,
    pub(super) commit_b: P::G1,
    pub(super) commit_c: P::G1,
    pub(super) commit_z: P::G1,
    pub(super) commit_t1: P::G1,
    pub(super) commit_t2: P::G1,
    pub(super) commit_t3: P::G1,
}

impl<P: Pairing> Round3Proof<P> {
    fn new(
        round2_proof: Round2Proof<P>,
        commit_t1: P::G1,
        commit_t2: P::G1,
        commit_t3: P::G1,
    ) -> Self {
        Self {
            commit_a: round2_proof.commit_a,
            commit_b: round2_proof.commit_b,
            commit_c: round2_proof.commit_c,
            commit_z: round2_proof.commit_z,
            commit_t1,
            commit_t2,
            commit_t3,
        }
    }
}
pub(super) struct Round3Challenges<T, P: Pairing>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    pub(super) b: [T::FieldShare; 11],
    pub(super) beta: P::ScalarField,
    pub(super) gamma: P::ScalarField,
    pub(super) alpha: P::ScalarField,
    pub(super) alpha2: P::ScalarField,
}

pub(super) struct FinalPolys<T, P: Pairing>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    pub(super) a: PolyEval<T, P>,
    pub(super) b: PolyEval<T, P>,
    pub(super) c: PolyEval<T, P>,
    pub(super) z: PolyEval<T, P>,
    pub(super) t1: FieldShareVec<T, P>,
    pub(super) t2: FieldShareVec<T, P>,
    pub(super) t3: FieldShareVec<T, P>,
}
impl<T, P: Pairing> FinalPolys<T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    fn new(
        polys: Round2Polys<T, P>,
        t1: FieldShareVec<T, P>,
        t2: FieldShareVec<T, P>,
        t3: FieldShareVec<T, P>,
    ) -> Self {
        Self {
            a: polys.poly_eval_a,
            b: polys.poly_eval_b,
            c: polys.poly_eval_c,
            z: polys.z,
            t1,
            t2,
            t3,
        }
    }
}

impl<T, P: Pairing> Round3Challenges<T, P>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    fn new(
        round2_challenges: Round2Challenges<T, P>,
        alpha: P::ScalarField,
        alpha2: P::ScalarField,
    ) -> Self {
        Self {
            b: round2_challenges.b,
            beta: round2_challenges.beta,
            gamma: round2_challenges.gamma,
            alpha,
            alpha2,
        }
    }
}

impl<T, P: Pairing> Round3<T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>
        + MSMProvider<P::G1>
        + MSMProvider<P::G2>,
    P::ScalarField: FFTPostProcessing,
{
    fn get_z1(domains: &Domains<P::ScalarField>) -> [P::ScalarField; 4] {
        //TODO MOVE THIS THIS MUST BE A CONSTANT
        let zero = P::ScalarField::zero();
        let neg_1 = zero - P::ScalarField::one();
        let neg_2 = neg_1 - P::ScalarField::one();
        let root_of_unity = domains.roots_of_unity[2];
        [zero, neg_1 + root_of_unity, neg_2, neg_1 - root_of_unity]
    }

    fn get_z2(domains: &Domains<P::ScalarField>) -> [P::ScalarField; 4] {
        let zero = P::ScalarField::zero();
        let two = P::ScalarField::one() + P::ScalarField::one();
        let four = two.square();
        let neg_2 = zero - two;
        let root_of_unity = domains.roots_of_unity[2];
        let neg2_root_unity = neg_2 * root_of_unity;
        [
            zero,
            neg2_root_unity,
            four,
            P::ScalarField::zero() - neg2_root_unity,
        ]
    }

    fn get_z3(domains: &Domains<P::ScalarField>) -> [P::ScalarField; 4] {
        let zero = P::ScalarField::zero();
        let two = P::ScalarField::one() + P::ScalarField::one();
        let neg_eight = -(two.square() * two);
        let root_of_unity = domains.roots_of_unity[2];
        let two_root_unity = two * root_of_unity;
        [zero, two + two_root_unity, neg_eight, two - two_root_unity]
    }
    fn compute_t(
        driver: &mut T,
        domains: &Domains<P::ScalarField>,
        challenges: &Round3Challenges<T, P>,
        zkey: &ZKey<P>,
        polys: &Round2Polys<T, P>,
    ) -> PlonkProofResult<[FieldShareVec<T, P>; 3]> {
        let z1 = Self::get_z1(domains);
        let z2 = Self::get_z2(domains);
        let z3 = Self::get_z3(domains);
        let mut w = P::ScalarField::one();
        let mut ap = Vec::with_capacity(zkey.domain_size * 4);
        let mut bp = Vec::with_capacity(zkey.domain_size * 4);
        let mut cp = Vec::with_capacity(zkey.domain_size * 4);

        let pow_root_of_unity = domains.roots_of_unity[zkey.power];
        let pow_plus2_root_of_unity = domains.roots_of_unity[zkey.power + 2];
        for _ in 0..zkey.domain_size * 4 {
            ap.push(driver.add_mul_public(&challenges.b[1], &challenges.b[0], &w));
            bp.push(driver.add_mul_public(&challenges.b[3], &challenges.b[2], &w));
            cp.push(driver.add_mul_public(&challenges.b[5], &challenges.b[4], &w));
            w *= &pow_plus2_root_of_unity;
        }

        let ap_vec: FieldShareVec<T, P> = ap.into();
        let bp_vec: FieldShareVec<T, P> = bp.into();
        let cp_vec: FieldShareVec<T, P> = cp.into();

        // TODO parallelize these?
        let a_b = driver.mul_vec(&polys.poly_eval_a.eval, &polys.poly_eval_b.eval)?;
        let a_bp = driver.mul_vec(&polys.poly_eval_a.eval, &bp_vec)?;
        let ap_b = driver.mul_vec(&polys.poly_eval_b.eval, &ap_vec)?;
        let ap_bp = driver.mul_vec(&ap_vec, &bp_vec)?;

        let mut e1 = Vec::with_capacity(zkey.domain_size * 4);
        let mut e1z = Vec::with_capacity(zkey.domain_size * 4);

        let mut e2a = Vec::with_capacity(zkey.domain_size * 4);
        let mut e2b = Vec::with_capacity(zkey.domain_size * 4);
        let mut e2c = Vec::with_capacity(zkey.domain_size * 4);
        let mut e2d = Vec::with_capacity(zkey.domain_size * 4);
        let mut zp = Vec::with_capacity(zkey.domain_size * 4);

        let mut e3a = Vec::with_capacity(zkey.domain_size * 4);
        let mut e3b = Vec::with_capacity(zkey.domain_size * 4);
        let mut e3c = Vec::with_capacity(zkey.domain_size * 4);
        let mut e3d = Vec::with_capacity(zkey.domain_size * 4);
        let mut zwp = Vec::with_capacity(zkey.domain_size * 4);
        let mut w = P::ScalarField::one();
        // We do not want to have any network operation in here to reduce MPC rounds. To enforce this, we have a for_each loop here (Network operations require a result)
        (0..zkey.domain_size * 4).for_each(|i| {
            let a = polys.poly_eval_a.eval.index(i);
            let b = polys.poly_eval_b.eval.index(i);
            let c = polys.poly_eval_c.eval.index(i);
            let z = polys.z.eval.index(i);
            let qm = zkey.qm_poly.evaluations[i];
            let ql = zkey.ql_poly.evaluations[i];
            let qr = zkey.qr_poly.evaluations[i];
            let qo = zkey.qo_poly.evaluations[i];
            let qc = zkey.qc_poly.evaluations[i];
            let s1 = zkey.s1_poly.evaluations[i];
            let s2 = zkey.s2_poly.evaluations[i];
            let s3 = zkey.s3_poly.evaluations[i];
            let a_bp = a_bp.index(i);
            let a_b = a_b.index(i);
            let ap_b = ap_b.index(i);
            let ap = ap_vec.index(i);
            let bp = bp_vec.index(i);

            let w2 = w.square();
            let zp_lhs = driver.mul_with_public(&w2, &challenges.b[6]);
            let zp_rhs = driver.mul_with_public(&w, &challenges.b[7]);
            let zp_ = driver.add(&zp_lhs, &zp_rhs);
            let zp_ = driver.add(&challenges.b[8], &zp_);
            zp.push(zp_);

            let w_w = w * pow_root_of_unity;
            let w_w2 = w_w.square();
            let zw = polys
                .z
                .eval
                .index((zkey.domain_size * 4 + 4 + i) % (zkey.domain_size * 4));
            let zwp_lhs = driver.mul_with_public(&w_w2, &challenges.b[6]);
            let zwp_rhs = driver.mul_with_public(&w_w, &challenges.b[7]);
            let zwp_ = driver.add(&zwp_lhs, &zwp_rhs);
            let zwp_ = driver.add(&challenges.b[8], &zwp_);
            zwp.push(zwp_);

            let mut a0 = driver.add(&a_bp, &ap_b);
            let mod_i = i % 4;
            if mod_i != 0 {
                let z1 = z1[mod_i];
                let ap_bp = ap_bp.index(i);
                let tmp = driver.mul_with_public(&z1, &ap_bp);
                a0 = driver.add(&a0, &tmp);
            }

            let (mut e1_, mut e1z_) = (a_b, a0);
            e1_ = driver.mul_with_public(&qm, &e1_);
            e1z_ = driver.mul_with_public(&qm, &e1z_);

            e1_ = driver.add_mul_public(&e1_, &a, &ql);
            e1z_ = driver.add_mul_public(&e1z_, &ap, &ql);

            e1_ = driver.add_mul_public(&e1_, &b, &qr);
            e1z_ = driver.add_mul_public(&e1z_, &bp, &qr);

            e1_ = driver.add_mul_public(&e1_, &c, &qo);
            e1z_ = driver.add_mul_public(&e1z_, &cp_vec.index(i), &qo);

            let mut pi = T::zero_share();
            for (j, lagrange) in zkey.lagrange.iter().enumerate() {
                let l_eval = lagrange.evaluations[i];
                let a_val = polys.buffer_a.index(j);
                let tmp = driver.mul_with_public(&l_eval, &a_val);
                pi = driver.sub(&pi, &tmp);
            }

            e1_ = driver.add(&e1_, &pi);
            e1_ = driver.add_with_public(&qc, &e1_);
            e1.push(e1_);
            e1z.push(e1z_);

            let betaw = challenges.beta * w;
            e2a.push(driver.add_with_public(&(betaw + challenges.gamma), &a));
            e2b.push(
                driver.add_with_public(&(betaw * zkey.verifying_key.k1 + challenges.gamma), &b),
            );
            e2c.push(
                driver.add_with_public(&(betaw * zkey.verifying_key.k2 + challenges.gamma), &c),
            );

            e2d.push(z.clone());
            e3a.push(driver.add_with_public(&(s1 * challenges.beta + challenges.gamma), &a));
            e3b.push(driver.add_with_public(&(s2 * challenges.beta + challenges.gamma), &b));
            e3c.push(driver.add_with_public(&(s3 * challenges.beta + challenges.gamma), &c));
            e3d.push(zw);
            w *= pow_plus2_root_of_unity;
        });

        let e2a_vec = e2a.into();
        let e2b_vec = e2b.into();
        let e2c_vec = e2c.into();
        let e2d_vec = e2d.into();
        let zp_vec = zp.into();

        let [e2, e2z_0, e2z_1, e2z_2, e2z_3] = mul4vec!(
            driver, &e2a_vec, &e2b_vec, &e2c_vec, &e2d_vec, &ap_vec, &bp_vec, &cp_vec, &zp_vec,
            &domain1
        );

        let e3a_vec = e3a.into();
        let e3b_vec = e3b.into();
        let e3c_vec = e3c.into();
        let e3d_vec = e3d.into();
        let zwp_vec = zwp.into();

        let [e3, e3z_0, e3z_1, e3z_2, e3z_3] = mul4vec!(
            driver, &e3a_vec, &e3b_vec, &e3c_vec, &e3d_vec, &ap_vec, &bp_vec, &cp_vec, &zwp_vec,
            &domain1
        );

        let mut t_vec = Vec::with_capacity(zkey.domain_size * 4);
        let mut tz_vec = Vec::with_capacity(zkey.domain_size * 4);
        // We do not want to have any network operation in here to reduce MPC rounds. To enforce this, we have a for_each loop here (Network operations require a result)
        (0..zkey.domain_size * 4).for_each(|i| {
            let mut e2 = e2.index(i);
            let mut e2z = mul4vec_post!(driver, e2z_0, e2z_1, e2z_2, e2z_3, i, z1, z2, z3);
            let mut e3 = e3.index(i);
            let mut e3z = mul4vec_post!(driver, e3z_0, e3z_1, e3z_2, e3z_3, i, z1, z2, z3);

            let z = polys.z.eval.index(i);
            let zp = zp_vec.index(i);

            e2 = driver.mul_with_public(&challenges.alpha, &e2);
            e2z = driver.mul_with_public(&challenges.alpha, &e2z);

            e3 = driver.mul_with_public(&challenges.alpha, &e3);
            e3z = driver.mul_with_public(&challenges.alpha, &e3z);

            let mut e4 = driver.add_with_public(&-P::ScalarField::one(), &z);
            e4 = driver.mul_with_public(&zkey.lagrange[0].evaluations[i], &e4);
            e4 = driver.mul_with_public(&challenges.alpha2, &e4);

            let mut e4z = driver.mul_with_public(&zkey.lagrange[0].evaluations[i], &zp);
            e4z = driver.mul_with_public(&challenges.alpha2, &e4z);

            let mut t = driver.add(&e1[i], &e2);
            t = driver.sub(&t, &e3);
            t = driver.add(&t, &e4);

            let mut tz = driver.add(&e1z[i], &e2z);
            tz = driver.sub(&tz, &e3z);
            tz = driver.add(&tz, &e4z);

            t_vec.push(t);
            tz_vec.push(tz);
        });
        let mut coefficients_t = driver.ifft(&t_vec.into(), &domains.extended_domain);
        driver.neg_vec_in_place_limit(&mut coefficients_t, zkey.domain_size);

        for i in zkey.domain_size..zkey.domain_size * 4 {
            let a_lhs = coefficients_t.index(i - zkey.domain_size);
            let a_rhs = coefficients_t.index(i);
            let a = driver.sub(&a_lhs, &a_rhs);
            coefficients_t.set_index(a, i);
            /*
              We cannot check whether the polynomial is divisible by Zh here
            */
        }

        let coefficients_tz = driver.ifft(&tz_vec.into(), &domains.extended_domain);
        let t_final = driver.add_vec(&coefficients_t, &coefficients_tz);
        let mut t_final = t_final.into_iter();
        let mut t1 = Vec::with_capacity(zkey.domain_size + 1);
        let mut t2 = Vec::with_capacity(zkey.domain_size + 1);
        for _ in 0..zkey.domain_size {
            t1.push(t_final.next().unwrap());
        }
        for _ in 0..zkey.domain_size {
            t2.push(t_final.next().unwrap());
        }
        let mut t3 = t_final.take(zkey.domain_size + 6).collect::<Vec<_>>();
        t1.push(challenges.b[9].to_owned());

        t2[0] = driver.sub(&t2[0], &challenges.b[9]);
        t2.push(challenges.b[10].to_owned());

        t3[0] = driver.sub(&t3[0], &challenges.b[10]);

        Ok([t1.into(), t2.into(), t3.into()])
    }

    pub(super) fn round3(self) -> PlonkProofResult<Round4<T, P>> {
        let Self {
            mut driver,
            domains,
            challenges,
            proof,
            polys,
            data,
        } = self;
        let mut transcript = Keccak256Transcript::<P>::default();
        // STEP 3.1 - Compute evaluation challenge alpha ∈ F
        transcript.add_scalar(challenges.beta);
        transcript.add_scalar(challenges.gamma);
        transcript.add_point(proof.commit_z.into());

        let alpha = transcript.get_challenge();
        let alpha2 = alpha.square();
        let challenges = Round3Challenges::new(challenges, alpha, alpha2);
        let [t1, t2, t3] = Self::compute_t(&mut driver, &domains, &challenges, &data.zkey, &polys)?;

        // Compute [T1]_1, [T2]_1, [T3]_1
        let commit_t1 = MSMProvider::<P::G1>::msm_public_points(
            &mut driver,
            &data.zkey.p_tau[..t1.get_len()],
            &t1,
        );
        let commit_t2 = MSMProvider::<P::G1>::msm_public_points(
            &mut driver,
            &data.zkey.p_tau[..t2.get_len()],
            &t2,
        );
        let commit_t3 = MSMProvider::<P::G1>::msm_public_points(
            &mut driver,
            &data.zkey.p_tau[..t3.get_len()],
            &t3,
        );

        let opened = driver.open_point_many(&[commit_t1, commit_t2, commit_t3])?;

        let polys = FinalPolys::new(polys, t1, t2, t3);
        let proof = Round3Proof::new(proof, opened[0], opened[1], opened[2]);
        Ok(Round4 {
            driver,
            domains,
            challenges,
            proof,
            polys,
            data,
        })
    }
}

#[cfg(test)]
pub mod tests {

    use std::{fs::File, io::BufReader};

    use ark_bn254::Bn254;
    use circom_types::{groth16::witness::Witness, plonk::ZKey};
    use collaborative_groth16::groth16::SharedWitness;
    use mpc_core::protocols::plain::PlainDriver;

    use crate::round1::{Round1, Round1Challenges};
    macro_rules! g1_from_xy {
        ($x: expr,$y: expr) => {
            <ark_bn254::Bn254 as Pairing>::G1Affine::new(
                ark_bn254::Fq::from_str($x).unwrap(),
                ark_bn254::Fq::from_str($y).unwrap(),
            )
        };
    }

    use ark_ec::pairing::Pairing;
    use num_traits::Zero;
    use std::str::FromStr;
    #[test]
    fn test_round3_multiplier2() {
        let mut driver = PlainDriver::<ark_bn254::Fr>::default();
        let mut reader = BufReader::new(
            File::open("../test_vectors/Plonk/bn254/multiplierAdd2/multiplier2.zkey").unwrap(),
        );
        let zkey = ZKey::<Bn254>::from_reader(&mut reader).unwrap();
        let witness_file =
            File::open("../test_vectors/Plonk/bn254/multiplierAdd2/multiplier2_wtns.wtns").unwrap();
        let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
        let witness = SharedWitness::<PlainDriver<ark_bn254::Fr>, Bn254> {
            public_inputs: vec![ark_bn254::Fr::zero(), witness.values[1]],
            witness: vec![witness.values[2], witness.values[3]],
        };

        let challenges = Round1Challenges::deterministic(&mut driver);
        let mut round1 = Round1::init_round(driver, zkey, witness).unwrap();
        round1.challenges = challenges;
        let round2 = round1.round1().unwrap();
        let round3 = round2.round2().unwrap();
        let round4 = round3.round3().unwrap();
        assert_eq!(
            round4.proof.commit_t1,
            g1_from_xy!(
                "10327706816981641898653936867326978572800462904089207833739215636683540834324",
                "5337656652503503683213667702893053180738744977881846387675513182448211681026"
            )
        );
        assert_eq!(
            round4.proof.commit_t2,
            g1_from_xy!(
                "11760191818256951290303960730312811023524308158422556533432353552006441425656",
                "2617625258193625857175469343536625880680654033457634077015004216663787850740"
            )
        );
        assert_eq!(
            round4.proof.commit_t3,
            g1_from_xy!(
                "15029731921448230484040702246894010251361328991865488980611537720038923147272",
                "10245480538259328650381255483852509347189129783689746910480576260940917259993"
            )
        );
    }
}
