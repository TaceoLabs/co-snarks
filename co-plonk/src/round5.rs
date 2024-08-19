use crate::{
    plonk_utils,
    round3::FinalPolys,
    round4::{Round4Challenges, Round4Proof},
    types::{Domains, Keccak256Transcript, PlonkData},
    FieldShare, FieldShareVec, PlonkProofResult,
};
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use circom_types::{
    plonk::PlonkProof,
    traits::{CircomArkworksPairingBridge, CircomArkworksPrimeFieldBridge},
};
use mpc_core::traits::{
    FFTProvider, FieldShareVecTrait, MSMProvider, PairingEcMpcProtocol, PrimeFieldMpcProtocol,
};
use num_traits::One;
use num_traits::Zero;

// Round 5 of https://eprint.iacr.org/2019/953.pdf (page 30)
pub(super) struct Round5<'a, T, P: Pairing>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>
        + MSMProvider<P::G1>
        + MSMProvider<P::G2>,
{
    pub(super) driver: T,
    pub(super) domains: Domains<P::ScalarField>,
    pub(super) challenges: Round4Challenges<P>,
    pub(super) proof: Round4Proof<P>,
    pub(super) polys: FinalPolys<T, P>,
    pub(super) data: PlonkData<'a, T, P>,
}
pub(super) struct Round5Challenges<P: Pairing> {
    beta: P::ScalarField,
    gamma: P::ScalarField,
    alpha: P::ScalarField,
    xi: P::ScalarField,
    v: [P::ScalarField; 5],
}

impl<P: Pairing> Round5Challenges<P> {
    fn new(round4_challenges: Round4Challenges<P>, v: [P::ScalarField; 5]) -> Self {
        Self {
            beta: round4_challenges.beta,
            gamma: round4_challenges.gamma,
            alpha: round4_challenges.alpha,
            xi: round4_challenges.xi,
            v,
        }
    }
}

impl<P: Pairing + CircomArkworksPairingBridge> Round4Proof<P>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    fn into_final_proof(self, commit_wxi: P::G1, commit_wxiw: P::G1) -> PlonkProof<P> {
        PlonkProof {
            a: P::G1Affine::from(self.commit_a),
            b: P::G1Affine::from(self.commit_b),
            c: P::G1Affine::from(self.commit_c),
            z: P::G1Affine::from(self.commit_z),
            t1: P::G1Affine::from(self.commit_t1),
            t2: P::G1Affine::from(self.commit_t2),
            t3: P::G1Affine::from(self.commit_t3),
            eval_a: self.eval_a,
            eval_b: self.eval_b,
            eval_c: self.eval_c,
            eval_s1: self.eval_s1,
            eval_s2: self.eval_s2,
            eval_zw: self.eval_zw,
            wxi: commit_wxi.into(),
            wxiw: P::G1Affine::from(commit_wxiw),
            protocol: "plonk".to_string(),
            curve: P::get_circom_name(),
        }
    }
}

// Round 5 of https://eprint.iacr.org/2019/953.pdf (page 30)
impl<'a, T, P: Pairing> Round5<'a, T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>
        + MSMProvider<P::G1>
        + MSMProvider<P::G2>,
    P: CircomArkworksPairingBridge,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    fn div_by_zerofier(
        driver: &mut T,
        inout: &mut Vec<FieldShare<T, P>>,
        n: usize,
        beta: P::ScalarField,
    ) {
        let inv_beta = beta.inverse().expect("Highly unlikely to be zero");
        let inv_beta_neg = -inv_beta;

        for el in inout.iter_mut().take(n) {
            *el = driver.mul_with_public(&inv_beta_neg, el);
        }
        for i in n..inout.len() {
            let element = driver.sub(&inout[i - n], &inout[i]);
            inout[i] = driver.mul_with_public(&inv_beta, &element);
        }
        // We cannot check whether the polyonmial is divisible by the zerofier, but we resize accordingly
        inout.resize(inout.len() - n, FieldShare::<T, P>::default());
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

    // The linearisation polynomial R(X) (see https://eprint.iacr.org/2019/953.pdf)
    fn compute_r(
        driver: &mut T,
        domains: &Domains<P::ScalarField>,
        proof: &Round4Proof<P>,
        challenges: &Round5Challenges<P>,
        data: &PlonkData<T, P>,
        polys: &FinalPolys<T, P>,
    ) -> FieldShareVec<T, P> {
        let zkey = &data.zkey;
        let public_inputs = &data.witness.public_inputs;
        let (l, xin) = plonk_utils::calculate_lagrange_evaluations::<P>(
            data.zkey.power,
            data.zkey.n_public,
            &challenges.xi,
            domains,
        );
        let zh = xin - P::ScalarField::one();

        let l0 = &l[0];
        let eval_pi = plonk_utils::calculate_pi::<P>(public_inputs, &l);

        let coef_ab = proof.eval_a * proof.eval_b;
        let betaxi = challenges.beta * challenges.xi;
        let e2a = proof.eval_a + betaxi + challenges.gamma;
        let e2b = proof.eval_b + betaxi * zkey.verifying_key.k1 + challenges.gamma;
        let e2c = proof.eval_c + betaxi * zkey.verifying_key.k2 + challenges.gamma;
        let e2 = e2a * e2b * e2c * challenges.alpha;

        let e3a = proof.eval_a + challenges.beta * proof.eval_s1 + challenges.gamma;
        let e3b = proof.eval_b + challenges.beta * proof.eval_s2 + challenges.gamma;
        let e3 = e3a * e3b * proof.eval_zw * challenges.alpha;

        let e4 = challenges.alpha.square() * l0;
        let e24 = e2 + e4;

        let mut poly_r = zkey.qm_poly.coeffs.clone();
        for coeff in poly_r.iter_mut() {
            *coeff *= coef_ab;
        }
        Self::add_factor_poly(&mut poly_r.coeffs, &zkey.ql_poly.coeffs, proof.eval_a);
        Self::add_factor_poly(&mut poly_r.coeffs, &zkey.qr_poly.coeffs, proof.eval_b);
        Self::add_factor_poly(&mut poly_r.coeffs, &zkey.qo_poly.coeffs, proof.eval_c);
        Self::add_poly(&mut poly_r.coeffs, &zkey.qc_poly.coeffs);
        Self::add_factor_poly(
            &mut poly_r.coeffs,
            &zkey.s3_poly.coeffs,
            -(e3 * challenges.beta),
        );

        let len = zkey.domain_size + 6;

        let mut poly_r_shared = vec![FieldShare::<T, P>::default(); len];

        for (inout, add) in poly_r_shared
            .iter_mut()
            .zip(polys.z.poly.clone().into_iter())
        {
            *inout = driver.mul_with_public(&e24, &add)
        }

        for (inout, add) in poly_r_shared.iter_mut().zip(poly_r.iter()) {
            *inout = driver.add_with_public(add, inout);
        }

        let mut tmp_poly = vec![FieldShare::<T, P>::default(); len];
        let xin2 = xin.square();
        for (inout, add) in tmp_poly.iter_mut().zip(polys.t3.clone().into_iter()) {
            *inout = driver.mul_with_public(&xin2, &add);
        }
        for (inout, add) in tmp_poly.iter_mut().zip(polys.t2.clone().into_iter()) {
            let tmp = driver.mul_with_public(&xin, &add);
            *inout = driver.add(&tmp, inout);
        }
        for (inout, add) in tmp_poly.iter_mut().zip(polys.t1.clone().into_iter()) {
            *inout = driver.add(inout, &add);
        }
        for inout in tmp_poly.iter_mut() {
            *inout = driver.mul_with_public(&zh, inout);
        }

        for (inout, sub) in poly_r_shared.iter_mut().zip(tmp_poly.iter()) {
            *inout = driver.sub(inout, sub);
        }

        let r0 = eval_pi - (e3 * (proof.eval_c + challenges.gamma)) - e4;

        poly_r_shared[0] = driver.add_with_public(&r0, &poly_r_shared[0]);
        poly_r_shared.into()
    }

    // The opening proof polynomial W_xi(X) (see https://eprint.iacr.org/2019/953.pdf)
    fn compute_wxi(
        driver: &mut T,
        proof: &Round4Proof<P>,
        challenges: &Round5Challenges<P>,
        data: &PlonkData<T, P>,
        polys: &FinalPolys<T, P>,
        poly_r: &FieldShareVec<T, P>,
    ) -> FieldShareVec<T, P> {
        let s1_poly_coeffs = &data.zkey.s1_poly.coeffs;
        let s2_poly_coeffs = &data.zkey.s2_poly.coeffs;
        let mut res = vec![FieldShare::<T, P>::default(); data.zkey.domain_size + 6];

        // R
        for (inout, add) in res.iter_mut().zip(poly_r.clone().into_iter()) {
            *inout = add;
        }
        // A
        for (inout, add) in res.iter_mut().zip(polys.a.poly.clone().into_iter()) {
            let tmp = driver.mul_with_public(&challenges.v[0], &add);
            *inout = driver.add(&tmp, inout);
        }
        // B
        for (inout, add) in res.iter_mut().zip(polys.b.poly.clone().into_iter()) {
            let tmp = driver.mul_with_public(&challenges.v[1], &add);
            *inout = driver.add(&tmp, inout);
        }
        // C
        for (inout, add) in res.iter_mut().zip(polys.c.poly.clone().into_iter()) {
            let tmp = driver.mul_with_public(&challenges.v[2], &add);
            *inout = driver.add(&tmp, inout);
        }
        // Sigma1
        for (inout, add) in res.iter_mut().zip(s1_poly_coeffs.iter()) {
            *inout = driver.add_with_public(&(challenges.v[3] * add), inout);
        }
        // Sigma2
        for (inout, add) in res.iter_mut().zip(s2_poly_coeffs.iter()) {
            *inout = driver.add_with_public(&(challenges.v[4] * add), inout);
        }

        res[0] = driver.add_with_public(&-(challenges.v[0] * proof.eval_a), &res[0]);
        res[0] = driver.add_with_public(&-(challenges.v[1] * proof.eval_b), &res[0]);
        res[0] = driver.add_with_public(&-(challenges.v[2] * proof.eval_c), &res[0]);
        res[0] = driver.add_with_public(&-(challenges.v[3] * proof.eval_s1), &res[0]);
        res[0] = driver.add_with_public(&-(challenges.v[4] * proof.eval_s2), &res[0]);

        Self::div_by_zerofier(driver, &mut res, 1, challenges.xi);

        res.into()
    }

    // The opening proof polynomial W_xiw(X) (see https://eprint.iacr.org/2019/953.pdf)
    fn compute_wxiw(
        driver: &mut T,
        domains: &Domains<P::ScalarField>,
        proof: &Round4Proof<P>,
        challenges: &Round5Challenges<P>,
        polys: &FinalPolys<T, P>,
    ) -> FieldShareVec<T, P> {
        let xiw = challenges.xi * domains.root_of_unity_pow;

        let mut res = polys.z.poly.clone().into_iter().collect::<Vec<_>>();
        res[0] = driver.add_with_public(&-proof.eval_zw, &res[0]);
        Self::div_by_zerofier(driver, &mut res, 1, xiw);

        res.into()
    }

    // Round 5 of https://eprint.iacr.org/2019/953.pdf (page 30)
    pub(super) fn round5(self) -> PlonkProofResult<PlonkProof<P>> {
        let Self {
            mut driver,
            domains,
            challenges,
            proof,
            polys,
            data,
        } = self;
        let mut transcript = Keccak256Transcript::<P>::default();
        // STEP 5.1 - Compute evaluation challenge v \in F_p
        transcript.add_scalar(challenges.xi);
        transcript.add_scalar(proof.eval_a);
        transcript.add_scalar(proof.eval_b);
        transcript.add_scalar(proof.eval_c);
        transcript.add_scalar(proof.eval_s1);
        transcript.add_scalar(proof.eval_s2);
        transcript.add_scalar(proof.eval_zw);

        let mut v = [P::ScalarField::one(); 5];
        v[0] = transcript.get_challenge();
        for i in 1..5 {
            v[i] = v[i - 1] * v[0];
        }
        let challenges = Round5Challenges::new(challenges, v);

        // STEP 5.2 Compute linearisation polynomial r(X)
        let r = Self::compute_r(&mut driver, &domains, &proof, &challenges, &data, &polys);
        //STEP 5.3 Compute opening proof polynomial Wxi(X)
        let wxi = Self::compute_wxi(&mut driver, &proof, &challenges, &data, &polys, &r);

        //STEP 5.4 Compute opening proof polynomial Wxiw(X)
        let wxiw = Self::compute_wxiw(&mut driver, &domains, &proof, &challenges, &polys);
        // Fifth output of the prover is ([Wxi]_1, [Wxiw]_1)

        let p_tau = &data.zkey.p_tau;
        let commit_wxi =
            MSMProvider::<P::G1>::msm_public_points(&mut driver, &p_tau[..wxi.get_len()], &wxi);
        let commit_wxiw =
            MSMProvider::<P::G1>::msm_public_points(&mut driver, &p_tau[..wxiw.get_len()], &wxiw);

        let opened = driver.open_point_many(&[commit_wxi, commit_wxiw])?;

        let commit_wxi = opened[0];
        let commit_wxiw = opened[1];
        Ok(proof.into_final_proof(commit_wxi, commit_wxiw))
    }
}

#[cfg(test)]
pub mod tests {

    use std::{fs::File, io::BufReader};

    use ark_bn254::Bn254;
    use circom_types::plonk::ZKey;
    use circom_types::Witness;
    use co_circom_snarks::SharedWitness;
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
    use std::str::FromStr;
    #[test]
    fn test_round5_multiplier2() {
        let mut driver = PlainDriver::<ark_bn254::Fr>::default();
        let mut reader = BufReader::new(
            File::open("../test_vectors/Plonk/bn254/multiplier2/circuit.zkey").unwrap(),
        );
        let zkey = ZKey::<Bn254>::from_reader(&mut reader).unwrap();
        let witness_file =
            File::open("../test_vectors/Plonk/bn254/multiplier2/witness.wtns").unwrap();
        let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
        let public_input = witness.values[..=zkey.n_public].to_vec();
        let witness = SharedWitness::<PlainDriver<ark_bn254::Fr>, Bn254> {
            public_inputs: public_input.clone(),
            witness: witness.values[zkey.n_public + 1..].to_vec(),
        };

        let challenges = Round1Challenges::deterministic(&mut driver);
        let mut round1 = Round1::init_round(driver, &zkey, witness).unwrap();
        round1.challenges = challenges;
        let round2 = round1.round1().unwrap();
        let round3 = round2.round2().unwrap();
        let round4 = round3.round3().unwrap();
        let round5 = round4.round4().unwrap();
        let proof = round5.round5().unwrap();
        assert_eq!(
            proof.wxi,
            g1_from_xy!(
                "17714933343167283383757911844657193439824158284537335005582807825912982308761",
                "10956622068891399683012461981563789956666325407769410657364052444385845871778"
            )
        );
        assert_eq!(
            proof.wxiw,
            g1_from_xy!(
                "11975595019949715918668172153793336705506375746143971491421022814159658028345",
                "21836122222240321064812409945656239690711148338716835775906941056446809090474"
            )
        );
    }
}
