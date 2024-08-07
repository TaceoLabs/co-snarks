use crate::{
    round1::{Round1Challenges, Round1Proof},
    round2::{Round2Challenges, Round2Polys, Round2Proof},
    round3::{Round3Challenges, Round3Polys, Round3Proof},
    round4::{Round4Challenges, Round4Proof},
    types::{Keccak256Transcript, PolyEval, Transcript},
    Domains, FieldShare, FieldShareVec, PlonkData, PlonkProofError, PlonkProofResult, Round,
};
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_poly::GeneralEvaluationDomain;
use circom_types::{
    groth16::{public_input, zkey},
    plonk::ZKey,
};
use collaborative_groth16::groth16::CollaborativeGroth16;
use mpc_core::traits::EcMpcProtocol;
use mpc_core::traits::{
    FFTPostProcessing, FFTProvider, MSMProvider, MontgomeryField, MpcToMontgomery,
    PairingEcMpcProtocol, PrimeFieldMpcProtocol,
};
use num_traits::One;
use num_traits::Zero;
pub(super) struct Round5Challenges<T, P: Pairing>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    b: [T::FieldShare; 11],
    beta: P::ScalarField,
    gamma: P::ScalarField,
    alpha: P::ScalarField,
    alpha2: P::ScalarField,
    xi: P::ScalarField,
    xiw: P::ScalarField,
    v: [P::ScalarField; 5],
}

pub(super) struct Round5Polys<T, P: Pairing>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    pub(crate) buffer_a: FieldShareVec<T, P>,
    pub(crate) buffer_b: FieldShareVec<T, P>,
    pub(crate) buffer_c: FieldShareVec<T, P>,
    pub(crate) poly_eval_a: PolyEval<T, P>,
    pub(crate) poly_eval_b: PolyEval<T, P>,
    pub(crate) poly_eval_c: PolyEval<T, P>,
    pub(crate) z: PolyEval<T, P>,
    pub(crate) t1: FieldShareVec<T, P>,
    pub(crate) t2: FieldShareVec<T, P>,
    pub(crate) t3: FieldShareVec<T, P>,
}
impl<T, P: Pairing> Round5Polys<T, P>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    fn new(polys: Round3Polys<T, P>) -> Self {
        Self {
            buffer_a: polys.buffer_a,
            buffer_b: polys.buffer_b,
            buffer_c: polys.buffer_c,
            poly_eval_a: polys.poly_eval_a,
            poly_eval_b: polys.poly_eval_b,
            poly_eval_c: polys.poly_eval_c,
            z: polys.z,
            t1: polys.t1,
            t2: polys.t2,
            t3: polys.t3,
        }
    }
}

impl<T, P: Pairing> Round5Challenges<T, P>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    fn new(round4_challenges: Round4Challenges<T, P>, v: [P::ScalarField; 5]) -> Self {
        Self {
            b: round4_challenges.b,
            beta: round4_challenges.beta,
            gamma: round4_challenges.gamma,
            alpha: round4_challenges.alpha,
            alpha2: round4_challenges.alpha2,
            xi: round4_challenges.xi,
            xiw: round4_challenges.xiw,
            v,
        }
    }
}

pub(super) struct Round5Proof<P: Pairing> {
    pub(crate) commit_a: P::G1,
    pub(crate) commit_b: P::G1,
    pub(crate) commit_c: P::G1,
    pub(crate) commit_z: P::G1,
    pub(crate) commit_t1: P::G1,
    pub(crate) commit_t2: P::G1,
    pub(crate) commit_t3: P::G1,
    pub(crate) eval_a: P::ScalarField,
    pub(crate) eval_b: P::ScalarField,
    pub(crate) eval_c: P::ScalarField,
    pub(crate) eval_zw: P::ScalarField,
    pub(crate) eval_s1: P::ScalarField,
    pub(crate) eval_s2: P::ScalarField,
    pub(crate) commit_wxi: P::G1,
    pub(crate) commit_wxiw: P::G1,
}

impl<P: Pairing> Round5Proof<P> {
    fn new(round4_proof: Round4Proof<P>, commit_wxi: P::G1, commit_wxiw: P::G1) -> Self {
        Self {
            commit_a: round4_proof.commit_a,
            commit_b: round4_proof.commit_b,
            commit_c: round4_proof.commit_c,
            commit_z: round4_proof.commit_z,
            commit_t1: round4_proof.commit_t1,
            commit_t2: round4_proof.commit_t1,
            commit_t3: round4_proof.commit_t1,
            eval_a: round4_proof.eval_a,
            eval_b: round4_proof.eval_b,
            eval_c: round4_proof.eval_c,
            eval_zw: round4_proof.eval_zw,
            eval_s1: round4_proof.eval_s1,
            eval_s2: round4_proof.eval_s2,
            commit_wxi,
            commit_wxiw,
        }
    }
}

impl<T, P: Pairing> Round<T, P>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>
        + MSMProvider<P::G1>
        + MSMProvider<P::G2>,
    P::ScalarField: FFTPostProcessing,
{
    fn calculate_lagrange_evaluations(
        power: usize,
        n_public: usize,
        xi: &P::ScalarField,
        domains: &Domains<P>,
    ) -> (Vec<P::ScalarField>, P::ScalarField) {
        let mut xin = *xi;
        let mut domain_size = 1;
        for _ in 0..power {
            xin.square_in_place();
            domain_size *= 2;
        }
        let zh = xin - P::ScalarField::one();

        // TODO Check if this root_of_unity is the one we need
        // TODO this is duplicate from compute_z
        let root_of_unity = domains.roots_of_unity[power];

        let l_length = usize::max(1, n_public);
        let mut l = Vec::with_capacity(l_length);

        let n = P::ScalarField::from(domain_size as u64);
        let mut w = P::ScalarField::one();
        for _ in 0..l_length {
            l.push((w * zh) / (n * (*xi - w)));
            w *= root_of_unity;
        }
        (l, xin)
    }
    fn calculate_pi(public_inputs: &[P::ScalarField], l: &[P::ScalarField]) -> P::ScalarField {
        let mut pi = P::ScalarField::zero();
        //TODO WE WANT THE PUBLIC INPUTS WITHOUT THE LEADING ZERO!
        //WHERE DO WE NEED TO CHANGE THIS
        for (val, l) in public_inputs.iter().skip(1).zip(l) {
            pi -= *l * val;
        }
        pi
    }

    fn div_by_zerofier(
        driver: &mut T,
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
                    *el = driver.neg(el);
                } else {
                    *el = driver.mul_with_public(&inv_beta_neg, el);
                }
            }
        }

        std::mem::swap(&mut is_negone, &mut is_one);

        for i in n..inout.len() {
            let element = driver.sub(&inout[i - n], &inout[i]);

            if !is_one {
                if is_negone {
                    inout[i] = driver.neg(&element);
                } else {
                    inout[i] = driver.mul_with_public(&inv_beta, &element);
                }
            }
        }
        // We cannot check whether the polyonmial is divisible by the zerofier, but we resize accordingly
        inout.resize(inout.len() - n, FieldShare::<T, P>::default());
    }

    fn add_poly(inout: &mut Vec<P::ScalarField>, add_poly: &[P::ScalarField]) {
        if add_poly.len() > inout.len() {
            inout.resize(add_poly.len(), P::ScalarField::zero());
        }

        for (mut inout, add) in inout.iter_mut().zip(add_poly.iter()) {
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

        for (mut inout, add) in inout.iter_mut().zip(add_poly.iter()) {
            *inout += *add * factor;
        }
    }

    fn compute_r(
        driver: &mut T,
        domains: &Domains<P>,
        proof: &Round4Proof<P>,
        challenges: &Round5Challenges<T, P>,
        data: &PlonkData<T, P>,
        polys: &Round3Polys<T, P>,
    ) -> FieldShareVec<T, P> {
        let zkey = &data.zkey;
        let public_inputs = &data.witness.shared_witness.public_inputs;
        let (l, xin) = Self::calculate_lagrange_evaluations(
            data.zkey.power,
            data.zkey.n_public,
            &challenges.xi,
            domains,
        );
        let zh = xin - P::ScalarField::one();

        let l0 = &l[0];
        let eval_pi = Self::calculate_pi(public_inputs, &l);

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
        for mut coeff in poly_r.iter_mut() {
            *coeff *= coef_ab;
        }
        Self::add_factor_poly(&mut poly_r, &zkey.ql_poly.coeffs, proof.eval_a);
        Self::add_factor_poly(&mut poly_r, &zkey.qr_poly.coeffs, proof.eval_b);
        Self::add_factor_poly(&mut poly_r, &zkey.qo_poly.coeffs, proof.eval_c);
        Self::add_poly(&mut poly_r, &zkey.qc_poly.coeffs);
        Self::add_factor_poly(&mut poly_r, &zkey.s3_poly.coeffs, -(e3 * challenges.beta));

        let len = zkey.domain_size + 6;

        let mut poly_r_shared = vec![FieldShare::<T, P>::default(); len];

        for (mut inout, add) in poly_r_shared
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
        for (mut inout, add) in tmp_poly.iter_mut().zip(polys.t3.clone().into_iter()) {
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

    fn compute_wxi(
        driver: &mut T,
        proof: &Round4Proof<P>,
        challenges: &Round5Challenges<T, P>,
        data: &PlonkData<T, P>,
        polys: &Round3Polys<T, P>,
        poly_r: &FieldShareVec<T, P>,
    ) -> FieldShareVec<T, P> {
        let s1_poly_coeffs = &data.zkey.s1_poly.coeffs;
        let s2_poly_coeffs = &data.zkey.s2_poly.coeffs;
        let len = usize::max(
            T::sharevec_len(poly_r),
            T::sharevec_len(&polys.poly_eval_a.poly),
        );

        let mut res = vec![FieldShare::<T, P>::default(); data.zkey.domain_size + 6];

        // R
        for (mut inout, add) in res.iter_mut().zip(poly_r.clone().into_iter()) {
            *inout = add;
        }
        // A
        for (inout, add) in res
            .iter_mut()
            .zip(polys.poly_eval_a.poly.clone().into_iter())
        {
            let tmp = driver.mul_with_public(&challenges.v[0], &add);
            *inout = driver.add(&tmp, inout);
        }
        // B
        for (inout, add) in res
            .iter_mut()
            .zip(polys.poly_eval_b.poly.clone().into_iter())
        {
            let tmp = driver.mul_with_public(&challenges.v[1], &add);
            *inout = driver.add(&tmp, inout);
        }
        // C
        for (inout, add) in res
            .iter_mut()
            .zip(polys.poly_eval_c.poly.clone().into_iter())
        {
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

    fn compute_wxiw(
        driver: &mut T,
        domains: &Domains<P>,
        proof: &Round4Proof<P>,
        challenges: &Round5Challenges<T, P>,
        data: &PlonkData<T, P>,
        polys: &Round3Polys<T, P>,
    ) -> FieldShareVec<T, P> {
        let xiw = challenges.xi * domains.roots_of_unity[data.zkey.power];

        let mut res = polys.z.poly.clone().into_iter().collect::<Vec<_>>();
        res[0] = driver.add_with_public(&-proof.eval_zw, &res[0]);
        Self::div_by_zerofier(driver, &mut res, 1, xiw);

        res.into()
    }
    pub(super) fn round5(
        driver: &mut T,
        domains: Domains<P>,
        challenges: Round4Challenges<T, P>,
        proof: Round4Proof<P>,
        polys: Round3Polys<T, P>,
        data: PlonkData<T, P>,
    ) -> PlonkProofResult<Self> {
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
        let r = Self::compute_r(driver, &domains, &proof, &challenges, &data, &polys);
        //STEP 5.3 Compute opening proof polynomial Wxi(X)
        let wxi = Self::compute_wxi(driver, &proof, &challenges, &data, &polys, &r);
        //snarkjs has one trailing zero - is this relevant?

        //STEP 5.4 Compute opening proof polynomial Wxiw(X)
        let wxiw = Self::compute_wxiw(driver, &domains, &proof, &challenges, &data, &polys);
        // Fifth output of the prover is ([Wxi]_1, [Wxiw]_1)

        let p_tau = &data.zkey.p_tau;
        let commit_wxi = MSMProvider::<P::G1>::msm_public_points(driver, p_tau, &wxi);
        let commit_wxiw = MSMProvider::<P::G1>::msm_public_points(driver, p_tau, &wxiw);

        let opened = driver.open_point_many(&[commit_wxi, commit_wxiw])?;
        debug_assert_eq!(opened.len(), 2);
        let commit_wxi = opened[0];
        let commit_wxiw = opened[1];
        Ok(Round::Finished {
            proof: Round5Proof::new(proof, commit_wxi, commit_wxiw),
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

    use crate::{Domains, PlonkData, Round};
    macro_rules! g1_from_xy {
        ($x: expr,$y: expr) => {
            <ark_bn254::Bn254 as Pairing>::G1Affine::new(
                ark_bn254::Fq::from_str($x).unwrap(),
                ark_bn254::Fq::from_str($y).unwrap(),
            )
        };
    }

    use super::Round1Challenges;
    use ark_ec::pairing::Pairing;
    use num_traits::Zero;
    use std::str::FromStr;
    #[test]
    fn test_round5_multiplier2() {
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

        let round1 = Round::<PlainDriver<ark_bn254::Fr>, Bn254>::Round1 {
            domains: Domains::new(&zkey).unwrap(),
            challenges: Round1Challenges::deterministic(&mut driver),
            data: PlonkData {
                witness: witness.into(),
                zkey,
            },
        };
        let round2 = round1.next_round(&mut driver).unwrap();
        let round3 = round2.next_round(&mut driver).unwrap();
        let round4 = round3.next_round(&mut driver).unwrap();
        let round5 = round4.next_round(&mut driver).unwrap();
        if let Round::Finished { proof } = round5.next_round(&mut driver).unwrap() {
            assert_eq!(
                proof.commit_wxi,
                g1_from_xy!(
                    "4329097845486505830634365153212275596432950765149605790709187747717015162804",
                    "3341366150734122225834578088990337734750095441774280053351010471181993400779"
                )
            );
            assert_eq!(
                proof.commit_wxiw,
                g1_from_xy!(
                    "16661904516393530409439952377741308650234616154674488926230015210553665229568",
                    "19414395546663341558564137558575273143353981410327853582113788899527050228324"
                )
            );
        } else {
            panic!("must be finished after round5");
        }
    }
}
