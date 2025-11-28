use crate::{
    PlonkProofResult,
    mpc::CircomPlonkProver,
    plonk_utils::rayon_join3,
    round2::{Round2Challenges, Round2Polys, Round2Proof},
    round4::Round4,
    types::{Domains, Keccak256Transcript, PlonkData, PolyEval},
};
use ark_ec::CurveGroup;
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use circom_types::plonk::Zkey;
use itertools::izip;
use mpc_core::MpcState;
use mpc_net::Network;
use num_traits::One;
use num_traits::Zero;
use tracing::instrument;

macro_rules! mul4vec {
    ($nets: expr, $state: expr, $a: expr,$b: expr,$c: expr,$d: expr,$ap: expr,$bp: expr,$cp: expr,$dp: expr, $len: expr) => {{
        let mut state0 = $state.fork($len)?;
        let mut state1 = $state.fork($len)?;
        let mut state2 = $state.fork($len)?;
        let mut state3 = $state.fork($len)?;
        let mut state4 = $state.fork($len)?;
        let mut state5 = $state.fork($len)?;
        let mut state6 = $state.fork($len)?;
        let mut state7 = $state.fork($len)?;

        let (a_b, a_bp, ap_b, ap_bp, c_d, c_dp, cp_d, cp_dp) = mpc_net::join8(
            || T::mul_vec($a, $b, &$nets[0], &mut state0),
            || T::mul_vec($a, $bp, &$nets[1], &mut state1),
            || T::mul_vec($ap, $b, &$nets[2], &mut state2),
            || T::mul_vec($ap, $bp, &$nets[3], &mut state3),
            || T::mul_vec($c, $d, &$nets[4], &mut state4),
            || T::mul_vec($c, $dp, &$nets[5], &mut state5),
            || T::mul_vec($cp, $d, &$nets[6], &mut state6),
            || T::mul_vec($cp, $dp, &$nets[7], &mut state7),
        );
        let a_b = a_b?;
        let a_bp = a_bp?;
        let ap_b = ap_b?;
        let ap_bp = ap_bp?;
        let c_d = c_d?;
        let c_dp = c_dp?;
        let cp_d = cp_d?;
        let cp_dp = cp_dp?;

        let mut state0 = $state.fork($len)?;
        let mut state1 = $state.fork($len * 4)?;
        let mut state2 = $state.fork($len * 6)?;
        let mut state3 = $state.fork($len * 4)?;
        let mut state4 = $state.fork($len)?;

        let (r, a0, a1, a2, a3) = mpc_net::join5(
            || T::mul_vec(&a_b, &c_d, &$nets[0], &mut state0),
            || {
                let mut a0 = T::mul_vec(&ap_b, &c_d, &$nets[1], &mut state1)?;
                a0 = T::add_mul_vec(&a0, &a_bp, &c_d, &$nets[1], &mut state1)?;
                a0 = T::add_mul_vec(&a0, &a_b, &cp_d, &$nets[1], &mut state1)?;
                a0 = T::add_mul_vec(&a0, &a_b, &c_dp, &$nets[1], &mut state1)?;
                eyre::Ok(a0)
            },
            || {
                let mut a1 = T::mul_vec(&ap_bp, &c_d, &$nets[2], &mut state2)?;
                a1 = T::add_mul_vec(&a1, &ap_b, &cp_d, &$nets[2], &mut state2)?;
                a1 = T::add_mul_vec(&a1, &ap_b, &c_dp, &$nets[2], &mut state2)?;
                a1 = T::add_mul_vec(&a1, &a_bp, &cp_d, &$nets[2], &mut state2)?;
                a1 = T::add_mul_vec(&a1, &a_bp, &c_dp, &$nets[2], &mut state2)?;
                a1 = T::add_mul_vec(&a1, &a_b, &cp_dp, &$nets[2], &mut state2)?;
                eyre::Ok(a1)
            },
            || {
                let mut a2 = T::mul_vec(&a_bp, &cp_dp, &$nets[3], &mut state3)?;
                a2 = T::add_mul_vec(&a2, &ap_b, &cp_dp, &$nets[3], &mut state3)?;
                a2 = T::add_mul_vec(&a2, &ap_bp, &c_dp, &$nets[3], &mut state3)?;
                a2 = T::add_mul_vec(&a2, &ap_bp, &cp_d, &$nets[3], &mut state3)?;
                eyre::Ok(a2)
            },
            || T::mul_vec(&ap_bp, &cp_dp, &$nets[4], &mut state4),
        );

        eyre::Ok([r?, a0?, a1?, a2?, a3?])
    }};
}

macro_rules! mul4vec_post {
    ($a: expr,$b: expr,$c: expr,$d: expr,$i: expr, $z1: expr, $z2: expr, $z3: expr) => {{
        let mod_i = $i % 4;
        let mut rz = $a[$i].clone();
        if mod_i != 0 {
            let b = &$b[$i];
            let c = &$c[$i];
            let d = &$d[$i];
            let tmp = T::mul_with_public(*b, $z1[mod_i]);
            rz = T::add(tmp, rz);
            let tmp = T::mul_with_public(*c, $z2[mod_i]);
            rz = T::add(rz, tmp);
            let tmp = T::mul_with_public(*d, $z3[mod_i]);
            rz = T::add(rz, tmp);
        }
        rz
    }};
}

// Round 3 of https://eprint.iacr.org/2019/953.pdf (page 29)
pub(super) struct Round3<'a, P: Pairing, T: CircomPlonkProver<P>, N: Network> {
    pub(super) nets: &'a [N; 8],
    pub(super) state: &'a mut T::State,
    pub(super) domains: Domains<P::ScalarField>,
    pub(super) challenges: Round2Challenges<P, T>,
    pub(super) proof: Round2Proof<P>,
    pub(super) polys: Round2Polys<P, T>,
    pub(super) data: PlonkData<'a, P, T>,
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
pub(super) struct Round3Challenges<P: Pairing, T: CircomPlonkProver<P>> {
    pub(super) b: [T::ArithmeticShare; 11],
    pub(super) beta: P::ScalarField,
    pub(super) gamma: P::ScalarField,
    pub(super) alpha: P::ScalarField,
    pub(super) alpha2: P::ScalarField,
}

pub(super) struct FinalPolys<P: Pairing, T: CircomPlonkProver<P>> {
    pub(super) a: PolyEval<P, T>,
    pub(super) b: PolyEval<P, T>,
    pub(super) c: PolyEval<P, T>,
    pub(super) z: PolyEval<P, T>,
    pub(super) t1: Vec<T::ArithmeticShare>,
    pub(super) t2: Vec<T::ArithmeticShare>,
    pub(super) t3: Vec<T::ArithmeticShare>,
}

impl<P: Pairing> std::fmt::Display for Round3Proof<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(
            f,
            "Round3Proof(t1: {}, t2: {}, t2: {})",
            self.commit_t1.into_affine(),
            self.commit_t2.into_affine(),
            self.commit_t3.into_affine()
        )
    }
}
impl<P: Pairing, T: CircomPlonkProver<P>> FinalPolys<P, T> {
    fn new(
        polys: Round2Polys<P, T>,
        t1: Vec<T::ArithmeticShare>,
        t2: Vec<T::ArithmeticShare>,
        t3: Vec<T::ArithmeticShare>,
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

impl<P: Pairing, T: CircomPlonkProver<P>> Round3Challenges<P, T> {
    fn new(
        round2_challenges: Round2Challenges<P, T>,
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

// Round 3 of https://eprint.iacr.org/2019/953.pdf (page 29)
impl<'a, P: Pairing, T: CircomPlonkProver<P>, N: Network + 'static> Round3<'a, P, T, N> {
    fn get_z1(domains: &Domains<P::ScalarField>) -> [P::ScalarField; 4] {
        let zero = P::ScalarField::zero();
        let neg_1 = zero - P::ScalarField::one();
        let neg_2 = neg_1 - P::ScalarField::one();
        let root_of_unity = domains.root_of_unity_2;
        [zero, neg_1 + root_of_unity, neg_2, neg_1 - root_of_unity]
    }

    fn get_z2(domains: &Domains<P::ScalarField>) -> [P::ScalarField; 4] {
        let zero = P::ScalarField::zero();
        let two = P::ScalarField::one() + P::ScalarField::one();
        let four = two.square();
        let neg_2 = zero - two;
        let root_of_unity = domains.root_of_unity_2;
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
        let root_of_unity = domains.root_of_unity_2;
        let two_root_unity = two * root_of_unity;
        [zero, two + two_root_unity, neg_eight, two - two_root_unity]
    }

    // Compute the quotient polynomial T(X) (see https://eprint.iacr.org/2019/953.pdf)
    // It is implemented with a constant number of communication rounds in MPC
    fn compute_t(
        nets: &[N; 8],
        state: &mut T::State,
        domains: &Domains<P::ScalarField>,
        challenges: &Round3Challenges<P, T>,
        zkey: &Zkey<P>,
        polys: &Round2Polys<P, T>,
    ) -> PlonkProofResult<[Vec<T::ArithmeticShare>; 3]> {
        tracing::trace!("computing t polynomial...");
        let len = zkey.domain_size * 4;
        let z1 = Self::get_z1(domains);
        let z2 = Self::get_z2(domains);
        let z3 = Self::get_z3(domains);
        let mut w = P::ScalarField::one();
        let mut ap = Vec::with_capacity(len);
        let mut bp = Vec::with_capacity(len);
        let mut cp = Vec::with_capacity(len);
        let id = state.id();

        let pow_root_of_unity = domains.root_of_unity_pow;
        let pow_plus2_root_of_unity = domains.root_of_unity_pow_2;
        // We do not want to have any network operation in here to reduce MPC rounds. To enforce this, we have a for_each loop here (Network operations require a result)
        let w_product_span = tracing::debug_span!("first w product").entered();
        (0..len).for_each(|_| {
            ap.push(T::add_mul_public(challenges.b[1], challenges.b[0], w));
            bp.push(T::add_mul_public(challenges.b[3], challenges.b[2], w));
            cp.push(T::add_mul_public(challenges.b[5], challenges.b[4], w));
            w *= &pow_plus2_root_of_unity;
        });
        w_product_span.exit();

        let ab_span = tracing::debug_span!("a_b, a_bp, ap_b, ap_bp").entered();
        // TODO check and explain numbers
        let mut state0 = state.fork(len)?;
        let mut state1 = state.fork(len)?;
        let mut state2 = state.fork(len)?;
        let mut state3 = state.fork(len)?;
        let (a_b, a_bp, ap_b, ap_bp) = mpc_net::join4(
            || {
                T::mul_vec(
                    &polys.poly_eval_a.eval,
                    &polys.poly_eval_b.eval,
                    &nets[0],
                    &mut state0,
                )
            },
            || T::mul_vec(&polys.poly_eval_a.eval, &bp, &nets[1], &mut state1),
            || T::mul_vec(&polys.poly_eval_b.eval, &ap, &nets[2], &mut state2),
            || T::mul_vec(&ap, &bp, &nets[3], &mut state3),
        );
        let a_b = a_b?;
        let a_bp = a_bp?;
        let ap_b = ap_b?;
        let ap_bp = ap_bp?;
        ab_span.exit();

        let w_product_span = tracing::debug_span!("second w product").entered();
        // TODO keep RAM requirements in mind
        let mut e1 = Vec::with_capacity(len);
        let mut e1z = Vec::with_capacity(len);

        let mut e2a = Vec::with_capacity(len);
        let mut e2b = Vec::with_capacity(len);
        let mut e2c = Vec::with_capacity(len);
        let mut e2d = Vec::with_capacity(len);
        let mut zp = Vec::with_capacity(len);

        let mut e3a = Vec::with_capacity(len);
        let mut e3b = Vec::with_capacity(len);
        let mut e3c = Vec::with_capacity(len);
        let mut e3d = Vec::with_capacity(len);
        let mut zwp = Vec::with_capacity(len);
        let mut w = P::ScalarField::one();
        // We do not want to have any network operation in here to reduce MPC rounds. To enforce this, we have a for_each loop here (Network operations require a result)
        (0..len).for_each(|i| {
            let a = &polys.poly_eval_a.eval[i];
            let b = &polys.poly_eval_b.eval[i];
            let c = &polys.poly_eval_c.eval[i];
            let z = &polys.z.eval[i];
            let qm = zkey.qm_poly.evaluations[i];
            let ql = zkey.ql_poly.evaluations[i];
            let qr = zkey.qr_poly.evaluations[i];
            let qo = zkey.qo_poly.evaluations[i];
            let qc = zkey.qc_poly.evaluations[i];
            let s1 = zkey.s1_poly.evaluations[i];
            let s2 = zkey.s2_poly.evaluations[i];
            let s3 = zkey.s3_poly.evaluations[i];
            let a_bp = &a_bp[i];
            let a_b = &a_b[i];
            let ap_b = &ap_b[i];
            let ap = &ap[i];
            let bp = &bp[i];

            let w2 = w.square();
            let zp_lhs = T::mul_with_public(challenges.b[6], w2);
            let zp_rhs = T::mul_with_public(challenges.b[7], w);
            let zp_ = T::add(zp_lhs, zp_rhs);
            let zp_ = T::add(challenges.b[8], zp_);
            zp.push(zp_);

            let w_w = w * pow_root_of_unity;
            let w_w2 = w_w.square();
            let zw = polys.z.eval[(len + 4 + i) % (len)];
            let zwp_lhs = T::mul_with_public(challenges.b[6], w_w2);
            let zwp_rhs = T::mul_with_public(challenges.b[7], w_w);
            let zwp_ = T::add(zwp_lhs, zwp_rhs);
            let zwp_ = T::add(challenges.b[8], zwp_);
            zwp.push(zwp_);

            let mut a0 = T::add(*a_bp, *ap_b);
            let mod_i = i % 4;
            if mod_i != 0 {
                let z1 = z1[mod_i];
                let ap_bp = ap_bp[i];
                let tmp = T::mul_with_public(ap_bp, z1);
                a0 = T::add(a0, tmp);
            }

            let (mut e1_, mut e1z_) = (a_b.to_owned(), a0.to_owned());
            e1_ = T::mul_with_public(e1_, qm);
            e1z_ = T::mul_with_public(e1z_, qm);

            e1_ = T::add_mul_public(e1_, *a, ql);
            e1z_ = T::add_mul_public(e1z_, *ap, ql);

            e1_ = T::add_mul_public(e1_, *b, qr);
            e1z_ = T::add_mul_public(e1z_, *bp, qr);

            e1_ = T::add_mul_public(e1_, *c, qo);
            e1z_ = T::add_mul_public(e1z_, cp[i], qo);

            let mut pi = T::ArithmeticShare::default();
            for (j, lagrange) in zkey.lagrange.iter().enumerate() {
                let tmp = T::mul_with_public(polys.buffer_a[j], lagrange.evaluations[i]);
                pi = T::sub(pi, tmp);
            }

            e1_ = T::add(e1_, pi);
            e1_ = T::add_with_public(id, e1_, qc);
            e1.push(e1_);
            e1z.push(e1z_);

            let betaw = challenges.beta * w;
            e2a.push(T::add_with_public(id, *a, betaw + challenges.gamma));
            e2b.push(T::add_with_public(
                id,
                *b,
                betaw * zkey.verifying_key.k1 + challenges.gamma,
            ));
            e2c.push(T::add_with_public(
                id,
                *c,
                betaw * zkey.verifying_key.k2 + challenges.gamma,
            ));

            e2d.push(*z);
            e3a.push(T::add_with_public(
                id,
                *a,
                s1 * challenges.beta + challenges.gamma,
            ));
            e3b.push(T::add_with_public(
                id,
                *b,
                s2 * challenges.beta + challenges.gamma,
            ));
            e3c.push(T::add_with_public(
                id,
                *c,
                s3 * challenges.beta + challenges.gamma,
            ));
            e3d.push(zw);
            w *= pow_plus2_root_of_unity;
        });
        w_product_span.exit();

        let mul4vec_span = tracing::debug_span!("mul4 vec").entered();
        let [e2, e2z_0, e2z_1, e2z_2, e2z_3] =
            mul4vec!(nets, state, &e2a, &e2b, &e2c, &e2d, &ap, &bp, &cp, &zp, len)?;

        let [e3, e3z_0, e3z_1, e3z_2, e3z_3] = mul4vec!(
            nets, state, &e3a, &e3b, &e3c, &e3d, &ap, &bp, &cp, &zwp, len
        )?;
        mul4vec_span.exit();

        let t_tz_span = tracing::debug_span!("t, tz").entered();
        let mut t_vec = Vec::with_capacity(len);
        let mut tz_vec = Vec::with_capacity(len);
        // We do not want to have any network operation in here to reduce MPC rounds. To enforce this, we have a for_each loop here (Network operations require a result)
        (0..len).for_each(|i| {
            let mut e2 = e2[i];
            let mut e2z = mul4vec_post!(e2z_0, e2z_1, e2z_2, e2z_3, i, z1, z2, z3);
            let mut e3 = e3[i];
            let mut e3z = mul4vec_post!(e3z_0, e3z_1, e3z_2, e3z_3, i, z1, z2, z3);

            let z = polys.z.eval[i];
            let zp = zp[i];

            e2 = T::mul_with_public(e2, challenges.alpha);
            e2z = T::mul_with_public(e2z, challenges.alpha);

            e3 = T::mul_with_public(e3, challenges.alpha);
            e3z = T::mul_with_public(e3z, challenges.alpha);

            let mut e4 = T::add_with_public(id, z, -P::ScalarField::one());
            e4 = T::mul_with_public(e4, zkey.lagrange[0].evaluations[i]);
            e4 = T::mul_with_public(e4, challenges.alpha2);

            let mut e4z = T::mul_with_public(zp, zkey.lagrange[0].evaluations[i]);
            e4z = T::mul_with_public(e4z, challenges.alpha2);

            let mut t = T::add(e1[i], e2);
            t = T::sub(t, e3);
            t = T::add(t, e4);

            let mut tz = T::add(e1z[i], e2z);
            tz = T::sub(tz, e3z);
            tz = T::add(tz, e4z);

            t_vec.push(t);
            tz_vec.push(tz);
        });
        let mut coefficients_t = T::ifft(&t_vec, &domains.extended_domain);
        T::neg_vec_in_place(&mut coefficients_t[..zkey.domain_size]);

        // We do not want to have any network operation in here to reduce MPC rounds. To enforce this, we have a for_each loop here (Network operations require a result)
        (zkey.domain_size..len).for_each(|i| {
            let a_lhs = &coefficients_t[i - zkey.domain_size];
            let a_rhs = &coefficients_t[i];
            let a = T::sub(*a_lhs, *a_rhs);
            coefficients_t[i] = a;
            // Snarkjs is checking whether the poly was divisble by Zh, but we cannot do this here
        });

        let coefficients_tz = T::ifft(&tz_vec, &domains.extended_domain);

        let mut t_final = izip!(coefficients_t.iter(), coefficients_tz.iter())
            .map(|(lhs, rhs)| T::add(*lhs, *rhs));
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

        t2[0] = T::sub(t2[0], challenges.b[9]);
        t2.push(challenges.b[10].to_owned());

        t3[0] = T::sub(t3[0], challenges.b[10]);
        t_tz_span.exit();
        tracing::debug!("computing t polynomial done!");
        Ok([t1, t2, t3])
    }

    // Round 3 of https://eprint.iacr.org/2019/953.pdf (page 29)
    #[instrument(level = "debug", name = "Plonk - Round 3", skip_all)]
    pub(super) fn round3(self) -> PlonkProofResult<Round4<'a, P, T, N>> {
        let Self {
            nets,
            state,
            domains,
            challenges,
            proof,
            polys,
            data,
        } = self;
        tracing::debug!("building challenges for round3 with Keccak256..");
        let mut transcript = Keccak256Transcript::<P>::default();
        // STEP 3.1 - Compute evaluation challenge alpha ∈ F
        transcript.add_scalar(challenges.beta);
        transcript.add_scalar(challenges.gamma);
        transcript.add_point(proof.commit_z.into());

        let alpha = transcript.get_challenge();
        let alpha2 = alpha.square();
        tracing::debug!("alpha: {alpha}, alpha2: {alpha2}");
        let challenges = Round3Challenges::new(challenges, alpha, alpha2);

        let t_span = tracing::debug_span!("compute t").entered();
        let [t1, t2, t3] = Self::compute_t(nets, state, &domains, &challenges, data.zkey, &polys)?;
        t_span.exit();

        tracing::debug!("committing to poly t (MSMs)");
        let commit_t_span = tracing::debug_span!("commit t").entered();
        // Compute [T1]_1, [T2]_1, [T3]_1
        let (commit_t1, commit_t2, commit_t3) = rayon_join3!(
            || T::msm_public_points_g1(&data.zkey.p_tau[..t1.len()], &t1),
            || T::msm_public_points_g1(&data.zkey.p_tau[..t2.len()], &t2),
            || T::msm_public_points_g1(&data.zkey.p_tau[..t3.len()], &t3)
        );
        commit_t_span.exit();

        let opened = T::open_point_vec_g1(&[commit_t1, commit_t2, commit_t3], &nets[0], state)?;

        let polys = FinalPolys::new(polys, t1, t2, t3);
        let proof = Round3Proof::new(proof, opened[0], opened[1], opened[2]);
        tracing::debug!("round3 result: {proof}");
        Ok(Round4 {
            nets,
            state,
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
    use circom_types::Witness;
    use circom_types::plonk::Zkey;
    use co_circom_types::SharedWitness;

    use crate::{
        mpc::plain::PlainPlonkDriver,
        round1::{Round1, Round1Challenges},
    };

    use ark_ec::pairing::Pairing;
    use std::str::FromStr;

    use circom_types::CheckElement;

    macro_rules! g1_from_xy {
        ($x: expr,$y: expr) => {
            <ark_bn254::Bn254 as Pairing>::G1Affine::new(
                ark_bn254::Fq::from_str($x).unwrap(),
                ark_bn254::Fq::from_str($y).unwrap(),
            )
        };
    }

    #[test]
    fn test_round3_multiplier2() {
        for check in [CheckElement::Yes, CheckElement::No] {
            let mut reader = BufReader::new(
                File::open("../../test_vectors/Plonk/bn254/multiplier2/circuit.zkey").unwrap(),
            );
            let zkey = Zkey::<Bn254>::from_reader(&mut reader, check).unwrap();
            let witness_file =
                File::open("../../test_vectors/Plonk/bn254/multiplier2/witness.wtns").unwrap();
            let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
            let public_input = witness.values[..=zkey.n_public].to_vec();
            let witness = SharedWitness {
                public_inputs: public_input.clone(),
                witness: witness.values[zkey.n_public + 1..].to_vec(),
            };

            let challenges = Round1Challenges::<Bn254, PlainPlonkDriver>::deterministic();
            let mut state = ();
            let mut round1 = Round1::init_round(&[(); 8], &mut state, &zkey, witness).unwrap();
            round1.challenges = challenges;
            let round2 = round1.round1().unwrap();
            let round3 = round2.round2().unwrap();
            let round4 = round3.round3().unwrap();
            assert_eq!(
                round4.proof.commit_t1,
                g1_from_xy!(
                    "14195659590223391588638033663362337117591990036333098666602164584829450067964",
                    "3556648023705175372561455635244621029434015848660599980046006090530807598362"
                )
            );
            assert_eq!(
                round4.proof.commit_t2,
                g1_from_xy!(
                    "3735872884021926351213137728148437717828227598563721199864822205706753909354",
                    "18937554230046023488342718793325695277505320264073327441600348965411357658388"
                )
            );
            assert_eq!(
                round4.proof.commit_t3,
                g1_from_xy!(
                    "16143856432987537130591639896375147783771732347095191085601174356801897211531",
                    "181289684093540268434296060454656362990106137005120511426963659280111589561"
                )
            );
        }
    }
}
