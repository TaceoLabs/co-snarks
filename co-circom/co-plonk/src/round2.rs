use crate::{
    PlonkProofError, PlonkProofResult,
    mpc::CircomPlonkProver,
    plonk_utils,
    round1::{Round1Challenges, Round1Polys, Round1Proof},
    round3::Round3,
    types::{Domains, Keccak256Transcript, PlonkData, PolyEval},
};
use ark_ec::CurveGroup;
use ark_ec::pairing::Pairing;
use circom_types::plonk::ZKey;
use mpc_core::MpcState;
use mpc_net::Network;
use num_traits::One;
use tracing::instrument;

// Round 2 of https://eprint.iacr.org/2019/953.pdf (page 28)
pub(super) struct Round2<'a, P: Pairing, T: CircomPlonkProver<P>, N: Network> {
    pub(super) nets: &'a [N; 8],
    pub(super) state: &'a mut T::State,
    pub(super) domains: Domains<P::ScalarField>,
    pub(super) challenges: Round1Challenges<P, T>,
    pub(super) proof: Round1Proof<P>,
    pub(super) polys: Round1Polys<P, T>,
    pub(super) data: PlonkData<'a, P, T>,
}

pub(super) struct Round2Challenges<P: Pairing, T: CircomPlonkProver<P>> {
    pub(super) b: [T::ArithmeticShare; 11],
    pub(super) beta: P::ScalarField,
    pub(super) gamma: P::ScalarField,
}

pub(super) struct Round2Proof<P: Pairing> {
    pub(super) commit_a: P::G1,
    pub(super) commit_b: P::G1,
    pub(super) commit_c: P::G1,
    pub(super) commit_z: P::G1,
}

pub(super) struct Round2Polys<P: Pairing, T: CircomPlonkProver<P>> {
    pub(super) buffer_a: Vec<T::ArithmeticShare>,
    pub(super) poly_eval_a: PolyEval<P, T>,
    pub(super) poly_eval_b: PolyEval<P, T>,
    pub(super) poly_eval_c: PolyEval<P, T>,
    pub(super) z: PolyEval<P, T>,
}

impl<P: Pairing> std::fmt::Display for Round2Proof<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "Round2Proof(z: {})", self.commit_z.into_affine())
    }
}
impl<P: Pairing, T: CircomPlonkProver<P>> Round2Challenges<P, T> {
    fn new(
        round1_challenges: Round1Challenges<P, T>,
        beta: P::ScalarField,
        gamma: P::ScalarField,
    ) -> Self {
        Self {
            b: round1_challenges.b,
            beta,
            gamma,
        }
    }
}

impl<P: Pairing> Round2Proof<P> {
    fn new(round1_proof: Round1Proof<P>, commit_z: P::G1) -> Self {
        Self {
            commit_a: round1_proof.commit_a,
            commit_b: round1_proof.commit_b,
            commit_c: round1_proof.commit_c,
            commit_z,
        }
    }
}

impl<P: Pairing, T: CircomPlonkProver<P>> Round2Polys<P, T> {
    fn new(polys: Round1Polys<P, T>, z: PolyEval<P, T>) -> Self {
        Self {
            buffer_a: polys.buffer_a,
            poly_eval_a: polys.a,
            poly_eval_b: polys.b,
            poly_eval_c: polys.c,
            z,
        }
    }
}

// Round 2 of https://eprint.iacr.org/2019/953.pdf (page 28)
impl<'a, P: Pairing, T: CircomPlonkProver<P>, N: Network + 'static> Round2<'a, P, T, N> {
    // Computes the permutation polynomial z(X) (see https://eprint.iacr.org/2019/953.pdf)
    // To reduce the number of communication rounds, we implement the array_prod_mul macro according to https://www.usenix.org/system/files/sec22-ozdemir.pdf, p11 first paragraph.
    #[instrument(level = "debug", name = "compute z", skip_all)]
    fn compute_z(
        nets: &[N; 8],
        state: &mut T::State,
        zkey: &ZKey<P>,
        domains: &Domains<P::ScalarField>,
        challenges: &Round2Challenges<P, T>,
        polys: &Round1Polys<P, T>,
    ) -> PlonkProofResult<PolyEval<P, T>> {
        let pow_root_of_unity = domains.root_of_unity_pow;
        let mut n1 = Vec::with_capacity(zkey.domain_size);
        let mut n2 = Vec::with_capacity(zkey.domain_size);
        let mut n3 = Vec::with_capacity(zkey.domain_size);
        let mut d1 = Vec::with_capacity(zkey.domain_size);
        let mut d2 = Vec::with_capacity(zkey.domain_size);
        let mut d3 = Vec::with_capacity(zkey.domain_size);
        let id = state.id();
        let mut w = P::ScalarField::one();
        // TODO: multithread me - this is not so easy as other
        // parts as we go through the roots of unity but it is doable
        let num_den_span = tracing::debug_span!("compute num/den").entered();
        for i in 0..zkey.domain_size {
            let a = &polys.buffer_a[i];
            let b = &polys.buffer_b[i];
            let c = &polys.buffer_c[i];

            // Z(X) := numArr / denArr
            // numArr := (a + beta·ω + gamma)(b + beta·ω·k1 + gamma)(c + beta·ω·k2 + gamma)
            let betaw = challenges.beta * w;

            let n1_ = T::add_with_public(id, *a, betaw);
            let n1_ = T::add_with_public(id, n1_, challenges.gamma);

            let tmp = zkey.verifying_key.k1 * betaw;
            let n2_ = T::add_with_public(id, *b, tmp);
            let n2_ = T::add_with_public(id, n2_, challenges.gamma);

            let tmp = zkey.verifying_key.k2 * betaw;
            let n3_ = T::add_with_public(id, *c, tmp);
            let n3_ = T::add_with_public(id, n3_, challenges.gamma);

            n1.push(n1_);
            n2.push(n2_);
            n3.push(n3_);

            // denArr := (a + beta·sigma1 + gamma)(b + beta·sigma2 + gamma)(c + beta·sigma3 + gamma)
            let d1_ = T::add_with_public(id, *a, challenges.beta * zkey.s1_poly.evaluations[i * 4]);
            let d1_ = T::add_with_public(id, d1_, challenges.gamma);

            let d2_ = T::add_with_public(id, *b, challenges.beta * zkey.s2_poly.evaluations[i * 4]);
            let d2_ = T::add_with_public(id, d2_, challenges.gamma);

            let d3_ = T::add_with_public(id, *c, challenges.beta * zkey.s3_poly.evaluations[i * 4]);
            let d3_ = T::add_with_public(id, d3_, challenges.gamma);

            d1.push(d1_);
            d2.push(d2_);
            d3.push(d3_);

            w *= &pow_root_of_unity;
        }

        num_den_span.exit();

        let batched_mul_span = tracing::debug_span!("buffer z network round").entered();
        // TODO check and explain numbers
        let mut state0 = state.fork(zkey.domain_size * 6 + 2)?;
        let mut state1 = state.fork(zkey.domain_size * 7 + 2)?;
        let (num, den) = mpc_net::join(
            || T::array_prod_mul(false, &n1, &n2, &n3, &nets[0], &mut state0),
            || T::array_prod_mul(true, &d1, &d2, &d3, &nets[1], &mut state1),
        );
        let num = num?;
        let den = den?;

        let mut buffer_z = T::mul_vec(&num, &den, &nets[0], state)?;
        buffer_z.rotate_right(1); // Required by SNARKJs/Plonk
        batched_mul_span.exit();

        let fft_span = tracing::debug_span!("fft-ifft for z(x)").entered();

        // Compute polynomial coefficients z(X) from buffer_z
        let mut poly_z = T::ifft(&buffer_z, &domains.domain);

        // Compute extended evaluations of z(X) polynomial
        let eval_z = T::fft(&poly_z, &domains.extended_domain);
        plonk_utils::blind_coefficients::<P, T>(&mut poly_z, &challenges.b[6..9]);
        fft_span.exit();

        if poly_z.len() > zkey.domain_size + 3 {
            Err(PlonkProofError::PolynomialDegreeTooLarge)
        } else {
            tracing::debug!("computing z polynomial done!");
            Ok(PolyEval {
                poly: poly_z,
                eval: eval_z,
            })
        }
    }

    // Round 2 of https://eprint.iacr.org/2019/953.pdf (page 28)
    #[instrument(level = "debug", name = "Plonk - Round 2", skip_all)]
    pub(super) fn round2(self) -> PlonkProofResult<Round3<'a, P, T, N>> {
        let Self {
            nets,
            state,
            data,
            proof,
            challenges,
            domains,
            polys,
        } = self;
        let zkey = &data.zkey;
        let public_input = &data.witness.public_inputs;
        tracing::debug!("building challenges for round2 with Keccak256..");
        let mut transcript = Keccak256Transcript::<P>::default();
        transcript.add_point(zkey.verifying_key.qm);
        transcript.add_point(zkey.verifying_key.ql);
        transcript.add_point(zkey.verifying_key.qr);
        transcript.add_point(zkey.verifying_key.qo);
        transcript.add_point(zkey.verifying_key.qc);
        transcript.add_point(zkey.verifying_key.s1);
        transcript.add_point(zkey.verifying_key.s2);
        transcript.add_point(zkey.verifying_key.s3);
        for val in public_input.iter().cloned() {
            transcript.add_scalar(val);
        }
        transcript.add_point(proof.commit_a.into());
        transcript.add_point(proof.commit_b.into());
        transcript.add_point(proof.commit_c.into());

        let beta = transcript.get_challenge();

        let mut transcript = Keccak256Transcript::<P>::default();
        transcript.add_scalar(beta);
        let gamma = transcript.get_challenge();
        tracing::debug!("beta: {beta}, gamma: {gamma}");
        let challenges = Round2Challenges::new(challenges, beta, gamma);
        let z = Self::compute_z(nets, state, zkey, &domains, &challenges, &polys)?;
        // STEP 2.3 - Compute permutation [z]_1

        tracing::debug!("committing to poly z (MSMs)");
        let commit_z = T::msm_public_points_g1(&zkey.p_tau[..z.poly.len()], &z.poly);
        let commit_z = T::open_point_g1(commit_z, &nets[0], state)?;
        let proof = Round2Proof::new(proof, commit_z);
        tracing::debug!("round2 result: {proof}");
        Ok(Round3 {
            nets,
            state,
            domains,
            challenges,
            proof,
            polys: Round2Polys::new(polys, z),
            data,
        })
    }
}

#[cfg(test)]
pub mod tests {

    use std::{fs::File, io::BufReader};

    use ark_bn254::Bn254;
    use circom_types::Witness;
    use circom_types::plonk::ZKey;
    use co_circom_types::SharedWitness;

    use crate::mpc::plain::PlainPlonkDriver;
    use crate::round1::Round1;
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
    use circom_types::traits::CheckElement;
    use std::str::FromStr;

    #[test]
    fn test_round2_multiplier2() {
        for check in [CheckElement::Yes, CheckElement::No] {
            let mut reader = BufReader::new(
                File::open("../../test_vectors/Plonk/bn254/multiplier2/circuit.zkey").unwrap(),
            );
            let zkey = ZKey::<Bn254>::from_reader(&mut reader, check).unwrap();
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
            assert_eq!(
                round3.proof.commit_z,
                g1_from_xy!(
                    "21851995660159341992573113210608672476110709810652234421585224566450425950906",
                    "9396597540042847815549199092556045933393323370500084953024302516882239981142"
                )
            );
        }
    }
}
