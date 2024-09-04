use crate::{
    mpc::CircomPlonkProver,
    plonk_utils,
    round1::{Round1Challenges, Round1Polys, Round1Proof},
    round3::Round3,
    types::{Domains, Keccak256Transcript, PlonkData, PolyEval},
    PlonkProofError, PlonkProofResult,
};
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use circom_types::plonk::ZKey;
use mpc_core::protocols::rep3new::arithmetic::mul_vec;
use num_traits::One;

// To reduce the number of communication rounds, we implement the array_prod_mul macro according to https://www.usenix.org/system/files/sec22-ozdemir.pdf, p11 first paragraph.
// TODO parallelize these? With a different network structure this might not be needed though
macro_rules! array_prod_mul {
    ($driver: expr, $inp: expr) => {{
        // Do the multiplications of inp[i] * inp[i-1] in constant rounds
        let len = $inp.len();
        let r = (0..=len).map(|_| $driver.rand()).collect::<Vec<_>>();
        let r_inv = futures::executor::block_on($driver.inv_many(&r))?;
        let r_inv0 = vec![r_inv[0].clone(); len];
        let mut unblind = futures::executor::block_on($driver.mul_vec(&r_inv0, &r[1..]))?;

        let mul = futures::executor::block_on($driver.mul_vec(&r[..len], &$inp))?;
        let mut open = $driver.mul_open_many(&mul, &r_inv[1..])?;

        for i in 1..open.len() {
            open[i] = open[i] * open[i - 1];
        }

        for (unblind, open) in unblind.iter_mut().zip(open.iter()) {
            *unblind = $driver.mul_with_public(open, unblind);
        }
        unblind
    }};
}

// Round 2 of https://eprint.iacr.org/2019/953.pdf (page 28)
pub(super) struct Round2<'a, P: Pairing, T: CircomPlonkProver<P>> {
    pub(super) driver: T,
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
impl<'a, P: Pairing, T: CircomPlonkProver<P>> Round2<'a, P, T> {
    // Computes the permutation polynomial z(X) (see https://eprint.iacr.org/2019/953.pdf)
    // To reduce the number of communication rounds, we implement the array_prod_mul macro according to https://www.usenix.org/system/files/sec22-ozdemir.pdf, p11 first paragraph.
    fn compute_z(
        driver: &mut T,
        zkey: &ZKey<P>,
        domains: &Domains<P::ScalarField>,
        challenges: &Round2Challenges<P, T>,
        polys: &Round1Polys<P, T>,
    ) -> PlonkProofResult<PolyEval<P, T>> {
        tracing::debug!("computing z polynomial...");
        let pow_root_of_unity = domains.root_of_unity_pow;
        let mut w = P::ScalarField::one();
        let mut n1 = Vec::with_capacity(zkey.domain_size);
        let mut n2 = Vec::with_capacity(zkey.domain_size);
        let mut n3 = Vec::with_capacity(zkey.domain_size);
        let mut d1 = Vec::with_capacity(zkey.domain_size);
        let mut d2 = Vec::with_capacity(zkey.domain_size);
        let mut d3 = Vec::with_capacity(zkey.domain_size);
        for i in 0..zkey.domain_size {
            let a = &polys.buffer_a[i];
            let b = &polys.buffer_b[i];
            let c = &polys.buffer_c[i];

            // Z(X) := numArr / denArr
            // numArr := (a + beta·ω + gamma)(b + beta·ω·k1 + gamma)(c + beta·ω·k2 + gamma)
            let betaw = challenges.beta * w;

            let n1_ = driver.add_with_public(&betaw, a);
            let n1_ = driver.add_with_public(&challenges.gamma, &n1_);

            let tmp = zkey.verifying_key.k1 * betaw;
            let n2_ = driver.add_with_public(&tmp, b);
            let n2_ = driver.add_with_public(&challenges.gamma, &n2_);

            let tmp = zkey.verifying_key.k2 * betaw;
            let n3_ = driver.add_with_public(&tmp, c);
            let n3_ = driver.add_with_public(&challenges.gamma, &n3_);

            n1.push(n1_);
            n2.push(n2_);
            n3.push(n3_);

            // denArr := (a + beta·sigma1 + gamma)(b + beta·sigma2 + gamma)(c + beta·sigma3 + gamma)
            let d1_ =
                driver.add_with_public(&(challenges.beta * zkey.s1_poly.evaluations[i * 4]), a);
            let d1_ = driver.add_with_public(&challenges.gamma, &d1_);

            let d2_ =
                driver.add_with_public(&(challenges.beta * zkey.s2_poly.evaluations[i * 4]), b);
            let d2_ = driver.add_with_public(&challenges.gamma, &d2_);

            let d3_ =
                driver.add_with_public(&(challenges.beta * zkey.s3_poly.evaluations[i * 4]), c);
            let d3_ = driver.add_with_public(&challenges.gamma, &d3_);

            d1.push(d1_);
            d2.push(d2_);
            d3.push(d3_);

            w *= &pow_root_of_unity;
        }

        // TODO parallelize these? With a different network structure this might not be needed though
        let num = futures::executor::block_on(driver.mul_vec(&n1, &n2))?;
        let num = futures::executor::block_on(driver.mul_vec(&num, &n3))?;
        let den = futures::executor::block_on(driver.mul_vec(&d1, &d2))?;
        let den = futures::executor::block_on(driver.mul_vec(&den, &d3))?;

        // TODO parallelize these? With a different network structure this might not be needed though
        // Do the multiplications of num[i] * num[i-1] and den[i] * den[i-1] in constant rounds
        let num = array_prod_mul!(driver, num);
        let den = array_prod_mul!(driver, den);

        // Compute the inverse of denArr to compute in the next command the
        // division numArr/denArr by multiplying num · 1/denArr
        let den = futures::executor::block_on(driver.inv_many(&den))?;
        let mut buffer_z = futures::executor::block_on(driver.mul_vec(&num, &den))?;

        buffer_z.rotate_right(1); // Required by SNARKJs/Plonk

        // Compute polynomial coefficients z(X) from buffer_z
        let poly_z = driver.ifft(&buffer_z, &domains.domain);

        // Compute extended evaluations of z(X) polynomial
        let eval_z = driver.fft(&poly_z, &domains.extended_domain);

        let poly_z = plonk_utils::blind_coefficients::<P, T>(driver, &poly_z, &challenges.b[6..9]);

        if poly_z.len() > zkey.domain_size + 3 {
            Err(PlonkProofError::PolynomialDegreeTooLarge)
        } else {
            tracing::debug!("computing z polynomial done!");
            Ok(PolyEval {
                poly: poly_z.into(),
                eval: eval_z,
            })
        }
    }

    // Round 2 of https://eprint.iacr.org/2019/953.pdf (page 28)
    pub(super) fn round2(self) -> PlonkProofResult<Round3<'a, P, T>> {
        let Self {
            mut driver,
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
        let z = Self::compute_z(&mut driver, zkey, &domains, &challenges, &polys)?;
        // STEP 2.3 - Compute permutation [z]_1

        tracing::debug!("committing to poly z (MSMs)");
        let commit_z = self
            .driver
            .msm_public_points(&zkey.p_tau[..z.poly.len()], &z.poly);
        let proof = Round2Proof::new(proof, driver.open_point(&commit_z)?);
        tracing::debug!("round2 result: {proof}");

        Ok(Round3 {
            driver,
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
    use circom_types::plonk::ZKey;
    use circom_types::Witness;
    use co_circom_snarks::SharedWitness;
    use mpc_core::protocols::plain::PlainDriver;

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
    use std::str::FromStr;
    #[test]
    fn test_round2_multiplier2() {
        let mut driver = PlainDriver::<ark_bn254::Fr>::default();
        let mut reader = BufReader::new(
            File::open("../../test_vectors/Plonk/bn254/multiplier2/circuit.zkey").unwrap(),
        );
        let zkey = ZKey::<Bn254>::from_reader(&mut reader).unwrap();
        let witness_file =
            File::open("../../test_vectors/Plonk/bn254/multiplier2/witness.wtns").unwrap();
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
        assert_eq!(
            round3.proof.commit_z,
            g1_from_xy!(
                "21851995660159341992573113210608672476110709810652234421585224566450425950906",
                "9396597540042847815549199092556045933393323370500084953024302516882239981142"
            )
        );
    }
}
