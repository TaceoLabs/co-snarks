use std::marker::PhantomData;

use crate::{types::Keccak256Transcript, Domains};
use ark_ec::{pairing::Pairing, Group};
use ark_ff::Field;
use circom_types::{
    plonk::{JsonVerificationKey, PlonkProof},
    traits::{CircomArkworksPairingBridge, CircomArkworksPrimeFieldBridge},
};
use num_traits::{One, Zero};

pub(crate) struct VerfierChallenges<P: Pairing> {
    alpha: P::ScalarField,
    beta: P::ScalarField,
    gamma: P::ScalarField,
    pub(crate) xi: P::ScalarField,
    v: [P::ScalarField; 5],
    u: P::ScalarField,
}

impl<P: Pairing> VerfierChallenges<P> {
    fn new() -> Self {
        Self {
            alpha: P::ScalarField::zero(),
            beta: P::ScalarField::zero(),
            gamma: P::ScalarField::zero(),
            xi: P::ScalarField::zero(),
            v: [P::ScalarField::zero(); 5],
            u: P::ScalarField::zero(),
        }
    }
}
pub(super) struct Plonk<P: Pairing> {
    phantom_data: PhantomData<P>,
}

impl<P: Pairing> Plonk<P>
where
    P::ScalarField: CircomArkworksPrimeFieldBridge,
    P: Pairing + CircomArkworksPairingBridge,
    P::BaseField: CircomArkworksPrimeFieldBridge,
{
    pub fn verify(
        vk: &JsonVerificationKey<P>,
        proof: &PlonkProof<P>,
        public_inputs: &[P::ScalarField],
    ) -> Result<bool, eyre::Report>
    where
        P: Pairing,
        P: CircomArkworksPairingBridge,
        P::BaseField: CircomArkworksPrimeFieldBridge,
        P::ScalarField: CircomArkworksPrimeFieldBridge,
    {
        if vk.n_public != public_inputs.len() {
            return Err(eyre::eyre!("Invalid number of public inputs"));
        }

        if proof.is_well_constructed().is_err() {
            return Ok(false);
        }

        let challenges = Plonk::<P>::calculate_challenges(vk, proof, public_inputs);

        let domains = Domains::<P>::new(1 << vk.power)?;
        let roots = domains.roots_of_unity;
        let (l, xin) = Plonk::<P>::calculate_lagrange_evaluations(
            vk.power,
            vk.n_public,
            &challenges.xi,
            &roots,
        );
        let pi = Plonk::<P>::calculate_pi(public_inputs, &l);
        let (r0, d) = Plonk::<P>::calculate_r0_d(vk, proof, &challenges, pi, &l[0], xin);

        let e = Plonk::<P>::calculate_e(proof, &challenges, r0);
        let f = Plonk::<P>::calculate_f(vk, proof, &challenges, d);

        Ok(Plonk::<P>::valid_pairing(
            vk,
            proof,
            &challenges,
            e,
            f,
            &roots,
        ))
    }
    pub(super) fn calculate_challenges(
        vk: &JsonVerificationKey<P>,
        proof: &PlonkProof<P>,
        public_inputs: &[P::ScalarField],
    ) -> VerfierChallenges<P>
    where
        P: CircomArkworksPairingBridge,
        P::BaseField: CircomArkworksPrimeFieldBridge,
        P::ScalarField: CircomArkworksPrimeFieldBridge,
    {
        let mut challenges = VerfierChallenges::new();
        let mut transcript = Keccak256Transcript::<P>::default();

        // Challenge round 2: beta and gamma
        transcript.add_point(vk.qm);
        transcript.add_point(vk.ql);
        transcript.add_point(vk.qr);
        transcript.add_point(vk.qo);
        transcript.add_point(vk.qc);
        transcript.add_point(vk.s1);
        transcript.add_point(vk.s2);
        transcript.add_point(vk.s3);

        for p in public_inputs.iter().cloned() {
            transcript.add_scalar(p);
        }

        transcript.add_point(proof.a);
        transcript.add_point(proof.b);
        transcript.add_point(proof.c);

        challenges.beta = transcript.get_challenge();

        let mut transcript = Keccak256Transcript::<P>::default();
        transcript.add_scalar(challenges.beta);
        challenges.gamma = transcript.get_challenge();

        // Challenge round 3: alpha
        let mut transcript = Keccak256Transcript::<P>::default();
        transcript.add_scalar(challenges.beta);
        transcript.add_scalar(challenges.gamma);
        transcript.add_point(proof.z);
        challenges.alpha = transcript.get_challenge();

        // Challenge round 4: xi
        let mut transcript = Keccak256Transcript::<P>::default();
        transcript.add_scalar(challenges.alpha);
        transcript.add_point(proof.t1);
        transcript.add_point(proof.t2);
        transcript.add_point(proof.t3);
        challenges.xi = transcript.get_challenge();

        // Challenge round 5: v
        let mut transcript = Keccak256Transcript::<P>::default();
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

        // Challenge: u
        let mut transcript = Keccak256Transcript::<P>::default();
        transcript.add_point(proof.wxi);
        transcript.add_point(proof.wxiw);
        challenges.u = transcript.get_challenge();

        challenges
    }

    pub(crate) fn calculate_lagrange_evaluations(
        power: usize,
        n_public: usize,
        xi: &P::ScalarField,
        root_of_unitys: &[P::ScalarField],
    ) -> (Vec<P::ScalarField>, P::ScalarField) {
        let mut xin = *xi;
        let mut domain_size = 1;
        for _ in 0..power {
            xin.square_in_place();
            domain_size *= 2;
        }
        let zh = xin - P::ScalarField::one();
        let l_length = usize::max(1, n_public);
        let mut l = Vec::with_capacity(l_length);
        let root_of_unity = root_of_unitys[power];

        let n = P::ScalarField::from(domain_size as u64);
        let mut w = P::ScalarField::one();
        for _ in 0..l_length {
            l.push((w * zh) / (n * (*xi - w)));
            w *= root_of_unity;
        }
        (l, xin)
    }

    pub(crate) fn calculate_pi(
        public_inputs: &[P::ScalarField],
        l: &[P::ScalarField],
    ) -> P::ScalarField {
        let mut pi = P::ScalarField::zero();
        //TODO WE WANT THE PUBLIC INPUTS WITHOUT THE LEADING ZERO!
        //WHERE DO WE NEED TO CHANGE THIS
        for (val, l) in public_inputs.iter().skip(1).zip(l) {
            pi -= *l * val;
        }
        pi
    }

    pub(crate) fn calculate_r0_d(
        vk: &JsonVerificationKey<P>,
        proof: &PlonkProof<P>,
        challenges: &VerfierChallenges<P>,
        pi: P::ScalarField,
        l0: &P::ScalarField,
        xin: P::ScalarField,
    ) -> (P::ScalarField, P::G1)
    where
        P: CircomArkworksPairingBridge,
        P::BaseField: CircomArkworksPrimeFieldBridge,
        P::ScalarField: CircomArkworksPrimeFieldBridge,
    {
        // R0
        let e1 = pi;
        let e2 = challenges.alpha.square() * l0;
        let e3a = proof.eval_a + proof.eval_s1 * challenges.beta + challenges.gamma;
        let e3b = proof.eval_b + proof.eval_s2 * challenges.beta + challenges.gamma;
        let e3c = proof.eval_c + challenges.gamma;

        let e3 = e3a * e3b * e3c * proof.eval_zw * challenges.alpha;
        let r0 = e1 - e2 - e3;

        // D
        let d1 = vk.qm * proof.eval_a * proof.eval_b
            + vk.ql * proof.eval_a
            + vk.qr * proof.eval_b
            + vk.qo * proof.eval_c
            + vk.qc;

        let betaxi = challenges.beta * challenges.xi;
        let d2a1 = proof.eval_a + betaxi + challenges.gamma;
        let d2a2 = proof.eval_b + betaxi * vk.k1 + challenges.gamma;
        let d2a3 = proof.eval_c + betaxi * vk.k2 + challenges.gamma;
        let d2a = d2a1 * d2a2 * d2a3 * challenges.alpha;
        let d2b = e2;
        let d2 = proof.z * (d2a + d2b + challenges.u);

        let d3a = e3a;
        let d3b = e3b;
        let d3c = challenges.alpha * challenges.beta * proof.eval_zw;
        let d3 = vk.s3 * (d3a * d3b * d3c);

        let d4_low = proof.t1;
        let d4_mid = proof.t2 * xin;
        let d4_high = proof.t3 * xin.square();
        let d4 = (d4_low + d4_mid + d4_high) * (xin - P::ScalarField::one());

        let d = d1 + d2 - d3 - d4;

        (r0, d)
    }

    pub(crate) fn calculate_e(
        proof: &PlonkProof<P>,
        challenges: &VerfierChallenges<P>,
        r0: P::ScalarField,
    ) -> P::G1 {
        let e = challenges.v[0] * proof.eval_a
            + challenges.v[1] * proof.eval_b
            + challenges.v[2] * proof.eval_c
            + challenges.v[3] * proof.eval_s1
            + challenges.v[4] * proof.eval_s2
            + challenges.u * proof.eval_zw
            - r0;
        P::G1::generator() * e
    }

    pub(crate) fn calculate_f(
        vk: &JsonVerificationKey<P>,
        proof: &PlonkProof<P>,
        challenges: &VerfierChallenges<P>,
        d: P::G1,
    ) -> P::G1
    where
        P: CircomArkworksPairingBridge,
        P::BaseField: CircomArkworksPrimeFieldBridge,
        P::ScalarField: CircomArkworksPrimeFieldBridge,
    {
        d + proof.a * challenges.v[0]
            + proof.b * challenges.v[1]
            + proof.c * challenges.v[2]
            + vk.s1 * challenges.v[3]
            + vk.s2 * challenges.v[4]
    }

    pub(crate) fn valid_pairing(
        vk: &JsonVerificationKey<P>,
        proof: &PlonkProof<P>,
        challenges: &VerfierChallenges<P>,
        e: P::G1,
        f: P::G1,
        root_of_unitys: &[P::ScalarField],
    ) -> bool
    where
        P: CircomArkworksPairingBridge,
        P::BaseField: CircomArkworksPrimeFieldBridge,
        P::ScalarField: CircomArkworksPrimeFieldBridge,
    {
        let root_of_unity = root_of_unitys[vk.power];
        let s = challenges.u * challenges.xi * root_of_unity;

        let a1 = -(proof.wxi + proof.wxiw * challenges.u);
        let b1 = proof.wxi * challenges.xi + proof.wxiw * s + e + f;

        let lhs = P::pairing(a1, vk.x2);
        let rhs = P::pairing(b1, P::G2::generator());

        lhs == rhs
    }
}
