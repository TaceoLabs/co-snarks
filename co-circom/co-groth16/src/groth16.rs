//! A Groth16 proof protocol that uses a collaborative MPC protocol to generate the proof.
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{FftField, PrimeField};
use ark_groth16::{Proof, ProvingKey};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::ConstraintMatrices;
use co_circom_snarks::{Rep3SharedWitness, ShamirSharedWitness, SharedWitness};
use eyre::Result;
use mpc_core::protocols::rep3::network::{IoContext, Rep3Network};
use mpc_core::protocols::shamir::network::ShamirNetwork;
use mpc_core::protocols::shamir::{ShamirPreprocessing, ShamirProtocol};
use num_traits::ToPrimitive;
use std::marker::PhantomData;
use tracing::instrument;

use crate::mpc::plain::PlainGroth16Driver;
use crate::mpc::rep3::Rep3Groth16Driver;
use crate::mpc::shamir::ShamirGroth16Driver;
use crate::mpc::CircomGroth16Prover;

pub use reduction::{CircomReduction, R1CSToQAP};
mod reduction;

macro_rules! rayon_join5 {
    ($t1: expr, $t2: expr, $t3: expr, $t4: expr, $t5: expr) => {{
        let ((((v, w), x), y), z) = rayon::join(
            || rayon::join(|| rayon::join(|| rayon::join($t1, $t2), $t3), $t4),
            $t5,
        );
        (v, w, x, y, z)
    }};
}

/// The plain [`Groth16`] type.
///
/// This type is actually the [`CoGroth16`] type initialized with
/// the [`PlainGroth16Driver`], a single party (you) MPC protocol (i.e., your everyday Groth16), and using the Circom R1CSToQAPReduction by default.
/// You can use this instance to create a proof, but we recommend against it for a real use-case.
/// Have a look at the [Groth16 implementation of arkworks](https://docs.rs/ark-groth16/latest/ark_groth16/)
/// for a plain Groth16 prover.
///
/// More interesting is the [`Groth16::verify`] method. You can verify any circom Groth16 proof, be it
/// from snarkjs or one created by this project. Under the hood we use the arkwork Groth16 project for verifying.
pub type Groth16<P, R = CircomReduction> = CoGroth16<P, PlainGroth16Driver, R>;

/// A type alias for a [CoGroth16] protocol using replicated secret sharing, using the Circom R1CSToQAPReduction by default.
pub type Rep3CoGroth16<P, N, R = CircomReduction> = CoGroth16<P, Rep3Groth16Driver<N>, R>;
/// A type alias for a [CoGroth16] protocol using shamir secret sharing, using the Circom R1CSToQAPReduction by default.
pub type ShamirCoGroth16<P, N, R = CircomReduction> =
    CoGroth16<P, ShamirGroth16Driver<<P as Pairing>::ScalarField, N>, R>;

/* old way of computing root of unity, does not work for bls12_381:
let root_of_unity = {
    let domain_size_double = 2 * domain_size;
    let domain_double =
        D::new(domain_size_double).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
    domain_double.element(1)
};
new one is computed in the same way as in snarkjs (More precisely in ffjavascript/src/wasm_field1.js)
calculate smallest quadratic non residue q (by checking q^((p-1)/2)=-1 mod p) also calculate smallest t (F::TRACE) s.t. p-1=2^s*t, s is the two_adicity
use g=q^t (this is a 2^s-th root of unity) as (some kind of) generator and compute another domain by repeatedly squaring g, should get to 1 in the s+1-th step.
then if log2(domain_size) equals s we take as root of unity q^2, and else we take the log2(domain_size) + 1-th element of the domain created above
*/
#[instrument(level = "debug", name = "root of unity", skip_all)]
fn root_of_unity_for_groth16<F: PrimeField + FftField>(
    pow: usize,
    domain: &mut GeneralEvaluationDomain<F>,
) -> F {
    let (q, roots) = co_circom_snarks::utils::roots_of_unity::<F>();
    match domain {
        GeneralEvaluationDomain::Radix2(domain) => {
            domain.group_gen = roots[pow];
            domain.group_gen_inv = domain.group_gen.inverse().expect("can compute inverse");
        }
        GeneralEvaluationDomain::MixedRadix(domain) => {
            domain.group_gen = roots[pow];
            domain.group_gen_inv = domain.group_gen.inverse().expect("can compute inverse");
        }
    };
    if F::TWO_ADICITY.to_u64().unwrap() == domain.log_size_of_group() {
        q.square()
    } else {
        roots[domain.log_size_of_group().to_usize().unwrap() + 1]
    }
}

/// A Groth16 proof protocol that uses a collaborative MPC protocol to generate the proof.
pub struct CoGroth16<P: Pairing, T: CircomGroth16Prover<P>, R: R1CSToQAP> {
    pub(crate) driver: T,
    phantom_data: PhantomData<(P, R)>,
}

impl<P: Pairing, T: CircomGroth16Prover<P>, R: R1CSToQAP> CoGroth16<P, T, R> {
    /// Creates a new [CoGroth16] protocol with a given MPC driver.
    pub fn new(driver: T) -> Self {
        Self {
            driver,
            phantom_data: PhantomData,
        }
    }

    /// Execute the Groth16 prover using the internal MPC driver.
    /// This version takes the Circom-generated constraint matrices as input and does not re-calculate them.
    #[instrument(level = "debug", name = "Groth16 - Proof", skip_all)]
    fn prove_inner(
        mut self,
        pkey: &ProvingKey<P>,
        matrices: &ConstraintMatrices<P::ScalarField>,
        private_witness: SharedWitness<P::ScalarField, T::ArithmeticShare>,
    ) -> Result<(Proof<P>, T)> {
        let public_inputs = private_witness.public_inputs;
        if public_inputs.len() != matrices.num_instance_variables {
            eyre::bail!(
                "amount of public inputs do not match with provided constraint system! Expected {}, but got {}",
                matrices.num_instance_variables,
                public_inputs.len()
            )
        }

        let h = R::witness_map_from_matrices(
            &mut self.driver,
            matrices,
            &public_inputs,
            &private_witness.witness,
        )?;
        let (r, s) = (self.driver.rand()?, self.driver.rand()?);

        let private_witness_half_share: Vec<_> = private_witness
            .witness
            .into_iter()
            .map(T::to_half_share)
            .collect();

        self.create_proof_with_assignment(
            pkey,
            r,
            s,
            h,
            &public_inputs,
            &private_witness_half_share,
        )
    }

    fn calculate_coeff<C>(
        id: T::PartyID,
        initial: T::PointHalfShare<C>,
        query: &[C::Affine],
        vk_param: C::Affine,
        input_assignment: &[P::ScalarField],
        aux_assignment: &[T::ArithmeticHalfShare],
    ) -> T::PointHalfShare<C>
    where
        C: CurveGroup<ScalarField = P::ScalarField>,
    {
        let pub_len = input_assignment.len();

        let (priv_acc, pub_acc) = rayon::join(
            || T::msm_public_points_hs(&query[1 + pub_len..], aux_assignment),
            || C::msm_unchecked(&query[1..=pub_len], input_assignment),
        );

        let mut res = initial;
        T::add_assign_points_public_hs(id, &mut res, &query[0].into_group());
        T::add_assign_points_public_hs(id, &mut res, &vk_param.into_group());
        T::add_assign_points_public_hs(id, &mut res, &pub_acc);
        res += priv_acc;
        res
    }

    #[instrument(level = "debug", name = "create proof with assignment", skip_all)]
    fn create_proof_with_assignment(
        mut self,
        pkey: &ProvingKey<P>,
        r: T::ArithmeticShare,
        s: T::ArithmeticShare,
        h: Vec<T::ArithmeticHalfShare>,
        input_assignment: &[P::ScalarField],
        aux_assignment: &[T::ArithmeticHalfShare],
    ) -> Result<(Proof<P>, T)> {
        let delta_g1 = pkey.delta_g1.into_group();

        let party_id = self.driver.get_party_id();
        let alpha_g1 = pkey.vk.alpha_g1;
        let beta_g1 = pkey.beta_g1;
        let beta_g2 = pkey.vk.beta_g2;
        let delta_g2 = pkey.vk.delta_g2.into_group();

        let (r_g1, s_g1, s_g2, l_acc, h_acc) = rayon_join5!(
            || {
                let compute_a =
                    tracing::debug_span!("compute A in create proof with assignment").entered();
                // Compute A
                let r = T::to_half_share(r);
                let r_g1 = T::scalar_mul_public_point_hs(&delta_g1, r);
                let r_g1 = Self::calculate_coeff(
                    party_id,
                    r_g1,
                    &pkey.a_query,
                    alpha_g1,
                    &input_assignment[1..],
                    aux_assignment,
                );
                compute_a.exit();
                r_g1
            },
            || {
                let compute_b =
                    tracing::debug_span!("compute B/G1 in create proof with assignment").entered();
                // Compute B in G1
                // In original implementation this is skipped if r==0, however r is shared in our case
                let s = T::to_half_share(s);
                let s_g1 = T::scalar_mul_public_point_hs(&delta_g1, s);
                let s_g1 = Self::calculate_coeff(
                    party_id,
                    s_g1,
                    &pkey.b_g1_query,
                    beta_g1,
                    &input_assignment[1..],
                    aux_assignment,
                );
                compute_b.exit();
                s_g1
            },
            || {
                let compute_b =
                    tracing::debug_span!("compute B/G2 in create proof with assignment").entered();
                // Compute B in G2
                let s = T::to_half_share(s);
                let s_g2 = T::scalar_mul_public_point_hs(&delta_g2, s);
                let s_g2 = Self::calculate_coeff(
                    party_id,
                    s_g2,
                    &pkey.b_g2_query,
                    beta_g2,
                    &input_assignment[1..],
                    aux_assignment,
                );
                compute_b.exit();
                s_g2
            },
            || {
                let msm_l_query = tracing::debug_span!("msm l_query").entered();
                let result: <T as CircomGroth16Prover<P>>::PointHalfShare<P::G1> =
                    T::msm_public_points_hs(&pkey.l_query, aux_assignment);
                msm_l_query.exit();
                result
            },
            || {
                let msm_h_query = tracing::debug_span!("msm h_query").entered();
                //perform the msm for h
                let result = T::msm_public_points_hs(&pkey.h_query, &h);
                msm_h_query.exit();
                result
            }
        );

        let rs_span = tracing::debug_span!("r*s without networking").entered();
        let rs = self.driver.local_mul_vec(vec![r], vec![s]).pop().unwrap();
        let r_s_delta_g1 = T::scalar_mul_public_point_hs(&delta_g1, rs);
        rs_span.exit();

        let g_a = r_g1;
        let g1_b = s_g1;

        let network_round = tracing::debug_span!("network round after calc coeff").entered();
        let (g_a_opened, r_g1_b) = self.driver.open_point_and_scalar_mul(&g_a, &g1_b, r)?;
        network_round.exit();

        let last_round = tracing::debug_span!("finish - open two points and some adds").entered();
        let s = T::to_half_share(s);
        let s_g_a = T::scalar_mul_public_point_hs(&g_a_opened, s);

        let mut g_c = s_g_a;
        g_c += r_g1_b;
        g_c -= r_s_delta_g1;
        g_c += l_acc;

        g_c += h_acc;

        let g2_b = s_g2;
        let (g_c_opened, g2_b_opened) = self.driver.open_two_half_points(g_c, g2_b)?;
        last_round.exit();

        Ok((
            Proof {
                a: g_a_opened.into_affine(),
                b: g2_b_opened.into_affine(),
                c: g_c_opened.into_affine(),
            },
            self.driver,
        ))
    }
}

impl<P: Pairing, N: Rep3Network, R: R1CSToQAP> Rep3CoGroth16<P, N, R> {
    /// Create a [`Proof`].
    pub fn prove(
        net: N,
        pkey: &ProvingKey<P>,
        matrices: &ConstraintMatrices<P::ScalarField>,
        witness: Rep3SharedWitness<P::ScalarField>,
    ) -> Result<(Proof<P>, N)> {
        let mut io_context0 = IoContext::init(net)?;
        let io_context1 = io_context0.fork()?;
        let driver = Rep3Groth16Driver::new(io_context0, io_context1);
        let prover = CoGroth16 {
            driver,
            phantom_data: PhantomData::<(P, R)>,
        };
        // execute prover in MPC
        let (proof, driver) = prover.prove_inner(pkey, matrices, witness)?;
        Ok((proof, driver.get_network()))
    }
}

impl<P: Pairing, N: ShamirNetwork, R: R1CSToQAP> ShamirCoGroth16<P, N, R> {
    /// Create a [`Proof`].
    pub fn prove(
        net: N,
        threshold: usize,
        pkey: &ProvingKey<P>,
        matrices: &ConstraintMatrices<P::ScalarField>,
        witness: ShamirSharedWitness<P::ScalarField>,
    ) -> Result<(Proof<P>, N)> {
        // we need 2 + 1 number of corr rand pairs. We need the values r/s (1 pair) and 2 muls (2
        // pairs)
        let num_pairs = 3;
        let preprocessing = ShamirPreprocessing::new(threshold, net, num_pairs)?;
        let mut protocol0 = ShamirProtocol::from(preprocessing);
        // the protocol1 is only used for scalar_mul and a field_mul which need 1 pair each (ergo 2
        // pairs)
        let protocol1 = protocol0.fork_with_pairs(2)?;
        let driver = ShamirGroth16Driver::new(protocol0, protocol1);
        let prover = CoGroth16 {
            driver,
            phantom_data: PhantomData::<(P, R)>,
        };
        // execute prover in MPC
        let (proof, driver) = prover.prove_inner(pkey, matrices, witness)?;
        Ok((proof, driver.get_network()))
    }
}

impl<P: Pairing, R: R1CSToQAP> Groth16<P, R> {
    /// *Locally* create a `Groth16` proof. This is just the [`CoGroth16`] prover
    /// initialized with the [`PlainGroth16Driver`].
    ///
    /// DOES NOT PERFORM ANY MPC. For a plain prover checkout the [Groth16 implementation of arkworks](https://docs.rs/ark-groth16/latest/ark_groth16/).
    pub fn plain_prove(
        pkey: &ProvingKey<P>,
        matrices: &ConstraintMatrices<P::ScalarField>,
        private_witness: SharedWitness<P::ScalarField, P::ScalarField>,
    ) -> Result<Proof<P>> {
        let prover = Self {
            driver: PlainGroth16Driver,
            phantom_data: PhantomData::<(P, R)>,
        };
        let (proof, _) = prover.prove_inner(pkey, matrices, private_witness)?;
        Ok(proof)
    }
}
