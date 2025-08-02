//! A Groth16 proof protocol that uses a collaborative MPC protocol to generate the proof.
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{FftField, LegendreSymbol, PrimeField};
use ark_groth16::{Proof, ProvingKey};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::ConstraintMatrices;
use co_circom_types::{Rep3SharedWitness, ShamirSharedWitness, SharedWitness};
use eyre::Result;
use mpc_core::MpcState;
use mpc_core::protocols::rep3::Rep3State;
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_core::protocols::shamir::{ShamirPreprocessing, ShamirState};
use mpc_net::Network;
use num_traits::ToPrimitive;
use std::marker::PhantomData;
use tracing::instrument;

use crate::mpc::CircomGroth16Prover;
use crate::mpc::plain::PlainGroth16Driver;
use crate::mpc::rep3::Rep3Groth16Driver;
use crate::mpc::shamir::ShamirGroth16Driver;

pub use reduction::{CircomReduction, LibSnarkReduction, R1CSToQAP};
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
pub type Groth16<P> = CoGroth16<P, PlainGroth16Driver>;

/// A type alias for a [CoGroth16] protocol using replicated secret sharing, using the Circom R1CSToQAPReduction by default.
pub type Rep3CoGroth16<P> = CoGroth16<P, Rep3Groth16Driver>;
/// A type alias for a [CoGroth16] protocol using shamir secret sharing, using the Circom R1CSToQAPReduction by default.
pub type ShamirCoGroth16<P> = CoGroth16<P, ShamirGroth16Driver>;

/// Computes the roots of unity over the provided prime field. This method
/// is equivalent with [circom's implementation](https://github.com/iden3/ffjavascript/blob/337b881579107ab74d5b2094dbe1910e33da4484/src/wasm_field1.js).
///
/// We calculate smallest quadratic non residue q (by checking q^((p-1)/2)=-1 mod p). We also calculate smallest t s.t. p-1=2^s*t, s is the two adicity.
/// We use g=q^t (this is a 2^s-th root of unity) as (some kind of) generator and compute another domain by repeatedly squaring g, should get to 1 in the s+1-th step.
/// Then if log2(\text{domain_size}) equals s we take q^2 as root of unity. Else we take the log2(\text{domain_size}) + 1-th element of the domain created above.
fn roots_of_unity<F: PrimeField + FftField>() -> (F, Vec<F>) {
    let mut roots = vec![F::zero(); F::TWO_ADICITY.to_usize().unwrap() + 1];
    let mut q = F::one();
    while q.legendre() != LegendreSymbol::QuadraticNonResidue {
        q += F::one();
    }
    let z = q.pow(F::TRACE);
    roots[0] = z;
    for i in 1..roots.len() {
        roots[i] = roots[i - 1].square();
    }
    roots.reverse();
    (q, roots)
}

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
    let (q, roots) = roots_of_unity::<F>();
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
pub struct CoGroth16<P: Pairing, T: CircomGroth16Prover<P>> {
    phantom_data: PhantomData<(P, T)>,
}

impl<P: Pairing, T: CircomGroth16Prover<P>> CoGroth16<P, T> {
    /// Execute the Groth16 prover using the internal MPC driver.
    /// This version takes the Circom-generated constraint matrices as input and does not re-calculate them.
    #[instrument(level = "debug", name = "Groth16 - Proof", skip_all)]
    fn prove_inner<N: Network, R: R1CSToQAP>(
        net0: &N,
        net1: &N,
        state0: &mut T::State,
        state1: &mut T::State,
        pkey: &ProvingKey<P>,
        matrices: &ConstraintMatrices<P::ScalarField>,
        private_witness: SharedWitness<P::ScalarField, T::ArithmeticShare>,
    ) -> eyre::Result<Proof<P>> {
        let public_inputs = private_witness.public_inputs;
        if public_inputs.len() != matrices.num_instance_variables {
            eyre::bail!(
                "amount of public inputs do not match with provided constraint system! Expected {}, but got {}",
                matrices.num_instance_variables,
                public_inputs.len()
            )
        }

        let h = R::witness_map_from_matrices::<P, T>(
            state0,
            matrices,
            &public_inputs,
            &private_witness.witness,
        )?;
        let (r, s) = (T::rand(net0, state0)?, T::rand(net0, state0)?);

        let private_witness_half_share: Vec<_> = private_witness
            .witness
            .into_iter()
            .map(T::to_half_share)
            .collect();

        Self::create_proof_with_assignment(
            net0,
            net1,
            state0,
            state1,
            pkey,
            r,
            s,
            h,
            &public_inputs,
            &private_witness_half_share,
        )
    }

    fn calculate_coeff<C>(
        id: <T::State as MpcState>::PartyID,
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
    #[expect(clippy::too_many_arguments)]
    fn create_proof_with_assignment<N: Network>(
        net0: &N,
        net1: &N,
        state0: &mut T::State,
        state1: &mut T::State,
        pkey: &ProvingKey<P>,
        r: T::ArithmeticShare,
        s: T::ArithmeticShare,
        h: Vec<T::ArithmeticHalfShare>,
        input_assignment: &[P::ScalarField],
        aux_assignment: &[T::ArithmeticHalfShare],
    ) -> eyre::Result<Proof<P>> {
        let delta_g1 = pkey.delta_g1.into_group();

        let id = state0.id();
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
                    id,
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
                    id,
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
                    id,
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
        let rs = T::local_mul_many(vec![r], vec![s], state0).pop().unwrap();
        let r_s_delta_g1 = T::scalar_mul_public_point_hs(&delta_g1, rs);
        rs_span.exit();

        let g_a = r_g1;
        let g1_b = s_g1;

        let network_round = tracing::debug_span!("network round after calc coeff").entered();
        let (g_a_opened, r_g1_b) = mpc_net::join(
            || T::open_half_point(g_a, net0, state0),
            || T::scalar_mul(&g1_b, r, net1, state1),
        );
        let g_a_opened = g_a_opened?;
        let r_g1_b = r_g1_b?;
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
        let (g_c_opened, g2_b_opened) = mpc_net::join(
            || T::open_half_point(g_c, net0, state0),
            || T::open_half_point(g2_b, net1, state1),
        );
        let g_c_opened = g_c_opened?;
        let g2_b_opened = g2_b_opened?;
        last_round.exit();

        Ok(Proof {
            a: g_a_opened.into_affine(),
            b: g2_b_opened.into_affine(),
            c: g_c_opened.into_affine(),
        })
    }
}

impl<P: Pairing> Rep3CoGroth16<P> {
    /// Create a [`Proof`].
    pub fn prove<N: Network, R: R1CSToQAP>(
        net0: &N,
        net1: &N,
        pkey: &ProvingKey<P>,
        matrices: &ConstraintMatrices<P::ScalarField>,
        witness: Rep3SharedWitness<P::ScalarField>,
    ) -> eyre::Result<Proof<P>> {
        let mut state0 = Rep3State::new(net0, A2BType::default())?;
        let mut state1 = state0.fork(0)?;
        // execute prover in MPC
        Self::prove_inner::<N, R>(
            net0,
            net1,
            &mut state0,
            &mut state1,
            pkey,
            matrices,
            witness,
        )
    }
}

impl<P: Pairing> ShamirCoGroth16<P> {
    /// Create a [`Proof`].
    pub fn prove<N: Network, R: R1CSToQAP>(
        net0: &N,
        net1: &N,
        num_parties: usize,
        threshold: usize,
        pkey: &ProvingKey<P>,
        matrices: &ConstraintMatrices<P::ScalarField>,
        witness: ShamirSharedWitness<P::ScalarField>,
    ) -> eyre::Result<Proof<P>> {
        // we need 3 number of corr rand pairs. 2 for two rand calls, 1 for scalar_mul
        let num_pairs = 3;
        let preprocessing = ShamirPreprocessing::new(num_parties, threshold, num_pairs, net0)?;
        let mut state0 = ShamirState::from(preprocessing);
        let mut state1 = state0.fork(1)?;
        // execute prover in MPC
        Self::prove_inner::<N, R>(
            net0,
            net1,
            &mut state0,
            &mut state1,
            pkey,
            matrices,
            witness,
        )
    }
}

impl<P: Pairing> Groth16<P> {
    /// *Locally* create a `Groth16` proof. This is just the [`CoGroth16`] prover
    /// initialized with the [`PlainGroth16Driver`].
    ///
    /// DOES NOT PERFORM ANY MPC. For a plain prover checkout the [Groth16 implementation of arkworks](https://docs.rs/ark-groth16/latest/ark_groth16/).
    pub fn plain_prove<R: R1CSToQAP>(
        pkey: &ProvingKey<P>,
        matrices: &ConstraintMatrices<P::ScalarField>,
        private_witness: SharedWitness<P::ScalarField, P::ScalarField>,
    ) -> Result<Proof<P>> {
        Self::prove_inner::<_, R>(&(), &(), &mut (), &mut (), pkey, matrices, private_witness)
    }
}
