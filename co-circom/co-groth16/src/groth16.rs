//! A Groth16 proof protocol that uses a collaborative MPC protocol to generate the proof.
use ark_ec::pairing::Pairing;
use ark_ec::scalar_mul::variable_base::VariableBaseMSM;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{FftField, PrimeField};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use circom_types::groth16::{ConstraintMatrix, Groth16Proof, ZKey};
use circom_types::traits::{CircomArkworksPairingBridge, CircomArkworksPrimeFieldBridge};
use co_circom_snarks::{Rep3SharedWitness, ShamirSharedWitness, SharedWitness};
use eyre::Result;
use mpc_core::protocols::rep3::Rep3State;
use mpc_core::protocols::shamir::{ShamirPreprocessing, ShamirProtocol};
use mpc_core::Fork;
use mpc_engine::{MpcEngine, Network};
use num_traits::identities::One;
use num_traits::ToPrimitive;
use rayon::prelude::*;
use std::marker::PhantomData;
use std::sync::Arc;
use tracing::instrument;

use crate::mpc::plain::PlainGroth16Driver;
use crate::mpc::rep3::Rep3Groth16Driver;
use crate::mpc::shamir::ShamirGroth16Driver;
use crate::mpc::CircomGroth16Prover;

/// The plain [`Groth16`] type.
///
/// This type is actually the [`CoGroth16`] type initialized with
/// the [`PlainGroth16Driver`], a single party (you) MPC protocol (i.e., your everyday Groth16).
/// You can use this instance to create a proof, but we recommend against it for a real use-case.
/// Have a look at the [Groth16 implementation of arkworks](https://docs.rs/ark-groth16/latest/ark_groth16/)
/// for a plain Groth16 prover.
///
/// More interesting is the [`Groth16::verify`] method. You can verify any circom Groth16 proof, be it
/// from snarkjs or one created by this project. Under the hood we use the arkwork Groth16 project for verifying.
pub type Groth16<P> = CoGroth16<P, PlainGroth16Driver>;

/// A type alias for a [CoGroth16] protocol using replicated secret sharing.
pub type Rep3CoGroth16<P> = CoGroth16<P, Rep3Groth16Driver>;
/// A type alias for a [CoGroth16] protocol using shamir secret sharing.
pub type ShamirCoGroth16<P> = CoGroth16<P, ShamirGroth16Driver>;

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
pub struct CoGroth16<P: Pairing, T: CircomGroth16Prover<P>> {
    phantom_data0: PhantomData<P>,
    phantom_data1: PhantomData<T>,
}

impl<P: Pairing + CircomArkworksPairingBridge, T: CircomGroth16Prover<P>> CoGroth16<P, T>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    /// Execute the Groth16 prover using the internal MPC driver.
    /// This version takes the Circom-generated constraint matrices as input and does not re-calculate them.
    #[instrument(level = "debug", name = "Groth16 - Proof", skip_all)]
    fn prove_inner<N: Network + 'static>(
        engine: &MpcEngine<N>,
        state: &mut T::State,
        zkey: Arc<ZKey<P>>,
        private_witness: SharedWitness<P::ScalarField, T::ArithmeticShare>,
    ) -> Result<Groth16Proof<P>> {
        let public_inputs = Arc::new(private_witness.public_inputs);
        if public_inputs.len() != zkey.n_public + 1 {
            eyre::bail!(
                "amount of public inputs do not match with provided zkey! Expected {}, but got {}",
                zkey.n_public + 1,
                public_inputs.len()
            )
        }

        let private_witness = Arc::new(private_witness.witness);
        let h = Self::witness_map_from_matrices(
            engine,
            state,
            &zkey,
            &public_inputs,
            &private_witness,
        )?;
        let (r, s) = (
            engine.install_net(|net| T::rand(net, state))?,
            engine.install_net(|net| T::rand(net, state))?,
        );

        Self::create_proof_with_assignment(
            engine,
            state,
            Arc::clone(&zkey),
            r,
            s,
            h,
            public_inputs,
            private_witness,
        )
    }

    fn evaluate_constraint(
        party_id: usize,
        domain_size: usize,
        matrix: &ConstraintMatrix<P::ScalarField>,
        public_inputs: &[P::ScalarField],
        private_witness: &[T::ArithmeticShare],
    ) -> Vec<T::ArithmeticShare> {
        let mut result = matrix
            .par_iter()
            .with_min_len(256)
            .map(|x| T::evaluate_constraint(party_id, x, public_inputs, private_witness))
            .collect::<Vec<_>>();
        result.resize(domain_size, T::ArithmeticShare::default());
        result
    }

    #[instrument(level = "debug", name = "witness map from matrices", skip_all)]
    fn witness_map_from_matrices<N: Network + 'static>(
        engine: &MpcEngine<N>,
        state: &mut T::State,
        zkey: &ZKey<P>,
        public_inputs: &[P::ScalarField],
        private_witness: &[T::ArithmeticShare],
    ) -> Result<Vec<P::ScalarField>> {
        let num_constraints = zkey.num_constraints;
        let num_inputs = zkey.n_public + 1;
        let power = zkey.pow;
        let mut domain =
            GeneralEvaluationDomain::<P::ScalarField>::new(num_constraints + num_inputs)
                .ok_or(eyre::eyre!("Polynomial Degree too large"))?;
        let domain_size = domain.size();
        let party_id = engine.id();

        let eval_constraint_span =
            tracing::debug_span!("evaluate constraints + root of unity computation").entered();
        let (roots_to_power_domain, a, b) = engine.join3_cpu(
            || {
                let root_of_unity_span =
                    tracing::debug_span!("root of unity computation").entered();
                let root_of_unity = root_of_unity_for_groth16(power, &mut domain);
                let mut roots = Vec::with_capacity(domain_size);
                let mut c = P::ScalarField::one();
                for _ in 0..domain_size {
                    roots.push(c);
                    c *= root_of_unity;
                }
                root_of_unity_span.exit();
                Arc::new(roots)
            },
            || {
                let eval_constraint_span_a =
                    tracing::debug_span!("evaluate constraints - a").entered();
                let mut result = Self::evaluate_constraint(
                    party_id,
                    domain_size,
                    &zkey.a_matrix,
                    public_inputs,
                    private_witness,
                );
                let promoted_public = T::promote_to_trivial_shares(party_id, public_inputs);
                result[num_constraints..num_constraints + num_inputs]
                    .clone_from_slice(&promoted_public[..num_inputs]);
                eval_constraint_span_a.exit();
                result
            },
            || {
                let eval_constraint_span_b =
                    tracing::debug_span!("evaluate constraints - a").entered();
                let result = Self::evaluate_constraint(
                    party_id,
                    domain_size,
                    &zkey.b_matrix,
                    public_inputs,
                    private_witness,
                );
                eval_constraint_span_b.exit();
                result
            },
        );
        eval_constraint_span.exit();

        let domain = Arc::new(domain);

        let a_domain = Arc::clone(&domain);
        let b_domain = Arc::clone(&domain);
        let c_domain = Arc::clone(&domain);
        let mut a_result = a.clone();
        let mut b_result = b.clone();
        let a_roots = Arc::clone(&roots_to_power_domain);
        let b_roots = Arc::clone(&roots_to_power_domain);
        let c_roots = Arc::clone(&roots_to_power_domain);

        let a_a_roots = engine.spawn_cpu(move || {
            let a_span = tracing::debug_span!("a: distribute powers mul a (fft/ifft)").entered();
            a_domain.ifft_in_place(&mut a_result);
            T::distribute_powers_and_mul_by_const(&mut a_result, &a_roots);
            a_domain.fft_in_place(&mut a_result);
            a_span.exit();
            a_result
        });

        let b_b_roots = engine.spawn_cpu(move || {
            let b_span = tracing::debug_span!("b: distribute powers mul b (fft/ifft)").entered();
            b_domain.ifft_in_place(&mut b_result);
            T::distribute_powers_and_mul_by_const(&mut b_result, &b_roots);
            b_domain.fft_in_place(&mut b_result);
            b_span.exit();
            b_result
        });

        let local_mul_vec_span = tracing::debug_span!("c: local_mul_vec").entered();
        let mut ab = T::local_mul_vec(a, b, state);
        local_mul_vec_span.exit();

        let c = engine.spawn_cpu(move || {
            let ifft_span = tracing::debug_span!("c: ifft in dist pows").entered();
            c_domain.ifft_in_place(&mut ab);
            ifft_span.exit();
            let dist_pows_span = tracing::debug_span!("c: dist pows").entered();
            ab.par_iter_mut()
                .zip_eq(c_roots.par_iter())
                .with_min_len(512)
                .for_each(|(share, pow)| {
                    *share *= pow;
                });
            dist_pows_span.exit();
            let fft_span = tracing::debug_span!("c: fft in dist pows").entered();
            c_domain.fft_in_place(&mut ab);
            fft_span.exit();
            ab
        });

        let a = a_a_roots.join();
        let b = b_b_roots.join();

        let compute_ab_span = tracing::debug_span!("compute ab").entered();
        let local_ab_span = tracing::debug_span!("local part (mul and sub)").entered();
        // same as above. No IO task is run at the moment.
        let mut ab = T::local_mul_vec(a, b, state);
        local_ab_span.exit();
        let c = c.join();
        engine.install_cpu(|| {
            ab.par_iter_mut()
                .zip_eq(c.par_iter())
                .with_min_len(512)
                .for_each(|(a, b)| {
                    *a -= b;
                });
        });
        compute_ab_span.exit();

        Ok(ab)
    }

    fn calculate_coeff<C>(
        id: usize,
        initial: T::PointShare<C>,
        query: &[C::Affine],
        vk_param: C::Affine,
        input_assignment: &[P::ScalarField],
        aux_assignment: &[T::ArithmeticShare],
    ) -> T::PointShare<C>
    where
        C: CurveGroup<ScalarField = P::ScalarField>,
    {
        let pub_len = input_assignment.len();

        let (priv_acc, pub_acc) = rayon::join(
            || T::msm_public_points(&query[1 + pub_len..], aux_assignment),
            || C::msm_unchecked(&query[1..=pub_len], input_assignment),
        );

        let mut res = initial;
        T::add_assign_points_public(id, &mut res, &query[0].into_group());
        T::add_assign_points_public(id, &mut res, &vk_param.into_group());
        T::add_assign_points_public(id, &mut res, &pub_acc);
        T::add_assign_points(&mut res, &priv_acc);
        res
    }

    #[allow(clippy::too_many_arguments)]
    #[instrument(level = "debug", name = "create proof with assignment", skip_all)]
    fn create_proof_with_assignment<N: Network + 'static>(
        engine: &MpcEngine<N>,
        state: &mut T::State,
        zkey: Arc<ZKey<P>>,
        r: T::ArithmeticShare,
        s: T::ArithmeticShare,
        h: Vec<P::ScalarField>,
        input_assignment: Arc<Vec<P::ScalarField>>,
        aux_assignment: Arc<Vec<T::ArithmeticShare>>,
    ) -> Result<Groth16Proof<P>> {
        let delta_g1 = zkey.delta_g1.into_group();
        let h_query = Arc::clone(&zkey);
        let l_query = Arc::clone(&zkey);

        let party_id = engine.id();
        let a_query = Arc::clone(&zkey);
        let b_g1_query = Arc::clone(&zkey);
        let b_g2_query = Arc::clone(&zkey);
        let input_assignment1 = Arc::clone(&input_assignment);
        let input_assignment2 = Arc::clone(&input_assignment);
        let input_assignment3 = Arc::clone(&input_assignment);
        let aux_assignment1 = Arc::clone(&aux_assignment);
        let aux_assignment2 = Arc::clone(&aux_assignment);
        let aux_assignment3 = Arc::clone(&aux_assignment);
        let aux_assignment4 = Arc::clone(&aux_assignment);
        let alpha_g1 = zkey.alpha_g1;
        let beta_g1 = zkey.beta_g1;
        let beta_g2 = zkey.beta_g2;
        let delta_g2 = zkey.delta_g2.into_group();

        let r_g1 = engine.spawn_cpu(move || {
            let compute_a =
                tracing::debug_span!("compute A in create proof with assignment").entered();
            // Compute A
            let r_g1 = T::scalar_mul_public_point(&delta_g1, r);
            let r_g1 = Self::calculate_coeff(
                party_id,
                r_g1,
                &a_query.a_query,
                alpha_g1,
                &input_assignment1[1..],
                &aux_assignment1,
            );
            compute_a.exit();
            r_g1
        });

        let s_g1 = engine.spawn_cpu(move || {
            let compute_b =
                tracing::debug_span!("compute B/G1 in create proof with assignment").entered();
            // Compute B in G1
            // In original implementation this is skipped if r==0, however r is shared in our case
            let s_g1 = T::scalar_mul_public_point(&delta_g1, s);
            let s_g1 = Self::calculate_coeff(
                party_id,
                s_g1,
                &b_g1_query.b_g1_query,
                beta_g1,
                &input_assignment2[1..],
                &aux_assignment2,
            );
            compute_b.exit();
            s_g1
        });

        let s_g2 = engine.spawn_cpu(move || {
            let compute_b =
                tracing::debug_span!("compute B/G2 in create proof with assignment").entered();
            // Compute B in G2
            let s_g2 = T::scalar_mul_public_point(&delta_g2, s);
            let s_g2 = Self::calculate_coeff(
                party_id,
                s_g2,
                &b_g2_query.b_g2_query,
                beta_g2,
                &input_assignment3[1..],
                &aux_assignment3,
            );
            compute_b.exit();
            s_g2
        });

        let l_acc = engine.spawn_cpu(move || {
            let msm_l_query = tracing::debug_span!("msm l_query").entered();
            let result = T::msm_public_points(&l_query.l_query, &aux_assignment4);
            msm_l_query.exit();
            result
        });

        let h_acc = engine.spawn_cpu(move || {
            let msm_h_query = tracing::debug_span!("msm h_query").entered();
            //perform the msm for h
            let result = P::G1::msm_unchecked(&h_query.h_query, &h);
            msm_h_query.exit();
            result
        });

        let mut state0 = state.fork(1)?;
        let r_s_delta_g1 = engine.spawn_net(move |net| {
            let rs_span = tracing::debug_span!("r*s with networking").entered();
            let rs = T::mul(r, s, net, &mut state0)?;
            let r_s_delta_g1 = T::scalar_mul_public_point(&delta_g1, rs);
            rs_span.exit();
            eyre::Ok(r_s_delta_g1)
        });

        let g_a = r_g1.join();
        let g1_b = s_g1.join();

        let network_round = tracing::debug_span!("network round after calc coeff").entered();
        let mut state0 = state.fork(0)?;
        let mut state1 = state.fork(1)?;
        let (g_a_opened, r_g1_b) = engine.join_net(
            |net| T::open_point(&g_a, net, &mut state0),
            |net| T::scalar_mul(&g1_b, r, net, &mut state1),
        );
        let g_a_opened = g_a_opened?;
        let r_g1_b = r_g1_b?;
        network_round.exit();

        let last_round = tracing::debug_span!("finish - open two points and some adds").entered();
        let s_g_a = T::scalar_mul_public_point(&g_a_opened, s);

        let mut g_c = s_g_a;
        T::add_assign_points(&mut g_c, &r_g1_b);
        let r_s_delta_g1 = r_s_delta_g1.join()?;
        T::sub_assign_points(&mut g_c, &r_s_delta_g1);
        let l_aux_acc = l_acc.join();
        T::add_assign_points(&mut g_c, &l_aux_acc);

        let h_acc = h_acc.join();
        let g_c = T::add_points_half_share(g_c, &h_acc);
        let g2_b = s_g2.join();

        let mut state0 = state.fork(0)?;
        let mut state1 = state.fork(0)?;
        let (g_c_opened, g2_b_opened) = engine.join_net(
            |net| T::open_half_point(g_c, net, &mut state0),
            |net| T::open_point(&g2_b, net, &mut state1),
        );
        let g_c_opened = g_c_opened?;
        let g2_b_opened = g2_b_opened?;

        last_round.exit();

        Ok(Groth16Proof {
            pi_a: g_a_opened.into_affine(),
            pi_b: g2_b_opened.into_affine(),
            pi_c: g_c_opened.into_affine(),
            protocol: "groth16".to_owned(),
            curve: P::get_circom_name(),
        })
    }
}

impl<P: Pairing> Rep3CoGroth16<P>
where
    P: CircomArkworksPairingBridge,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    /// Create a [`Groth16Proof`].
    pub fn prove<N: Network + 'static>(
        engine: &MpcEngine<N>,
        zkey: Arc<ZKey<P>>,
        witness: Rep3SharedWitness<P::ScalarField>,
    ) -> Result<Groth16Proof<P>> {
        let mut state = engine.install_net(|net| Rep3State::new(net))?;
        // execute prover in MPC
        Self::prove_inner(engine, &mut state, zkey, witness)
    }
}

impl<P: Pairing> ShamirCoGroth16<P>
where
    P: CircomArkworksPairingBridge,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    /// Create a [`Groth16Proof`].
    pub fn prove<N: Network + 'static>(
        engine: &MpcEngine<N>,
        num_parties: usize,
        threshold: usize,
        zkey: Arc<ZKey<P>>,
        witness: ShamirSharedWitness<P::ScalarField>,
    ) -> eyre::Result<Groth16Proof<P>> {
        // we need 2 + 1 number of corr rand pairs. We need the values r/s (1 pair) and 2 muls (2
        // pairs)
        let num_pairs = 3;
        let preprocessing = engine
            .install_net(|net| ShamirPreprocessing::new(num_parties, threshold, num_pairs, net))?;
        let mut protocol = ShamirProtocol::from(preprocessing);
        // the protocol1 is only used for scalar_mul and a field_mul which need 1 pair each (ergo 2
        // pairs)
        // execute prover in MPC
        Self::prove_inner(engine, &mut protocol, zkey, witness)
    }
}

impl<P: Pairing> Groth16<P>
where
    P: CircomArkworksPairingBridge,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    /// *Locally* create a `Groth16` proof. This is just the [`CoGroth16`] prover
    /// initialized with the [`PlainGroth16Driver`].
    ///
    /// DOES NOT PERFORM ANY MPC. For a plain prover checkout the [Groth16 implementation of arkworks](https://docs.rs/ark-groth16/latest/ark_groth16/).
    pub fn plain_prove<N: Network + 'static>(
        engine: &MpcEngine<N>,
        zkey: Arc<ZKey<P>>,
        private_witness: SharedWitness<P::ScalarField, P::ScalarField>,
    ) -> Result<Groth16Proof<P>> {
        Self::prove_inner(engine, &mut (), zkey, private_witness)
    }
}
