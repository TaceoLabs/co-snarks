//! A Groth16 proof protocol that uses a collaborative MPC protocol to generate the proof.
use ark_ec::pairing::Pairing;
use ark_ec::scalar_mul::variable_base::VariableBaseMSM;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{FftField, PrimeField};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::{ConstraintMatrices, Matrix, SynthesisError};
use circom_types::groth16::{Groth16Proof, ZKey};
use circom_types::traits::{CircomArkworksPairingBridge, CircomArkworksPrimeFieldBridge};
use co_circom_snarks::SharedWitness;
use eyre::Result;
use itertools::izip;
use mpc_core::protocols::rep3::network::{IoContext, Rep3MpcNet, Rep3Network};
use mpc_net::config::NetworkConfig;
use num_traits::identities::One;
use num_traits::ToPrimitive;
use std::io;
use std::marker::PhantomData;
use std::sync::Arc;
use tokio::runtime::{self, Runtime};
use tokio::sync::oneshot;
use tracing::instrument;

use crate::mpc::plain::PlainGroth16Driver;
use crate::mpc::rep3::Rep3Groth16Driver;
use crate::mpc::CircomGroth16Prover;

/// The plain [`Groth16`] type.
///
/// This type is actually the [`CoGroth16`] type initialized with
/// the [`PlainDriver`], a single party (you) MPC protocol (i.e., your everyday Groth16).
/// You can use this instance to create a proof, but we recommend against it for a real use-case.
/// Have a look at the [Groth16 implementation of arkworks](https://docs.rs/ark-groth16/latest/ark_groth16/)
/// for a plain Groth16 prover.
///
/// More interesting is the [`Groth16::verify`] method. You can verify any circom Groth16 proof, be it
/// from snarkjs or one created by this project. Under the hood we use the arkwork Groth16 project for verifying.
pub type Groth16<P> = CoGroth16<P, PlainGroth16Driver>;

/// A type alias for a [CoGroth16] protocol using replicated secret sharing.
pub type Rep3CoGroth16<P, N> = CoGroth16<P, Rep3Groth16Driver<N>>;

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
    pub(crate) driver: T,
    pub(crate) runtime: Runtime,
    phantom_data: PhantomData<P>,
}

impl<P: Pairing + CircomArkworksPairingBridge, T: CircomGroth16Prover<P>> CoGroth16<P, T>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    /// Creates a new [CoGroth16] protocol with a given MPC driver.
    pub fn new(driver: T, runtime: Runtime) -> Self {
        Self {
            driver,
            runtime,
            phantom_data: PhantomData,
        }
    }

    /// Execute the Groth16 prover using the internal MPC driver.
    /// This version takes the Circom-generated constraint matrices as input and does not re-calculate them.
    #[instrument(level = "debug", name = "Groth16 - Proof", skip_all)]
    pub fn prove(
        &mut self,
        zkey: &ZKey<P>,
        private_witness: SharedWitness<P::ScalarField, T::ArithmeticShare>,
    ) -> Result<Groth16Proof<P>> {
        let matrices = &zkey.matrices;
        let num_inputs = matrices.num_instance_variables;
        let num_constraints = matrices.num_constraints;
        let public_inputs = &private_witness.public_inputs;
        let private_witness = private_witness.witness;
        // TODO: actually we do not like that we have to block here
        // can we somehow manage that this doesn't have to use the network?
        let mut forked_driver = self.runtime.block_on(self.driver.fork())?;
        let h = self.witness_map_from_matrices(
            zkey.pow,
            matrices,
            num_constraints,
            num_inputs,
            public_inputs,
            &private_witness,
        )?;
        tracing::debug!("getting r and s...");
        //TODO: this is bad - we need something else
        let r = self.runtime.block_on(self.driver.rand())?;
        let s = self.runtime.block_on(self.driver.rand())?;
        tracing::debug!("done!");
        self.create_proof_with_assignment(
            &mut forked_driver,
            zkey,
            r,
            s,
            h,
            &public_inputs[1..],
            private_witness,
        )
    }

    fn evaluate_constraint(
        party_id: T::PartyID,
        domain_size: usize,
        matrix: &Matrix<P::ScalarField>,
        public_inputs: &[P::ScalarField],
        private_witness: &[T::ArithmeticShare],
    ) -> Vec<T::ArithmeticShare> {
        let mut result = vec![T::ArithmeticShare::default(); domain_size];
        for (res, x) in izip!(&mut result, matrix) {
            *res = T::evaluate_constraint(party_id, x, public_inputs, private_witness);
        }
        result
    }

    #[instrument(level = "debug", name = "witness map from matrices", skip_all)]
    fn witness_map_from_matrices(
        &mut self,
        power: usize,
        matrices: &ConstraintMatrices<P::ScalarField>,
        num_constraints: usize,
        num_inputs: usize,
        public_inputs: &[P::ScalarField],
        private_witness: &[T::ArithmeticShare],
    ) -> Result<Vec<T::ArithmeticShare>> {
        let mut domain =
            GeneralEvaluationDomain::<P::ScalarField>::new(num_constraints + num_inputs)
                .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let root_of_unity = root_of_unity_for_groth16(power, &mut domain);
        let domain = Arc::new(domain);
        let domain_size = domain.size();
        let party_id = self.driver.get_party_id();
        let eval_constraint_span = tracing::debug_span!("evaluate constraints").entered();
        let (a, b) = rayon::join(
            || {
                let mut result = Self::evaluate_constraint(
                    party_id,
                    domain_size,
                    &matrices.a,
                    public_inputs,
                    private_witness,
                );
                let promoted_public = T::promote_to_trivial_shares(party_id, public_inputs);
                result[num_constraints..num_constraints + num_inputs]
                    .clone_from_slice(&promoted_public[..num_inputs]);
                result
            },
            || {
                let result = Self::evaluate_constraint(
                    party_id,
                    domain_size,
                    &matrices.b,
                    public_inputs,
                    private_witness,
                );
                result
            },
        );

        eval_constraint_span.exit();

        let (a_tx, a_rx) = oneshot::channel();
        let (b_tx, b_rx) = oneshot::channel();
        let a_domain = Arc::clone(&domain);
        let b_domain = Arc::clone(&domain);
        let mut a_result = a.clone();
        let mut b_result = b.clone();
        rayon::spawn(move || {
            T::ifft_in_place(&mut a_result, a_domain.as_ref());
            T::distribute_powers_and_mul_by_const(
                &mut a_result,
                root_of_unity,
                P::ScalarField::one(),
            );
            T::fft_in_place(&mut a_result, a_domain.as_ref());
            a_tx.send(a_result).expect("channel not droped");
        });

        rayon::spawn(move || {
            T::ifft_in_place(&mut b_result, b_domain.as_ref());
            T::distribute_powers_and_mul_by_const(
                &mut b_result,
                root_of_unity,
                P::ScalarField::one(),
            );
            T::fft_in_place(&mut b_result, b_domain.as_ref());
            b_tx.send(b_result).expect("channel not droped");
        });

        let mut ab = self.runtime.block_on(self.driver.mul_vec(&a, &b))?;
        let mul_vec_span = tracing::debug_span!("groth16 - mul vec in dist pows").entered();
        let ifft_span = tracing::debug_span!("ifft in dist pows").entered();
        T::ifft_in_place(&mut ab, domain.as_ref());
        ifft_span.exit();
        let dist_pows_span = tracing::debug_span!("dist pows").entered();
        T::distribute_powers_and_mul_by_const(&mut ab, root_of_unity, P::ScalarField::one());
        dist_pows_span.exit();
        let fft_span = tracing::debug_span!("fft in dist pows").entered();
        T::fft_in_place(&mut ab, domain.as_ref());
        fft_span.exit();
        let c_dist_pow = ab;
        mul_vec_span.exit();

        tracing::error!("DONE MUL VEC SCOPE");
        let a = a_rx.blocking_recv()?;
        let b = b_rx.blocking_recv()?;

        let mul_vec_span = tracing::debug_span!("compute ab").entered();
        //TODO we can merge the mul and sub commands but it most likely is not that
        //much of a difference
        let mut ab = self.runtime.block_on(self.driver.mul_vec(&a, &b))?;
        T::sub_assign_vec(&mut ab, &c_dist_pow);
        mul_vec_span.exit();
        Ok(a)
    }

    fn calculate_coeff_g1(
        id: T::PartyID,
        initial: T::PointShareG1,
        query: &[P::G1Affine],
        vk_param: P::G1Affine,
        input_assignment: &[P::ScalarField],
        aux_assignment: &[T::ArithmeticShare],
    ) -> T::PointShareG1 {
        let pub_len = input_assignment.len();

        let mut pub_acc = None;
        let mut priv_acc = None;
        rayon::scope(|s| {
            s.spawn(|_| {
                pub_acc = Some(P::G1::msm_unchecked(&query[1..=pub_len], input_assignment))
            });
            s.spawn(|_| {
                priv_acc = Some(T::msm_public_points_g1(
                    &query[1 + pub_len..],
                    aux_assignment,
                ))
            });
        });
        // must be terminated after rayon scope
        let pub_acc = pub_acc.unwrap();
        let priv_acc = priv_acc.unwrap();

        let mut res = initial;
        T::add_assign_points_public_g1(id, &mut res, &query[0].into_group());
        T::add_assign_points_public_g1(id, &mut res, &vk_param.into_group());
        T::add_assign_points_public_g1(id, &mut res, &pub_acc);
        T::add_assign_points_g1(&mut res, &priv_acc);
        res
    }

    fn calculate_coeff_g2(
        id: T::PartyID,
        initial: T::PointShareG2,
        query: &[P::G2Affine],
        vk_param: P::G2Affine,
        input_assignment: &[P::ScalarField],
        aux_assignment: &[T::ArithmeticShare],
    ) -> T::PointShareG2 {
        let pub_len = input_assignment.len();

        let mut pub_acc = None;
        let mut priv_acc = None;
        rayon::scope(|s| {
            s.spawn(|_| {
                pub_acc = Some(P::G2::msm_unchecked(&query[1..=pub_len], input_assignment))
            });
            s.spawn(|_| {
                priv_acc = Some(T::msm_public_points_g2(
                    &query[1 + pub_len..],
                    aux_assignment,
                ))
            });
        });
        // must be terminated after rayon scope
        let pub_acc = pub_acc.unwrap();
        let priv_acc = priv_acc.unwrap();

        let mut res = initial;
        T::add_assign_points_public_g2(id, &mut res, &query[0].into_group());
        T::add_assign_points_public_g2(id, &mut res, &vk_param.into_group());
        T::add_assign_points_public_g2(id, &mut res, &pub_acc);
        T::add_assign_points_g2(&mut res, &priv_acc);
        res
    }

    #[instrument(level = "debug", name = "create proof with assignment", skip_all)]
    fn create_proof_with_assignment(
        &mut self,
        forked_driver: &mut T,
        zkey: &ZKey<P>,
        r: T::ArithmeticShare,
        s: T::ArithmeticShare,
        h: Vec<T::ArithmeticShare>,
        input_assignment: &[P::ScalarField],
        aux_assignment: Vec<T::ArithmeticShare>,
    ) -> Result<Groth16Proof<P>> {
        let delta_g1 = zkey.delta_g1.into_group();
        let msm_create_proof = tracing::debug_span!("first MSMs").entered();

        let (h_acc_tx, h_acc_rx) = oneshot::channel();
        let (l_acc_tx, l_acc_rx) = oneshot::channel();
        let h_query = Arc::clone(&zkey.h_query);
        let l_query = Arc::clone(&zkey.l_query);
        rayon::spawn(move || {
            let result = T::msm_public_points_g1(h_query.as_ref(), &h);
            h_acc_tx.send(result).expect("channel not dropped");
        });

        rayon::spawn(move || {
            let result = T::msm_public_points_g1(l_query.as_ref(), &aux_assignment);
            l_acc_tx
                .send((result, aux_assignment))
                .expect("channel not dropped");
        });
        let rs = self.runtime.block_on(self.driver.mul(r, s))?;
        let r_s_delta_g1 = T::scalar_mul_public_point_g1(&delta_g1, rs);
        msm_create_proof.exit();

        let h_acc = h_acc_rx.blocking_recv().unwrap();
        let (l_aux_acc, aux_assignment) = l_acc_rx.blocking_recv().unwrap();

        let mut g_a = None;
        let mut g1_b = None;
        let mut g2_b = None;
        let party_id = self.driver.get_party_id();
        let calculate_coeff_span = tracing::debug_span!("calculate coeff").entered();
        rayon::scope(|scope| {
            scope.spawn(|_| {
                // Compute A
                let r_g1 = T::scalar_mul_public_point_g1(&delta_g1, r);
                g_a = Some(Self::calculate_coeff_g1(
                    party_id,
                    r_g1,
                    &zkey.a_query,
                    zkey.vk.alpha_g1,
                    input_assignment,
                    &aux_assignment,
                ));
            });
            scope.spawn(|_| {
                // Compute B in G1
                // In original implementation this is skipped if r==0, however r is shared in our case
                let s_g1 = T::scalar_mul_public_point_g1(&delta_g1, s);
                g1_b = Some(Self::calculate_coeff_g1(
                    party_id,
                    s_g1,
                    &zkey.b_g1_query,
                    zkey.beta_g1,
                    input_assignment,
                    &aux_assignment,
                ));
            });
            scope.spawn(|_| {
                // Compute B in G2
                let s_g2 = T::scalar_mul_public_point_g2(&zkey.vk.delta_g2.into_group(), s);
                g2_b = Some(Self::calculate_coeff_g2(
                    party_id,
                    s_g2,
                    &zkey.b_g2_query,
                    zkey.vk.beta_g2,
                    input_assignment,
                    &aux_assignment,
                ));
            });
        });
        // must be there after rayon scope
        let g_a = g_a.unwrap();
        let g1_b = g1_b.unwrap();
        let g2_b = g2_b.unwrap();
        calculate_coeff_span.exit();

        let network_round = tracing::debug_span!("network round after calc coeff").entered();
        let mut g_a_opened = None;
        let mut r_g1_b = None;
        self.runtime.block_on(async {
            let (opened, mul_result) = tokio::join!(
                forked_driver.open_point_g1(&g_a),
                self.driver.scalar_mul_g1(&g1_b, r)
            );
            g_a_opened = Some(opened);
            r_g1_b = Some(mul_result);
        });

        let g_a_opened = g_a_opened.unwrap()?;
        let r_g1_b = r_g1_b.unwrap()?;
        network_round.exit();

        let last_round = tracing::debug_span!("finish open two points and some adds").entered();
        let s_g_a = T::scalar_mul_public_point_g1(&g_a_opened, s);

        let mut g_c = s_g_a;
        T::add_assign_points_g1(&mut g_c, &r_g1_b);
        T::sub_assign_points_g1(&mut g_c, &r_s_delta_g1);
        T::add_assign_points_g1(&mut g_c, &l_aux_acc);
        T::add_assign_points_g1(&mut g_c, &h_acc);

        let (g_c_opened, g2_b_opened) = self
            .runtime
            .block_on(self.driver.open_two_points(g_c, g2_b))?;
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

impl<P: Pairing> Rep3CoGroth16<P, Rep3MpcNet>
where
    P: CircomArkworksPairingBridge,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    /// Create a new [Rep3CoGroth16] protocol with a given network configuration.
    pub fn with_network_config(config: NetworkConfig) -> Result<Self> {
        let runtime = runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let mpc_net = runtime.block_on(Rep3MpcNet::new(config))?;
        let io_context = runtime.block_on(IoContext::init(mpc_net))?;
        let driver = Rep3Groth16Driver::new(io_context);
        Ok(CoGroth16 {
            driver,
            runtime,
            phantom_data: PhantomData,
        })
    }
}

impl<P: Pairing, N: Rep3Network> Rep3CoGroth16<P, N> {
    pub fn close_network(self) -> io::Result<()> {
        self.runtime
            .block_on(self.driver.into_network().shutdown())?;
        Ok(())
    }
}

impl<P: Pairing> Groth16<P>
where
    P: CircomArkworksPairingBridge,
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    /// *Locally* create a `Groth16` proof. This is just the [`CoGroth16`] prover
    /// initialized with the [`PlainDriver`].
    ///
    /// DOES NOT PERFORM ANY MPC. For a plain prover checkout the [Groth16 implementation of arkworks](https://docs.rs/ark-groth16/latest/ark_groth16/).
    pub fn plain_prove(
        zkey: &ZKey<P>,
        private_witness: SharedWitness<P::ScalarField, P::ScalarField>,
    ) -> Result<Groth16Proof<P>> {
        let mut prover = Self {
            driver: PlainGroth16Driver,
            runtime: runtime::Builder::new_current_thread().build()?,
            phantom_data: PhantomData,
        };
        prover.prove(zkey, private_witness)
    }
}
