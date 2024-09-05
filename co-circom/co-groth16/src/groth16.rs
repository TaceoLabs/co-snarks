//! A Groth16 proof protocol that uses a collaborative MPC protocol to generate the proof.
use ark_ec::pairing::Pairing;
use ark_ec::scalar_mul::variable_base::VariableBaseMSM;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{FftField, PrimeField};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::{ConstraintMatrices, SynthesisError};
use circom_types::groth16::{Groth16Proof, ZKey};
use circom_types::traits::{CircomArkworksPairingBridge, CircomArkworksPrimeFieldBridge};
use co_circom_snarks::SharedWitness;
use eyre::Result;
use itertools::izip;
use mpc_core::protocols::rep3::network::{Rep3MpcNet, Rep3Network};
use mpc_net::config::NetworkConfig;
use num_traits::identities::One;
use num_traits::ToPrimitive;
use std::marker::PhantomData;

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
    phantom_data: PhantomData<P>,
}

impl<P: Pairing + CircomArkworksPairingBridge, T: CircomGroth16Prover<P>> CoGroth16<P, T>
where
    P::BaseField: CircomArkworksPrimeFieldBridge,
    P::ScalarField: CircomArkworksPrimeFieldBridge,
{
    /// Creates a new [CoGroth16] protocol with a given MPC driver.
    pub fn new(driver: T) -> Self {
        Self {
            driver,
            phantom_data: PhantomData,
        }
    }

    /// Execute the Groth16 prover using the internal MPC driver.
    /// This version takes the Circom-generated constraint matrices as input and does not re-calculate them.
    pub fn prove(
        &mut self,
        zkey: &ZKey<P>,
        private_witness: SharedWitness<P::ScalarField, T::ArithmeticShare>,
    ) -> Result<Groth16Proof<P>> {
        let matrices = &zkey.matrices;
        let num_inputs = matrices.num_instance_variables;
        let num_constraints = matrices.num_constraints;
        let public_inputs = &private_witness.public_inputs;
        let private_witness = &private_witness.witness;
        tracing::debug!("calling witness map from matrices...");
        let h = self.witness_map_from_matrices(
            zkey.pow,
            matrices,
            num_constraints,
            num_inputs,
            public_inputs,
            private_witness,
        )?;
        tracing::debug!("done!");
        tracing::debug!("getting r and s...");
        let r = self.driver.rand();
        let s = self.driver.rand();
        tracing::debug!("done!");
        tracing::debug!("calling create_proof_with_assignment...");
        self.create_proof_with_assignment(zkey, r, s, &h, &public_inputs[1..], private_witness)
    }

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

        let domain_size = domain.size();
        let mut a = vec![T::ArithmeticShare::default(); domain_size];
        let mut b = vec![T::ArithmeticShare::default(); domain_size];
        tracing::debug!("evaluating constraints..");
        for (a, b, at_i, bt_i) in izip!(&mut a, &mut b, &matrices.a, &matrices.b) {
            *a = self
                .driver
                .evaluate_constraint(at_i, public_inputs, private_witness);
            *b = self
                .driver
                .evaluate_constraint(bt_i, public_inputs, private_witness);
        }
        tracing::debug!("done!");
        let promoted_public = self.driver.promote_to_trivial_shares(public_inputs);
        a[num_constraints..].clone_from_slice(&promoted_public[..num_inputs]);
        //TODO MT ME
        let mut c = futures::executor::block_on(self.driver.mul_vec(&a, &b))?;
        self.driver.ifft_in_place(&mut a, &domain);
        self.driver.ifft_in_place(&mut b, &domain);
        self.driver.distribute_powers_and_mul_by_const(
            &mut a,
            root_of_unity,
            P::ScalarField::one(),
        );
        self.driver.distribute_powers_and_mul_by_const(
            &mut b,
            root_of_unity,
            P::ScalarField::one(),
        );
        self.driver.fft_in_place(&mut a, &domain);
        self.driver.fft_in_place(&mut b, &domain);
        //this can be in-place so that we do not have to allocate memory
        let mut ab = futures::executor::block_on(self.driver.mul_vec(&a, &b))?;
        std::mem::drop(a);
        std::mem::drop(b);

        self.driver.ifft_in_place(&mut c, &domain);
        self.driver.distribute_powers_and_mul_by_const(
            &mut c,
            root_of_unity,
            P::ScalarField::one(),
        );
        self.driver.fft_in_place(&mut c, &domain);
        self.driver.sub_assign_vec(&mut ab, &c);
        Ok(ab)
    }

    fn calculate_coeff<C: CurveGroup>(
        &mut self,
        initial: T::PointShare<C>,
        query: &[C::Affine],
        vk_param: C::Affine,
        input_assignment: &[C::ScalarField],
        aux_assignment: &[T::ArithmeticShare],
    ) -> T::PointShare<C> {
        tracing::debug!("calculate coeffs..");
        let pub_len = input_assignment.len();
        let pub_acc = C::msm_unchecked(&query[1..=pub_len], input_assignment);
        let priv_acc = self
            .driver
            .msm_public_points(&query[1 + pub_len..], aux_assignment);

        let mut res = initial;
        self.driver
            .add_assign_points_public_affine(&mut res, &query[0]);
        self.driver
            .add_assign_points_public_affine(&mut res, &vk_param);
        self.driver.add_assign_points_public(&mut res, &pub_acc);
        self.driver.add_assign_points(&mut res, &priv_acc);

        tracing::debug!("done..");
        res
    }

    fn create_proof_with_assignment(
        &mut self,
        zkey: &ZKey<P>,
        r: T::ArithmeticShare,
        s: T::ArithmeticShare,
        h: &[T::ArithmeticShare],
        input_assignment: &[P::ScalarField],
        aux_assignment: &[T::ArithmeticShare],
    ) -> Result<Groth16Proof<P>> {
        tracing::debug!("create proof with assignment...");
        //let c_acc_time = start_timer!(|| "Compute C");
        let h_acc = self.driver.msm_public_points(&zkey.h_query, h);

        // Compute C
        let l_aux_acc = self.driver.msm_public_points(&zkey.l_query, aux_assignment);

        let delta_g1 = zkey.delta_g1.into_group();
        let rs = futures::executor::block_on(self.driver.mul(&r, &s))?;
        let r_s_delta_g1 = self.driver.scalar_mul_public_point(&delta_g1, &rs);

        //end_timer!(c_acc_time);

        // Compute A
        // let a_acc_time = start_timer!(|| "Compute A");
        let r_g1 = self.driver.scalar_mul_public_point(&delta_g1, &r);

        let g_a = self.calculate_coeff(
            r_g1,
            &zkey.a_query,
            zkey.vk.alpha_g1,
            input_assignment,
            aux_assignment,
        );

        // Open here since g_a is part of proof
        let g_a_opened = futures::executor::block_on(self.driver.open_point(&g_a))?;
        let s_g_a = self.driver.scalar_mul_public_point(&g_a_opened, &s);
        // end_timer!(a_acc_time);

        // Compute B in G1
        // In original implementation this is skipped if r==0, however r is shared in our case
        //  let b_g1_acc_time = start_timer!(|| "Compute B in G1");
        let s_g1 = self.driver.scalar_mul_public_point(&delta_g1, &s);
        let g1_b = self.calculate_coeff(
            s_g1,
            &zkey.b_g1_query,
            zkey.beta_g1,
            input_assignment,
            aux_assignment,
        );
        let r_g1_b = futures::executor::block_on(self.driver.scalar_mul(&g1_b, &r))?;
        //  end_timer!(b_g1_acc_time);

        // Compute B in G2
        let delta_g2 = zkey.vk.delta_g2.into_group();
        //  let b_g2_acc_time = start_timer!(|| "Compute B in G2");
        let s_g2 = self.driver.scalar_mul_public_point(&delta_g2, &s);
        let g2_b = self.calculate_coeff::<P::G2>(
            s_g2,
            &zkey.b_g2_query,
            zkey.vk.beta_g2,
            input_assignment,
            aux_assignment,
        );
        // end_timer!(b_g2_acc_time);

        //  let c_time = start_timer!(|| "Finish C");
        let mut g_c = s_g_a;
        self.driver.add_assign_points(&mut g_c, &r_g1_b);
        self.driver.sub_assign_points(&mut g_c, &r_s_delta_g1);
        self.driver.add_assign_points(&mut g_c, &l_aux_acc);
        self.driver.add_assign_points(&mut g_c, &h_acc);
        //  end_timer!(c_time);

        tracing::debug!("almost done...");
        let (g_c_opened, g2_b_opened) = self.driver.open_two_points(g_c, g2_b)?;

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
        let mpc_net = Rep3MpcNet::new(config)?;
        let driver = Rep3Groth16Driver::new(mpc_net)?;
        Ok(CoGroth16::new(driver))
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
            phantom_data: PhantomData,
        };
        prover.prove(zkey, private_witness)
    }
}
