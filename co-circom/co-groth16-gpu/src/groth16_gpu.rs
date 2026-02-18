//! A Groth16 proof protocol that uses a collaborative MPC protocol to generate the proof.
use crate::gpu_utils::{
    from_host_slice, get_first_affine, get_first_projective, initialize_domain, msm_async,
};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::ConstraintMatrices;
use co_circom_types::SharedWitness;
use eyre::Result;
use icicle_core::curve::{Affine, Curve};
use icicle_runtime::memory::{DeviceVec, HostOrDeviceSlice};
use icicle_runtime::runtime;
use icicle_runtime::stream::IcicleStream;
use mpc_core::MpcState;
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_core::protocols::rep3::{Rep3PrimeFieldShare, Rep3State};
use mpc_net::Network;
use std::marker::PhantomData;
use std::mem::transmute;
use std::ops::{Index, IndexMut};

use icicle_core::msm::MSM;

use crate::bridges::{ArkIcicleBridge, Bn254Bridge, ark_to_icicle_scalars};
use crate::gpu_utils::{Proof, ProvingKey, VerifyingKey};
use crate::mpc::CircomGroth16Prover;
use crate::mpc::plain::PlainGroth16Driver;
use crate::mpc::rep3::Rep3Groth16Driver;
// use crate::mpc::shamir::ShamirGroth16Driver;

pub use reduction::{CircomReduction, R1CSToQAP};
mod reduction;

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
pub struct Groth16<P> {
    phantom_data: PhantomData<P>,
}

/// A type alias for a [CoGroth16] protocol using replicated secret sharing, using the Circom R1CSToQAPReduction by default.
pub struct Rep3CoGroth16<P> {
    phantom_data: PhantomData<P>,
}

/// A type alias for a [CoGroth16] protocol using replicated secret sharing, using the Circom R1CSToQAPReduction by default.
// TODO CESAR
// pub type Rep3CoGroth16<P> = CoGroth16<P, Rep3Groth16Driver>;
/// A type alias for a [CoGroth16] protocol using shamir secret sharing, using the Circom R1CSToQAPReduction by default.
// TODO CESAR
// pub type ShamirCoGroth16<P> = CoGroth16<P, ShamirGroth16Driver>;

/// A Groth16 proof protocol that uses a collaborative MPC protocol to generate the proof.
pub struct CoGroth16Icicle<B: ArkIcicleBridge, T: CircomGroth16Prover<B::IcicleScalarField>> {
    phantom_data: PhantomData<(B, T)>,
}

impl<B: ArkIcicleBridge, T: CircomGroth16Prover<B::IcicleScalarField>> CoGroth16Icicle<B, T> {
    fn setup<U: co_groth16::CircomGroth16Prover<B::ArkPairing> + 'static>(
        id: <T::State as MpcState>::PartyID,
        pkey: &co_groth16::ProvingKey<B::ArkPairing>,
        matrices: &ConstraintMatrices<B::ArkScalarField>,
        private_witness: &Vec<U::ArithmeticShare>,
        public_inputs: &Vec<B::ArkScalarField>,
        domain_size: usize,
    ) -> eyre::Result<(
        ProvingKey<B::IcicleScalarField, B::IcicleG1, B::IcicleG2>,
        T::DeviceShares,
        T::DeviceShares,
        DeviceVec<B::IcicleScalarField>,
        T::DeviceShares,
    )> {
        // TODO CESAR: Handle properly
        runtime::load_backend_from_env_or_default().unwrap();

        // Select CUDA device
        let device = icicle_runtime::Device::new("CUDA", 0);
        icicle_runtime::set_device(&device).unwrap();

        initialize_domain::<B::IcicleScalarField>(domain_size);

        let (eval_a, eval_b) = T::evaluate_constraints::<B, U>(
            id,
            matrices,
            public_inputs,
            private_witness,
            domain_size,
        );

        let private_witness = T::shares_to_device::<B, U>(private_witness);

        let key = ProvingKey::from_ark(
            pkey,
            matrices.num_constraints,
            matrices.num_instance_variables,
        );

        let public_inputs = ark_to_icicle_scalars(from_host_slice(public_inputs)).unwrap();
        Ok((key, eval_a, eval_b, public_inputs, private_witness))
    }

    /// Execute the Groth16 prover using the internal MPC driver.
    /// This version takes the Circom-generated constraint matrices as input and does not re-calculate them.
    fn prove_inner<N: Network, R: R1CSToQAP>(
        net0: &N,
        net1: &N,
        state0: &mut T::State,
        state1: &mut T::State,
        eval_a: &mut T::DeviceShares,
        eval_b: &mut T::DeviceShares,
        pkey: &ProvingKey<B::IcicleScalarField, B::IcicleG1, B::IcicleG2>,
        private_witness: T::DeviceShares,
        public_inputs: &DeviceVec<B::IcicleScalarField>,
    ) -> eyre::Result<Proof<B::IcicleScalarField, B::IcicleG1, B::IcicleG2>> {
        let timer_start = std::time::Instant::now();
        let h = R::witness_map_from_r1cs_eval::<B, T>(
            state0,
            eval_a,
            eval_b,
            public_inputs,
            &pkey.precomputed_roots,
            pkey.num_constraints,
            pkey.domain_size,
        )?;
        println!(
            "Witness map computation took {} ms",
            timer_start.elapsed().as_millis()
        );

        let (r, s) = (
            T::rand::<_, B>(net0, state0)?,
            T::rand::<_, B>(net0, state0)?,
        );

        let private_witness_half_shares = T::to_half_share_vec(&private_witness);

        let timer_start = std::time::Instant::now();
        let out = Self::create_proof_with_assignment(
            net0,
            net1,
            state0,
            state1,
            pkey,
            r,
            s,
            h,
            &public_inputs,
            &private_witness_half_shares,
        );
        println!(
            "Proof with assignment took {} ms",
            timer_start.elapsed().as_millis()
        );
        out
    }

    fn calculate_coeff<C>(
        id: <T::State as MpcState>::PartyID,
        initial: Affine<C>,
        first_query: Affine<C>,
        vk_param: Affine<C>,
        priv_pub_acc: Affine<C>,
    ) -> Affine<C>
    where
        C: Curve<ScalarField = B::IcicleScalarField> + MSM<C>,
    {
        let mut res = initial;
        T::add_assign_points_public_hs::<C>(id, &mut res, &first_query);
        T::add_assign_points_public_hs::<C>(id, &mut res, &vk_param);
        T::add_assign_points_public_hs::<C>(id, &mut res, &priv_pub_acc);
        res
    }

    #[expect(clippy::too_many_arguments)]
    fn create_proof_with_assignment<N: Network>(
        net0: &N,
        net1: &N,
        state0: &mut T::State,
        state1: &mut T::State,
        pkey: &ProvingKey<B::IcicleScalarField, B::IcicleG1, B::IcicleG2>,
        r: T::ArithmeticShare,
        s: T::ArithmeticShare,
        h: DeviceVec<B::IcicleScalarField>,
        input_assignment: &DeviceVec<B::IcicleScalarField>,
        aux_assignment: &DeviceVec<B::IcicleScalarField>,
    ) -> eyre::Result<Proof<B::IcicleScalarField, B::IcicleG1, B::IcicleG2>> {
        let ProvingKey {
            vk,
            beta_g1,
            delta_g1,
            a_query,
            b_g1_query,
            b_g2_query,
            l_query,
            h_query,
            ..
        } = pkey;

        let VerifyingKey {
            alpha_g1,
            beta_g2,
            delta_g2,
            ..
        } = vk;

        let delta_g1 = delta_g1.to_projective();
        let delta_g2 = delta_g2.to_projective();

        let id = state0.id();

        let (mut stream_g1, mut stream_g2) = (
            IcicleStream::create().unwrap(),
            IcicleStream::create().unwrap(),
        );

        let mut assignment =
            DeviceVec::device_malloc(input_assignment.len() + aux_assignment.len() - 1)
                .expect("Failed to allocate device vector");
        assignment.copy(input_assignment.index(1..)).unwrap();
        assignment
            .index_mut((input_assignment.len() - 1)..)
            .copy(aux_assignment)
            .unwrap();

        // Compute A
        let timer_start = std::time::Instant::now();
        let priv_pub_acc_r_g1 = msm_async(&a_query[1..], &assignment, &stream_g1);
        println!(
            "Queueing GPU ops for r_g1 took {} ms",
            timer_start.elapsed().as_millis()
        );

        // Compute B in G1
        let timer_start = std::time::Instant::now();
        let priv_pub_acc_s_g1 = msm_async(&b_g1_query[1..], &assignment, &stream_g1);
        println!(
            "Queueing GPU ops for B in G1 took {} ms",
            timer_start.elapsed().as_millis()
        );

        // Compute B in G2
        let timer_start = std::time::Instant::now();
        let priv_pub_acc_s_g2 = msm_async(&b_g2_query[1..], &assignment, &stream_g2);
        println!(
            "Queueing GPU ops for B in G2 took {} ms",
            timer_start.elapsed().as_millis()
        );

        // Compute msm(l_query, aux_assignment)
        let timer_start = std::time::Instant::now();
        let l_acc = msm_async(l_query, aux_assignment, &stream_g1);
        println!(
            "Queueing GPU ops for L took {} ms",
            timer_start.elapsed().as_millis()
        );

        // Compute msm(h_query, h)
        let timer_start = std::time::Instant::now();
        let h_acc = msm_async(h_query, &h, &stream_g1);
        println!(
            "Queueing GPU ops for H took {} ms",
            timer_start.elapsed().as_millis()
        );

        stream_g1.synchronize().unwrap();
        stream_g2.synchronize().unwrap();

        stream_g1.destroy().unwrap();
        stream_g2.destroy().unwrap();

        let r_hs = T::to_half_share(&r);
        let r_g1 = delta_g1 * r_hs;
        let timer_start = std::time::Instant::now();
        let r_g1 = Self::calculate_coeff::<B::IcicleG1>(
            id,
            r_g1.into(),
            get_first_affine(a_query).unwrap(),
            *alpha_g1,
            get_first_projective(&priv_pub_acc_r_g1).unwrap().into(),
        );
        println!(
            "Coefficient calculation for A took {} ms",
            timer_start.elapsed().as_millis()
        );

        // In original implementation this is skipped if r==0, however r is shared in our case
        let s_hs = T::to_half_share(&s);
        let s_g1 = delta_g1 * s_hs;
        let timer_start = std::time::Instant::now();
        let s_g1 = Self::calculate_coeff::<B::IcicleG1>(
            id,
            s_g1.into(),
            get_first_affine(&b_g1_query).unwrap(),
            *beta_g1,
            get_first_projective(&priv_pub_acc_s_g1).unwrap().into(),
        );
        println!(
            "Coefficient calculation for B in G1 took {} ms",
            timer_start.elapsed().as_millis()
        );

        let timer_start = std::time::Instant::now();
        let s_g2 = delta_g2 * s_hs;
        let s_g2 = Self::calculate_coeff::<B::IcicleG2>(
            id,
            s_g2.into(),
            get_first_affine(&b_g2_query).unwrap(),
            *beta_g2,
            get_first_projective(&priv_pub_acc_s_g2).unwrap().into(),
        );
        println!(
            "Coefficient calculation for B in G2 took {} ms",
            timer_start.elapsed().as_millis()
        );

        let timer_start = std::time::Instant::now();
        let l_acc = get_first_projective(&l_acc).unwrap();
        println!(
            "Coefficient calculation for L took {} ms",
            timer_start.elapsed().as_millis()
        );

        let timer_start = std::time::Instant::now();
        let h_acc = get_first_projective(&h_acc).unwrap();
        println!(
            "Coefficient calculation for H took {} ms",
            timer_start.elapsed().as_millis()
        );

        // streams.iter_mut().for_each(|s| s.destroy().unwrap());

        let timer_start = std::time::Instant::now();

        // Compute r * s
        let rs = T::local_mul::<B>(&r, &s, state0);
        let r_s_delta_g1 = delta_g1 * rs;

        let g_a = r_g1;
        let g1_b = s_g1;

        // TODO CESAR: Use threads
        let g_a_opened = T::open_half_point_g1::<_, B>(g_a, net0, state0)?;
        let r_g1_b = T::scalar_mul_g1::<_, B>(&g1_b, r, net1, state1)?;

        let s_g_a = g_a_opened.to_projective() * s_hs;

        let mut g_c = s_g_a;
        g_c = g_c + r_g1_b.to_projective();
        g_c = g_c - r_s_delta_g1;
        g_c = g_c + l_acc;
        g_c = g_c + h_acc;

        // TODO CESAR: Use threads
        let g2_b = s_g2;
        let g_c_opened = T::open_half_point_g1::<_, B>(g_c.into(), net0, state0)?;
        let g2_b_opened = T::open_half_point_g2::<_, B>(g2_b, net1, state1)?;

        println!(
            "Final openings took {} ms",
            timer_start.elapsed().as_millis()
        );

        Ok(Proof {
            a: g_a_opened,
            b: g2_b_opened,
            c: g_c_opened,
        })
    }
}

/// Transmutes Groth16 artifacts from a generic pairing `P` into concrete pairing
///
/// # Safety / Invariant
/// This is only sound if the values you pass in are *actually* built for `$DstPair` / `$DstField`,
/// but are currently being referenced through the generic `P` / `P::ScalarField` types.
/// (I.e. `P == $DstPair` and `P::ScalarField == $DstField` in reality.)
#[macro_export]
macro_rules! transmute_groth16_artifacts {
    (
        src_pairing = $SrcPair:ty,
        dst_pairing = $DstPair:ty,
        dst_field   = $DstField:ty,
        src_arithmetic_share = $SrcArithmeticShare:ty,
        dst_arithmetic_share = $DstArithmeticShare:ty,
        $pkey:expr,
        $matrices:expr,
        $private_witness:expr,
        $public_inputs:expr
    ) => {{
        use core::mem::{size_of, transmute};

        // Optional sanity checks (won't prove correctness, but can catch obvious mismatches)
        debug_assert_eq!(
            size_of::<ark_groth16::ProvingKey<$SrcPair>>(),
            size_of::<ark_groth16::ProvingKey<$DstPair>>(),
        );
        debug_assert_eq!(
            size_of::<Vec<<$SrcPair as ark_ec::pairing::Pairing>::ScalarField>>(),
            size_of::<Vec<$DstField>>(),
        );

        unsafe {
            (
                transmute::<&ark_groth16::ProvingKey<$SrcPair>, &ark_groth16::ProvingKey<$DstPair>>(
                    $pkey,
                ),
                transmute::<&Vec<$SrcArithmeticShare>, &Vec<$DstArithmeticShare>>($private_witness),
                transmute::<
                    &ConstraintMatrices<<$SrcPair as ark_ec::pairing::Pairing>::ScalarField>,
                    &ConstraintMatrices<$DstField>,
                >($matrices),
                transmute::<
                    &Vec<<$SrcPair as ark_ec::pairing::Pairing>::ScalarField>,
                    &Vec<$DstField>,
                >($public_inputs),
            )
        }
    }};
}

impl<P: ark_ec::pairing::Pairing> Groth16<P> {
    /// *Locally* create a `Groth16` proof. This is just the [`CoGroth16`] prover
    /// initialized with the [`PlainGroth16Driver`].
    ///
    /// DOES NOT PERFORM ANY MPC. For a plain prover checkout the [Groth16 implementation of arkworks](https://docs.rs/ark-groth16/latest/ark_groth16/).
    pub fn plain_prove<R: R1CSToQAP>(
        pkey: &ark_groth16::ProvingKey<P>,
        matrices: &ConstraintMatrices<P::ScalarField>,
        private_witness: SharedWitness<P::ScalarField, P::ScalarField>,
    ) -> Result<ark_groth16::Proof<P>> {
        let public_inputs = &private_witness.public_inputs;
        let private_witness = &private_witness.witness;

        // TODO CESAR: Handle properly
        runtime::load_backend_from_env_or_default().unwrap();

        // Select CUDA device
        let device = icicle_runtime::Device::new("CUDA", 0);
        icicle_runtime::set_device(&device).unwrap();

        // TODO CESAR: Duplicate
        let domain = GeneralEvaluationDomain::<P::ScalarField>::new(
            matrices.num_constraints + matrices.num_instance_variables,
        )
        .ok_or(eyre::eyre!("Polynomial Degree too large"))?;
        let domain_size = domain.size();

        let all_timer = std::time::Instant::now();

        if std::any::TypeId::of::<P>() == std::any::TypeId::of::<ark_bn254::Bn254>() {
            let (key, private_witness, matrices, public_inputs) = transmute_groth16_artifacts!(
                src_pairing = P,
                dst_pairing = ark_bn254::Bn254,
                dst_field = ark_bn254::Fr,
                src_arithmetic_share = P::ScalarField,
                dst_arithmetic_share = ark_bn254::Fr,
                pkey,
                matrices,
                private_witness,
                public_inputs
            );

            let (key, mut eval_a, mut eval_b, public_inputs, private_witness) =
                CoGroth16Icicle::<Bn254Bridge, PlainGroth16Driver>::setup::<
                    co_groth16::mpc::PlainGroth16Driver,
                >(
                    0, // id irrelevant in the
                    key,
                    matrices,
                    private_witness,
                    public_inputs,
                    domain_size,
                )?;

            let timer_start = std::time::Instant::now();
            let icicle_proof =
                CoGroth16Icicle::<Bn254Bridge, PlainGroth16Driver>::prove_inner::<_, R>(
                    &(),
                    &(),
                    &mut (),
                    &mut (),
                    &mut eval_a,
                    &mut eval_b,
                    &key,
                    private_witness,
                    &public_inputs,
                )?;
            println!(
                "Proof generation took {} ms",
                timer_start.elapsed().as_millis()
            );

            let proof = icicle_proof.to_ark::<Bn254Bridge>();

            let proof = unsafe {
                transmute::<&ark_groth16::Proof<ark_bn254::Bn254>, &ark_groth16::Proof<P>>(&proof)
            };

            println!("Total time took {} ms", all_timer.elapsed().as_millis());
            return Ok(proof.clone());
        } else {
            panic!("Unsupported pairing")
        };
    }
}

impl<P: ark_ec::pairing::Pairing> Rep3CoGroth16<P> {
    pub fn prove<N: Network, R: R1CSToQAP>(
        net0: &N,
        net1: &N,
        pkey: &ark_groth16::ProvingKey<P>,
        matrices: &ConstraintMatrices<P::ScalarField>,
        private_witness: SharedWitness<P::ScalarField, Rep3PrimeFieldShare<P::ScalarField>>,
    ) -> Result<ark_groth16::Proof<P>> {
        let public_inputs = &private_witness.public_inputs;
        let private_witness = &private_witness.witness;

        // TODO CESAR: Duplicate
        let domain = GeneralEvaluationDomain::<P::ScalarField>::new(
            matrices.num_constraints + matrices.num_instance_variables,
        )
        .ok_or(eyre::eyre!("Polynomial Degree too large"))?;
        let domain_size = domain.size();

        let all_timer = std::time::Instant::now();

        // we need 3 number of corr rand pairs. 2 for two rand calls, 1 for scalar_mul
        let mut state0 = Rep3State::new(net0, A2BType::default())?;
        let mut state1 = state0.fork(0)?;

        if std::any::TypeId::of::<P>() == std::any::TypeId::of::<ark_bn254::Bn254>() {
            let (key, private_witness, matrices, public_inputs) = transmute_groth16_artifacts!(
                src_pairing = P,
                dst_pairing = ark_bn254::Bn254,
                dst_field = ark_bn254::Fr,
                src_arithmetic_share = Rep3PrimeFieldShare<P::ScalarField>,
                dst_arithmetic_share = Rep3PrimeFieldShare<ark_bn254::Fr>,
                pkey,
                matrices,
                private_witness,
                public_inputs
            );

            let (key, mut eval_a, mut eval_b, public_inputs, private_witness) =
                CoGroth16Icicle::<Bn254Bridge, Rep3Groth16Driver>::setup::<
                    co_groth16::mpc::Rep3Groth16Driver,
                >(
                    state0.id(),
                    key,
                    matrices,
                    private_witness,
                    public_inputs,
                    domain_size,
                )?;

            let timer_start = std::time::Instant::now();
            let icicle_proof =
                CoGroth16Icicle::<Bn254Bridge, Rep3Groth16Driver>::prove_inner::<N, R>(
                    &net0,
                    &net1,
                    &mut state0,
                    &mut state1,
                    &mut eval_a,
                    &mut eval_b,
                    &key,
                    private_witness,
                    &public_inputs,
                )?;
            println!(
                "Proof generation took {} ms",
                timer_start.elapsed().as_millis()
            );

            let proof = icicle_proof.to_ark::<Bn254Bridge>();

            let proof = unsafe {
                transmute::<&ark_groth16::Proof<ark_bn254::Bn254>, &ark_groth16::Proof<P>>(&proof)
            };

            println!("Total time took {} ms", all_timer.elapsed().as_millis());
            return Ok(proof.clone());
        } else {
            panic!("Unsupported pairing")
        };
    }
}
