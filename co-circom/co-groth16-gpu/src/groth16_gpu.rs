//! A Groth16 proof protocol that uses a collaborative MPC protocol to generate the proof.
use ark_bn254::Bn254;
use ark_ec::bn::Bn;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, FftField, Field as ArkField, LegendreSymbol, PrimeField};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::ConstraintMatrices;
use co_circom_types::{Rep3SharedWitness, ShamirSharedWitness, SharedWitness};
use eyre::Result;
use icicle_core::msm::msm;
use icicle_core::traits::MontgomeryConvertible;
use icicle_runtime::Device;
use icicle_runtime::memory::{DeviceSlice, DeviceVec, HostOrDeviceSlice};
use mpc_core::MpcState;
use mpc_core::protocols::rep3::Rep3State;
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_core::protocols::shamir::{ShamirPreprocessing, ShamirState};
use mpc_net::Network;
use num_traits::ToPrimitive;
use rayon::str;
use std::marker::PhantomData;
use std::mem::transmute;
use std::ops::Index;
use icicle_core::bignum::BigNum;
use tracing::instrument;
use icicle_core::affine::Affine;

use icicle_bn254::curve::ScalarField;
use icicle_core::{ecntt::Projective, ntt::NTT, msm::MSM, vec_ops::VecOps, field::Field, pairing::Pairing};
use rayon::iter::{
    IndexedParallelIterator
};


use crate::bridges::{ArkIcicleBridge, Bn254Bridge};
use crate::gpu_utils::{DeviceMatrices, Proof, ProvingKey, VerifyingKey};
use crate::groth16_gpu;
use crate::mpc::CircomGroth16Prover;
use crate::mpc::plain::PlainGroth16Driver;
// use crate::mpc::rep3::Rep3Groth16Driver;
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
pub struct CoGroth16<P: ark_ec::pairing::Pairing> {
    phantom_data: PhantomData<P>
}

/// A type alias for a [CoGroth16] protocol using replicated secret sharing, using the Circom R1CSToQAPReduction by default.
// TODO CESAR
// pub type Rep3CoGroth16<P> = CoGroth16<P, Rep3Groth16Driver>;
/// A type alias for a [CoGroth16] protocol using shamir secret sharing, using the Circom R1CSToQAPReduction by default.
// TODO CESAR
// pub type ShamirCoGroth16<P> = CoGroth16<P, ShamirGroth16Driver>;

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
pub struct CoGroth16Icicle<B: ArkIcicleBridge, T: CircomGroth16Prover<B::IcicleScalarField>> {
    phantom_data: PhantomData<(B, T)>,
}

impl<B: ArkIcicleBridge, T: CircomGroth16Prover<B::IcicleScalarField>> CoGroth16Icicle<B, T> {

    fn setup_and_prove<N: Network, R: R1CSToQAP>(
        net0: &N,
        net1: &N,
        state0: &mut T::State,
        state1: &mut T::State,
        pkey: &ark_groth16::ProvingKey<B::ArkPairing>,
        matrices: &ConstraintMatrices<B::ArkScalarField>,
        public_inputs: &Vec<B::ArkScalarField>,
        private_witness: T::DeviceShares,
    ) -> eyre::Result<ark_groth16::Proof<B::ArkPairing>> {

        let matrices = DeviceMatrices::from_constraint_matrices::<B>(matrices);
        let pk = ProvingKey::from_ark::<B>(pkey);

        // TODO CESAR: This looks sooo bad
        let public_inputs = public_inputs.iter().map(B::ark_to_icicle_scalar).collect::<Vec<_>>();
        let public_inputs = DeviceVec::from_host_slice(&public_inputs);

        let icicle_proof = Self::prove_inner::<N, R>(net0, net1, state0, state1, &pk, &matrices, &public_inputs, private_witness)?;

        Ok(icicle_proof.to_ark::<B>())
    }

    /// Execute the Groth16 prover using the internal MPC driver.
    /// This version takes the Circom-generated constraint matrices as input and does not re-calculate them.
    #[instrument(level = "debug", name = "Groth16 - Proof", skip_all)]
    fn prove_inner<N: Network, R: R1CSToQAP>(
        net0: &N,
        net1: &N,
        state0: &mut T::State,
        state1: &mut T::State,
        pkey: &ProvingKey<B::IcicleScalarField, B::IcicleG1, B::IcicleG2>,
        matrices: &DeviceMatrices<B::IcicleScalarField>,
        public_inputs: &DeviceVec<B::IcicleScalarField>,
        private_witness: T::DeviceShares,
    ) -> eyre::Result<Proof<B::IcicleScalarField, B::IcicleG1, B::IcicleG2>> {
        if public_inputs.len() != matrices.num_instance_variables {
            eyre::bail!(
                "amount of public inputs does not match with provided constraint system! Expected {}, but got {}",
                matrices.num_instance_variables,
                public_inputs.len()
            )
        }
        
        // TODO CESAR
        // if private_witness.len() != matrices.num_witness_variables {
        //     eyre::bail!(
        //         "amount of private witness variables does not match with provided constraint system! Expected {}, but got {}",
        //         matrices.num_witness_variables,
        //         private_witness.len()
        //     )
        // }

        let h = R::witness_map_from_matrices::<B::IcicleScalarField, B::IcicleG1, B::IcicleG2, T>(
            state0,
            matrices,
            &public_inputs,
            &private_witness,
        )?;
        let (r, s) = (T::rand::<_, B>(net0, state0)?, T::rand::<_, B>(net0, state0)?);

        let private_witness_half_shares= T::to_half_share_vec(&private_witness);

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
            &private_witness_half_shares,
        )
    }

    fn calculate_coeff<C>(
        id: <T::State as MpcState>::PartyID,
        initial: C::Affine,
        query: &DeviceVec<C::Affine>,
        vk_param: C::Affine,
        input_assignment: &DeviceSlice<B::IcicleScalarField>,
        aux_assignment: &DeviceSlice<B::IcicleScalarField>,
    ) -> C::Affine
    where
        C: Projective<ScalarField = B::IcicleScalarField> + MSM<C>,
    {
        let pub_len = input_assignment.len();

        // TODO CESAR: parallelize with threads
        let priv_acc = T::msm_public_points_hs::<C>(query.index(1 + pub_len..), aux_assignment);
        let pub_acc = T::msm_public_points_hs::<C>(query.index(1..=pub_len), input_assignment);

        let mut res = initial;
        // TODO CESAR: Is this bad?
        T::add_assign_points_public_hs::<C>(id, &mut res, &query.index(0..1).to_host_vec().pop().unwrap());
        T::add_assign_points_public_hs::<C>(id, &mut res, &vk_param);
        T::add_assign_points_public_hs::<C>(id, &mut res, &pub_acc);
        res = (C::from_affine(res) + C::from_affine(priv_acc)).to_affine();
        res
    }

    #[instrument(level = "debug", name = "create proof with assignment", skip_all)]
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
        } = pkey;

        // TODO CESAR: Maybe this is too much copying
        let VerifyingKey {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ..
        } = vk.clone();


        let delta_g1 = B::from_affine_g1(*delta_g1);
        let delta_g2 = B::from_affine_g2(delta_g2);

        let id = state0.id();

        // TODO CESAR: Use threads

        // Compute A
        let r_hs = T::to_half_share(r);
        let r_g1 = delta_g1 * r_hs;
        let r_g1 = Self::calculate_coeff::<B::IcicleG1>(
            id,
            r_g1.to_affine(),
            a_query,
            alpha_g1,
            &input_assignment[1..],
            aux_assignment,
        );

        // Compute B in G1
        // In original implementation this is skipped if r==0, however r is shared in our case
        let s_hs = T::to_half_share(s);
        let s_g1 = delta_g1 * s_hs;
        let s_g1 = Self::calculate_coeff::<B::IcicleG1>(
            id,
            s_g1.to_affine(),
            b_g1_query,
            *beta_g1,
            &input_assignment[1..],
            aux_assignment,
        );

        // Compute B in G2
        let s_g2 = delta_g2 * s_hs;
        let s_g2 = Self::calculate_coeff::<B::IcicleG2>(
            id,
            s_g2.to_affine(),
            b_g2_query,
            beta_g2,
            &input_assignment[1..],
            aux_assignment,
        );

        // Compute msm(l_query, aux_assignment)
        let l_acc = T::msm_public_points_hs::<B::IcicleG1>(l_query, aux_assignment);

        // Compute msm(h_query, h)
        let h_acc = T::msm_public_points_hs::<B::IcicleG1>(h_query, &h);

        // Compute r * s
        let rs = T::local_mul(&r, &s, state0);
        let r_s_delta_g1 = delta_g1 * rs;

        let g_a = r_g1;
        let g1_b = s_g1;

        // TODO CESAR: Use threads
        let g_a_opened = T::open_half_point::<_, B::IcicleG1, B>(g_a, net0, state0)?;
        let r_g1_b = T::scalar_mul::<_, B::IcicleG1>(&g1_b, r, net1, state1)?;

        let s_g_a = B::IcicleG1::from_affine(g_a_opened) * s_hs;

        let mut g_c = s_g_a;
        g_c = g_c + B::from_affine_g1(r_g1_b);
        g_c = g_c - r_s_delta_g1;
        g_c = g_c + B::from_affine_g1(l_acc);
        g_c = g_c + B::from_affine_g1(h_acc);

        // TODO CESAR: Use threads
        let g2_b = s_g2;
        let g_c_opened = T::open_half_point::<_, B::IcicleG1, B>(g_c.to_affine(), net0, state0)?;
        let g2_b_opened = T::open_half_point::<_, B::IcicleG2, B>(g2_b, net1, state1)?;

        Ok(Proof {
            a: g_a_opened,
            b: g2_b_opened,
            c: g_c_opened,
        })
    }
}

// TODO CESAR
// impl<P: Pairing> Rep3CoGroth16<P> {
//     /// Create a [`Proof`].
//     pub fn prove<N: Network, R: R1CSToQAP>(
//         net0: &N,
//         net1: &N,
//         pkey: &ProvingKey<P>,
//         matrices: &ConstraintMatrices<P::ScalarField>,
//         witness: Rep3SharedWitness<P::ScalarField>,
//     ) -> eyre::Result<Proof<P>> {
//         let mut state0 = Rep3State::new(net0, A2BType::default())?;
//         let mut state1 = state0.fork(0)?;
//         // execute prover in MPC
//         Self::prove_inner::<N, R>(
//             net0,
//             net1,
//             &mut state0,
//             &mut state1,
//             pkey,
//             matrices,
//             witness,
//         )
//     }
// }

// impl<P: Pairing> ShamirCoGroth16<P> {
//     /// Create a [`Proof`].
//     pub fn prove<N: Network, R: R1CSToQAP>(
//         net0: &N,
//         net1: &N,
//         num_parties: usize,
//         threshold: usize,
//         pkey: &ProvingKey<P>,
//         matrices: &ConstraintMatrices<P::ScalarField>,
//         witness: ShamirSharedWitness<P::ScalarField>,
//     ) -> eyre::Result<Proof<P>> {
//         // we need 3 number of corr rand pairs. 2 for two rand calls, 1 for scalar_mul
//         let num_pairs = 3;
//         let preprocessing = ShamirPreprocessing::new(num_parties, threshold, num_pairs, net0)?;
//         let mut state0 = ShamirState::from(preprocessing);
//         let mut state1 = state0.fork(1)?;
//         // execute prover in MPC
//         Self::prove_inner::<N, R>(
//             net0,
//             net1,
//             &mut state0,
//             &mut state1,
//             pkey,
//             matrices,
//             witness,
//         )
//     }
// }

impl<P: ark_ec::pairing::Pairing> CoGroth16<P> {
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
         if std::any::TypeId::of::<P>() == std::any::TypeId::of::<ark_bn254::Bn254>() {
            // SAFETY: transmutes are safe here because we know P == Bn254
            let public_inputs = unsafe {
                transmute::<&Vec<P::ScalarField>, &Vec<ark_bn254::Fr>>(public_inputs)
            };
            
            let private_witness = unsafe {
                transmute::<&Vec<P::ScalarField>, &Vec<ark_bn254::Fr>>(private_witness)
            };

            let matrices = unsafe {
                transmute::<&ConstraintMatrices<P::ScalarField>, &ConstraintMatrices<ark_bn254::Fr>>(matrices)
            };

            let key = unsafe {
                transmute::<&ark_groth16::ProvingKey<P>, &ark_groth16::ProvingKey<ark_bn254::Bn254>>(pkey)
            };

            // TODO CESAR: This looks sooo bad
            let private_witness = private_witness.iter().map(Bn254Bridge::ark_to_icicle_scalar).collect::<Vec<_>>();
            let private_witness = DeviceVec::from_host_slice(&private_witness);

            let proof = CoGroth16Icicle::<Bn254Bridge, PlainGroth16Driver>::setup_and_prove::<_, R>(&(), &(), &mut (), &mut (), key, matrices, public_inputs, private_witness);
            
            let proof = unsafe {
                transmute::<&ark_groth16::Proof<ark_bn254::Bn254>, &ark_groth16::Proof<P>>(&proof?)
            };
            
            return Ok(proof.clone());
        } else {
            panic!("Unsupported pairing")
        };


    }
}
