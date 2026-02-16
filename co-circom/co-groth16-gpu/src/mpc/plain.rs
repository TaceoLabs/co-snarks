use std::ops::{Index, IndexMut};

use ark_ff::UniformRand;
use icicle_core::{ecntt::Projective, field::Field, matrix_ops::{MatMulConfig, MatrixOps, matmul}, msm::{MSM, MSMConfig, msm}, ntt::NTT, vec_ops::{VecOps, VecOpsConfig, mul_scalars, sub_scalars, sum_scalars}};
use icicle_runtime::memory::{DeviceSlice, DeviceVec, HostOrDeviceSlice};
use mpc_core::MpcState;
use mpc_net::Network;
use rand::thread_rng;

use crate::{bridges::ArkIcicleBridge, gpu_utils::{DeviceMatrix,fft_inplace, ifft_inplace}};

use super::CircomGroth16Prover;

/// A plain Groth16 driver
pub struct PlainGroth16Driver;

impl<F: Field + VecOps<F> + NTT<F, F> + MatrixOps<F>> CircomGroth16Prover<F> for PlainGroth16Driver {
    type ArithmeticShare = F;

    type DeviceShares = DeviceVec<F>;
    type DevicePointShares<P: Projective> = DeviceVec<P::Affine>;

    type State = ();

    // TODO CESAR: Can we avoid the two allocs
    // TODO CESAR: Explore MatMulConfig
    fn evaluate_constraints(
        _: <Self::State as MpcState>::PartyID,
        domain_size: usize,
        matrix: &DeviceMatrix<F>,
        public_inputs: &DeviceSlice<F>,
        private_witness: &Self::DeviceShares,
    ) -> Self::DeviceShares {
        let b_rows = public_inputs.len() + private_witness.len();
        let mut b = DeviceVec::device_malloc(b_rows).expect("Failed to allocate device vector");
        b.copy(public_inputs).unwrap();
        b.index_mut(public_inputs.len()..).copy(private_witness).unwrap();

        let DeviceMatrix {
            data,
            cols,
            rows
        } = matrix;

        // TODO CESAR: Maybe this alloc trick doesn't work
        let mut result = DeviceVec::zeros(domain_size);
        matmul(data, *rows, *cols, &b, b_rows as u32, 1, &MatMulConfig::default(), result.index_mut(..(*rows as usize))).unwrap();

        result
    }

    fn evaluate_constraint(
        _: <Self::State as MpcState>::PartyID,
        active_values: &DeviceSlice<F>,
        active_public_inputs: &DeviceSlice<F>,
        active_private_witness: &Self::DeviceShares,
    ) -> Self::ArithmeticShare {
        let mut pairwise = DeviceVec::device_malloc(active_values.len()).expect("Failed to allocate device vector");
        mul_scalars(active_public_inputs, active_values.index(..active_public_inputs.len()), pairwise.index_mut(..active_public_inputs.len()), &VecOpsConfig::default()).unwrap();
        mul_scalars(active_private_witness, active_values.index(active_public_inputs.len()..), pairwise.index_mut(active_public_inputs.len()..), &VecOpsConfig::default()).unwrap();
        let mut result = DeviceVec::device_malloc(1).expect("Failed to allocate device vector");
        sum_scalars(&pairwise, &mut result, &VecOpsConfig::default()).unwrap();
        result.to_host_vec().pop().unwrap()
    }

    fn evaluate_constraint_half_share(
        _: <Self::State as MpcState>::PartyID,
        active_values: &DeviceSlice<F>,
        active_public_inputs: &DeviceSlice<F>,
        active_private_witness: &Self::DeviceShares,
    ) -> F {
        let mut pairwise = DeviceVec::device_malloc(active_values.len()).expect("Failed to allocate device vector");
        mul_scalars(active_public_inputs, active_values.index(..active_public_inputs.len()), pairwise.index_mut(..active_public_inputs.len()), &VecOpsConfig::default()).unwrap();
        mul_scalars(active_private_witness, active_values.index(active_public_inputs.len()..), pairwise.index_mut(active_public_inputs.len()..), &VecOpsConfig::default()).unwrap();
        let mut result = DeviceVec::device_malloc(1).expect("Failed to allocate device vector");
        sum_scalars(&pairwise, &mut result, &VecOpsConfig::default()).unwrap();
        result.to_host_vec().pop().unwrap()
    }

    fn to_half_share(a: Self::ArithmeticShare) -> F {
        a
    }

    // TODO CESAR: Avoid copy
    fn to_half_share_vec(a: &Self::DeviceShares) -> DeviceVec<F> {
        let mut result = DeviceVec::device_malloc(a.len()).expect("Failed to allocate device vector");
        result.copy(a).unwrap() ;
        result
    }

    fn msm_public_points_hs<P: Projective<ScalarField = F> + MSM<P>>(
        points: &DeviceSlice<P::Affine>,
        scalars: &DeviceSlice<F>,
    ) -> P::Affine
    {
        let mut results = DeviceVec::device_malloc(1).expect("Failed to allocate device vector");
        msm::<P>(scalars, points, &MSMConfig::default(), results.index_mut(..)).unwrap();
        results.to_host_vec().pop().unwrap().into()
    }

    fn promote_to_trivial_shares(
        _: <Self::State as MpcState>::PartyID,
        public_values: &DeviceSlice<F>,
    ) -> Self::DeviceShares {
       let mut result = DeviceVec::device_malloc(public_values.len()).expect("Failed to allocate device vector");
       result.copy( public_values).unwrap();
       result
    }

    fn local_mul_vec(
        a: &Self::DeviceShares,
        b: &Self::DeviceShares,
        _: &mut Self::State,
    ) -> DeviceVec<F> {
        let mut result = DeviceVec::device_malloc(a.len()).expect("Failed to allocate device vector");
        mul_scalars(a, b, result.as_mut_slice(), &VecOpsConfig::default()).unwrap();
        result
    }

    fn local_mul(
        a: &Self::ArithmeticShare,
        b: &Self::ArithmeticShare,
        _: &mut Self::State,
    ) -> F {
        *a * *b
    }

    // TODO CESAR: Remove
    fn sub_vec_hs(
        a: &DeviceVec<F>,
        b: &DeviceVec<F>,
        _: &mut Self::State,
    ) -> DeviceVec<F> {
        let mut result = DeviceVec::device_malloc(a.len()).expect("Failed to allocate device vector");
        sub_scalars(a, b, result.as_mut_slice(), &VecOpsConfig::default()).unwrap();
        result
    }

    fn add_assign_points_public_hs<P: Projective<ScalarField = F>>(
        _: <Self::State as MpcState>::PartyID,
        a: &mut P::Affine,
        b: &P::Affine,
    ) {
        *a = (P::from_affine(*a) + P::from_affine(*b)).to_affine();
    }

    // TODO CESAR: Check if we can avoid alloc
    fn distribute_powers_and_mul_by_const(
        coeffs: &mut Self::DeviceShares,
        roots: &DeviceSlice<F>,
    ) {
        let mut result = DeviceVec::device_malloc(coeffs.len()).expect("Failed to allocate device vector");
        mul_scalars(coeffs, roots, result.as_mut_slice(), &VecOpsConfig::default()).unwrap();
        *coeffs = result;
    }


    // TODO CESAR: Check if we can avoid alloc
    fn distribute_powers_and_mul_by_const_hs(
        coeffs: &mut DeviceVec<F>,
        roots: &DeviceSlice<F>,
    ) {
        let mut result = DeviceVec::device_malloc(coeffs.len()).expect("Failed to allocate device vector");
        mul_scalars(coeffs, roots, result.as_mut_slice(), &VecOpsConfig::default()).unwrap();
        *coeffs = result;
    }

    fn scalar_mul<N: Network, P: Projective<ScalarField = F>>(
        a: &P::Affine,
        b: Self::ArithmeticShare,
        _: &N,
        _: &mut Self::State,
    ) -> eyre::Result<P::Affine> {
        Ok((P::from_affine(*a) * b).to_affine())
    }

    fn fft_in_place(input: &mut Self::DeviceShares) {
        fft_inplace(input).expect("FFT failed");
    }

    fn ifft_in_place(input: &mut Self::DeviceShares) {
        ifft_inplace(input).expect("IFFT failed");
    }

    fn fft_in_place_hs(input: &mut DeviceVec<F>) {
        fft_inplace(input).expect("FFT failed");
    }

    fn ifft_in_place_hs(input: &mut DeviceVec<F>) {
        ifft_inplace(input).expect("IFFT failed");
    }

    fn copy_to_device_shares(src: &Self::DeviceShares, dst: &mut Self::DeviceShares, start: usize, end: usize) {
        dst.index_mut(start..end).copy(src).unwrap();
    }

    fn rand<N: Network, B: ArkIcicleBridge<IcicleScalarField = F>>(_: &N, _: &mut Self::State) -> eyre::Result<Self::ArithmeticShare> {
        let mut rng = thread_rng();
        let res = B::ArkScalarField::rand(&mut rng);
        Ok(B::ark_to_icicle_scalar(&res))
    }

    fn open_half_point<N: Network, P: Projective<ScalarField = F>, B: ArkIcicleBridge<IcicleScalarField = F>>(
        a: P::Affine,
        _: &N,
        _: &mut Self::State,
    ) -> eyre::Result<P::Affine> {
        Ok(a)
    }
}
