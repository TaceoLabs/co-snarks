use std::ops::{Index, IndexMut};

use icicle_core::{ecntt::Projective, field::Field, matrix_ops::{MatMulConfig, MatrixOps, matmul}, msm::{MSM, MSMConfig, msm}, ntt::NTT, vec_ops::{VecOps, VecOpsConfig, mul_scalars, sub_scalars, sum_scalars}};
use icicle_runtime::{Device, memory::{DeviceSlice, DeviceVec, HostOrDeviceSlice}};
use mpc_core::{MpcState, protocols::rep3::{Rep3State, arithmetic}};
use mpc_net::Network;

use crate::{bridges::ArkIcicleBridge, gpu_utils::{DeviceMatrix,fft_inplace, ifft_inplace}};

use super::CircomGroth16Prover;

/// A Groth16 driver for REP3 secret sharing
pub struct Rep3Groth16Driver;

pub struct Rep3IcicleShare<T> {
    a: T,
    b: T,
}

pub struct Rep3IcicleShares<T> {
    a: DeviceVec<T>,
    b: DeviceVec<T>,
}

impl<F: Field + VecOps<F> + NTT<F, F> + MatrixOps<F>> CircomGroth16Prover<F> for Rep3Groth16Driver {
    type ArithmeticShare = Rep3IcicleShare<F>;

    type DeviceShares = Rep3IcicleShares<F>;
    type DevicePointShares<P: Projective> = Rep3IcicleShares<P::Affine>;

    type State = Rep3State;

    // TODO CESAR: Can we avoid the two allocs
    // TODO CESAR: Explore MatMulConfig
    fn evaluate_constraints(
        _: <Self::State as MpcState>::PartyID,
        domain_size: usize,
        matrix: &DeviceMatrix<F>,
        public_inputs: &DeviceSlice<F>,
        private_witness: &Self::DeviceShares,
    ) -> Self::DeviceShares {
        let DeviceMatrix {
            data,
            cols,
            rows
        } = matrix;

        let b_rows = public_inputs.len() + private_witness.a.len();
        let mut b = DeviceVec::device_malloc(b_rows).expect("Failed to allocate device vector");
        b.copy(public_inputs).unwrap();

        // TODO CESAR: Is there a better way?

        b.index_mut(public_inputs.len()..).copy(&private_witness.a).unwrap();
        let mut result_a = DeviceVec::zeros(domain_size);
        matmul(data, *rows, *cols, &b, b_rows as u32, 1, &MatMulConfig::default(), result_a.index_mut(..(*rows as usize))).unwrap();

        b.index_mut(public_inputs.len()..).copy(&private_witness.b).unwrap();
        let mut result_b = DeviceVec::zeros(domain_size);
        matmul(data, *rows, *cols, &b, b_rows as u32, 1, &MatMulConfig::default(), result_b.index_mut(..(*rows as usize))).unwrap();

        Rep3IcicleShares {
            a: result_a,
            b: result_b,
        }
    }

    fn evaluate_constraint(
        _: <Self::State as MpcState>::PartyID,
        active_values: &DeviceSlice<F>,
        active_public_inputs: &DeviceSlice<F>,
        active_private_witness: &Self::DeviceShares,
    ) -> Self::ArithmeticShare {
        unimplemented!()
    }

    fn evaluate_constraint_half_share(
        _: <Self::State as MpcState>::PartyID,
        active_values: &DeviceSlice<F>,
        active_public_inputs: &DeviceSlice<F>,
        active_private_witness: &Self::DeviceShares,
    ) -> F {
        unimplemented!()
    }

    fn to_half_share(a: &Self::ArithmeticShare) -> F {
        a.a.clone()
    }

    // TODO CESAR: Avoid copy
    fn to_half_share_vec(a: &Self::DeviceShares) -> DeviceVec<F> {
        let mut result = DeviceVec::device_malloc(a.a.len()).expect("Failed to allocate device vector");
        result.copy(&a.a).unwrap();
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
        Rep3IcicleShares {
            a: result,
            b: DeviceVec::zeros(public_values.len()),
        }
    }

    fn local_mul_vec(
        a: &Self::DeviceShares,
        b: &Self::DeviceShares,
        state: &mut Self::State,
    ) -> DeviceVec<F> {
        unimplemented!()
    }

    fn local_mul(
        a: &Self::ArithmeticShare,
        b: &Self::ArithmeticShare,
        _: &mut Self::State,
    ) -> F {
        unimplemented!()
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
        let mut a = DeviceVec::device_malloc(coeffs.a.len()).expect("Failed to allocate device vector");
        mul_scalars(&coeffs.a, roots, a.as_mut_slice(), &VecOpsConfig::default()).unwrap();
        
        let mut b = DeviceVec::device_malloc(coeffs.b.len()).expect("Failed to allocate device vector");
        mul_scalars(&coeffs.b, roots, b.as_mut_slice(), &VecOpsConfig::default()).unwrap();

        *coeffs = Rep3IcicleShares {
            a,
            b,
        };
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
        unimplemented!()
    }

    fn fft_in_place(input: &mut Self::DeviceShares) {
        fft_inplace(&mut input.a).expect("FFT failed");
        fft_inplace(&mut input.b).expect("FFT failed");
    }

    fn ifft_in_place(input: &mut Self::DeviceShares) {
        ifft_inplace(&mut input.a).expect("IFFT failed");
        ifft_inplace(&mut input.b).expect("IFFT failed");
    }

    fn fft_in_place_hs(input: &mut DeviceVec<F>) {
        fft_inplace(input).expect("FFT failed");
    }

    fn ifft_in_place_hs(input: &mut DeviceVec<F>) {
        ifft_inplace(input).expect("IFFT failed");
    }

    fn copy_to_device_shares(src: &Self::DeviceShares, dst: &mut Self::DeviceShares, start: usize, end: usize) {
        dst.a.index_mut(start..end).copy(&src.a).unwrap();
        dst.b.index_mut(start..end).copy(&src.b).unwrap();
    }

    fn rand<N: Network, B: ArkIcicleBridge<IcicleScalarField = F>>(_: &N, state: &mut Self::State) -> eyre::Result<Self::ArithmeticShare> {
        let shares = arithmetic::rand(state);
        Ok(
            Rep3IcicleShare { a: B::ark_to_icicle_scalar(&shares.a), b: B::ark_to_icicle_scalar(&shares.b) }
        )
    }

    fn open_half_point<N: Network, P: Projective<ScalarField = F>, B: ArkIcicleBridge<IcicleScalarField = F>>(
        a: P::Affine,
        _: &N,
        _: &mut Self::State,
    ) -> eyre::Result<P::Affine> {
        unimplemented!()
    }
}
