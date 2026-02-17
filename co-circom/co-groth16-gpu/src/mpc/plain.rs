use std::ops::{Index, IndexMut};

use ark_ff::UniformRand;
use icicle_core::{
    curve::{Affine, Curve},
    msm::{MSM, MSMConfig, msm},
    ntt::NTT,
    traits::{Arithmetic, FieldImpl},
    vec_ops::{VecOps, VecOpsConfig, mul_scalars, sub_scalars, sum_scalars},
};
use icicle_runtime::{
    Device,
    memory::{DeviceSlice, DeviceVec, HostOrDeviceSlice},
    stream::IcicleStream,
};
use mpc_core::MpcState;
use mpc_net::Network;
use rand::thread_rng;

use crate::{
    bridges::ArkIcicleBridge,
    gpu_utils::{fft_inplace, get_first_projective, ifft_inplace},
};

use super::CircomGroth16Prover;

/// A plain Groth16 driver
pub struct PlainGroth16Driver;

impl<F: FieldImpl<Config: VecOps<F> + NTT<F, F>> + Arithmetic> CircomGroth16Prover<F>
    for PlainGroth16Driver
{
    type ArithmeticShare = F;

    type DeviceShares = DeviceVec<F>;
    type DevicePointShares<C: Curve<ScalarField = F>> = DeviceVec<Affine<C>>;

    type State = ();
    fn to_half_share(a: &Self::ArithmeticShare) -> F {
        *a
    }

    // TODO CESAR: Avoid copy
    fn to_half_share_vec(a: &Self::DeviceShares) -> DeviceVec<F> {
        let mut result =
            DeviceVec::device_malloc(a.len()).expect("Failed to allocate device vector");
        result.copy(a).unwrap();
        result
    }

    fn msm_public_points_hs<C: Curve<ScalarField = F> + MSM<C>>(
        points: &DeviceSlice<Affine<C>>,
        scalars: &DeviceSlice<F>,
        stream: &IcicleStream,
    ) -> Affine<C> {
        let mut results =
            DeviceVec::device_malloc_async(1, stream).expect("Failed to allocate device vector");
        let mut cfg = MSMConfig::default();
        cfg.stream_handle = **stream;
        cfg.is_async = true;
        msm::<C>(scalars, points, &cfg, results.index_mut(..)).unwrap();
        get_first_projective(&results).unwrap().into()
    }

    fn promote_to_trivial_shares(
        _: <Self::State as MpcState>::PartyID,
        public_values: &DeviceSlice<F>,
    ) -> Self::DeviceShares {
        let mut result = DeviceVec::device_malloc(public_values.len())
            .expect("Failed to allocate device vector");
        result.copy(public_values).unwrap();
        result
    }

    fn local_mul_vec(
        a: &Self::DeviceShares,
        b: &Self::DeviceShares,
        _: &mut Self::State,
        stream: &IcicleStream,
    ) -> DeviceVec<F> {
        let mut result = DeviceVec::device_malloc_async(a.len(), stream)
            .expect("Failed to allocate device vector");
        let mut cfg = VecOpsConfig::default();
        cfg.stream_handle = **stream;
        cfg.is_async = true;
        mul_scalars(a, b, result.as_mut_slice(), &cfg).unwrap();
        result
    }

    fn local_mul(a: &Self::ArithmeticShare, b: &Self::ArithmeticShare, _: &mut Self::State) -> F {
        *a * *b
    }

    fn add_assign_points_public_hs<C: Curve<ScalarField = F>>(
        _: <Self::State as MpcState>::PartyID,
        a: &mut Affine<C>,
        b: &Affine<C>,
    ) {
        *a = (a.to_projective() + b.to_projective()).into();
    }

    // TODO CESAR: Check if we can avoid alloc
    fn distribute_powers_and_mul_by_const(
        coeffs: &mut Self::DeviceShares,
        roots: &DeviceSlice<F>,
        stream: &IcicleStream,
    ) {
        let mut result = DeviceVec::device_malloc_async(coeffs.len(), stream)
            .expect("Failed to allocate device vector");
        let mut cfg = VecOpsConfig::default();
        cfg.stream_handle = **stream;
        cfg.is_async = true;
        mul_scalars(coeffs, roots, result.as_mut_slice(), &cfg).unwrap();
        *coeffs = result;
    }

    // TODO CESAR: Check if we can avoid alloc
    fn distribute_powers_and_mul_by_const_hs(
        coeffs: &mut DeviceVec<F>,
        roots: &DeviceSlice<F>,
        stream: &IcicleStream,
    ) {
        let mut result = DeviceVec::device_malloc_async(coeffs.len(), stream)
            .expect("Failed to allocate device vector");
        let mut cfg = VecOpsConfig::default();
        cfg.stream_handle = **stream;
        cfg.is_async = true;
        mul_scalars(coeffs, roots, result.as_mut_slice(), &cfg).unwrap();
        *coeffs = result;
    }

    fn scalar_mul<N: Network, C: Curve<ScalarField = F>>(
        a: &Affine<C>,
        b: Self::ArithmeticShare,
        _: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Affine<C>> {
        Ok((a.to_projective() * b).into())
    }

    fn fft_in_place(input: &mut Self::DeviceShares, stream: &IcicleStream) {
        fft_inplace(input, stream).expect("FFT failed");
    }

    fn ifft_in_place(input: &mut Self::DeviceShares, stream: &IcicleStream) {
        ifft_inplace(input, stream).expect("IFFT failed");
    }

    fn fft_in_place_hs(input: &mut DeviceVec<F>, stream: &IcicleStream) {
        fft_inplace(input, stream).expect("FFT failed");
    }

    fn ifft_in_place_hs(input: &mut DeviceVec<F>, stream: &IcicleStream) {
        ifft_inplace(input, stream).expect("IFFT failed");
    }

    fn copy_to_device_shares(
        src: &Self::DeviceShares,
        dst: &mut Self::DeviceShares,
        start: usize,
        end: usize,
    ) {
        dst.index_mut(start..end).copy(src).unwrap();
    }

    fn rand<N: Network, B: ArkIcicleBridge<IcicleScalarField = F>>(
        _: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Self::ArithmeticShare> {
        let mut rng = thread_rng();
        let res = B::ArkScalarField::rand(&mut rng);
        Ok(B::ark_to_icicle_scalar(&res))
    }

    fn open_half_point<
        N: Network,
        C: Curve<ScalarField = F>,
        B: ArkIcicleBridge<IcicleScalarField = F>,
    >(
        a: Affine<C>,
        _: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Affine<C>> {
        Ok(a)
    }
}
