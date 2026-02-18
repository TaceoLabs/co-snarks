use std::{mem::transmute, ops::IndexMut};

use ark_ff::UniformRand;
use icicle_core::{
    curve::{Affine, Curve},
    ntt::NTT,
    traits::{Arithmetic, FieldImpl, MontgomeryConvertible},
    vec_ops::{VecOps, VecOpsConfig, mul_scalars},
};
use icicle_runtime::{
    memory::{DeviceSlice, DeviceVec, HostOrDeviceSlice},
    stream::IcicleStream,
};
use mpc_core::MpcState;
use mpc_net::Network;
use rand::thread_rng;

use crate::{
    bridges::{ArkIcicleBridge, ark_to_icicle_scalar, ark_to_icicle_scalars},
    gpu_utils::{fft_inplace, from_host_slice, ifft_inplace},
};

use super::CircomGroth16Prover;

/// A plain Groth16 driver
pub struct PlainGroth16Driver;

impl<F: FieldImpl<Config: VecOps<F> + NTT<F, F>> + Arithmetic + MontgomeryConvertible>
    CircomGroth16Prover<F> for PlainGroth16Driver
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

    fn promote_to_trivial_shares(
        _: <Self::State as MpcState>::PartyID,
        public_values: &DeviceSlice<F>,
    ) -> Self::DeviceShares {
        let mut result = DeviceVec::device_malloc(public_values.len())
            .expect("Failed to allocate device vector");
        result.copy(public_values).unwrap();
        result
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

    fn add_assign_points_public_hs<C: Curve<ScalarField = F>>(
        _: <Self::State as MpcState>::PartyID,
        a: &mut Affine<C>,
        b: &Affine<C>,
    ) {
        *a = (a.to_projective() + b.to_projective()).into();
    }

    fn fft_in_place(input: &mut Self::DeviceShares, stream: &IcicleStream) {
        fft_inplace(input, stream);
    }

    fn ifft_in_place(input: &mut Self::DeviceShares, stream: &IcicleStream) {
        ifft_inplace(input, stream);
    }

    fn copy_to_device_shares(
        src: &Self::DeviceShares,
        dst: &mut Self::DeviceShares,
        start: usize,
        end: usize,
    ) {
        dst.index_mut(start..end).copy(src).unwrap();
    }

    fn shares_to_device<
        B: ArkIcicleBridge<IcicleScalarField = F>,
        T: co_groth16::CircomGroth16Prover<B::ArkPairing> + 'static,
    >(
        shares: &Vec<T::ArithmeticShare>,
    ) -> Self::DeviceShares {
        if std::any::TypeId::of::<T>()
            != std::any::TypeId::of::<co_groth16::mpc::PlainGroth16Driver>()
        {
            panic!("Invalid driver: expected PlainGroth16Driver");
        }

        // SAFETY: At this point we know the shares are safe to transmute
        let shares =
            unsafe { transmute::<&Vec<T::ArithmeticShare>, &Vec<B::ArkScalarField>>(shares) };

        let shares_icicle = from_host_slice(shares);
        ark_to_icicle_scalars(shares_icicle).unwrap()
    }

    fn local_mul_vec<B: ArkIcicleBridge<IcicleScalarField = F>>(
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

    fn local_mul<B: ArkIcicleBridge<IcicleScalarField = F>>(
        a: &Self::ArithmeticShare,
        b: &Self::ArithmeticShare,
        _: &mut Self::State,
    ) -> F {
        *a * *b
    }

    fn rand<N: Network, B: ArkIcicleBridge<IcicleScalarField = F>>(
        _: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Self::ArithmeticShare> {
        let mut rng = thread_rng();
        let res = B::ArkScalarField::rand(&mut rng);
        Ok(ark_to_icicle_scalar(res))
    }

    fn open_half_point_g1<N: Network, B: ArkIcicleBridge<IcicleScalarField = F>>(
        a: Affine<B::IcicleG1>,
        _: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Affine<B::IcicleG1>> {
        Ok(a)
    }

    fn open_half_point_g2<N: Network, B: ArkIcicleBridge<IcicleScalarField = F>>(
        a: Affine<B::IcicleG2>,
        _: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Affine<B::IcicleG2>> {
        Ok(a)
    }

    fn scalar_mul_g1<N: Network, B: ArkIcicleBridge<IcicleScalarField = F>>(
        a: &Affine<B::IcicleG1>,
        b: Self::ArithmeticShare,
        _: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Affine<B::IcicleG1>> {
        Ok((a.to_projective() * b).into())
    }
}
