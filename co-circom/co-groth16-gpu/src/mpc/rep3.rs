use std::{mem::transmute, ops::IndexMut};

use ark_ec::CurveGroup;
use icicle_core::{
    curve::{Affine, Curve},
    ntt::NTT,
    traits::{Arithmetic, FieldImpl, MontgomeryConvertible},
    vec_ops::{VecOps, VecOpsConfig, add_scalars, mul_scalars},
};
use icicle_runtime::{
    memory::{DeviceSlice, DeviceVec, HostOrDeviceSlice},
    stream::IcicleStream,
};
use mpc_core::{
    MpcState,
    protocols::rep3::{
        Rep3PointShare, Rep3PrimeFieldShare, Rep3State, arithmetic, id::PartyID, pointshare,
    },
};
use mpc_net::Network;

use crate::{
    bridges::{
        ArkIcicleBridge, ark_to_icicle_affine, ark_to_icicle_scalar, ark_to_icicle_scalars,
        icicle_to_ark_scalar,
    },
    gpu_utils::{fft_inplace, from_host_slice, ifft_inplace},
};
use mpc_core::protocols::rep3::network::Rep3NetworkExt;

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
impl<F: FieldImpl<Config: VecOps<F> + NTT<F, F>> + Arithmetic + MontgomeryConvertible>
    CircomGroth16Prover<F> for Rep3Groth16Driver
{
    type ArithmeticShare = Rep3IcicleShare<F>;

    type DeviceShares = Rep3IcicleShares<F>;
    type DevicePointShares<C: Curve<ScalarField = F>> = Rep3IcicleShares<Affine<C>>;

    type State = Rep3State;

    fn to_half_share(a: &Self::ArithmeticShare) -> F {
        a.a.clone()
    }

    // TODO CESAR: Avoid copy
    fn to_half_share_vec(a: &Self::DeviceShares) -> DeviceVec<F> {
        let mut result =
            DeviceVec::device_malloc(a.a.len()).expect("Failed to allocate device vector");
        result.copy(&a.a).unwrap();
        result
    }

    fn promote_to_trivial_shares(
        _: <Self::State as MpcState>::PartyID,
        public_values: &DeviceSlice<F>,
    ) -> Self::DeviceShares {
        let mut result = DeviceVec::device_malloc(public_values.len())
            .expect("Failed to allocate device vector");
        let mut zeros = DeviceVec::device_malloc(public_values.len())
            .expect("Failed to allocate device vector");
        zeros.memset(0, public_values.len()).unwrap();
        result.copy(public_values).unwrap();

        Self::DeviceShares {
            a: result,
            b: zeros,
        }
    }

    // TODO CESAR: Check if there's a better way
    fn distribute_powers_and_mul_by_const(
        coeffs: &mut Self::DeviceShares,
        roots: &DeviceSlice<F>,
        stream: &IcicleStream,
    ) {
        let mut result_a = DeviceVec::device_malloc_async(coeffs.a.len(), stream)
            .expect("Failed to allocate device vector");
        let mut result_b = DeviceVec::device_malloc_async(coeffs.b.len(), stream)
            .expect("Failed to allocate device vector");
        let mut cfg = VecOpsConfig::default();
        cfg.stream_handle = **stream;
        cfg.is_async = true;
        mul_scalars(&coeffs.a, roots, result_a.as_mut_slice(), &cfg).unwrap();
        mul_scalars(&coeffs.b, roots, result_b.as_mut_slice(), &cfg).unwrap();
        *coeffs = Self::DeviceShares {
            a: result_a,
            b: result_b,
        };
    }

    fn add_assign_points_public_hs<C: Curve<ScalarField = F>>(
        id: <Self::State as MpcState>::PartyID,
        a: &mut Affine<C>,
        b: &Affine<C>,
    ) {
        if matches!(id, PartyID::ID0) {
            *a = (a.to_projective() + b.to_projective()).into();
        }
    }

    fn fft_in_place(input: &mut Self::DeviceShares, stream: &IcicleStream) {
        fft_inplace(&mut input.a, stream);
        fft_inplace(&mut input.b, stream);
    }

    fn ifft_in_place(input: &mut Self::DeviceShares, stream: &IcicleStream) {
        ifft_inplace(&mut input.a, stream);
        ifft_inplace(&mut input.b, stream);
    }

    fn copy_to_device_shares(
        src: &Self::DeviceShares,
        dst: &mut Self::DeviceShares,
        start: usize,
        end: usize,
    ) {
        dst.a.index_mut(start..end).copy(&src.a).unwrap();
        dst.b.index_mut(start..end).copy(&src.b).unwrap();
    }

    fn shares_to_device<
        B: ArkIcicleBridge<IcicleScalarField = F>,
        T: co_groth16::CircomGroth16Prover<B::ArkPairing> + 'static,
    >(
        shares: &Vec<T::ArithmeticShare>,
    ) -> Self::DeviceShares {
        if std::any::TypeId::of::<T>()
            != std::any::TypeId::of::<co_groth16::mpc::Rep3Groth16Driver>()
        {
            panic!("Invalid driver: expected Rep3Groth16Driver");
        }

        // SAFETY: At this point we know the shares are safe to transmute
        let shares = unsafe {
            transmute::<&Vec<T::ArithmeticShare>, &Vec<Rep3PrimeFieldShare<B::ArkScalarField>>>(
                shares,
            )
        };

        let (shares_a, shares_b): (Vec<B::ArkScalarField>, Vec<B::ArkScalarField>) =
            shares.iter().map(|s| (s.a, s.b)).unzip();

        let shares_a = from_host_slice(&shares_a);
        let shares_b = from_host_slice(&shares_b);

        let a = ark_to_icicle_scalars(shares_a).unwrap();
        let b = ark_to_icicle_scalars(shares_b).unwrap();

        Self::DeviceShares { a, b }
    }

    fn local_mul_vec<B: ArkIcicleBridge<IcicleScalarField = F>>(
        a: &Self::DeviceShares,
        b: &Self::DeviceShares,
        state: &mut Self::State,
        stream: &IcicleStream,
    ) -> DeviceVec<F> {
        let masking_fes = state
            .rngs
            .rand
            .masking_field_elements_vec::<B::ArkScalarField>(a.a.len());
        let masking_fes = from_host_slice(&masking_fes);
        let masking_fes: DeviceVec<F> =
            ark_to_icicle_scalars::<B::ArkScalarField, F>(masking_fes).unwrap();

        let mut tmp0 = DeviceVec::device_malloc_async(a.a.len(), stream)
            .expect("Failed to allocate device vector");
        let mut tmp1 = DeviceVec::device_malloc_async(a.b.len(), stream)
            .expect("Failed to allocate device vector");
        let mut tmp2 = DeviceVec::device_malloc_async(a.b.len(), stream)
            .expect("Failed to allocate device vector");

        let mut cfg = VecOpsConfig::default();
        cfg.stream_handle = **stream;
        cfg.is_async = true;
        mul_scalars(&a.a, &b.a, tmp0.as_mut_slice(), &cfg).unwrap();
        mul_scalars(&a.a, &b.b, tmp1.as_mut_slice(), &cfg).unwrap();
        mul_scalars(&a.b, &b.a, tmp2.as_mut_slice(), &cfg).unwrap();

        let mut result = DeviceVec::device_malloc_async(a.b.len(), stream)
            .expect("Failed to allocate device vector");

        add_scalars(&tmp0, &tmp1, result.as_mut_slice(), &cfg).unwrap();
        add_scalars(&tmp2, &result, tmp0.as_mut_slice(), &cfg).unwrap();
        add_scalars(&tmp0, &masking_fes, result.as_mut_slice(), &cfg).unwrap();

        result
    }

    fn local_mul<B: ArkIcicleBridge<IcicleScalarField = F>>(
        a: &Self::ArithmeticShare,
        b: &Self::ArithmeticShare,
        state: &mut Self::State,
    ) -> F {
        let masking_fe = state.rngs.rand.masking_field_element::<B::ArkScalarField>();
        let masking_fe = ark_to_icicle_scalar(masking_fe);
        a.a * b.a + a.a * b.b + a.b * b.a + masking_fe
    }

    fn rand<N: Network, B: ArkIcicleBridge<IcicleScalarField = F>>(
        _: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Self::ArithmeticShare> {
        let res = arithmetic::rand::<B::ArkScalarField>(state);
        Ok(Self::ArithmeticShare {
            a: ark_to_icicle_scalar(res.a),
            b: ark_to_icicle_scalar(res.b),
        })
    }

    fn open_half_point_g1<N: Network, B: ArkIcicleBridge<IcicleScalarField = F>>(
        a: Affine<B::IcicleG1>,
        net: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Affine<B::IcicleG1>> {
        let ark_a = B::icicle_to_ark_g1(a);
        let open_a = pointshare::open_half_point(ark_a.into(), net)?.into_affine();
        Ok(ark_to_icicle_affine(&open_a))
    }

    fn open_half_point_g2<N: Network, B: ArkIcicleBridge<IcicleScalarField = F>>(
        a: Affine<B::IcicleG2>,
        net: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Affine<B::IcicleG2>> {
        let ark_a = B::icicle_to_ark_g2(a);
        let open_a = pointshare::open_half_point(ark_a.into(), net)?.into_affine();
        Ok(ark_to_icicle_affine(&open_a))
    }

    fn scalar_mul_g1<N: Network, B: ArkIcicleBridge<IcicleScalarField = F>>(
        a: &Affine<B::IcicleG1>,
        b: Self::ArithmeticShare,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Affine<B::IcicleG1>> {
        let ark_a = B::icicle_to_ark_g1(*a);
        let a_hs = net.reshare(ark_a)?;
        let point = Rep3PointShare::new(ark_a.into(), a_hs.into());
        let res = pointshare::scalar_mul_local(
            &point,
            Rep3PrimeFieldShare {
                a: icicle_to_ark_scalar(b.a),
                b: icicle_to_ark_scalar(b.b),
            },
            state,
        )
        .into_affine();
        Ok(ark_to_icicle_affine(&res))
    }
}
