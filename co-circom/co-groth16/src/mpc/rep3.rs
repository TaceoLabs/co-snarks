use std::marker::PhantomData;
use std::sync::Arc;

use ark_bn254::{
    Bn254, Fq, Fq2, Fr, G1Affine as ArkAffine, G1Projective as ArkProjective,
    G2Projective as ArkG2Projective,
};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ec::{AffineRepr, VariableBaseMSM};
use ark_ff::{BigInteger, Field, PrimeField};
use icicle_bn254::curve::{G1Projective, G2Projective, ScalarField};
use icicle_core::curve::Curve;
use icicle_core::{
    ntt::{self, ntt, ntt_inplace, NTTConfig},
    traits::{FieldImpl, MontgomeryConvertible},
};
use icicle_runtime::{
    self,
    memory::{DeviceVec, HostOrDeviceSlice},
};
use icicle_runtime::{memory::HostSlice, stream::IcicleStream};
use mpc_core::protocols::rep3::{
    arithmetic,
    id::PartyID,
    network::{IoContext, Rep3Network},
    pointshare, Rep3PointShare, Rep3PrimeFieldShare,
};

use icicle_bn254::curve::{
    G1Affine as IcicleAffine, G1Projective as IcicleProjective, G2Affine as IcicleG2Affine,
    G2Projective as IcicleG2Projective, ScalarField as IcicleScalar,
};
use icicle_core::msm::{msm, MSMConfig};
use rayon::prelude::*;

use super::{CircomGroth16Prover, FftHandle, IoResult, MsmHandle};

fn transmute_ark_to_icicle_scalars<T, I>(ark_scalars: &mut [T]) -> &mut [I]
where
    T: PrimeField,
    I: FieldImpl + MontgomeryConvertible,
{
    // SAFETY: Reinterpreting Arkworks field elements as Icicle-specific scalars
    let icicle_scalars = unsafe { &mut *(ark_scalars as *mut _ as *mut [I]) };

    let icicle_host_slice = HostSlice::from_mut_slice(&mut icicle_scalars[..]);

    // Convert from Montgomery representation using the Icicle type's conversion method
    I::from_mont(icicle_host_slice, &IcicleStream::default());

    icicle_scalars
}

fn from_ark<T, I>(ark: &T) -> I
where
    T: Field,
    I: FieldImpl,
{
    let mut ark_bytes = vec![];
    for base_elem in ark.to_base_prime_field_elements() {
        ark_bytes.extend_from_slice(&base_elem.into_bigint().to_bytes_le());
    }
    I::from_bytes_le(&ark_bytes)
}

fn to_ark<T, I>(icicle: &I) -> T
where
    T: Field,
    I: FieldImpl,
{
    T::from_random_bytes(&icicle.to_bytes_le()).unwrap()
}

fn ark_to_icicle_affine_points(ark_affine: &[ArkAffine]) -> Vec<IcicleAffine> {
    ark_affine
        .par_iter()
        .map(|ark| IcicleAffine {
            x: from_ark(&ark.x),
            y: from_ark(&ark.y),
        })
        .collect()
}

fn ark_to_icicle_affine_points_g1(ark_affine: &[impl AffineRepr]) -> Vec<IcicleAffine> {
    ark_affine
        .par_iter()
        .map(|ark| IcicleAffine {
            x: from_ark(&ark.x().unwrap_or_default()),
            y: from_ark(&ark.y().unwrap_or_default()),
        })
        .collect()
}

fn ark_to_icicle_affine_points_g2(ark_affine: &[impl AffineRepr]) -> Vec<IcicleG2Affine> {
    ark_affine
        .par_iter()
        .map(|ark| IcicleG2Affine {
            x: from_ark(&ark.x().unwrap_or_default()),
            y: from_ark(&ark.y().unwrap_or_default()),
        })
        .collect()
}

fn ark_to_icicle_projective_points(ark_projective: &[ArkProjective]) -> Vec<IcicleProjective> {
    ark_projective
        .par_iter()
        .map(|ark| {
            let proj_x = ark.x * ark.z;
            let proj_z = ark.z * ark.z * ark.z;
            IcicleProjective {
                x: from_ark(&proj_x),
                y: from_ark(&ark.y),
                z: from_ark(&proj_z),
            }
        })
        .collect()
}

#[allow(unused)]
fn icicle_to_ark_affine_points(icicle_projective: &[IcicleAffine]) -> Vec<ArkAffine> {
    icicle_projective
        .par_iter()
        .map(|icicle| ArkAffine::new_unchecked(to_ark(&icicle.x), to_ark(&icicle.y)))
        .collect()
}

pub trait IcileToArkProjective
where
    Self: Pairing,
{
    fn convert(value: &IcicleProjective) -> Self::G1;
    fn convert_g2(value: &IcicleG2Projective) -> Self::G2;
}

impl IcileToArkProjective for Bn254 {
    fn convert(value: &IcicleProjective) -> Self::G1 {
        let proj_x: Fq = to_ark(&value.x);
        let proj_y: Fq = to_ark(&value.y);
        let proj_z: Fq = to_ark(&value.z);

        // conversion between projective used in icicle and Jacobian used in arkworks
        let proj_x = proj_x * proj_z;
        let proj_y = proj_y * proj_z * proj_z;
        ArkProjective::new_unchecked(proj_x, proj_y, proj_z)
    }

    fn convert_g2(value: &IcicleG2Projective) -> Self::G2 {
        let proj_x: Fq2 = to_ark(&value.x);
        let proj_y: Fq2 = to_ark(&value.y);
        let proj_z: Fq2 = to_ark(&value.z);

        // conversion between projective used in icicle and Jacobian used in arkworks
        let proj_x = proj_x * proj_z;
        let proj_y = proj_y * proj_z * proj_z;
        ArkG2Projective::new_unchecked(proj_x, proj_y, proj_z)
    }
}

fn icicle_to_ark_projective_points(icicle_projective: &[IcicleProjective]) -> Vec<ArkProjective> {
    icicle_projective
        .par_iter()
        .map(|icicle| {
            let proj_x: Fq = to_ark(&icicle.x);
            let proj_y: Fq = to_ark(&icicle.y);
            let proj_z: Fq = to_ark(&icicle.z);

            // conversion between projective used in icicle and Jacobian used in arkworks
            let proj_x = proj_x * proj_z;
            let proj_y = proj_y * proj_z * proj_z;
            ArkProjective::new_unchecked(proj_x, proj_y, proj_z)
        })
        .collect()
}

fn icicle_to_ark_projective_points_g1<P: Pairing + IcileToArkProjective>(
    icicle_projective: &[IcicleProjective],
) -> Vec<P::G1> {
    icicle_projective
        .par_iter()
        .map(|icicle| <P as IcileToArkProjective>::convert(icicle))
        .collect()
}

fn icicle_to_ark_projective_points_g2<P: Pairing + IcileToArkProjective>(
    icicle_projective: &[IcicleG2Projective],
) -> Vec<P::G2> {
    icicle_projective
        .par_iter()
        .map(|icicle| <P as IcileToArkProjective>::convert_g2(icicle))
        .collect()
}

fn ark_to_icicle_scalars_async<T, I>(ark_scalars: &[T], stream: &IcicleStream) -> DeviceVec<I>
where
    T: PrimeField,
    I: FieldImpl + MontgomeryConvertible,
{
    // SAFETY: Reinterpreting Arkworks field elements as Icicle-specific scalars
    let icicle_scalars = unsafe { &*(ark_scalars as *const _ as *const [I]) };

    // Create a HostSlice from the mutable slice
    let icicle_host_slice = HostSlice::from_slice(&icicle_scalars[..]);

    let mut icicle_scalars =
        DeviceVec::<I>::device_malloc_async(ark_scalars.len(), &stream).unwrap();
    icicle_scalars
        .copy_from_host_async(&icicle_host_slice, &stream)
        .unwrap();

    // Convert from Montgomery representation using the Icicle type's conversion method
    I::from_mont(&mut icicle_scalars, &stream);
    icicle_scalars
}

pub struct Rep3FftHandle<P, T, I> {
    a_results: DeviceVec<I>,
    b_results: DeviceVec<I>,
    a_stream: IcicleStream,
    b_stream: IcicleStream,
    phantom0: PhantomData<T>,
    phantom1: PhantomData<P>,
}

impl<P: Pairing, T: Field, I: FieldImpl> FftHandle<P, Vec<Rep3PrimeFieldShare<P::ScalarField>>>
    for Rep3FftHandle<P, T, I>
{
    fn join(mut self) -> Vec<Rep3PrimeFieldShare<P::ScalarField>> {
        let span = tracing::debug_span!("(i)fft_async join").entered();
        self.a_stream.synchronize().unwrap();
        let mut a_host_result = vec![I::zero(); self.a_results.len()];
        self.a_results
            .copy_to_host(HostSlice::from_mut_slice(&mut a_host_result[..]))
            .unwrap();
        self.b_stream.synchronize().unwrap();
        let mut b_host_result = vec![I::zero(); self.b_results.len()];
        self.b_results
            .copy_to_host(HostSlice::from_mut_slice(&mut b_host_result[..]))
            .unwrap();
        self.a_stream.destroy().unwrap();
        self.b_stream.destroy().unwrap();
        let res = a_host_result
            .into_iter()
            .zip(b_host_result)
            .map(|(a, b)| Rep3PrimeFieldShare {
                a: to_ark(&a),
                b: to_ark(&b),
            })
            .collect();
        span.exit();
        res
    }
}

pub struct Rep3MsmHandle {
    a_results: DeviceVec<G1Projective>,
    b_results: DeviceVec<G1Projective>,
    a_stream: IcicleStream,
    b_stream: IcicleStream,
}

impl MsmHandle<Rep3PointShare<ArkProjective>> for Rep3MsmHandle {
    fn join(mut self) -> Rep3PointShare<ArkProjective> {
        self.a_stream.synchronize().unwrap();
        let mut a_host_result = vec![G1Projective::zero(); self.a_results.len()];
        self.a_results
            .copy_to_host(HostSlice::from_mut_slice(&mut a_host_result[..]))
            .unwrap();
        self.b_stream.synchronize().unwrap();
        let mut b_host_result = vec![G1Projective::zero(); self.b_results.len()];
        self.b_results
            .copy_to_host(HostSlice::from_mut_slice(&mut b_host_result[..]))
            .unwrap();
        self.a_stream.destroy().unwrap();
        self.b_stream.destroy().unwrap();

        let a = icicle_to_ark_projective_points(&a_host_result);
        let b = icicle_to_ark_projective_points(&b_host_result);

        Rep3PointShare { a: a[0], b: b[0] }
    }
}

/// A Groth16 driver for REP3 secret sharing
///
/// Contains two [`IoContext`]s, `io_context0` for the main execution and `io_context1` for parts that can run concurrently.
pub struct Rep3Groth16Driver<N: Rep3Network> {
    io_context0: IoContext<N>,
    io_context1: IoContext<N>,
}

impl<N: Rep3Network> Rep3Groth16Driver<N> {
    /// Create a new [`Rep3Groth16Driver`] with two [`IoContext`]s
    pub fn new(io_context0: IoContext<N>, io_context1: IoContext<N>) -> Self {
        Self {
            io_context0,
            io_context1,
        }
    }

    /// Get the underlying network
    pub fn get_network(self) -> N {
        self.io_context0.network
    }
}

impl<P: Pairing + IcileToArkProjective, N: Rep3Network> CircomGroth16Prover<P>
    for Rep3Groth16Driver<N>
{
    type ArithmeticShare = Rep3PrimeFieldShare<P::ScalarField>;
    type PointShare<C>
        = Rep3PointShare<C>
    where
        C: CurveGroup;
    type PartyID = PartyID;
    type FftHandle = Rep3FftHandle<P, P::ScalarField, ScalarField>;
    type MsmHandle = Rep3MsmHandle;

    fn rand(&mut self) -> IoResult<Self::ArithmeticShare> {
        Ok(Self::ArithmeticShare::rand(&mut self.io_context0))
    }

    fn get_party_id(&self) -> Self::PartyID {
        self.io_context0.id
    }

    fn fft(coeffs: Vec<Self::ArithmeticShare>) -> Vec<Self::ArithmeticShare> {
        let ntt_config = NTTConfig::<ScalarField>::default();
        let (mut a_inout, mut b_inout) = coeffs
            .into_iter()
            .map(|x| (x.a, x.b))
            .collect::<(Vec<_>, Vec<_>)>();
        let a_inout = transmute_ark_to_icicle_scalars(&mut a_inout);
        let b_inout = transmute_ark_to_icicle_scalars(&mut b_inout);
        ntt_inplace(
            HostSlice::from_mut_slice(a_inout),
            ntt::NTTDir::kForward,
            &ntt_config,
        )
        .expect("NTT computation failed on GPU");
        ntt_inplace(
            HostSlice::from_mut_slice(b_inout),
            ntt::NTTDir::kForward,
            &ntt_config,
        )
        .expect("NTT computation failed on GPU");
        a_inout
            .iter()
            .zip(b_inout)
            .map(|(a, b)| {
                Rep3PrimeFieldShare::new(
                    P::ScalarField::from_random_bytes(&a.to_bytes_le()).unwrap(),
                    P::ScalarField::from_random_bytes(&b.to_bytes_le()).unwrap(),
                )
            })
            .collect::<Vec<_>>()
    }

    fn fft_async(
        coeffs: Vec<Self::ArithmeticShare>,
    ) -> Rep3FftHandle<P, P::ScalarField, ScalarField> {
        let span = tracing::debug_span!("fft_async setup").entered();
        let (mut a_input, mut b_input) = coeffs
            .into_iter()
            .map(|x| (x.a, x.b))
            .collect::<(Vec<_>, Vec<_>)>();
        let a_input = transmute_ark_to_icicle_scalars(&mut a_input);
        let b_input = transmute_ark_to_icicle_scalars(&mut b_input);

        let a_stream = IcicleStream::create().unwrap();
        let mut a_ntt_config = NTTConfig::<ScalarField>::default();
        a_ntt_config.is_async = true;
        a_ntt_config.stream_handle = *a_stream;
        let mut a_results = DeviceVec::<ScalarField>::device_malloc(a_input.len()).unwrap();

        let b_stream = IcicleStream::create().unwrap();
        let mut b_ntt_config = NTTConfig::<ScalarField>::default();
        b_ntt_config.is_async = true;
        b_ntt_config.stream_handle = *b_stream;
        let mut b_results = DeviceVec::<ScalarField>::device_malloc(b_input.len()).unwrap();

        span.exit();

        ntt(
            HostSlice::from_slice(a_input),
            ntt::NTTDir::kForward,
            &a_ntt_config,
            &mut a_results[..],
        )
        .expect("NTT computation failed on GPU");

        ntt(
            HostSlice::from_slice(b_input),
            ntt::NTTDir::kForward,
            &b_ntt_config,
            &mut b_results[..],
        )
        .expect("NTT computation failed on GPU");

        Rep3FftHandle {
            a_results,
            b_results,
            a_stream,
            b_stream,
            phantom0: PhantomData,
            phantom1: PhantomData,
        }
    }

    fn fft_half_share(mut coeffs: Vec<P::ScalarField>) -> Vec<<P as Pairing>::ScalarField> {
        let ntt_config = NTTConfig::<ScalarField>::default();
        let inout = transmute_ark_to_icicle_scalars(&mut coeffs);
        ntt_inplace(
            HostSlice::from_mut_slice(inout),
            ntt::NTTDir::kForward,
            &ntt_config,
        )
        .expect("NTT computation failed on GPU");
        inout
            .iter()
            .map(|a| P::ScalarField::from_random_bytes(&a.to_bytes_le()).unwrap())
            .collect::<Vec<_>>()
    }

    // fn fft_half_share_async(
    //     mut coeffs: Vec<P::ScalarField>,
    // ) -> FftHandle<P::ScalarField, ScalarField> {
    //     let stream = IcicleStream::create().unwrap();
    //     let mut ntt_config = NTTConfig::<ScalarField>::default();
    //     ntt_config.is_async = true;
    //     ntt_config.stream_handle = *stream;
    //     let mut results = DeviceVec::<ScalarField>::device_malloc(coeffs.len()).unwrap();
    //     let input = transmute_ark_to_icicle_scalars(&mut coeffs);
    //     ntt(
    //         HostSlice::from_mut_slice(input),
    //         ntt::NTTDir::kForward,
    //         &ntt_config,
    //         &mut results[..],
    //     )
    //     .expect("NTT computation failed on GPU");
    //     FftHandle {
    //         results,
    //         stream,
    //         phantom: PhantomData,
    //     }
    // }

    fn ifft(evals: Vec<Self::ArithmeticShare>) -> Vec<Self::ArithmeticShare> {
        let ntt_config = NTTConfig::<ScalarField>::default();
        let (mut a_inout, mut b_inout) = evals
            .into_iter()
            .map(|x| (x.a, x.b))
            .collect::<(Vec<_>, Vec<_>)>();
        let a_inout = transmute_ark_to_icicle_scalars(&mut a_inout);
        let b_inout = transmute_ark_to_icicle_scalars(&mut b_inout);
        ntt_inplace(
            HostSlice::from_mut_slice(a_inout),
            ntt::NTTDir::kInverse,
            &ntt_config,
        )
        .expect("NTT computation failed on GPU");
        ntt_inplace(
            HostSlice::from_mut_slice(b_inout),
            ntt::NTTDir::kInverse,
            &ntt_config,
        )
        .expect("NTT computation failed on GPU");
        a_inout
            .iter()
            .zip(b_inout)
            .map(|(a, b)| {
                Rep3PrimeFieldShare::new(
                    P::ScalarField::from_random_bytes(&a.to_bytes_le()).unwrap(),
                    P::ScalarField::from_random_bytes(&b.to_bytes_le()).unwrap(),
                )
            })
            .collect::<Vec<_>>()
    }

    fn ifft_async(
        coeffs: Vec<Self::ArithmeticShare>,
    ) -> Rep3FftHandle<P, P::ScalarField, ScalarField> {
        let span = tracing::debug_span!("ifft_async setup").entered();
        let (mut a_input, mut b_input) = coeffs
            .into_iter()
            .map(|x| (x.a, x.b))
            .collect::<(Vec<_>, Vec<_>)>();
        let a_input = transmute_ark_to_icicle_scalars(&mut a_input);
        let b_input = transmute_ark_to_icicle_scalars(&mut b_input);

        let a_stream = IcicleStream::create().unwrap();
        let mut a_ntt_config = NTTConfig::<ScalarField>::default();
        a_ntt_config.is_async = true;
        a_ntt_config.stream_handle = *a_stream;
        let mut a_results = DeviceVec::<ScalarField>::device_malloc(a_input.len()).unwrap();

        let b_stream = IcicleStream::create().unwrap();
        let mut b_ntt_config = NTTConfig::<ScalarField>::default();
        b_ntt_config.is_async = true;
        b_ntt_config.stream_handle = *b_stream;
        let mut b_results = DeviceVec::<ScalarField>::device_malloc(b_input.len()).unwrap();
        span.exit();

        ntt(
            HostSlice::from_slice(a_input),
            ntt::NTTDir::kInverse,
            &a_ntt_config,
            &mut a_results[..],
        )
        .expect("NTT computation failed on GPU");

        ntt(
            HostSlice::from_slice(b_input),
            ntt::NTTDir::kInverse,
            &b_ntt_config,
            &mut b_results[..],
        )
        .expect("NTT computation failed on GPU");

        Rep3FftHandle {
            a_results,
            b_results,
            a_stream,
            b_stream,
            phantom0: PhantomData,
            phantom1: PhantomData,
        }
    }

    fn ifft_half_share(mut coeffs: Vec<P::ScalarField>) -> Vec<<P as Pairing>::ScalarField> {
        let ntt_config = NTTConfig::<ScalarField>::default();
        let inout = transmute_ark_to_icicle_scalars(&mut coeffs);
        ntt_inplace(
            HostSlice::from_mut_slice(inout),
            ntt::NTTDir::kInverse,
            &ntt_config,
        )
        .expect("NTT computation failed on GPU");
        inout
            .iter()
            .map(|a| P::ScalarField::from_random_bytes(&a.to_bytes_le()).unwrap())
            .collect::<Vec<_>>()
    }

    fn msm_async(points: &[ArkAffine], scalars: &[Self::ArithmeticShare]) -> Self::MsmHandle {
        debug_assert_eq!(points.len(), scalars.len());
        let (mut a, mut b) = scalars
            .into_par_iter()
            .with_min_len(1 << 14)
            .map(|share| (share.a, share.b))
            .collect::<(Vec<_>, Vec<_>)>();
        let points = ark_to_icicle_affine_points(points);
        let a = transmute_ark_to_icicle_scalars(&mut a);
        let b = transmute_ark_to_icicle_scalars(&mut b);

        let a_stream = IcicleStream::create().unwrap();
        let mut a_msm_config = MSMConfig::default();
        a_msm_config.is_async = true;
        a_msm_config.stream_handle = *a_stream;
        let mut a_results = DeviceVec::<G1Projective>::device_malloc(1).unwrap();

        let b_stream = IcicleStream::create().unwrap();
        let mut b_msm_config = MSMConfig::default();
        b_msm_config.is_async = true;
        b_msm_config.stream_handle = *b_stream;
        let mut b_results = DeviceVec::<G1Projective>::device_malloc(1).unwrap();

        msm(
            HostSlice::from_slice(a),
            HostSlice::from_slice(&points),
            &a_msm_config,
            &mut a_results[..],
        )
        .unwrap();

        msm(
            HostSlice::from_slice(b),
            HostSlice::from_slice(&points),
            &b_msm_config,
            &mut b_results[..],
        )
        .unwrap();

        Rep3MsmHandle {
            a_results,
            b_results,
            a_stream,
            b_stream,
        }
    }

    fn msm_g1(
        points: &[P::G1Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShare<P::G1> {
        let span = tracing::debug_span!("msm_g1 setup").entered();
        let min = points.len().min(scalars.len());
        let points = &points[..min];
        let scalars = &scalars[..min];
        debug_assert_eq!(points.len(), scalars.len());
        let (a, b) = scalars
            .into_par_iter()
            .with_min_len(1 << 14)
            .map(|share| (share.a, share.b))
            .collect::<(Vec<_>, Vec<_>)>();
        let points = ark_to_icicle_affine_points_g1(points);

        let mut a_stream = IcicleStream::create().unwrap();
        let mut a_msm_config = MSMConfig::default();
        a_msm_config.is_async = true;
        a_msm_config.stream_handle = *a_stream;
        let mut a_results = DeviceVec::<G1Projective>::device_malloc(1).unwrap();

        let mut b_stream = IcicleStream::create().unwrap();
        let mut b_msm_config = MSMConfig::default();
        b_msm_config.is_async = true;
        b_msm_config.stream_handle = *b_stream;
        let mut b_results = DeviceVec::<G1Projective>::device_malloc(1).unwrap();

        let a_dev: DeviceVec<ScalarField> = ark_to_icicle_scalars_async(&a, &a_stream);
        let b_dev: DeviceVec<ScalarField> = ark_to_icicle_scalars_async(&b, &b_stream);
        let mut points_dev = DeviceVec::<IcicleAffine>::device_malloc(points.len()).unwrap();
        points_dev
            .copy_from_host(HostSlice::from_slice(&points))
            .unwrap();

        a_stream.synchronize().unwrap();
        b_stream.synchronize().unwrap();

        span.exit();

        let span = tracing::debug_span!("msm_g1 compute").entered();

        msm(&a_dev, &points_dev, &a_msm_config, &mut a_results[..]).unwrap();

        msm(&b_dev, &points_dev, &b_msm_config, &mut b_results[..]).unwrap();

        a_stream.synchronize().unwrap();
        b_stream.synchronize().unwrap();

        span.exit();

        let span = tracing::debug_span!("msm_g1 conv and copy back").entered();
        let mut a_host_result = vec![G1Projective::zero(); a_results.len()];
        a_results
            .copy_to_host_async(HostSlice::from_mut_slice(&mut a_host_result[..]), &a_stream)
            .unwrap();
        b_stream.synchronize().unwrap();
        let mut b_host_result = vec![G1Projective::zero(); b_results.len()];
        b_results
            .copy_to_host_async(HostSlice::from_mut_slice(&mut b_host_result[..]), &b_stream)
            .unwrap();

        a_stream.synchronize().unwrap();
        b_stream.synchronize().unwrap();
        a_stream.destroy().unwrap();
        b_stream.destroy().unwrap();

        let a = icicle_to_ark_projective_points_g1::<P>(&a_host_result);
        let b = icicle_to_ark_projective_points_g1::<P>(&b_host_result);

        span.exit();

        Rep3PointShare { a: a[0], b: b[0] }
    }

    fn msm_g1_public(points: &[P::G1Affine], scalars: &[P::ScalarField]) -> P::G1 {
        let min = points.len().min(scalars.len());
        let points = &points[..min];
        let scalars = &scalars[..min];
        let span = tracing::debug_span!("msm_g1_public setup").entered();
        debug_assert_eq!(points.len(), scalars.len());
        let points = ark_to_icicle_affine_points_g1(points);

        let scalars_dev: DeviceVec<ScalarField> =
            ark_to_icicle_scalars_async(scalars, &IcicleStream::default());
        let mut points_dev = DeviceVec::<IcicleAffine>::device_malloc(points.len()).unwrap();
        points_dev
            .copy_from_host(HostSlice::from_slice(&points))
            .unwrap();

        let mut results = DeviceVec::<G1Projective>::device_malloc(1).unwrap();

        span.exit();

        let span = tracing::debug_span!("msm_g1_public compute").entered();

        msm(
            &scalars_dev,
            &points_dev,
            &MSMConfig::default(),
            &mut results[..],
        )
        .unwrap();

        span.exit();

        let span = tracing::debug_span!("msm_g1_public conv and copy back").entered();

        let mut host_result = vec![G1Projective::zero(); 1];
        results
            .copy_to_host(HostSlice::from_mut_slice(&mut host_result[..]))
            .unwrap();

        let a = icicle_to_ark_projective_points_g1::<P>(&host_result);

        span.exit();

        a[0]
    }

    fn msm_g2(
        points: &[P::G2Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShare<P::G2> {
        let span = tracing::debug_span!("msm_g2 setup").entered();
        let min = points.len().min(scalars.len());
        let points = &points[..min];
        let scalars = &scalars[..min];
        debug_assert_eq!(points.len(), scalars.len());
        let (a, b) = scalars
            .into_par_iter()
            .with_min_len(1 << 14)
            .map(|share| (share.a, share.b))
            .collect::<(Vec<_>, Vec<_>)>();
        let points = ark_to_icicle_affine_points_g2(points);

        let mut a_stream = IcicleStream::create().unwrap();
        let mut a_msm_config = MSMConfig::default();
        a_msm_config.is_async = true;
        a_msm_config.stream_handle = *a_stream;
        let mut a_results = DeviceVec::<G2Projective>::device_malloc(1).unwrap();

        let mut b_stream = IcicleStream::create().unwrap();
        let mut b_msm_config = MSMConfig::default();
        b_msm_config.is_async = true;
        b_msm_config.stream_handle = *b_stream;
        let mut b_results = DeviceVec::<G2Projective>::device_malloc(1).unwrap();

        let a_dev: DeviceVec<ScalarField> = ark_to_icicle_scalars_async(&a, &a_stream);
        let b_dev: DeviceVec<ScalarField> = ark_to_icicle_scalars_async(&b, &b_stream);
        let mut points_dev = DeviceVec::<IcicleG2Affine>::device_malloc(points.len()).unwrap();
        points_dev
            .copy_from_host(HostSlice::from_slice(&points))
            .unwrap();

        a_stream.synchronize().unwrap();
        b_stream.synchronize().unwrap();

        span.exit();

        let span = tracing::debug_span!("msm_g2 compute").entered();

        msm(&a_dev, &points_dev, &a_msm_config, &mut a_results[..]).unwrap();

        msm(&b_dev, &points_dev, &b_msm_config, &mut b_results[..]).unwrap();

        a_stream.synchronize().unwrap();
        b_stream.synchronize().unwrap();

        span.exit();

        let span = tracing::debug_span!("msm_g2 conv and copy back").entered();
        let mut a_host_result = vec![G2Projective::zero(); a_results.len()];
        a_results
            .copy_to_host_async(HostSlice::from_mut_slice(&mut a_host_result[..]), &a_stream)
            .unwrap();
        b_stream.synchronize().unwrap();
        let mut b_host_result = vec![G2Projective::zero(); b_results.len()];
        b_results
            .copy_to_host_async(HostSlice::from_mut_slice(&mut b_host_result[..]), &b_stream)
            .unwrap();

        a_stream.synchronize().unwrap();
        b_stream.synchronize().unwrap();
        a_stream.destroy().unwrap();
        b_stream.destroy().unwrap();

        let a = icicle_to_ark_projective_points_g2::<P>(&a_host_result);
        let b = icicle_to_ark_projective_points_g2::<P>(&b_host_result);

        span.exit();

        Rep3PointShare { a: a[0], b: b[0] }
    }

    fn evaluate_constraint(
        party_id: Self::PartyID,
        lhs: &[(P::ScalarField, usize)],
        public_inputs: &[P::ScalarField],
        private_witness: &[Self::ArithmeticShare],
    ) -> Self::ArithmeticShare {
        let mut acc = Self::ArithmeticShare::default();
        for (coeff, index) in lhs {
            if index < &public_inputs.len() {
                let val = public_inputs[*index];
                let mul_result = val * coeff;
                arithmetic::add_assign_public(&mut acc, mul_result, party_id);
            } else {
                let current_witness = private_witness[*index - public_inputs.len()];
                arithmetic::add_assign(&mut acc, arithmetic::mul_public(current_witness, *coeff));
            }
        }
        acc
    }

    fn promote_to_trivial_shares(
        id: Self::PartyID,
        public_values: &[P::ScalarField],
    ) -> Vec<Self::ArithmeticShare> {
        public_values
            .par_iter()
            .with_min_len(1024)
            .map(|value| Self::ArithmeticShare::promote_from_trivial(value, id))
            .collect()
    }

    fn local_mul_vec(
        &mut self,
        a: Vec<Self::ArithmeticShare>,
        b: Vec<Self::ArithmeticShare>,
    ) -> Vec<P::ScalarField> {
        arithmetic::local_mul_vec(&a, &b, &mut self.io_context0.rngs)
    }

    fn mul(
        &mut self,
        r: Self::ArithmeticShare,
        s: Self::ArithmeticShare,
    ) -> IoResult<Self::ArithmeticShare> {
        arithmetic::mul(r, s, &mut self.io_context1)
    }

    fn distribute_powers_and_mul_by_const(
        coeffs: &mut [Self::ArithmeticShare],
        roots: &[P::ScalarField],
    ) {
        coeffs
            .par_iter_mut()
            .zip_eq(roots.par_iter())
            .with_min_len(512)
            .for_each(|(c, pow)| {
                arithmetic::mul_assign_public(c, *pow);
            })
    }

    fn msm_public_points<C>(
        points: &[C::Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShare<C>
    where
        C: CurveGroup<ScalarField = P::ScalarField>,
    {
        pointshare::msm_public_points(points, scalars)
    }

    fn scalar_mul_public_point<C>(a: &C, b: Self::ArithmeticShare) -> Self::PointShare<C>
    where
        C: CurveGroup<ScalarField = P::ScalarField>,
    {
        pointshare::scalar_mul_public_point(a, b)
    }

    /// Add a shared point B in place to the shared point A: \[A\] += \[B\]
    fn add_assign_points<C: CurveGroup>(a: &mut Self::PointShare<C>, b: &Self::PointShare<C>) {
        pointshare::add_assign(a, b)
    }

    fn add_points_half_share<C: CurveGroup>(a: Self::PointShare<C>, b: &C) -> C {
        let (a, _) = a.ab();
        a + b
    }

    fn add_assign_points_public<C: CurveGroup>(
        id: Self::PartyID,
        a: &mut Self::PointShare<C>,
        b: &C,
    ) {
        pointshare::add_assign_public(a, b, id)
    }

    fn open_point<C>(&mut self, a: &Self::PointShare<C>) -> IoResult<C>
    where
        C: CurveGroup<ScalarField = P::ScalarField>,
    {
        pointshare::open_point(a, &mut self.io_context0)
    }

    fn scalar_mul<C>(
        &mut self,
        a: &Self::PointShare<C>,
        b: Self::ArithmeticShare,
    ) -> IoResult<Self::PointShare<C>>
    where
        C: CurveGroup<ScalarField = P::ScalarField>,
    {
        pointshare::scalar_mul(a, b, &mut self.io_context0)
    }

    fn sub_assign_points<C: CurveGroup>(a: &mut Self::PointShare<C>, b: &Self::PointShare<C>) {
        pointshare::sub_assign(a, b);
    }

    fn open_two_points(
        &mut self,
        a: P::G1,
        b: Self::PointShare<P::G2>,
    ) -> std::io::Result<(P::G1, P::G2)> {
        let mut s1 = a;
        let s2 = b.b;
        let (r1, r2) = std::thread::scope(|s| {
            let r1 = s.spawn(|| self.io_context0.network.broadcast(s1));
            let r2 = s.spawn(|| self.io_context1.network.reshare(s2));
            (r1.join().expect("can join"), r2.join().expect("can join"))
        });
        let (r1b, r1c) = r1?;
        let mut r2 = r2?;
        s1 += r1b + r1c;
        r2 += b.a + b.b;
        Ok((s1, r2))
    }

    fn open_point_and_scalar_mul(
        &mut self,
        g_a: &Self::PointShare<P::G1>,
        g1_b: &Self::PointShare<P::G1>,
        r: Self::ArithmeticShare,
    ) -> std::io::Result<(<P as Pairing>::G1, Self::PointShare<P::G1>)> {
        std::thread::scope(|s| {
            let opened = s.spawn(|| pointshare::open_point(g_a, &mut self.io_context0));
            let mul_result = pointshare::scalar_mul(g1_b, r, &mut self.io_context1)?;
            Ok((opened.join().expect("can join")?, mul_result))
        })
    }
}
