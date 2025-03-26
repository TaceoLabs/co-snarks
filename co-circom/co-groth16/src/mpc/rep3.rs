use std::marker::PhantomData;

use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::{Field, PrimeField};
use icicle_bn254::curve::ScalarField;
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
use rayon::prelude::*;

use super::{CircomGroth16Prover, FftHandle, IoResult};

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

fn to_ark<T, I>(icicle: &I) -> T
where
    T: Field,
    I: FieldImpl,
{
    T::from_random_bytes(&icicle.to_bytes_le()).unwrap()
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
    fn join(self) -> Vec<Rep3PrimeFieldShare<P::ScalarField>> {
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
        a_host_result
            .into_iter()
            .zip(b_host_result)
            .map(|(a, b)| Rep3PrimeFieldShare {
                a: to_ark(&a),
                b: to_ark(&b),
            })
            .collect()
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

impl<P: Pairing, N: Rep3Network> CircomGroth16Prover<P> for Rep3Groth16Driver<N> {
    type ArithmeticShare = Rep3PrimeFieldShare<P::ScalarField>;
    type PointShare<C>
        = Rep3PointShare<C>
    where
        C: CurveGroup;
    type PartyID = PartyID;
    type FftHandle = Rep3FftHandle<P, P::ScalarField, ScalarField>;

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

        ntt(
            HostSlice::from_mut_slice(a_input),
            ntt::NTTDir::kForward,
            &a_ntt_config,
            &mut a_results[..],
        )
        .expect("NTT computation failed on GPU");

        ntt(
            HostSlice::from_mut_slice(b_input),
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

        ntt(
            HostSlice::from_mut_slice(a_input),
            ntt::NTTDir::kInverse,
            &a_ntt_config,
            &mut a_results[..],
        )
        .expect("NTT computation failed on GPU");

        ntt(
            HostSlice::from_mut_slice(b_input),
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
