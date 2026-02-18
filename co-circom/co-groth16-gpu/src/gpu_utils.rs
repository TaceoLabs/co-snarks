use std::ops::{Index, IndexMut};

use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use ark_poly::GeneralEvaluationDomain;
use co_groth16::root_of_unity_for_groth16;
use icicle_core::curve::Affine;
use icicle_core::vec_ops::VecOps;
use icicle_core::{
    curve::{Curve, Projective},
    msm::{MSM, MSMConfig, msm},
    ntt::{self, NTT, NTTConfig, NTTDir, NTTDomain, ntt_inplace},
    traits::{Arithmetic, FieldImpl, MontgomeryConvertible},
};
use icicle_runtime::{
    memory::{DeviceSlice, DeviceVec, HostOrDeviceSlice, HostSlice},
    stream::IcicleStream,
};

use crate::bridges::{ArkIcicleBridge, ark_to_icicle_affine, ark_to_icicle_scalar};

pub fn from_host_slice<T>(slice: &[T]) -> DeviceVec<T> {
    let count = slice.len();
    let mut result = DeviceVec::device_malloc(count).expect("Failed to allocate device vector");
    result
        .copy_from_host(HostSlice::from_slice(slice))
        .expect("Failed to copy data from host to device");
    result
}

pub fn to_host_vec_ark_scalar<F: PrimeField>(slice: &DeviceSlice<F>) -> Vec<F> {
    let mut host_vec = vec![F::zero(); slice.len()];
    let host_slice = HostSlice::from_mut_slice(&mut host_vec);
    slice.copy_to_host(host_slice).unwrap();
    host_vec
}

pub fn get_first_ark_scalar<F: PrimeField>(vec: &DeviceSlice<F>) -> Option<F> {
    let mut host_vec = to_host_vec_ark_scalar(vec.index(..1));
    host_vec.pop()
}

pub fn to_host_vec_icicle_scalar<F: FieldImpl>(slice: &DeviceSlice<F>) -> Vec<F> {
    let mut host_vec = vec![F::zero(); slice.len()];
    let host_slice = HostSlice::from_mut_slice(&mut host_vec);
    slice.copy_to_host(host_slice).unwrap();
    host_vec
}

pub fn get_first_icicle_scalar<F: FieldImpl>(vec: &DeviceSlice<F>) -> Option<F> {
    let mut host_vec = to_host_vec_icicle_scalar(vec.index(..1));
    host_vec.pop()
}

pub fn to_host_vec_projective<C: Curve>(slice: &DeviceSlice<Projective<C>>) -> Vec<Projective<C>> {
    let mut host_vec = vec![Projective::<C>::zero(); slice.len()];
    let host_slice = HostSlice::from_mut_slice(&mut host_vec);
    slice.copy_to_host(host_slice).unwrap();
    host_vec
}

pub fn to_host_vec_affine<C: Curve>(slice: &DeviceSlice<Affine<C>>) -> Vec<Affine<C>> {
    let mut host_vec = vec![Affine::<C>::zero(); slice.len()];
    let host_slice = HostSlice::from_mut_slice(&mut host_vec);
    slice.copy_to_host(host_slice).unwrap();
    host_vec
}

pub fn get_first_projective<C: Curve>(vec: &DeviceSlice<Projective<C>>) -> Option<Projective<C>> {
    let mut host_vec = to_host_vec_projective(vec.index(..1));
    host_vec.pop()
}

pub fn get_first_affine<C: Curve>(vec: &DeviceSlice<Affine<C>>) -> Option<Affine<C>> {
    let mut host_vec = to_host_vec_affine(vec.index(..1));
    host_vec.pop()
}
pub(crate) struct Proof<
    F: FieldImpl<Config: VecOps<F> + NTT<F, F>>,
    C1: Curve<ScalarField = F>,
    C2: Curve<ScalarField = F>,
> {
    /// The `A` element in `G1`.
    pub a: Affine<C1>,
    /// The `B` element in `G2`.
    pub b: Affine<C2>,
    /// The `C` element in `G1`.
    pub c: Affine<C1>,
}

impl<
    F: FieldImpl<Config: VecOps<F> + NTT<F, F>>,
    C1: Curve<ScalarField = F>,
    C2: Curve<ScalarField = F>,
> Proof<F, C1, C2>
{
    pub(crate) fn to_ark<
        B: ArkIcicleBridge<IcicleG1 = C1, IcicleG2 = C2, IcicleScalarField = F>,
    >(
        &self,
    ) -> ark_groth16::Proof<B::ArkPairing> {
        ark_groth16::Proof {
            a: B::icicle_to_ark_g1(self.a),
            b: B::icicle_to_ark_g2(self.b),
            c: B::icicle_to_ark_g1(self.c),
        }
    }
}

pub(crate) struct VerifyingKey<
    F: FieldImpl<Config: VecOps<F> + NTT<F, F>>,
    C1: Curve<ScalarField = F>,
    C2: Curve<ScalarField = F>,
> {
    /// The `alpha * G`, where `G` is the generator of `E::G1`.
    pub(crate) alpha_g1: Affine<C1>,
    /// The `alpha * H`, where `H` is the generator of `E::G2`.
    pub(crate) beta_g2: Affine<C2>,
    /// The `gamma * H`, where `H` is the generator of `E::G2`.
    pub(crate) gamma_g2: Affine<C2>,
    /// The `delta * H`, where `H` is the generator of `E::G2`.
    pub(crate) delta_g2: Affine<C2>,
    /// The `gamma^{-1} * (beta * a_i + alpha * b_i + c_i) * H`, where `H` is
    /// the generator of `E::G1`.
    pub(crate) gamma_abc_g1: DeviceVec<Affine<C1>>,
}

pub(crate) struct ProvingKey<
    F: FieldImpl<Config: VecOps<F> + NTT<F, F>>,
    C1: Curve<ScalarField = F>,
    C2: Curve<ScalarField = F>,
> {
    /// The underlying verification key.
    pub(crate) vk: VerifyingKey<F, C1, C2>,
    /// The element `beta * G` in `E::G1`.
    pub(crate) beta_g1: Affine<C1>,
    /// The element `delta * G` in `E::G1`.
    pub(crate) delta_g1: Affine<C1>,
    /// The elements `a_i * G` in `E::G1`.
    pub(crate) a_query: DeviceVec<Affine<C1>>,
    /// The elements `b_i * G` in `E::G1`.
    pub(crate) b_g1_query: DeviceVec<Affine<C1>>,
    /// The elements `b_i * H` in `E::G2`.
    pub(crate) b_g2_query: DeviceVec<Affine<C2>>,
    /// The elements `h_i * G` in `E::G1`.
    pub(crate) h_query: DeviceVec<Affine<C1>>,
    /// The elements `l_i * G` in `E::G1`.
    pub(crate) l_query: DeviceVec<Affine<C1>>,
    pub(crate) domain_size: usize,
    pub(crate) precomputed_roots: DeviceVec<F>,
    pub(crate) num_constraints: usize,
}

impl<
    F: FieldImpl<Config: VecOps<F> + NTT<F, F>> + Arithmetic + MontgomeryConvertible,
    C1: Curve<ScalarField = F>,
    C2: Curve<ScalarField = F>,
> ProvingKey<F, C1, C2>
{
    pub(crate) fn from_ark<P: ark_ec::pairing::Pairing>(
        pk: &ark_groth16::ProvingKey<P>,
        num_constraints: usize,
        num_instance_variables: usize,
    ) -> Self {
        let alpha_g1 = ark_to_icicle_affine(&pk.vk.alpha_g1);
        let beta_g2 = ark_to_icicle_affine(&pk.vk.beta_g2);
        let gamma_g2 = ark_to_icicle_affine(&pk.vk.gamma_g2);
        let delta_g2 = ark_to_icicle_affine(&pk.vk.delta_g2);
        let gamma_abc_g1 = from_host_slice(
            &pk.vk
                .gamma_abc_g1
                .iter()
                .map(ark_to_icicle_affine)
                .collect::<Vec<_>>(),
        );

        let beta_g1 = ark_to_icicle_affine(&pk.beta_g1);
        let delta_g1 = ark_to_icicle_affine(&pk.delta_g1);
        let a_query = from_host_slice(
            &pk.a_query
                .iter()
                .map(ark_to_icicle_affine)
                .collect::<Vec<_>>(),
        );
        let b_g1_query = from_host_slice(
            &pk.b_g1_query
                .iter()
                .map(ark_to_icicle_affine)
                .collect::<Vec<_>>(),
        );
        let b_g2_query = from_host_slice(
            &pk.b_g2_query
                .iter()
                .map(ark_to_icicle_affine)
                .collect::<Vec<_>>(),
        );
        let h_query = from_host_slice(
            &pk.h_query
                .iter()
                .map(ark_to_icicle_affine)
                .collect::<Vec<_>>(),
        );
        let l_query = from_host_slice(
            &pk.l_query
                .iter()
                .map(ark_to_icicle_affine)
                .collect::<Vec<_>>(),
        );

        let mut domain = GeneralEvaluationDomain::<P::ScalarField>::new(
            num_constraints + num_instance_variables,
        )
        .unwrap();
        let domain_size = domain.size();
        let power = domain_size.ilog2() as usize;

        let root_of_unity = root_of_unity_for_groth16::<P::ScalarField>(power, &mut domain);
        let root_of_unity = ark_to_icicle_scalar(root_of_unity);
        let mut roots = Vec::with_capacity(domain_size);
        let mut c = F::one();
        for _ in 0..domain_size {
            roots.push(c);
            c = c * root_of_unity;
        }
        let precomputed_roots = from_host_slice(&roots);

        Self {
            vk: VerifyingKey {
                alpha_g1,
                beta_g2,
                gamma_g2,
                delta_g2,
                gamma_abc_g1,
            },
            beta_g1,
            delta_g1,
            a_query,
            b_g1_query,
            b_g2_query,
            h_query,
            l_query,
            domain_size,
            precomputed_roots,
            num_constraints,
        }
    }
}

pub(crate) fn initialize_domain<F: FieldImpl<Config: NTTDomain<F>>>(max_size: usize) {
    // TODO CESAR: Handle better
    ntt::initialize_domain(
        ntt::get_root_of_unity::<F>(max_size.try_into().unwrap()),
        &ntt::NTTInitDomainConfig::default(),
    )
    .unwrap();
}

pub(crate) fn fft_inplace<F: FieldImpl<Config: VecOps<F> + NTT<F, F>>>(
    input: &mut DeviceSlice<F>,
    stream: &IcicleStream,
) {
    let mut ntt_config = NTTConfig::<F>::default();
    ntt_config.stream_handle = **stream;
    ntt_config.is_async = true;

    ntt_inplace(input, NTTDir::kForward, &ntt_config).expect("Failed to compute FFT in place");
}

pub(crate) fn ifft_inplace<F: FieldImpl<Config: VecOps<F> + NTT<F, F>>>(
    input: &mut DeviceSlice<F>,
    stream: &IcicleStream,
) {
    let mut ntt_config = NTTConfig::<F>::default();
    ntt_config.stream_handle = **stream;
    ntt_config.is_async = true;

    ntt_inplace(input, NTTDir::kInverse, &ntt_config)
        .expect("Failed to compute inverse FFT in place");
}

pub(crate) fn msm_async<
    F: FieldImpl<Config: VecOps<F> + NTT<F, F>>,
    C: Curve<ScalarField = F> + MSM<C>,
>(
    points: &DeviceSlice<Affine<C>>,
    scalars: &DeviceSlice<F>,
    stream: &IcicleStream,
) -> DeviceVec<Projective<C>> {
    println!(
        "Starting MSM with {} points and {} scalars",
        points.len(),
        scalars.len()
    );
    let mut results: DeviceVec<Projective<C>> =
        DeviceVec::device_malloc_async(1, stream).expect("Failed to allocate device vector");
    let mut cfg = MSMConfig::default();
    cfg.stream_handle = **stream;
    cfg.is_async = true;

    msm::<C>(scalars, points, &cfg, results.index_mut(..)).expect("Failed to compute MSM");
    results
}
