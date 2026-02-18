use std::mem::transmute;

use ark_bn254::Bn254;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use icicle_core::curve::{Affine, Curve};
use icicle_core::traits::{Arithmetic, FieldImpl, MontgomeryConvertible};
use icicle_runtime::memory::DeviceVec;

use icicle_core::{
    msm::MSM,
    ntt::{NTT, NTTDomain},
    vec_ops::VecOps,
};

use icicle_runtime::stream::IcicleStream;

use crate::gpu_utils::{from_host_slice, get_first_ark_scalar, get_first_icicle_scalar};

pub(crate) fn ark_to_icicle_base<T, I>(ark: &T) -> I
where
    T: ark_ff::Field,
    I: FieldImpl,
{
    let mut ark_bytes = vec![];
    for base_elem in ark.to_base_prime_field_elements() {
        ark_bytes.extend_from_slice(&base_elem.into_bigint().to_bytes_le());
    }
    I::from_bytes_le(&ark_bytes)
}

pub(crate) fn icicle_to_ark_base<T, I>(icicle: &I) -> T
where
    T: ark_ff::Field,
    I: FieldImpl,
{
    T::from_random_bytes(&icicle.to_bytes_le()).unwrap()
}

pub(crate) fn ark_to_icicle_affine<T, C>(ark_affine: &T) -> Affine<C>
where
    T: AffineRepr,
    C: Curve,
{
    if let Some((x, y)) = ark_affine.xy() {
        Affine::<C>::from_limbs(
            ark_to_icicle_base::<_, C::BaseField>(&x).into(),
            ark_to_icicle_base::<_, C::BaseField>(&y).into(),
        )
    } else {
        Affine::<C>::zero()
    }
}

pub(crate) fn ark_to_icicle_scalars<T, I>(ark_scalars: DeviceVec<T>) -> eyre::Result<DeviceVec<I>>
where
    T: PrimeField,
    I: FieldImpl + MontgomeryConvertible,
{
    // SAFETY: Reinterpreting Arkworks field elements as Icicle-specific scalars
    let mut icicle_scalars = unsafe { transmute::<DeviceVec<T>, DeviceVec<I>>(ark_scalars) };

    // Convert from Montgomery representation using the Icicle type's conversion method
    I::from_mont(&mut icicle_scalars, &IcicleStream::default());

    Ok(icicle_scalars)
}

pub(crate) fn icicle_to_ark_scalars<T, I>(
    icicle_scalars: DeviceVec<I>,
) -> eyre::Result<DeviceVec<T>>
where
    T: PrimeField,
    I: FieldImpl + MontgomeryConvertible,
{
    let mut icicle_scalars = icicle_scalars;

    // Convert to Montgomery representation using the Icicle type's conversion method
    I::to_mont(&mut icicle_scalars, &IcicleStream::default());

    // SAFETY: Reinterpreting Icicle-specific scalars as Arkworks field elements
    let ark_scalars = unsafe { transmute::<DeviceVec<I>, DeviceVec<T>>(icicle_scalars) };

    Ok(ark_scalars)
}

// TODO CESAR: Batch
pub(crate) fn ark_to_icicle_scalar<T, I>(ark_scalar: T) -> I
where
    T: PrimeField,
    I: FieldImpl + MontgomeryConvertible,
{
    let ark_scalars = vec![ark_scalar];
    let ark_scalars = from_host_slice(&ark_scalars);
    get_first_icicle_scalar(&ark_to_icicle_scalars(ark_scalars).unwrap()).unwrap()
}

pub(crate) fn icicle_to_ark_scalar<T, I>(icicle_scalar: I) -> T
where
    T: PrimeField,
    I: FieldImpl + MontgomeryConvertible,
{
    let icicle_scalars = vec![icicle_scalar];
    let icicle_scalars = from_host_slice(&icicle_scalars);
    get_first_ark_scalar(&icicle_to_ark_scalars(icicle_scalars).unwrap()).unwrap()
}

pub trait ArkIcicleBridge {
    type ArkScalarField: PrimeField;
    type ArkG1Affine: AffineRepr<ScalarField = Self::ArkScalarField>;
    type ArkG2Affine: AffineRepr<ScalarField = Self::ArkScalarField>;
    type ArkG1: CurveGroup<ScalarField = Self::ArkScalarField, Affine = Self::ArkG1Affine>;
    type ArkG2: CurveGroup<ScalarField = Self::ArkScalarField, Affine = Self::ArkG2Affine>;
    type ArkPairing: ark_ec::pairing::Pairing<
            G1 = Self::ArkG1,
            G2 = Self::ArkG2,
            ScalarField = Self::ArkScalarField,
            G1Affine = Self::ArkG1Affine,
            G2Affine = Self::ArkG2Affine,
        >;

    type IcicleScalarCfg: VecOps<Self::IcicleScalarField>
        + NTT<Self::IcicleScalarField, Self::IcicleScalarField>
        + NTTDomain<Self::IcicleScalarField>;
    type IcicleScalarField: FieldImpl<Config = Self::IcicleScalarCfg>
        + MontgomeryConvertible
        + Arithmetic;
    type IcicleG1: Curve<ScalarField = Self::IcicleScalarField> + MSM<Self::IcicleG1>;
    type IcicleG2: Curve<ScalarField = Self::IcicleScalarField> + MSM<Self::IcicleG2>;

    fn icicle_to_ark_g1(point: Affine<Self::IcicleG1>) -> Self::ArkG1Affine;

    fn icicle_to_ark_g2(point: Affine<Self::IcicleG2>) -> Self::ArkG2Affine;
}

pub(crate) struct Bn254Bridge;

impl ArkIcicleBridge for Bn254Bridge {
    type ArkScalarField = ark_bn254::Fr;
    type ArkG1Affine = <Bn254 as ark_ec::pairing::Pairing>::G1Affine;
    type ArkG2Affine = <Bn254 as ark_ec::pairing::Pairing>::G2Affine;
    type ArkG1 = <Bn254 as ark_ec::pairing::Pairing>::G1;
    type ArkG2 = <Bn254 as ark_ec::pairing::Pairing>::G2;
    type ArkPairing = Bn254;

    type IcicleScalarCfg = icicle_bn254::curve::ScalarCfg;
    type IcicleScalarField = icicle_bn254::curve::ScalarField;
    type IcicleG1 = icicle_bn254::curve::CurveCfg;
    type IcicleG2 = icicle_bn254::curve::G2CurveCfg;

    fn icicle_to_ark_g1(point: icicle_bn254::curve::G1Affine) -> Self::ArkG1Affine {
        if point == icicle_bn254::curve::G1Affine::zero() {
            return Self::ArkG1Affine::zero();
        }

        Self::ArkG1Affine::new(icicle_to_ark_base(&point.x), icicle_to_ark_base(&point.y))
    }

    fn icicle_to_ark_g2(point: icicle_bn254::curve::G2Affine) -> Self::ArkG2Affine {
        if point == icicle_bn254::curve::G2Affine::zero() {
            return Self::ArkG2Affine::zero();
        }

        Self::ArkG2Affine::new(icicle_to_ark_base(&point.x), icicle_to_ark_base(&point.y))
    }
}
