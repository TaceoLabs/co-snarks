use std::mem::transmute;

use ark_bn254::Bn254;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, FftField, Field as ArkField, PrimeField};
use icicle_core::curve::{Affine, Curve, Projective};
use icicle_core::traits::{Arithmetic, FieldImpl, MontgomeryConvertible};
use icicle_runtime::memory::{DeviceSlice, DeviceVec, HostOrDeviceSlice, HostSlice};

use icicle_core::{
    field::Field,
    msm::MSM,
    ntt::{NTT, NTTDomain},
    pairing::Pairing,
    vec_ops::VecOps,
};
use icicle_runtime::stream::IcicleStream;
use rayon::vec;

use crate::gpu_utils::{from_host_slice, get_first_scalar};

fn ark_to_icicle_base<T, I>(ark: &T) -> I
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

fn icicle_to_ark_base<T, I>(icicle: &I) -> T
where
    T: ark_ff::Field,
    I: FieldImpl,
{
    T::from_random_bytes(&icicle.to_bytes_le()).unwrap()
}

fn ark_to_icicle_affine<T, C>(ark_affine: &T) -> Affine<C>
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

fn ark_to_icicle_affine_points<T, C>(ark_affine: &[T]) -> Vec<Affine<C>>
where
    T: AffineRepr,
    C: Curve,
{
    ark_affine
        .iter()
        .map(|ark| {
            Affine::<C>::from_limbs(
                ark_to_icicle_base::<_, C::BaseField>(&ark.x().unwrap()).into(),
                ark_to_icicle_base::<_, C::BaseField>(&ark.y().unwrap()).into(),
            )
        })
        .collect()
}

pub fn to_ark<T, I>(icicle: &I) -> T
where
    I: FieldImpl,
    T: PrimeField,
{
    T::from_random_bytes(&icicle.to_bytes_le()).unwrap()
}

pub fn transmute_ark_to_icicle_scalars<T, I>(
    ark_scalars: DeviceVec<T>,
) -> eyre::Result<DeviceVec<I>>
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

// TODO CESAR: Batch
pub fn transmute_ark_to_icicle_scalar<T, I>(ark_scalar: T) -> I
where
    T: PrimeField,
    I: FieldImpl + MontgomeryConvertible,
{
    let ark_scalars = vec![ark_scalar];
    let ark_scalars = from_host_slice(&ark_scalars);
    get_first_scalar(&transmute_ark_to_icicle_scalars(ark_scalars).unwrap()).unwrap()
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

    fn ark_to_icicle_scalar(ark: &Self::ArkScalarField) -> Self::IcicleScalarField {
        transmute_ark_to_icicle_scalar(*ark)
    }

    fn from_affine_g1(point: Affine<Self::IcicleG1>) -> Projective<Self::IcicleG1> {
        point.to_projective()
    }

    fn from_affine_g2(point: Affine<Self::IcicleG2>) -> Projective<Self::IcicleG2> {
        point.to_projective()
    }

    fn ark_to_icicle_base_g1(
        ark: &<Self::ArkG1 as CurveGroup>::BaseField,
    ) -> <Self::IcicleG1 as Curve>::BaseField {
        ark_to_icicle_base(ark)
    }

    fn ark_to_icicle_base_g2(
        ark: &<Self::ArkG2 as CurveGroup>::BaseField,
    ) -> <Self::IcicleG2 as Curve>::BaseField {
        ark_to_icicle_base(ark)
    }

    fn icicle_to_ark_base_g1(
        icicle: &<Self::IcicleG1 as Curve>::BaseField,
    ) -> <Self::ArkG1 as CurveGroup>::BaseField {
        icicle_to_ark_base(icicle)
    }

    fn icicle_to_ark_base_g2(
        icicle: &<Self::IcicleG2 as Curve>::BaseField,
    ) -> <Self::ArkG2 as CurveGroup>::BaseField {
        icicle_to_ark_base(icicle)
    }

    fn ark_to_icicle_g1(point: &Self::ArkG1Affine) -> Affine<Self::IcicleG1> {
        ark_to_icicle_affine(point)
    }

    fn ark_to_icicle_g2(point: &Self::ArkG2Affine) -> Affine<Self::IcicleG2> {
        ark_to_icicle_affine(point)
    }

    fn icicle_to_ark_g1(point: Affine<Self::IcicleG1>) -> Self::ArkG1Affine;

    fn icicle_to_ark_g2(point: Affine<Self::IcicleG2>) -> Self::ArkG2Affine;
}

pub struct Bn254Bridge;

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

        Self::ArkG1Affine::new(
            Self::icicle_to_ark_base_g1(&point.x),
            Self::icicle_to_ark_base_g1(&point.y),
        )
    }

    fn icicle_to_ark_g2(point: icicle_bn254::curve::G2Affine) -> Self::ArkG2Affine {
        if point == icicle_bn254::curve::G2Affine::zero() {
            return Self::ArkG2Affine::zero();
        }

        Self::ArkG2Affine::new(
            Self::icicle_to_ark_base_g2(&point.x),
            Self::icicle_to_ark_base_g2(&point.y),
        )
    }
}

pub fn select_bridge<P: ark_ec::pairing::Pairing>() -> impl ArkIcicleBridge {
    if std::any::TypeId::of::<P>() == std::any::TypeId::of::<ark_bn254::Bn254>() {
        Bn254Bridge
    } else {
        panic!("Unsupported pairing")
    }
}
