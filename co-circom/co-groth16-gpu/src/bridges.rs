use std::mem::transmute;

use ark_bn254::Bn254;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, FftField, Field as ArkField, PrimeField};
use icicle_core::traits::MontgomeryConvertible;
use icicle_runtime::memory::{DeviceSlice, DeviceVec, HostOrDeviceSlice};
use icicle_core::affine::Affine;

use icicle_core::{ecntt::Projective, ntt::{NTTDomain, NTT}, msm::MSM, vec_ops::VecOps, field::Field, pairing::Pairing};
use icicle_runtime::stream::IcicleStream;

fn ark_to_icicle_base<T, I>(ark: &T) -> I
where
    T: ark_ff::Field,
    I: Field
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
    I: Field,
{
    T::from_random_bytes(&icicle.to_bytes_le()).unwrap()
}

fn ark_to_icicle_affine<T, I>(ark_affine: &T) -> I
where
    T: AffineRepr,
    I: Affine,
{
    if let Some((x, y)) = ark_affine.xy() {
        I::from_xy(
            ark_to_icicle_base(&x),
            ark_to_icicle_base(&y),
        )
    } else {
        I::zero()
    }
}

fn ark_to_icicle_affine_points<T, I>(ark_affine: &[T]) -> Vec<I>
where
    T: AffineRepr,
    I: Affine,
{
    ark_affine
        .iter()
        .map(|ark| I::from_xy(
            ark_to_icicle_base(&ark.x().unwrap()),
            ark_to_icicle_base(&ark.y().unwrap()),
        ))
        .collect()
}

pub fn to_ark<T, I>(icicle: &I) -> T
where
    I: Field,
    T: PrimeField,
{
    T::from_random_bytes(&icicle.to_bytes_le()).unwrap()
}

pub fn transmute_ark_to_icicle_scalars<T, I>(ark_scalars: DeviceVec<T>) -> eyre::Result<DeviceVec<I>>
where
    T: PrimeField,
    I: Field + MontgomeryConvertible,
{
    // SAFETY: Reinterpreting Arkworks field elements as Icicle-specific scalars
    let mut icicle_scalars = unsafe { transmute::<DeviceVec<T>, DeviceVec<I>>(ark_scalars) };

    // Convert from Montgomery representation using the Icicle type's conversion method
    I::from_mont(&mut icicle_scalars, &IcicleStream::default())?;

    Ok(icicle_scalars)
}

// TODO CESAR: Batch
pub fn transmute_ark_to_icicle_scalar<T, I>(ark_scalar: T) -> I
where
    T: PrimeField,
    I: Field + MontgomeryConvertible,
{
    // SAFETY: Reinterpreting Arkworks field elements as Icicle-specific scalars
    transmute_ark_to_icicle_scalars(DeviceVec::from_host_slice(&[ark_scalar]))
        .expect("transmutation should succeed")
        .to_host_vec()
        .pop()
        .expect("should have at least one element")
}

pub trait ArkIcicleBridge {
    type ArkScalarField: PrimeField;
    type ArkG1Affine: AffineRepr<ScalarField = Self::ArkScalarField>;
    type ArkG2Affine: AffineRepr<ScalarField = Self::ArkScalarField>;
    type ArkG1: CurveGroup<ScalarField = Self::ArkScalarField, Affine = Self::ArkG1Affine>;
    type ArkG2: CurveGroup<ScalarField = Self::ArkScalarField, Affine = Self::ArkG2Affine>;
    type ArkPairing: ark_ec::pairing::Pairing<G1 = Self::ArkG1, G2 = Self::ArkG2, ScalarField = Self::ArkScalarField, G1Affine = Self::ArkG1Affine, G2Affine = Self::ArkG2Affine>;

    type IcicleScalarField: Field + VecOps<Self::IcicleScalarField> + NTT<Self::IcicleScalarField, Self::IcicleScalarField> + MontgomeryConvertible + NTTDomain<Self::IcicleScalarField>;
    type IcicleG1Affine: Affine;
    type IcicleG2Affine: Affine;
    type IcicleG1: Projective<ScalarField = Self::IcicleScalarField, Affine = Self::IcicleG1Affine> + MSM<Self::IcicleG1>;
    type IcicleG2: Projective<ScalarField = Self::IcicleScalarField, Affine = Self::IcicleG2Affine> + MSM<Self::IcicleG2>;

    fn ark_to_icicle_scalar(ark: &Self::ArkScalarField) -> Self::IcicleScalarField {
        transmute_ark_to_icicle_scalar(*ark)
    }

    fn from_affine_g1(point: Self::IcicleG1Affine) -> Self::IcicleG1 {
        Self::IcicleG1::from_affine(point)
    }

    fn from_affine_g2(point: Self::IcicleG2Affine) -> Self::IcicleG2 {
        Self::IcicleG2::from_affine(point)
    }

    fn ark_to_icicle_base_g1(ark: &<Self::ArkG1 as CurveGroup>::BaseField) -> <Self::IcicleG1 as Projective>::BaseField {
        ark_to_icicle_base(ark)
    }

    fn ark_to_icicle_base_g2(ark: &<Self::ArkG2 as CurveGroup>::BaseField) -> <Self::IcicleG2 as Projective>::BaseField {
        ark_to_icicle_base(ark)
    }

    fn icicle_to_ark_base_g1(icicle: &<Self::IcicleG1 as Projective>::BaseField) -> <Self::ArkG1 as CurveGroup>::BaseField {
        icicle_to_ark_base(icicle)
    }

    fn icicle_to_ark_base_g2(icicle: &<Self::IcicleG2 as Projective>::BaseField) -> <Self::ArkG2 as CurveGroup>::BaseField {
        icicle_to_ark_base(icicle)
    }

    fn ark_to_icicle_g1(point: &Self::ArkG1Affine) -> Self::IcicleG1Affine {
        ark_to_icicle_affine(point)
    }

    fn ark_to_icicle_g2(point: &Self::ArkG2Affine) -> Self::IcicleG2Affine {
        ark_to_icicle_affine(point)
    }

    // TODO CESAR: Can't be implemented out of the box
    fn icicle_to_ark_g1(point: Self::IcicleG1Affine) -> Self::ArkG1Affine {
        todo!()
    }

    // TODO CESAR: Can't be implemented out of the box
    fn icicle_to_ark_g2(point: Self::IcicleG2Affine) -> Self::ArkG2Affine {
        todo!()
    }
}

pub struct Bn254Bridge;

impl ArkIcicleBridge for Bn254Bridge {
    type ArkScalarField = ark_bn254::Fr;
    type ArkG1Affine = <Bn254 as ark_ec::pairing::Pairing>::G1Affine;
    type ArkG2Affine = <Bn254 as ark_ec::pairing::Pairing>::G2Affine;
    type ArkG1 = <Bn254 as ark_ec::pairing::Pairing>::G1;
    type ArkG2 = <Bn254 as ark_ec::pairing::Pairing>::G2;
    type ArkPairing = Bn254;

    type IcicleScalarField = icicle_bn254::curve::ScalarField;
    type IcicleG1Affine = icicle_bn254::curve::G1Affine;
    type IcicleG2Affine = icicle_bn254::curve::G2Affine;
    type IcicleG1 = icicle_bn254::curve::G1Projective;
    type IcicleG2 = icicle_bn254::curve::G2Projective;

    fn icicle_to_ark_g1(point: Self::IcicleG1Affine) -> Self::ArkG1Affine {
        if point == Self::IcicleG1Affine::zero() {
            return Self::ArkG1Affine::zero();
        }

        Self::ArkG1Affine::new(
            Self::icicle_to_ark_base_g1(&point.x),
            Self::icicle_to_ark_base_g1(&point.y),
        )
    }

    fn icicle_to_ark_g2(point: Self::IcicleG2Affine) -> Self::ArkG2Affine {
        if point == Self::IcicleG2Affine::zero() {
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