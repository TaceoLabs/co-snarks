//! `sqlx` support for the share types.
//!
//! Enabled per database with the `sqlx-postgres`, `sqlx-mysql` and `sqlx-sqlite` features.
//! Types are stored as binary blobs using the uncompressed [`ark_serialize`] encoding, [`Bit`] as a bool.

use crate::protocols::{
    rep3::{Rep3PointShare, Rep3PrimeFieldShare, Rep3UintShare},
    rep3_ring::{
        Rep3RingShare,
        ring::{bit::Bit, int_ring::IntRing2k, ring_impl::RingElement},
    },
    shamir::{ShamirPointShare, ShamirPrimeFieldShare},
};
use crate::uint::FieldUint;
use ::sqlx::{Database, Decode, Encode, Type, encode::IsNull, error::BoxDynError};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

macro_rules! impl_bytes {
    ($db:ty, [$($gen:tt)*] $ty:ty) => {
        impl<$($gen)*> Type<$db> for $ty {
            fn type_info() -> <$db as Database>::TypeInfo {
                <[u8] as Type<$db>>::type_info()
            }

            fn compatible(ty: &<$db as Database>::TypeInfo) -> bool {
                <[u8] as Type<$db>>::compatible(ty)
            }
        }

        impl<'q, $($gen)*> Encode<'q, $db> for $ty {
            fn encode_by_ref(
                &self,
                buf: &mut <$db as Database>::ArgumentBuffer,
            ) -> Result<IsNull, BoxDynError> {
                let mut bytes = Vec::new();
                self.serialize_uncompressed(&mut bytes)?;
                <Vec<u8> as Encode<$db>>::encode(bytes, buf)
            }
        }

        impl<'r, $($gen)*> Decode<'r, $db> for $ty {
            fn decode(value: <$db as Database>::ValueRef<'r>) -> Result<Self, BoxDynError> {
                let bytes = <&[u8] as Decode<$db>>::decode(value)?;
                Ok(Self::deserialize_uncompressed(bytes)?)
            }
        }
    };
}

macro_rules! impl_bit {
    ($db:ty) => {
        impl Type<$db> for Bit {
            fn type_info() -> <$db as Database>::TypeInfo {
                <bool as Type<$db>>::type_info()
            }

            fn compatible(ty: &<$db as Database>::TypeInfo) -> bool {
                <bool as Type<$db>>::compatible(ty)
            }
        }

        impl Encode<'_, $db> for Bit {
            fn encode_by_ref(
                &self,
                buf: &mut <$db as Database>::ArgumentBuffer,
            ) -> Result<IsNull, BoxDynError> {
                <bool as Encode<$db>>::encode_by_ref(&self.convert(), buf)
            }
        }

        impl Decode<'_, $db> for Bit {
            fn decode(value: <$db as Database>::ValueRef<'_>) -> Result<Self, BoxDynError> {
                Ok(Bit::new(<bool as Decode<$db>>::decode(value)?))
            }
        }
    };
}

macro_rules! impl_sqlx {
    ($db:ty) => {
        impl_bytes!($db, [F: PrimeField] Rep3PrimeFieldShare<F>);
        impl_bytes!($db, [F: FieldUint] Rep3UintShare<F>);
        impl_bytes!($db, [C: CurveGroup] Rep3PointShare<C>);
        impl_bytes!($db, [T: IntRing2k] Rep3RingShare<T>);
        impl_bytes!($db, [T: IntRing2k] RingElement<T>);
        impl_bytes!($db, [F: PrimeField] ShamirPrimeFieldShare<F>);
        impl_bytes!($db, [C: CurveGroup] ShamirPointShare<C>);
        impl_bit!($db);
    };
}

#[cfg(feature = "sqlx-postgres")]
impl_sqlx!(::sqlx::Postgres);
#[cfg(feature = "sqlx-mysql")]
impl_sqlx!(::sqlx::MySql);
#[cfg(feature = "sqlx-sqlite")]
impl_sqlx!(::sqlx::Sqlite);
