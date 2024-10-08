use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use mpc_core::traits::PrimeFieldMpcProtocol;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use ultrahonk::prelude::UltraCircuitVariable;

#[derive(Serialize, Deserialize)]
pub enum SharedBuilderVariable<T, P>
where
    P: Pairing,
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    Public(#[serde(serialize_with = "ark_se", deserialize_with = "ark_de")] P::ScalarField),
    Shared(#[serde(serialize_with = "ark_se", deserialize_with = "ark_de")] T::FieldShare),
}

/// Serialize an object with ark serialization, to be used with serde.
/// `#[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]`
pub(crate) fn ark_se<S, A: CanonicalSerialize>(a: &A, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut bytes = vec![];
    a.serialize_with_mode(&mut bytes, Compress::Yes)
        .map_err(serde::ser::Error::custom)?;
    s.serialize_bytes(&bytes)
}

/// Deserialize an object with ark deserialization, to be used with serde.
/// `#[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]`
pub(crate) fn ark_de<'de, D, A: CanonicalDeserialize>(data: D) -> Result<A, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s: Vec<u8> = serde::de::Deserialize::deserialize(data)?;
    let a = A::deserialize_with_mode(s.as_slice(), Compress::Yes, Validate::Yes);
    a.map_err(serde::de::Error::custom)
}

impl<T, P> SharedBuilderVariable<T, P>
where
    P: Pairing,
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    pub fn get_as_shared(&self, driver: &T) -> T::FieldShare {
        match self {
            SharedBuilderVariable::Public(value) => driver.promote_to_trivial_share(*value),
            SharedBuilderVariable::Shared(value) => value.to_owned(),
        }
    }
}

impl<T, P> Clone for SharedBuilderVariable<T, P>
where
    P: Pairing,
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    fn clone(&self) -> Self {
        match self {
            SharedBuilderVariable::Public(value) => Self::Public(*value),
            SharedBuilderVariable::Shared(value) => Self::Shared(value.clone()),
        }
    }
}

impl<T, P> PartialEq for SharedBuilderVariable<T, P>
where
    P: Pairing,
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (SharedBuilderVariable::Public(a), SharedBuilderVariable::Public(b)) => a == b,
            (SharedBuilderVariable::Shared(a), SharedBuilderVariable::Shared(b)) => a == b,
            _ => false,
        }
    }
}

impl<T, P> Debug for SharedBuilderVariable<T, P>
where
    P: Pairing,
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SharedBuilderVariable::Public(value) => write!(f, "Public({:?})", value),
            SharedBuilderVariable::Shared(value) => write!(f, "Shared({:?})", value),
        }
    }
}

impl<T, P> UltraCircuitVariable<P::ScalarField> for SharedBuilderVariable<T, P>
where
    P: Pairing,
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    type Shared = T::FieldShare;

    fn from_public(value: P::ScalarField) -> Self {
        Self::Public(value)
    }

    fn from_shared(value: T::FieldShare) -> Self {
        Self::Shared(value)
    }

    fn is_public(&self) -> bool {
        match self {
            SharedBuilderVariable::Public(_) => true,
            SharedBuilderVariable::Shared(_) => false,
        }
    }

    fn public_into_field(self) -> P::ScalarField {
        match self {
            SharedBuilderVariable::Public(val) => val,
            SharedBuilderVariable::Shared(_) => panic!("Expected public value"),
        }
    }
}
