use ark_ec::pairing::Pairing;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use ultrahonk::prelude::UltraCircuitVariable;

use crate::mpc::NoirUltraHonkProver;

#[derive(Serialize, Deserialize)]
pub enum SharedBuilderVariable<T: NoirUltraHonkProver<P>, P: Pairing> {
    Public(
        #[serde(
            serialize_with = "mpc_core::ark_se",
            deserialize_with = "mpc_core::ark_de"
        )]
        P::ScalarField,
    ),
    Shared(
        #[serde(
            serialize_with = "mpc_core::ark_se",
            deserialize_with = "mpc_core::ark_de"
        )]
        T::ArithmeticShare,
    ),
}

impl<T: NoirUltraHonkProver<P>, P: Pairing> SharedBuilderVariable<T, P> {
    pub fn get_as_shared(&self, id: T::PartyID) -> T::ArithmeticShare {
        match self {
            SharedBuilderVariable::Public(value) => T::promote_to_trivial_share(id, *value),
            SharedBuilderVariable::Shared(value) => value.to_owned(),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: Pairing> Clone for SharedBuilderVariable<T, P> {
    fn clone(&self) -> Self {
        match self {
            SharedBuilderVariable::Public(value) => Self::Public(*value),
            SharedBuilderVariable::Shared(value) => Self::Shared(*value),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: Pairing> PartialEq for SharedBuilderVariable<T, P> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (SharedBuilderVariable::Public(a), SharedBuilderVariable::Public(b)) => a == b,
            (SharedBuilderVariable::Shared(a), SharedBuilderVariable::Shared(b)) => a == b,
            _ => false,
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: Pairing> Debug for SharedBuilderVariable<T, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SharedBuilderVariable::Public(value) => write!(f, "Public({:?})", value),
            SharedBuilderVariable::Shared(value) => write!(f, "Shared({:?})", value),
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: Pairing> UltraCircuitVariable<P::ScalarField>
    for SharedBuilderVariable<T, P>
{
    type Shared = T::ArithmeticShare;

    fn from_public(value: P::ScalarField) -> Self {
        Self::Public(value)
    }

    fn from_shared(value: T::ArithmeticShare) -> Self {
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
