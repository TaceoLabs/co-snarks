use ark_ec::pairing::Pairing;
use mpc_core::traits::PrimeFieldMpcProtocol;
use std::fmt::Debug;
use ultrahonk::prelude::UltraCircuitVariable;

pub enum SharedBuilderVariable<T, P>
where
    P: Pairing,
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    Public(P::ScalarField),
    Shared(T::FieldShare),
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
    fn from_public(value: P::ScalarField) -> Self {
        Self::Public(value)
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
