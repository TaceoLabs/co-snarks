//! SPDZ ACVM types — Public/Shared enums for the ACVM layer.

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use mpc_core::serde_compat::{ark_de, ark_se};
use serde::{Deserialize, Serialize};
use spdz_core::types::{SpdzPointShare, SpdzPrimeFieldShare};

/// ACVM value type for SPDZ: either a public field element or a shared value.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub enum SpdzAcvmType<F: PrimeField> {
    /// A public (cleartext) field element.
    Public(
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
        F,
    ),
    /// A SPDZ secret-shared field element.
    Shared(
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
        SpdzPrimeFieldShare<F>,
    ),
}

impl<F: PrimeField> Default for SpdzAcvmType<F> {
    fn default() -> Self {
        Self::Public(F::zero())
    }
}

impl<F: PrimeField> std::fmt::Debug for SpdzAcvmType<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(field) => f.debug_tuple("Public").field(field).finish(),
            Self::Shared(share) => f.debug_tuple("Shared").field(share).finish(),
        }
    }
}

impl<F: PrimeField> std::fmt::Display for SpdzAcvmType<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(field) => write!(f, "Public ({field})"),
            Self::Shared(share) => write!(f, "Shared ({:?})", share),
        }
    }
}

impl<F: PrimeField> From<F> for SpdzAcvmType<F> {
    fn from(value: F) -> Self {
        Self::Public(value)
    }
}

impl<F: PrimeField> From<SpdzPrimeFieldShare<F>> for SpdzAcvmType<F> {
    fn from(value: SpdzPrimeFieldShare<F>) -> Self {
        Self::Shared(value)
    }
}

impl<F: PrimeField> From<crate::brillig::SpdzBrilligType<F>> for SpdzAcvmType<F> {
    fn from(value: crate::brillig::SpdzBrilligType<F>) -> Self {
        match value {
            crate::brillig::SpdzBrilligType::Public(public) => {
                SpdzAcvmType::Public(public.into_field())
            }
            crate::brillig::SpdzBrilligType::Shared(s) => SpdzAcvmType::Shared(s),
        }
    }
}

impl<F: PrimeField> From<SpdzAcvmType<F>> for crate::brillig::SpdzBrilligType<F> {
    fn from(value: SpdzAcvmType<F>) -> Self {
        match value {
            SpdzAcvmType::Public(f) => crate::brillig::SpdzBrilligType::Public(
                co_brillig::mpc::PlainBrilligType::Field(f),
            ),
            SpdzAcvmType::Shared(s) => crate::brillig::SpdzBrilligType::Shared(s),
        }
    }
}

/// ACVM point type for SPDZ: either a public curve point or a shared point.
#[derive(Clone)]
pub enum SpdzAcvmPoint<C: CurveGroup> {
    /// A public curve point.
    Public(C),
    /// A SPDZ secret-shared curve point.
    Shared(SpdzPointShare<C>),
}

impl<C: CurveGroup> std::fmt::Debug for SpdzAcvmPoint<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(point) => f.debug_tuple("Public").field(point).finish(),
            Self::Shared(share) => f.debug_tuple("Shared").field(share).finish(),
        }
    }
}

impl<C: CurveGroup> std::fmt::Display for SpdzAcvmPoint<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(point) => write!(f, "Public ({point})"),
            Self::Shared(share) => write!(f, "Shared ({:?})", share),
        }
    }
}

impl<C: CurveGroup> From<C> for SpdzAcvmPoint<C> {
    fn from(value: C) -> Self {
        Self::Public(value)
    }
}
