use crate::PlainAcvmSolver;
use ark_ff::PrimeField;
use mpc_core::protocols::{
    rep3::{lut::NaiveRep3LookupTable, network::Rep3MpcNet},
    shamir::{arithmetic, network::ShamirNetwork, ShamirPrimeFieldShare, ShamirProtocol},
};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

use super::NoirWitnessExtensionProtocol;

pub struct ShamirAcvmSolver<F: PrimeField, N: ShamirNetwork> {
    protocol: ShamirProtocol<F, N>,
    plain_solver: PlainAcvmSolver<F>,
    phantom_data: PhantomData<F>,
}

impl<F: PrimeField, N: ShamirNetwork> ShamirAcvmSolver<F, N> {
    pub(crate) fn new(protocol: ShamirProtocol<F, N>) -> Self {
        let plain_solver = PlainAcvmSolver::<F>::default();
        Self {
            protocol,
            plain_solver,
            phantom_data: PhantomData,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub enum ShamirAcvmType<F: PrimeField> {
    Public(
        #[serde(
            serialize_with = "mpc_core::ark_se",
            deserialize_with = "mpc_core::ark_de"
        )]
        F,
    ),
    Shared(
        #[serde(
            serialize_with = "mpc_core::ark_se",
            deserialize_with = "mpc_core::ark_de"
        )]
        ShamirPrimeFieldShare<F>,
    ),
}

impl<F: PrimeField> std::fmt::Debug for ShamirAcvmType<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(field) => f.debug_tuple("Public").field(field).finish(),
            Self::Shared(share) => f.debug_tuple("Arithmetic").field(share).finish(),
        }
    }
}

impl<F: PrimeField> std::fmt::Display for ShamirAcvmType<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(field) => f.write_str(&format!("Public ({field})")),
            Self::Shared(arithmetic) => {
                f.write_str(&format!("Arithmetic ({})", arithmetic.inner()))
            }
        }
    }
}

impl<F: PrimeField> Default for ShamirAcvmType<F> {
    fn default() -> Self {
        Self::Public(F::zero())
    }
}

impl<F: PrimeField> From<F> for ShamirAcvmType<F> {
    fn from(value: F) -> Self {
        Self::Public(value)
    }
}

impl<F: PrimeField> From<ShamirPrimeFieldShare<F>> for ShamirAcvmType<F> {
    fn from(value: ShamirPrimeFieldShare<F>) -> Self {
        Self::Shared(value)
    }
}

impl<F: PrimeField, N: ShamirNetwork> NoirWitnessExtensionProtocol<F> for ShamirAcvmSolver<F, N> {
    type Lookup = NaiveRep3LookupTable<Rep3MpcNet>; // This is just a dummy and unused

    type ArithmeticShare = ShamirPrimeFieldShare<F>;

    type AcvmType = ShamirAcvmType<F>;

    fn is_public_zero(a: &Self::AcvmType) -> bool {
        if let ShamirAcvmType::Public(x) = a {
            x.is_zero()
        } else {
            false
        }
    }

    fn is_public_one(a: &Self::AcvmType) -> bool {
        if let ShamirAcvmType::Public(x) = a {
            x.is_one()
        } else {
            false
        }
    }

    fn acvm_add_assign_with_public(&mut self, public: F, target: &mut Self::AcvmType) {
        let result = match target.to_owned() {
            ShamirAcvmType::Public(secret) => ShamirAcvmType::Public(public + secret),
            ShamirAcvmType::Shared(secret) => {
                ShamirAcvmType::Shared(arithmetic::add_public(secret, public))
            }
        };
        *target = result;
    }

    fn acvm_mul_with_public(&mut self, public: F, secret: Self::AcvmType) -> Self::AcvmType {
        match secret {
            ShamirAcvmType::Public(secret) => ShamirAcvmType::Public(public * secret),
            ShamirAcvmType::Shared(secret) => {
                ShamirAcvmType::Shared(arithmetic::mul_public(secret, public))
            }
        }
    }

    fn solve_linear_term(&mut self, q_l: F, w_l: Self::AcvmType, target: &mut Self::AcvmType) {
        let result = match (w_l, target.to_owned()) {
            (ShamirAcvmType::Public(w_l), ShamirAcvmType::Public(result)) => {
                ShamirAcvmType::Public(q_l * w_l + result)
            }
            (ShamirAcvmType::Public(w_l), ShamirAcvmType::Shared(result)) => {
                ShamirAcvmType::Shared(arithmetic::add_public(result, q_l * w_l))
            }
            (ShamirAcvmType::Shared(w_l), ShamirAcvmType::Public(result)) => {
                let mul = arithmetic::mul_public(w_l, q_l);
                ShamirAcvmType::Shared(arithmetic::add_public(mul, result))
            }
            (ShamirAcvmType::Shared(w_l), ShamirAcvmType::Shared(result)) => {
                let mul = arithmetic::mul_public(w_l, q_l);
                ShamirAcvmType::Shared(arithmetic::add(mul, result))
            }
        };
        *target = result;
    }

    fn solve_mul_term(
        &mut self,
        c: F,
        lhs: Self::AcvmType,
        rhs: Self::AcvmType,
        target: &mut Self::AcvmType,
    ) -> std::io::Result<()> {
        let result = match (lhs, rhs) {
            (ShamirAcvmType::Public(lhs), ShamirAcvmType::Public(rhs)) => {
                ShamirAcvmType::Public(lhs * rhs * c)
            }
            (ShamirAcvmType::Public(public), ShamirAcvmType::Shared(shared))
            | (ShamirAcvmType::Shared(shared), ShamirAcvmType::Public(public)) => {
                ShamirAcvmType::Shared(arithmetic::mul_public(shared, public))
            }
            (ShamirAcvmType::Shared(lhs), ShamirAcvmType::Shared(rhs)) => {
                let shared_mul = arithmetic::mul(lhs, rhs, &mut self.protocol)?;
                ShamirAcvmType::Shared(arithmetic::mul_public(shared_mul, c))
            }
        };
        *target = result;
        Ok(())
    }

    fn solve_equation(
        &mut self,
        q_l: Self::AcvmType,
        c: Self::AcvmType,
    ) -> eyre::Result<Self::AcvmType> {
        //-c/q_l
        let result = match (q_l, c) {
            (ShamirAcvmType::Public(q_l), ShamirAcvmType::Public(c)) => {
                ShamirAcvmType::Public(self.plain_solver.solve_equation(q_l, c)?)
            }
            (ShamirAcvmType::Public(q_l), ShamirAcvmType::Shared(c)) => {
                ShamirAcvmType::Shared(arithmetic::div_shared_by_public(arithmetic::neg(c), q_l)?)
            }
            (ShamirAcvmType::Shared(q_l), ShamirAcvmType::Public(c)) => {
                let result = arithmetic::div_public_by_shared(-c, q_l, &mut self.protocol)?;
                ShamirAcvmType::Shared(result)
            }
            (ShamirAcvmType::Shared(q_l), ShamirAcvmType::Shared(c)) => {
                let result = arithmetic::div(arithmetic::neg(c), q_l, &mut self.protocol)?;
                ShamirAcvmType::Shared(result)
            }
        };
        Ok(result)
    }

    fn init_lut_by_acvm_type(
        &mut self,
        _values: Vec<Self::AcvmType>,
    ) -> <Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::SecretSharedMap {
        panic!("init_lut_by_acvm_type: Operation atm not supported")
    }

    fn read_lut_by_acvm_type(
        &mut self,
        _index: &Self::AcvmType,
        _lut: &<Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::SecretSharedMap,
    ) -> std::io::Result<Self::AcvmType> {
        panic!("read_lut_by_acvm_type: Operation atm not supported")
    }

    fn write_lut_by_acvm_type(
        &mut self,
        _index: Self::AcvmType,
        _value: Self::AcvmType,
        _lut: &mut <Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::SecretSharedMap,
    ) -> std::io::Result<()> {
        panic!("write_lut_by_acvm_type: Operation atm not supported")
    }

    fn is_shared(a: &Self::AcvmType) -> bool {
        matches!(a, ShamirAcvmType::Shared(_))
    }

    fn get_shared(a: &Self::AcvmType) -> Option<Self::ArithmeticShare> {
        match a {
            ShamirAcvmType::Shared(shared) => Some(*shared),
            _ => None,
        }
    }

    fn get_public(a: &Self::AcvmType) -> Option<F> {
        match a {
            ShamirAcvmType::Public(public) => Some(*public),
            _ => None,
        }
    }

    fn open_many(&mut self, a: &[Self::ArithmeticShare]) -> std::io::Result<Vec<F>> {
        arithmetic::open_vec(a, &mut self.protocol)
    }
}
