use super::{NoirWitnessExtensionProtocol, plain::PlainAcvmSolver};
use ark_ec::CurveGroup;
use ark_ff::Zero;
use ark_ff::{One, PrimeField};
use co_brillig::mpc::{ShamirBrilligDriver, ShamirBrilligType};
use co_noir_types::ShamirType;
use core::panic;
use itertools::{Either, Itertools};
use mpc_core::lut::LookupTableProvider;
use mpc_core::protocols::rep3_ring::lut_curve::Rep3CurveLookupTable;
use mpc_core::{
    MpcState,
    gadgets::poseidon2::{Poseidon2, Poseidon2Precomputations},
    protocols::{
        rep3::yao::circuits::SHA256Table,
        rep3_ring::lut_field::Rep3FieldLookupTable,
        shamir::{
            ShamirPointShare, ShamirPrimeFieldShare, ShamirState, arithmetic,
            network::ShamirNetworkExt, pointshare,
        },
    },
};
use mpc_net::Network;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::{array, marker::PhantomData};

pub struct ShamirAcvmSolver<'a, F: PrimeField, N: Network> {
    net: &'a N,
    state: ShamirState<F>,
    plain_solver: PlainAcvmSolver<F>,
    phantom_data: PhantomData<F>,
}

impl<'a, F: PrimeField, N: Network> ShamirAcvmSolver<'a, F, N> {
    /// Creates a new instance of the Shamir solver
    pub fn new(net: &'a N, state: ShamirState<F>) -> Self {
        Self {
            net,
            state,
            plain_solver: PlainAcvmSolver::default(),
            phantom_data: PhantomData,
        }
    }
}

// For some intermediate representations
#[derive(Clone, Copy)]
pub enum ShamirAcvmPoint<C: CurveGroup> {
    Public(C),
    Shared(ShamirPointShare<C>),
}
impl<C: CurveGroup> Default for ShamirAcvmPoint<C> {
    fn default() -> Self {
        Self::Public(C::zero())
    }
}

impl<C: CurveGroup> std::fmt::Debug for ShamirAcvmPoint<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(point) => f.debug_tuple("Public").field(point).finish(),
            Self::Shared(share) => f.debug_tuple("Arithmetic").field(share).finish(),
        }
    }
}

impl<C: CurveGroup> std::fmt::Display for ShamirAcvmPoint<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(point) => f.write_str(&format!("Public ({point})")),
            Self::Shared(arithmetic) => {
                f.write_str(&format!("Arithmetic ({})", arithmetic.to_owned().inner()))
            }
        }
    }
}

impl<C: CurveGroup> From<C> for ShamirAcvmPoint<C> {
    fn from(value: C) -> Self {
        Self::Public(value)
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Copy)]
pub enum ShamirAcvmType<F: PrimeField> {
    Public(
        #[serde(
            serialize_with = "mpc_core::serde_compat::ark_se",
            deserialize_with = "mpc_core::serde_compat::ark_de"
        )]
        F,
    ),
    Shared(
        #[serde(
            serialize_with = "mpc_core::serde_compat::ark_se",
            deserialize_with = "mpc_core::serde_compat::ark_de"
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

impl<F: PrimeField> From<ShamirType<F>> for ShamirAcvmType<F> {
    fn from(value: ShamirType<F>) -> Self {
        match value {
            ShamirType::Public(public) => ShamirAcvmType::Public(public),
            ShamirType::Shared(shared) => ShamirAcvmType::Shared(shared),
        }
    }
}

impl<F: PrimeField> From<ShamirAcvmType<F>> for ShamirBrilligType<F> {
    fn from(val: ShamirAcvmType<F>) -> Self {
        match val {
            ShamirAcvmType::Public(public) => ShamirBrilligType::from(public),
            ShamirAcvmType::Shared(share) => ShamirBrilligType::Shared(share),
        }
    }
}

impl<F: PrimeField> From<ShamirBrilligType<F>> for ShamirAcvmType<F> {
    fn from(value: ShamirBrilligType<F>) -> Self {
        match value {
            ShamirBrilligType::Public(public) => ShamirAcvmType::Public(public.into_field()),
            ShamirBrilligType::Shared(shared) => ShamirAcvmType::Shared(shared),
        }
    }
}

impl<'a, F: PrimeField, N: Network> NoirWitnessExtensionProtocol<F> for ShamirAcvmSolver<'a, F, N> {
    type Lookup = Rep3FieldLookupTable<F>; // This is just a dummy and unused
    type CurveLookup<C: CurveGroup<ScalarField = F>> = Rep3CurveLookupTable<C>; // This is just a dummy and unused

    type ArithmeticShare = ShamirPrimeFieldShare<F>;

    type AcvmType = ShamirAcvmType<F>;
    type CycleGroupAcvmPoint<C: CurveGroup<BaseField = F>> = ShamirAcvmPoint<C>;

    type OtherArithmeticShare<C: CurveGroup<ScalarField = F, BaseField: PrimeField>> =
        ShamirPrimeFieldShare<C::BaseField>;
    type NativeAcvmPoint<C: CurveGroup<ScalarField = F, BaseField: PrimeField>> =
        ShamirAcvmPoint<C>;

    type OtherAcvmType<C: CurveGroup<ScalarField = F, BaseField: PrimeField>> =
        ShamirAcvmType<C::BaseField>;

    type BrilligDriver = ShamirBrilligDriver<'a, F, N>;

    fn init_brillig_driver(&mut self) -> eyre::Result<Self::BrilligDriver> {
        // TODO we just copy the net ref here this is not safe if used concurrently
        // TODO maybe take corr rand pairs here?
        Ok(ShamirBrilligDriver::new(self.net, self.state.fork(0)?))
    }

    fn parse_brillig_result(
        &mut self,
        brillig_result: Vec<ShamirBrilligType<F>>,
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        Ok(brillig_result
            .into_iter()
            .map(ShamirAcvmType::from)
            .collect())
    }

    fn public_zero() -> Self::AcvmType {
        Self::AcvmType::default()
    }

    fn shared_zeros(&mut self, len: usize) -> eyre::Result<Vec<Self::AcvmType>> {
        // TODO: This is not the best implementaiton for shared zeros
        let trivial_zeros = vec![F::zero(); len];
        let res = self
            .net
            .degree_reduce_many(&mut self.state, trivial_zeros)?;
        Ok(res.into_iter().map(ShamirAcvmType::from).collect())
    }

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

    fn cmux(
        &mut self,
        cond: Self::AcvmType,
        truthy: Self::AcvmType,
        falsy: Self::AcvmType,
    ) -> eyre::Result<Self::AcvmType> {
        match (cond, truthy, falsy) {
            (ShamirAcvmType::Public(cond), truthy, falsy) => {
                assert!(cond.is_one() || cond.is_zero());
                if cond.is_one() { Ok(truthy) } else { Ok(falsy) }
            }
            (ShamirAcvmType::Shared(cond), truthy, falsy) => {
                let b_min_a = self.sub(truthy, falsy);
                let d = self.mul(cond.into(), b_min_a)?;
                Ok(self.add(falsy, d))
            }
        }
    }

    fn cmux_other<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        _cond: Self::OtherAcvmType<C>,
        _truthy: Self::OtherAcvmType<C>,
        _falsy: Self::OtherAcvmType<C>,
    ) -> eyre::Result<Self::OtherAcvmType<C>> {
        unimplemented!("cmux_other not implemented yet for Shamir")
    }

    fn add_assign_with_public(&mut self, public: F, target: &mut Self::AcvmType) {
        let result = match target.to_owned() {
            ShamirAcvmType::Public(secret) => ShamirAcvmType::Public(public + secret),
            ShamirAcvmType::Shared(secret) => {
                ShamirAcvmType::Shared(arithmetic::add_public(secret, public))
            }
        };
        *target = result;
    }

    fn add_assign_with_public_other<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        public: C::BaseField,
        target: &mut Self::OtherAcvmType<C>,
    ) {
        let result = match target.to_owned() {
            ShamirAcvmType::Public(secret) => ShamirAcvmType::Public(public + secret),
            ShamirAcvmType::Shared(secret) => {
                ShamirAcvmType::Shared(arithmetic::add_public(secret, public))
            }
        };
        *target = result;
    }

    fn add(&self, lhs: Self::AcvmType, rhs: Self::AcvmType) -> Self::AcvmType {
        match (lhs, rhs) {
            (ShamirAcvmType::Public(lhs), ShamirAcvmType::Public(rhs)) => {
                ShamirAcvmType::Public(lhs + rhs)
            }
            (ShamirAcvmType::Public(public), ShamirAcvmType::Shared(shared))
            | (ShamirAcvmType::Shared(shared), ShamirAcvmType::Public(public)) => {
                ShamirAcvmType::Shared(arithmetic::add_public(shared, public))
            }
            (ShamirAcvmType::Shared(lhs), ShamirAcvmType::Shared(rhs)) => {
                let result = arithmetic::add(lhs, rhs);
                ShamirAcvmType::Shared(result)
            }
        }
    }

    fn add_points<C: CurveGroup<BaseField = F>>(
        &self,
        lhs: Self::CycleGroupAcvmPoint<C>,
        rhs: Self::CycleGroupAcvmPoint<C>,
    ) -> Self::CycleGroupAcvmPoint<C> {
        match (lhs, rhs) {
            (ShamirAcvmPoint::Public(lhs), ShamirAcvmPoint::Public(rhs)) => {
                ShamirAcvmPoint::Public(lhs + rhs)
            }
            (ShamirAcvmPoint::Public(public), ShamirAcvmPoint::Shared(mut shared))
            | (ShamirAcvmPoint::Shared(mut shared), ShamirAcvmPoint::Public(public)) => {
                pointshare::add_assign_public(&mut shared, &public);
                ShamirAcvmPoint::Shared(shared)
            }
            (ShamirAcvmPoint::Shared(lhs), ShamirAcvmPoint::Shared(rhs)) => {
                let result = pointshare::add(&lhs, &rhs);
                ShamirAcvmPoint::Shared(result)
            }
        }
    }

    fn add_points_other<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &self,
        lhs: Self::NativeAcvmPoint<C>,
        rhs: Self::NativeAcvmPoint<C>,
    ) -> Self::NativeAcvmPoint<C> {
        match (lhs, rhs) {
            (ShamirAcvmPoint::Public(lhs), ShamirAcvmPoint::Public(rhs)) => {
                ShamirAcvmPoint::Public(lhs + rhs)
            }
            (ShamirAcvmPoint::Public(public), ShamirAcvmPoint::Shared(mut shared))
            | (ShamirAcvmPoint::Shared(mut shared), ShamirAcvmPoint::Public(public)) => {
                pointshare::add_assign_public(&mut shared, &public);
                ShamirAcvmPoint::Shared(shared)
            }
            (ShamirAcvmPoint::Shared(lhs), ShamirAcvmPoint::Shared(rhs)) => {
                let result = pointshare::add(&lhs, &rhs);
                ShamirAcvmPoint::Shared(result)
            }
        }
    }

    fn sub(&self, share_1: Self::AcvmType, share_2: Self::AcvmType) -> Self::AcvmType {
        match (share_1, share_2) {
            (ShamirAcvmType::Public(share_1), ShamirAcvmType::Public(share_2)) => {
                ShamirAcvmType::Public(share_1 - share_2)
            }
            (ShamirAcvmType::Public(share_1), ShamirAcvmType::Shared(share_2)) => {
                ShamirAcvmType::Shared(arithmetic::add_public(-share_2, share_1))
            }
            (ShamirAcvmType::Shared(share_1), ShamirAcvmType::Public(share_2)) => {
                ShamirAcvmType::Shared(arithmetic::add_public(share_1, -share_2))
            }
            (ShamirAcvmType::Shared(share_1), ShamirAcvmType::Shared(share_2)) => {
                let result = arithmetic::sub(share_1, share_2);
                ShamirAcvmType::Shared(result)
            }
        }
    }

    fn mul_with_public(&mut self, public: F, secret: Self::AcvmType) -> Self::AcvmType {
        match secret {
            ShamirAcvmType::Public(secret) => ShamirAcvmType::Public(public * secret),
            ShamirAcvmType::Shared(secret) => {
                ShamirAcvmType::Shared(arithmetic::mul_public(secret, public))
            }
        }
    }

    fn mul(
        &mut self,
        secret_1: Self::AcvmType,
        secret_2: Self::AcvmType,
    ) -> eyre::Result<Self::AcvmType> {
        match (secret_1, secret_2) {
            (ShamirAcvmType::Public(secret_1), ShamirAcvmType::Public(secret_2)) => {
                Ok(ShamirAcvmType::Public(secret_1 * secret_2))
            }
            (ShamirAcvmType::Public(secret_1), ShamirAcvmType::Shared(secret_2)) => Ok(
                ShamirAcvmType::Shared(arithmetic::mul_public(secret_2, secret_1)),
            ),
            (ShamirAcvmType::Shared(secret_1), ShamirAcvmType::Public(secret_2)) => Ok(
                ShamirAcvmType::Shared(arithmetic::mul_public(secret_1, secret_2)),
            ),
            (ShamirAcvmType::Shared(secret_1), ShamirAcvmType::Shared(secret_2)) => {
                let result = arithmetic::mul(secret_1, secret_2, self.net, &mut self.state)?;
                Ok(ShamirAcvmType::Shared(result))
            }
        }
    }

    fn invert(&mut self, secret: Self::AcvmType) -> eyre::Result<Self::AcvmType> {
        match secret {
            ShamirAcvmType::Public(secret) => {
                let inv = secret
                    .inverse()
                    .ok_or_else(|| eyre::eyre!("Cannot invert zero"))?;
                Ok(ShamirAcvmType::Public(inv))
            }
            ShamirAcvmType::Shared(secret) => {
                let inv = arithmetic::inv(secret, self.net, &mut self.state)?;
                Ok(ShamirAcvmType::Shared(inv))
            }
        }
    }

    fn negate_inplace(&mut self, a: &mut Self::AcvmType) {
        match a {
            ShamirAcvmType::Public(public) => {
                public.neg_in_place();
            }
            ShamirAcvmType::Shared(shared) => *shared = arithmetic::neg(*shared),
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

    fn add_assign(&mut self, target: &mut Self::AcvmType, rhs: Self::AcvmType) {
        let result = match (*target, rhs) {
            (ShamirAcvmType::Public(lhs), ShamirAcvmType::Public(rhs)) => {
                ShamirAcvmType::Public(lhs + rhs)
            }
            (ShamirAcvmType::Public(public), ShamirAcvmType::Shared(shared))
            | (ShamirAcvmType::Shared(shared), ShamirAcvmType::Public(public)) => {
                ShamirAcvmType::Shared(arithmetic::add_public(shared, public))
            }
            (ShamirAcvmType::Shared(lhs), ShamirAcvmType::Shared(rhs)) => {
                ShamirAcvmType::Shared(arithmetic::add(lhs, rhs))
            }
        };
        *target = result;
    }

    fn add_assign_other<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        lhs: &mut Self::OtherAcvmType<C>,
        rhs: Self::OtherAcvmType<C>,
    ) {
        let result = match (*lhs, rhs) {
            (ShamirAcvmType::Public(lhs), ShamirAcvmType::Public(rhs)) => {
                ShamirAcvmType::Public(lhs + rhs)
            }
            (ShamirAcvmType::Public(public), ShamirAcvmType::Shared(shared))
            | (ShamirAcvmType::Shared(shared), ShamirAcvmType::Public(public)) => {
                ShamirAcvmType::Shared(arithmetic::add_public(shared, public))
            }
            (ShamirAcvmType::Shared(lhs), ShamirAcvmType::Shared(rhs)) => {
                ShamirAcvmType::Shared(arithmetic::add(lhs, rhs))
            }
        };
        *lhs = result;
    }

    fn solve_mul_term(
        &mut self,
        c: F,
        lhs: Self::AcvmType,
        rhs: Self::AcvmType,
    ) -> eyre::Result<Self::AcvmType> {
        let result = match (lhs, rhs) {
            (ShamirAcvmType::Public(lhs), ShamirAcvmType::Public(rhs)) => {
                ShamirAcvmType::Public(lhs * rhs * c)
            }
            (ShamirAcvmType::Public(public), ShamirAcvmType::Shared(shared))
            | (ShamirAcvmType::Shared(shared), ShamirAcvmType::Public(public)) => {
                ShamirAcvmType::Shared(arithmetic::mul_public(shared, public))
            }
            (ShamirAcvmType::Shared(lhs), ShamirAcvmType::Shared(rhs)) => {
                let shared_mul = arithmetic::mul(lhs, rhs, self.net, &mut self.state)?;
                ShamirAcvmType::Shared(arithmetic::mul_public(shared_mul, c))
            }
        };
        Ok(result)
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
                let result = arithmetic::div_public_by_shared(-c, q_l, self.net, &mut self.state)?;
                ShamirAcvmType::Shared(result)
            }
            (ShamirAcvmType::Shared(q_l), ShamirAcvmType::Shared(c)) => {
                let result = arithmetic::div(arithmetic::neg(c), q_l, self.net, &mut self.state)?;
                ShamirAcvmType::Shared(result)
            }
        };
        Ok(result)
    }

    fn init_lut_by_acvm_type(
        &mut self,
        _values: Vec<Self::AcvmType>,
    ) -> <Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType {
        panic!("init_lut_by_acvm_type: Operation atm not supported")
    }

    fn read_lut_by_acvm_type(
        &mut self,
        _index: Self::AcvmType,
        _lut: &<Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType,
    ) -> eyre::Result<Self::AcvmType> {
        panic!("read_lut_by_acvm_type: Operation atm not supported")
    }

    fn read_from_public_luts(
        &mut self,
        _index: Self::AcvmType,
        _luts: &[Vec<F>],
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        panic!("read_from_public_luts: Operation atm not supported")
    }

    fn write_lut_by_acvm_type(
        &mut self,
        _index: Self::AcvmType,
        _value: Self::AcvmType,
        _lut: &mut <Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType,
    ) -> eyre::Result<()> {
        panic!("write_lut_by_acvm_type: Operation atm not supported")
    }

    fn one_hot_vector_from_shared_index(
        &mut self,
        _index: Self::ArithmeticShare,
        _len: usize,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        panic!("one_hot_vector_from_shared_index: Operation atm not supported")
    }

    fn one_hot_vector_from_shared_index_other<
        C: CurveGroup<ScalarField = F, BaseField: PrimeField>,
    >(
        &mut self,
        _index: Self::OtherArithmeticShare<C>,
        _len: usize,
    ) -> eyre::Result<Vec<Self::OtherArithmeticShare<C>>> {
        panic!("one_hot_vector_from_shared_index_other: Operation atm not supported")
    }

    fn write_to_shared_lut_from_ohv(
        &mut self,
        _ohv: &[Self::ArithmeticShare],
        _value: Self::ArithmeticShare,
        _lut: &mut [Self::ArithmeticShare],
    ) -> eyre::Result<()> {
        panic!("write_to_shared_lut_from_ohv: Operation atm not supported")
    }

    fn get_length_of_lut(
        _lut: &<Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType,
    ) -> usize {
        panic!("get_length_of_lut: Operation atm not supported")
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

    fn get_shared_other<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        a: &Self::OtherAcvmType<C>,
    ) -> Option<Self::OtherArithmeticShare<C>> {
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

    fn get_public_point<C: CurveGroup<BaseField = F>>(
        a: &Self::CycleGroupAcvmPoint<C>,
    ) -> Option<C> {
        match a {
            ShamirAcvmPoint::Public(public) => Some(*public),
            _ => None,
        }
    }

    fn open_many(&mut self, a: &[Self::ArithmeticShare]) -> eyre::Result<Vec<F>> {
        arithmetic::open_vec(a, self.net, &mut self.state)
    }

    fn open_many_other<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        _a: &[Self::OtherArithmeticShare<C>],
    ) -> eyre::Result<Vec<C::BaseField>> {
        panic!("open_many_other not implemented for Shamir")
    }

    fn promote_to_trivial_share(&mut self, public_value: F) -> Self::ArithmeticShare {
        arithmetic::promote_to_trivial_share(public_value)
    }

    fn promote_to_trivial_shares(&mut self, public_values: &[F]) -> Vec<Self::ArithmeticShare> {
        arithmetic::promote_to_trivial_shares(public_values)
    }

    fn decompose_arithmetic(
        &mut self,
        _input: Self::ArithmeticShare,
        _total_bit_size_per_field: usize,
        _decompose_bit_size: usize,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        panic!("functionality decompose_arithmetic not feasible for Shamir")
    }
    fn decompose_arithmetic_many(
        &mut self,
        _input: &[Self::ArithmeticShare],
        _total_bit_size_per_field: usize,
        _decompose_bit_size: usize,
    ) -> eyre::Result<Vec<Vec<Self::ArithmeticShare>>> {
        panic!("functionality decompose_arithmetic_many not feasible for Shamir")
    }

    fn sort(
        &mut self,
        inputs: &[Self::AcvmType],
        bitsize: usize,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        if inputs.iter().any(|x| Self::is_shared(x)) {
            panic!("functionality sort not feasible for Shamir")
        } else {
            let public: Vec<F> = inputs
                .iter()
                .map(|input| Self::get_public(input).unwrap())
                .collect();
            let mut result: Vec<_> = Vec::with_capacity(inputs.len());
            let mask = (BigUint::from(1u64) << bitsize) - BigUint::one();
            for x in public.iter() {
                let mut x: BigUint = (*x).into();
                x &= &mask;
                result.push(F::from(x));
            }
            result.sort();

            result
                .iter()
                .map(|x| Ok(arithmetic::promote_to_trivial_share(*x)))
                .collect()
        }
    }

    fn slice(
        &mut self,
        _input: Self::ArithmeticShare,
        _msb: u8,
        _lsb: u8,
        _bitsize: usize,
    ) -> eyre::Result<[Self::ArithmeticShare; 3]> {
        panic!("functionality slice not feasible for Shamir")
    }

    fn right_shift(
        &mut self,
        _input: Self::AcvmType,
        _shift: usize,
    ) -> eyre::Result<Self::AcvmType> {
        panic!("functionality right_shift not feasible for Shamir")
    }

    fn integer_bitwise_and(
        &mut self,
        lhs: Self::AcvmType,
        rhs: Self::AcvmType,
        num_bits: u32,
    ) -> eyre::Result<Self::AcvmType> {
        debug_assert!(num_bits <= 128);
        let mask = (BigUint::one() << num_bits) - BigUint::one();
        match (lhs, rhs) {
            (ShamirAcvmType::Public(lhs), ShamirAcvmType::Public(rhs)) => {
                let lhs: BigUint = lhs.into();
                let rhs: BigUint = rhs.into();
                let res = (lhs & rhs) & mask;
                let res = F::from(res);
                Ok(ShamirAcvmType::Public(res))
            }
            _ => panic!("functionality bitwise_and not feasible for Shamir"),
        }
    }

    fn integer_bitwise_xor(
        &mut self,
        lhs: Self::AcvmType,
        rhs: Self::AcvmType,
        num_bits: u32,
    ) -> eyre::Result<Self::AcvmType> {
        debug_assert!(num_bits <= 128);
        let mask = (BigUint::one() << num_bits) - BigUint::one();
        match (lhs, rhs) {
            (ShamirAcvmType::Public(lhs), ShamirAcvmType::Public(rhs)) => {
                let lhs: BigUint = lhs.into();
                let rhs: BigUint = rhs.into();
                let res = (lhs ^ rhs) & mask;
                let res = F::from(res);
                Ok(ShamirAcvmType::Public(res))
            }
            _ => panic!("functionality bitwise_xor not feasible for Shamir"),
        }
    }

    fn slice_and_get_and_rotate_values(
        &mut self,
        _input1: Self::ArithmeticShare,
        _input2: Self::ArithmeticShare,
        _basis_bits: usize,
        _total_bitsize: usize,
        _rotation: usize,
    ) -> eyre::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )> {
        panic!("functionality slice_and_get_and_rotate_values not feasible for Shamir")
    }

    fn slice_and_get_xor_rotate_values(
        &mut self,
        _input1: Self::ArithmeticShare,
        _input2: Self::ArithmeticShare,
        _basis_bits: usize,
        _total_bitsize: usize,
        _rotation: usize,
    ) -> eyre::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )> {
        panic!("functionality slice_and_get_xor_rotate_values not feasible for Shamir")
    }

    fn slice_and_get_xor_rotate_values_with_filter(
        &mut self,
        _input1: Self::ArithmeticShare,
        _input2: Self::ArithmeticShare,
        _basis_bits: &[u64],
        _rotation: &[usize],
        _filter: &[bool],
    ) -> eyre::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )> {
        panic!("functionality slice_and_get_xor_rotate_values_with_filter not feasible for Shamir")
    }

    fn sort_vec_by(
        &mut self,
        _key: &[Self::AcvmType],
        _inputs: Vec<&[Self::ArithmeticShare]>,
        _bitsize: usize,
    ) -> eyre::Result<Vec<Vec<Self::ArithmeticShare>>> {
        panic!("functionality sort_vec_by not feasible for Shamir")
    }

    fn poseidon2_permutation<const T: usize, const D: u64>(
        &mut self,
        mut input: Vec<Self::AcvmType>,
        poseidon2: &Poseidon2<F, T, D>,
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        if input.len() != T {
            eyre::bail!("Expected {} values but encountered {}", T, input.len());
        }

        if input.iter().any(|x| Self::is_shared(x)) {
            let mut shared = array::from_fn(|i| match input[i] {
                ShamirAcvmType::Public(public) => {
                    // The initial linear layer of poseidon makes the whole state shared anyway
                    arithmetic::promote_to_trivial_share(public)
                }
                ShamirAcvmType::Shared(shared) => shared,
            });
            let mut precomp = poseidon2.precompute_shamir(1, self.net, &mut self.state)?;
            poseidon2.shamir_permutation_in_place_with_precomputation(
                &mut shared,
                &mut precomp,
                self.net,
                &mut self.state,
            )?;

            for (src, des) in shared.into_iter().zip(input.iter_mut()) {
                *des = ShamirAcvmType::Shared(src);
            }
        } else {
            let mut public = array::from_fn(|i| Self::get_public(&input[i]).unwrap());
            poseidon2.permutation_in_place(&mut public);

            for (src, des) in public.into_iter().zip(input.iter_mut()) {
                *des = ShamirAcvmType::Public(src);
            }
        }

        Ok(input)
    }

    fn poseidon2_matmul_external_inplace<const T: usize, const D: u64>(
        &self,
        input: &mut [Self::ArithmeticShare; T],
    ) {
        Poseidon2::<F, T, D>::matmul_external_shamir(input);
    }

    fn poseidon2_preprocess_permutation<const T: usize, const D: u64>(
        &mut self,
        num_poseidon: usize,
        poseidon2: &Poseidon2<F, T, D>,
    ) -> eyre::Result<Poseidon2Precomputations<Self::ArithmeticShare>> {
        // Prepare enough randomness
        self.state
            .buffer_triples(self.net, poseidon2.rand_required(num_poseidon, true))?;
        poseidon2.precompute_shamir(num_poseidon, self.net, &mut self.state)
    }

    fn poseidon2_external_round_inplace_with_precomp<const T: usize, const D: u64>(
        &mut self,
        input: &mut [Self::ArithmeticShare; T],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Self::ArithmeticShare>,
        poseidon2: &Poseidon2<F, T, D>,
    ) -> eyre::Result<()> {
        poseidon2.shamir_external_round_precomp(input, r, precomp, self.net, &mut self.state)
    }

    fn poseidon2_internal_round_inplace_with_precomp<const T: usize, const D: u64>(
        &mut self,
        input: &mut [Self::ArithmeticShare; T],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Self::ArithmeticShare>,
        poseidon2: &Poseidon2<F, T, D>,
    ) -> eyre::Result<()> {
        poseidon2.shamir_internal_round_precomp(input, r, precomp, self.net, &mut self.state)
    }

    fn get_public_lut(
        _lut: &<Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType,
    ) -> eyre::Result<&Vec<F>> {
        panic!("functionality get_public_lut not feasible for Shamir")
    }

    fn is_public_lut(
        _lut: &<Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType,
    ) -> bool {
        panic!("functionality is_public_lut not feasible for Shamir")
    }

    fn equal(&mut self, _a: &Self::AcvmType, _b: &Self::AcvmType) -> eyre::Result<Self::AcvmType> {
        panic!("functionality equal not feasible for Shamir")
    }

    fn equal_other<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        _a: &Self::OtherAcvmType<C>,
        _b: &Self::OtherAcvmType<C>,
    ) -> eyre::Result<Self::OtherAcvmType<C>> {
        panic!("functionality equal not feasible for Shamir")
    }

    fn equal_many(
        &mut self,
        _a: &[Self::AcvmType],
        _b: &[Self::AcvmType],
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        panic!("functionality equal_many not feasible for Shamir")
    }

    fn equal_many_other<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        _a: &[Self::OtherAcvmType<C>],
        _b: &[Self::OtherAcvmType<C>],
    ) -> eyre::Result<Vec<Self::OtherAcvmType<C>>> {
        panic!("functionality equal_many_other not feasible for Shamir")
    }

    fn multi_scalar_mul(
        &mut self,
        _points: &[Self::AcvmType],
        _scalars_lo: &[Self::AcvmType],
        _scalars_hi: &[Self::AcvmType],
        _pedantic_solving: bool,
    ) -> eyre::Result<(Self::AcvmType, Self::AcvmType, Self::AcvmType)> {
        panic!("functionality multi_scalar_mul not feasible for Shamir")
    }

    fn field_shares_to_pointshare<C: CurveGroup<BaseField = F>>(
        &mut self,
        _x: Self::AcvmType,
        _y: Self::AcvmType,
        _is_infinity: Self::AcvmType,
    ) -> eyre::Result<Self::CycleGroupAcvmPoint<C>> {
        panic!("functionality field_share_to_pointshare not feasible for Shamir")
    }

    fn pointshare_to_field_shares<C: CurveGroup<BaseField = F>>(
        &mut self,
        _point: Self::CycleGroupAcvmPoint<C>,
    ) -> eyre::Result<(Self::AcvmType, Self::AcvmType, Self::AcvmType)> {
        panic!("functionality pointshare_to_field_shares not feasible for Shamir")
    }

    fn gt(&mut self, _lhs: Self::AcvmType, _rhs: Self::AcvmType) -> eyre::Result<Self::AcvmType> {
        panic!("functionality gt not feasible for Shamir")
    }

    fn set_point_to_value_if_zero<C: CurveGroup<BaseField = F>>(
        &mut self,
        _point: Self::CycleGroupAcvmPoint<C>,
        _value: Self::CycleGroupAcvmPoint<C>,
    ) -> eyre::Result<Self::CycleGroupAcvmPoint<C>> {
        panic!("functionality set_point_to_value_if_zero not feasible for Shamir")
    }

    fn sha256_compression(
        &mut self,
        _state: &[Self::AcvmType; 8],
        _message: &[Self::AcvmType; 16],
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        panic!("functionality sha256_compression not feasible for Shamir")
    }

    fn sha256_get_overflow_bit(
        &mut self,
        _input: Self::ArithmeticShare,
    ) -> eyre::Result<Self::ArithmeticShare> {
        panic!("functionality sha256_get_overflow_bit not feasible for Shamir")
    }

    fn slice_and_get_sparse_table_with_rotation_values(
        &mut self,
        _input1: Self::ArithmeticShare,
        _input2: Self::ArithmeticShare,
        _basis_bits: &[u64],
        _rotation: &[u32],
        _total_bitsize: usize,
        _base: u64,
    ) -> eyre::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )> {
        panic!(
            "functionality slice_and_get_sparse_table_with_rotation_values not feasible for Shamir"
        )
    }

    fn slice_and_get_sparse_normalization_values(
        &mut self,
        _input1: Self::ArithmeticShare,
        _input2: Self::ArithmeticShare,
        _base_bits: &[u64],
        _base: u64,
        _total_output_bitlen_per_field: usize,
        _table_type: &SHA256Table,
    ) -> eyre::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )> {
        panic!("functionality slice_and_get_sparse_normalization_values not feasible for Shamir")
    }

    fn blake2s_hash(
        &mut self,
        _message_input: Vec<Self::AcvmType>,
        _num_bits: &[usize],
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        panic!("functionality blake2s_hash not feasible for Shamir")
    }

    fn blake3_hash(
        &mut self,
        _message_input: Vec<Self::AcvmType>,
        _num_bits: &[usize],
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        panic!("functionality blake2s_hash not feasible for Shamir")
    }

    fn embedded_curve_add(
        &mut self,
        _input1_x: Self::AcvmType,
        _input1_y: Self::AcvmType,
        _input1_infinite: Self::AcvmType,
        _input2_x: Self::AcvmType,
        _input2_y: Self::AcvmType,
        _input2_infinite: Self::AcvmType,
    ) -> eyre::Result<(Self::AcvmType, Self::AcvmType, Self::AcvmType)> {
        panic!("functionality embedded_curve_add not feasible for Shamir")
    }

    fn aes128_encrypt(
        &mut self,
        _scalars: &[Self::AcvmType],
        _iv: Vec<Self::AcvmType>,
        _key: Vec<Self::AcvmType>,
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        panic!("functionality aes128_encrypt not feasible for Shamir")
    }

    fn slice_and_get_aes_sparse_normalization_values_from_key(
        &mut self,
        _input1: Self::ArithmeticShare,
        _input2: Self::ArithmeticShare,
        _base_bits: &[u64],
        _base: u64,
    ) -> eyre::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )> {
        panic!(
            "functionality slice_and_get_aes_sparse_normalization_values_from_key not feasible for Shamir"
        )
    }

    fn slice_and_get_aes_sbox_values_from_key(
        &mut self,
        _input1: Self::ArithmeticShare,
        _input2: Self::ArithmeticShare,
        _base_bits: &[u64],
        _base: u64,
        _sbox: &[u8],
    ) -> eyre::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )> {
        panic!("functionality slice_and_get_aes_sbox_values_from_key not feasible for Shamir")
    }

    fn accumulate_from_sparse_bytes(
        &mut self,
        _inputs: &[Self::AcvmType],
        _base: u64,
        _input_bitsize: usize,
        _output_bitsize: usize,
    ) -> eyre::Result<Self::AcvmType> {
        panic!("functionality accumulate_from_sparse_bytes not feasible for Shamir")
    }

    fn is_zero(&mut self, _a: &Self::AcvmType) -> eyre::Result<Self::AcvmType> {
        panic!("functionality is_zero not feasible for Shamir")
    }

    fn other_pointshare_to_other_field_share<
        C: CurveGroup<ScalarField = F, BaseField: PrimeField>,
    >(
        &mut self,
        _point: &Self::NativeAcvmPoint<C>,
    ) -> eyre::Result<(
        Self::OtherAcvmType<C>,
        Self::OtherAcvmType<C>,
        Self::OtherAcvmType<C>,
    )> {
        panic!("functionality pointshare_to_field_shares not feasible for Shamir")
    }

    fn other_pointshare_to_other_field_shares_many<
        C: CurveGroup<ScalarField = F, BaseField: PrimeField>,
    >(
        &mut self,
        _point: &[Self::NativeAcvmPoint<C>],
    ) -> eyre::Result<(
        Vec<Self::OtherAcvmType<C>>,
        Vec<Self::OtherAcvmType<C>>,
        Vec<Self::OtherAcvmType<C>>,
    )> {
        panic!("functionality pointshare_to_field_shares_many not feasible for Shamir")
    }

    fn mul_other<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        _secret_1: Self::OtherAcvmType<C>,
        _secret_2: Self::OtherAcvmType<C>,
    ) -> eyre::Result<Self::OtherAcvmType<C>> {
        unimplemented!("mul_other is not implemented for Shamir")
    }

    fn mul_many_other<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        _secrets_1: &[Self::OtherAcvmType<C>],
        _secrets_2: &[Self::OtherAcvmType<C>],
    ) -> eyre::Result<Vec<Self::OtherAcvmType<C>>> {
        unimplemented!("mul_many_other is not implemented for Shamir")
    }

    fn is_zero_many_other<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        _a: &[Self::OtherAcvmType<C>],
    ) -> eyre::Result<Vec<Self::OtherAcvmType<C>>> {
        panic!("functionality is_zero_many not feasible for Shamir")
    }

    fn add_other<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &self,
        lhs: Self::OtherAcvmType<C>,
        rhs: Self::OtherAcvmType<C>,
    ) -> Self::OtherAcvmType<C> {
        match (lhs, rhs) {
            (ShamirAcvmType::Public(lhs), ShamirAcvmType::Public(rhs)) => {
                ShamirAcvmType::Public(lhs + rhs)
            }
            (ShamirAcvmType::Public(public), ShamirAcvmType::Shared(shared))
            | (ShamirAcvmType::Shared(shared), ShamirAcvmType::Public(public)) => {
                ShamirAcvmType::Shared(arithmetic::add_public(shared, public))
            }
            (ShamirAcvmType::Shared(lhs), ShamirAcvmType::Shared(rhs)) => {
                let result = arithmetic::add(lhs, rhs);
                ShamirAcvmType::Shared(result)
            }
        }
    }

    fn sub_points<C: CurveGroup<BaseField = F>>(
        &self,
        lhs: Self::CycleGroupAcvmPoint<C>,
        rhs: Self::CycleGroupAcvmPoint<C>,
    ) -> Self::CycleGroupAcvmPoint<C> {
        match (lhs, rhs) {
            (ShamirAcvmPoint::Public(lhs), ShamirAcvmPoint::Public(rhs)) => {
                ShamirAcvmPoint::Public(lhs - rhs)
            }
            (ShamirAcvmPoint::Public(public), ShamirAcvmPoint::Shared(mut shared))
            | (ShamirAcvmPoint::Shared(mut shared), ShamirAcvmPoint::Public(public)) => {
                pointshare::sub_assign_public(&mut shared, &public);
                ShamirAcvmPoint::Shared(shared)
            }
            (ShamirAcvmPoint::Shared(lhs), ShamirAcvmPoint::Shared(rhs)) => {
                let result = pointshare::sub(&lhs, &rhs);
                ShamirAcvmPoint::Shared(result)
            }
        }
    }

    fn sub_other<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &self,
        lhs: Self::OtherAcvmType<C>,
        rhs: Self::OtherAcvmType<C>,
    ) -> Self::OtherAcvmType<C> {
        match (lhs, rhs) {
            (ShamirAcvmType::Public(share_1), ShamirAcvmType::Public(share_2)) => {
                ShamirAcvmType::Public(share_1 - share_2)
            }
            (ShamirAcvmType::Public(share_1), ShamirAcvmType::Shared(share_2)) => {
                ShamirAcvmType::Shared(arithmetic::add_public(-share_2, share_1))
            }
            (ShamirAcvmType::Shared(share_1), ShamirAcvmType::Public(share_2)) => {
                ShamirAcvmType::Shared(arithmetic::add_public(share_1, -share_2))
            }
            (ShamirAcvmType::Shared(share_1), ShamirAcvmType::Shared(share_2)) => {
                let result = arithmetic::sub(share_1, share_2);
                ShamirAcvmType::Shared(result)
            }
        }
    }

    fn mul_assign_with_public(shared: &mut Self::AcvmType, public: F) {
        let result = match shared.to_owned() {
            ShamirAcvmType::Public(secret) => ShamirAcvmType::Public(public * secret),
            ShamirAcvmType::Shared(secret) => {
                ShamirAcvmType::Shared(arithmetic::mul_public(secret, public))
            }
        };
        *shared = result;
    }

    fn mul_with_public_other<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        public: C::BaseField,
        secret: Self::OtherAcvmType<C>,
    ) -> Self::OtherAcvmType<C> {
        match secret {
            ShamirAcvmType::Public(secret) => ShamirAcvmType::Public(public * secret),
            ShamirAcvmType::Shared(secret) => {
                ShamirAcvmType::Shared(arithmetic::mul_public(secret, public))
            }
        }
    }

    fn init_lut_by_acvm_point<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        _values: Vec<Self::NativeAcvmPoint<C>>,
    ) -> <Self::CurveLookup<C> as LookupTableProvider<C>>::LutType {
        panic!("functionality init_lut_by_acvm_point not feasible for Shamir")
    }

    fn read_lut_by_acvm_point<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        _index: Self::AcvmType,
        _lut: &<Self::CurveLookup<C> as LookupTableProvider<C>>::LutType,
    ) -> eyre::Result<Self::NativeAcvmPoint<C>> {
        panic!("functionality read_lut_by_acvm_point not feasible for Shamir")
    }

    fn read_from_public_curve_luts<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        _index: Self::AcvmType,
        _luts: &[Vec<C>],
    ) -> eyre::Result<Vec<Self::NativeAcvmPoint<C>>> {
        panic!("functionality read_from_public_curve_luts not feasible for Shamir")
    }

    fn write_lut_by_acvm_point<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        _index: Self::AcvmType,
        _value: Self::NativeAcvmPoint<C>,
        _lut: &mut <Self::CurveLookup<C> as LookupTableProvider<C>>::LutType,
    ) -> eyre::Result<()> {
        panic!("functionality write_lut_by_acvm_point not feasible for Shamir")
    }

    fn point_is_zero_many<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        _a: &[Self::NativeAcvmPoint<C>],
    ) -> eyre::Result<Vec<Self::OtherAcvmType<C>>> {
        panic!("functionality point_is_zero_many not feasible for Shamir")
    }

    fn msm<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        _points: &[Self::NativeAcvmPoint<C>],
        _scalars: &[Self::AcvmType],
    ) -> eyre::Result<Self::NativeAcvmPoint<C>> {
        unimplemented!("msm not implemented for Shamir")
    }

    fn scale_native_point<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        point: Self::NativeAcvmPoint<C>,
        scalar: Self::AcvmType,
    ) -> eyre::Result<Self::NativeAcvmPoint<C>> {
        match (point, scalar) {
            (ShamirAcvmPoint::Public(public), ShamirAcvmType::Public(scalar)) => {
                Ok(ShamirAcvmPoint::Public(public * scalar))
            }
            (ShamirAcvmPoint::Public(point), ShamirAcvmType::Shared(shared)) => Ok(
                ShamirAcvmPoint::Shared(pointshare::scalar_mul_public_point(shared, &point)),
            ),
            (ShamirAcvmPoint::Shared(shared), ShamirAcvmType::Public(scalar)) => Ok(
                ShamirAcvmPoint::Shared(pointshare::scalar_mul_public_scalar(&shared, &scalar)),
            ),
            (ShamirAcvmPoint::Shared(_), ShamirAcvmType::Shared(_)) => {
                unimplemented!("not implemented for Shamir")
            }
        }
    }

    fn convert_fields<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        _a: &[Self::OtherAcvmType<C>],
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        unimplemented!("convert_fields not implemented for Shamir")
    }

    fn compute_wnaf_digits_and_compute_rows_many<
        C: CurveGroup<ScalarField = F, BaseField: PrimeField>,
    >(
        &mut self,
        _zs: &[Self::OtherAcvmType<C>],
        _num_bits: usize,
    ) -> eyre::Result<(
        Vec<Self::OtherAcvmType<C>>,       // Returns whether the input is even
        Vec<[Self::OtherAcvmType<C>; 32]>, // Returns the wnaf digits (They are already positive (by adding +15 (and also dividing by 2)))
        Vec<[Self::OtherAcvmType<C>; 32]>, // Returns whether the wnaf digit is negative
        Vec<[Self::OtherAcvmType<C>; 64]>, // Returns s1,...,s8 for every 4 wnaf digits (needed later for PointTablePrecomputationRow computation)
        Vec<[Self::OtherAcvmType<C>; 8]>, // Returns the (absolute) value of the row_chunk (also in PointTablePrecomputationRow computation)
        Vec<[Self::OtherAcvmType<C>; 8]>, // Returns the sign of the row_chunk (also in PointTablePrecomputationRow computation)
    )> {
        unimplemented!("compute_wnaf_digits_and_compute_rows_many not implemented for Shamir")
    }

    fn compute_endo_point<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        _point: &Self::NativeAcvmPoint<C>,
        _cube_root_of_unity: C::BaseField,
    ) -> eyre::Result<Self::NativeAcvmPoint<C>> {
        unimplemented!("compute_endo_point not implemented for Shamir")
    }

    fn is_shared_point<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        a: &Self::NativeAcvmPoint<C>,
    ) -> bool {
        match a {
            ShamirAcvmPoint::Shared(_) => true,
            ShamirAcvmPoint::Public(_) => false,
        }
    }

    fn is_shared_other<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        a: &Self::OtherAcvmType<C>,
    ) -> bool {
        match a {
            ShamirAcvmType::Shared(_) => true,
            ShamirAcvmType::Public(_) => false,
        }
    }

    fn get_public_other<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        a: &Self::OtherAcvmType<C>,
    ) -> Option<C::BaseField> {
        match a {
            ShamirAcvmType::Public(public) => Some(*public),
            _ => None,
        }
    }

    fn inverse_or_zero_many_other<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        _secrets: &[Self::OtherAcvmType<C>],
    ) -> eyre::Result<Vec<Self::OtherAcvmType<C>>> {
        unimplemented!("inverse_or_zero_many not implemented for Shamir")
    }

    fn cmux_many_other<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        cond: &[Self::OtherAcvmType<C>],
        truthy: &[Self::OtherAcvmType<C>],
        falsy: &[Self::OtherAcvmType<C>],
    ) -> eyre::Result<Vec<Self::OtherAcvmType<C>>> {
        if cond.iter().any(|v| Self::is_shared_other::<C>(v)) {
            let b_min_a = self.sub_many_other::<C>(truthy, falsy);
            let d = self.mul_many_other::<C>(cond, &b_min_a)?;
            Ok(self.add_many_other::<C>(falsy, &d))
        } else {
            Ok(cond
                .iter()
                .zip(truthy)
                .zip(falsy)
                .map(|((c, t), f)| {
                    if let ShamirAcvmType::Public(c) = c {
                        assert!(c.is_one() || c.is_zero());
                        if c.is_one() { *t } else { *f }
                    } else {
                        unreachable!("We checked that all cond are public")
                    }
                })
                .collect())
        }
    }

    fn get_as_shared(&mut self, value: &Self::AcvmType) -> Self::ArithmeticShare {
        if Self::is_shared(value) {
            Self::get_shared(value).expect("Already checked it is shared")
        } else {
            self.promote_to_trivial_share(
                Self::get_public(value).expect("Already checked it is public"),
            )
        }
    }

    fn get_as_shared_other<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        value: &Self::OtherAcvmType<C>,
    ) -> Self::OtherArithmeticShare<C> {
        if Self::is_shared_other::<C>(value) {
            Self::get_shared_other::<C>(value).expect("Already checked it is shared")
        } else {
            arithmetic::promote_to_trivial_share(
                Self::get_public_other::<C>(value).expect("Already checked it is public"),
            )
        }
    }

    fn get_public_point_other<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        a: &Self::NativeAcvmPoint<C>,
    ) -> Option<C> {
        match a {
            ShamirAcvmPoint::Public(public) => Some(*public),
            _ => None,
        }
    }

    // checks if lhs <= rhs. Returns 1 if true, 0 otherwise.
    fn le(&mut self, _lhs: Self::AcvmType, _rhs: Self::AcvmType) -> eyre::Result<Self::AcvmType> {
        panic!("functionality le not feasible for Shamir")
    }

    /// Given a pointshare, decomposes it into its x and y coordinates and the is_infinity flag, all as base field shares
    fn native_point_to_other_acvm_types<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        _point: Self::NativeAcvmPoint<C>,
    ) -> eyre::Result<(
        Self::OtherAcvmType<C>,
        Self::OtherAcvmType<C>,
        Self::OtherAcvmType<C>,
    )> {
        panic!("functionality other_pointshare_to_other_field_shares not feasible for Shamir")
    }

    // TACEO TODO: Currently only supports LIMB_BITS = 136, i.e. two Bn254::Fr elements per Bn254::Fq element
    /// Converts a base field share into a vector of field shares, where the field shares
    /// represent the limbs of the base field element. Each limb has at most LIMB_BITS bits.
    fn other_field_shares_to_field_shares<
        const LIMB_BITS: usize,
        C: CurveGroup<ScalarField = F, BaseField: PrimeField>,
    >(
        &mut self,
        _input: Self::OtherAcvmType<C>,
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        panic!("functionality other_field_shares_to_field_shares not feasible for Shamir")
    }

    // Similar to decompose_arithmetic, but works on the full AcvmType, which can either be public or shared
    fn decompose_acvm_type(
        &mut self,
        _input: Self::AcvmType,
        _total_bit_size_per_field: usize,
        _decompose_bit_size: usize,
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        panic!("functionality decompose_acvm_type not feasible for Shamir")
    }

    // For each value in a, checks whether the value is zero. The result is a vector of ACVM-types that are 1 if the value is zero and 0 otherwise.
    fn is_zero_many(&mut self, _a: &[Self::AcvmType]) -> eyre::Result<Vec<Self::AcvmType>> {
        panic!("functionality is_zero_many not feasible for Shamir")
    }

    // For each point in a, checks whether the point is the point at infinity. The result is a vector of ACVM-types that are 1 if the point is at infinity and 0 otherwise.
    fn is_native_point_at_infinity_many<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        _a: &[Self::NativeAcvmPoint<C>],
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        panic!("functionality is_point_at_infinity_many_other not feasible for Shamir")
    }

    /// Multiply two slices of ACVM-types elementwise: \[c_i\] = \[secret_1_i\] * \[secret_2_i\].
    fn mul_many(
        &mut self,
        secrets_1: &[Self::AcvmType],
        secrets_2: &[Self::AcvmType],
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        if secrets_1.len() != secrets_2.len() {
            eyre::bail!("Vectors must have the same length");
        }
        // For each coordinate we have four cases:
        // 1. Both are shared
        // 2. First is shared, second is public
        // 3. First is public, second is shared
        // 4. Both are public
        // We handle case one separately, in order to use batching and then combine the results.
        let (all_shared_indices, any_public_indices): (Vec<usize>, Vec<usize>) = (0..secrets_1
            .len())
            .partition(|&i| Self::is_shared(&secrets_1[i]) && Self::is_shared(&secrets_2[i]));

        // Case 1: Both are shared
        let (indices, shares_1, shares_2): (
            Vec<usize>,
            Vec<Self::ArithmeticShare>,
            Vec<Self::ArithmeticShare>,
        ) = all_shared_indices
            .into_iter()
            .map(|i| {
                (
                    i,
                    Self::get_shared(&secrets_1[i]).unwrap(),
                    Self::get_shared(&secrets_2[i]).unwrap(),
                )
            })
            .multiunzip();
        let mul_all_shared = arithmetic::mul_vec(&shares_1, &shares_2, self.net, &mut self.state)?;
        let mul_all_shared = mul_all_shared.into_iter().map(ShamirAcvmType::Shared);
        let mul_all_shared_indexed = indices
            .into_iter()
            .zip(mul_all_shared)
            .collect::<Vec<(usize, Self::AcvmType)>>();

        // For all the other cases, we can just call self.mul
        let mul_any_public = any_public_indices
            .iter()
            .map(|&i| {
                let a = &secrets_1[i];
                let b = &secrets_2[i];
                self.mul(*a, *b)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mul_any_public_indexed = any_public_indices
            .into_iter()
            .zip(mul_any_public)
            .collect::<Vec<(usize, Self::AcvmType)>>();

        // Merge sort by index
        Ok(mul_all_shared_indexed
            .into_iter()
            .chain(mul_any_public_indexed)
            .sorted_by_key(|(i, _)| *i)
            .map(|(_, val)| val)
            .collect::<Vec<Self::AcvmType>>())
    }

    // Given two points, adds them together. Both can either be public or shared
    fn add_native_points<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &self,
        lhs: Self::NativeAcvmPoint<C>,
        rhs: Self::NativeAcvmPoint<C>,
    ) -> Self::NativeAcvmPoint<C> {
        match (lhs, rhs) {
            (ShamirAcvmPoint::Public(lhs), ShamirAcvmPoint::Public(rhs)) => {
                ShamirAcvmPoint::Public(lhs + rhs)
            }
            (ShamirAcvmPoint::Public(public), ShamirAcvmPoint::Shared(mut shared))
            | (ShamirAcvmPoint::Shared(mut shared), ShamirAcvmPoint::Public(public)) => {
                pointshare::add_assign_public(&mut shared, &public);
                ShamirAcvmPoint::Shared(shared)
            }
            (ShamirAcvmPoint::Shared(lhs), ShamirAcvmPoint::Shared(rhs)) => {
                ShamirAcvmPoint::Shared(pointshare::add(&lhs, &rhs))
            }
        }
    }

    fn msm_public_native_points<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        points: &[C::Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::NativeAcvmPoint<C> {
        ShamirAcvmPoint::Shared(pointshare::msm_public_points(points, scalars))
    }

    #[expect(clippy::type_complexity)]
    fn open_many_native_points<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        a: &[Self::NativeAcvmPoint<C>],
    ) -> eyre::Result<Vec<C::Affine>> {
        let (indexed_shares, indexed_public): (
            Vec<(usize, ShamirPointShare<C>)>,
            Vec<(usize, C::Affine)>,
        ) = a.iter().enumerate().partition_map(|(i, val)| match val {
            ShamirAcvmPoint::Shared(share) => Either::Left((i, *share)),
            ShamirAcvmPoint::Public(public) => Either::Right((i, public.into_affine())),
        });

        let (indices, shares): (Vec<usize>, Vec<ShamirPointShare<C>>) =
            indexed_shares.into_iter().unzip();

        let opened_shares = pointshare::open_point_many(&shares, self.net, &mut self.state)?
            .into_iter()
            .map(|p| p.into_affine())
            .collect::<Vec<_>>();
        let opened_shares = indices
            .into_iter()
            .zip(opened_shares)
            .collect::<Vec<(usize, C::Affine)>>();

        // Merge sort by index
        Ok(opened_shares
            .into_iter()
            .chain(indexed_public)
            .sorted_by_key(|(i, _)| *i)
            .map(|(_, val)| val)
            .collect::<Vec<C::Affine>>())
    }

    fn acvm_type_to_other_acvm_type_many<C: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        _value: &[Self::AcvmType],
    ) -> eyre::Result<Vec<Self::OtherAcvmType<C>>> {
        panic!("functionality acvm_type_to_other_acvm_type_many not feasible for Shamir")
    }
}
