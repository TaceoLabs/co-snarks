use super::plain::PlainAcvmSolver;
use super::{NoirWitnessExtensionProtocol, downcast};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, MontConfig, One, PrimeField, Zero};
use blake2::{Blake2s256, Digest};
use co_brillig::mpc::{Rep3BrilligDriver, Rep3BrilligType};
use co_noir_types::Rep3Type;
use itertools::{Itertools, izip};
use libaes::Cipher;
use mpc_core::MpcState as _;
use mpc_core::gadgets::poseidon2::{Poseidon2, Poseidon2Precomputations};
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_core::protocols::rep3::id::PartyID;
use mpc_core::protocols::rep3::yao::circuits::SHA256Table;
use mpc_core::protocols::rep3::{
    Rep3BigUintShare, Rep3PointShare, Rep3State, arithmetic, binary, conversion,
    network::Rep3NetworkExt, pointshare, yao,
};
use mpc_core::protocols::rep3_ring::gadgets::sort::{radix_sort_fields, radix_sort_fields_vec_by};
use mpc_core::{
    lut::LookupTableProvider, protocols::rep3::Rep3PrimeFieldShare,
    protocols::rep3_ring::lut::Rep3LookupTable,
};
use mpc_net::Network;
use num_bigint::BigUint;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::any::TypeId;
use std::array;
use std::marker::PhantomData;
use std::ops::BitXor;

type ArithmeticShare<F> = Rep3PrimeFieldShare<F>;

pub struct Rep3AcvmSolver<'a, F: PrimeField, N: Network> {
    id: PartyID,
    net0: &'a N,
    net1: &'a N,
    state0: Rep3State,
    state1: Rep3State,
    lut_provider: Rep3LookupTable<F>,
    plain_solver: PlainAcvmSolver<F>,
    phantom_data: PhantomData<F>,
}

impl<'a, F: PrimeField, N: Network> Rep3AcvmSolver<'a, F, N> {
    pub fn new(net0: &'a N, net1: &'a N, a2b_type: A2BType) -> eyre::Result<Self> {
        let mut state0 = Rep3State::new(net0, a2b_type)?;
        let state1 = state0.fork(0)?;
        Ok(Self {
            id: state0.id,
            net0,
            net1,
            state0,
            state1,
            lut_provider: Rep3LookupTable::new(),
            plain_solver: PlainAcvmSolver::<F>::default(),
            phantom_data: PhantomData,
        })
    }

    fn combine_grumpkin_scalar_field_limbs(
        low: &Rep3AcvmType<ark_bn254::Fr>,
        high: &Rep3AcvmType<ark_bn254::Fr>,
        net: &N,
        state: &mut Rep3State,
        pedantic_solving: bool,
    ) -> eyre::Result<Rep3AcvmType<ark_grumpkin::Fr>> {
        let scale = ark_grumpkin::Fr::from(BigUint::one() << 128);
        let res = match (low, high) {
            (Rep3AcvmType::Public(low), Rep3AcvmType::Public(high)) => {
                let scalar_low = PlainAcvmSolver::<F>::bn254_fr_to_u128(*low)?;
                let scalar_high = PlainAcvmSolver::<F>::bn254_fr_to_u128(*high)?;
                let grumpkin_integer: BigUint = (BigUint::from(scalar_high) << 128) + scalar_low;

                // Check if this is smaller than the grumpkin modulus
                if pedantic_solving && grumpkin_integer >= ark_grumpkin::FrConfig::MODULUS.into() {
                    eyre::bail!(
                        "{} is not a valid grumpkin scalar",
                        grumpkin_integer.to_str_radix(16)
                    );
                }
                Rep3AcvmType::Public(ark_grumpkin::Fr::from(grumpkin_integer))
            }
            (Rep3AcvmType::Public(low), Rep3AcvmType::Shared(high)) => {
                let scalar_low = PlainAcvmSolver::<F>::bn254_fr_to_u128(*low)?;
                // Change the sharing field
                let scalar_high = conversion::a2b(*high, net, state)?;
                let scalar_high =
                    Rep3BigUintShare::<ark_grumpkin::Fr>::new(scalar_high.a, scalar_high.b);
                let scalar_high = conversion::b2a(&scalar_high, net, state)?;

                let res = arithmetic::add_public(scalar_high * scale, scalar_low.into(), state.id);
                Rep3AcvmType::Shared(res)
            }
            (Rep3AcvmType::Shared(low), Rep3AcvmType::Public(high)) => {
                let scalar_high = PlainAcvmSolver::<F>::bn254_fr_to_u128(*high)?;
                // Change the sharing field
                let scalar_low = conversion::a2b(*low, net, state)?;
                let scalar_low =
                    Rep3BigUintShare::<ark_grumpkin::Fr>::new(scalar_low.a, scalar_low.b);
                let scalar_low = conversion::b2a(&scalar_low, net, state)?;

                let res = arithmetic::add_public(
                    scalar_low,
                    scale * ark_grumpkin::Fr::from(scalar_high),
                    state.id,
                );
                Rep3AcvmType::Shared(res)
            }
            (Rep3AcvmType::Shared(low), Rep3AcvmType::Shared(high)) => {
                // Change the sharing field

                // TODO parallelize these
                let scalar_low = conversion::a2b(*low, net, state)?;
                let scalar_low =
                    Rep3BigUintShare::<ark_grumpkin::Fr>::new(scalar_low.a, scalar_low.b);
                let scalar_low = conversion::b2a(&scalar_low, net, state)?;

                let scalar_high = conversion::a2b(*high, net, state)?;
                let scalar_high =
                    Rep3BigUintShare::<ark_grumpkin::Fr>::new(scalar_high.a, scalar_high.b);
                let scalar_high = conversion::b2a(&scalar_high, net, state)?;

                let res = scalar_high * scale + scalar_low;
                Rep3AcvmType::Shared(res)
            }
        };
        Ok(res)
    }

    fn create_grumpkin_point(
        x: &Rep3AcvmType<ark_bn254::Fr>,
        y: &Rep3AcvmType<ark_bn254::Fr>,
        is_infinity: &Rep3AcvmType<ark_bn254::Fr>,
        net: &N,
        state: &mut Rep3State,
        pedantic_solving: bool,
    ) -> eyre::Result<Rep3AcvmPoint<ark_grumpkin::Projective>> {
        if let Rep3AcvmType::Public(is_infinity) = is_infinity {
            if pedantic_solving && is_infinity > &ark_bn254::Fr::one() {
                eyre::bail!(
                    "--pedantic-solving: is_infinity expected to be a bool, but found to be > 1"
                );
            }

            if is_infinity.is_one() {
                return Ok(Rep3AcvmPoint::Public(ark_grumpkin::Projective::zero()));
            }
            if let (Rep3AcvmType::Public(x), Rep3AcvmType::Public(y)) = (x, y) {
                return Ok(Rep3AcvmPoint::Public(
                    PlainAcvmSolver::<F>::create_grumpkin_point(*x, *y, false)?.into(),
                ));
            }
        }

        // At least one part is shared, convert and calculate
        let x = match x {
            Rep3AcvmType::Public(x) => arithmetic::promote_to_trivial_share(state.id, *x),
            Rep3AcvmType::Shared(x) => *x,
        };
        let y = match y {
            Rep3AcvmType::Public(y) => arithmetic::promote_to_trivial_share(state.id, *y),
            Rep3AcvmType::Shared(y) => *y,
        };
        let is_infinity = match is_infinity {
            Rep3AcvmType::Public(is_infinity) => {
                arithmetic::promote_to_trivial_share(state.id, *is_infinity)
            }
            Rep3AcvmType::Shared(is_infinity) => *is_infinity,
        };
        let res = conversion::fieldshares_to_pointshare(x, y, is_infinity, net, state)?;
        Ok(Rep3AcvmPoint::Shared(res))
    }

    fn scalar_point_mul<C: CurveGroup>(
        a: Rep3AcvmType<C::ScalarField>,
        b: Rep3AcvmPoint<C>,
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<Rep3AcvmPoint<C>> {
        let result = match (a, b) {
            (Rep3AcvmType::Public(a), Rep3AcvmPoint::Public(b)) => Rep3AcvmPoint::Public(b * a),
            (Rep3AcvmType::Public(a), Rep3AcvmPoint::Shared(b)) => {
                Rep3AcvmPoint::Shared(pointshare::scalar_mul_public_scalar(&b, a))
            }
            (Rep3AcvmType::Shared(a), Rep3AcvmPoint::Public(b)) => {
                Rep3AcvmPoint::Shared(pointshare::scalar_mul_public_point(&b, a))
            }
            (Rep3AcvmType::Shared(a), Rep3AcvmPoint::Shared(b)) => {
                let result = pointshare::scalar_mul(&b, a, net, state)?;
                Rep3AcvmPoint::Shared(result)
            }
        };
        Ok(result)
    }

    fn add_assign_point<C: CurveGroup>(
        mut inout: &mut Rep3AcvmPoint<C>,
        other: Rep3AcvmPoint<C>,
        id: PartyID,
    ) {
        match (&mut inout, other) {
            (Rep3AcvmPoint::Public(inout), Rep3AcvmPoint::Public(other)) => *inout += other,
            (Rep3AcvmPoint::Shared(inout), Rep3AcvmPoint::Shared(other)) => {
                pointshare::add_assign(inout, &other)
            }
            (Rep3AcvmPoint::Public(inout_), Rep3AcvmPoint::Shared(mut other)) => {
                pointshare::add_assign_public(&mut other, inout_, id);
                *inout = Rep3AcvmPoint::Shared(other);
            }
            (Rep3AcvmPoint::Shared(inout), Rep3AcvmPoint::Public(other)) => {
                pointshare::add_assign_public(inout, &other, id);
            }
        }
    }
}

// For some intermediate representations
#[derive(Clone)]
pub enum Rep3AcvmPoint<C: CurveGroup> {
    Public(C),
    Shared(Rep3PointShare<C>),
}

impl<C: CurveGroup> std::fmt::Debug for Rep3AcvmPoint<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(point) => f.debug_tuple("Public").field(point).finish(),
            Self::Shared(share) => f.debug_tuple("Arithmetic").field(share).finish(),
        }
    }
}

impl<C: CurveGroup> std::fmt::Display for Rep3AcvmPoint<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(point) => f.write_str(&format!("Public ({point})")),
            Self::Shared(arithmetic) => {
                let (a, b) = arithmetic.to_owned().ab();
                f.write_str(&format!("Arithmetic (a: {a}, b: {b})"))
            }
        }
    }
}

impl<C: CurveGroup> From<C> for Rep3AcvmPoint<C> {
    fn from(value: C) -> Self {
        Self::Public(value)
    }
}

// TODO maybe we want to merge that with the Rep3VmType?? Atm we do not need
// binary shares so maybe it is ok..
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub enum Rep3AcvmType<F: PrimeField> {
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
        ArithmeticShare<F>,
    ),
}

impl<F: PrimeField> std::fmt::Debug for Rep3AcvmType<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(field) => f.debug_tuple("Public").field(field).finish(),
            Self::Shared(share) => f.debug_tuple("Arithmetic").field(share).finish(),
        }
    }
}

impl<F: PrimeField> std::fmt::Display for Rep3AcvmType<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(field) => f.write_str(&format!("Public ({field})")),
            Self::Shared(arithmetic) => {
                let (a, b) = arithmetic.ab();
                f.write_str(&format!("Arithmetic (a: {a}, b: {b})"))
            }
        }
    }
}

impl<F: PrimeField> Default for Rep3AcvmType<F> {
    fn default() -> Self {
        Self::Public(F::zero())
    }
}

impl<F: PrimeField> From<F> for Rep3AcvmType<F> {
    fn from(value: F) -> Self {
        Self::Public(value)
    }
}

impl<F: PrimeField> From<ArithmeticShare<F>> for Rep3AcvmType<F> {
    fn from(value: ArithmeticShare<F>) -> Self {
        Self::Shared(value)
    }
}

impl<F: PrimeField> From<Rep3Type<F>> for Rep3AcvmType<F> {
    fn from(value: Rep3Type<F>) -> Self {
        match value {
            Rep3Type::Public(public) => Rep3AcvmType::Public(public),
            Rep3Type::Shared(shared) => Rep3AcvmType::Shared(shared),
        }
    }
}

impl<F: PrimeField> From<Rep3AcvmType<F>> for Rep3BrilligType<F> {
    fn from(val: Rep3AcvmType<F>) -> Self {
        match val {
            Rep3AcvmType::Public(public) => Rep3BrilligType::public_field(public),
            Rep3AcvmType::Shared(share) => Rep3BrilligType::shared_field(share),
        }
    }
}

impl<F: PrimeField> Rep3AcvmType<F> {
    fn from_brillig_type<N: Network>(
        value: Rep3BrilligType<F>,
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<Self> {
        match value {
            Rep3BrilligType::Public(public) => Ok(Rep3AcvmType::Public(public.into_field())),
            Rep3BrilligType::Shared(shared) => {
                let shared = Rep3BrilligType::into_arithmetic_share(shared, net, state)?;
                Ok(Rep3AcvmType::Shared(shared))
            }
        }
    }
}

fn get_base_powers<const NUM_SLICES: usize>(base: u64) -> [BigUint; NUM_SLICES] {
    let mut output: [BigUint; NUM_SLICES] = array::from_fn(|_| BigUint::one());
    let mask: BigUint = (BigUint::from(1u64) << 256) - BigUint::one();
    for i in 1..NUM_SLICES {
        let tmp = &output[i - 1] * base;
        output[i] = tmp & &mask;
    }
    output
}

impl<'a, F: PrimeField, N: Network> NoirWitnessExtensionProtocol<F> for Rep3AcvmSolver<'a, F, N> {
    type Lookup = Rep3LookupTable<F>;

    type ArithmeticShare = Rep3PrimeFieldShare<F>;

    type AcvmType = Rep3AcvmType<F>;
    type AcvmPoint<C: CurveGroup<BaseField = F>> = Rep3AcvmPoint<C>;

    type BrilligDriver = Rep3BrilligDriver<'a, F, N>;

    fn init_brillig_driver(&mut self) -> eyre::Result<Self::BrilligDriver> {
        // TODO we just copy the net ref here this is not safe if used concurrently
        Ok(Rep3BrilligDriver::new(self.net0, self.state0.fork(0)?))
    }

    fn parse_brillig_result(
        &mut self,
        brillig_result: Vec<Rep3BrilligType<F>>,
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        brillig_result
            .into_iter()
            .map(|value| Rep3AcvmType::from_brillig_type(value, self.net0, &mut self.state0))
            .collect()
    }

    fn cmux(
        &mut self,
        cond: Self::AcvmType,
        truthy: Self::AcvmType,
        falsy: Self::AcvmType,
    ) -> eyre::Result<Self::AcvmType> {
        match (cond, truthy, falsy) {
            (Rep3AcvmType::Public(cond), truthy, falsy) => {
                assert!(cond.is_one() || cond.is_zero());
                if cond.is_one() { Ok(truthy) } else { Ok(falsy) }
            }
            (Rep3AcvmType::Shared(cond), truthy, falsy) => {
                let b_min_a = self.sub(truthy, falsy.clone());
                let d = self.mul(cond.into(), b_min_a)?;
                Ok(self.add(falsy, d))
            }
        }
    }

    fn shared_zeros(&mut self, len: usize) -> eyre::Result<Vec<Self::AcvmType>> {
        let a = (0..len)
            .map(|_| self.state0.rngs.rand.masking_field_element())
            .collect::<Vec<_>>();
        let b = self.net0.reshare_many(&a)?;
        let result = izip!(a, b)
            .map(|(a, b)| Rep3AcvmType::Shared(Rep3PrimeFieldShare::new(a, b)))
            .collect();
        Ok(result)
    }

    fn is_public_zero(a: &Self::AcvmType) -> bool {
        if let Rep3AcvmType::Public(x) = a {
            x.is_zero()
        } else {
            false
        }
    }

    fn is_public_one(a: &Self::AcvmType) -> bool {
        if let Rep3AcvmType::Public(x) = a {
            x.is_one()
        } else {
            false
        }
    }

    fn add_assign_with_public(&mut self, public: F, target: &mut Self::AcvmType) {
        let result = match target.to_owned() {
            Rep3AcvmType::Public(secret) => Rep3AcvmType::Public(public + secret),
            Rep3AcvmType::Shared(secret) => {
                Rep3AcvmType::Shared(arithmetic::add_public(secret, public, self.id))
            }
        };
        *target = result;
    }

    fn add(&self, lhs: Self::AcvmType, rhs: Self::AcvmType) -> Self::AcvmType {
        match (lhs, rhs) {
            (Rep3AcvmType::Public(lhs), Rep3AcvmType::Public(rhs)) => {
                Rep3AcvmType::Public(lhs + rhs)
            }
            (Rep3AcvmType::Public(public), Rep3AcvmType::Shared(shared))
            | (Rep3AcvmType::Shared(shared), Rep3AcvmType::Public(public)) => {
                Rep3AcvmType::Shared(arithmetic::add_public(shared, public, self.id))
            }
            (Rep3AcvmType::Shared(lhs), Rep3AcvmType::Shared(rhs)) => {
                let result = arithmetic::add(lhs, rhs);
                Rep3AcvmType::Shared(result)
            }
        }
    }

    fn add_points<C: CurveGroup<BaseField = F>>(
        &self,
        lhs: Self::AcvmPoint<C>,
        rhs: Self::AcvmPoint<C>,
    ) -> Self::AcvmPoint<C> {
        match (lhs, rhs) {
            (Rep3AcvmPoint::Public(lhs), Rep3AcvmPoint::Public(rhs)) => {
                Rep3AcvmPoint::Public(lhs + rhs)
            }
            (Rep3AcvmPoint::Public(public), Rep3AcvmPoint::Shared(mut shared))
            | (Rep3AcvmPoint::Shared(mut shared), Rep3AcvmPoint::Public(public)) => {
                pointshare::add_assign_public(&mut shared, &public, self.id);
                Rep3AcvmPoint::Shared(shared)
            }
            (Rep3AcvmPoint::Shared(lhs), Rep3AcvmPoint::Shared(rhs)) => {
                let result = pointshare::add(&lhs, &rhs);
                Rep3AcvmPoint::Shared(result)
            }
        }
    }

    fn sub(&mut self, share_1: Self::AcvmType, share_2: Self::AcvmType) -> Self::AcvmType {
        match (share_1, share_2) {
            (Rep3AcvmType::Public(share_1), Rep3AcvmType::Public(share_2)) => {
                Rep3AcvmType::Public(share_1 - share_2)
            }
            (Rep3AcvmType::Public(share_1), Rep3AcvmType::Shared(share_2)) => {
                Rep3AcvmType::Shared(arithmetic::sub_public_by_shared(share_1, share_2, self.id))
            }
            (Rep3AcvmType::Shared(share_1), Rep3AcvmType::Public(share_2)) => {
                Rep3AcvmType::Shared(arithmetic::sub_shared_by_public(share_1, share_2, self.id))
            }
            (Rep3AcvmType::Shared(share_1), Rep3AcvmType::Shared(share_2)) => {
                let result = arithmetic::sub(share_1, share_2);
                Rep3AcvmType::Shared(result)
            }
        }
    }

    fn mul_with_public(&mut self, public: F, secret: Self::AcvmType) -> Self::AcvmType {
        match secret {
            Rep3AcvmType::Public(secret) => Rep3AcvmType::Public(public * secret),
            Rep3AcvmType::Shared(secret) => {
                Rep3AcvmType::Shared(arithmetic::mul_public(secret, public))
            }
        }
    }

    fn mul(
        &mut self,
        secret_1: Self::AcvmType,
        secret_2: Self::AcvmType,
    ) -> eyre::Result<Self::AcvmType> {
        match (secret_1, secret_2) {
            (Rep3AcvmType::Public(secret_1), Rep3AcvmType::Public(secret_2)) => {
                Ok(Rep3AcvmType::Public(secret_1 * secret_2))
            }
            (Rep3AcvmType::Public(secret_1), Rep3AcvmType::Shared(secret_2)) => Ok(
                Rep3AcvmType::Shared(arithmetic::mul_public(secret_2, secret_1)),
            ),
            (Rep3AcvmType::Shared(secret_1), Rep3AcvmType::Public(secret_2)) => Ok(
                Rep3AcvmType::Shared(arithmetic::mul_public(secret_1, secret_2)),
            ),
            (Rep3AcvmType::Shared(secret_1), Rep3AcvmType::Shared(secret_2)) => {
                let result = arithmetic::mul(secret_1, secret_2, self.net0, &mut self.state0)?;
                Ok(Rep3AcvmType::Shared(result))
            }
        }
    }

    fn invert(&mut self, secret: Self::AcvmType) -> eyre::Result<Self::AcvmType> {
        match secret {
            Rep3AcvmType::Public(secret) => {
                let inv = secret
                    .inverse()
                    .ok_or_else(|| eyre::eyre!("Cannot invert zero"))?;
                Ok(Rep3AcvmType::Public(inv))
            }
            Rep3AcvmType::Shared(secret) => {
                let inv = arithmetic::inv(secret, self.net0, &mut self.state0)?;
                Ok(Rep3AcvmType::Shared(inv))
            }
        }
    }

    fn negate_inplace(&mut self, a: &mut Self::AcvmType) {
        match a {
            Rep3AcvmType::Public(public) => {
                public.neg_in_place();
            }
            Rep3AcvmType::Shared(shared) => *shared = arithmetic::neg(*shared),
        }
    }

    fn solve_linear_term(&mut self, q_l: F, w_l: Self::AcvmType, target: &mut Self::AcvmType) {
        let result = match (w_l, target.to_owned()) {
            (Rep3AcvmType::Public(w_l), Rep3AcvmType::Public(result)) => {
                Rep3AcvmType::Public(q_l * w_l + result)
            }
            (Rep3AcvmType::Public(w_l), Rep3AcvmType::Shared(result)) => {
                Rep3AcvmType::Shared(arithmetic::add_public(result, q_l * w_l, self.id))
            }
            (Rep3AcvmType::Shared(w_l), Rep3AcvmType::Public(result)) => {
                let mul = arithmetic::mul_public(w_l, q_l);
                Rep3AcvmType::Shared(arithmetic::add_public(mul, result, self.id))
            }
            (Rep3AcvmType::Shared(w_l), Rep3AcvmType::Shared(result)) => {
                let mul = arithmetic::mul_public(w_l, q_l);
                Rep3AcvmType::Shared(arithmetic::add(mul, result))
            }
        };
        *target = result;
    }

    fn add_assign(&mut self, target: &mut Self::AcvmType, rhs: Self::AcvmType) {
        let result = match (target.clone(), rhs) {
            (Rep3AcvmType::Public(lhs), Rep3AcvmType::Public(rhs)) => {
                Rep3AcvmType::Public(lhs + rhs)
            }
            (Rep3AcvmType::Public(public), Rep3AcvmType::Shared(shared))
            | (Rep3AcvmType::Shared(shared), Rep3AcvmType::Public(public)) => {
                Rep3AcvmType::Shared(arithmetic::add_public(shared, public, self.id))
            }
            (Rep3AcvmType::Shared(lhs), Rep3AcvmType::Shared(rhs)) => {
                Rep3AcvmType::Shared(arithmetic::add(lhs, rhs))
            }
        };
        *target = result;
    }

    fn solve_mul_term(
        &mut self,
        c: F,
        lhs: Self::AcvmType,
        rhs: Self::AcvmType,
    ) -> eyre::Result<Self::AcvmType> {
        let result = match (lhs, rhs) {
            (Rep3AcvmType::Public(lhs), Rep3AcvmType::Public(rhs)) => {
                Rep3AcvmType::Public(lhs * rhs * c)
            }
            (Rep3AcvmType::Public(public), Rep3AcvmType::Shared(shared))
            | (Rep3AcvmType::Shared(shared), Rep3AcvmType::Public(public)) => {
                let mul = arithmetic::mul_public(shared, public);
                Rep3AcvmType::Shared(arithmetic::mul_public(mul, c))
            }
            (Rep3AcvmType::Shared(lhs), Rep3AcvmType::Shared(rhs)) => {
                let shared_mul = arithmetic::mul(lhs, rhs, self.net0, &mut self.state0)?;
                Rep3AcvmType::Shared(arithmetic::mul_public(shared_mul, c))
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
            (Rep3AcvmType::Public(q_l), Rep3AcvmType::Public(c)) => {
                Rep3AcvmType::Public(self.plain_solver.solve_equation(q_l, c)?)
            }
            (Rep3AcvmType::Public(q_l), Rep3AcvmType::Shared(c)) => {
                Rep3AcvmType::Shared(arithmetic::div_shared_by_public(arithmetic::neg(c), q_l)?)
            }
            (Rep3AcvmType::Shared(q_l), Rep3AcvmType::Public(c)) => {
                let result =
                    arithmetic::div_public_by_shared(-c, q_l, self.net0, &mut self.state0)?;
                Rep3AcvmType::Shared(result)
            }
            (Rep3AcvmType::Shared(q_l), Rep3AcvmType::Shared(c)) => {
                let result = arithmetic::div(arithmetic::neg(c), q_l, self.net0, &mut self.state0)?;
                Rep3AcvmType::Shared(result)
            }
        };
        Ok(result)
    }

    fn init_lut_by_acvm_type(
        &mut self,
        values: Vec<Self::AcvmType>,
    ) -> <Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType {
        if values.iter().any(|v| Self::is_shared(v)) {
            let mut shares = Vec::with_capacity(values.len());
            for val in values {
                shares.push(match val {
                    Rep3AcvmType::Public(public) => {
                        arithmetic::promote_to_trivial_share(self.id, public)
                    }
                    Rep3AcvmType::Shared(shared) => shared,
                });
            }
            self.lut_provider.init_private(shares)
        } else {
            let mut public = Vec::with_capacity(values.len());
            for val in values {
                public.push(Self::get_public(&val).expect("Already checked it is public"));
            }
            self.lut_provider.init_public(public)
        }
    }

    fn read_lut_by_acvm_type(
        &mut self,
        index: Self::AcvmType,
        lut: &<Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType,
    ) -> eyre::Result<Self::AcvmType> {
        let result = match index {
            Rep3AcvmType::Public(public) => {
                let index: BigUint = public.into();
                let index = usize::try_from(index)
                    .map_err(|_| eyre::eyre!("Index can not be translated to usize"))?;

                match lut {
                    mpc_core::protocols::rep3_ring::lut::PublicPrivateLut::Public(vec) => {
                        Self::AcvmType::from(vec[index].to_owned())
                    }
                    mpc_core::protocols::rep3_ring::lut::PublicPrivateLut::Shared(vec) => {
                        Self::AcvmType::from(vec[index].to_owned())
                    }
                }
            }
            Rep3AcvmType::Shared(shared) => Self::AcvmType::from(self.lut_provider.get_from_lut(
                shared,
                lut,
                self.net0,
                self.net1,
                &mut self.state0,
                &mut self.state1,
            )?),
        };
        Ok(result)
    }

    fn read_from_public_luts(
        &mut self,
        index: Self::AcvmType,
        luts: &[Vec<F>],
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        let mut result = Vec::with_capacity(luts.len());
        match index {
            Rep3AcvmType::Public(index) => {
                let index: BigUint = index.into();
                let index = usize::try_from(index)
                    .map_err(|_| eyre::eyre!("Index can not be translated to usize"))?;
                for lut in luts {
                    result.push(Rep3AcvmType::Public(lut[index].to_owned()));
                }
            }
            Rep3AcvmType::Shared(index) => {
                let res = Rep3LookupTable::get_from_public_luts(
                    index,
                    luts,
                    self.net0,
                    self.net1,
                    &mut self.state0,
                    &mut self.state1,
                )?;
                for res in res {
                    result.push(Rep3AcvmType::Shared(res));
                }
            }
        }
        Ok(result)
    }

    fn write_lut_by_acvm_type(
        &mut self,
        index: Self::AcvmType,
        value: Self::AcvmType,
        lut: &mut <Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType,
    ) -> eyre::Result<()> {
        match (index, value) {
            (Rep3AcvmType::Public(index), Rep3AcvmType::Public(value)) => {
                let index: BigUint = (index).into();
                let index = usize::try_from(index)
                    .map_err(|_| eyre::eyre!("Index can not be translated to usize"))?;

                match lut {
                    mpc_core::protocols::rep3_ring::lut::PublicPrivateLut::Public(vec) => {
                        vec[index] = value;
                    }
                    mpc_core::protocols::rep3_ring::lut::PublicPrivateLut::Shared(vec) => {
                        vec[index] = arithmetic::promote_to_trivial_share(self.id, value);
                    }
                }
            }
            (Rep3AcvmType::Public(index), Rep3AcvmType::Shared(value)) => {
                let index: BigUint = (index).into();
                let index = usize::try_from(index)
                    .map_err(|_| eyre::eyre!("Index can not be translated to usize"))?;

                match lut {
                    mpc_core::protocols::rep3_ring::lut::PublicPrivateLut::Public(vec) => {
                        let mut vec = vec
                            .iter()
                            .map(|value| arithmetic::promote_to_trivial_share(self.id, *value))
                            .collect::<Vec<_>>();
                        vec[index] = value;
                        *lut = mpc_core::protocols::rep3_ring::lut::PublicPrivateLut::Shared(vec);
                    }
                    mpc_core::protocols::rep3_ring::lut::PublicPrivateLut::Shared(vec) => {
                        vec[index] = value;
                    }
                }
            }
            (Rep3AcvmType::Shared(index), Rep3AcvmType::Public(value)) => {
                // TODO there might be a more efficient implementation for this if the table is also public
                let value = arithmetic::promote_to_trivial_share(self.id, value);
                self.lut_provider.write_to_lut(
                    index,
                    value,
                    lut,
                    self.net0,
                    self.net1,
                    &mut self.state0,
                    &mut self.state1,
                )?;
            }
            (Rep3AcvmType::Shared(index), Rep3AcvmType::Shared(value)) => {
                self.lut_provider.write_to_lut(
                    index,
                    value,
                    lut,
                    self.net0,
                    self.net1,
                    &mut self.state0,
                    &mut self.state1,
                )?;
            }
        }
        Ok(())
    }

    fn one_hot_vector_from_shared_index(
        &mut self,
        index: Self::ArithmeticShare,
        len: usize,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        self.lut_provider.ohv_from_index(
            index,
            len,
            self.net0,
            self.net1,
            &mut self.state0,
            &mut self.state1,
        )
    }

    fn write_to_shared_lut_from_ohv(
        &mut self,
        ohv: &[Self::ArithmeticShare],
        value: Self::ArithmeticShare,
        lut: &mut [Self::ArithmeticShare],
    ) -> eyre::Result<()> {
        self.lut_provider
            .write_to_shared_lut_from_ohv(ohv, value, lut, self.net0, &mut self.state0)
    }

    fn get_length_of_lut(lut: &<Self::Lookup as LookupTableProvider<F>>::LutType) -> usize {
        <Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::get_lut_len(lut)
    }

    fn get_public_lut(
        lut: &<Self::Lookup as LookupTableProvider<F>>::LutType,
    ) -> eyre::Result<&Vec<F>> {
        <Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::get_public_lut(lut)
    }

    fn is_shared(a: &Self::AcvmType) -> bool {
        matches!(a, Rep3AcvmType::Shared(_))
    }

    fn get_shared(a: &Self::AcvmType) -> Option<Self::ArithmeticShare> {
        match a {
            Rep3AcvmType::Shared(shared) => Some(*shared),
            _ => None,
        }
    }
    fn get_public(a: &Self::AcvmType) -> Option<F> {
        match a {
            Rep3AcvmType::Public(public) => Some(*public),
            _ => None,
        }
    }

    fn get_public_point<C: CurveGroup<BaseField = F>>(a: &Self::AcvmPoint<C>) -> Option<C> {
        match a {
            Rep3AcvmPoint::Public(public) => Some(*public),
            _ => None,
        }
    }

    fn open_many(&mut self, a: &[Self::ArithmeticShare]) -> eyre::Result<Vec<F>> {
        let bs = a.iter().map(|x| x.b).collect_vec();
        let mut cs = self.net0.reshare(bs)?;

        izip!(a, cs.iter_mut()).for_each(|(x, c)| *c += x.a + x.b);

        Ok(cs)
    }

    fn promote_to_trivial_share(&mut self, public_value: F) -> Self::ArithmeticShare {
        arithmetic::promote_to_trivial_share(self.id, public_value)
    }

    fn promote_to_trivial_shares(&mut self, public_values: &[F]) -> Vec<Self::ArithmeticShare> {
        public_values
            .par_iter()
            .with_min_len(1024)
            .map(|value| Self::ArithmeticShare::promote_from_trivial(value, self.id))
            .collect()
    }

    fn decompose_arithmetic(
        &mut self,
        input: Self::ArithmeticShare,
        total_bit_size_per_field: usize,
        decompose_bit_size: usize,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        yao::decompose_arithmetic(
            input,
            self.net0,
            &mut self.state0,
            total_bit_size_per_field,
            decompose_bit_size,
        )
    }

    fn decompose_arithmetic_many(
        &mut self,
        input: &[Self::ArithmeticShare],
        total_bit_size_per_field: usize,
        decompose_bit_size: usize,
    ) -> eyre::Result<Vec<Vec<Self::ArithmeticShare>>> {
        // Defines an upper bound on the size of the input vector to keep the GC at a reasonable size (for RAM)
        const BATCH_SIZE: usize = 512; // TODO adapt this if it requires too much RAM

        let num_decomps_per_field = total_bit_size_per_field.div_ceil(decompose_bit_size);
        let mut results = Vec::with_capacity(input.len());

        for inp_chunk in input.chunks(BATCH_SIZE) {
            let result = yao::decompose_arithmetic_many(
                inp_chunk,
                self.net0,
                &mut self.state0,
                total_bit_size_per_field,
                decompose_bit_size,
            )?;
            for chunk in result.chunks(num_decomps_per_field) {
                results.push(chunk.to_vec());
            }
        }
        Ok(results)
    }

    fn sort(
        &mut self,
        inputs: &[Self::AcvmType],
        bitsize: usize,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        let mut priv_inputs = Vec::new();
        let mut pub_inputs = Vec::new();
        for val in inputs {
            if Self::is_shared(val) {
                priv_inputs.push(Self::get_shared(val).expect("Already checked it is shared"));
            } else {
                pub_inputs.push(Self::get_public(val).expect("Already checked it is public"));
            }
        }
        radix_sort_fields(
            priv_inputs,
            pub_inputs,
            bitsize,
            self.net0,
            self.net1,
            &mut self.state0,
            &mut self.state1,
        )
    }

    fn slice(
        &mut self,
        input: Self::ArithmeticShare,
        msb: u8,
        lsb: u8,
        bitsize: usize,
    ) -> eyre::Result<[Self::ArithmeticShare; 3]> {
        let res = yao::slice_arithmetic(
            input,
            self.net0,
            &mut self.state0,
            msb as usize,
            lsb as usize,
            bitsize,
        )?;
        debug_assert_eq!(res.len(), 3);
        Ok([res[0], res[1], res[2]])
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
            (Rep3AcvmType::Public(lhs), Rep3AcvmType::Public(rhs)) => {
                let lhs: BigUint = lhs.into();
                let rhs: BigUint = rhs.into();
                let res = (lhs & rhs) & mask;
                let res = F::from(res);
                Ok(Rep3AcvmType::Public(res))
            }
            (Rep3AcvmType::Public(public), Rep3AcvmType::Shared(shared))
            | (Rep3AcvmType::Shared(shared), Rep3AcvmType::Public(public)) => {
                let shared = conversion::a2b_selector(shared, self.net0, &mut self.state0)?;
                let public: BigUint = public.into();
                let public = public & mask;
                let binary = binary::and_with_public(&shared, &public); // Already includes masking
                let result = conversion::b2a_selector(&binary, self.net0, &mut self.state0)?;
                Ok(Rep3AcvmType::Shared(result))
            }
            (Rep3AcvmType::Shared(lhs), Rep3AcvmType::Shared(rhs)) => {
                let (lhs, rhs) = mpc_net::join(
                    || conversion::a2b_selector(lhs, self.net0, &mut self.state0),
                    || conversion::a2b_selector(rhs, self.net1, &mut self.state1),
                );
                let binary = binary::and(&lhs?, &rhs?, self.net0, &mut self.state0)? & mask;
                let result = conversion::b2a_selector(&binary, self.net0, &mut self.state0)?;
                Ok(Rep3AcvmType::Shared(result))
            }
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
            (Rep3AcvmType::Public(lhs), Rep3AcvmType::Public(rhs)) => {
                let lhs: BigUint = lhs.into();
                let rhs: BigUint = rhs.into();
                let res = (lhs ^ rhs) & mask;
                let res = F::from(res);
                Ok(Rep3AcvmType::Public(res))
            }
            (Rep3AcvmType::Public(public), Rep3AcvmType::Shared(shared))
            | (Rep3AcvmType::Shared(shared), Rep3AcvmType::Public(public)) => {
                let shared = conversion::a2b_selector(shared, self.net0, &mut self.state0)?;
                let public: BigUint = public.into();
                let binary = binary::xor_public(&shared, &public, self.id) & mask;
                let result = conversion::b2a_selector(&binary, self.net0, &mut self.state0)?;
                Ok(Rep3AcvmType::Shared(result))
            }
            (Rep3AcvmType::Shared(lhs), Rep3AcvmType::Shared(rhs)) => {
                let (lhs, rhs) = mpc_net::join(
                    || conversion::a2b_selector(lhs, self.net0, &mut self.state0),
                    || conversion::a2b_selector(rhs, self.net1, &mut self.state1),
                );
                let binary = binary::xor(&lhs?, &rhs?) & mask;
                let result = conversion::b2a_selector(&binary, self.net0, &mut self.state0)?;
                Ok(Rep3AcvmType::Shared(result))
            }
        }
    }

    fn slice_and_get_and_rotate_values(
        &mut self,
        input1: Self::ArithmeticShare,
        input2: Self::ArithmeticShare,
        basis_bits: usize,
        total_bitsize: usize,
        rotation: usize,
    ) -> eyre::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )> {
        let result = yao::slice_and(
            input1,
            input2,
            self.net0,
            &mut self.state0,
            basis_bits,
            rotation,
            total_bitsize,
        )?;
        let num_outputs = result.len();
        debug_assert_eq!(num_outputs % 3, 0);
        let size = num_outputs / 3;
        let key_a_slices = result
            .iter()
            .take(size)
            .map(|a| Rep3AcvmType::Shared(*a))
            .collect();
        let key_b_slices = result
            .iter()
            .skip(size)
            .take(size)
            .map(|a| Rep3AcvmType::Shared(*a))
            .collect();
        let rotation_values = result
            .into_iter()
            .skip(2 * size)
            .map(|a| Rep3AcvmType::Shared(a))
            .collect();

        Ok((rotation_values, key_a_slices, key_b_slices))
    }

    fn slice_and_get_xor_rotate_values(
        &mut self,
        input1: Self::ArithmeticShare,
        input2: Self::ArithmeticShare,
        basis_bits: usize,
        total_bitsize: usize,
        rotation: usize,
    ) -> eyre::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )> {
        let result = yao::slice_xor(
            input1,
            input2,
            self.net0,
            &mut self.state0,
            basis_bits,
            rotation,
            total_bitsize,
        )?;
        let num_outputs = result.len();
        debug_assert_eq!(num_outputs % 3, 0);
        let size = num_outputs / 3;
        let key_a_slices = result
            .iter()
            .take(size)
            .map(|a| Rep3AcvmType::Shared(*a))
            .collect();
        let key_b_slices = result
            .iter()
            .skip(size)
            .take(size)
            .map(|a| Rep3AcvmType::Shared(*a))
            .collect();
        let rotation_values = result
            .into_iter()
            .skip(2 * size)
            .map(|a| Rep3AcvmType::Shared(a))
            .collect();

        Ok((rotation_values, key_a_slices, key_b_slices))
    }

    fn slice_and_get_xor_rotate_values_with_filter(
        &mut self,
        input1: Self::ArithmeticShare,
        input2: Self::ArithmeticShare,
        basis_bits: &[u64],
        rotation: &[usize],
        filter: &[bool],
    ) -> eyre::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )> {
        let result = yao::slice_xor_with_filter(
            input1,
            input2,
            self.net0,
            &mut self.state0,
            basis_bits,
            rotation,
            filter,
        )?;
        let num_outputs = result.len();
        let num_of_slices = basis_bits.len();
        debug_assert_eq!(num_outputs % 3, 0);
        let size = num_outputs / 3;

        let key_a_slices: Vec<_> = result
            .iter()
            .take(num_of_slices)
            .map(|a| Rep3AcvmType::Shared(*a))
            .collect();
        let key_b_slices: Vec<_> = result
            .iter()
            .skip(size)
            .take(num_of_slices)
            .map(|a| Rep3AcvmType::Shared(*a))
            .collect();
        let rotation_values: Vec<_> = result
            .into_iter()
            .skip(2 * size)
            .take(num_of_slices)
            .map(|a| Rep3AcvmType::Shared(a))
            .collect();

        Ok((rotation_values, key_a_slices, key_b_slices))
    }

    fn sort_vec_by(
        &mut self,
        key: &[Self::AcvmType],
        inputs: Vec<&[Self::ArithmeticShare]>,
        bitsize: usize,
    ) -> eyre::Result<Vec<Vec<Self::ArithmeticShare>>> {
        let mut priv_key = Vec::new();
        let mut pub_key = Vec::new();
        let mut order = Vec::with_capacity(key.len());
        for val in key {
            if Self::is_shared(val) {
                order.push(true);
                priv_key.push(Self::get_shared(val).expect("Already checked it is shared"));
            } else {
                order.push(false);
                pub_key.push(Self::get_public(val).expect("Already checked it is public"));
            }
        }

        radix_sort_fields_vec_by(
            &priv_key,
            &pub_key,
            &order,
            inputs,
            bitsize,
            self.net0,
            self.net1,
            &mut self.state0,
            &mut self.state1,
        )
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
                Rep3AcvmType::Public(public) => {
                    // The initial linear layer of poseidon makes the whole state shared anyway
                    arithmetic::promote_to_trivial_share(self.id, public)
                }
                Rep3AcvmType::Shared(shared) => shared,
            });
            let mut precomp = poseidon2.precompute_rep3(1, self.net0, &mut self.state0)?;
            poseidon2.rep3_permutation_in_place_with_precomputation(
                &mut shared,
                &mut precomp,
                self.net0,
            )?;

            for (src, des) in shared.into_iter().zip(input.iter_mut()) {
                *des = Rep3AcvmType::Shared(src);
            }
        } else {
            let mut public = array::from_fn(|i| Self::get_public(&input[i]).unwrap());
            poseidon2.permutation_in_place(&mut public);

            for (src, des) in public.into_iter().zip(input.iter_mut()) {
                *des = Rep3AcvmType::Public(src);
            }
        }

        Ok(input)
    }

    fn poseidon2_matmul_external_inplace<const T: usize, const D: u64>(
        &self,
        input: &mut [Self::ArithmeticShare; T],
    ) {
        Poseidon2::<F, T, D>::matmul_external_rep3(input);
    }

    fn poseidon2_preprocess_permutation<const T: usize, const D: u64>(
        &mut self,
        num_poseidon: usize,
        poseidon2: &Poseidon2<F, T, D>,
    ) -> eyre::Result<Poseidon2Precomputations<Self::ArithmeticShare>> {
        poseidon2.precompute_rep3(num_poseidon, self.net0, &mut self.state0)
    }

    fn poseidon2_external_round_inplace_with_precomp<const T: usize, const D: u64>(
        &mut self,
        input: &mut [Self::ArithmeticShare; T],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Self::ArithmeticShare>,
        poseidon2: &Poseidon2<F, T, D>,
    ) -> eyre::Result<()> {
        poseidon2.rep3_external_round_precomp(input, r, precomp, self.net0)
    }

    fn poseidon2_internal_round_inplace_with_precomp<const T: usize, const D: u64>(
        &mut self,
        input: &mut [Self::ArithmeticShare; T],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Self::ArithmeticShare>,
        poseidon2: &Poseidon2<F, T, D>,
    ) -> eyre::Result<()> {
        poseidon2.rep3_internal_round_precomp(input, r, precomp, self.net0)
    }

    fn is_public_lut(lut: &<Self::Lookup as LookupTableProvider<F>>::LutType) -> bool {
        Self::Lookup::is_public_lut(lut)
    }

    fn equal(&mut self, a: &Self::AcvmType, b: &Self::AcvmType) -> eyre::Result<Self::AcvmType> {
        match (a, b) {
            (Rep3AcvmType::Public(a), Rep3AcvmType::Public(b)) => {
                Ok(Rep3AcvmType::Public(F::from(a == b)))
            }
            (Rep3AcvmType::Public(public), Rep3AcvmType::Shared(shared)) => {
                Ok(Rep3AcvmType::Shared(arithmetic::eq_public(
                    *shared,
                    *public,
                    self.net0,
                    &mut self.state0,
                )?))
            }

            (Rep3AcvmType::Shared(shared), Rep3AcvmType::Public(public)) => {
                Ok(Rep3AcvmType::Shared(arithmetic::eq_public(
                    *shared,
                    *public,
                    self.net0,
                    &mut self.state0,
                )?))
            }

            (Rep3AcvmType::Shared(a), Rep3AcvmType::Shared(b)) => Ok(Rep3AcvmType::Shared(
                arithmetic::eq(*a, *b, self.net0, &mut self.state0)?,
            )),
        }
    }

    fn equal_many(
        &mut self,
        a: &[Self::AcvmType],
        b: &[Self::AcvmType],
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        // TODO: we probably want to compare public values directly if there happen to be any in the same index
        let bool_a = a.iter().any(|v| Self::is_shared(v));
        let bool_b = b.iter().any(|v| Self::is_shared(v));
        if !bool_a && !bool_b {
            Ok(a.iter()
                .zip(b.iter())
                .map(|(a, b)| Self::equal(self, a, b).unwrap())
                .collect())
        } else if bool_a && !bool_b {
            let b = b
                .iter()
                .map(|v| Self::get_public(v).expect("Already checked it is public"))
                .collect::<Vec<_>>();
            let a: Vec<Self::ArithmeticShare> = a
                .iter()
                .map(|v| {
                    if Self::is_shared(v) {
                        Self::get_shared(v).expect("Already checked it is shared")
                    } else {
                        self.promote_to_trivial_share(
                            Self::get_public(v).expect("Already checked it is public"),
                        )
                    }
                })
                .collect();
            arithmetic::eq_public_many(&a, &b, self.net0, &mut self.state0)
                .map(|shares| shares.into_iter().map(Rep3AcvmType::Shared).collect())
        } else if !bool_a && bool_b {
            let a = a
                .iter()
                .map(|v| Self::get_public(v).expect("Already checked it is public"))
                .collect::<Vec<_>>();
            let b: Vec<Self::ArithmeticShare> = b
                .iter()
                .map(|v| {
                    if Self::is_shared(v) {
                        Self::get_shared(v).expect("Already checked it is shared")
                    } else {
                        self.promote_to_trivial_share(
                            Self::get_public(v).expect("Already checked it is public"),
                        )
                    }
                })
                .collect();
            arithmetic::eq_public_many(&b, &a, self.net0, &mut self.state0)
                .map(|shares| shares.into_iter().map(Rep3AcvmType::Shared).collect())
        } else {
            let a: Vec<Self::ArithmeticShare> = a
                .iter()
                .map(|v| {
                    if Self::is_shared(v) {
                        Self::get_shared(v).expect("Already checked it is shared")
                    } else {
                        self.promote_to_trivial_share(
                            Self::get_public(v).expect("Already checked it is public"),
                        )
                    }
                })
                .collect();
            let b: Vec<Self::ArithmeticShare> = b
                .iter()
                .map(|v| {
                    if Self::is_shared(v) {
                        Self::get_shared(v).expect("Already checked it is shared")
                    } else {
                        self.promote_to_trivial_share(
                            Self::get_public(v).expect("Already checked it is public"),
                        )
                    }
                })
                .collect();
            arithmetic::eq_many(&a, &b, self.net0, &mut self.state0)
                .map(|shares| shares.into_iter().map(Rep3AcvmType::Shared).collect())
        }
    }

    fn multi_scalar_mul(
        &mut self,
        points: &[Self::AcvmType],
        scalars_lo: &[Self::AcvmType],
        scalars_hi: &[Self::AcvmType],
        pedantic_solving: bool, // Cannot check values
    ) -> eyre::Result<(Self::AcvmType, Self::AcvmType, Self::AcvmType)> {
        // This is very hardcoded to the grumpkin curve
        if TypeId::of::<F>() != TypeId::of::<ark_bn254::Fr>() {
            panic!("Only BN254 is supported");
        }

        // We transmute since we only support one curve

        // Safety: We checked that the types match
        let points = unsafe {
            std::mem::transmute::<&[Self::AcvmType], &[Rep3AcvmType<ark_bn254::Fr>]>(points)
        };
        // Safety: We checked that the types match
        let scalars_lo = unsafe {
            std::mem::transmute::<&[Self::AcvmType], &[Rep3AcvmType<ark_bn254::Fr>]>(scalars_lo)
        };
        // Safety: We checked that the types match
        let scalars_hi = unsafe {
            std::mem::transmute::<&[Self::AcvmType], &[Rep3AcvmType<ark_bn254::Fr>]>(scalars_hi)
        };

        if points.len() != 3 * scalars_lo.len() || scalars_lo.len() != scalars_hi.len() {
            eyre::bail!("Points and scalars must have the same length");
        }

        let mut output_point = Rep3AcvmPoint::Public(ark_grumpkin::Projective::zero());

        // TODO parallelize all points?
        for i in (0..points.len()).step_by(3) {
            let (point, grumpkin_integer) = mpc_net::join(
                || {
                    Self::create_grumpkin_point(
                        &points[i],
                        &points[i + 1],
                        &points[i + 2],
                        self.net0,
                        &mut self.state0,
                        pedantic_solving,
                    )
                },
                || {
                    Self::combine_grumpkin_scalar_field_limbs(
                        &scalars_lo[i / 3],
                        &scalars_hi[i / 3],
                        self.net1,
                        &mut self.state1,
                        pedantic_solving,
                    )
                },
            );
            let iteration_output_point =
                Self::scalar_point_mul(grumpkin_integer?, point?, self.net0, &mut self.state0)?;
            Self::add_assign_point(&mut output_point, iteration_output_point, self.id);
        }

        // TODO maybe find a way to unify this with pointshare_to_field_shares
        let res = match output_point {
            Rep3AcvmPoint::Public(output_point) => {
                if let Some((out_x, out_y)) = ark_grumpkin::Affine::from(output_point).xy() {
                    let out_x: F = *downcast(&out_x).expect("We checked types");
                    let out_y: F = *downcast(&out_y).expect("We checked types");

                    (out_x.into(), out_y.into(), F::zero().into())
                } else {
                    (F::zero().into(), F::zero().into(), F::one().into())
                }
            }
            Rep3AcvmPoint::Shared(output_point) => {
                let (x, y, i) = conversion::point_share_to_fieldshares(
                    output_point,
                    self.net0,
                    &mut self.state0,
                )?;
                // Set x,y to 0 of infinity is one.
                // TODO is this even necesary?
                let mul = arithmetic::sub_public_by_shared(ark_bn254::Fr::one(), i, self.id);
                let res = arithmetic::mul_vec(&[x, y], &[mul, mul], self.net0, &mut self.state0)?;

                let out_x = downcast::<_, Self::ArithmeticShare>(&res[0])
                    .expect("We checked types")
                    .to_owned();
                let out_y = downcast::<_, Self::ArithmeticShare>(&res[1])
                    .expect("We checked types")
                    .to_owned();
                let out_i = downcast::<_, Self::ArithmeticShare>(&i)
                    .expect("We checked types")
                    .to_owned();

                (out_x.into(), out_y.into(), out_i.into())
            }
        };
        Ok(res)
    }

    fn field_shares_to_pointshare<C: CurveGroup<BaseField = F>>(
        &mut self,
        x: Self::AcvmType,
        y: Self::AcvmType,
        is_infinity: Self::AcvmType,
    ) -> eyre::Result<Self::AcvmPoint<C>> {
        // This is very hardcoded to the grumpkin curve
        if TypeId::of::<F>() != TypeId::of::<ark_bn254::Fr>() {
            panic!("Only BN254 is supported");
        }

        // Ensure the curve type matches grumpkin at runtime to avoid invalid downcasts
        if TypeId::of::<C::Affine>() != TypeId::of::<ark_grumpkin::Affine>()
            || TypeId::of::<C>() != TypeId::of::<ark_grumpkin::Projective>()
        {
            eyre::bail!("Only the grumpkin curve is supported for field_shares_to_pointshare");
        }

        let x = downcast(&x).expect("We checked types");
        let y = downcast(&y).expect("We checked types");
        let is_infinity = downcast(&is_infinity).expect("We checked types");

        let point =
            Self::create_grumpkin_point(x, y, is_infinity, self.net0, &mut self.state0, true)?;

        let y = downcast::<_, Self::AcvmPoint<C>>(&point)
            .expect("We checked types")
            .to_owned();

        Ok(y)
    }

    fn pointshare_to_field_shares<C: CurveGroup<BaseField = F>>(
        &mut self,
        point: Self::AcvmPoint<C>,
    ) -> eyre::Result<(Self::AcvmType, Self::AcvmType, Self::AcvmType)> {
        let res = match point {
            Rep3AcvmPoint::Public(point) => {
                if let Some((out_x, out_y)) = point.into_affine().xy() {
                    (out_x.into(), out_y.into(), F::zero().into())
                } else {
                    (F::zero().into(), F::zero().into(), F::one().into())
                }
            }
            Rep3AcvmPoint::Shared(point) => {
                let (x, y, i) =
                    conversion::point_share_to_fieldshares(point, self.net0, &mut self.state0)?;
                // Set x,y to 0 of infinity is one.
                // TODO is this even necesary?
                let mul = arithmetic::sub_public_by_shared(F::one(), i, self.id);
                let res = arithmetic::mul_vec(&[x, y], &[mul, mul], self.net0, &mut self.state0)?;

                (res[0].into(), res[1].into(), i.into())
            }
        };
        Ok(res)
    }

    fn gt(&mut self, lhs: Self::AcvmType, rhs: Self::AcvmType) -> eyre::Result<Self::AcvmType> {
        match (lhs, rhs) {
            (Rep3AcvmType::Public(a), Rep3AcvmType::Public(b)) => {
                Ok(F::from((a > b) as u64).into())
            }
            (Rep3AcvmType::Public(a), Rep3AcvmType::Shared(b)) => {
                Ok(arithmetic::lt_public(b, a, self.net0, &mut self.state0)?.into())
            }
            (Rep3AcvmType::Shared(a), Rep3AcvmType::Public(b)) => {
                Ok(arithmetic::ge_public(a, b, self.net0, &mut self.state0)?.into())
            }
            (Rep3AcvmType::Shared(a), Rep3AcvmType::Shared(b)) => {
                Ok(arithmetic::ge(a, b, self.net0, &mut self.state0)?.into())
            }
        }
    }

    fn right_shift(&mut self, input: Self::AcvmType, shift: usize) -> eyre::Result<Self::AcvmType> {
        match input {
            Rep3AcvmType::Public(a) => {
                let x: BigUint = a.into();
                Ok(Rep3AcvmType::Public(F::from(x >> shift)))
            }
            Rep3AcvmType::Shared(shared) => Ok(Rep3AcvmType::Shared(yao::field_int_div_power_2(
                shared,
                self.net0,
                &mut self.state0,
                shift,
            )?)),
        }
    }

    fn set_point_to_value_if_zero<C: CurveGroup<BaseField = F>>(
        &mut self,
        point: Self::AcvmPoint<C>,
        value: Self::AcvmPoint<C>,
    ) -> eyre::Result<Self::AcvmPoint<C>> {
        match point {
            Rep3AcvmPoint::Public(point) => {
                if point.is_zero() {
                    Ok(value)
                } else {
                    Ok(Rep3AcvmPoint::Public(point))
                }
            }
            Rep3AcvmPoint::Shared(point) => {
                let is_zero = pointshare::is_zero(point.to_owned(), self.net0, &mut self.state0)?;
                let is_zero = Rep3BigUintShare::<C::ScalarField>::new(
                    BigUint::from(is_zero.0),
                    BigUint::from(is_zero.1),
                );
                let is_zero = conversion::bit_inject(&is_zero, self.net0, &mut self.state0)?;

                let sub = match value {
                    Rep3AcvmPoint::Public(value) => {
                        let mut neg = -point.to_owned();
                        pointshare::add_assign_public(&mut neg, &value, self.id);
                        neg
                    }
                    Rep3AcvmPoint::Shared(value) => pointshare::sub(&value, &point),
                };

                let mut res = pointshare::scalar_mul(&sub, is_zero, self.net0, &mut self.state0)?;
                pointshare::add_assign(&mut res, &point);

                Ok(Rep3AcvmPoint::Shared(res))
            }
        }
    }

    fn sha256_compression(
        &mut self,
        state: &[Self::AcvmType; 8],
        message: &[Self::AcvmType; 16],
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        if state.iter().any(|v| Self::is_shared(v)) || message.iter().any(|v| Self::is_shared(v)) {
            let state = array::from_fn(|i| match state[i] {
                Rep3AcvmType::Public(public) => {
                    arithmetic::promote_to_trivial_share(self.id, public)
                }
                Rep3AcvmType::Shared(shared) => shared,
            });
            let message = array::from_fn(|i| match message[i] {
                Rep3AcvmType::Public(public) => {
                    arithmetic::promote_to_trivial_share(self.id, public)
                }
                Rep3AcvmType::Shared(shared) => shared,
            });
            let result = yao::sha256_from_bristol(&state, &message, self.net0, &mut self.state0)?;
            result
                .iter()
                .map(|y| Ok(Rep3AcvmType::Shared(*y)))
                .collect::<Result<Vec<_>, _>>()
        } else {
            let mut state_as_u32 = [0u32; 8];
            for (i, input) in state.iter().enumerate() {
                let input = Self::get_public(input).expect("Already checked it is public");
                let x: BigUint = (input.into_bigint()).into();
                state_as_u32[i] = x.iter_u32_digits().next().unwrap_or_default();
            }
            let mut blocks = [0_u8; 64];
            for (i, input) in message.iter().enumerate() {
                let input = Self::get_public(input).expect("Already checked it is public");
                let x: BigUint = (input.into_bigint()).into();
                let message_as_u32 = x.iter_u32_digits().next().unwrap_or_default();
                let bytes = message_as_u32.to_be_bytes();
                blocks[i * 4..i * 4 + 4].copy_from_slice(&bytes);
            }

            let blocks = blocks.into();
            sha2::compress256(&mut state_as_u32, &[blocks]);
            state_as_u32
                .iter()
                .map(|x| Ok(Rep3AcvmType::Public(F::from(*x))))
                .collect()
        }
    }

    fn sha256_get_overflow_bit(
        &mut self,
        input: Self::ArithmeticShare,
    ) -> eyre::Result<Self::ArithmeticShare> {
        let shared = conversion::a2b_selector(input, self.net0, &mut self.state0)?;

        let mut result = Rep3BigUintShare::default();
        for i in 32..35 {
            result.a.set_bit(i as u64 - 32, shared.a.bit(i as u64));
            result.b.set_bit(i as u64 - 32, shared.b.bit(i as u64));
        }
        conversion::b2a_selector(&result.clone(), self.net0, &mut self.state0)
    }

    fn slice_and_get_sparse_table_with_rotation_values(
        &mut self,
        input1: Self::ArithmeticShare,
        input2: Self::ArithmeticShare,
        basis_bits: &[u64],
        rotation: &[u32],
        total_bitsize: usize,
        base: u64,
    ) -> eyre::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )> {
        let result = yao::get_sparse_table_with_rotation_values(
            input1,
            input2,
            self.net0,
            &mut self.state0,
            basis_bits,
            rotation,
            total_bitsize,
        )?;
        let slices = basis_bits.len();
        let num_outputs = result.len();
        debug_assert_eq!(num_outputs, 2 * slices + 2 * 32 * slices);
        let key_a_slices = result
            .iter()
            .take(slices)
            .map(|a| Rep3AcvmType::Shared(*a))
            .collect();
        let key_b_slices = result
            .iter()
            .skip(slices)
            .take(slices)
            .map(|a| Rep3AcvmType::Shared(*a))
            .collect();

        let rotation_values: Vec<_> = result
            .into_iter()
            .skip(2 * slices)
            .map(|a| Rep3AcvmType::Shared(a))
            .collect();
        let base_powers = get_base_powers::<32>(base);
        let base_powers: [F; 32] = array::from_fn(|i| F::from(base_powers[i].clone()));

        let mut res0 = Vec::with_capacity(rotation_values.len() / 64);
        let mut res1 = Vec::with_capacity(rotation_values.len() / 64);
        for chunk in rotation_values.chunks_exact(64) {
            let vec_t0 = &chunk[..32];
            let vec_t1 = &chunk[32..];
            let mut sum_a = self.mul_with_public(base_powers[0], vec_t0[0].to_owned());
            let mut sum_b = self.mul_with_public(base_powers[0], vec_t1[0].to_owned());
            for (vec_t0_, vec_t1_, base_power) in izip!(
                vec_t0.iter().cloned(),
                vec_t1.iter().cloned(),
                base_powers.iter()
            )
            .skip(1)
            {
                let tmp = self.mul_with_public(*base_power, vec_t0_);
                sum_a = self.add(sum_a, tmp);
                let tmp = self.mul_with_public(*base_power, vec_t1_);
                sum_b = self.add(sum_b, tmp);
            }
            res0.push(sum_a);
            res1.push(sum_b);
        }

        Ok((res0, res1, key_a_slices, key_b_slices))
    }

    fn slice_and_get_sparse_normalization_values(
        &mut self,
        input1: Self::ArithmeticShare,
        input2: Self::ArithmeticShare,
        base_bits: &[u64],
        base: u64,
        total_output_bitlen_per_field: usize,
        table_type: &SHA256Table,
    ) -> eyre::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )> {
        let result = yao::get_sparse_normalization_values(
            input1,
            input2,
            self.net0,
            &mut self.state0,
            base_bits,
            base,
            total_output_bitlen_per_field,
            table_type,
        )?;
        let num_outputs = result.len();
        debug_assert_eq!(num_outputs % 3, 0);
        let size = num_outputs / 3;
        let key_a_slices = result
            .iter()
            .take(size)
            .map(|a| Rep3AcvmType::Shared(*a))
            .collect();
        let key_b_slices = result
            .iter()
            .skip(size)
            .take(size)
            .map(|a| Rep3AcvmType::Shared(*a))
            .collect();
        let key_values = result
            .into_iter()
            .skip(2 * size)
            .map(|a| Rep3AcvmType::Shared(a))
            .collect();

        Ok((key_values, key_a_slices, key_b_slices))
    }

    fn blake2s_hash(
        &mut self,
        message_input: Vec<Self::AcvmType>,
        num_bits: &[usize],
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        if message_input.iter().any(|v| Self::is_shared(v)) {
            let message_input: Vec<_> = message_input
                .into_iter()
                .map(|y| match y {
                    Rep3AcvmType::Public(public) => {
                        arithmetic::promote_to_trivial_share(self.id, public)
                    }
                    Rep3AcvmType::Shared(shared) => shared,
                })
                .collect();
            let result = yao::blake2s(&message_input, self.net0, &mut self.state0, num_bits)?;
            result
                .into_iter()
                .map(|y| Ok(Rep3AcvmType::Shared(y)))
                .collect::<Result<Vec<_>, _>>()
        } else {
            let mut real_input = Vec::new();
            for (inp, num_bits) in message_input.into_iter().zip(num_bits.iter()) {
                let inp = Self::get_public(&inp).expect("Already checked it is public");
                let num_elements = num_bits.div_ceil(8); // We need to round to the next byte
                let bytes = inp.into_bigint().to_bytes_le();
                real_input.extend_from_slice(&bytes[..num_elements])
            }
            let output_bytes: [u8; 32] = Blake2s256::digest(real_input).into();
            let result = output_bytes
                .into_iter()
                .map(|x| Rep3AcvmType::Public(F::from(x)))
                .collect();
            Ok(result)
        }
    }

    fn blake3_hash(
        &mut self,
        message_input: Vec<Self::AcvmType>,
        num_bits: &[usize],
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        if message_input.iter().any(|v| Self::is_shared(v)) {
            let message_input: Vec<_> = message_input
                .into_iter()
                .map(|y| match y {
                    Rep3AcvmType::Public(public) => {
                        arithmetic::promote_to_trivial_share(self.id, public)
                    }
                    Rep3AcvmType::Shared(shared) => shared,
                })
                .collect();
            let result = yao::blake3(&message_input, self.net0, &mut self.state0, num_bits)?;
            result
                .into_iter()
                .map(|y| Ok(Rep3AcvmType::Shared(y)))
                .collect::<Result<Vec<_>, _>>()
        } else {
            let mut real_input = Vec::new();
            for (inp, num_bits) in message_input.into_iter().zip(num_bits.iter()) {
                let inp = Self::get_public(&inp).expect("Already checked it is public");
                let num_elements = num_bits.div_ceil(8); // We need to round to the next byte
                let bytes = inp.into_bigint().to_bytes_le();
                real_input.extend_from_slice(&bytes[..num_elements])
            }
            let output_bytes: [u8; 32] = blake3::hash(&real_input).into();
            let result = output_bytes
                .into_iter()
                .map(|x| Rep3AcvmType::Public(F::from(x)))
                .collect();
            Ok(result)
        }
    }

    fn embedded_curve_add(
        &mut self,
        input1_x: Self::AcvmType,
        input1_y: Self::AcvmType,
        input1_infinite: Self::AcvmType,
        input2_x: Self::AcvmType,
        input2_y: Self::AcvmType,
        input2_infinite: Self::AcvmType,
    ) -> eyre::Result<(Self::AcvmType, Self::AcvmType, Self::AcvmType)> {
        // This is very hardcoded to the grumpkin curve
        if TypeId::of::<F>() != TypeId::of::<ark_bn254::Fr>() {
            panic!("Only BN254 is supported");
        }

        let input1_x =
            downcast::<_, Rep3AcvmType<ark_bn254::Fr>>(&input1_x).expect("We checked types");
        let input1_y =
            downcast::<_, Rep3AcvmType<ark_bn254::Fr>>(&input1_y).expect("We checked types");
        let input1_infinite =
            downcast::<_, Rep3AcvmType<ark_bn254::Fr>>(&input1_infinite).expect("We checked types");
        let input2_x =
            downcast::<_, Rep3AcvmType<ark_bn254::Fr>>(&input2_x).expect("We checked types");
        let input2_y =
            downcast::<_, Rep3AcvmType<ark_bn254::Fr>>(&input2_y).expect("We checked types");
        let input2_infinite =
            downcast::<_, Rep3AcvmType<ark_bn254::Fr>>(&input2_infinite).expect("We checked types");

        let point1 = Self::create_grumpkin_point(
            input1_x,
            input1_y,
            input1_infinite,
            self.net0,
            &mut self.state0,
            true,
        )?;

        let point2 = Self::create_grumpkin_point(
            input2_x,
            input2_y,
            input2_infinite,
            self.net0,
            &mut self.state0,
            true,
        )?;

        let shared = match (point1, point2) {
            (Rep3AcvmPoint::Public(lhs), Rep3AcvmPoint::Public(rhs)) => {
                let res = lhs + rhs;
                let res = if let Some((out_x, out_y)) = res.into_affine().xy() {
                    let out_x = *downcast(&out_x).expect("We checked types");
                    let out_y = *downcast(&out_y).expect("We checked types");
                    (out_x, out_y, F::zero())
                } else {
                    (F::zero(), F::zero(), F::one())
                };
                return Ok((res.0.into(), res.1.into(), res.2.into()));
            }
            (Rep3AcvmPoint::Public(public), Rep3AcvmPoint::Shared(mut shared))
            | (Rep3AcvmPoint::Shared(mut shared), Rep3AcvmPoint::Public(public)) => {
                pointshare::add_assign_public(&mut shared, &public, self.id);
                shared
            }
            (Rep3AcvmPoint::Shared(lhs), Rep3AcvmPoint::Shared(rhs)) => pointshare::add(&lhs, &rhs),
        };

        let (x, y, i) =
            conversion::point_share_to_fieldshares(shared, self.net0, &mut self.state0)?;
        let x = *downcast(&x).expect("We checked types");
        let y = *downcast(&y).expect("We checked types");
        let i = *downcast(&i).expect("We checked types");

        // Set x,y to 0 of infinity is one.
        // TODO is this even necesary?
        let mul = arithmetic::sub_public_by_shared(F::one(), i, self.id);
        let res = arithmetic::mul_vec(&[x, y], &[mul, mul], self.net0, &mut self.state0)?;

        Ok((res[0].into(), res[1].into(), i.into()))
    }

    fn aes128_encrypt(
        &mut self,
        scalars: &[Self::AcvmType],
        iv: Vec<Self::AcvmType>,
        key: Vec<Self::AcvmType>,
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        if scalars
            .iter()
            .zip(iv.iter().zip(key.iter()))
            .all(|(scalar, (iv_elem, key_elem))| {
                !Self::is_shared(scalar) && !Self::is_shared(iv_elem) && !Self::is_shared(key_elem)
            })
        {
            let mut scalar_to_be_bytes = Vec::with_capacity(scalars.len());
            let mut iv_to_be_bytes = Vec::with_capacity(iv.len());
            let mut key_to_be_bytes = Vec::with_capacity(key.len());
            for inp in scalars.iter() {
                let inp = Self::get_public(inp).expect("Already checked it is public");
                let byte = inp.into_bigint().as_ref()[0].to_le_bytes()[0];
                scalar_to_be_bytes.push(byte);
            }
            for inp in iv {
                let inp = Self::get_public(&inp).expect("Already checked it is public");
                let byte = inp.into_bigint().as_ref()[0].to_le_bytes()[0];
                iv_to_be_bytes.push(byte);
            }
            for inp in key {
                let inp = Self::get_public(&inp).expect("Already checked it is public");
                let byte = inp.into_bigint().as_ref()[0].to_le_bytes()[0];
                key_to_be_bytes.push(byte);
            }
            let cipher = Cipher::new_128(
                key_to_be_bytes
                    .as_slice()
                    .try_into()
                    .expect("slice with incorrect length"),
            );
            let encrypted = cipher.cbc_encrypt(&iv_to_be_bytes, &scalar_to_be_bytes);
            encrypted
                .into_iter()
                .map(|x| Ok(Rep3AcvmType::Public(F::from(x as u128))))
                .collect()
        } else {
            let scalars: Vec<_> = scalars
                .iter()
                .map(|y| match y {
                    Rep3AcvmType::Public(public) => {
                        arithmetic::promote_to_trivial_share(self.state0.id, *public)
                    }
                    Rep3AcvmType::Shared(shared) => *shared,
                })
                .collect();
            let iv: Vec<_> = iv
                .iter()
                .map(|y| match y {
                    Rep3AcvmType::Public(public) => {
                        arithmetic::promote_to_trivial_share(self.state0.id, *public)
                    }
                    Rep3AcvmType::Shared(shared) => *shared,
                })
                .collect();
            let key: Vec<_> = key
                .iter()
                .map(|y| match y {
                    Rep3AcvmType::Public(public) => {
                        arithmetic::promote_to_trivial_share(self.state0.id, *public)
                    }
                    Rep3AcvmType::Shared(shared) => *shared,
                })
                .collect();
            let result = yao::aes_from_bristol(&scalars, &key, &iv, self.net0, &mut self.state0)?;

            result
                .iter()
                .map(|y| Ok(Rep3AcvmType::Shared(*y)))
                .collect::<Result<Vec<_>, _>>()
        }
    }

    fn slice_and_get_aes_sparse_normalization_values_from_key(
        &mut self,
        input1: Self::ArithmeticShare,
        input2: Self::ArithmeticShare,
        base_bits: &[u64],
        base: u64,
    ) -> eyre::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )> {
        let bitsize = base_bits[0].ilog2() as usize;
        let _total_size = bitsize * base_bits.len();
        let results = yao::slice_and_map_from_sparse_form(
            input1,
            input2,
            self.net0,
            &mut self.state0,
            base_bits,
            base,
            64,
        )?;
        let slices = base_bits.len();
        let num_outputs = results.len();
        debug_assert_eq!(num_outputs, 2 * slices + 64 * slices);
        let key_a_slices: Vec<_> = results
            .iter()
            .take(slices)
            .map(|a| Rep3AcvmType::Shared(*a))
            .collect();
        let key_b_slices: Vec<_> = results
            .iter()
            .skip(slices)
            .take(slices)
            .map(|a| Rep3AcvmType::Shared(*a))
            .collect();

        let sliced_bits: Vec<_> = results
            .into_iter()
            .skip(2 * slices)
            .map(|a| Rep3AcvmType::Shared(a))
            .collect();
        let base_powers = get_base_powers::<32>(base);
        let base_powers: [F; 32] = array::from_fn(|i| F::from(base_powers[i].clone()));
        let mut res0 = Vec::with_capacity(sliced_bits.len() / 8);
        for chunk in sliced_bits.chunks_exact(8) {
            let vec_t0 = chunk.to_vec();
            let mut sum_a = self.mul_with_public(base_powers[0], vec_t0[0].clone());

            for (i, a) in vec_t0.iter().enumerate().skip(1).take(31) {
                let tmp = self.mul_with_public(base_powers[i], a.clone());
                sum_a = self.add(sum_a, tmp);
            }

            res0.push(sum_a);
        }
        Ok((res0, key_a_slices, key_b_slices))
    }

    fn slice_and_get_aes_sbox_values_from_key(
        &mut self,
        input1: Self::ArithmeticShare,
        input2: Self::ArithmeticShare,
        base_bits: &[u64],
        base: u64,
        sbox: &[u8],
    ) -> eyre::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )> {
        let results = yao::slice_and_map_from_sparse_form_sbox(
            input1,
            input2,
            self.net0,
            &mut self.state0,
            base_bits,
            base,
            64,
        )?;
        let slices = base_bits.len();
        let num_outputs = results.len();
        debug_assert_eq!(num_outputs, 3 * slices);
        let key_a_slices: Vec<_> = results
            .iter()
            .take(slices)
            .map(|a| Rep3AcvmType::Shared(*a))
            .collect();
        let key_b_slices: Vec<_> = results
            .iter()
            .skip(slices)
            .take(slices)
            .map(|a| Rep3AcvmType::Shared(*a))
            .collect();

        let res0 = conversion::a2b_many(&results[2 * slices..], self.net0, &mut self.state0)?;

        let sbox_lut = mpc_core::protocols::rep3_ring::lut::PublicPrivateLut::Public(
            sbox.iter().map(|&value| F::from(value)).collect::<Vec<_>>(),
        );
        let base_powers = get_base_powers::<32>(base);
        let base_powers: [F; 32] = array::from_fn(|i| F::from(base_powers[i].clone()));
        let mut res1 = Vec::with_capacity(res0.len());
        let mut res2 = Vec::with_capacity(res0.len());
        for index_bits in res0 {
            let sbox_value = Rep3LookupTable::get_from_public_lut_no_b2a_conversion::<u8, _>(
                index_bits,
                &sbox_lut,
                self.net0,
                self.net1,
                &mut self.state0,
                &mut self.state1,
            )?;
            let shift_1 = &sbox_value << 1;
            let shift_2 = &sbox_value >> 7;
            let and = shift_2 & BigUint::one();

            // This is a multiplication by 0x1b in the binary domain
            let mut and2a = &and << 4;
            and2a = and2a.bitxor(&and << 3);
            and2a = and2a.bitxor(&and << 1);
            and2a = and2a.bitxor(and);

            let swizzled = shift_1.bitxor(and2a);
            let value = swizzled.bitxor(sbox_value.clone());
            let mut a_bits_split = (0..8).map(|i| (&value >> i) & BigUint::one()).collect_vec();
            a_bits_split.extend(
                (0..8)
                    .map(|i| (&sbox_value >> i) & BigUint::one())
                    .collect_vec(),
            );
            let bin_share = mpc_core::protocols::rep3::conversion::bit_inject_many(
                &a_bits_split,
                self.net0,
                &mut self.state0,
            )?;
            let (first_bin_share, second_bin_share) = bin_share.split_at(bin_share.len() / 2);
            let mut sum_a = arithmetic::mul_public(first_bin_share[0], base_powers[0]);
            let mut sum_b = arithmetic::mul_public(second_bin_share[0], base_powers[0]);
            for (vec_t0_, vec_t1_, base_power) in izip!(
                first_bin_share.iter().cloned(),
                second_bin_share.iter().cloned(),
                base_powers.iter()
            )
            .skip(1)
            .take(31)
            {
                let tmp = arithmetic::mul_public(vec_t0_, *base_power);
                sum_a = arithmetic::add(sum_a, tmp);
                let tmp = arithmetic::mul_public(vec_t1_, *base_power);
                sum_b = arithmetic::add(sum_b, tmp);
            }
            res1.push(Rep3AcvmType::Shared(sum_b));
            res2.push(Rep3AcvmType::Shared(sum_a));
        }

        Ok((res1, res2, key_a_slices, key_b_slices))
    }

    fn accumulate_from_sparse_bytes(
        &mut self,
        inputs: &[Self::AcvmType],
        base: u64,
        input_bitsize: usize,
        output_bitsize: usize,
    ) -> eyre::Result<Self::AcvmType> {
        let inputs: Vec<_> = inputs
            .iter()
            .map(|y| {
                if Self::is_shared(y) {
                    Self::get_shared(y).expect("Already checked it is shared")
                } else {
                    self.promote_to_trivial_share(
                        Self::get_public(y).expect("Already checked it is public"),
                    )
                }
            })
            .collect();
        let result = yao::accumulate_from_sparse_bytes(
            &inputs,
            self.net0,
            &mut self.state0,
            input_bitsize,
            output_bitsize,
            base,
        )?;
        let num_outputs = result.len();
        debug_assert_eq!(num_outputs, 1);
        Ok(Rep3AcvmType::Shared(result[0]))
    }

    fn is_zero(&mut self, a: &Self::AcvmType) -> eyre::Result<Self::AcvmType> {
        match a {
            Rep3AcvmType::Public(a) => Ok(Rep3AcvmType::Public(F::from((a.is_zero()) as u64))),
            Rep3AcvmType::Shared(a) => {
                let is_zero = arithmetic::eq_public(*a, F::zero(), self.net0, &mut self.state0)?;
                Ok(Rep3AcvmType::Shared(is_zero))
            }
        }
    }
}
