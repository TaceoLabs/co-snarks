use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{MontConfig, One, PrimeField, Zero};
use co_brillig::mpc::{Rep3BrilligDriver, Rep3BrilligType};
use itertools::{izip, Itertools};
use mpc_core::gadgets::poseidon2::{Poseidon2, Poseidon2Precomputations};
use mpc_core::protocols::rep3::{
    arithmetic, binary, conversion, pointshare, yao, Rep3BigUintShare, Rep3PointShare,
};
use mpc_core::protocols::rep3_ring::gadgets::sort::{radix_sort_fields, radix_sort_fields_vec_by};
use mpc_core::{
    lut::LookupTableProvider,
    protocols::rep3::{
        network::{IoContext, Rep3Network},
        Rep3PrimeFieldShare,
    },
    protocols::rep3_ring::lut::Rep3LookupTable,
};
use num_bigint::BigUint;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::any::TypeId;
use std::array;
use std::marker::PhantomData;

use super::plain::PlainAcvmSolver;
use super::NoirWitnessExtensionProtocol;
type ArithmeticShare<F> = Rep3PrimeFieldShare<F>;

macro_rules! join {
    ($t1: expr, $t2: expr) => {{
        std::thread::scope(|s| {
            let t1 = s.spawn(|| $t1);
            let t2 = $t2;
            (t1.join().expect("can join"), t2)
        })
    }};
}

pub struct Rep3AcvmSolver<F: PrimeField, N: Rep3Network> {
    lut_provider: Rep3LookupTable<N>,
    io_context0: IoContext<N>,
    io_context1: IoContext<N>,
    plain_solver: PlainAcvmSolver<F>,
    phantom_data: PhantomData<F>,
}

impl<F: PrimeField, N: Rep3Network> Rep3AcvmSolver<F, N> {
    // TODO remove unwrap
    pub fn new(network: N) -> Self {
        let plain_solver = PlainAcvmSolver::<F>::default();
        let mut io_context = IoContext::init(network).unwrap();
        let forked = io_context.fork().unwrap();
        Self {
            lut_provider: Rep3LookupTable::new(),
            io_context0: io_context,
            io_context1: forked,
            plain_solver,
            phantom_data: PhantomData,
        }
    }

    pub fn into_io_contexts(self) -> (IoContext<N>, IoContext<N>) {
        (self.io_context0, self.io_context1)
    }

    pub fn into_network(self) -> N {
        self.io_context0.network
    }

    fn combine_grumpkin_scalar_field_limbs(
        low: &Rep3AcvmType<ark_bn254::Fr>,
        high: &Rep3AcvmType<ark_bn254::Fr>,
        io_context: &mut IoContext<N>,
        pedantic_solving: bool,
    ) -> std::io::Result<Rep3AcvmType<ark_grumpkin::Fr>> {
        let scale = ark_grumpkin::Fr::from(BigUint::one() << 128);
        let res = match (low, high) {
            (Rep3AcvmType::Public(low), Rep3AcvmType::Public(high)) => {
                let scalar_low = PlainAcvmSolver::<F>::bn254_fr_to_u128(*low)?;
                let scalar_high = PlainAcvmSolver::<F>::bn254_fr_to_u128(*high)?;
                let grumpkin_integer: BigUint = (BigUint::from(scalar_high) << 128) + scalar_low;

                // Check if this is smaller than the grumpkin modulus
                if pedantic_solving && grumpkin_integer >= ark_grumpkin::FrConfig::MODULUS.into() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "{} is not a valid grumpkin scalar",
                            grumpkin_integer.to_str_radix(16)
                        ),
                    ));
                }
                Rep3AcvmType::Public(ark_grumpkin::Fr::from(grumpkin_integer))
            }
            (Rep3AcvmType::Public(low), Rep3AcvmType::Shared(high)) => {
                let scalar_low = PlainAcvmSolver::<F>::bn254_fr_to_u128(*low)?;
                // Change the sharing field
                let scalar_high = conversion::a2b(*high, io_context)?;
                let scalar_high =
                    Rep3BigUintShare::<ark_grumpkin::Fr>::new(scalar_high.a, scalar_high.b);
                let scalar_high = conversion::b2a(&scalar_high, io_context)?;

                let res =
                    arithmetic::add_public(scalar_high * scale, scalar_low.into(), io_context.id);
                Rep3AcvmType::Shared(res)
            }
            (Rep3AcvmType::Shared(low), Rep3AcvmType::Public(high)) => {
                let scalar_high = PlainAcvmSolver::<F>::bn254_fr_to_u128(*high)?;
                // Change the sharing field
                let scalar_low = conversion::a2b(*low, io_context)?;
                let scalar_low =
                    Rep3BigUintShare::<ark_grumpkin::Fr>::new(scalar_low.a, scalar_low.b);
                let scalar_low = conversion::b2a(&scalar_low, io_context)?;

                let res = arithmetic::add_public(
                    scalar_low,
                    scale * ark_grumpkin::Fr::from(scalar_high),
                    io_context.id,
                );
                Rep3AcvmType::Shared(res)
            }
            (Rep3AcvmType::Shared(low), Rep3AcvmType::Shared(high)) => {
                // Change the sharing field

                // TODO parallelize these
                let scalar_low = conversion::a2b(*low, io_context)?;
                let scalar_low =
                    Rep3BigUintShare::<ark_grumpkin::Fr>::new(scalar_low.a, scalar_low.b);
                let scalar_low = conversion::b2a(&scalar_low, io_context)?;

                let scalar_high = conversion::a2b(*high, io_context)?;
                let scalar_high =
                    Rep3BigUintShare::<ark_grumpkin::Fr>::new(scalar_high.a, scalar_high.b);
                let scalar_high = conversion::b2a(&scalar_high, io_context)?;

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
        io_context: &mut IoContext<N>,
        pedantic_solving: bool,
    ) -> std::io::Result<Rep3AcvmPoint<ark_grumpkin::Projective>> {
        if let Rep3AcvmType::Public(is_infinity) = is_infinity {
            if pedantic_solving && is_infinity > &ark_bn254::Fr::one() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "--pedantic-solving: is_infinity expected to be a bool, but found to be > 1",
                ));
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
            Rep3AcvmType::Public(x) => arithmetic::promote_to_trivial_share(io_context.id, *x),
            Rep3AcvmType::Shared(x) => *x,
        };
        let y = match y {
            Rep3AcvmType::Public(y) => arithmetic::promote_to_trivial_share(io_context.id, *y),
            Rep3AcvmType::Shared(y) => *y,
        };
        let is_infinity = match is_infinity {
            Rep3AcvmType::Public(is_infinity) => {
                arithmetic::promote_to_trivial_share(io_context.id, *is_infinity)
            }
            Rep3AcvmType::Shared(is_infinity) => *is_infinity,
        };
        let res = conversion::fieldshares_to_pointshare(x, y, is_infinity, io_context)?;
        Ok(Rep3AcvmPoint::Shared(res))
    }

    fn scalar_point_mul<C: CurveGroup>(
        a: Rep3AcvmType<C::ScalarField>,
        b: Rep3AcvmPoint<C>,
        io_context: &mut IoContext<N>,
    ) -> std::io::Result<Rep3AcvmPoint<C>> {
        let result = match (a, b) {
            (Rep3AcvmType::Public(a), Rep3AcvmPoint::Public(b)) => Rep3AcvmPoint::Public(b * a),
            (Rep3AcvmType::Public(a), Rep3AcvmPoint::Shared(b)) => {
                Rep3AcvmPoint::Shared(pointshare::scalar_mul_public_scalar(&b, a))
            }
            (Rep3AcvmType::Shared(a), Rep3AcvmPoint::Public(b)) => {
                Rep3AcvmPoint::Shared(pointshare::scalar_mul_public_point(&b, a))
            }
            (Rep3AcvmType::Shared(a), Rep3AcvmPoint::Shared(b)) => {
                let result = pointshare::scalar_mul(&b, a, io_context)?;
                Rep3AcvmPoint::Shared(result)
            }
        };
        Ok(result)
    }

    fn add_assign_point<C: CurveGroup>(
        mut inout: &mut Rep3AcvmPoint<C>,
        other: Rep3AcvmPoint<C>,
        io_context: &mut IoContext<N>,
    ) {
        match (&mut inout, other) {
            (Rep3AcvmPoint::Public(inout), Rep3AcvmPoint::Public(other)) => *inout += other,
            (Rep3AcvmPoint::Shared(inout), Rep3AcvmPoint::Shared(other)) => {
                pointshare::add_assign(inout, &other)
            }
            (Rep3AcvmPoint::Public(inout_), Rep3AcvmPoint::Shared(mut other)) => {
                pointshare::add_assign_public(&mut other, inout_, io_context.id);
                *inout = Rep3AcvmPoint::Shared(other);
            }
            (Rep3AcvmPoint::Shared(inout), Rep3AcvmPoint::Public(other)) => {
                pointshare::add_assign_public(inout, &other, io_context.id);
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
                f.write_str(&format!("Arithmetic (a: {}, b: {})", a, b))
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
                f.write_str(&format!("Arithmetic (a: {}, b: {})", a, b))
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

impl<F: PrimeField> From<Rep3AcvmType<F>> for Rep3BrilligType<F> {
    fn from(val: Rep3AcvmType<F>) -> Self {
        match val {
            Rep3AcvmType::Public(public) => Rep3BrilligType::public_field(public),
            Rep3AcvmType::Shared(share) => Rep3BrilligType::shared_field(share),
        }
    }
}

impl<F: PrimeField> Rep3AcvmType<F> {
    fn from_brillig_type<N: Rep3Network>(
        value: Rep3BrilligType<F>,
        io_context: &mut IoContext<N>,
    ) -> eyre::Result<Self> {
        match value {
            Rep3BrilligType::Public(public) => Ok(Rep3AcvmType::Public(public.into_field())),
            Rep3BrilligType::Shared(shared) => {
                let shared = Rep3BrilligType::into_arithmetic_share(io_context, shared)?;
                Ok(Rep3AcvmType::Shared(shared))
            }
        }
    }
}

impl<F: PrimeField, N: Rep3Network> NoirWitnessExtensionProtocol<F> for Rep3AcvmSolver<F, N> {
    type Lookup = Rep3LookupTable<N>;

    type ArithmeticShare = Rep3PrimeFieldShare<F>;

    type AcvmType = Rep3AcvmType<F>;
    type AcvmPoint<C: CurveGroup<BaseField = F>> = Rep3AcvmPoint<C>;

    type BrilligDriver = Rep3BrilligDriver<F, N>;

    fn init_brillig_driver(&mut self) -> std::io::Result<Self::BrilligDriver> {
        Ok(Rep3BrilligDriver::with_io_context(self.io_context0.fork()?))
    }

    fn parse_brillig_result(
        &mut self,
        brillig_result: Vec<Rep3BrilligType<F>>,
    ) -> eyre::Result<Vec<Self::AcvmType>> {
        brillig_result
            .into_iter()
            .map(|value| Rep3AcvmType::from_brillig_type(value, &mut self.io_context0))
            .collect()
    }

    fn cmux(
        &mut self,
        cond: Self::AcvmType,
        truthy: Self::AcvmType,
        falsy: Self::AcvmType,
    ) -> std::io::Result<Self::AcvmType> {
        match (cond, truthy, falsy) {
            (Rep3AcvmType::Public(cond), truthy, falsy) => {
                assert!(cond.is_one() || cond.is_zero());
                if cond.is_one() {
                    Ok(truthy)
                } else {
                    Ok(falsy)
                }
            }
            (Rep3AcvmType::Shared(cond), truthy, falsy) => {
                let b_min_a = self.sub(truthy, falsy.clone());
                let d = self.mul(cond.into(), b_min_a)?;
                Ok(self.add(falsy, d))
            }
        }
    }

    fn shared_zeros(&mut self, len: usize) -> std::io::Result<Vec<Self::AcvmType>> {
        let a = (0..len)
            .map(|_| self.io_context0.masking_field_element())
            .collect::<Vec<_>>();
        let b = self.io_context0.network.reshare_many(&a)?;
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
        let id = self.io_context0.id;
        let result = match target.to_owned() {
            Rep3AcvmType::Public(secret) => Rep3AcvmType::Public(public + secret),
            Rep3AcvmType::Shared(secret) => {
                Rep3AcvmType::Shared(arithmetic::add_public(secret, public, id))
            }
        };
        *target = result;
    }

    fn add(&self, lhs: Self::AcvmType, rhs: Self::AcvmType) -> Self::AcvmType {
        let id = self.io_context0.id;
        match (lhs, rhs) {
            (Rep3AcvmType::Public(lhs), Rep3AcvmType::Public(rhs)) => {
                Rep3AcvmType::Public(lhs + rhs)
            }
            (Rep3AcvmType::Public(public), Rep3AcvmType::Shared(shared))
            | (Rep3AcvmType::Shared(shared), Rep3AcvmType::Public(public)) => {
                Rep3AcvmType::Shared(arithmetic::add_public(shared, public, id))
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
                pointshare::add_assign_public(&mut shared, &public, self.io_context0.id);
                Rep3AcvmPoint::Shared(shared)
            }
            (Rep3AcvmPoint::Shared(lhs), Rep3AcvmPoint::Shared(rhs)) => {
                let result = pointshare::add(&lhs, &rhs);
                Rep3AcvmPoint::Shared(result)
            }
        }
    }

    fn sub(&mut self, share_1: Self::AcvmType, share_2: Self::AcvmType) -> Self::AcvmType {
        let id = self.io_context0.id;

        match (share_1, share_2) {
            (Rep3AcvmType::Public(share_1), Rep3AcvmType::Public(share_2)) => {
                Rep3AcvmType::Public(share_1 - share_2)
            }
            (Rep3AcvmType::Public(share_1), Rep3AcvmType::Shared(share_2)) => {
                Rep3AcvmType::Shared(arithmetic::sub_public_by_shared(share_1, share_2, id))
            }
            (Rep3AcvmType::Shared(share_1), Rep3AcvmType::Public(share_2)) => {
                Rep3AcvmType::Shared(arithmetic::sub_shared_by_public(share_1, share_2, id))
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
    ) -> std::io::Result<Self::AcvmType> {
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
                let result = arithmetic::mul(secret_1, secret_2, &mut self.io_context0)?;
                Ok(Rep3AcvmType::Shared(result))
            }
        }
    }

    fn invert(&mut self, secret: Self::AcvmType) -> std::io::Result<Self::AcvmType> {
        match secret {
            Rep3AcvmType::Public(secret) => {
                let inv = secret.inverse().ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "Cannot invert zero")
                })?;
                Ok(Rep3AcvmType::Public(inv))
            }
            Rep3AcvmType::Shared(secret) => {
                let inv = arithmetic::inv(secret, &mut self.io_context0)?;
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
        let id = self.io_context0.id;
        let result = match (w_l, target.to_owned()) {
            (Rep3AcvmType::Public(w_l), Rep3AcvmType::Public(result)) => {
                Rep3AcvmType::Public(q_l * w_l + result)
            }
            (Rep3AcvmType::Public(w_l), Rep3AcvmType::Shared(result)) => {
                Rep3AcvmType::Shared(arithmetic::add_public(result, q_l * w_l, id))
            }
            (Rep3AcvmType::Shared(w_l), Rep3AcvmType::Public(result)) => {
                let mul = arithmetic::mul_public(w_l, q_l);
                Rep3AcvmType::Shared(arithmetic::add_public(mul, result, id))
            }
            (Rep3AcvmType::Shared(w_l), Rep3AcvmType::Shared(result)) => {
                let mul = arithmetic::mul_public(w_l, q_l);
                Rep3AcvmType::Shared(arithmetic::add(mul, result))
            }
        };
        *target = result;
    }

    fn add_assign(&mut self, target: &mut Self::AcvmType, rhs: Self::AcvmType) {
        let id = self.io_context0.id;
        let result = match (target.clone(), rhs) {
            (Rep3AcvmType::Public(lhs), Rep3AcvmType::Public(rhs)) => {
                Rep3AcvmType::Public(lhs + rhs)
            }
            (Rep3AcvmType::Public(public), Rep3AcvmType::Shared(shared))
            | (Rep3AcvmType::Shared(shared), Rep3AcvmType::Public(public)) => {
                Rep3AcvmType::Shared(arithmetic::add_public(shared, public, id))
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
    ) -> std::io::Result<Self::AcvmType> {
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
                let shared_mul = arithmetic::mul(lhs, rhs, &mut self.io_context0)?;
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
        let io_context = &mut self.io_context0;
        let result = match (q_l, c) {
            (Rep3AcvmType::Public(q_l), Rep3AcvmType::Public(c)) => {
                Rep3AcvmType::Public(self.plain_solver.solve_equation(q_l, c)?)
            }
            (Rep3AcvmType::Public(q_l), Rep3AcvmType::Shared(c)) => {
                Rep3AcvmType::Shared(arithmetic::div_shared_by_public(arithmetic::neg(c), q_l)?)
            }
            (Rep3AcvmType::Shared(q_l), Rep3AcvmType::Public(c)) => {
                let result = arithmetic::div_public_by_shared(-c, q_l, io_context)?;
                Rep3AcvmType::Shared(result)
            }
            (Rep3AcvmType::Shared(q_l), Rep3AcvmType::Shared(c)) => {
                let result = arithmetic::div(arithmetic::neg(c), q_l, io_context)?;
                Rep3AcvmType::Shared(result)
            }
        };
        Ok(result)
    }

    fn init_lut_by_acvm_type(
        &mut self,
        values: Vec<Self::AcvmType>,
    ) -> <Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::LutType {
        let id = self.io_context0.id;

        if values.iter().any(|v| Self::is_shared(v)) {
            let mut shares = Vec::with_capacity(values.len());
            for val in values {
                shares.push(match val {
                    Rep3AcvmType::Public(public) => {
                        arithmetic::promote_to_trivial_share(id, public)
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
    ) -> std::io::Result<Self::AcvmType> {
        let result = match index {
            Rep3AcvmType::Public(public) => {
                let index: BigUint = public.into();
                let index = usize::try_from(index).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Index can not be translated to usize",
                    )
                })?;

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
                &mut self.io_context0,
                &mut self.io_context1,
            )?),
        };
        Ok(result)
    }

    fn read_from_public_luts(
        &mut self,
        index: Self::AcvmType,
        luts: &[Vec<F>],
    ) -> std::io::Result<Vec<Self::AcvmType>> {
        let mut result = Vec::with_capacity(luts.len());
        match index {
            Rep3AcvmType::Public(index) => {
                let index: BigUint = index.into();
                let index = usize::try_from(index).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Index can not be translated to usize",
                    )
                })?;
                for lut in luts {
                    result.push(Rep3AcvmType::Public(lut[index].to_owned()));
                }
            }
            Rep3AcvmType::Shared(index) => {
                let res = Rep3LookupTable::<N>::get_from_public_luts(
                    index,
                    luts,
                    &mut self.io_context0,
                    &mut self.io_context1,
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
    ) -> std::io::Result<()> {
        let id = self.io_context0.id;
        match (index, value) {
            (Rep3AcvmType::Public(index), Rep3AcvmType::Public(value)) => {
                let index: BigUint = (index).into();
                let index = usize::try_from(index).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Index can not be translated to usize",
                    )
                })?;

                match lut {
                    mpc_core::protocols::rep3_ring::lut::PublicPrivateLut::Public(vec) => {
                        vec[index] = value;
                    }
                    mpc_core::protocols::rep3_ring::lut::PublicPrivateLut::Shared(vec) => {
                        vec[index] = arithmetic::promote_to_trivial_share(id, value);
                    }
                }
            }
            (Rep3AcvmType::Public(index), Rep3AcvmType::Shared(value)) => {
                let index: BigUint = (index).into();
                let index = usize::try_from(index).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Index can not be translated to usize",
                    )
                })?;

                match lut {
                    mpc_core::protocols::rep3_ring::lut::PublicPrivateLut::Public(vec) => {
                        let mut vec = vec
                            .iter()
                            .map(|value| arithmetic::promote_to_trivial_share(id, *value))
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
                let value = arithmetic::promote_to_trivial_share(id, value);
                self.lut_provider.write_to_lut(
                    index,
                    value,
                    lut,
                    &mut self.io_context0,
                    &mut self.io_context1,
                )?;
            }
            (Rep3AcvmType::Shared(index), Rep3AcvmType::Shared(value)) => {
                self.lut_provider.write_to_lut(
                    index,
                    value,
                    lut,
                    &mut self.io_context0,
                    &mut self.io_context1,
                )?;
            }
        }
        Ok(())
    }

    fn one_hot_vector_from_shared_index(
        &mut self,
        index: Self::ArithmeticShare,
        len: usize,
    ) -> std::io::Result<Vec<Self::ArithmeticShare>> {
        self.lut_provider
            .ohv_from_index(index, len, &mut self.io_context0, &mut self.io_context1)
    }

    fn write_to_shared_lut_from_ohv(
        &mut self,
        ohv: &[Self::ArithmeticShare],
        value: Self::ArithmeticShare,
        lut: &mut [Self::ArithmeticShare],
    ) -> std::io::Result<()> {
        self.lut_provider.write_to_shared_lut_from_ohv(
            ohv,
            value,
            lut,
            &mut self.io_context0,
            &mut self.io_context1,
        )
    }

    fn get_length_of_lut(lut: &<Self::Lookup as LookupTableProvider<F>>::LutType) -> usize {
        <Self::Lookup as mpc_core::lut::LookupTableProvider<F>>::get_lut_len(lut)
    }

    fn get_public_lut(
        lut: &<Self::Lookup as LookupTableProvider<F>>::LutType,
    ) -> std::io::Result<&Vec<F>> {
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

    fn open_many(&mut self, a: &[Self::ArithmeticShare]) -> std::io::Result<Vec<F>> {
        let bs = a.iter().map(|x| x.b).collect_vec();
        self.io_context0.network.send_next(bs)?;
        let mut cs = self.io_context0.network.recv_prev::<Vec<F>>()?;

        izip!(a, cs.iter_mut()).for_each(|(x, c)| *c += x.a + x.b);

        Ok(cs)
    }

    fn promote_to_trivial_share(&mut self, public_value: F) -> Self::ArithmeticShare {
        let id = self.io_context0.id;
        arithmetic::promote_to_trivial_share(id, public_value)
    }

    fn promote_to_trivial_shares(&mut self, public_values: &[F]) -> Vec<Self::ArithmeticShare> {
        let id = self.io_context0.id;
        public_values
            .par_iter()
            .with_min_len(1024)
            .map(|value| Self::ArithmeticShare::promote_from_trivial(value, id))
            .collect()
    }

    fn decompose_arithmetic(
        &mut self,
        input: Self::ArithmeticShare,
        total_bit_size_per_field: usize,
        decompose_bit_size: usize,
    ) -> std::io::Result<Vec<Self::ArithmeticShare>> {
        yao::decompose_arithmetic(
            input,
            &mut self.io_context0,
            total_bit_size_per_field,
            decompose_bit_size,
        )
    }

    fn decompose_arithmetic_many(
        &mut self,
        input: &[Self::ArithmeticShare],
        total_bit_size_per_field: usize,
        decompose_bit_size: usize,
    ) -> std::io::Result<Vec<Vec<Self::ArithmeticShare>>> {
        // Defines an upper bound on the size of the input vector to keep the GC at a reasonable size (for RAM)
        const BATCH_SIZE: usize = 512; // TODO adapt this if it requires too much RAM

        let num_decomps_per_field = total_bit_size_per_field.div_ceil(decompose_bit_size);
        let mut results = Vec::with_capacity(input.len());

        for inp_chunk in input.chunks(BATCH_SIZE) {
            let result = yao::decompose_arithmetic_many(
                inp_chunk,
                &mut self.io_context0,
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
    ) -> std::io::Result<Vec<Self::ArithmeticShare>> {
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
            &mut self.io_context0,
            &mut self.io_context1,
            bitsize,
        )
    }

    fn slice(
        &mut self,
        input: Self::ArithmeticShare,
        msb: u8,
        lsb: u8,
        bitsize: usize,
    ) -> std::io::Result<[Self::ArithmeticShare; 3]> {
        let res = yao::slice_arithmetic(
            input,
            &mut self.io_context0,
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
    ) -> std::io::Result<Self::AcvmType> {
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
                let shared = conversion::a2b_selector(shared, &mut self.io_context0)?;
                let public: BigUint = public.into();
                let public = public & mask;
                let binary = binary::and_with_public(&shared, &public); // Already includes masking
                let result = conversion::b2a_selector(&binary, &mut self.io_context0)?;
                Ok(Rep3AcvmType::Shared(result))
            }
            (Rep3AcvmType::Shared(lhs), Rep3AcvmType::Shared(rhs)) => {
                let (lhs, rhs) = join!(
                    conversion::a2b_selector(lhs, &mut self.io_context0),
                    conversion::a2b_selector(rhs, &mut self.io_context1)
                );
                let binary = binary::and(&lhs?, &rhs?, &mut self.io_context0)? & mask;
                let result = conversion::b2a_selector(&binary, &mut self.io_context0)?;
                Ok(Rep3AcvmType::Shared(result))
            }
        }
    }

    fn integer_bitwise_xor(
        &mut self,
        lhs: Self::AcvmType,
        rhs: Self::AcvmType,
        num_bits: u32,
    ) -> std::io::Result<Self::AcvmType> {
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
                let shared = conversion::a2b_selector(shared, &mut self.io_context0)?;
                let public: BigUint = public.into();
                let binary = binary::xor_public(&shared, &public, self.io_context0.id) & mask;
                let result = conversion::b2a_selector(&binary, &mut self.io_context0)?;
                Ok(Rep3AcvmType::Shared(result))
            }
            (Rep3AcvmType::Shared(lhs), Rep3AcvmType::Shared(rhs)) => {
                let (lhs, rhs) = join!(
                    conversion::a2b_selector(lhs, &mut self.io_context0),
                    conversion::a2b_selector(rhs, &mut self.io_context1)
                );
                let binary = binary::xor(&lhs?, &rhs?) & mask;
                let result = conversion::b2a_selector(&binary, &mut self.io_context0)?;
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
    ) -> std::io::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )> {
        let result = yao::slice_and(
            input1,
            input2,
            &mut self.io_context0,
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
    ) -> std::io::Result<(
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
        Vec<Self::AcvmType>,
    )> {
        let result = yao::slice_xor(
            input1,
            input2,
            &mut self.io_context0,
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

    fn sort_vec_by(
        &mut self,
        key: &[Self::AcvmType],
        inputs: Vec<&[Self::ArithmeticShare]>,
        bitsize: usize,
    ) -> std::io::Result<Vec<Vec<Self::ArithmeticShare>>> {
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
            &mut self.io_context0,
            &mut self.io_context1,
            bitsize,
        )
    }

    fn poseidon2_permutation<const T: usize, const D: u64>(
        &mut self,
        mut input: Vec<Self::AcvmType>,
        poseidon2: &Poseidon2<F, T, D>,
    ) -> std::io::Result<Vec<Self::AcvmType>> {
        if input.len() != T {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Expected {} values but encountered {}", T, input.len(),),
            ));
        }

        if input.iter().any(|x| Self::is_shared(x)) {
            let mut shared = array::from_fn(|i| match input[i] {
                Rep3AcvmType::Public(public) => {
                    // The initial linear layer of poseidon makes the whole state shared anyway
                    arithmetic::promote_to_trivial_share(self.io_context0.id, public)
                }
                Rep3AcvmType::Shared(shared) => shared,
            });
            let mut precomp = poseidon2.precompute_rep3(1, &mut self.io_context0)?;
            poseidon2.rep3_permutation_in_place_with_precomputation(
                &mut shared,
                &mut precomp,
                &mut self.io_context0,
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
    ) -> std::io::Result<Poseidon2Precomputations<Self::ArithmeticShare>> {
        poseidon2.precompute_rep3(num_poseidon, &mut self.io_context0)
    }

    fn poseidon2_external_round_inplace_with_precomp<const T: usize, const D: u64>(
        &mut self,
        input: &mut [Self::ArithmeticShare; T],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Self::ArithmeticShare>,
        poseidon2: &Poseidon2<F, T, D>,
    ) -> std::io::Result<()> {
        poseidon2.rep3_external_round_precomp(input, r, precomp, &mut self.io_context0)
    }

    fn poseidon2_internal_round_inplace_with_precomp<const T: usize, const D: u64>(
        &mut self,
        input: &mut [Self::ArithmeticShare; T],
        r: usize,
        precomp: &mut Poseidon2Precomputations<Self::ArithmeticShare>,
        poseidon2: &Poseidon2<F, T, D>,
    ) -> std::io::Result<()> {
        poseidon2.rep3_internal_round_precomp(input, r, precomp, &mut self.io_context0)
    }

    fn is_public_lut(lut: &<Self::Lookup as LookupTableProvider<F>>::LutType) -> bool {
        Self::Lookup::is_public_lut(lut)
    }

    fn equal(&mut self, a: &Self::AcvmType, b: &Self::AcvmType) -> std::io::Result<Self::AcvmType> {
        match (a, b) {
            (Rep3AcvmType::Public(a), Rep3AcvmType::Public(b)) => {
                Ok(Rep3AcvmType::Public(F::from(a == b)))
            }
            (Rep3AcvmType::Public(public), Rep3AcvmType::Shared(shared)) => {
                Ok(Rep3AcvmType::Shared(arithmetic::eq_public(
                    *shared,
                    *public,
                    &mut self.io_context0,
                )?))
            }

            (Rep3AcvmType::Shared(shared), Rep3AcvmType::Public(public)) => {
                Ok(Rep3AcvmType::Shared(arithmetic::eq_public(
                    *shared,
                    *public,
                    &mut self.io_context0,
                )?))
            }

            (Rep3AcvmType::Shared(a), Rep3AcvmType::Shared(b)) => Ok(Rep3AcvmType::Shared(
                arithmetic::eq(*a, *b, &mut self.io_context0)?,
            )),
        }
    }

    fn multi_scalar_mul(
        &mut self,
        points: &[Self::AcvmType],
        scalars_lo: &[Self::AcvmType],
        scalars_hi: &[Self::AcvmType],
        pedantic_solving: bool, // Cannot check values
    ) -> std::io::Result<(Self::AcvmType, Self::AcvmType, Self::AcvmType)> {
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
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Points and scalars must have the same length",
            ));
        }

        let mut output_point = Rep3AcvmPoint::Public(ark_grumpkin::Projective::zero());

        // TODO parallelize all points?
        for i in (0..points.len()).step_by(3) {
            let (point, grumpkin_integer) = join!(
                Self::create_grumpkin_point(
                    &points[i],
                    &points[i + 1],
                    &points[i + 2],
                    &mut self.io_context0,
                    pedantic_solving,
                ),
                Self::combine_grumpkin_scalar_field_limbs(
                    &scalars_lo[i / 3],
                    &scalars_hi[i / 3],
                    &mut self.io_context1,
                    pedantic_solving,
                )
            );
            let iteration_output_point =
                Self::scalar_point_mul(grumpkin_integer?, point?, &mut self.io_context0)?;
            Self::add_assign_point(
                &mut output_point,
                iteration_output_point,
                &mut self.io_context0,
            );
        }

        // TODO maybe find a way to unify this with pointshare_to_field_shares
        let res = match output_point {
            Rep3AcvmPoint::Public(output_point) => {
                if let Some((out_x, out_y)) = ark_grumpkin::Affine::from(output_point).xy() {
                    // Safety: We checked that the types match
                    let out_x = unsafe { *(&out_x as *const ark_bn254::Fr as *const F) };
                    // Safety: We checked that the types match
                    let out_y = unsafe { *(&out_y as *const ark_bn254::Fr as *const F) };

                    (out_x.into(), out_y.into(), F::zero().into())
                } else {
                    (F::zero().into(), F::zero().into(), F::one().into())
                }
            }
            Rep3AcvmPoint::Shared(output_point) => {
                let (x, y, i) =
                    conversion::point_share_to_fieldshares(output_point, &mut self.io_context0)?;
                // Set x,y to 0 of infinity is one.
                // TODO is this even necesary?
                let mul =
                    arithmetic::sub_public_by_shared(ark_bn254::Fr::one(), i, self.io_context0.id);
                let res = arithmetic::mul_vec(&[x, y], &[mul, mul], &mut self.io_context0)?;

                // Safety: We checked that the types match
                let out_x = unsafe {
                    *(&res[0] as *const Rep3PrimeFieldShare<ark_bn254::Fr>
                        as *const Rep3PrimeFieldShare<F>)
                };
                // Safety: We checked that the types match
                let out_y = unsafe {
                    *(&res[1] as *const Rep3PrimeFieldShare<ark_bn254::Fr>
                        as *const Rep3PrimeFieldShare<F>)
                };
                // Safety: We checked that the types match
                let out_i = unsafe {
                    *(&i as *const Rep3PrimeFieldShare<ark_bn254::Fr>
                        as *const Rep3PrimeFieldShare<F>)
                };
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
    ) -> std::io::Result<Self::AcvmPoint<C>> {
        // This is very hardcoded to the grumpkin curve
        if TypeId::of::<F>() != TypeId::of::<ark_bn254::Fr>() {
            panic!("Only BN254 is supported");
        }

        // Safety: We checked that the types match
        let x =
            unsafe { std::mem::transmute::<&Rep3AcvmType<F>, &Rep3AcvmType<ark_bn254::Fr>>(&x) };
        // Safety: We checked that the types match
        let y =
            unsafe { std::mem::transmute::<&Rep3AcvmType<F>, &Rep3AcvmType<ark_bn254::Fr>>(&y) };
        // Safety: We checked that the types match
        let is_infinity = unsafe {
            std::mem::transmute::<&Rep3AcvmType<F>, &Rep3AcvmType<ark_bn254::Fr>>(&is_infinity)
        };

        let point = Self::create_grumpkin_point(x, y, is_infinity, &mut self.io_context0, true)?;

        // Safety: We checked that the types match
        let y = unsafe {
            let val =
                &point as *const Rep3AcvmPoint<ark_grumpkin::Projective> as *const Rep3AcvmPoint<C>;
            (*val).to_owned()
        };

        Ok(y)
    }

    fn pointshare_to_field_shares<C: CurveGroup<BaseField = F>>(
        &mut self,
        point: Self::AcvmPoint<C>,
    ) -> std::io::Result<(Self::AcvmType, Self::AcvmType, Self::AcvmType)> {
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
                    conversion::point_share_to_fieldshares(point, &mut self.io_context0)?;
                // Set x,y to 0 of infinity is one.
                // TODO is this even necesary?
                let mul = arithmetic::sub_public_by_shared(F::one(), i, self.io_context0.id);
                let res = arithmetic::mul_vec(&[x, y], &[mul, mul], &mut self.io_context0)?;

                (res[0].into(), res[1].into(), i.into())
            }
        };
        Ok(res)
    }

    fn gt(&mut self, lhs: Self::AcvmType, rhs: Self::AcvmType) -> std::io::Result<Self::AcvmType> {
        match (lhs, rhs) {
            (Rep3AcvmType::Public(a), Rep3AcvmType::Public(b)) => {
                Ok(F::from((a > b) as u64).into())
            }
            (Rep3AcvmType::Public(a), Rep3AcvmType::Shared(b)) => {
                Ok(arithmetic::lt_public(b, a, &mut self.io_context0)?.into())
            }
            (Rep3AcvmType::Shared(a), Rep3AcvmType::Public(b)) => {
                Ok(arithmetic::ge_public(a, b, &mut self.io_context0)?.into())
            }
            (Rep3AcvmType::Shared(a), Rep3AcvmType::Shared(b)) => {
                Ok(arithmetic::ge(a, b, &mut self.io_context0)?.into())
            }
        }
    }
}
