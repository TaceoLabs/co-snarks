//! SPDZ Brillig Driver
//!
//! Implements `BrilligDriver` for SPDZ. Like Shamir, most operations on
//! shared values panic — only basic arithmetic (add, sub, mul) is supported.

use ark_ff::{Field, One, PrimeField};
use co_brillig::mpc::{BrilligDriver, PlainBrilligDriver, PlainBrilligType};
use mpc_core::MpcState;
use mpc_net::Network;
use spdz_core::types::SpdzPrimeFieldShare;
use spdz_core::SpdzState;
use std::marker::PhantomData;

/// Brillig type for SPDZ: public or shared values.
#[derive(Clone, Debug, PartialEq)]
pub enum SpdzBrilligType<F: PrimeField> {
    /// A public value.
    Public(PlainBrilligType<F>),
    /// A shared value (only field type supported for now).
    Shared(SpdzPrimeFieldShare<F>),
}

impl<F: PrimeField> From<F> for SpdzBrilligType<F> {
    fn from(value: F) -> Self {
        SpdzBrilligType::Public(PlainBrilligType::Field(value))
    }
}

impl<F: PrimeField> Default for SpdzBrilligType<F> {
    fn default() -> Self {
        Self::from(F::default())
    }
}

/// SPDZ Brillig driver.
pub struct SpdzBrilligDriver<'a, F: PrimeField, N: Network> {
    id: usize,
    net: &'a N,
    state: SpdzState<F>,
    plain_driver: PlainBrilligDriver<F>,
    phantom_data: PhantomData<F>,
}

impl<'a, F: PrimeField, N: Network> SpdzBrilligDriver<'a, F, N> {
    /// Create a new SPDZ Brillig driver.
    pub fn new(net: &'a N, state: SpdzState<F>) -> Self {
        Self {
            id: net.id(),
            net,
            state,
            plain_driver: PlainBrilligDriver::default(),
            phantom_data: PhantomData,
        }
    }
}

impl<F: PrimeField, N: Network> BrilligDriver<F> for SpdzBrilligDriver<'_, F, N> {
    type BrilligType = SpdzBrilligType<F>;

    fn fork(&mut self) -> eyre::Result<(Self, Self)> {
        // Branches run sequentially (not parallel), so both forks share
        // the same network reference. Each gets a forked state with split
        // preprocessing material. Matches Shamir's pattern.
        let state0 = self.state.fork(0)?;
        let state1 = self.state.fork(0)?;
        let fork0 = Self {
            id: self.id,
            net: self.net,
            state: state0,
            plain_driver: PlainBrilligDriver::default(),
            phantom_data: PhantomData,
        };
        let fork1 = Self {
            id: self.id,
            net: self.net,
            state: state1,
            plain_driver: PlainBrilligDriver::default(),
            phantom_data: PhantomData,
        };
        Ok((fork0, fork1))
    }

    fn cast(
        &mut self,
        src: Self::BrilligType,
        bit_size: brillig::BitSize,
    ) -> eyre::Result<Self::BrilligType> {
        match src {
            SpdzBrilligType::Public(p) => {
                Ok(SpdzBrilligType::Public(self.plain_driver.cast(p, bit_size)?))
            }
            SpdzBrilligType::Shared(_) => {
                eyre::bail!("Cannot cast shared values in SPDZ Brillig driver")
            }
        }
    }

    fn try_into_usize(val: Self::BrilligType) -> eyre::Result<usize> {
        match val {
            SpdzBrilligType::Public(p) => PlainBrilligDriver::try_into_usize(p),
            SpdzBrilligType::Shared(_) => eyre::bail!("Cannot convert shared value to usize"),
        }
    }

    fn try_into_char(val: Self::BrilligType) -> eyre::Result<char> {
        match val {
            SpdzBrilligType::Public(p) => PlainBrilligDriver::try_into_char(p),
            SpdzBrilligType::Shared(_) => eyre::bail!("Cannot convert shared value to char"),
        }
    }

    fn try_into_bool(val: Self::BrilligType) -> Result<bool, Self::BrilligType> {
        match val {
            SpdzBrilligType::Public(p) => {
                PlainBrilligDriver::<F>::try_into_bool(p).map_err(SpdzBrilligType::Public)
            }
            SpdzBrilligType::Shared(s) => Err(SpdzBrilligType::Shared(s)),
        }
    }

    fn public_value(val: F, bit_size: brillig::BitSize) -> Self::BrilligType {
        SpdzBrilligType::Public(PlainBrilligDriver::public_value(val, bit_size))
    }

    fn random(&mut self, other: &Self::BrilligType) -> Self::BrilligType {
        match other {
            SpdzBrilligType::Public(p) => {
                SpdzBrilligType::Public(self.plain_driver.random(p))
            }
            SpdzBrilligType::Shared(_) => {
                panic!("SpdzBrilligDriver::random not supported for shared values")
            }
        }
    }

    fn is_public(val: Self::BrilligType) -> bool {
        matches!(val, SpdzBrilligType::Public(_))
    }

    fn add(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        match (lhs, rhs) {
            (SpdzBrilligType::Public(l), SpdzBrilligType::Public(r)) => {
                Ok(SpdzBrilligType::Public(self.plain_driver.add(l, r)?))
            }
            (SpdzBrilligType::Shared(l), SpdzBrilligType::Shared(r)) => {
                Ok(SpdzBrilligType::Shared(l + r))
            }
            (SpdzBrilligType::Public(PlainBrilligType::Field(p)), SpdzBrilligType::Shared(s))
            | (SpdzBrilligType::Shared(s), SpdzBrilligType::Public(PlainBrilligType::Field(p))) => {
                Ok(SpdzBrilligType::Shared(spdz_core::arithmetic::add_public(
                    s,
                    p,
                    self.state.mac_key_share,
                    self.id,
                )))
            }
            _ => eyre::bail!("Unsupported add combination in SPDZ Brillig"),
        }
    }

    fn sub(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        match (lhs, rhs) {
            (SpdzBrilligType::Public(l), SpdzBrilligType::Public(r)) => {
                Ok(SpdzBrilligType::Public(self.plain_driver.sub(l, r)?))
            }
            (SpdzBrilligType::Shared(l), SpdzBrilligType::Shared(r)) => {
                Ok(SpdzBrilligType::Shared(l - r))
            }
            (SpdzBrilligType::Public(PlainBrilligType::Field(p)), SpdzBrilligType::Shared(s)) => {
                Ok(SpdzBrilligType::Shared(spdz_core::arithmetic::add_public(
                    -s,
                    p,
                    self.state.mac_key_share,
                    self.id,
                )))
            }
            (SpdzBrilligType::Shared(s), SpdzBrilligType::Public(PlainBrilligType::Field(p))) => {
                Ok(SpdzBrilligType::Shared(spdz_core::arithmetic::sub_public(
                    s,
                    p,
                    self.state.mac_key_share,
                    self.id,
                )))
            }
            _ => eyre::bail!("Unsupported sub combination in SPDZ Brillig"),
        }
    }

    fn mul(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        match (lhs, rhs) {
            (SpdzBrilligType::Public(l), SpdzBrilligType::Public(r)) => {
                Ok(SpdzBrilligType::Public(self.plain_driver.mul(l, r)?))
            }
            (SpdzBrilligType::Public(PlainBrilligType::Field(p)), SpdzBrilligType::Shared(s))
            | (SpdzBrilligType::Shared(s), SpdzBrilligType::Public(PlainBrilligType::Field(p))) => {
                Ok(SpdzBrilligType::Shared(s * p))
            }
            (SpdzBrilligType::Shared(l), SpdzBrilligType::Shared(r)) => {
                let result = spdz_core::arithmetic::mul(&l, &r, self.net, &mut self.state)?;
                Ok(SpdzBrilligType::Shared(result))
            }
            _ => eyre::bail!("Unsupported mul combination in SPDZ Brillig"),
        }
    }

    fn div(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        match (lhs, rhs) {
            (SpdzBrilligType::Public(l), SpdzBrilligType::Public(r)) => {
                Ok(SpdzBrilligType::Public(self.plain_driver.div(l, r)?))
            }
            (SpdzBrilligType::Shared(l), SpdzBrilligType::Shared(r)) => {
                // Field division: l / r = l * inv(r)
                let r_inv = spdz_core::arithmetic::inv(&r, self.net, &mut self.state)?;
                let result = spdz_core::arithmetic::mul(&l, &r_inv, self.net, &mut self.state)?;
                Ok(SpdzBrilligType::Shared(result))
            }
            (SpdzBrilligType::Shared(l), SpdzBrilligType::Public(PlainBrilligType::Field(r))) => {
                Ok(SpdzBrilligType::Shared(l * r.inverse().unwrap()))
            }
            _ => eyre::bail!("SPDZ Brillig: unsupported div combination"),
        }
    }

    fn int_div(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        match (lhs, rhs) {
            (SpdzBrilligType::Public(l), SpdzBrilligType::Public(r)) => {
                Ok(SpdzBrilligType::Public(self.plain_driver.int_div(l, r)?))
            }
            _ => eyre::bail!("SPDZ Brillig: int_div requires bit decomposition on shared values"),
        }
    }

    fn not(&self, val: Self::BrilligType) -> eyre::Result<Self::BrilligType> {
        match val {
            SpdzBrilligType::Public(p) => Ok(SpdzBrilligType::Public(self.plain_driver.not(p)?)),
            SpdzBrilligType::Shared(s) => {
                // NOT for a boolean (bit): 1 - s
                Ok(SpdzBrilligType::Shared(spdz_core::arithmetic::add_public(
                    -s,
                    F::one(),
                    self.state.mac_key_share,
                    self.id,
                )))
            }
        }
    }

    fn eq(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        match (lhs, rhs) {
            (SpdzBrilligType::Public(l), SpdzBrilligType::Public(r)) => {
                Ok(SpdzBrilligType::Public(self.plain_driver.eq(l, r)?))
            }
            (SpdzBrilligType::Shared(l), SpdzBrilligType::Shared(r)) => {
                let result = spdz_core::gadgets::bits::equal(&l, &r, 128, self.net, &mut self.state)?;
                Ok(SpdzBrilligType::Shared(result))
            }
            (SpdzBrilligType::Public(PlainBrilligType::Field(p)), SpdzBrilligType::Shared(s))
            | (SpdzBrilligType::Shared(s), SpdzBrilligType::Public(PlainBrilligType::Field(p))) => {
                let p_share = SpdzPrimeFieldShare::promote_from_trivial(&p, self.state.mac_key_share, self.id);
                let result = spdz_core::gadgets::bits::equal(&s, &p_share, 128, self.net, &mut self.state)?;
                Ok(SpdzBrilligType::Shared(result))
            }
            _ => eyre::bail!("SPDZ Brillig: unsupported eq combination"),
        }
    }

    fn lt(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        match (lhs, rhs) {
            (SpdzBrilligType::Public(l), SpdzBrilligType::Public(r)) => {
                Ok(SpdzBrilligType::Public(self.plain_driver.lt(l, r)?))
            }
            (SpdzBrilligType::Shared(l), SpdzBrilligType::Shared(r)) => {
                // lt(a, b) = gt(b, a)
                let result = spdz_core::gadgets::bits::greater_than(&r, &l, 128, self.net, &mut self.state)?;
                Ok(SpdzBrilligType::Shared(result))
            }
            _ => eyre::bail!("SPDZ Brillig: unsupported lt combination"),
        }
    }

    fn to_radix(
        &mut self,
        val: Self::BrilligType,
        radix: Self::BrilligType,
        output_size: usize,
        bits: bool,
    ) -> eyre::Result<Vec<Self::BrilligType>> {
        match (val, radix) {
            (SpdzBrilligType::Public(v), SpdzBrilligType::Public(r)) => Ok(self
                .plain_driver
                .to_radix(v, r, output_size, bits)?
                .into_iter()
                .map(SpdzBrilligType::Public)
                .collect()),
            _ => eyre::bail!("SPDZ Brillig: to_radix on shared values not yet implemented"),
        }
    }

    fn cmux(
        &mut self,
        cond: Self::BrilligType,
        truthy: Self::BrilligType,
        falsy: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        match cond {
            SpdzBrilligType::Public(c) => {
                match (truthy, falsy) {
                    (SpdzBrilligType::Public(t), SpdzBrilligType::Public(f)) => {
                        Ok(SpdzBrilligType::Public(self.plain_driver.cmux(c, t, f)?))
                    }
                    _ => eyre::bail!("SPDZ Brillig: cmux with public cond but shared values not supported"),
                }
            }
            SpdzBrilligType::Shared(c) => {
                // cmux(c, t, f) = f + c * (t - f)
                let (t_share, f_share) = match (truthy, falsy) {
                    (SpdzBrilligType::Shared(t), SpdzBrilligType::Shared(f)) => (t, f),
                    (SpdzBrilligType::Public(PlainBrilligType::Field(t)), SpdzBrilligType::Shared(f)) => {
                        (SpdzPrimeFieldShare::promote_from_trivial(&t, self.state.mac_key_share, self.id), f)
                    }
                    (SpdzBrilligType::Shared(t), SpdzBrilligType::Public(PlainBrilligType::Field(f))) => {
                        (t, SpdzPrimeFieldShare::promote_from_trivial(&f, self.state.mac_key_share, self.id))
                    }
                    _ => eyre::bail!("SPDZ Brillig: unsupported cmux combination"),
                };
                let diff = t_share - f_share;
                let c_times_diff = spdz_core::arithmetic::mul(&c, &diff, self.net, &mut self.state)?;
                Ok(SpdzBrilligType::Shared(f_share + c_times_diff))
            }
        }
    }

    fn expect_int(
        val: Self::BrilligType,
        bit_size: brillig::IntegerBitSize,
    ) -> eyre::Result<Self::BrilligType> {
        match val {
            SpdzBrilligType::Public(p) => {
                Ok(SpdzBrilligType::Public(PlainBrilligDriver::<F>::expect_int(p, bit_size)?))
            }
            SpdzBrilligType::Shared(_) => {
                eyre::bail!("Cannot expect_int on shared value")
            }
        }
    }

    fn expect_field(val: Self::BrilligType) -> eyre::Result<Self::BrilligType> {
        match val {
            SpdzBrilligType::Public(p) => {
                Ok(SpdzBrilligType::Public(PlainBrilligDriver::<F>::expect_field(p)?))
            }
            SpdzBrilligType::Shared(s) => {
                // Shared values are always field type in SPDZ
                Ok(SpdzBrilligType::Shared(s))
            }
        }
    }
}
