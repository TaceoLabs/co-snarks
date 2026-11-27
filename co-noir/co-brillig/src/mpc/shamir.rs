use super::{BrilligDriver, PlainBrilligDriver};
use ark_ff::{One, PrimeField};
use brillig::{BitSize, IntegerBitSize};
use mpc_core::{
    MpcState as _,
    protocols::shamir::{self, ShamirPrimeFieldShare, ShamirState},
};
use mpc_net::Network;
use std::marker::PhantomData;

use super::PlainBrilligType as Public;

/// A driver for the coBrillig-VM that uses Shamir secret sharing.
pub struct ShamirBrilligDriver<'a, F: PrimeField, N: Network> {
    id: usize,
    net: &'a N,
    state: ShamirState<F>,
    plain_driver: PlainBrilligDriver<F>,
    phantom_data: PhantomData<F>,
}

/// The types for the coBrillig
/// Shamir driver. The values
/// can either be shared or public.
#[derive(Clone, PartialEq)]
pub enum ShamirBrilligType<F: PrimeField> {
    /// A public value
    Public(Public<F>),
    /// A shared value.
    /// TODO for now we only support prime fields
    Shared(ShamirPrimeFieldShare<F>),
}

// The shares are secret, so they are not printed
impl<F: PrimeField> std::fmt::Debug for ShamirBrilligType<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(public) => f.debug_tuple("Public").field(public).finish(),
            Self::Shared(_) => f.write_str("Shared(Field(<redacted>))"),
        }
    }
}

impl<F: PrimeField> From<F> for ShamirBrilligType<F> {
    fn from(value: F) -> Self {
        ShamirBrilligType::Public(Public::Field(value))
    }
}

impl<F: PrimeField> Default for ShamirBrilligType<F> {
    fn default() -> Self {
        Self::from(F::default())
    }
}

impl<'a, F: PrimeField, N: Network> ShamirBrilligDriver<'a, F, N> {
    /// Creates a new instance of the Shamir driver
    pub fn new(net: &'a N, state: ShamirState<F>) -> Self {
        Self {
            id: net.id(),
            net,
            state,
            plain_driver: PlainBrilligDriver::default(),
            phantom_data: PhantomData,
        }
    }
}

impl<F: PrimeField, N: Network> BrilligDriver<F> for ShamirBrilligDriver<'_, F, N> {
    type BrilligType = ShamirBrilligType<F>;

    fn fork(&mut self) -> eyre::Result<(Self, Self)> {
        // TODO currently this is only used for branches and each fork is used for 1 case
        // because they are run in sequence we can just clone the net ref, but if we run them in parallel in the future we must fork the networks
        let net0 = self.net;
        let net1 = self.net;
        let state0 = self.state.fork(0)?; // TODO 0 for now ...
        let state1 = self.state.fork(0)?; // TODO 0 for now ...
        let fork0 = Self {
            id: self.id,
            net: net0,
            state: state0,
            plain_driver: PlainBrilligDriver::default(),
            phantom_data: PhantomData,
        };
        let fork1 = Self {
            id: self.id,
            net: net1,
            state: state1,
            plain_driver: PlainBrilligDriver::default(),
            phantom_data: PhantomData,
        };
        Ok((fork0, fork1))
    }

    fn cast(
        &mut self,
        val: Self::BrilligType,
        bit_size: BitSize,
    ) -> eyre::Result<Self::BrilligType> {
        if let ShamirBrilligType::Public(public) = val {
            let casted = self.plain_driver.cast(public, bit_size)?;
            Ok(ShamirBrilligType::Public(casted))
        } else {
            eyre::bail!("Cannot cast shared value with Shamir")
        }
    }

    fn try_into_usize(val: Self::BrilligType) -> eyre::Result<usize> {
        // for now we only support casting public values to usize
        // we return an error if we call this on a shared value
        if let ShamirBrilligType::Public(public) = val {
            PlainBrilligDriver::try_into_usize(public)
        } else {
            eyre::bail!("cannot convert shared value to usize")
        }
    }

    fn try_into_char(val: Self::BrilligType) -> eyre::Result<char> {
        // for now we only support casting public values to chars
        // we return an error if we call this on a shared value
        if let ShamirBrilligType::Public(public) = val {
            PlainBrilligDriver::try_into_char(public)
        } else {
            eyre::bail!("cannot convert shared value to char")
        }
    }

    fn try_into_bool(val: Self::BrilligType) -> Result<bool, Self::BrilligType> {
        match val {
            ShamirBrilligType::Public(Public::Int(val, IntegerBitSize::U1)) => Ok(val != 1),
            x => Err(x),
        }
    }

    fn public_value(val: F, bit_size: BitSize) -> Self::BrilligType {
        ShamirBrilligType::Public(PlainBrilligDriver::public_value(val, bit_size))
    }

    fn predicate_to_condition(
        &mut self,
        _predicate: Self::BrilligType,
    ) -> eyre::Result<Option<Self::BrilligType>> {
        // Shamir has no shared boolean values
        Ok(None)
    }

    fn dummy(&mut self, other: &Self::BrilligType) -> Self::BrilligType {
        match other {
            // A public value has to be equal for all parties, so it must not be sampled locally
            ShamirBrilligType::Public(other) => ShamirBrilligType::Public(other.clone()),
            ShamirBrilligType::Shared(_) => ShamirBrilligType::Shared(
                self.state
                    .rand(self.net)
                    .expect("TODO: replace with error handling"),
            ),
        }
    }

    fn is_public(val: Self::BrilligType) -> bool {
        matches!(val, ShamirBrilligType::Public(_))
    }

    fn add(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let result = match (lhs, rhs) {
            (ShamirBrilligType::Public(lhs), ShamirBrilligType::Public(rhs)) => {
                ShamirBrilligType::Public(self.plain_driver.add(lhs, rhs)?)
            }
            (ShamirBrilligType::Public(public), ShamirBrilligType::Shared(secret))
            | (ShamirBrilligType::Shared(secret), ShamirBrilligType::Public(public)) => {
                if let Public::Field(public) = public {
                    ShamirBrilligType::Shared(shamir::arithmetic::add_public(secret, public))
                } else {
                    panic!("type mismatch. Can only add matching values")
                }
            }
            (ShamirBrilligType::Shared(s1), ShamirBrilligType::Shared(s2)) => {
                ShamirBrilligType::Shared(shamir::arithmetic::add(s1, s2))
            }
        };
        Ok(result)
    }

    fn sub(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let result = match (lhs, rhs) {
            (ShamirBrilligType::Public(lhs), ShamirBrilligType::Public(rhs)) => {
                ShamirBrilligType::Public(self.plain_driver.sub(lhs, rhs)?)
            }
            (ShamirBrilligType::Public(public), ShamirBrilligType::Shared(secret)) => {
                if let Public::Field(public) = public {
                    ShamirBrilligType::Shared(shamir::arithmetic::add_public(-secret, public))
                } else {
                    panic!("type mismatch. Can only sub matching values")
                }
            }
            (ShamirBrilligType::Shared(secret), ShamirBrilligType::Public(public)) => {
                if let Public::Field(public) = public {
                    ShamirBrilligType::Shared(shamir::arithmetic::add_public(secret, -public))
                } else {
                    panic!("type mismatch. Can only sub matching values")
                }
            }
            (ShamirBrilligType::Shared(s1), ShamirBrilligType::Shared(s2)) => {
                ShamirBrilligType::Shared(shamir::arithmetic::sub(s1, s2))
            }
        };
        Ok(result)
    }

    fn mul(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let result = match (lhs, rhs) {
            (ShamirBrilligType::Public(lhs), ShamirBrilligType::Public(rhs)) => {
                ShamirBrilligType::Public(self.plain_driver.mul(lhs, rhs)?)
            }
            (ShamirBrilligType::Public(public), ShamirBrilligType::Shared(secret))
            | (ShamirBrilligType::Shared(secret), ShamirBrilligType::Public(public)) => {
                if let Public::Field(public) = public {
                    ShamirBrilligType::Shared(shamir::arithmetic::mul_public(secret, public))
                } else {
                    panic!("type mismatch. Can only mul matching values")
                }
            }
            (ShamirBrilligType::Shared(s1), ShamirBrilligType::Shared(s2)) => {
                ShamirBrilligType::Shared(shamir::arithmetic::mul(
                    s1,
                    s2,
                    self.net,
                    &mut self.state,
                )?)
            }
        };
        Ok(result)
    }

    fn div(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let result = match (lhs, rhs) {
            (ShamirBrilligType::Public(lhs), ShamirBrilligType::Public(rhs)) => {
                ShamirBrilligType::Public(self.plain_driver.div(lhs, rhs)?)
            }
            (ShamirBrilligType::Public(public), ShamirBrilligType::Shared(secret)) => {
                if let Public::Field(public) = public {
                    ShamirBrilligType::Shared(shamir::arithmetic::div_shared_by_public(
                        secret, public,
                    )?)
                } else {
                    panic!("type mismatch. Can only div matching values")
                }
            }
            (ShamirBrilligType::Shared(secret), ShamirBrilligType::Public(public)) => {
                if let Public::Field(public) = public {
                    ShamirBrilligType::Shared(shamir::arithmetic::div_public_by_shared(
                        public,
                        secret,
                        self.net,
                        &mut self.state,
                    )?)
                } else {
                    panic!("type mismatch. Can only div matching values")
                }
            }
            (ShamirBrilligType::Shared(s1), ShamirBrilligType::Shared(s2)) => {
                ShamirBrilligType::Shared(shamir::arithmetic::div(
                    s1,
                    s2,
                    self.net,
                    &mut self.state,
                )?)
            }
        };
        Ok(result)
    }

    fn int_div(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        if let (ShamirBrilligType::Public(lhs), ShamirBrilligType::Public(rhs)) = (lhs, rhs) {
            let result = self.plain_driver.int_div(lhs, rhs)?;
            Ok(ShamirBrilligType::Public(result))
        } else {
            eyre::bail!("Cannot use int_div with Shamir shares")
        }
    }

    fn not(&self, val: Self::BrilligType) -> eyre::Result<Self::BrilligType> {
        let result = match val {
            ShamirBrilligType::Public(val) => {
                let result = self.plain_driver.not(val)?;
                ShamirBrilligType::Public(result)
            }
            _ => eyre::bail!("Cannot use NOT on shared values with Shamir"),
        };
        Ok(result)
    }

    fn eq(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let result = match (lhs, rhs) {
            (ShamirBrilligType::Public(lhs), ShamirBrilligType::Public(rhs)) => {
                let result = self.plain_driver.eq(lhs, rhs)?;
                ShamirBrilligType::Public(result)
            }
            _ => eyre::bail!("Cannot compare shared values with Shamir"),
        };
        Ok(result)
    }

    fn lt(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let result = match (lhs, rhs) {
            (ShamirBrilligType::Public(lhs), ShamirBrilligType::Public(rhs)) => {
                let result = self.plain_driver.lt(lhs, rhs)?;
                ShamirBrilligType::Public(result)
            }
            _ => eyre::bail!("Cannot compare shared values with Shamir"),
        };
        Ok(result)
    }

    fn le(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let result = match (lhs, rhs) {
            (ShamirBrilligType::Public(lhs), ShamirBrilligType::Public(rhs)) => {
                let result = self.plain_driver.le(lhs, rhs)?;
                ShamirBrilligType::Public(result)
            }
            _ => eyre::bail!("Cannot compare shared values with Shamir"),
        };
        Ok(result)
    }

    fn to_radix(
        &mut self,
        val: Self::BrilligType,
        radix: Self::BrilligType,
        output_size: usize,
        bits: bool,
    ) -> eyre::Result<Vec<Self::BrilligType>> {
        if let (ShamirBrilligType::Public(val), ShamirBrilligType::Public(radix)) = (val, radix) {
            let result = self.plain_driver.to_radix(val, radix, output_size, bits)?;
            Ok(result
                .into_iter()
                .map(|val| ShamirBrilligType::Public(val))
                .collect())
        } else {
            eyre::bail!("Cannot use to_radix with Shamir shares")
        }
    }

    fn cmux(
        &mut self,
        cond: Self::BrilligType,
        truthy: Self::BrilligType,
        falsy: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        match cond {
            ShamirBrilligType::Public(Public::Int(cond, IntegerBitSize::U1)) => {
                if cond.is_one() {
                    Ok(truthy)
                } else {
                    Ok(falsy)
                }
            }
            _ => {
                eyre::bail!("cmux where cond is a non bool value: SHAMIR has no bool values atm...")
            }
        }
    }

    fn expect_int(
        val: Self::BrilligType,
        bit_size: IntegerBitSize,
    ) -> eyre::Result<Self::BrilligType> {
        if let ShamirBrilligType::Public(public) = val {
            let result = PlainBrilligDriver::expect_int(public, bit_size)?;
            Ok(ShamirBrilligType::Public(result))
        } else {
            eyre::bail!("expected int with bit size {bit_size}, but was something else")
        }
    }

    fn expect_field(val: Self::BrilligType) -> eyre::Result<Self::BrilligType> {
        match &val {
            ShamirBrilligType::Public(Public::Field(_)) | ShamirBrilligType::Shared(_) => Ok(val),
            _ => eyre::bail!("expected field but got int"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpc::PlainBrilligType;
    use ark_bn254::Fr;
    use brillig::IntegerBitSize;
    use mpc_core::protocols::shamir::ShamirPreprocessing;
    use mpc_net::local::LocalNetwork;

    // The dummy for a public value must be equal for all parties, as it is used together with shared values afterwards
    #[test]
    fn dummy_for_public_value_is_equal_for_all_parties() {
        let publics = [
            PlainBrilligType::Field(Fr::from(42u64)),
            PlainBrilligType::Int(7, IntegerBitSize::U64),
        ];
        let threads = LocalNetwork::new(3)
            .into_iter()
            .map(|net| {
                let publics = publics.clone();
                std::thread::spawn(move || {
                    let preprocessing = ShamirPreprocessing::new(3, 1, 0, &net).unwrap();
                    let mut driver =
                        ShamirBrilligDriver::<Fr, _>::new(&net, ShamirState::from(preprocessing));
                    publics
                        .iter()
                        .map(|public| {
                            match driver.dummy(&ShamirBrilligType::Public(public.clone())) {
                                ShamirBrilligType::Public(dummy) => dummy,
                                ShamirBrilligType::Shared(_) => {
                                    unreachable!("the dummy must be public")
                                }
                            }
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            assert_eq!(thread.join().unwrap(), publics);
        }
    }
}
