use core::panic;
use std::marker::PhantomData;

use ark_ff::PrimeField;
use brillig::{BitSize, IntegerBitSize};
use mpc_core::protocols::rep3::network::{IoContext, Rep3Network};
use mpc_core::protocols::rep3::Rep3PrimeFieldShare;
use mpc_core::protocols::rep3_ring::{Rep3BitShare, Rep3RingShare};

use super::{BrilligDriver, PlainBrilligDriver};

use super::PlainBrilligType as Public;

/// A driver for the coBrillig-VM that uses replicated secret sharing.
pub struct Rep3BrilligDriver<F: PrimeField, N: Rep3Network> {
    io_context: IoContext<N>,
    plain_driver: PlainBrilligDriver<F>,
    phantom_data: PhantomData<F>,
}

/// The types for the coBrillig Rep3 driver. The values
/// can either be shared or public.
#[derive(Clone, Debug, PartialEq)]
pub enum Rep3BrilligType<F: PrimeField> {
    /// A public value
    Public(Public<F>),
    /// A shared value
    Shared(Shared<F>),
}

/// The potential shared values of the co-Brillig Rep3 driver.
#[derive(Clone, Debug, PartialEq)]
pub enum Shared<F: PrimeField> {
    Field(Rep3PrimeFieldShare<F>),
    Ring128(Rep3RingShare<u128>),
    Ring64(Rep3RingShare<u64>),
    Ring32(Rep3RingShare<u32>),
    Ring16(Rep3RingShare<u16>),
    Ring8(Rep3RingShare<u8>),
    Ring1(Rep3BitShare),
}

impl<F: PrimeField> From<F> for Rep3BrilligType<F> {
    fn from(value: F) -> Self {
        Rep3BrilligType::Public(Public::Field(value))
    }
}

impl<F: PrimeField> Default for Rep3BrilligType<F> {
    fn default() -> Self {
        Self::from(F::default())
    }
}

impl<F: PrimeField, N: Rep3Network> Rep3BrilligDriver<F, N> {
    /// Creates a new instance of the rep3 driver with the provided
    /// io context.
    pub fn with_io_context(io_context: IoContext<N>) -> Self {
        Self {
            io_context,
            plain_driver: PlainBrilligDriver::default(),
            phantom_data: PhantomData,
        }
    }
}

impl<F: PrimeField> Rep3BrilligType<F> {
    /// Creates a new public field element from the provided field
    pub fn public_field(val: F) -> Self {
        Self::Public(Public::Field(val))
    }

    /// Creates a new shared field element from the provided share
    pub fn shared_field(share: Rep3PrimeFieldShare<F>) -> Self {
        Self::Shared(Shared::Field(share))
    }
}

impl<F: PrimeField, N: Rep3Network> BrilligDriver<F> for Rep3BrilligDriver<F, N> {
    type BrilligType = Rep3BrilligType<F>;

    fn cast(&self, val: Self::BrilligType, bit_size: BitSize) -> eyre::Result<Self::BrilligType> {
        if let Rep3BrilligType::Public(public) = val {
            let casted = self.plain_driver.cast(public, bit_size)?;
            Ok(Rep3BrilligType::Public(casted))
        } else {
            todo!("wait for romans cast impl")
        }
    }

    fn try_into_usize(val: Self::BrilligType) -> eyre::Result<usize> {
        // for now we only support casting public values to usize
        // we return an error if we call this on a shared value
        if let Rep3BrilligType::Public(public) = val {
            PlainBrilligDriver::try_into_usize(public)
        } else {
            eyre::bail!("cannot convert shared value to usize")
        }
    }

    fn try_into_bool(_val: Self::BrilligType) -> eyre::Result<bool> {
        todo!()
    }

    fn public_value(val: F, bit_size: BitSize) -> Self::BrilligType {
        Rep3BrilligType::Public(PlainBrilligDriver::public_value(val, bit_size))
    }

    fn add(
        &self,
        _lhs: Self::BrilligType,
        _rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn sub(
        &mut self,
        _lhs: Self::BrilligType,
        _rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn mul(
        &mut self,
        _lhs: Self::BrilligType,
        _rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn div(
        &mut self,
        _lhs: Self::BrilligType,
        _rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn int_div(
        &mut self,
        _lhs: Self::BrilligType,
        _rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn not(&self, _val: Self::BrilligType) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn eq(
        &mut self,
        _lhs: Self::BrilligType,
        _rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn lt(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        match (lhs, rhs) {
            (Rep3BrilligType::Public(lhs), Rep3BrilligType::Public(rhs)) => {
                let result = self.plain_driver.lt(lhs, rhs)?;
                Ok(Rep3BrilligType::Public(result))
            }
            (Rep3BrilligType::Public(_), Rep3BrilligType::Shared(_)) => todo!(),
            (Rep3BrilligType::Shared(_), Rep3BrilligType::Public(_)) => todo!(),
            (Rep3BrilligType::Shared(_), Rep3BrilligType::Shared(_)) => todo!(),
        }
    }

    fn le(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let gt = self.gt(lhs, rhs)?;
        self.not(gt)
    }

    fn gt(
        &self,
        _lhs: Self::BrilligType,
        _rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn ge(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let gt = self.lt(lhs, rhs)?;
        self.not(gt)
    }

    fn to_radix(
        &self,
        _val: Self::BrilligType,
        _radix: Self::BrilligType,
        _output_size: usize,
        _bits: bool,
    ) -> eyre::Result<Vec<Self::BrilligType>> {
        todo!()
    }

    fn expect_int(
        val: Self::BrilligType,
        bit_size: IntegerBitSize,
    ) -> eyre::Result<Self::BrilligType> {
        if let Rep3BrilligType::Public(public) = val {
            let result = PlainBrilligDriver::expect_int(public, bit_size)?;
            Ok(Rep3BrilligType::Public(result))
        } else {
            match (&val, bit_size) {
                (Rep3BrilligType::Shared(Shared::Ring1(_)), IntegerBitSize::U1)
                | (Rep3BrilligType::Shared(Shared::Ring8(_)), IntegerBitSize::U8)
                | (Rep3BrilligType::Shared(Shared::Ring16(_)), IntegerBitSize::U16)
                | (Rep3BrilligType::Shared(Shared::Ring32(_)), IntegerBitSize::U32)
                | (Rep3BrilligType::Shared(Shared::Ring64(_)), IntegerBitSize::U64)
                | (Rep3BrilligType::Shared(Shared::Ring128(_)), IntegerBitSize::U128) => Ok(val),
                _ => eyre::bail!("expected int with bit size {bit_size}, but was something else"),
            }
        }
    }

    fn expect_field(val: Self::BrilligType) -> eyre::Result<Self::BrilligType> {
        match &val {
            Rep3BrilligType::Public(Public::Field(_))
            | Rep3BrilligType::Shared(Shared::Field(_)) => Ok(val),
            _ => eyre::bail!("expected field but got int"),
        }
    }
}
