use core::panic;
use std::marker::PhantomData;

use ark_ff::PrimeField;
use brillig::{BitSize, IntegerBitSize};
use mpc_core::protocols::rep3::network::{IoContext, Rep3Network};
use mpc_core::protocols::rep3::{self, Rep3PrimeFieldShare};
use mpc_core::protocols::rep3_ring::ring::bit::Bit;
use mpc_core::protocols::rep3_ring::ring::int_ring::IntRing2k;
use mpc_core::protocols::rep3_ring::ring::ring_impl::RingElement;
use mpc_core::protocols::rep3_ring::{self, Rep3BitShare, Rep3RingShare};

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

    pub fn into_arithemtic_share(shared: Shared<F>) -> Rep3PrimeFieldShare<F> {
        match shared {
            Shared::Field(share) => share,
            Shared::Ring128(share) => todo!(),
            Shared::Ring64(_) => todo!(),
            Shared::Ring32(_) => todo!(),
            Shared::Ring16(_) => todo!(),
            Shared::Ring8(_) => todo!(),
            Shared::Ring1(_) => todo!(),
        }
    }

    /// Creates a new shared field element from the provided share
    pub fn shared_field(share: Rep3PrimeFieldShare<F>) -> Self {
        Self::Shared(Shared::Field(share))
    }

    /// Creates a new shared u128 element from the provided share
    pub fn shared_u128(share: Rep3RingShare<u128>) -> Self {
        Self::Shared(Shared::Ring128(share))
    }

    /// Creates a new shared u64 element from the provided share
    pub fn shared_u64(share: Rep3RingShare<u64>) -> Self {
        Self::Shared(Shared::Ring64(share))
    }

    /// Creates a new shared u32 element from the provided share
    pub fn shared_u32(share: Rep3RingShare<u32>) -> Self {
        Self::Shared(Shared::Ring32(share))
    }

    /// Creates a new shared u16 element from the provided share
    pub fn shared_u16(share: Rep3RingShare<u16>) -> Self {
        Self::Shared(Shared::Ring16(share))
    }

    /// Creates a new shared u8 element from the provided share
    pub fn shared_u8(share: Rep3RingShare<u8>) -> Self {
        Self::Shared(Shared::Ring8(share))
    }

    /// Creates a new shared u1 element from the provided share
    pub fn shared_u1(share: Rep3BitShare) -> Self {
        Self::Shared(Shared::Ring1(share))
    }
}

macro_rules! bit_from_u128 {
    ($val:expr) => {{
        let u8 = u8::try_from($val).expect("must be u8");
        assert!(u8 == 0 || u8 == 1);
        RingElement(Bit::new(u8 == 1))
    }};
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

    fn try_into_bool(val: Self::BrilligType) -> eyre::Result<bool> {
        // for now we only support casting public values to bools
        // we return an error if we call this on a shared value
        if let Rep3BrilligType::Public(public) = val {
            PlainBrilligDriver::try_into_bool(public)
        } else {
            eyre::bail!("cannot convert shared value to usize")
        }
    }

    fn public_value(val: F, bit_size: BitSize) -> Self::BrilligType {
        Rep3BrilligType::Public(PlainBrilligDriver::public_value(val, bit_size))
    }

    fn add(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let result = match (lhs, rhs) {
            (Rep3BrilligType::Public(lhs), Rep3BrilligType::Public(rhs)) => {
                Rep3BrilligType::Public(self.plain_driver.add(lhs, rhs)?)
            }
            (Rep3BrilligType::Public(public), Rep3BrilligType::Shared(secret))
            | (Rep3BrilligType::Shared(secret), Rep3BrilligType::Public(public)) => {
                match (secret, public) {
                    (Shared::Field(secret), Public::Field(public)) => {
                        Rep3BrilligType::shared_field(rep3::arithmetic::add_public(
                            secret,
                            public,
                            self.io_context.id,
                        ))
                    }
                    (Shared::Ring128(secret), Public::Int(public, IntegerBitSize::U128)) => {
                        Rep3BrilligType::shared_u128(rep3_ring::arithmetic::add_public(
                            secret,
                            public.into(),
                            self.io_context.id,
                        ))
                    }
                    (Shared::Ring64(secret), Public::Int(public, IntegerBitSize::U64)) => {
                        Rep3BrilligType::shared_u64(rep3_ring::arithmetic::add_public(
                            secret,
                            u64::try_from(public).expect("must be u64").into(),
                            self.io_context.id,
                        ))
                    }
                    (Shared::Ring32(secret), Public::Int(public, IntegerBitSize::U32)) => {
                        Rep3BrilligType::shared_u32(rep3_ring::arithmetic::add_public(
                            secret,
                            u32::try_from(public).expect("must be u32").into(),
                            self.io_context.id,
                        ))
                    }
                    (Shared::Ring16(secret), Public::Int(public, IntegerBitSize::U16)) => {
                        Rep3BrilligType::shared_u16(rep3_ring::arithmetic::add_public(
                            secret,
                            u16::try_from(public).expect("must be u16").into(),
                            self.io_context.id,
                        ))
                    }
                    (Shared::Ring8(secret), Public::Int(public, IntegerBitSize::U8)) => {
                        Rep3BrilligType::shared_u8(rep3_ring::arithmetic::add_public(
                            secret,
                            u8::try_from(public).expect("must be u8").into(),
                            self.io_context.id,
                        ))
                    }
                    (Shared::Ring1(secret), Public::Int(public, IntegerBitSize::U1)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::add_public(
                            secret,
                            bit_from_u128!(public),
                            self.io_context.id,
                        ))
                    }
                    _ => panic!("type mismatch. Can only add matching values"),
                }
            }
            (Rep3BrilligType::Shared(s1), Rep3BrilligType::Shared(s2)) => match (s1, s2) {
                (Shared::Field(s1), Shared::Field(s2)) => {
                    Rep3BrilligType::shared_field(rep3::arithmetic::add(s1, s2))
                }
                (Shared::Ring128(s1), Shared::Ring128(s2)) => {
                    Rep3BrilligType::shared_u128(rep3_ring::arithmetic::add(s1, s2))
                }
                (Shared::Ring64(s1), Shared::Ring64(s2)) => {
                    Rep3BrilligType::shared_u64(rep3_ring::arithmetic::add(s1, s2))
                }
                (Shared::Ring32(s1), Shared::Ring32(s2)) => {
                    Rep3BrilligType::shared_u32(rep3_ring::arithmetic::add(s1, s2))
                }
                (Shared::Ring16(s1), Shared::Ring16(s2)) => {
                    Rep3BrilligType::shared_u16(rep3_ring::arithmetic::add(s1, s2))
                }
                (Shared::Ring8(s1), Shared::Ring8(s2)) => {
                    Rep3BrilligType::shared_u8(rep3_ring::arithmetic::add(s1, s2))
                }
                (Shared::Ring1(s1), Shared::Ring1(s2)) => {
                    Rep3BrilligType::shared_u1(rep3_ring::arithmetic::add(s1, s2))
                }
                _ => panic!("type mismatch. Can only add matching values"),
            },
        };
        Ok(result)
    }

    fn sub(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let result = match (lhs, rhs) {
            (Rep3BrilligType::Public(lhs), Rep3BrilligType::Public(rhs)) => {
                Rep3BrilligType::Public(self.plain_driver.sub(lhs, rhs)?)
            }
            (Rep3BrilligType::Shared(secret), Rep3BrilligType::Public(public)) => {
                match (secret, public) {
                    (Shared::Field(secret), Public::Field(public)) => {
                        Rep3BrilligType::shared_field(rep3::arithmetic::sub_shared_by_public(
                            secret,
                            public,
                            self.io_context.id,
                        ))
                    }
                    (Shared::Ring128(secret), Public::Int(public, IntegerBitSize::U128)) => {
                        Rep3BrilligType::shared_u128(rep3_ring::arithmetic::sub_shared_by_public(
                            secret,
                            public.into(),
                            self.io_context.id,
                        ))
                    }
                    (Shared::Ring64(secret), Public::Int(public, IntegerBitSize::U64)) => {
                        Rep3BrilligType::shared_u64(rep3_ring::arithmetic::sub_shared_by_public(
                            secret,
                            u64::try_from(public).expect("must be u64").into(),
                            self.io_context.id,
                        ))
                    }
                    (Shared::Ring32(secret), Public::Int(public, IntegerBitSize::U32)) => {
                        Rep3BrilligType::shared_u32(rep3_ring::arithmetic::sub_shared_by_public(
                            secret,
                            u32::try_from(public).expect("must be u32").into(),
                            self.io_context.id,
                        ))
                    }
                    (Shared::Ring16(secret), Public::Int(public, IntegerBitSize::U16)) => {
                        Rep3BrilligType::shared_u16(rep3_ring::arithmetic::sub_shared_by_public(
                            secret,
                            u16::try_from(public).expect("must be u16").into(),
                            self.io_context.id,
                        ))
                    }
                    (Shared::Ring8(secret), Public::Int(public, IntegerBitSize::U8)) => {
                        Rep3BrilligType::shared_u8(rep3_ring::arithmetic::sub_shared_by_public(
                            secret,
                            u8::try_from(public).expect("must be u8").into(),
                            self.io_context.id,
                        ))
                    }
                    (Shared::Ring1(secret), Public::Int(public, IntegerBitSize::U1)) => {
                        let u8 = u8::try_from(public).expect("must be u8");
                        assert!(u8 == 0 || u8 == 1);
                        let bit = RingElement(Bit::new(u8 == 1));
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::sub_shared_by_public(
                            secret,
                            bit,
                            self.io_context.id,
                        ))
                    }
                    _ => panic!("type mismatch. Can only sub matching values"),
                }
            }
            (Rep3BrilligType::Public(public), Rep3BrilligType::Shared(secret)) => {
                match (secret, public) {
                    (Shared::Field(secret), Public::Field(public)) => {
                        Rep3BrilligType::shared_field(rep3::arithmetic::sub_public_by_shared(
                            public,
                            secret,
                            self.io_context.id,
                        ))
                    }
                    (Shared::Ring128(secret), Public::Int(public, IntegerBitSize::U128)) => {
                        Rep3BrilligType::shared_u128(rep3_ring::arithmetic::sub_public_by_shared(
                            public.into(),
                            secret,
                            self.io_context.id,
                        ))
                    }
                    (Shared::Ring64(secret), Public::Int(public, IntegerBitSize::U64)) => {
                        Rep3BrilligType::shared_u64(rep3_ring::arithmetic::sub_public_by_shared(
                            u64::try_from(public).expect("must be u64").into(),
                            secret,
                            self.io_context.id,
                        ))
                    }
                    (Shared::Ring32(secret), Public::Int(public, IntegerBitSize::U32)) => {
                        Rep3BrilligType::shared_u32(rep3_ring::arithmetic::sub_public_by_shared(
                            u32::try_from(public).expect("must be u32").into(),
                            secret,
                            self.io_context.id,
                        ))
                    }
                    (Shared::Ring16(secret), Public::Int(public, IntegerBitSize::U16)) => {
                        Rep3BrilligType::shared_u16(rep3_ring::arithmetic::sub_public_by_shared(
                            u16::try_from(public).expect("must be u16").into(),
                            secret,
                            self.io_context.id,
                        ))
                    }
                    (Shared::Ring8(secret), Public::Int(public, IntegerBitSize::U8)) => {
                        Rep3BrilligType::shared_u8(rep3_ring::arithmetic::sub_public_by_shared(
                            u8::try_from(public).expect("must be u8").into(),
                            secret,
                            self.io_context.id,
                        ))
                    }
                    (Shared::Ring1(secret), Public::Int(public, IntegerBitSize::U1)) => {
                        let u8 = u8::try_from(public).expect("must be u8");
                        assert!(u8 == 0 || u8 == 1);
                        let bit = RingElement(Bit::new(u8 == 1));
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::sub_public_by_shared(
                            bit,
                            secret,
                            self.io_context.id,
                        ))
                    }
                    _ => panic!("type mismatch. Can only sub matching values"),
                }
            }
            (Rep3BrilligType::Shared(s1), Rep3BrilligType::Shared(s2)) => match (s1, s2) {
                (Shared::Field(s1), Shared::Field(s2)) => {
                    Rep3BrilligType::shared_field(rep3::arithmetic::sub(s1, s2))
                }
                (Shared::Ring128(s1), Shared::Ring128(s2)) => {
                    Rep3BrilligType::shared_u128(rep3_ring::arithmetic::sub(s1, s2))
                }
                (Shared::Ring64(s1), Shared::Ring64(s2)) => {
                    Rep3BrilligType::shared_u64(rep3_ring::arithmetic::sub(s1, s2))
                }
                (Shared::Ring32(s1), Shared::Ring32(s2)) => {
                    Rep3BrilligType::shared_u32(rep3_ring::arithmetic::sub(s1, s2))
                }
                (Shared::Ring16(s1), Shared::Ring16(s2)) => {
                    Rep3BrilligType::shared_u16(rep3_ring::arithmetic::sub(s1, s2))
                }
                (Shared::Ring8(s1), Shared::Ring8(s2)) => {
                    Rep3BrilligType::shared_u8(rep3_ring::arithmetic::sub(s1, s2))
                }
                (Shared::Ring1(s1), Shared::Ring1(s2)) => {
                    Rep3BrilligType::shared_u1(rep3_ring::arithmetic::sub(s1, s2))
                }
                _ => panic!("type mismatch. Can only sub matching values"),
            },
        };
        Ok(result)
    }

    fn mul(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let result = match (lhs, rhs) {
            (Rep3BrilligType::Public(lhs), Rep3BrilligType::Public(rhs)) => {
                Rep3BrilligType::Public(self.plain_driver.mul(lhs, rhs)?)
            }
            (Rep3BrilligType::Public(public), Rep3BrilligType::Shared(secret))
            | (Rep3BrilligType::Shared(secret), Rep3BrilligType::Public(public)) => {
                match (secret, public) {
                    (Shared::Field(secret), Public::Field(public)) => {
                        Rep3BrilligType::shared_field(rep3::arithmetic::mul_public(secret, public))
                    }
                    (Shared::Ring128(secret), Public::Int(public, IntegerBitSize::U128)) => {
                        Rep3BrilligType::shared_u128(rep3_ring::arithmetic::mul_public(
                            secret,
                            public.into(),
                        ))
                    }
                    (Shared::Ring64(secret), Public::Int(public, IntegerBitSize::U64)) => {
                        Rep3BrilligType::shared_u64(rep3_ring::arithmetic::mul_public(
                            secret,
                            u64::try_from(public).expect("must be u64").into(),
                        ))
                    }
                    (Shared::Ring32(secret), Public::Int(public, IntegerBitSize::U32)) => {
                        Rep3BrilligType::shared_u32(rep3_ring::arithmetic::mul_public(
                            secret,
                            u32::try_from(public).expect("must be u32").into(),
                        ))
                    }
                    (Shared::Ring16(secret), Public::Int(public, IntegerBitSize::U16)) => {
                        Rep3BrilligType::shared_u16(rep3_ring::arithmetic::mul_public(
                            secret,
                            u16::try_from(public).expect("must be u16").into(),
                        ))
                    }
                    (Shared::Ring8(secret), Public::Int(public, IntegerBitSize::U8)) => {
                        Rep3BrilligType::shared_u8(rep3_ring::arithmetic::mul_public(
                            secret,
                            u8::try_from(public).expect("must be u8").into(),
                        ))
                    }
                    (Shared::Ring1(secret), Public::Int(public, IntegerBitSize::U1)) => {
                        let u8 = u8::try_from(public).expect("must be u8");
                        assert!(u8 == 0 || u8 == 1);
                        let bit = RingElement(Bit::new(u8 == 1));
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::mul_public(secret, bit))
                    }
                    _ => panic!("type mismatch. Can only mul matching values"),
                }
            }
            (Rep3BrilligType::Shared(s1), Rep3BrilligType::Shared(s2)) => match (s1, s2) {
                (Shared::Field(s1), Shared::Field(s2)) => Rep3BrilligType::shared_field(
                    rep3::arithmetic::mul(s1, s2, &mut self.io_context)?,
                ),
                (Shared::Ring128(s1), Shared::Ring128(s2)) => Rep3BrilligType::shared_u128(
                    rep3_ring::arithmetic::mul(s1, s2, &mut self.io_context)?,
                ),
                (Shared::Ring64(s1), Shared::Ring64(s2)) => Rep3BrilligType::shared_u64(
                    rep3_ring::arithmetic::mul(s1, s2, &mut self.io_context)?,
                ),
                (Shared::Ring32(s1), Shared::Ring32(s2)) => Rep3BrilligType::shared_u32(
                    rep3_ring::arithmetic::mul(s1, s2, &mut self.io_context)?,
                ),
                (Shared::Ring16(s1), Shared::Ring16(s2)) => Rep3BrilligType::shared_u16(
                    rep3_ring::arithmetic::mul(s1, s2, &mut self.io_context)?,
                ),
                (Shared::Ring8(s1), Shared::Ring8(s2)) => Rep3BrilligType::shared_u8(
                    rep3_ring::arithmetic::mul(s1, s2, &mut self.io_context)?,
                ),
                (Shared::Ring1(s1), Shared::Ring1(s2)) => Rep3BrilligType::shared_u1(
                    rep3_ring::arithmetic::mul(s1, s2, &mut self.io_context)?,
                ),
                _ => panic!("type mismatch. Can only mul matching values"),
            },
        };
        Ok(result)
    }

    fn div(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let result = match (lhs, rhs) {
            (Rep3BrilligType::Public(lhs), Rep3BrilligType::Public(rhs)) => {
                Rep3BrilligType::Public(self.plain_driver.div(lhs, rhs)?)
            }
            (Rep3BrilligType::Public(public), Rep3BrilligType::Shared(shared)) => {
                match (public, shared) {
                    (Public::Field(lhs), Shared::Field(rhs)) => Rep3BrilligType::shared_field(
                        rep3::arithmetic::div_public_by_shared(lhs, rhs, &mut self.io_context)?,
                    ),
                    _ => todo!("Implement division for public/shared"),
                }
            }
            (Rep3BrilligType::Shared(shared), Rep3BrilligType::Public(public)) => {
                match (public, shared) {
                    (Public::Field(rhs), Shared::Field(lhs)) => Rep3BrilligType::shared_field(
                        rep3::arithmetic::div_shared_by_public(lhs, rhs)?,
                    ),
                    _ => todo!("Implement division for shared/public"),
                }
            }
            (Rep3BrilligType::Shared(s1), Rep3BrilligType::Shared(s2)) => match (s1, s2) {
                (Shared::Field(lhs), Shared::Field(rhs)) => Rep3BrilligType::shared_field(
                    rep3::arithmetic::div(lhs, rhs, &mut self.io_context)?,
                ),
                _ => todo!("Implement division for shared/shared"),
            },
        };
        Ok(result)
    }

    fn int_div(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let result = match (lhs, rhs) {
            (Rep3BrilligType::Public(lhs), Rep3BrilligType::Public(rhs)) => {
                Rep3BrilligType::Public(self.plain_driver.int_div(lhs, rhs)?)
            }
            (Rep3BrilligType::Public(public), Rep3BrilligType::Shared(shared)) => {
                if let (Public::Field(_), Shared::Field(_)) = (public, shared) {
                    todo!("Implement IntDiv for public/shared")
                } else {
                    eyre::bail!("IntDiv only supported on fields")
                }
            }
            (Rep3BrilligType::Shared(shared), Rep3BrilligType::Public(public)) => {
                if let (Public::Field(_), Shared::Field(_)) = (public, shared) {
                    todo!("Implement IntDiv for shared/public")
                } else {
                    eyre::bail!("IntDiv only supported on fields")
                }
            }
            (Rep3BrilligType::Shared(s1), Rep3BrilligType::Shared(s2)) => {
                if let (Shared::Field(_), Shared::Field(_)) = (s1, s2) {
                    todo!("Implement IntDiv for shared/shared")
                } else {
                    eyre::bail!("IntDiv only supported on fields")
                }
            }
        };
        Ok(result)
    }

    fn not(&self, val: Self::BrilligType) -> eyre::Result<Self::BrilligType> {
        if let Rep3BrilligType::Public(public) = val {
            let result = self.plain_driver.not(public)?;
            Ok(Rep3BrilligType::Public(result))
        } else {
            todo!()
        }
    }

    fn eq(
        &mut self,
        _lhs: Self::BrilligType,
        _rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        todo!()
    }

    fn lt(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let result = match (lhs, rhs) {
            (Rep3BrilligType::Public(lhs), Rep3BrilligType::Public(rhs)) => {
                let result = self.plain_driver.lt(lhs, rhs)?;
                Rep3BrilligType::Public(result)
            }
            (Rep3BrilligType::Public(public), Rep3BrilligType::Shared(shared)) => {
                match (shared, public) {
                    (Shared::Field(rhs), Public::Field(lhs)) => {
                        let ge = rep3::arithmetic::le_public_bit(rhs, lhs, &mut self.io_context)?;
                        let result = !Rep3RingShare::new(
                            Bit::cast_from_biguint(&ge.a),
                            Bit::cast_from_biguint(&ge.b),
                        );
                        Rep3BrilligType::shared_u1(result)
                    }
                    (Shared::Ring128(rhs), Public::Int(lhs, IntegerBitSize::U128)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::gt_public(
                            rhs,
                            lhs.into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring64(rhs), Public::Int(lhs, IntegerBitSize::U64)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::gt_public(
                            rhs,
                            u64::try_from(lhs).expect("must be u64").into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring32(rhs), Public::Int(lhs, IntegerBitSize::U32)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::gt_public(
                            rhs,
                            u32::try_from(lhs).expect("must be u32").into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring16(rhs), Public::Int(lhs, IntegerBitSize::U16)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::gt_public(
                            rhs,
                            u16::try_from(lhs).expect("must be u16").into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring8(rhs), Public::Int(lhs, IntegerBitSize::U8)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::gt_public(
                            rhs,
                            u8::try_from(lhs).expect("must be u8").into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring1(rhs), Public::Int(lhs, IntegerBitSize::U1)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::gt_public(
                            rhs,
                            bit_from_u128!(lhs),
                            &mut self.io_context,
                        )?)
                    }
                    x => eyre::bail!(
                        "type mismatch! Can only do bin ops on same types, but tried with {x:?}"
                    ),
                }
            }
            (Rep3BrilligType::Shared(shared), Rep3BrilligType::Public(public)) => {
                match (shared, public) {
                    (Shared::Field(lhs), Public::Field(rhs)) => {
                        let ge = rep3::arithmetic::ge_public_bit(lhs, rhs, &mut self.io_context)?;
                        let result = !Rep3RingShare::new(
                            Bit::cast_from_biguint(&ge.a),
                            Bit::cast_from_biguint(&ge.b),
                        );
                        Rep3BrilligType::shared_u1(result)
                    }
                    (Shared::Ring128(lhs), Public::Int(rhs, IntegerBitSize::U128)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::lt_public(
                            lhs,
                            rhs.into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring64(lhs), Public::Int(rhs, IntegerBitSize::U64)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::lt_public(
                            lhs,
                            u64::try_from(rhs).expect("must be u64").into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring32(lhs), Public::Int(rhs, IntegerBitSize::U32)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::lt_public(
                            lhs,
                            u32::try_from(rhs).expect("must be u32").into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring16(lhs), Public::Int(rhs, IntegerBitSize::U16)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::lt_public(
                            lhs,
                            u16::try_from(rhs).expect("must be u16").into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring8(lhs), Public::Int(rhs, IntegerBitSize::U8)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::lt_public(
                            lhs,
                            u8::try_from(rhs).expect("must be u8").into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring1(lhs), Public::Int(rhs, IntegerBitSize::U1)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::lt_public(
                            lhs,
                            bit_from_u128!(rhs),
                            &mut self.io_context,
                        )?)
                    }
                    x => eyre::bail!(
                        "type mismatch! Can only do bin ops on same types, but tried with {x:?}"
                    ),
                }
            }
            (Rep3BrilligType::Shared(s1), Rep3BrilligType::Shared(s2)) => match (s1, s2) {
                (Shared::Field(s1), Shared::Field(s2)) => {
                    let ge = rep3::arithmetic::ge_bit(s1, s2, &mut self.io_context)?;
                    let result = !Rep3RingShare::new(
                        Bit::cast_from_biguint(&ge.a),
                        Bit::cast_from_biguint(&ge.b),
                    );
                    Rep3BrilligType::shared_u1(result)
                }
                (Shared::Ring128(s1), Shared::Ring128(s2)) => Rep3BrilligType::shared_u1(
                    rep3_ring::arithmetic::lt(s1, s2, &mut self.io_context)?,
                ),
                (Shared::Ring64(s1), Shared::Ring64(s2)) => Rep3BrilligType::shared_u1(
                    rep3_ring::arithmetic::lt(s1, s2, &mut self.io_context)?,
                ),
                (Shared::Ring32(s1), Shared::Ring32(s2)) => Rep3BrilligType::shared_u1(
                    rep3_ring::arithmetic::lt(s1, s2, &mut self.io_context)?,
                ),
                (Shared::Ring16(s1), Shared::Ring16(s2)) => Rep3BrilligType::shared_u1(
                    rep3_ring::arithmetic::lt(s1, s2, &mut self.io_context)?,
                ),
                (Shared::Ring8(s1), Shared::Ring8(s2)) => Rep3BrilligType::shared_u1(
                    rep3_ring::arithmetic::lt(s1, s2, &mut self.io_context)?,
                ),
                (Shared::Ring1(s1), Shared::Ring1(s2)) => Rep3BrilligType::shared_u1(
                    rep3_ring::arithmetic::lt(s1, s2, &mut self.io_context)?,
                ),
                x => eyre::bail!(
                    "type mismatch! Can only do bin ops on same types, but tried with {x:?}"
                ),
            },
        };
        Ok(result)
    }

    fn le(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let result = match (lhs, rhs) {
            (Rep3BrilligType::Public(lhs), Rep3BrilligType::Public(rhs)) => {
                let result = self.plain_driver.le(lhs, rhs)?;
                Rep3BrilligType::Public(result)
            }
            (Rep3BrilligType::Public(public), Rep3BrilligType::Shared(shared)) => {
                match (shared, public) {
                    (Shared::Field(rhs), Public::Field(lhs)) => {
                        let le = rep3::arithmetic::ge_public_bit(rhs, lhs, &mut self.io_context)?;
                        let result = Rep3RingShare::new(
                            Bit::cast_from_biguint(&le.a),
                            Bit::cast_from_biguint(&le.b),
                        );
                        Rep3BrilligType::shared_u1(result)
                    }
                    (Shared::Ring128(rhs), Public::Int(lhs, IntegerBitSize::U128)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::ge_public(
                            rhs,
                            lhs.into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring64(rhs), Public::Int(lhs, IntegerBitSize::U64)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::ge_public(
                            rhs,
                            u64::try_from(lhs).expect("must be u64").into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring32(rhs), Public::Int(lhs, IntegerBitSize::U32)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::ge_public(
                            rhs,
                            u32::try_from(lhs).expect("must be u32").into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring16(rhs), Public::Int(lhs, IntegerBitSize::U16)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::ge_public(
                            rhs,
                            u16::try_from(lhs).expect("must be u16").into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring8(rhs), Public::Int(lhs, IntegerBitSize::U8)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::ge_public(
                            rhs,
                            u8::try_from(lhs).expect("must be u8").into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring1(rhs), Public::Int(lhs, IntegerBitSize::U1)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::ge_public(
                            rhs,
                            bit_from_u128!(lhs),
                            &mut self.io_context,
                        )?)
                    }
                    x => eyre::bail!(
                        "type mismatch! Can only do bin ops on same types, but tried with {x:?}"
                    ),
                }
            }
            (Rep3BrilligType::Shared(shared), Rep3BrilligType::Public(public)) => {
                match (shared, public) {
                    (Shared::Field(lhs), Public::Field(rhs)) => {
                        let le = rep3::arithmetic::le_public_bit(lhs, rhs, &mut self.io_context)?;
                        let result = Rep3RingShare::new(
                            Bit::cast_from_biguint(&le.a),
                            Bit::cast_from_biguint(&le.b),
                        );
                        Rep3BrilligType::shared_u1(result)
                    }
                    (Shared::Ring128(lhs), Public::Int(rhs, IntegerBitSize::U128)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::le_public(
                            lhs,
                            rhs.into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring64(lhs), Public::Int(rhs, IntegerBitSize::U64)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::le_public(
                            lhs,
                            u64::try_from(rhs).expect("must be u64").into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring32(lhs), Public::Int(rhs, IntegerBitSize::U32)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::le_public(
                            lhs,
                            u32::try_from(rhs).expect("must be u32").into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring16(lhs), Public::Int(rhs, IntegerBitSize::U16)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::le_public(
                            lhs,
                            u16::try_from(rhs).expect("must be u16").into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring8(lhs), Public::Int(rhs, IntegerBitSize::U8)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::le_public(
                            lhs,
                            u8::try_from(rhs).expect("must be u8").into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring1(lhs), Public::Int(rhs, IntegerBitSize::U1)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::le_public(
                            lhs,
                            bit_from_u128!(rhs),
                            &mut self.io_context,
                        )?)
                    }
                    x => eyre::bail!(
                        "type mismatch! Can only do bin ops on same types, but tried with {x:?}"
                    ),
                }
            }
            (Rep3BrilligType::Shared(s1), Rep3BrilligType::Shared(s2)) => match (s1, s2) {
                (Shared::Field(s1), Shared::Field(s2)) => {
                    let le = rep3::arithmetic::ge_bit(s2, s1, &mut self.io_context)?;
                    let result = Rep3RingShare::new(
                        Bit::cast_from_biguint(&le.a),
                        Bit::cast_from_biguint(&le.b),
                    );
                    Rep3BrilligType::shared_u1(result)
                }
                (Shared::Ring128(s1), Shared::Ring128(s2)) => Rep3BrilligType::shared_u1(
                    rep3_ring::arithmetic::le(s1, s2, &mut self.io_context)?,
                ),
                (Shared::Ring64(s1), Shared::Ring64(s2)) => Rep3BrilligType::shared_u1(
                    rep3_ring::arithmetic::le(s1, s2, &mut self.io_context)?,
                ),
                (Shared::Ring32(s1), Shared::Ring32(s2)) => Rep3BrilligType::shared_u1(
                    rep3_ring::arithmetic::le(s1, s2, &mut self.io_context)?,
                ),
                (Shared::Ring16(s1), Shared::Ring16(s2)) => Rep3BrilligType::shared_u1(
                    rep3_ring::arithmetic::le(s1, s2, &mut self.io_context)?,
                ),
                (Shared::Ring8(s1), Shared::Ring8(s2)) => Rep3BrilligType::shared_u1(
                    rep3_ring::arithmetic::le(s1, s2, &mut self.io_context)?,
                ),
                (Shared::Ring1(s1), Shared::Ring1(s2)) => Rep3BrilligType::shared_u1(
                    rep3_ring::arithmetic::le(s1, s2, &mut self.io_context)?,
                ),
                x => eyre::bail!(
                    "type mismatch! Can only do bin ops on same types, but tried with {x:?}"
                ),
            },
        };
        Ok(result)
    }

    fn gt(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let result = match (lhs, rhs) {
            (Rep3BrilligType::Public(lhs), Rep3BrilligType::Public(rhs)) => {
                let result = self.plain_driver.gt(lhs, rhs)?;
                Rep3BrilligType::Public(result)
            }
            (Rep3BrilligType::Public(public), Rep3BrilligType::Shared(shared)) => {
                match (shared, public) {
                    (Shared::Field(rhs), Public::Field(lhs)) => {
                        let le = rep3::arithmetic::ge_public_bit(rhs, lhs, &mut self.io_context)?;
                        let result = !Rep3RingShare::new(
                            Bit::cast_from_biguint(&le.a),
                            Bit::cast_from_biguint(&le.b),
                        );
                        Rep3BrilligType::shared_u1(result)
                    }
                    (Shared::Ring128(rhs), Public::Int(lhs, IntegerBitSize::U128)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::lt_public(
                            rhs,
                            lhs.into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring64(rhs), Public::Int(lhs, IntegerBitSize::U64)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::lt_public(
                            rhs,
                            u64::try_from(lhs).expect("must be u64").into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring32(rhs), Public::Int(lhs, IntegerBitSize::U32)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::lt_public(
                            rhs,
                            u32::try_from(lhs).expect("must be u32").into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring16(rhs), Public::Int(lhs, IntegerBitSize::U16)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::lt_public(
                            rhs,
                            u16::try_from(lhs).expect("must be u16").into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring8(rhs), Public::Int(lhs, IntegerBitSize::U8)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::lt_public(
                            rhs,
                            u8::try_from(lhs).expect("must be u8").into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring1(rhs), Public::Int(lhs, IntegerBitSize::U1)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::lt_public(
                            rhs,
                            bit_from_u128!(lhs),
                            &mut self.io_context,
                        )?)
                    }
                    x => eyre::bail!(
                        "type mismatch! Can only do bin ops on same types, but tried with {x:?}"
                    ),
                }
            }
            (Rep3BrilligType::Shared(shared), Rep3BrilligType::Public(public)) => {
                match (shared, public) {
                    (Shared::Field(lhs), Public::Field(rhs)) => {
                        let le = rep3::arithmetic::le_public_bit(lhs, rhs, &mut self.io_context)?;
                        let result = !Rep3RingShare::new(
                            Bit::cast_from_biguint(&le.a),
                            Bit::cast_from_biguint(&le.b),
                        );
                        Rep3BrilligType::shared_u1(result)
                    }
                    (Shared::Ring128(lhs), Public::Int(rhs, IntegerBitSize::U128)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::gt_public(
                            lhs,
                            rhs.into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring64(lhs), Public::Int(rhs, IntegerBitSize::U64)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::gt_public(
                            lhs,
                            u64::try_from(rhs).expect("must be u64").into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring32(lhs), Public::Int(rhs, IntegerBitSize::U32)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::gt_public(
                            lhs,
                            u32::try_from(rhs).expect("must be u32").into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring16(lhs), Public::Int(rhs, IntegerBitSize::U16)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::gt_public(
                            lhs,
                            u16::try_from(rhs).expect("must be u16").into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring8(lhs), Public::Int(rhs, IntegerBitSize::U8)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::gt_public(
                            lhs,
                            u8::try_from(rhs).expect("must be u8").into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring1(lhs), Public::Int(rhs, IntegerBitSize::U1)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::gt_public(
                            lhs,
                            bit_from_u128!(rhs),
                            &mut self.io_context,
                        )?)
                    }
                    x => eyre::bail!(
                        "type mismatch! Can only do bin ops on same types, but tried with {x:?}"
                    ),
                }
            }
            (Rep3BrilligType::Shared(s1), Rep3BrilligType::Shared(s2)) => match (s1, s2) {
                (Shared::Field(s1), Shared::Field(s2)) => {
                    let le = rep3::arithmetic::ge_bit(s2, s1, &mut self.io_context)?;
                    let result = !Rep3RingShare::new(
                        Bit::cast_from_biguint(&le.a),
                        Bit::cast_from_biguint(&le.b),
                    );
                    Rep3BrilligType::shared_u1(result)
                }
                (Shared::Ring128(s1), Shared::Ring128(s2)) => Rep3BrilligType::shared_u1(
                    rep3_ring::arithmetic::gt(s1, s2, &mut self.io_context)?,
                ),
                (Shared::Ring64(s1), Shared::Ring64(s2)) => Rep3BrilligType::shared_u1(
                    rep3_ring::arithmetic::gt(s1, s2, &mut self.io_context)?,
                ),
                (Shared::Ring32(s1), Shared::Ring32(s2)) => Rep3BrilligType::shared_u1(
                    rep3_ring::arithmetic::gt(s1, s2, &mut self.io_context)?,
                ),
                (Shared::Ring16(s1), Shared::Ring16(s2)) => Rep3BrilligType::shared_u1(
                    rep3_ring::arithmetic::gt(s1, s2, &mut self.io_context)?,
                ),
                (Shared::Ring8(s1), Shared::Ring8(s2)) => Rep3BrilligType::shared_u1(
                    rep3_ring::arithmetic::gt(s1, s2, &mut self.io_context)?,
                ),
                (Shared::Ring1(s1), Shared::Ring1(s2)) => Rep3BrilligType::shared_u1(
                    rep3_ring::arithmetic::gt(s1, s2, &mut self.io_context)?,
                ),
                x => eyre::bail!(
                    "type mismatch! Can only do bin ops on same types, but tried with {x:?}"
                ),
            },
        };
        Ok(result)
    }

    fn ge(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let gt = self.lt(lhs, rhs)?;
        self.not(gt)
    }

    fn to_radix(
        &mut self,
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
