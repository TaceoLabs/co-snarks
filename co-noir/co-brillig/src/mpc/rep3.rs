use super::{BrilligDriver, PlainBrilligDriver};
use ark_ff::{One as _, PrimeField};
use brillig::{BitSize, IntegerBitSize};
use core::panic;
use mpc_core::protocols::rep3::network::{IoContext, Rep3Network};
use mpc_core::protocols::rep3::{self, Rep3PrimeFieldShare};
use mpc_core::protocols::rep3_ring::ring::bit::Bit;
use mpc_core::protocols::rep3_ring::ring::int_ring::IntRing2k;
use mpc_core::protocols::rep3_ring::ring::ring_impl::RingElement;
use mpc_core::protocols::rep3_ring::{self, Rep3BitShare, Rep3RingShare};
use num_bigint::BigUint;
use num_traits::AsPrimitive;
use rand::distributions::{Distribution, Standard};
use std::marker::PhantomData;

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

    /// Converts a Rep3BrilligType into a Rep3PrimeFieldShare
    pub fn into_arithmetic_share<N: Rep3Network>(
        io_context: &mut IoContext<N>,
        shared: Shared<F>,
    ) -> eyre::Result<Rep3PrimeFieldShare<F>> {
        match shared {
            Shared::Field(share) => Ok(share),
            Shared::Ring128(share) => {
                Ok(rep3_ring::casts::ring_to_field_selector(share, io_context)?)
            }
            Shared::Ring64(share) => {
                Ok(rep3_ring::casts::ring_to_field_selector(share, io_context)?)
            }
            Shared::Ring32(share) => {
                Ok(rep3_ring::casts::ring_to_field_selector(share, io_context)?)
            }
            Shared::Ring16(share) => {
                Ok(rep3_ring::casts::ring_to_field_selector(share, io_context)?)
            }
            Shared::Ring8(share) => {
                Ok(rep3_ring::casts::ring_to_field_selector(share, io_context)?)
            }
            Shared::Ring1(share) => {
                Ok(rep3_ring::casts::ring_to_field_selector(share, io_context)?)
            }
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

fn cast_ring<T, F: PrimeField, N: Rep3Network>(
    share: Rep3RingShare<T>,
    integer_bit_size: IntegerBitSize,
    io_context: &mut IoContext<N>,
) -> eyre::Result<Rep3BrilligType<F>>
where
    Standard: Distribution<T>,
    T: IntRing2k
        + AsPrimitive<Bit>
        + AsPrimitive<u8>
        + AsPrimitive<u16>
        + AsPrimitive<u32>
        + AsPrimitive<u64>
        + AsPrimitive<u128>,
{
    match integer_bit_size {
        IntegerBitSize::U1 => Ok(Rep3BrilligType::Shared(Shared::Ring1(
            rep3_ring::casts::ring_cast_selector::<_, Bit, _>(share, io_context)?,
        ))),
        IntegerBitSize::U8 => Ok(Rep3BrilligType::Shared(Shared::Ring8(
            rep3_ring::casts::ring_cast_selector::<_, u8, _>(share, io_context)?,
        ))),
        IntegerBitSize::U16 => Ok(Rep3BrilligType::Shared(Shared::Ring16(
            rep3_ring::casts::ring_cast_selector::<_, u16, _>(share, io_context)?,
        ))),
        IntegerBitSize::U32 => Ok(Rep3BrilligType::Shared(Shared::Ring32(
            rep3_ring::casts::ring_cast_selector::<_, u32, _>(share, io_context)?,
        ))),
        IntegerBitSize::U64 => Ok(Rep3BrilligType::Shared(Shared::Ring64(
            rep3_ring::casts::ring_cast_selector::<_, u64, _>(share, io_context)?,
        ))),
        IntegerBitSize::U128 => Ok(Rep3BrilligType::Shared(Shared::Ring128(
            rep3_ring::casts::ring_cast_selector::<_, u128, _>(share, io_context)?,
        ))),
    }
}

impl<F: PrimeField, N: Rep3Network> BrilligDriver<F> for Rep3BrilligDriver<F, N> {
    type BrilligType = Rep3BrilligType<F>;

    fn fork(&mut self) -> eyre::Result<(Self, Self)> {
        let network1 = self.io_context.fork()?;
        let network2 = self.io_context.fork()?;
        let fork1 = Self {
            io_context: network1,
            plain_driver: PlainBrilligDriver::default(),
            phantom_data: PhantomData,
        };
        let fork2 = Self {
            io_context: network2,
            plain_driver: PlainBrilligDriver::default(),
            phantom_data: PhantomData,
        };
        Ok((fork1, fork2))
    }

    fn cast(
        &mut self,
        val: Self::BrilligType,
        bit_size: BitSize,
    ) -> eyre::Result<Self::BrilligType> {
        match (val, bit_size) {
            (Rep3BrilligType::Shared(shared), BitSize::Field) => match shared {
                Shared::Field(rep3_prime_field_share) => Ok(Rep3BrilligType::Shared(
                    Shared::Field(rep3_prime_field_share),
                )),
                Shared::Ring128(rep3_ring_share) => Ok(Rep3BrilligType::Shared(Shared::Field(
                    rep3_ring::casts::ring_to_field_selector(
                        rep3_ring_share,
                        &mut self.io_context,
                    )?,
                ))),
                Shared::Ring64(rep3_ring_share) => Ok(Rep3BrilligType::Shared(Shared::Field(
                    rep3_ring::casts::ring_to_field_selector(
                        rep3_ring_share,
                        &mut self.io_context,
                    )?,
                ))),
                Shared::Ring32(rep3_ring_share) => Ok(Rep3BrilligType::Shared(Shared::Field(
                    rep3_ring::casts::ring_to_field_selector(
                        rep3_ring_share,
                        &mut self.io_context,
                    )?,
                ))),
                Shared::Ring16(rep3_ring_share) => Ok(Rep3BrilligType::Shared(Shared::Field(
                    rep3_ring::casts::ring_to_field_selector(
                        rep3_ring_share,
                        &mut self.io_context,
                    )?,
                ))),
                Shared::Ring8(rep3_ring_share) => Ok(Rep3BrilligType::Shared(Shared::Field(
                    rep3_ring::casts::ring_to_field_selector(
                        rep3_ring_share,
                        &mut self.io_context,
                    )?,
                ))),
                Shared::Ring1(rep3_ring_share) => Ok(Rep3BrilligType::Shared(Shared::Field(
                    rep3_ring::casts::ring_to_field_selector(
                        rep3_ring_share,
                        &mut self.io_context,
                    )?,
                ))),
            },
            (Rep3BrilligType::Shared(shared), BitSize::Integer(integer_bit_size)) => match shared {
                Shared::Field(rep3_prime_field_share) => match integer_bit_size {
                    IntegerBitSize::U1 => Ok(Rep3BrilligType::Shared(Shared::Ring1(
                        rep3_ring::casts::field_to_ring_selector(
                            rep3_prime_field_share,
                            &mut self.io_context,
                        )?,
                    ))),
                    IntegerBitSize::U8 => Ok(Rep3BrilligType::Shared(Shared::Ring8(
                        rep3_ring::casts::field_to_ring_selector(
                            rep3_prime_field_share,
                            &mut self.io_context,
                        )?,
                    ))),

                    IntegerBitSize::U16 => Ok(Rep3BrilligType::Shared(Shared::Ring16(
                        rep3_ring::casts::field_to_ring_selector(
                            rep3_prime_field_share,
                            &mut self.io_context,
                        )?,
                    ))),
                    IntegerBitSize::U32 => Ok(Rep3BrilligType::Shared(Shared::Ring32(
                        rep3_ring::casts::field_to_ring_selector(
                            rep3_prime_field_share,
                            &mut self.io_context,
                        )?,
                    ))),
                    IntegerBitSize::U64 => Ok(Rep3BrilligType::Shared(Shared::Ring64(
                        rep3_ring::casts::field_to_ring_selector(
                            rep3_prime_field_share,
                            &mut self.io_context,
                        )?,
                    ))),
                    IntegerBitSize::U128 => Ok(Rep3BrilligType::Shared(Shared::Ring128(
                        rep3_ring::casts::field_to_ring_selector(
                            rep3_prime_field_share,
                            &mut self.io_context,
                        )?,
                    ))),
                },
                Shared::Ring128(rep3_ring_share) => {
                    cast_ring(rep3_ring_share, integer_bit_size, &mut self.io_context)
                }
                Shared::Ring64(rep3_ring_share) => {
                    cast_ring(rep3_ring_share, integer_bit_size, &mut self.io_context)
                }
                Shared::Ring32(rep3_ring_share) => {
                    cast_ring(rep3_ring_share, integer_bit_size, &mut self.io_context)
                }
                Shared::Ring16(rep3_ring_share) => {
                    cast_ring(rep3_ring_share, integer_bit_size, &mut self.io_context)
                }
                Shared::Ring8(rep3_ring_share) => {
                    cast_ring(rep3_ring_share, integer_bit_size, &mut self.io_context)
                }
                Shared::Ring1(rep3_ring_share) => {
                    cast_ring(rep3_ring_share, integer_bit_size, &mut self.io_context)
                }
            },
            (Rep3BrilligType::Public(public), bits) => {
                let casted = self.plain_driver.cast(public, bits)?;
                Ok(Rep3BrilligType::Public(casted))
            }
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

    fn try_into_bool(val: Self::BrilligType) -> Result<bool, Self::BrilligType> {
        match val {
            Rep3BrilligType::Public(Public::Int(val, IntegerBitSize::U1)) => Ok(val != 0),
            x => Err(x),
        }
    }

    fn public_value(val: F, bit_size: BitSize) -> Self::BrilligType {
        Rep3BrilligType::Public(PlainBrilligDriver::public_value(val, bit_size))
    }

    fn random(&mut self, other: &Self::BrilligType) -> Self::BrilligType {
        match other {
            Rep3BrilligType::Public(other) => {
                Rep3BrilligType::Public(self.plain_driver.random(other))
            }
            Rep3BrilligType::Shared(Shared::Field(_)) => {
                let (a, b) = self.io_context.random_fes();
                Rep3BrilligType::shared_field(Rep3PrimeFieldShare::new(a, b))
            }
            Rep3BrilligType::Shared(Shared::Ring128(_)) => {
                let (a, b) = self.io_context.random_elements();
                Rep3BrilligType::shared_u128(Rep3RingShare::new(a, b))
            }
            Rep3BrilligType::Shared(Shared::Ring64(_)) => {
                let (a, b) = self.io_context.random_elements();
                Rep3BrilligType::shared_u64(Rep3RingShare::new(a, b))
            }
            Rep3BrilligType::Shared(Shared::Ring32(_)) => {
                let (a, b) = self.io_context.random_elements();
                Rep3BrilligType::shared_u32(Rep3RingShare::new(a, b))
            }
            Rep3BrilligType::Shared(Shared::Ring16(_)) => {
                let (a, b) = self.io_context.random_elements();
                Rep3BrilligType::shared_u16(Rep3RingShare::new(a, b))
            }
            Rep3BrilligType::Shared(Shared::Ring8(_)) => {
                let (a, b) = self.io_context.random_elements();
                Rep3BrilligType::shared_u8(Rep3RingShare::new(a, b))
            }
            Rep3BrilligType::Shared(Shared::Ring1(_)) => {
                let (a, b) = self.io_context.random_elements();
                Rep3BrilligType::shared_u1(Rep3RingShare::new(a, b))
            }
        }
    }

    fn is_public(val: Self::BrilligType) -> bool {
        matches!(val, Rep3BrilligType::Public(_))
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
        &self,
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
                    (Public::Int(public, IntegerBitSize::U128), Shared::Ring128(shared)) => {
                        let divided = rep3_ring::yao::ring_div_by_shared(
                            public.into(),
                            shared,
                            &mut self.io_context,
                        )?;
                        Rep3BrilligType::shared_u128(divided)
                    }
                    (Public::Int(public, IntegerBitSize::U64), Shared::Ring64(shared)) => {
                        let divided = rep3_ring::yao::ring_div_by_shared(
                            u64::try_from(public).expect("must be u64").into(),
                            shared,
                            &mut self.io_context,
                        )?;
                        Rep3BrilligType::shared_u64(divided)
                    }
                    (Public::Int(public, IntegerBitSize::U32), Shared::Ring32(shared)) => {
                        let divided = rep3_ring::yao::ring_div_by_shared(
                            u32::try_from(public).expect("must be u32").into(),
                            shared,
                            &mut self.io_context,
                        )?;
                        Rep3BrilligType::shared_u32(divided)
                    }
                    (Public::Int(public, IntegerBitSize::U16), Shared::Ring16(shared)) => {
                        let divided = rep3_ring::yao::ring_div_by_shared(
                            u16::try_from(public).expect("must be u16").into(),
                            shared,
                            &mut self.io_context,
                        )?;
                        Rep3BrilligType::shared_u16(divided)
                    }
                    (Public::Int(public, IntegerBitSize::U8), Shared::Ring8(shared)) => {
                        let divided = rep3_ring::yao::ring_div_by_shared(
                            u8::try_from(public).expect("must be u8").into(),
                            shared,
                            &mut self.io_context,
                        )?;
                        Rep3BrilligType::shared_u8(divided)
                    }
                    (Public::Int(_, IntegerBitSize::U1), Shared::Ring1(_)) => {
                        todo!("do we need this?")
                    }
                    _ => panic!("type mismatch. Can only div matching values"),
                }
            }
            (Rep3BrilligType::Shared(shared), Rep3BrilligType::Public(public)) => {
                match (public, shared) {
                    (Public::Field(rhs), Shared::Field(lhs)) => Rep3BrilligType::shared_field(
                        rep3::arithmetic::div_shared_by_public(lhs, rhs)?,
                    ),
                    (Public::Int(public, IntegerBitSize::U128), Shared::Ring128(shared)) => {
                        if public.is_power_of_two() {
                            let divisor_bits = public.ilog2() as usize;
                            let divided = rep3_ring::yao::ring_div_power_2(
                                shared,
                                &mut self.io_context,
                                divisor_bits,
                            )?;
                            Rep3BrilligType::shared_u128(divided)
                        } else {
                            let divided = rep3_ring::yao::ring_div_by_public(
                                shared,
                                public.into(),
                                &mut self.io_context,
                            )?;
                            Rep3BrilligType::shared_u128(divided)
                        }
                    }
                    (Public::Int(public, IntegerBitSize::U64), Shared::Ring64(shared)) => {
                        if public.is_power_of_two() {
                            let divisor_bits = public.ilog2() as usize;
                            let divided = rep3_ring::yao::ring_div_power_2(
                                shared,
                                &mut self.io_context,
                                divisor_bits,
                            )?;
                            Rep3BrilligType::shared_u64(divided)
                        } else {
                            let divided = rep3_ring::yao::ring_div_by_public(
                                shared,
                                u64::try_from(public).expect("must be u64").into(),
                                &mut self.io_context,
                            )?;
                            Rep3BrilligType::shared_u64(divided)
                        }
                    }
                    (Public::Int(public, IntegerBitSize::U32), Shared::Ring32(shared)) => {
                        if public.is_power_of_two() {
                            let divisor_bits = public.ilog2() as usize;
                            let divided = rep3_ring::yao::ring_div_power_2(
                                shared,
                                &mut self.io_context,
                                divisor_bits,
                            )?;
                            Rep3BrilligType::shared_u32(divided)
                        } else {
                            let divided = rep3_ring::yao::ring_div_by_public(
                                shared,
                                u32::try_from(public).expect("must be u32").into(),
                                &mut self.io_context,
                            )?;
                            Rep3BrilligType::shared_u32(divided)
                        }
                    }
                    (Public::Int(public, IntegerBitSize::U16), Shared::Ring16(shared)) => {
                        if public.is_power_of_two() {
                            let divisor_bits = public.ilog2() as usize;
                            let divided = rep3_ring::yao::ring_div_power_2(
                                shared,
                                &mut self.io_context,
                                divisor_bits,
                            )?;
                            Rep3BrilligType::shared_u16(divided)
                        } else {
                            let divided = rep3_ring::yao::ring_div_by_public(
                                shared,
                                u16::try_from(public).expect("must be u16").into(),
                                &mut self.io_context,
                            )?;
                            Rep3BrilligType::shared_u16(divided)
                        }
                    }
                    (Public::Int(public, IntegerBitSize::U8), Shared::Ring8(shared)) => {
                        if public.is_power_of_two() {
                            let divisor_bits = public.ilog2() as usize;
                            let divided = rep3_ring::yao::ring_div_power_2(
                                shared,
                                &mut self.io_context,
                                divisor_bits,
                            )?;
                            Rep3BrilligType::shared_u8(divided)
                        } else {
                            let divided = rep3_ring::yao::ring_div_by_public(
                                shared,
                                u8::try_from(public).expect("must be u8").into(),
                                &mut self.io_context,
                            )?;
                            Rep3BrilligType::shared_u8(divided)
                        }
                    }
                    (Public::Int(public, IntegerBitSize::U1), Shared::Ring1(shared)) => {
                        if public.is_power_of_two() {
                            let divisor_bits = public.ilog2() as usize;
                            let divided = rep3_ring::yao::ring_div_power_2(
                                shared,
                                &mut self.io_context,
                                divisor_bits,
                            )?;
                            Rep3BrilligType::shared_u1(divided)
                        } else {
                            todo!("do we need this?")
                        }
                    }
                    _ => todo!("Implement division for shared/public"),
                }
            }
            (Rep3BrilligType::Shared(s1), Rep3BrilligType::Shared(s2)) => match (s1, s2) {
                (Shared::Field(lhs), Shared::Field(rhs)) => Rep3BrilligType::shared_field(
                    rep3::arithmetic::div(lhs, rhs, &mut self.io_context)?,
                ),

                (Shared::Ring128(lhs), Shared::Ring128(rhs)) => {
                    let divided = rep3_ring::yao::ring_div(lhs, rhs, &mut self.io_context)?;
                    Rep3BrilligType::shared_u128(divided)
                }
                (Shared::Ring64(lhs), Shared::Ring64(rhs)) => {
                    let divided = rep3_ring::yao::ring_div(lhs, rhs, &mut self.io_context)?;
                    Rep3BrilligType::shared_u64(divided)
                }
                (Shared::Ring32(lhs), Shared::Ring32(rhs)) => {
                    let divided = rep3_ring::yao::ring_div(lhs, rhs, &mut self.io_context)?;
                    Rep3BrilligType::shared_u32(divided)
                }
                (Shared::Ring16(lhs), Shared::Ring16(rhs)) => {
                    let divided = rep3_ring::yao::ring_div(lhs, rhs, &mut self.io_context)?;
                    Rep3BrilligType::shared_u16(divided)
                }
                (Shared::Ring8(lhs), Shared::Ring8(rhs)) => {
                    let divided = rep3_ring::yao::ring_div(lhs, rhs, &mut self.io_context)?;
                    Rep3BrilligType::shared_u8(divided)
                }
                (Shared::Ring1(_), Shared::Ring1(_)) => {
                    todo!("do we want this?")
                }
                _ => panic!("type mismatch. Can only div matching values"),
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
                if let (Public::Field(public), Shared::Field(shared)) = (public, shared) {
                    let divided =
                        rep3::yao::field_int_div_by_shared(public, shared, &mut self.io_context)?;
                    Rep3BrilligType::shared_field(divided)
                } else {
                    eyre::bail!("IntDiv only supported on fields")
                }
            }
            (Rep3BrilligType::Shared(shared), Rep3BrilligType::Public(public)) => {
                if let (Public::Field(public), Shared::Field(shared)) = (public, shared) {
                    let divisor: BigUint = public.into();
                    if divisor.count_ones() == 1 {
                        // is power-of-2
                        let divisor_bit = divisor.bits() as usize - 1;
                        let divided = rep3::yao::field_int_div_power_2(
                            shared,
                            &mut self.io_context,
                            divisor_bit,
                        )?;
                        Rep3BrilligType::shared_field(divided)
                    } else {
                        let divided = rep3::yao::field_int_div_by_public(
                            shared,
                            public,
                            &mut self.io_context,
                        )?;
                        Rep3BrilligType::shared_field(divided)
                    }
                } else {
                    eyre::bail!("IntDiv only supported on fields")
                }
            }
            (Rep3BrilligType::Shared(s1), Rep3BrilligType::Shared(s2)) => {
                if let (Shared::Field(s1), Shared::Field(s2)) = (s1, s2) {
                    let divided = rep3::yao::field_int_div(s1, s2, &mut self.io_context)?;
                    Rep3BrilligType::shared_field(divided)
                } else {
                    eyre::bail!("IntDiv only supported on fields")
                }
            }
        };
        Ok(result)
    }

    fn not(&self, val: Self::BrilligType) -> eyre::Result<Self::BrilligType> {
        let result = match val {
            Rep3BrilligType::Public(public) => {
                Rep3BrilligType::Public(self.plain_driver.not(public)?)
            }
            Rep3BrilligType::Shared(shared) => match shared {
                Shared::Ring1(secret) => Rep3BrilligType::shared_u1(!secret),
                _ => eyre::bail!("NOT only supported on u1 values"),
            },
        };
        Ok(result)
    }

    fn eq(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        let result = match (lhs, rhs) {
            (Rep3BrilligType::Public(lhs), Rep3BrilligType::Public(rhs)) => {
                let result = self.plain_driver.eq(lhs, rhs)?;
                Rep3BrilligType::Public(result)
            }
            (Rep3BrilligType::Public(public), Rep3BrilligType::Shared(secret))
            | (Rep3BrilligType::Shared(secret), Rep3BrilligType::Public(public)) => {
                match (secret, public) {
                    (Shared::Field(secret), Public::Field(public)) => {
                        let eq =
                            rep3::arithmetic::eq_bit_public(secret, public, &mut self.io_context)?;
                        let result = Rep3RingShare::new(
                            Bit::cast_from_biguint(&eq.a),
                            Bit::cast_from_biguint(&eq.b),
                        );
                        Rep3BrilligType::shared_u1(result)
                    }
                    (Shared::Ring128(secret), Public::Int(public, IntegerBitSize::U128)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::eq_public(
                            secret,
                            public.into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring64(secret), Public::Int(public, IntegerBitSize::U64)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::eq_public(
                            secret,
                            u64::try_from(public).expect("must be u64").into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring32(secret), Public::Int(public, IntegerBitSize::U32)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::eq_public(
                            secret,
                            u32::try_from(public).expect("must be u32").into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring16(secret), Public::Int(public, IntegerBitSize::U16)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::eq_public(
                            secret,
                            u16::try_from(public).expect("must be u16").into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring8(secret), Public::Int(public, IntegerBitSize::U8)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::eq_public(
                            secret,
                            u8::try_from(public).expect("must be u8").into(),
                            &mut self.io_context,
                        )?)
                    }
                    (Shared::Ring1(secret), Public::Int(public, IntegerBitSize::U1)) => {
                        Rep3BrilligType::shared_u1(rep3_ring::arithmetic::eq_public(
                            secret,
                            bit_from_u128!(public),
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
                    let eq = rep3::arithmetic::eq_bit(s1, s2, &mut self.io_context)?;
                    let result = Rep3RingShare::new(
                        Bit::cast_from_biguint(&eq.a),
                        Bit::cast_from_biguint(&eq.b),
                    );
                    Rep3BrilligType::shared_u1(result)
                }
                (Shared::Ring128(s1), Shared::Ring128(s2)) => Rep3BrilligType::shared_u1(
                    rep3_ring::arithmetic::eq(s1, s2, &mut self.io_context)?,
                ),
                (Shared::Ring64(s1), Shared::Ring64(s2)) => Rep3BrilligType::shared_u1(
                    rep3_ring::arithmetic::eq(s1, s2, &mut self.io_context)?,
                ),
                (Shared::Ring32(s1), Shared::Ring32(s2)) => Rep3BrilligType::shared_u1(
                    rep3_ring::arithmetic::eq(s1, s2, &mut self.io_context)?,
                ),
                (Shared::Ring16(s1), Shared::Ring16(s2)) => Rep3BrilligType::shared_u1(
                    rep3_ring::arithmetic::eq(s1, s2, &mut self.io_context)?,
                ),
                (Shared::Ring8(s1), Shared::Ring8(s2)) => Rep3BrilligType::shared_u1(
                    rep3_ring::arithmetic::eq(s1, s2, &mut self.io_context)?,
                ),
                (Shared::Ring1(s1), Shared::Ring1(s2)) => Rep3BrilligType::shared_u1(
                    rep3_ring::arithmetic::eq(s1, s2, &mut self.io_context)?,
                ),
                x => eyre::bail!(
                    "type mismatch! Can only do bin ops on same types, but tried with {x:?}"
                ),
            },
        };
        Ok(result)
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

    fn to_radix(
        &mut self,
        val: Self::BrilligType,
        radix: Self::BrilligType,
        output_size: usize,
        bits: bool,
    ) -> eyre::Result<Vec<Self::BrilligType>> {
        let result = match (val, radix) {
            (Rep3BrilligType::Public(val), Rep3BrilligType::Public(radix)) => {
                let result = self.plain_driver.to_radix(val, radix, output_size, bits)?;
                result
                    .into_iter()
                    .map(|val| Rep3BrilligType::Public(val))
                    .collect()
            }
            (Rep3BrilligType::Shared(val), Rep3BrilligType::Public(radix)) => {
                if let (Shared::Field(val), Public::Int(radix, IntegerBitSize::U32)) = (val, radix)
                {
                    if bits {
                        todo!("Implement to_radix for shared value and public radix for bits=true")
                    }

                    let radix = u32::try_from(radix).expect("must be u32");
                    let mut input = val;
                    assert!(radix <= 256, "radix is at most 256");
                    if radix.is_power_of_two() {
                        let bits = radix.ilog2();
                        let result = rep3_ring::yao::decompose_field_to_rings::<_, u8, _>(
                            val,
                            &mut self.io_context,
                            output_size,
                            bits as usize,
                        )?;
                        result
                            .into_iter()
                            .rev()
                            .map(|val| Rep3BrilligType::Shared(Shared::Ring8(val)))
                            .collect()
                    } else {
                        let mut limbs: Vec<Rep3BrilligType<_>> =
                            vec![Rep3BrilligType::default(); output_size];
                        for i in (0..output_size).rev() {
                            let div = rep3::yao::field_int_div_by_public(
                                input,
                                radix.into(),
                                &mut self.io_context,
                            )?;
                            let limb = input - rep3::arithmetic::mul_public(div, radix.into());

                            let limb = rep3_ring::yao::field_to_ring_many::<_, u8, _>(
                                &[limb],
                                &mut self.io_context,
                            )?; //radix is at most 256, so should fit into u8, but is this necessary?
                            limbs[i] = Rep3BrilligType::Shared(Shared::<F>::Ring8(limb[0]));

                            input = div;
                        }
                        limbs
                    }
                } else {
                    eyre::bail!("can only ToRadix on field and radix must be Int32")
                }
            }
            (Rep3BrilligType::Public(val), Rep3BrilligType::Shared(radix)) => {
                if let (Public::Field(val), Shared::Ring32(radix)) = (val, radix) {
                    if bits {
                        todo!("Implement to_radix for public value and shared radix for bits=true")
                    }
                    // //todo: do we want to do checks for radix <= 256?
                    let mut limbs: Vec<Rep3BrilligType<_>> =
                        vec![Rep3BrilligType::default(); output_size];
                    let radix_as_field =
                        rep3_ring::yao::ring_to_field_many(&[radix], &mut self.io_context)?;
                    let my_id = self.io_context.network.get_id();
                    let div = rep3::yao::field_int_div_by_shared(
                        val,
                        radix_as_field[0],
                        &mut self.io_context,
                    )?;
                    let limb = rep3::arithmetic::sub_public_by_shared(
                        val,
                        rep3::arithmetic::mul(div, radix_as_field[0], &mut self.io_context)?,
                        my_id,
                    ); // this feels very stupid?

                    let limb = rep3_ring::yao::field_to_ring_many::<_, u8, _>(
                        &[limb],
                        &mut self.io_context,
                    )?; //radix is at most 256, so should fit into u8
                    limbs[output_size - 1] = Rep3BrilligType::Shared(Shared::<F>::Ring8(limb[0]));
                    let mut input = div;
                    for i in (0..output_size).rev().skip(1) {
                        let div = rep3::yao::field_int_div(
                            input,
                            radix_as_field[0],
                            &mut self.io_context,
                        )?;
                        let limb = rep3::arithmetic::sub(
                            input,
                            rep3::arithmetic::mul(div, radix_as_field[0], &mut self.io_context)?,
                        ); // this feels very stupid?

                        let limb = rep3_ring::yao::field_to_ring_many::<_, u8, _>(
                            &[limb],
                            &mut self.io_context,
                        )?; //radix is at most 256, so should fit into u8
                        limbs[i] = Rep3BrilligType::Shared(Shared::<F>::Ring8(limb[0]));
                        input = div;
                    }
                    limbs
                } else {
                    eyre::bail!("can only ToRadix on field and radix must be Int32")
                }
            }
            (Rep3BrilligType::Shared(val), Rep3BrilligType::Shared(radix)) => {
                if let (Shared::Field(_val), Shared::Ring32(_radix)) = (val, radix) {
                    todo!("Implement to_radix for shared value and shared radix")
                } else {
                    eyre::bail!("can only ToRadix on field and radix must be Int32")
                }
            }
        };
        Ok(result)
    }

    fn cmux(
        &mut self,
        cond: Self::BrilligType,
        truthy: Self::BrilligType,
        falsy: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        match cond {
            Rep3BrilligType::Public(Public::Int(cond, IntegerBitSize::U1)) => {
                if cond.is_one() {
                    Ok(truthy)
                } else {
                    Ok(falsy)
                }
            }
            Rep3BrilligType::Shared(Shared::Ring1(cond)) => {
                let casted_condition = match truthy {
                    Rep3BrilligType::Public(Public::Int(_, IntegerBitSize::U128))
                    | Rep3BrilligType::Shared(Shared::Ring128(_)) => {
                        let cast = rep3_ring::casts::ring_cast_selector::<_, u128, _>(
                            cond,
                            &mut self.io_context,
                        )?;
                        Rep3BrilligType::shared_u128(cast)
                    }

                    Rep3BrilligType::Public(Public::Int(_, IntegerBitSize::U64))
                    | Rep3BrilligType::Shared(Shared::Ring64(_)) => {
                        let cast = rep3_ring::casts::ring_cast_selector::<_, u64, _>(
                            cond,
                            &mut self.io_context,
                        )?;
                        Rep3BrilligType::shared_u64(cast)
                    }
                    Rep3BrilligType::Public(Public::Int(_, IntegerBitSize::U32))
                    | Rep3BrilligType::Shared(Shared::Ring32(_)) => {
                        let cast = rep3_ring::casts::ring_cast_selector::<_, u32, _>(
                            cond,
                            &mut self.io_context,
                        )?;
                        Rep3BrilligType::shared_u32(cast)
                    }
                    Rep3BrilligType::Public(Public::Int(_, IntegerBitSize::U16))
                    | Rep3BrilligType::Shared(Shared::Ring16(_)) => {
                        let cast = rep3_ring::casts::ring_cast_selector::<_, u16, _>(
                            cond,
                            &mut self.io_context,
                        )?;
                        Rep3BrilligType::shared_u16(cast)
                    }
                    Rep3BrilligType::Public(Public::Int(_, IntegerBitSize::U8))
                    | Rep3BrilligType::Shared(Shared::Ring8(_)) => {
                        let cast = rep3_ring::casts::ring_cast_selector::<_, u8, _>(
                            cond,
                            &mut self.io_context,
                        )?;
                        Rep3BrilligType::shared_u8(cast)
                    }
                    Rep3BrilligType::Public(Public::Int(_, IntegerBitSize::U1))
                    | Rep3BrilligType::Shared(Shared::Ring1(_)) => Rep3BrilligType::shared_u1(cond),
                    Rep3BrilligType::Public(Public::Field(_))
                    | Rep3BrilligType::Shared(Shared::Field(_)) => {
                        let cast =
                            rep3_ring::casts::ring_to_field_selector(cond, &mut self.io_context)?;
                        Rep3BrilligType::shared_field(cast)
                    }
                };
                let b_min_a = self.sub(truthy, falsy.clone())?;
                let d = self.mul(casted_condition, b_min_a)?;
                self.add(d, falsy)
            }
            _ => eyre::bail!("cmux where cond is a non bool value"),
        }
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
