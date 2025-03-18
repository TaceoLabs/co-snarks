use std::marker::PhantomData;

use acvm::brillig_vm::MEMORY_ADDRESSING_BIT_SIZE;
use ark_ff::{One as _, PrimeField};
use brillig::{BitSize, IntegerBitSize};
use num_bigint::BigUint;
use num_traits::Zero;
use rand::Rng;

use super::{acir_field_utils, BrilligDriver, CHAR_BIT_SIZE};

macro_rules! wrapping_op {
    ($lhs:expr, $op: tt, $rhs:expr, $bit_size:expr) => {
        ($lhs $op $rhs) % match $bit_size {
                    IntegerBitSize::U1 => 1 << 1,
                    IntegerBitSize::U8 => 1 << 8,
                    IntegerBitSize::U16 => 1 << 16,
                    IntegerBitSize::U32 => 1 << 32,
                    IntegerBitSize::U64 => 1 << 64,
                    IntegerBitSize::U128 => unreachable!("match it"),
                }
    };
}

/// A plain driver for the coBrillig-VM. This driver is mostly
/// for testing purposes. It does NOT perform any MPC operations.
/// Everything is locally computed on your machine.
#[derive(Default)]
pub struct PlainBrilligDriver<F: PrimeField> {
    phantom_data: PhantomData<F>,
}
impl<F: PrimeField> PlainBrilligDriver<F> {
    /// Creates a new instance of the driver.
    pub fn new() -> Self {
        Self {
            phantom_data: Default::default(),
        }
    }
}

/// The types for the coBrillig plain driver. The values
/// can either be fields or integers.
#[derive(Clone, Debug, PartialEq)]
pub enum PlainBrilligType<F: PrimeField> {
    /// A field element
    Field(F),
    /// An integer with the provided bit size.
    Int(u128, IntegerBitSize),
}

impl<F: PrimeField> PlainBrilligType<F> {
    /// Consumes `self` and converts the type to the underlying
    /// field implementation.
    pub fn into_field(self) -> F {
        match self {
            PlainBrilligType::Field(f) => f,
            PlainBrilligType::Int(i, _) => F::from(i),
        }
    }
}

impl<F: PrimeField> From<F> for PlainBrilligType<F> {
    fn from(value: F) -> Self {
        PlainBrilligType::Field(value)
    }
}

impl<F: PrimeField> Default for PlainBrilligType<F> {
    fn default() -> Self {
        Self::from(F::default())
    }
}

impl<F: PrimeField> BrilligDriver<F> for PlainBrilligDriver<F> {
    type BrilligType = PlainBrilligType<F>;

    fn fork(&mut self) -> eyre::Result<(Self, Self)> {
        Ok((Self::default(), Self::default()))
    }

    fn cast(
        &mut self,
        src: Self::BrilligType,
        bit_size: BitSize,
    ) -> eyre::Result<Self::BrilligType> {
        let casted = match (src, bit_size) {
            // no-op
            (PlainBrilligType::Field(f), BitSize::Field) => PlainBrilligType::Field(f),
            // downcast to int
            (PlainBrilligType::Field(f), BitSize::Integer(target_bit_size)) => {
                let target_bit_size_u32: u32 = target_bit_size.into();
                let mask = (1_u128 << target_bit_size_u32) - 1;
                PlainBrilligType::Int(acir_field_utils::to_u128(f) & mask, target_bit_size)
            }
            // promote to field
            (PlainBrilligType::Int(int, _), BitSize::Field) => {
                PlainBrilligType::Field(F::from(int))
            }
            (PlainBrilligType::Int(int, bit_size), BitSize::Integer(target_bit_size)) => {
                if bit_size <= target_bit_size {
                    // upcast
                    PlainBrilligType::Int(int, target_bit_size)
                } else {
                    // downcast
                    let target_bit_size_u32: u32 = target_bit_size.into();
                    let mask = (1_u128 << target_bit_size_u32) - 1;
                    PlainBrilligType::Int(int & mask, target_bit_size)
                }
            }
        };
        Ok(casted)
    }

    fn try_into_usize(val: Self::BrilligType) -> eyre::Result<usize> {
        match val {
            PlainBrilligType::Field(_) => Err(eyre::eyre!("cannot convert field to usize")),
            PlainBrilligType::Int(int, bit_size) => {
                if bit_size == MEMORY_ADDRESSING_BIT_SIZE {
                    Ok(usize::try_from(int).expect("u32 into usize"))
                } else {
                    Err(eyre::eyre!(
                        "Must be {} for addresses, but is {}",
                        MEMORY_ADDRESSING_BIT_SIZE,
                        bit_size
                    ))
                }
            }
        }
    }

    fn try_into_char(val: Self::BrilligType) -> eyre::Result<char> {
        match val {
            PlainBrilligType::Field(_) => Err(eyre::eyre!("cannot convert field to char")),
            PlainBrilligType::Int(int, bit_size) => {
                if bit_size == CHAR_BIT_SIZE {
                    Ok(char::from(u8::try_from(int).expect("u8 fits into char")))
                } else {
                    Err(eyre::eyre!(
                        "Must be {} bits for charcters, but is {}",
                        CHAR_BIT_SIZE,
                        bit_size
                    ))
                }
            }
        }
    }

    fn try_into_bool(val: Self::BrilligType) -> Result<bool, Self::BrilligType> {
        //Err(val)
        match val {
            PlainBrilligType::Int(val, IntegerBitSize::U1) => Ok(val != 0),
            x => Err(x),
        }
    }

    fn public_value(val: F, bit_size: BitSize) -> Self::BrilligType {
        match bit_size {
            BitSize::Field => PlainBrilligType::Field(val),
            BitSize::Integer(bit_size) => {
                PlainBrilligType::Int(acir_field_utils::to_u128(val), bit_size)
            }
        }
    }

    fn random(&mut self, other: &Self::BrilligType) -> Self::BrilligType {
        let mut rng = rand::thread_rng();
        match other {
            PlainBrilligType::Field(_) => PlainBrilligType::Field(F::rand(&mut rng)),
            PlainBrilligType::Int(_, IntegerBitSize::U128) => {
                PlainBrilligType::Int(rng.gen(), IntegerBitSize::U128)
            }
            PlainBrilligType::Int(_, IntegerBitSize::U64) => {
                PlainBrilligType::Int(rng.gen::<u64>().into(), IntegerBitSize::U64)
            }
            PlainBrilligType::Int(_, IntegerBitSize::U32) => {
                PlainBrilligType::Int(rng.gen::<u32>().into(), IntegerBitSize::U32)
            }
            PlainBrilligType::Int(_, IntegerBitSize::U16) => {
                PlainBrilligType::Int(rng.gen::<u16>().into(), IntegerBitSize::U16)
            }
            PlainBrilligType::Int(_, IntegerBitSize::U8) => {
                PlainBrilligType::Int(rng.gen::<u8>().into(), IntegerBitSize::U8)
            }
            PlainBrilligType::Int(_, IntegerBitSize::U1) => {
                PlainBrilligType::Int(rng.gen::<bool>().into(), IntegerBitSize::U1)
            }
        }
    }

    fn is_public(_: Self::BrilligType) -> bool {
        true
    }

    fn add(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        match (lhs, rhs) {
            (PlainBrilligType::Field(lhs), PlainBrilligType::Field(rhs)) => {
                Ok(PlainBrilligType::Field(lhs + rhs))
            }

            (
                PlainBrilligType::Int(lhs, IntegerBitSize::U128),
                PlainBrilligType::Int(rhs, IntegerBitSize::U128),
            ) => {
                let result = lhs.wrapping_add(rhs);
                Ok(PlainBrilligType::Int(result, IntegerBitSize::U128))
            }
            (
                PlainBrilligType::Int(lhs, lhs_bit_size),
                PlainBrilligType::Int(rhs, rhs_bit_size),
            ) if lhs_bit_size == rhs_bit_size => {
                let result = wrapping_op!(lhs, +, rhs, lhs_bit_size);
                Ok(PlainBrilligType::Int(result, lhs_bit_size))
            }
            x => eyre::bail!(
                "type mismatch! Can only do bin ops on same types, but tried with {x:?}"
            ),
        }
    }

    fn sub(
        &self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        match (lhs, rhs) {
            (PlainBrilligType::Field(lhs), PlainBrilligType::Field(rhs)) => {
                Ok(PlainBrilligType::Field(lhs - rhs))
            }

            (
                PlainBrilligType::Int(lhs, IntegerBitSize::U128),
                PlainBrilligType::Int(rhs, IntegerBitSize::U128),
            ) => {
                let result = lhs.wrapping_sub(rhs);
                Ok(PlainBrilligType::Int(result, IntegerBitSize::U128))
            }
            (
                PlainBrilligType::Int(lhs, lhs_bit_size),
                PlainBrilligType::Int(rhs, rhs_bit_size),
            ) if lhs_bit_size == rhs_bit_size => {
                let result = wrapping_op!(lhs, -, rhs, lhs_bit_size);
                Ok(PlainBrilligType::Int(result, lhs_bit_size))
            }
            x => eyre::bail!(
                "type mismatch! Can only do bin ops on same types, but tried with {x:?}"
            ),
        }
    }

    fn mul(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        match (lhs, rhs) {
            (PlainBrilligType::Field(lhs), PlainBrilligType::Field(rhs)) => {
                Ok(PlainBrilligType::Field(lhs * rhs))
            }

            (
                PlainBrilligType::Int(lhs, IntegerBitSize::U128),
                PlainBrilligType::Int(rhs, IntegerBitSize::U128),
            ) => {
                let result = lhs.wrapping_mul(rhs);
                Ok(PlainBrilligType::Int(result, IntegerBitSize::U128))
            }
            (
                PlainBrilligType::Int(lhs, lhs_bit_size),
                PlainBrilligType::Int(rhs, rhs_bit_size),
            ) if lhs_bit_size == rhs_bit_size => {
                let result = wrapping_op!(lhs, *, rhs, lhs_bit_size);
                Ok(PlainBrilligType::Int(result, lhs_bit_size))
            }
            x => eyre::bail!(
                "type mismatch! Can only do bin ops on same types, but tried with {x:?}"
            ),
        }
    }

    fn div(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        match (lhs, rhs) {
            (PlainBrilligType::Field(lhs), PlainBrilligType::Field(rhs)) => {
                Ok(PlainBrilligType::Field(lhs / rhs))
            }
            (
                PlainBrilligType::Int(lhs, IntegerBitSize::U128),
                PlainBrilligType::Int(rhs, IntegerBitSize::U128),
            ) => {
                let result = lhs.wrapping_div(rhs);
                Ok(PlainBrilligType::Int(result, IntegerBitSize::U128))
            }
            (
                PlainBrilligType::Int(lhs, lhs_bit_size),
                PlainBrilligType::Int(rhs, rhs_bit_size),
            ) if lhs_bit_size == rhs_bit_size => {
                let result = wrapping_op!(lhs, /, rhs, lhs_bit_size);
                Ok(PlainBrilligType::Int(result, lhs_bit_size))
            }
            x => eyre::bail!(
                "type mismatch! Can only do bin ops on same types, but tried with {x:?}"
            ),
        }
    }

    fn int_div(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        if let (PlainBrilligType::Field(lhs), PlainBrilligType::Field(rhs)) = (lhs, rhs) {
            let lhs: BigUint = lhs.into();
            let rhs: BigUint = rhs.into();
            Ok(PlainBrilligType::Field(F::from(lhs / rhs)))
        } else {
            eyre::bail!("IntDiv only supported on fields")
        }
    }

    fn not(&self, val: Self::BrilligType) -> eyre::Result<Self::BrilligType> {
        match val {
            PlainBrilligType::Int(val, integer_bit_size) => {
                if integer_bit_size == IntegerBitSize::U128 {
                    Ok(PlainBrilligType::Int(!val, IntegerBitSize::U128))
                } else {
                    let bit_size: u32 = integer_bit_size.into();
                    let mask = (1_u128 << bit_size as u128) - 1;
                    Ok(PlainBrilligType::Int((!val) & mask, integer_bit_size))
                }
            }
            PlainBrilligType::Field(_) => eyre::bail!("NOT is not supported for fields"),
        }
    }

    fn eq(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        match (lhs, rhs) {
            (PlainBrilligType::Field(lhs), PlainBrilligType::Field(rhs)) => {
                let result = u128::from(lhs == rhs);
                Ok(PlainBrilligType::Int(result, IntegerBitSize::U1))
            }
            (
                PlainBrilligType::Int(lhs, lhs_bit_size),
                PlainBrilligType::Int(rhs, rhs_bit_size),
            ) if lhs_bit_size == rhs_bit_size => {
                let result = u128::from(lhs == rhs);
                Ok(PlainBrilligType::Int(result, IntegerBitSize::U1))
            }
            x => eyre::bail!(
                "type mismatch! Can only do bin ops on same types, but tried with {x:?}"
            ),
        }
    }

    fn lt(
        &mut self,
        lhs: Self::BrilligType,
        rhs: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        match (lhs, rhs) {
            (PlainBrilligType::Field(lhs), PlainBrilligType::Field(rhs)) => {
                let result = u128::from(lhs < rhs);
                Ok(PlainBrilligType::Int(result, IntegerBitSize::U1))
            }
            (
                PlainBrilligType::Int(lhs, lhs_bit_size),
                PlainBrilligType::Int(rhs, rhs_bit_size),
            ) if lhs_bit_size == rhs_bit_size => {
                let result = u128::from(lhs < rhs);
                Ok(PlainBrilligType::Int(result, IntegerBitSize::U1))
            }
            x => eyre::bail!(
                "type mismatch! Can only do bin ops on same types, but tried with {x:?}"
            ),
        }
    }

    fn to_radix(
        &mut self,
        val: Self::BrilligType,
        radix: Self::BrilligType,
        output_size: usize,
        bits: bool,
    ) -> eyre::Result<Vec<Self::BrilligType>> {
        if let (PlainBrilligType::Field(val), PlainBrilligType::Int(radix, IntegerBitSize::U32)) =
            (val, radix)
        {
            // this method is copied from
            // https://github.com/noir-lang/noir/blob/7216f0829dcece948d3243471e6d57380522e997/acvm-repo/brillig_vm/src/black_box.rs#L323
            // and modified for our implementation

            let mut input: BigUint = val.into();
            let radix = BigUint::from(radix);

            let mut limbs = vec![PlainBrilligType::default(); output_size];

            for i in (0..output_size).rev() {
                let limb = &input % &radix;
                if bits {
                    let limb = if limb.is_zero() { 0 } else { 1 };
                    limbs[i] = PlainBrilligType::Int(limb, IntegerBitSize::U1);
                } else {
                    let limb: u128 = limb
                        .try_into()
                        .expect("fits into u128 since radix is at most 256");
                    limbs[i] = PlainBrilligType::Int(limb, IntegerBitSize::U8);
                };
                input /= &radix;
            }
            for limb in limbs.iter() {
                tracing::debug!("{limb:?}");
            }
            Ok(limbs)
        } else {
            eyre::bail!("can only ToRadix on field and radix must be Int32")
        }
    }

    fn cmux(
        &mut self,
        cond: Self::BrilligType,
        truthy: Self::BrilligType,
        falsy: Self::BrilligType,
    ) -> eyre::Result<Self::BrilligType> {
        if let PlainBrilligType::Int(cond, IntegerBitSize::U1) = cond {
            if cond.is_one() {
                Ok(truthy)
            } else {
                Ok(falsy)
            }
        } else {
            eyre::bail!("cmux where cond is a non bool value")
        }
    }

    fn expect_int(
        val: Self::BrilligType,
        should_bit_size: IntegerBitSize,
    ) -> eyre::Result<Self::BrilligType> {
        if let PlainBrilligType::Int(_, is_bit_size) = val {
            if is_bit_size == should_bit_size {
                Ok(val)
            } else {
                eyre::bail!("expected int with size: {should_bit_size}, but got {val:?}")
            }
        } else {
            eyre::bail!("expected int with size: {should_bit_size}, but got {val:?}")
        }
    }

    fn expect_field(val: Self::BrilligType) -> eyre::Result<Self::BrilligType> {
        if let PlainBrilligType::Field(val) = val {
            Ok(PlainBrilligType::Field(val))
        } else {
            eyre::bail!("expected field, but got {val:?}")
        }
    }
}
