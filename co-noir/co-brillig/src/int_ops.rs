use std::fmt::Result;

use acvm::brillig_vm::MemoryValue;
use ark_ff::PrimeField;
use brillig::{BinaryIntOp, IntegerBitSize, MemoryAddress};

use crate::{memory::memory_utils, mpc::BrilligDriver, CoBrilligVM};

impl<T, F> CoBrilligVM<T, F>
where
    T: BrilligDriver<F>,
    F: PrimeField,
{
    pub(super) fn handle_binary_int_op(
        &mut self,
        destination: &MemoryAddress,
        op: &BinaryIntOp,
        bit_size: &IntegerBitSize,
        lhs: &MemoryAddress,
        rhs: &MemoryAddress,
    ) -> eyre::Result<()> {
        // do some sanity checks on bitsize
        let rhs_bit_size = if op == &BinaryIntOp::Shl || op == &BinaryIntOp::Shr {
            IntegerBitSize::U8
        } else {
            *bit_size
        };

        let lhs = memory_utils::expect_int_with_bit_size(self.memory.read(*lhs), *bit_size)?;
        let rhs = memory_utils::expect_int_with_bit_size(self.memory.read(*rhs), rhs_bit_size)?;

        let result = match op {
            BinaryIntOp::Add => MemoryValue::new_integer(lhs + rhs, *bit_size),
            BinaryIntOp::Sub => todo!(),
            BinaryIntOp::Mul => todo!(),
            BinaryIntOp::Div => todo!(),
            BinaryIntOp::Equals => todo!(),
            BinaryIntOp::LessThan => {
                //self.driver.less_than(lhs, rhs);
                MemoryValue::new_integer(u128::from(lhs < rhs), IntegerBitSize::U1)
            }
            BinaryIntOp::LessThanEquals => todo!(),
            BinaryIntOp::And => todo!(),
            BinaryIntOp::Or => todo!(),
            BinaryIntOp::Xor => todo!(),
            BinaryIntOp::Shl => todo!(),
            BinaryIntOp::Shr => todo!(),
        };

        self.memory.write(*destination, result);
        self.increment_program_counter();
        Ok(())
    }
}

// we pas
