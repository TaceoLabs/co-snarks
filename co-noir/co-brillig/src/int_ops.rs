use ark_ff::PrimeField;
use brillig::{BinaryIntOp, IntegerBitSize, MemoryAddress};

use crate::{mpc::BrilligDriver, CoBrilligVM};

impl<T, F> CoBrilligVM<T, F>
where
    T: BrilligDriver<F>,
    F: PrimeField,
{
    pub(super) fn handle_binary_int_op(
        &mut self,
        destination: MemoryAddress,
        op: BinaryIntOp,
        bit_size: IntegerBitSize,
        lhs: MemoryAddress,
        rhs: MemoryAddress,
    ) -> eyre::Result<()> {
        // do some sanity checks on bitsize
        let rhs_bit_size = if op == BinaryIntOp::Shl || op == BinaryIntOp::Shr {
            IntegerBitSize::U8
        } else {
            bit_size
        };

        let lhs = T::expect_int_bit_size(self.memory.read(lhs)?, bit_size)?;
        let rhs = T::expect_int_bit_size(self.memory.read(rhs)?, rhs_bit_size)?;

        let result = match op {
            BinaryIntOp::Add => self.driver.add(lhs, rhs),
            BinaryIntOp::Sub => todo!(),
            BinaryIntOp::Mul => todo!(),
            BinaryIntOp::Div => todo!(),
            BinaryIntOp::Equals => todo!(),
            BinaryIntOp::LessThan => self.driver.lt(lhs, rhs),
            BinaryIntOp::LessThanEquals => self.driver.le(lhs, rhs),
            BinaryIntOp::And => todo!(),
            BinaryIntOp::Or => todo!(),
            BinaryIntOp::Xor => todo!(),
            BinaryIntOp::Shl => todo!(),
            BinaryIntOp::Shr => todo!(),
        };

        self.memory.write(destination, result?)?;
        self.increment_program_counter();
        Ok(())
    }
}

// we pas
