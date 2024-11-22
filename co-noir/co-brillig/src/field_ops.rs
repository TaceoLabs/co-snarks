use std::fmt::Result;

use acvm::brillig_vm::MemoryValue;
use ark_ff::PrimeField;
use brillig::{BinaryFieldOp, MemoryAddress};

use crate::{mpc::BrilligDriver, CoBrilligVM};

impl<T, F> CoBrilligVM<T, F>
where
    T: BrilligDriver<F>,
    F: PrimeField,
{
    pub(crate) fn handle_binary_field_op(
        &mut self,
        op: BinaryFieldOp,
        lhs: MemoryAddress,
        rhs: MemoryAddress,
        destination: MemoryAddress,
    ) -> eyre::Result<()> {
        // TODO
        // let a = match lhs {
        //     T::BrilligType::Field(a) => a,
        //     MemoryValue::Integer(_, bit_size) => {
        //         todo!("mismatchedlhsbitsize error")
        //         // return Err(BrilligArithmeticError::MismatchedLhsBitSize {
        //         //     lhs_bit_size: bit_size.into(),
        //         //     op_bit_size: F::max_num_bits(),
        //         // });
        //     }
        // };
        // let b = match rhs {
        //     MemoryValue::Field(b) => b,
        //     MemoryValue::Integer(_, bit_size) => {
        //         todo!("mismatchedlhsbitsize error")
        //         // return Err(BrilligArithmeticError::MismatchedRhsBitSize {
        //         //     rhs_bit_size: bit_size.into(),
        //         //     op_bit_size: F::max_num_bits(),
        //         // });
        //     }
        // };
        let lhs = self.memory.try_read_field(lhs)?;
        let rhs = self.memory.try_read_field(rhs)?;
        let result = match op {
            // Perform addition, subtraction, multiplication, and division based on the BinaryOp variant.
            BinaryFieldOp::Add => self.driver.add(lhs, rhs),
            BinaryFieldOp::Sub => self.driver.sub(lhs, rhs),
            BinaryFieldOp::Mul => self.driver.mul(lhs, rhs),
            BinaryFieldOp::Div => self.driver.div(lhs, rhs),
            BinaryFieldOp::IntegerDiv => self.driver.int_div(lhs, rhs),
            BinaryFieldOp::Equals => self.driver.eq(lhs, rhs), // (a == b).into(),
            BinaryFieldOp::LessThan => self.driver.lt(lhs, rhs),
            BinaryFieldOp::LessThanEquals => self.driver.le(lhs, rhs),
        }?;

        self.memory.write(destination, result)?;
        self.increment_program_counter();
        Ok(())
    }
}
