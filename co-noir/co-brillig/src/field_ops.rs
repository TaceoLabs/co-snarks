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
        let lhs_value = self.memory.read(lhs);
        let rhs_value = self.memory.read(rhs);

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
        let a = self.memory.read(lhs)?;
        let b = self.memory.read(rhs)?;
        let result = match op {
            // Perform addition, subtraction, multiplication, and division based on the BinaryOp variant.
            BinaryFieldOp::Add => self.driver.add_franco(a, b),
            BinaryFieldOp::Sub => self.driver.sub(a, b),
            BinaryFieldOp::Mul => self.driver.mul(a, b),
            BinaryFieldOp::Div => self.driver.div(a, b),
            BinaryFieldOp::IntegerDiv => {
                todo!()
                // if T::is_public_zero(&b) {
                //     todo!("division by zero error")
                // } else {
                //     let a_big = BigUint::from_bytes_be(&a.to_be_bytes());
                //     let b_big = BigUint::from_bytes_be(&b.to_be_bytes());

                //     let result = a_big / b_big;
                //     MemoryValue::new_field(F::from_be_bytes_reduce(&result.to_bytes_be()))
                // }
            }
            BinaryFieldOp::Equals => self.driver.equal(a, b), // (a == b).into(),
            BinaryFieldOp::LessThan => self.driver.lt_franco(a, b),
            BinaryFieldOp::LessThanEquals => self.driver.le_franco(a, b),
        }?;

        self.memory.write(destination, result)?;
        self.increment_program_counter();
        Ok(())
    }
}
