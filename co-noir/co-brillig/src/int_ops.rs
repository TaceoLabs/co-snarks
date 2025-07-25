use ark_ff::PrimeField;
use brillig::{BinaryIntOp, IntegerBitSize, MemoryAddress};
use eyre::Context;

use crate::{CoBrilligVM, mpc::BrilligDriver};

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

        let lhs = self
            .memory
            .try_read_int(lhs, bit_size)
            .context("while getting lhs int for int binary op")?;
        let mut rhs = self
            .memory
            .try_read_int(rhs, rhs_bit_size)
            .context("while getting rhs for int binary op")?;

        let result = match op {
            BinaryIntOp::Add => self.driver.add(lhs, rhs),
            BinaryIntOp::Sub => self.driver.sub(lhs, rhs),
            BinaryIntOp::Mul => self.driver.mul(lhs, rhs),
            BinaryIntOp::Div => {
                if let Some(cond) = self.shared_ctx.as_ref() {
                    tracing::debug!(
                        "we are in shared context and and maybe need to prevent from div by zero"
                    );
                    rhs = self.driver.cmux(cond.clone(), rhs, T::public_one())?;
                }
                self.driver.div(lhs, rhs)
            }
            BinaryIntOp::Equals => self.driver.eq(lhs, rhs),
            BinaryIntOp::LessThan => self.driver.lt(lhs, rhs),
            BinaryIntOp::LessThanEquals => self.driver.le(lhs, rhs),
            BinaryIntOp::And => todo!("BinaryIntOp::And"),
            BinaryIntOp::Or => todo!("BinaryIntOp::Or"),
            BinaryIntOp::Xor => todo!("BinaryIntOp::Xor"),
            BinaryIntOp::Shl => todo!("BinaryIntOp::Shl"),
            BinaryIntOp::Shr => todo!("BinaryIntOp::Shr"),
        };

        self.memory.write(destination, result?)?;
        self.increment_program_counter();
        Ok(())
    }
}

// we pas
