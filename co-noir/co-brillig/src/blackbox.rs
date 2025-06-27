use ark_ff::PrimeField;
use brillig::{BlackBoxOp, IntegerBitSize, MemoryAddress};
use eyre::Context;

use crate::{CoBrilligVM, mpc::BrilligDriver};

impl<T, F> CoBrilligVM<T, F>
where
    T: BrilligDriver<F>,
    F: PrimeField,
{
    pub(super) fn handle_blackbox(&mut self, blackbox_op: BlackBoxOp) -> eyre::Result<()> {
        match blackbox_op {
            BlackBoxOp::ToRadix {
                input,
                radix,
                output_pointer,
                num_limbs,
                output_bits,
            } => self.handle_to_radix(input, radix, output_pointer, num_limbs, output_bits)?,
            x => todo!("unimplemented blackbox {x:?}"),
        }
        self.increment_program_counter();
        Ok(())
    }

    fn handle_to_radix(
        &mut self,
        input: MemoryAddress,
        radix: MemoryAddress,
        output_pointer: MemoryAddress,
        num_limbs: MemoryAddress,
        output_bits: MemoryAddress,
    ) -> eyre::Result<()> {
        let input = self
            .memory
            .try_read_field(input)
            .context("while getting field for ToRadix")?;
        let radix = self
            .memory
            .try_read_int(radix, IntegerBitSize::U32)
            .context("while getting radix for ToRadix")?;
        let num_limbs = self.memory.try_read_usize(num_limbs)?;
        let output_bits = self
            .memory
            .try_read_int(output_bits, IntegerBitSize::U1)
            .context("while getting output_bits for ToRadix")?;
        let output_bits = T::try_into_bool(output_bits).expect("output_bits must be a public");

        let limbs = self.driver.to_radix(input, radix, num_limbs, output_bits)?;
        let mem_offset = self.memory.read_ref(output_pointer)?;
        self.memory.write_slice(mem_offset, &limbs)?;
        Ok(())
    }
}
