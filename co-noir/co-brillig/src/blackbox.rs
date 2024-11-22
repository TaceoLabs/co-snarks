use ark_ff::PrimeField;
use brillig::{BlackBoxOp, HeapArray, IntegerBitSize, MemoryAddress};
use eyre::Context;

use crate::{mpc::BrilligDriver, CoBrilligVM};

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
                output,
                output_bits,
            } => self.handle_to_radix(input, radix, output, output_bits)?,
            x => todo!("unimplemented blackbox {x:?}"),
        }
        self.increment_program_counter();
        Ok(())
    }

    fn handle_to_radix(
        &mut self,
        input: MemoryAddress,
        radix: MemoryAddress,
        output: HeapArray,
        output_bits: bool,
    ) -> eyre::Result<()> {
        let input = self
            .memory
            .try_read_field(input)
            .context("while geting field for ToRadix")?;
        let radix = self
            .memory
            .try_read_int(radix, IntegerBitSize::U32)
            .context("while getting radix for ToRadix")?;
        let limbs = self
            .driver
            .to_radix(input, radix, output.size, output_bits)?;
        let mem_offset = self.memory.read_ref(output.pointer)?;
        self.memory.write_slice(mem_offset, &limbs)?;
        Ok(())
    }
}
