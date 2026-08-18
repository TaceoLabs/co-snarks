use crate::mpc::NoirWitnessExtensionProtocol;
use acir::{
    acir_field::GenericFieldElement,
    circuit::opcodes::{BlockId, MemOp, MemOpKind},
    native_types::Witness,
};
use ark_ff::PrimeField;

use super::{CoAcvmResult, CoSolver};

impl<T, F> CoSolver<T, F>
where
    T: NoirWitnessExtensionProtocol<F>,
    F: PrimeField,
{
    pub(super) fn solve_memory_init_block(
        &mut self,
        block_id: BlockId,
        init: &[Witness],
    ) -> CoAcvmResult<()> {
        tracing::trace!("solving memory init block {}", block_id.0);
        if self.memory_access.get(block_id.0.into()).is_some() {
            //there is already a block? This should no be possible
            tracing::error!("There is already a block for id {}", block_id.0);
            Err(eyre::eyre!(
                "There is already a block for id {}",
                block_id.0
            ))?;
        }
        // let get all witnesses
        let witness_map = self.witness();
        let init = init
            .iter()
            .map(|witness| witness_map.get(witness).cloned())
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| {
                eyre::eyre!("tried to write not initialized witness to memory - this is a  bug")
            })?;
        let lut = self.driver.init_lut_by_acvm_type(init);
        self.memory_access.insert(block_id.0.into(), lut);
        Ok(())
    }

    pub(super) fn solve_memory_op(
        &mut self,
        block_id: BlockId,
        op: &MemOp<GenericFieldElement<F>>,
    ) -> CoAcvmResult<()> {
        tracing::trace!("solving memory op {:?}", op);
        let index = Self::witness_to_value(self.witness(), op.index)?.to_owned();
        tracing::trace!("index is {}", index);
        match op.operation {
            MemOpKind::Read => {
                // read the value from the LUT
                tracing::trace!("reading value from LUT");
                let lut = self.memory_access.get(block_id.0.into()).ok_or_else(|| {
                    eyre::eyre!("tried to access block {} but not present", block_id.0)
                })?;
                let value = self.driver.read_lut_by_acvm_type(index, lut)?;

                self.witness().insert(op.value, value);
            }
            MemOpKind::Write => {
                // write value to LUT
                tracing::trace!("writing value to LUT");
                let value = Self::witness_to_value(self.witness(), op.value)?.to_owned();
                let lut = self
                    .memory_access
                    .get_mut(block_id.0.into())
                    .ok_or_else(|| {
                        eyre::eyre!("tried to access block {} but not present", block_id.0)
                    })?;

                self.driver.write_lut_by_acvm_type(index, value, lut)?;
            }
        }
        Ok(())
    }
}
