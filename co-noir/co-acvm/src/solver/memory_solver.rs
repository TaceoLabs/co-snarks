use acir::{
    acir_field::GenericFieldElement,
    circuit::opcodes::{BlockId, MemOp},
    native_types::{Expression, Witness},
};
use ark_ff::PrimeField;
use mpc_core::traits::NoirWitnessExtensionProtocol;

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
        // TODO: should we trust on the compiler here?
        // this should not be possible so maybe we do not need the check?
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
            .ok_or(eyre::eyre!(
                "tried to write not initialized witness to memory - this is a  bug"
            ))?;
        let lut = self.driver.init_lut_by_acvm_type(init);
        self.memory_access.insert(block_id.0.into(), lut);
        Ok(())
    }

    pub(super) fn solve_memory_op(
        &mut self,
        block_id: BlockId,
        op: &MemOp<GenericFieldElement<F>>,
        _predicate: Option<Expression<GenericFieldElement<F>>>,
    ) -> CoAcvmResult<()> {
        tracing::trace!("solving memory op {:?}", op);
        let index = self.evaluate_expression(&op.index)?;
        tracing::trace!("index is {}", index);
        let value = self.simplify_expression(&op.value)?;
        tracing::trace!("value is {:?}", value);
        let witness = if value.is_degree_one_univariate() {
            //we can get the witness
            let (coef, witness) = &value.linear_combinations[0];
            if T::is_public_one(coef) && T::is_public_zero(&value.q_c) {
                Ok(*witness)
            } else {
                Err(eyre::eyre!(
                    "value for mem op must be a degree one univariate polynomial with coef 1 and constant 0"
                ))
            }
        } else {
            Err(eyre::eyre!(
                "value for mem op must be a degree one univariate polynomial"
            ))
        }?;
        let read_write = op.operation.q_c.into_repr();
        //TODO CHECK PREDICATE - do we need to cmux here?
        if read_write.is_zero() {
            // read the value from the LUT
            tracing::trace!("reading value from LUT");
            let lut = self
                .memory_access
                .get(block_id.0.into())
                .ok_or(eyre::eyre!(
                    "tried to access block {} but not present",
                    block_id.0
                ))?;
            let value = self.driver.read_lut_by_acvm_type(&index, lut);
            self.witness().insert(witness, value);
        } else if read_write.is_one() {
            // write value to LUT
            tracing::trace!("writing value to LUT");
            let value = self
                .witness()
                .get(&witness)
                .cloned()
                .ok_or(eyre::eyre!("Trying to write unknown witness in mem block"))?;
            let lut = self
                .memory_access
                .get_mut(block_id.0.into())
                .ok_or(eyre::eyre!(
                    "tried to access block {} but not present",
                    block_id.0
                ))?;
            self.driver.write_lut_by_acvm_type(index, value, lut);
        } else {
            Err(eyre::eyre!(
                "Got unknown operation {} for mem op - this is a bug",
                op.operation.q_c
            ))?
        }
        Ok(())
    }
}
