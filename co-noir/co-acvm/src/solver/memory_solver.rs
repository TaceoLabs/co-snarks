use acir::{
    circuit::opcodes::{BlockId, MemOp},
    native_types::{Expression, Witness},
    AcirField,
};
use mpc_core::traits::NoirWitnessExtensionProtocol;

use super::{CoAcvmResult, CoSolver};

impl<T, F> CoSolver<T, F>
where
    T: NoirWitnessExtensionProtocol<F>,
    F: AcirField,
{
    pub(super) fn solve_memory_init_block(
        &mut self,
        block_id: BlockId,
        init: &[Witness],
    ) -> CoAcvmResult<()> {
        // TODO: should we trust on the compiler here?
        // this should not be possible so maybe we do not need the check?
        if self.memory_access.get(block_id.0.into()).is_some() {
            //there is already a block? This should no be possible
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
        let lut = self.driver.init_lut(init);
        self.memory_access.insert(block_id.0.into(), lut);
        Ok(())
    }

    pub(super) fn solve_memory_op(
        &mut self,
        block_id: BlockId,
        op: &MemOp<F>,
        _predicate: Option<Expression<F>>,
    ) -> CoAcvmResult<()> {
        let index = self.evaluate_expression(&op.index)?;
        let value = self.simplify_expression(&op.value)?;
        let witness = if value.is_degree_one_univariate() {
            //we can get the witness
            let (_coef, witness) = &value.linear_combinations[0];
            let _q_c = value.q_c;
            Ok(*witness)
            //todo check if coef is one and q_c is zero!
        } else {
            Err(eyre::eyre!(
                "value for mem op must be a degree one univariate polynomial"
            ))
        }?;
        //TODO CHECK PREDICATE - do we need to cmux here?
        if op.operation.q_c.is_zero() {
            // read the value from the LUT
            let lut = self
                .memory_access
                .get(block_id.0.into())
                .ok_or(eyre::eyre!(
                    "tried to access block {} but not present",
                    block_id.0
                ))?;
            let value = self.driver.get_from_lut(&index, lut);
            self.witness().insert(witness, value);
        } else if op.operation.q_c.is_one() {
            // write value to LUT
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
            self.driver.write_to_lut(index, value, lut);
        } else {
            Err(eyre::eyre!(
                "Got unknown operation {} for mem op - this is a bug",
                op.operation.q_c
            ))?
        }
        Ok(())
    }
}
