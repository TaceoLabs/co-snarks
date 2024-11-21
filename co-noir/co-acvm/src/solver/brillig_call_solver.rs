use crate::mpc::NoirWitnessExtensionProtocol;
use acir::{
    acir_field::GenericFieldElement,
    circuit::brillig::{BrilligFunctionId, BrilligInputs, BrilligOutputs},
    native_types::Expression,
};
use ark_ff::PrimeField;
use co_brillig::CoBrilligVM;
use eyre::Context;

use super::{CoAcvmResult, CoSolver};

impl<T, F> CoSolver<T, F>
where
    T: NoirWitnessExtensionProtocol<F>,
    F: PrimeField,
{
    pub(super) fn brillig_call(
        &mut self,
        id: &BrilligFunctionId,
        inputs: &[BrilligInputs<GenericFieldElement<F>>],
        outputs: &[BrilligOutputs],
        _predicate: &Option<Expression<GenericFieldElement<F>>>,
    ) -> CoAcvmResult<()> {
        tracing::debug!("solving brillig call: {}", id);

        let mut calldata = vec![];
        for input in inputs {
            match input {
                BrilligInputs::Single(expr) => {
                    let param = self
                        .evaluate_expression(expr)
                        .context("during call data init for brillig")?;
                    calldata.push(param.into());
                }
                BrilligInputs::Array(array) => {
                    for expr in array.iter() {
                        let param = self
                            .evaluate_expression(expr)
                            .context("during call data init for brillig")?;
                        calldata.push(param.into());
                    }
                }
                BrilligInputs::MemoryArray(_) => todo!("memory array calldata TODO"),
            };
        }
        let brillig_result = T::from_brillig_result(self.brillig.run(id, calldata)?);
        let mut current_ret_data_idx = 0;
        for output in outputs.iter() {
            match output {
                BrilligOutputs::Simple(witness) => {
                    self.witness()
                        .insert(*witness, brillig_result[current_ret_data_idx].clone());
                    current_ret_data_idx += 1;
                }
                BrilligOutputs::Array(witness_arr) => {
                    for witness in witness_arr.iter() {
                        self.witness()
                            .insert(*witness, brillig_result[current_ret_data_idx].clone());
                        current_ret_data_idx += 1;
                    }
                }
            }
        }

        Ok(())
    }
}
