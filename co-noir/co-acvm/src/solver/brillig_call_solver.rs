use crate::mpc::NoirWitnessExtensionProtocol;
use acir::{
    acir_field::GenericFieldElement,
    circuit::brillig::{BrilligFunctionId, BrilligInputs, BrilligOutputs},
    native_types::Expression,
};
use ark_ff::PrimeField;
use eyre::Context;

use super::{CoAcvmResult, CoSolver};

fn get_output_size(outputs: &[BrilligOutputs]) -> usize {
    outputs
        .iter()
        .map(|output| match output {
            BrilligOutputs::Simple(_) => 1,
            BrilligOutputs::Array(arr) => arr.len(),
        })
        .sum()
}

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
        predicate: &Option<Expression<GenericFieldElement<F>>>,
    ) -> CoAcvmResult<()> {
        if let Some(expr) = predicate {
            let predicate = self.evaluate_expression(expr)?;
            // we skip if predicate is zero
            if T::is_public_zero(&predicate) {
                tracing::debug!("skipping brillig call as predicate is zero");
                // short circuit and fill with zeros
                let zeroes_result = vec![T::public_zero(); get_output_size(outputs)];
                self.fill_output(zeroes_result, outputs);
                return Ok(());
            }
        }
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
            }
        }
        let brillig_result = T::from_brillig_result(self.brillig.run(id, calldata)?);
        self.fill_output(brillig_result, outputs);
        Ok(())
    }

    fn fill_output(&mut self, brillig_result: Vec<T::AcvmType>, outputs: &[BrilligOutputs]) {
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
    }
}
