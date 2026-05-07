use crate::{mpc::NoirWitnessExtensionProtocol, solver::CoAcvmError};
use acir::{
    acir_field::GenericFieldElement,
    circuit::brillig::{BrilligFunctionId, BrilligInputs, BrilligOutputs},
    native_types::Expression,
};
use ark_ff::PrimeField;
use co_brillig::BrilligSuccess;
use co_brillig::CoBrilligResult;
use eyre::Context;
use itertools::izip;

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

fn mask_brillig_result<T, F>(
    cond: T::AcvmType,
    result: Vec<T::AcvmType>,
    driver: &mut T,
) -> CoAcvmResult<Vec<T::AcvmType>>
where
    T: NoirWitnessExtensionProtocol<F>,
    F: PrimeField,
{
    let masking_zeros = driver.shared_zeros(result.len())?;
    let mut masked_result = Vec::with_capacity(result.len());
    for (correct, mask) in izip!(result, masking_zeros) {
        masked_result.push(driver.cmux(cond.clone(), correct, mask)?);
    }
    Ok(masked_result)
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
        predicate: &Expression<GenericFieldElement<F>>,
    ) -> CoAcvmResult<()> {
        let mask_predicate = {
            let predicate = self.evaluate_expression(predicate)?;
            // we skip if predicate is zero
            if T::is_public_zero(&predicate) {
                tracing::debug!("skipping brillig call as predicate is zero");
                // short circuit and fill with zeros
                let zeroes_result = vec![T::public_zero(); get_output_size(outputs)];
                self.fill_output(zeroes_result, outputs);
                return Ok(());
            } else if T::is_public_one(&predicate) {
                None
            } else {
                // we need to cmux the result with random zeros
                Some(predicate)
            }
        };
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
        let brillig_result = self.brillig.run(id, calldata)?;
        if let CoBrilligResult::Success(BrilligSuccess {
            unconstrained_witnesses,
            generated_pss,
        }) = brillig_result
        {
            self.value_store
                .add_from_brillig(&mut self.driver, generated_pss)?;
            let brillig_result = self.driver.parse_brillig_result(unconstrained_witnesses)?;
            let brillig_result = if let Some(predicate) = mask_predicate {
                mask_brillig_result(predicate, brillig_result, &mut self.driver)?
            } else {
                brillig_result
            };
            self.fill_output(brillig_result, outputs);
            Ok(())
        } else {
            Err(CoAcvmError::BrilligVmFailed)
        }
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
