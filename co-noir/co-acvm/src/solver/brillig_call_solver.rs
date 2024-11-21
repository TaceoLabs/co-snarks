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
        predicate: &Option<Expression<GenericFieldElement<F>>>,
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
        self.brillig.run(id, calldata, outputs);

        //CoBrilligVM::<T, F>::solve(&function_to_run, calldata, outputs);

        // spin up CoBrillig instance
        todo!()
    }
}
