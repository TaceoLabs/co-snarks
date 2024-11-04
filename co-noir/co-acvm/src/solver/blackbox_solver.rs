use super::{CoAcvmResult, CoSolver};
use crate::mpc::NoirWitnessExtensionProtocol;
use acir::{
    acir_field::GenericFieldElement,
    circuit::opcodes::{BlackBoxFuncCall, ConstantOrWitnessEnum, FunctionInput},
    native_types::{Witness, WitnessMap},
    AcirField,
};
use ark_ff::PrimeField;

impl<T, F> CoSolver<T, F>
where
    T: NoirWitnessExtensionProtocol<F>,
    F: PrimeField,
{
    /// Check if all of the inputs to the function have assignments
    ///
    /// Returns the first missing assignment if any are missing
    fn first_missing_assignment(
        witness_assignments: &WitnessMap<T::AcvmType>,
        inputs: &[FunctionInput<GenericFieldElement<F>>],
    ) -> Option<Witness> {
        inputs.iter().find_map(|input| {
            if let ConstantOrWitnessEnum::Witness(ref witness) = input.input {
                if witness_assignments.contains_key(witness) {
                    None
                } else {
                    Some(*witness)
                }
            } else {
                None
            }
        })
    }

    /// Check if all of the inputs to the function have assignments
    fn contains_all_inputs(
        witness_assignments: &WitnessMap<T::AcvmType>,
        inputs: &[FunctionInput<GenericFieldElement<F>>],
    ) -> bool {
        Self::first_missing_assignment(witness_assignments, inputs).is_none()
    }

    // Returns the concrete value for a particular witness
    // If the witness has no assignment, then
    // an error is returned
    pub fn witness_to_value(
        initial_witness: &WitnessMap<T::AcvmType>,
        witness: Witness,
    ) -> CoAcvmResult<&T::AcvmType> {
        match initial_witness.get(&witness) {
            Some(value) => Ok(value),
            None => Err(eyre::eyre!("missing assignment for witness: {}", witness.0))?,
        }
    }

    // TODO(https://github.com/noir-lang/noir/issues/5985):
    // remove skip_bitsize_checks
    pub fn input_to_value(
        initial_witness: &WitnessMap<T::AcvmType>,
        input: FunctionInput<GenericFieldElement<F>>,
        skip_bitsize_checks: bool,
    ) -> CoAcvmResult<T::AcvmType> {
        match input.input {
            ConstantOrWitnessEnum::Witness(witness) => {
                let initial_value = Self::witness_to_value(initial_witness, witness)?;

                // We also skip for shared values since we cannot check them
                if skip_bitsize_checks || T::is_shared(initial_value) {
                    return Ok(initial_value.to_owned());
                }
                let initial_value_ = GenericFieldElement::from_repr(
                    T::get_public(initial_value).expect("Already checked it is public"),
                );
                if initial_value_.num_bits() <= input.num_bits() {
                    Ok(initial_value.to_owned())
                } else {
                    let value_num_bits = initial_value_.num_bits();
                    let value = initial_value_.to_string();

                    Err(eyre::eyre!(
                        "InvalidInputBitSize: {}, {}",
                        value,
                        value_num_bits
                    ))?
                }
            }
            ConstantOrWitnessEnum::Constant(value) => Ok(T::AcvmType::from(value.into_repr())),
        }
    }

    pub(crate) fn solve_range_opcode(
        initial_witness: &WitnessMap<T::AcvmType>,
        input: &FunctionInput<GenericFieldElement<F>>,
    ) -> CoAcvmResult<()> {
        // TODO(https://github.com/noir-lang/noir/issues/5985):
        // re-enable bitsize checks
        let skip_bitsize_checks = true;
        let w_value = Self::input_to_value(initial_witness, *input, skip_bitsize_checks)?;
        // Can only check if the value is public
        if let Some(w_value) = T::get_public(&w_value) {
            let w_value = GenericFieldElement::from_repr(w_value);
            if w_value.num_bits() > input.num_bits() {
                return Err(eyre::eyre!("UnsatisfiedConstraint"))?;
            }
        }
        Ok(())
    }

    pub(super) fn solve_blackbox(
        &mut self,
        bb_func: &BlackBoxFuncCall<GenericFieldElement<F>>,
    ) -> CoAcvmResult<()> {
        tracing::trace!("solving blackbox");

        let initial_witness = &mut self.witness_map[self.function_index];

        let inputs = bb_func.get_inputs_vec();

        if !Self::contains_all_inputs(initial_witness, &inputs) {
            let unassigned_witness = Self::first_missing_assignment(initial_witness, &inputs)
                .expect("Some assignments must be missing because it does not contains all inputs");
            Err(eyre::eyre!(
                "missing assignment for witness: {}",
                unassigned_witness.0
            ))?;
        }

        match bb_func {
            BlackBoxFuncCall::RANGE { input } => Self::solve_range_opcode(initial_witness, input)?,
            _ => todo!("solve blackbox funciton {} not supported", bb_func.name()),
        }

        Ok(())
    }
}
