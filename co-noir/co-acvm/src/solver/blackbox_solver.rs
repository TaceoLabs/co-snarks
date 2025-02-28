use crate::mpc::NoirWitnessExtensionProtocol;

use super::{CoAcvmResult, CoSolver};
use acir::{
    acir_field::GenericFieldElement,
    circuit::opcodes::{BlackBoxFuncCall, ConstantOrWitnessEnum, FunctionInput},
    native_types::{Witness, WitnessMap},
    AcirField,
};
use ark_ff::PrimeField;
use mpc_core::gadgets::poseidon2::Poseidon2;

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
            if let ConstantOrWitnessEnum::Witness(ref witness) = input.input() {
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
    pub(crate) fn witness_to_value(
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
    pub(crate) fn input_to_value(
        initial_witness: &WitnessMap<T::AcvmType>,
        input: FunctionInput<GenericFieldElement<F>>,
        skip_bitsize_checks: bool,
    ) -> CoAcvmResult<T::AcvmType> {
        match input.input() {
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

    /// Inserts `value` into the initial witness map under the index `witness`.
    ///
    /// Returns an error if there was already a value in the map
    /// which does not match the value that one is about to insert
    pub fn insert_value(
        witness: &Witness,
        value_to_insert: T::AcvmType,
        initial_witness: &mut WitnessMap<T::AcvmType>,
    ) -> CoAcvmResult<()> {
        let optional_old_value = initial_witness.insert(*witness, value_to_insert.to_owned());

        let old_value = match optional_old_value {
            Some(old_value) => old_value,
            None => return Ok(()),
        };

        match (T::get_public(&old_value), T::get_public(&value_to_insert)) {
            (Some(old_value), Some(value_to_insert)) => {
                if old_value != value_to_insert {
                    Err(eyre::eyre!("UnsatisfiedConstraint"))?;
                }
            }
            _ => { // We cannot have this sanitiy check
            }
        }

        Ok(())
    }

    pub(crate) fn solve_range_opcode(
        initial_witness: &WitnessMap<T::AcvmType>,
        input: &FunctionInput<GenericFieldElement<F>>,
        pedantic_solving: bool,
    ) -> CoAcvmResult<()> {
        // TODO(https://github.com/noir-lang/noir/issues/5985):
        // re-enable bitsize checks
        let skip_bitsize_checks = !pedantic_solving;
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

    fn and(
        driver: &mut T,
        initial_witness: &mut WitnessMap<T::AcvmType>,
        lhs: &FunctionInput<GenericFieldElement<F>>,
        rhs: &FunctionInput<GenericFieldElement<F>>,
        output: &Witness,
        pedantic_solving: bool,
    ) -> CoAcvmResult<()> {
        assert_eq!(
            lhs.num_bits(),
            rhs.num_bits(),
            "number of bits specified for each input must be the same"
        );
        Self::solve_logic_opcode(
            driver,
            initial_witness,
            lhs,
            rhs,
            *output,
            pedantic_solving,
            |driver, left, right| T::integer_bitwise_and(driver, left, right, lhs.num_bits()),
        )
    }

    fn xor(
        driver: &mut T,
        initial_witness: &mut WitnessMap<T::AcvmType>,
        lhs: &FunctionInput<GenericFieldElement<F>>,
        rhs: &FunctionInput<GenericFieldElement<F>>,
        output: &Witness,
        pedantic_solving: bool,
    ) -> CoAcvmResult<()> {
        assert_eq!(
            lhs.num_bits(),
            rhs.num_bits(),
            "number of bits specified for each input must be the same"
        );
        Self::solve_logic_opcode(
            driver,
            initial_witness,
            lhs,
            rhs,
            *output,
            pedantic_solving,
            |driver, left, right| T::integer_bitwise_xor(driver, left, right, lhs.num_bits()),
        )
    }

    /// Derives the rest of the witness based on the initial low level variables
    fn solve_logic_opcode(
        driver: &mut T,
        initial_witness: &mut WitnessMap<T::AcvmType>,
        a: &FunctionInput<GenericFieldElement<F>>,
        b: &FunctionInput<GenericFieldElement<F>>,
        result: Witness,
        pedantic_solving: bool,
        logic_op: impl Fn(&mut T, T::AcvmType, T::AcvmType) -> std::io::Result<T::AcvmType>,
    ) -> CoAcvmResult<()> {
        // TODO(https://github.com/noir-lang/noir/issues/5985): re-enable these by
        // default once we figure out how to combine these with existing
        // noirc_frontend/noirc_evaluator overflow error messages
        let skip_bitsize_checks = !pedantic_solving;
        let w_l_value = Self::input_to_value(initial_witness, *a, skip_bitsize_checks)?;
        let w_r_value = Self::input_to_value(initial_witness, *b, skip_bitsize_checks)?;
        let assignment = logic_op(driver, w_l_value, w_r_value)?;

        Self::insert_value(&result, assignment, initial_witness)
    }

    fn solve_poseidon2_permutation_opcode(
        driver: &mut T,
        initial_witness: &mut WitnessMap<T::AcvmType>,
        inputs: &[FunctionInput<GenericFieldElement<F>>],
        outputs: &[Witness],
        len: u32,
    ) -> CoAcvmResult<()> {
        if len as usize != inputs.len() {
            Err(eyre::eyre!(
                "the number of inputs does not match specified length. {} != {}",
                inputs.len(),
                len
            ))?;
        }
        if len as usize != outputs.len() {
            Err(eyre::eyre!(
                "the number of outputs does not match specified length. {} != {}",
                outputs.len(),
                len
            ))?;
        }

        // Read witness assignments
        let mut state = Vec::with_capacity(inputs.len());
        for input in inputs.iter() {
            let witness_assignment = Self::input_to_value(initial_witness, *input, false)?;
            state.push(witness_assignment);
        }

        const STATE_T: usize = 4;
        const D: u64 = 5;
        let poseidon2 = Poseidon2::<F, STATE_T, D>::default();
        let state = driver.poseidon2_permutation(state, &poseidon2)?;

        // Write witness assignments
        for (output_witness, value) in outputs.iter().zip(state.into_iter()) {
            Self::insert_value(output_witness, value, initial_witness)?;
        }
        Ok(())
    }

    pub(super) fn multi_scalar_mul(
        driver: &mut T,
        initial_witness: &mut WitnessMap<T::AcvmType>,
        points: &[FunctionInput<GenericFieldElement<F>>],
        scalars: &[FunctionInput<GenericFieldElement<F>>],
        outputs: &(Witness, Witness, Witness),
        pedantic_solving: bool,
    ) -> CoAcvmResult<()> {
        let points: Result<Vec<_>, _> = points
            .iter()
            .map(|input| Self::input_to_value(initial_witness, *input, false))
            .collect();
        let points: Vec<_> = points?.into_iter().collect();

        let scalars: Result<Vec<_>, _> = scalars
            .iter()
            .map(|input| Self::input_to_value(initial_witness, *input, false))
            .collect();
        let scalars = scalars?;
        let mut scalars_lo = Vec::with_capacity(scalars.len().div_ceil(2));
        let mut scalars_hi = Vec::with_capacity(scalars.len() / 2);
        for (i, scalar) in scalars.into_iter().enumerate() {
            if i % 2 == 0 {
                scalars_lo.push(scalar);
            } else {
                scalars_hi.push(scalar);
            }
        }
        // Call the backend's multi-scalar multiplication function
        let (res_x, res_y, is_infinity) =
            driver.multi_scalar_mul(&points, &scalars_lo, &scalars_hi, pedantic_solving)?;

        // Insert the resulting point into the witness map
        Self::insert_value(&outputs.0, res_x, initial_witness)?;
        Self::insert_value(&outputs.1, res_y, initial_witness)?;
        Self::insert_value(&outputs.2, is_infinity, initial_witness)?;
        Ok(())
    }

    pub(super) fn solve_blackbox(
        &mut self,
        bb_func: &BlackBoxFuncCall<GenericFieldElement<F>>,
    ) -> CoAcvmResult<()> {
        tracing::trace!("solving blackbox");

        let pedantic_solving = self.pedantic_solving();
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
            BlackBoxFuncCall::RANGE { input } => {
                Self::solve_range_opcode(initial_witness, input, pedantic_solving)?
            }
            BlackBoxFuncCall::AND { lhs, rhs, output } => Self::and(
                &mut self.driver,
                initial_witness,
                lhs,
                rhs,
                output,
                pedantic_solving,
            )?,
            BlackBoxFuncCall::XOR { lhs, rhs, output } => Self::xor(
                &mut self.driver,
                initial_witness,
                lhs,
                rhs,
                output,
                pedantic_solving,
            )?,
            BlackBoxFuncCall::Poseidon2Permutation {
                inputs,
                outputs,
                len,
            } => Self::solve_poseidon2_permutation_opcode(
                &mut self.driver,
                initial_witness,
                inputs,
                outputs,
                *len,
            )?,
            BlackBoxFuncCall::MultiScalarMul {
                points,
                scalars,
                outputs,
            } => Self::multi_scalar_mul(
                &mut self.driver,
                initial_witness,
                points,
                scalars,
                outputs,
                pedantic_solving,
            )?,
            _ => todo!("solve blackbox function {} not supported", bb_func.name()),
        }

        Ok(())
    }
}
