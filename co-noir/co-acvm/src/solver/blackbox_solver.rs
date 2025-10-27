use super::{CoAcvmResult, CoSolver};
use crate::mpc::NoirWitnessExtensionProtocol;
use acir::{
    AcirField,
    acir_field::GenericFieldElement,
    circuit::opcodes::{BlackBoxFuncCall, FunctionInput},
    native_types::{Witness, WitnessMap},
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
            if let FunctionInput::Witness(witness) = input {
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
    ) -> CoAcvmResult<T::AcvmType> {
        match input {
            FunctionInput::Witness(witness) => {
                let initial_value = Self::witness_to_value(initial_witness, witness)?;
                Ok(initial_value.to_owned())
            }
            FunctionInput::Constant(value) => Ok(T::AcvmType::from(value.into_repr())),
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
        num_bits: u32,
    ) -> CoAcvmResult<()> {
        let w_value = Self::input_to_value(initial_witness, *input)?;
        // Can only check if the value is public
        if let Some(w_value) = T::get_public(&w_value) {
            let w_value = GenericFieldElement::from_repr(w_value);
            if w_value.num_bits() > num_bits {
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
        num_bits: u32,
        output: &Witness,
        pedantic_solving: bool,
    ) -> CoAcvmResult<()> {
        Self::solve_logic_opcode(
            driver,
            initial_witness,
            lhs,
            rhs,
            num_bits,
            *output,
            pedantic_solving,
            |driver, left, right| T::integer_bitwise_and(driver, left, right, num_bits),
        )
    }

    fn xor(
        driver: &mut T,
        initial_witness: &mut WitnessMap<T::AcvmType>,
        lhs: &FunctionInput<GenericFieldElement<F>>,
        rhs: &FunctionInput<GenericFieldElement<F>>,
        num_bits: u32,
        output: &Witness,
        pedantic_solving: bool,
    ) -> CoAcvmResult<()> {
        Self::solve_logic_opcode(
            driver,
            initial_witness,
            lhs,
            rhs,
            num_bits,
            *output,
            pedantic_solving,
            |driver, left, right| T::integer_bitwise_xor(driver, left, right, num_bits),
        )
    }

    /// Derives the rest of the witness based on the initial low level variables
    #[expect(clippy::too_many_arguments)]
    fn solve_logic_opcode(
        driver: &mut T,
        initial_witness: &mut WitnessMap<T::AcvmType>,
        a: &FunctionInput<GenericFieldElement<F>>,
        b: &FunctionInput<GenericFieldElement<F>>,
        num_bits: u32,
        result: Witness,
        pedantic_solving: bool,
        logic_op: impl Fn(&mut T, T::AcvmType, T::AcvmType) -> eyre::Result<T::AcvmType>,
    ) -> CoAcvmResult<()> {
        // TODO(https://github.com/noir-lang/noir/issues/5985): re-enable these by
        // default once we figure out how to combine these with existing
        // noirc_frontend/noirc_evaluator overflow error messages

        let w_l_value = Self::input_to_value(initial_witness, *a)?;
        let w_r_value = Self::input_to_value(initial_witness, *b)?;
        if pedantic_solving {
            //we only check bit size for public values
            if let Some(public_value) = T::get_public(&w_l_value) {
                Self::check_bit_size(public_value, num_bits)?;
            }
            if let Some(public_value) = T::get_public(&w_r_value) {
                Self::check_bit_size(public_value, num_bits)?;
            }
        }
        let assignment = logic_op(driver, w_l_value, w_r_value)?;

        Self::insert_value(&result, assignment, initial_witness)
    }

    fn check_bit_size(value: F, num_bits: u32) -> CoAcvmResult<()> {
        let public_value = GenericFieldElement::from_repr(value);
        if public_value.num_bits() > num_bits {
            return Err(eyre::eyre!(
                "InvalidInputBitSize: expected at most {} bits, got {}",
                num_bits,
                public_value.num_bits()
            ))?;
        }
        Ok(())
    }

    fn solve_poseidon2_permutation_opcode(
        driver: &mut T,
        initial_witness: &mut WitnessMap<T::AcvmType>,
        inputs: &[FunctionInput<GenericFieldElement<F>>],
        outputs: &[Witness],
    ) -> CoAcvmResult<()> {
        if inputs.len() != outputs.len() {
            Err(eyre::eyre!(
                "the input and output sizes are not consistent. {} != {}",
                inputs.len(),
                outputs.len()
            ))?;
        }

        // Read witness assignments
        let mut state = Vec::with_capacity(inputs.len());
        for input in inputs.iter() {
            let witness_assignment = Self::input_to_value(initial_witness, *input)?;
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
    fn solve_blake3_opcode(
        driver: &mut T,
        initial_witness: &mut WitnessMap<T::AcvmType>,
        inputs: &[FunctionInput<GenericFieldElement<F>>],
        outputs: &[Witness; 32],
    ) -> CoAcvmResult<()> {
        let message_input = Self::get_hash_input(initial_witness, inputs)?;
        let digest = T::blake3_hash(driver, message_input, 8)?; // This is now hardcoded to 8 in Noir

        for (output_witness, value) in outputs.iter().zip(digest.into_iter()) {
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
            .map(|input| Self::input_to_value(initial_witness, *input))
            .collect();
        let points: Vec<_> = points?.into_iter().collect();

        let scalars: Result<Vec<_>, _> = scalars
            .iter()
            .map(|input| Self::input_to_value(initial_witness, *input))
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

    pub(super) fn embedded_curve_add(
        driver: &mut T,
        initial_witness: &mut WitnessMap<T::AcvmType>,
        input1: &[FunctionInput<GenericFieldElement<F>>; 3],
        input2: &[FunctionInput<GenericFieldElement<F>>; 3],
        outputs: &(Witness, Witness, Witness),
    ) -> CoAcvmResult<()> {
        let input1_x = Self::input_to_value(initial_witness, input1[0])?;
        let input1_y = Self::input_to_value(initial_witness, input1[1])?;
        let input1_infinite = Self::input_to_value(initial_witness, input1[2])?;
        let input2_x = Self::input_to_value(initial_witness, input2[0])?;
        let input2_y = Self::input_to_value(initial_witness, input2[1])?;
        let input2_infinite = Self::input_to_value(initial_witness, input2[2])?;
        let (res_x, res_y, res_infinite) = driver.embedded_curve_add(
            input1_x,
            input1_y,
            input1_infinite,
            input2_x,
            input2_y,
            input2_infinite,
        )?;

        Self::insert_value(&outputs.0, res_x, initial_witness)?;
        Self::insert_value(&outputs.1, res_y, initial_witness)?;
        Self::insert_value(&outputs.2, res_infinite, initial_witness)?;
        Ok(())
    }

    pub(crate) fn solve_sha_256_permutation_opcode(
        driver: &mut T,
        initial_witness: &mut WitnessMap<T::AcvmType>,
        inputs: &[FunctionInput<GenericFieldElement<F>>; 16],
        hash_values: &[FunctionInput<GenericFieldElement<F>>; 8],
        outputs: &[Witness; 8],
    ) -> CoAcvmResult<()> {
        let mut message = core::array::from_fn(|_| T::AcvmType::default());
        for (i, inp) in inputs.iter().enumerate() {
            let witness_value = Self::input_to_value(initial_witness, *inp)?;
            message[i] = witness_value;
        }
        let mut state = core::array::from_fn(|_| T::AcvmType::default());
        for (i, inp) in hash_values.iter().enumerate() {
            let witness_value = Self::input_to_value(initial_witness, *inp)?;
            state[i] = witness_value;
        }

        let state = T::sha256_compression(driver, &state, &message)?;

        for (output_witness, value) in outputs.iter().zip(state.into_iter()) {
            Self::insert_value(output_witness, value, initial_witness)?;
        }

        Ok(())
    }

    fn solve_blake2s_opcode(
        driver: &mut T,
        initial_witness: &mut WitnessMap<T::AcvmType>,
        inputs: &[FunctionInput<GenericFieldElement<F>>],
        outputs: &[Witness; 32],
    ) -> CoAcvmResult<()> {
        let message_input = Self::get_hash_input(initial_witness, inputs)?;
        let digest = T::blake2s_hash(driver, message_input, 8)?; // This is now hardcoded to 8 in Noir

        for (output_witness, value) in outputs.iter().zip(digest.into_iter()) {
            Self::insert_value(output_witness, value, initial_witness)?;
        }

        Ok(())
    }

    /// Reads the hash function input from a [`WitnessMap`].
    fn get_hash_input(
        initial_witness: &WitnessMap<T::AcvmType>,
        inputs: &[FunctionInput<GenericFieldElement<F>>],
        // message_size: Option<&FunctionInput<GenericFieldElement<F>>>,
    ) -> CoAcvmResult<Vec<T::AcvmType>> {
        // Read witness assignments.
        let mut message_input = Vec::new();
        for input in inputs.iter() {
            let witness_assignment = Self::input_to_value(initial_witness, *input)?;
            message_input.push(witness_assignment);
            // Note: in Noir fetch_nearest_bytes gets called on witness_assignment, but we postpone this and do this in the computation of the hash
        }
        Ok(message_input)
    }

    pub(super) fn solve_aes128_encryption_opcode(
        driver: &mut T,
        initial_witness: &mut WitnessMap<T::AcvmType>,
        inputs: &[FunctionInput<GenericFieldElement<F>>],
        iv: &[FunctionInput<GenericFieldElement<F>>; 16],
        key: &[FunctionInput<GenericFieldElement<F>>; 16],
        outputs: &[Witness],
    ) -> CoAcvmResult<()> {
        let mut scalars = Vec::with_capacity(inputs.len());
        for inp in inputs {
            let witness_value = Self::input_to_value(initial_witness, *inp)?;
            scalars.push(witness_value);
        }
        let mut ivs = Vec::with_capacity(iv.len());
        for inp in iv {
            let witness_value = Self::input_to_value(initial_witness, *inp)?;
            ivs.push(witness_value);
        }
        let mut keys = Vec::with_capacity(key.len());
        for inp in key {
            let witness_value = Self::input_to_value(initial_witness, *inp)?;
            keys.push(witness_value);
        }
        let ciphertext = T::aes128_encrypt(driver, &scalars, ivs, keys)?;

        // Write witness assignments
        for (output_witness, value) in outputs.iter().zip(ciphertext.into_iter()) {
            Self::insert_value(output_witness, value, initial_witness)?;
        }
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
                .expect("Some assignments must be missing because it does not contain all inputs");
            Err(eyre::eyre!(
                "missing assignment for witness: {}",
                unassigned_witness.0
            ))?;
        }

        match bb_func {
            BlackBoxFuncCall::RANGE { input, num_bits } => {
                Self::solve_range_opcode(initial_witness, input, *num_bits)?
            }
            BlackBoxFuncCall::AND {
                lhs,
                rhs,
                num_bits,
                output,
            } => Self::and(
                &mut self.driver,
                initial_witness,
                lhs,
                rhs,
                *num_bits,
                output,
                pedantic_solving,
            )?,
            BlackBoxFuncCall::XOR {
                lhs,
                rhs,
                num_bits,
                output,
            } => Self::xor(
                &mut self.driver,
                initial_witness,
                lhs,
                rhs,
                *num_bits,
                output,
                pedantic_solving,
            )?,
            BlackBoxFuncCall::Poseidon2Permutation { inputs, outputs } => {
                Self::solve_poseidon2_permutation_opcode(
                    &mut self.driver,
                    initial_witness,
                    inputs,
                    outputs,
                )?
            }
            BlackBoxFuncCall::MultiScalarMul {
                points,
                scalars,
                outputs,
                ..
            } => Self::multi_scalar_mul(
                &mut self.driver,
                initial_witness,
                points,
                scalars,
                outputs,
                pedantic_solving,
            )?,
            BlackBoxFuncCall::EmbeddedCurveAdd {
                input1,
                input2,
                outputs,
                ..
            } => {
                Self::embedded_curve_add(&mut self.driver, initial_witness, input1, input2, outputs)
            }?,
            BlackBoxFuncCall::Sha256Compression {
                inputs,
                hash_values,
                outputs,
            } => Self::solve_sha_256_permutation_opcode(
                &mut self.driver,
                initial_witness,
                inputs,
                hash_values,
                outputs,
            )?,
            BlackBoxFuncCall::Blake2s { inputs, outputs } => {
                Self::solve_blake2s_opcode(&mut self.driver, initial_witness, inputs, outputs)?
            }
            BlackBoxFuncCall::Blake3 { inputs, outputs } => {
                Self::solve_blake3_opcode(&mut self.driver, initial_witness, inputs, outputs)?
            }
            BlackBoxFuncCall::AES128Encrypt {
                inputs,
                iv,
                key,
                outputs,
            } => Self::solve_aes128_encryption_opcode(
                &mut self.driver,
                initial_witness,
                inputs,
                iv,
                key,
                outputs,
            )?,
            _ => todo!("solve blackbox function {} not supported", bb_func.name()),
        }

        Ok(())
    }

    pub(super) fn solve_r1cs_blackbox(
        &mut self,
        bb_func: &BlackBoxFuncCall<GenericFieldElement<F>>,
    ) -> CoAcvmResult<()> {
        tracing::trace!("solving blackbox");

        let initial_witness = &mut self.witness_map[self.function_index];

        let inputs = bb_func.get_inputs_vec();

        if !Self::contains_all_inputs(initial_witness, &inputs) {
            let unassigned_witness = Self::first_missing_assignment(initial_witness, &inputs)
                .expect("Some assignments must be missing because it does not contain all inputs");
            Err(eyre::eyre!(
                "missing assignment for witness: {}",
                unassigned_witness.0
            ))?;
        }

        match bb_func {
            BlackBoxFuncCall::RANGE { input, num_bits } => {
                Self::solve_range_opcode(initial_witness, input, *num_bits)?
            }
            _ => todo!("solve blackbox function {} not supported", bb_func.name()),
        }

        Ok(())
    }
}
