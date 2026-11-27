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

/// The y-coordinate of the generator (1, y) of the embedded curve (Grumpkin)
const GRUMPKIN_GENERATOR_Y: &str = "17631683881184975370165255887551781615748388533673675138860";

/// The predicate of an embedded curve operation
enum CurveOpPredicate<T> {
    /// The operation is executed
    Enabled,
    /// The operation is skipped and its result is (0, 0)
    Disabled,
    /// Whether the operation is enabled is secret shared
    Shared(T),
}

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
            (Some(old_value), Some(value_to_insert)) if old_value != value_to_insert => {
                Err(eyre::eyre!("UnsatisfiedConstraint"))?;
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
                return Err(eyre::eyre!("UnsatisfiedConstraint").into());
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
            )
            .into());
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
        for (output_witness, value) in outputs.iter().zip(state) {
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

        for (output_witness, value) in outputs.iter().zip(digest) {
            Self::insert_value(output_witness, value, initial_witness)?;
        }

        Ok(())
    }

    /// Derives whether points given by their (x, y) coordinates are the point at infinity, which
    /// is encoded as (0, 0). The backends still work with an explicit is_infinity flag internally,
    /// but acir no longer supplies one as an opcode input, so it is reconstructed here. Batches the
    /// equality and multiplication checks for all points into a single round each.
    fn point_is_infinity_many(
        driver: &mut T,
        xs: &[T::AcvmType],
        ys: &[T::AcvmType],
    ) -> CoAcvmResult<Vec<T::AcvmType>> {
        debug_assert_eq!(xs.len(), ys.len());
        let zero = T::public_zero();
        let coords: Vec<_> = xs.iter().chain(ys.iter()).cloned().collect();
        let zeros = vec![zero; coords.len()];
        let is_zero = driver.equal_many(&coords, &zeros)?;
        let (x_is_zero, y_is_zero) = is_zero.split_at(xs.len());
        Ok(driver.mul_many(x_is_zero, y_is_zero)?)
    }

    /// Reads the predicate of an embedded curve operation.
    ///
    /// As in the ACVM, a public predicate enables the operation iff it is one. A shared predicate is expected to be 0 or 1, which is enforced by the circuit.
    fn curve_op_predicate(
        initial_witness: &WitnessMap<T::AcvmType>,
        predicate: FunctionInput<GenericFieldElement<F>>,
    ) -> CoAcvmResult<CurveOpPredicate<T::AcvmType>> {
        let predicate = Self::input_to_value(initial_witness, predicate)?;
        Ok(match T::get_public(&predicate) {
            Some(public) if public.is_one() => CurveOpPredicate::Enabled,
            Some(_) => CurveOpPredicate::Disabled,
            None => CurveOpPredicate::Shared(predicate),
        })
    }

    /// Replaces the points by the generator of the embedded curve if the shared `predicate` is zero.
    ///
    /// A disabled operation must not depend on its inputs, which may be arbitrary values in this case, in particular points that are not on the curve. As the predicate is shared, we cannot skip the operation, so we execute it on valid points instead.
    #[expect(clippy::type_complexity)]
    fn points_or_generator(
        driver: &mut T,
        predicate: &T::AcvmType,
        xs: &[T::AcvmType],
        ys: &[T::AcvmType],
    ) -> CoAcvmResult<(Vec<T::AcvmType>, Vec<T::AcvmType>)> {
        debug_assert_eq!(xs.len(), ys.len());
        let generator_y = F::from_str(GRUMPKIN_GENERATOR_Y)
            .map_err(|_| eyre::eyre!("cannot parse the y-coordinate of the generator"))?;
        let coords: Vec<_> = xs.iter().chain(ys.iter()).cloned().collect();
        let mut generator = vec![T::AcvmType::from(F::one()); xs.len()];
        generator.resize(coords.len(), T::AcvmType::from(generator_y));
        let conds = vec![predicate.to_owned(); coords.len()];
        let mut xs = driver.cmux_many(&conds, &coords, &generator)?;
        let ys = xs.split_off(ys.len());
        Ok((xs, ys))
    }

    pub(super) fn multi_scalar_mul(
        driver: &mut T,
        initial_witness: &mut WitnessMap<T::AcvmType>,
        points: &[FunctionInput<GenericFieldElement<F>>],
        scalars: &[FunctionInput<GenericFieldElement<F>>],
        predicate: FunctionInput<GenericFieldElement<F>>,
        outputs: &(Witness, Witness),
        pedantic_solving: bool,
    ) -> CoAcvmResult<()> {
        let predicate = Self::curve_op_predicate(initial_witness, predicate)?;
        if matches!(predicate, CurveOpPredicate::Disabled) {
            // As the ACVM, we do not look at the inputs in this case
            Self::insert_value(&outputs.0, T::public_zero(), initial_witness)?;
            Self::insert_value(&outputs.1, T::public_zero(), initial_witness)?;
            return Ok(());
        }

        let points: Result<Vec<_>, _> = points
            .iter()
            .map(|input| Self::input_to_value(initial_witness, *input))
            .collect();
        let points: Vec<_> = points?;

        // acir encodes each point as an (x, y) pair with no explicit is_infinity input;
        // reconstruct the (x, y, is_infinity) triples the driver still expects.
        let num_points = points.len() / 2;
        let mut xs = Vec::with_capacity(num_points);
        let mut ys = Vec::with_capacity(num_points);
        for pair in points.chunks(2) {
            let [x, y] = pair else {
                return Err(eyre::eyre!("MultiScalarMul points must come in (x, y) pairs").into());
            };
            xs.push(x.to_owned());
            ys.push(y.to_owned());
        }
        if let CurveOpPredicate::Shared(predicate) = &predicate {
            (xs, ys) = Self::points_or_generator(driver, predicate, &xs, &ys)?;
        }
        let is_infinity = Self::point_is_infinity_many(driver, &xs, &ys)?;

        let mut points_with_infinity = Vec::with_capacity(num_points * 3);
        for ((x, y), is_infinity) in xs.into_iter().zip(ys).zip(is_infinity) {
            points_with_infinity.push(x);
            points_with_infinity.push(y);
            points_with_infinity.push(is_infinity);
        }

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
        let (res_x, res_y, _) = driver.multi_scalar_mul(
            &points_with_infinity,
            &scalars_lo,
            &scalars_hi,
            pedantic_solving,
        )?;

        let (res_x, res_y) = Self::apply_shared_predicate(driver, &predicate, res_x, res_y)?;

        // Insert the resulting point into the witness map. The backend already returns (0, 0)
        // for the point at infinity, so the is_infinity component can be dropped.
        Self::insert_value(&outputs.0, res_x, initial_witness)?;
        Self::insert_value(&outputs.1, res_y, initial_witness)?;
        Ok(())
    }

    /// Sets the result of an embedded curve operation to (0, 0) if its shared predicate is zero.
    fn apply_shared_predicate(
        driver: &mut T,
        predicate: &CurveOpPredicate<T::AcvmType>,
        res_x: T::AcvmType,
        res_y: T::AcvmType,
    ) -> CoAcvmResult<(T::AcvmType, T::AcvmType)> {
        let CurveOpPredicate::Shared(predicate) = predicate else {
            return Ok((res_x, res_y));
        };
        let mut res = driver.mul_many(
            &[res_x, res_y],
            &[predicate.to_owned(), predicate.to_owned()],
        )?;
        let res_y = res.pop().expect("has 2 elements");
        let res_x = res.pop().expect("has 2 elements");
        Ok((res_x, res_y))
    }

    pub(super) fn embedded_curve_add(
        driver: &mut T,
        initial_witness: &mut WitnessMap<T::AcvmType>,
        input1: &[FunctionInput<GenericFieldElement<F>>; 2],
        input2: &[FunctionInput<GenericFieldElement<F>>; 2],
        predicate: FunctionInput<GenericFieldElement<F>>,
        outputs: &(Witness, Witness),
    ) -> CoAcvmResult<()> {
        let predicate = Self::curve_op_predicate(initial_witness, predicate)?;
        if matches!(predicate, CurveOpPredicate::Disabled) {
            // As the ACVM, we do not look at the inputs in this case
            Self::insert_value(&outputs.0, T::public_zero(), initial_witness)?;
            Self::insert_value(&outputs.1, T::public_zero(), initial_witness)?;
            return Ok(());
        }

        let mut xs = vec![
            Self::input_to_value(initial_witness, input1[0])?,
            Self::input_to_value(initial_witness, input2[0])?,
        ];
        let mut ys = vec![
            Self::input_to_value(initial_witness, input1[1])?,
            Self::input_to_value(initial_witness, input2[1])?,
        ];
        if let CurveOpPredicate::Shared(predicate) = &predicate {
            (xs, ys) = Self::points_or_generator(driver, predicate, &xs, &ys)?;
        }
        let [input1_x, input2_x]: [T::AcvmType; 2] = xs.try_into().expect("has 2 elements");
        let [input1_y, input2_y]: [T::AcvmType; 2] = ys.try_into().expect("has 2 elements");

        let mut is_infinite = Self::point_is_infinity_many(
            driver,
            &[input1_x.clone(), input2_x.clone()],
            &[input1_y.clone(), input2_y.clone()],
        )?
        .into_iter();
        let input1_infinite = is_infinite.next().expect("has 2 elements");
        let input2_infinite = is_infinite.next().expect("has 2 elements");

        let (res_x, res_y, _) = driver.embedded_curve_add(
            input1_x,
            input1_y,
            input1_infinite,
            input2_x,
            input2_y,
            input2_infinite,
        )?;
        let (res_x, res_y) = Self::apply_shared_predicate(driver, &predicate, res_x, res_y)?;

        Self::insert_value(&outputs.0, res_x, initial_witness)?;
        Self::insert_value(&outputs.1, res_y, initial_witness)?;
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

        for (output_witness, value) in outputs.iter().zip(state) {
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

        for (output_witness, value) in outputs.iter().zip(digest) {
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
        for (output_witness, value) in outputs.iter().zip(ciphertext) {
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
                predicate,
                outputs,
            } => Self::multi_scalar_mul(
                &mut self.driver,
                initial_witness,
                points,
                scalars,
                *predicate,
                outputs,
                pedantic_solving,
            )?,
            BlackBoxFuncCall::EmbeddedCurveAdd {
                input1,
                input2,
                predicate,
                outputs,
            } => Self::embedded_curve_add(
                &mut self.driver,
                initial_witness,
                input1,
                input2,
                *predicate,
                outputs,
            )?,
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
            // Recursive aggregation will be entirely handled by the backend and is not solved by the ACVM
            BlackBoxFuncCall::RecursiveAggregation { .. } => (),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpc::rep3::{Rep3AcvmSolver, Rep3AcvmType};
    use ark_bn254::Fr;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{AdditiveGroup, One, Zero};
    use mpc_core::protocols::rep3::{self, conversion::A2BType};
    use mpc_net::local::LocalNetwork;
    use std::str::FromStr;

    type Solver<'a> = CoSolver<Rep3AcvmSolver<'a, Fr, LocalNetwork>, Fr>;

    #[derive(Clone, Copy)]
    enum Value {
        Public(Fr),
        Shared(Fr),
    }

    #[derive(Clone, Copy)]
    enum Op {
        /// Witnesses 1 to 4 are the coordinates of the two points
        Add,
        /// Witnesses 1 and 2 are the coordinates of the point, 3 and 4 the low and high limb of the scalar
        Msm,
    }

    /// Executes the operation with three parties, where the inputs are witnesses 1 to 4 and the predicate is witness 5, and returns the opened result.
    fn run(op: Op, inputs: [Value; 4], predicate: Value) -> (Fr, Fr) {
        let mut rng = rand::thread_rng();
        let mut witnesses = [vec![], vec![], vec![]];
        for value in inputs.into_iter().chain([predicate]) {
            let shares = match value {
                Value::Public(value) => std::array::from_fn(|_| Rep3AcvmType::Public(value)),
                Value::Shared(value) => {
                    rep3::share_field_element(value, &mut rng).map(Rep3AcvmType::Shared)
                }
            };
            for (witness, share) in witnesses.iter_mut().zip(shares) {
                witness.push(share);
            }
        }

        let threads = LocalNetwork::new_3_parties()
            .into_iter()
            .zip(witnesses)
            .map(|(net, witness)| {
                std::thread::spawn(move || {
                    let mut driver =
                        Rep3AcvmSolver::<Fr, _>::new(&net, A2BType::default()).unwrap();
                    let mut witness_map = WitnessMap::new();
                    for (i, value) in witness.into_iter().enumerate() {
                        witness_map.insert(Witness(i as u32 + 1), value);
                    }
                    let input = |i| FunctionInput::Witness(Witness(i));
                    let outputs = (Witness(6), Witness(7));
                    let result = match op {
                        Op::Add => Solver::embedded_curve_add(
                            &mut driver,
                            &mut witness_map,
                            &[input(1), input(2)],
                            &[input(3), input(4)],
                            input(5),
                            &outputs,
                        ),
                        Op::Msm => Solver::multi_scalar_mul(
                            &mut driver,
                            &mut witness_map,
                            &[input(1), input(2)],
                            &[input(3), input(4)],
                            input(5),
                            &outputs,
                            false,
                        ),
                    };
                    assert!(result.is_ok(), "the operation failed");
                    [
                        witness_map[&outputs.0].clone(),
                        witness_map[&outputs.1].clone(),
                    ]
                })
            })
            .collect::<Vec<_>>();
        let results = threads
            .into_iter()
            .map(|thread| thread.join().expect("a party panicked"))
            .collect::<Vec<_>>();

        let open = |i: usize| match (&results[0][i], &results[1][i], &results[2][i]) {
            (Rep3AcvmType::Public(a), Rep3AcvmType::Public(b), Rep3AcvmType::Public(c)) => {
                assert!(a == b && b == c);
                *a
            }
            (Rep3AcvmType::Shared(a), Rep3AcvmType::Shared(b), Rep3AcvmType::Shared(c)) => {
                rep3::combine_field_element(*a, *b, *c)
            }
            _ => panic!("the parties have different types"),
        };
        (open(0), open(1))
    }

    fn coords(point: ark_grumpkin::Projective) -> (Fr, Fr) {
        point.into_affine().xy().unwrap()
    }

    fn generator() -> ark_grumpkin::Projective {
        ark_grumpkin::Affine::generator().into_group()
    }

    #[test]
    fn generator_matches_grumpkin() {
        let (x, y) = coords(generator());
        assert_eq!(x, Fr::one());
        assert_eq!(y, Fr::from_str(GRUMPKIN_GENERATOR_Y).unwrap());
    }

    // (5, 7) is not on the curve. With a false predicate the inputs must not matter.
    fn off_curve() -> (Fr, Fr) {
        let (x, y) = (Fr::from(5u64), Fr::from(7u64));
        assert!(!ark_grumpkin::Affine::new_unchecked(x, y).is_on_curve());
        (x, y)
    }

    #[test]
    fn embedded_curve_add_with_predicate() {
        let (g_x, g_y) = coords(generator());
        let (g2_x, g2_y) = coords(generator().double());
        let valid = [g_x, g_y, g2_x, g2_y].map(Value::Shared);
        let expected = coords(generator() + generator().double());
        let (bad_x, bad_y) = off_curve();
        let invalid = [bad_x, bad_y, g2_x, g2_y].map(Value::Shared);
        let zero = (Fr::zero(), Fr::zero());

        // enabled
        assert_eq!(run(Op::Add, valid, Value::Public(Fr::one())), expected);
        assert_eq!(run(Op::Add, valid, Value::Shared(Fr::one())), expected);
        // disabled
        assert_eq!(run(Op::Add, valid, Value::Shared(Fr::zero())), zero);
        assert_eq!(run(Op::Add, invalid, Value::Shared(Fr::zero())), zero);
        assert_eq!(run(Op::Add, invalid, Value::Public(Fr::zero())), zero);
    }

    #[test]
    fn multi_scalar_mul_with_predicate() {
        let (g_x, g_y) = coords(generator());
        let scalar = Fr::from(5u64);
        let valid = [g_x, g_y, scalar, Fr::zero()].map(Value::Shared);
        let expected = coords(generator() * ark_grumpkin::Fr::from(5u64));
        let (bad_x, bad_y) = off_curve();
        let invalid = [bad_x, bad_y, scalar, Fr::zero()].map(Value::Shared);
        let zero = (Fr::zero(), Fr::zero());

        // enabled
        assert_eq!(run(Op::Msm, valid, Value::Public(Fr::one())), expected);
        assert_eq!(run(Op::Msm, valid, Value::Shared(Fr::one())), expected);
        // disabled
        assert_eq!(run(Op::Msm, valid, Value::Shared(Fr::zero())), zero);
        assert_eq!(run(Op::Msm, invalid, Value::Shared(Fr::zero())), zero);
        assert_eq!(run(Op::Msm, invalid, Value::Public(Fr::zero())), zero);
    }

    // The result is publicly known to be the point at infinity, which must not end up in a share
    #[test]
    fn multi_scalar_mul_with_public_zero() {
        let (g_x, g_y) = coords(generator());
        let enabled = Value::Public(Fr::one());
        let zero = (Fr::zero(), Fr::zero());

        // shared point, public scalar 0
        let inputs = [
            Value::Shared(g_x),
            Value::Shared(g_y),
            Value::Public(Fr::zero()),
            Value::Public(Fr::zero()),
        ];
        assert_eq!(run(Op::Msm, inputs, enabled), zero);

        // public point at infinity, shared scalar
        let inputs = [
            Value::Public(Fr::zero()),
            Value::Public(Fr::zero()),
            Value::Shared(Fr::from(5u64)),
            Value::Shared(Fr::zero()),
        ];
        assert_eq!(run(Op::Msm, inputs, enabled), zero);
    }
}
