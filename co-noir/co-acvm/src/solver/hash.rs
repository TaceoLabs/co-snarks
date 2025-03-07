use super::{CoAcvmResult, CoSolver};
use crate::solver::NoirWitnessExtensionProtocol;
use acir::{
    acir_field::GenericFieldElement,
    circuit::opcodes::FunctionInput,
    native_types::{Witness, WitnessMap},
};
use ark_ff::PrimeField;
use mpc_core::gadgets::poseidon2::Poseidon2;

impl<T, F> CoSolver<T, F>
where
    T: NoirWitnessExtensionProtocol<F>,
    F: PrimeField,
{
    /// Attempts to solve a 256 bit hash function opcode.
    /// If successful, `initial_witness` will be mutated to contain the new witness assignment.
    pub(super) fn solve_generic_256_hash_opcode(
        driver: &mut T,
        initial_witness: &mut WitnessMap<T::AcvmType>,
        inputs: &[FunctionInput<GenericFieldElement<F>>],
        var_message_size: Option<&FunctionInput<GenericFieldElement<F>>>,
        outputs: &[Witness; 32],
        hash_function: fn(data: &[T::AcvmType]) -> CoAcvmResult<[T::AcvmType; 32]>,
    ) -> CoAcvmResult<()> {
        let message_input =
            Self::get_hash_input(driver, initial_witness, inputs, var_message_size)?;
        let digest: [T::AcvmType; 32] = hash_function(&message_input)?;

        Self::write_digest_to_outputs(initial_witness, outputs, digest)
    }

    /// Reads the hash function input from a [`WitnessMap`].
    fn get_hash_input(
        driver: &mut T,
        initial_witness: &WitnessMap<T::AcvmType>,
        inputs: &[FunctionInput<GenericFieldElement<F>>],
        message_size: Option<&FunctionInput<GenericFieldElement<F>>>,
    ) -> CoAcvmResult<Vec<T::AcvmType>> {
        // Read witness assignments.
        let mut message_input = Vec::new();
        for input in inputs.iter() {
            let num_bits = input.num_bits() as usize;

            let witness_assignment = Self::input_to_value(initial_witness, *input, false)?;
            let bytes = T::fetch_nearest_bytes(driver, witness_assignment, num_bits);

            message_input.extend(bytes);
        }

        // Truncate the message if there is a `message_size` parameter given
        match message_size {
            Some(input) => {
                let _num_bytes_to_take = Self::input_to_value(initial_witness, *input, false)?;
                // TODO FLORIN input_to_value(initial_witness, *input, false)?.to_u128() as usize;

                // If the number of bytes to take is more than the amount of bytes available
                // in the message, then we error.
                // if num_bytes_to_take > message_input.len() {
                //     Err(eyre::eyre!("the number of bytes to take from the message is more than the number of bytes in the message. {} > {}", num_bytes_to_take, message_input.len()))?;
                // }
                let truncated_message = message_input; // TODO FLORIN [0..num_bytes_to_take].to_vec();
                Ok(truncated_message)
            }
            None => Ok(message_input),
        }
    }

    /// Writes a `digest` to the [`WitnessMap`] at witness indices `outputs`.
    fn write_digest_to_outputs(
        initial_witness: &mut WitnessMap<T::AcvmType>,
        outputs: &[Witness; 32],
        digest: [T::AcvmType; 32],
    ) -> CoAcvmResult<()> {
        for (output_witness, value) in outputs.iter().zip(digest.into_iter()) {
            Self::insert_value(
                output_witness,
                value, //F::from_be_bytes_reduce(&[value])
                initial_witness,
            )?;
        }

        Ok(())
    }

    pub(crate) fn solve_poseidon2_permutation_opcode(
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
}

// // Does a generic hash of the inputs returning the resulting 32 bytes separately.
// fn generic_hash_256<D: Digest>(message: &[u8]) -> Result<[u8; 32], String> {
//     let output_bytes: [u8; 32] = D::digest(message)
//         .as_slice()
//         .try_into()
//         .map_err(|_| "digest should be 256 bits")?;
//     Ok(output_bytes)
// }
// pub fn blake2s(_inputs: &[u8]) -> CoAcvmResult<[u8; 32]> {
//     // generic_hash_256::<Blake2s256>(inputs)
//     //     .map_err(|err| BlackBoxResolutionError::Failed(BlackBoxFunc::Blake2s, err))
//     todo!()
// }
