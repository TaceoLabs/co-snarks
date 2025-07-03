use ark_ff::PrimeField;
use brillig::{HeapValueType, ValueOrArray};

use crate::{CoBrilligVM, mpc::BrilligDriver};

impl<T, F> CoBrilligVM<T, F>
where
    T: BrilligDriver<F>,
    F: PrimeField,
{
    pub(super) fn taceo_store(
        &mut self,
        destinations: &[ValueOrArray],
        destination_value_types: &[HeapValueType],
        inputs: &[ValueOrArray],
        input_value_type: &[HeapValueType],
    ) -> eyre::Result<()> {
        if self.shared_ctx.is_some() {
            eyre::bail!("Cannot store private shared state when in shared if");
        }

        if !destination_value_types.is_empty() || !destinations.is_empty() {
            eyre::bail!("Invalid signature for TACEO store. Do not expect return types")
        }
        if inputs.len() != 2 || input_value_type.len() != 2 {
            eyre::bail!(
                "Invalid signature for TACEO store. We expect two inputs, a name and the data"
            );
        }
        let identifer = if let ValueOrArray::HeapArray(heap_array) = inputs[0].to_owned() {
            let mem = self.memory.read_heap_array(heap_array)?;
            mem.into_iter()
                .map(|c| T::try_into_char(c))
                .collect::<eyre::Result<String>>()?
        } else {
            eyre::bail!(
                "Invalid signature for TACEO store. First parameter must be a string identifier."
            );
        };

        let serialized = if let ValueOrArray::HeapArray(heap_array) = inputs[1].to_owned() {
            self.memory.read_heap_array(heap_array)?
        } else {
            eyre::bail!(
                "Invalid signature for TACEO store. Second paramter must be array of field elements."
            );
        };
        if self
            .persistent_shared_state
            .insert(identifer.clone(), serialized)
            .is_some()
        {
            eyre::bail!("duplicate entry for shared state id: {identifer}");
        }

        Ok(())
    }
}
