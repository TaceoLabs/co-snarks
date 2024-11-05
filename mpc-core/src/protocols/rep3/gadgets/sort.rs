use crate::protocols::rep3::{
    arithmetic::FieldShare,
    network::{IoContext, Rep3Network},
    yao::{self, circuits::GarbledCircuits},
    IoResult,
};
use ark_ff::PrimeField;

pub fn batcher_odd_even_merge_sort_yao<F: PrimeField, N: Rep3Network>(
    inputs: &[FieldShare<F>],
    io_context: &mut IoContext<N>,
    bitsize: usize,
) -> IoResult<Vec<FieldShare<F>>> {
    if bitsize > F::MODULUS_BIT_SIZE as usize {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Bit size is larger than field size",
        ))?;
    }
    let num_inputs = inputs.len();

    yao::decompose_circuit_compose_blueprint!(
        inputs,
        io_context,
        num_inputs,
        GarbledCircuits::batcher_odd_even_merge_sort::<_, F>,
        (bitsize)
    )
}
