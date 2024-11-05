use crate::protocols::rep3::{
    arithmetic::FieldShare,
    id::PartyID,
    network::{IoContext, Rep3Network},
    yao::{
        self, circuits::GarbledCircuits, evaluator::Rep3Evaluator, garbler::Rep3Garbler, GCUtils,
    },
    IoResult, Rep3PrimeFieldShare,
};
use ark_ff::PrimeField;
use itertools::izip;

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

    let delta = io_context.rngs.generate_random_garbler_delta(io_context.id);

    let [x01, x2] = yao::joint_input_arithmetic_added_many(inputs, delta, io_context)?;

    let mut res = vec![Rep3PrimeFieldShare::zero_share(); num_inputs];

    match io_context.id {
        PartyID::ID0 => {
            for res in res.iter_mut() {
                let k3 = io_context.rngs.bitcomp2.random_fes_3keys::<F>();
                res.b = (k3.0 + k3.1 + k3.2).neg();
            }

            // TODO this can be parallelized with joint_input_arithmetic_added_many
            let x23 = yao::input_field_id2_many::<F, _>(None, None, num_inputs, io_context)?;

            let mut evaluator = Rep3Evaluator::new(io_context);
            evaluator.receive_circuit()?;

            let x1 = GarbledCircuits::batcher_odd_even_merge_sort::<_, F>(
                &mut evaluator,
                &x01,
                &x2,
                &x23,
                bitsize,
            );
            let x1 = GCUtils::garbled_circuits_error(x1)?;
            let x1 = evaluator.output_to_id0_and_id1(x1.wires())?;

            // Compose the bits
            for (res, x1) in izip!(res.iter_mut(), x1.chunks(F::MODULUS_BIT_SIZE as usize)) {
                res.a = GCUtils::bits_to_field(x1)?;
            }
        }
        PartyID::ID1 => {
            for res in res.iter_mut() {
                let k2 = io_context.rngs.bitcomp1.random_fes_3keys::<F>();
                res.a = (k2.0 + k2.1 + k2.2).neg();
            }

            // TODO this can be parallelized with joint_input_arithmetic_added_many
            let x23 = yao::input_field_id2_many::<F, _>(None, None, num_inputs, io_context)?;

            let mut garbler =
                Rep3Garbler::new_with_delta(io_context, delta.expect("Delta not provided"));

            let x1 = GarbledCircuits::batcher_odd_even_merge_sort::<_, F>(
                &mut garbler,
                &x01,
                &x2,
                &x23,
                bitsize,
            );
            let x1 = GCUtils::garbled_circuits_error(x1)?;
            let x1 = garbler.output_to_id0_and_id1(x1.wires())?;
            let x1 = match x1 {
                Some(x1) => x1,
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "No output received",
                ))?,
            };

            // Compose the bits
            for (res, x1) in izip!(res.iter_mut(), x1.chunks(F::MODULUS_BIT_SIZE as usize)) {
                res.b = GCUtils::bits_to_field(x1)?;
            }
        }
        PartyID::ID2 => {
            let mut x23 = Vec::with_capacity(num_inputs);
            for res in res.iter_mut() {
                let k2 = io_context.rngs.bitcomp1.random_fes_3keys::<F>();
                let k3 = io_context.rngs.bitcomp2.random_fes_3keys::<F>();
                let k2_comp = k2.0 + k2.1 + k2.2;
                let k3_comp = k3.0 + k3.1 + k3.2;
                x23.push(k2_comp + k3_comp);
                res.a = k3_comp.neg();
                res.b = k2_comp.neg();
            }

            // TODO this can be parallelized with joint_input_arithmetic_added_many
            let x23 = yao::input_field_id2_many(Some(x23), delta, num_inputs, io_context)?;

            let mut garbler =
                Rep3Garbler::new_with_delta(io_context, delta.expect("Delta not provided"));

            let x1 = GarbledCircuits::batcher_odd_even_merge_sort::<_, F>(
                &mut garbler,
                &x01,
                &x2,
                &x23,
                bitsize,
            );
            let x1 = GCUtils::garbled_circuits_error(x1)?;
            let x1 = garbler.output_to_id0_and_id1(x1.wires())?;
            if x1.is_some() {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Unexpected output received",
                ))?;
            }
        }
    }

    Ok(res)
}
