use super::CoUltraCircuitBuilder;
use crate::types::Polynomials;
use crate::types::ProvingKey;
use ark_ec::pairing::Pairing;
use ark_ff::One;
use eyre::Result;
use mpc_core::traits::PrimeFieldMpcProtocol;
use std::marker::PhantomData;
use ultrahonk::prelude::ProverCrs;
use ultrahonk::prelude::ProvingKey as PlainProvingKey;

impl<T, P: Pairing> ProvingKey<T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    // We ignore the TraceStructure for now (it is None in barretenberg for UltraHonk)
    pub fn create(mut circuit: CoUltraCircuitBuilder<T, P>, crs: ProverCrs<P>) -> Self {
        tracing::info!("ProvingKey create");
        circuit.add_gates_to_ensure_all_polys_are_non_zero();
        circuit.finalize_circuit();

        let dyadic_circuit_size = circuit.compute_dyadic_size();
        let mut proving_key = Self::new(dyadic_circuit_size, circuit.public_inputs.len(), crs);
        // Construct and add to proving key the wire, selector and copy constraint polynomials
        proving_key.populate_trace(&mut circuit, false);

        // First and last lagrange polynomials (in the full circuit size)
        proving_key.polynomials.precomputed.lagrange_first_mut()[0] = P::ScalarField::one();
        proving_key.polynomials.precomputed.lagrange_last_mut()[dyadic_circuit_size - 1] =
            P::ScalarField::one();

        PlainProvingKey::construct_lookup_table_polynomials(
            proving_key
                .polynomials
                .precomputed
                .get_table_polynomials_mut(),
            &circuit,
            dyadic_circuit_size,
            0,
        );
        PlainProvingKey::construct_lookup_read_counts(
            proving_key
                .polynomials
                .witness
                .lookup_read_counts_and_tags_mut()
                .try_into()
                .unwrap(),
            &mut circuit,
            dyadic_circuit_size,
        );

        todo!("ProvingKey pubinput");
        // Construct the public inputs array
        // let public_wires_src = proving_key.polynomials.witness.w_r();

        // for input in public_wires_src
        //     .iter()
        //     .skip(proving_key.pub_inputs_offset as usize)
        //     .take(proving_key.num_public_inputs as usize)
        // {
        //     proving_key.public_inputs.push(*input);
        // }

        // TODO the following elements are not part of the proving key so far
        // Set the recursive proof indices
        // proving_key.recursive_proof_public_input_indices =
        //     circuit.recursive_proof_public_input_indices;
        // proving_key.contains_recursive_proof = circuit.contains_recursive_proof;

        proving_key
    }

    pub fn get_prover_crs(
        circuit: &CoUltraCircuitBuilder<T, P>,
        path_g1: &str,
    ) -> Result<ProverCrs<P>> {
        PlainProvingKey::get_prover_crs(circuit, path_g1)
    }

    fn new(circuit_size: usize, num_public_inputs: usize, crs: ProverCrs<P>) -> Self {
        tracing::info!("ProvingKey new");
        let polynomials = Polynomials::new(circuit_size);

        Self {
            crs,
            circuit_size: circuit_size as u32,
            public_inputs: Vec::with_capacity(num_public_inputs),
            num_public_inputs: num_public_inputs as u32,
            pub_inputs_offset: 0,
            polynomials,
            memory_read_records: Vec::new(),
            memory_write_records: Vec::new(),
            phantom: PhantomData,
        }
    }

    fn populate_trace(&mut self, builder: &mut CoUltraCircuitBuilder<T, P>, is_strucutred: bool) {
        tracing::info!("Populating trace");

        let mut trace_data = TraceData::new(builder, self);
        trace_data.construct_trace_data(builder, is_strucutred);

        let ram_rom_offset = trace_data.ram_rom_offset;
        let copy_cycles = trace_data.copy_cycles;
        self.pub_inputs_offset = trace_data.pub_inputs_offset;

        PlainProvingKey::add_memory_records_to_proving_key(
            ram_rom_offset,
            builder,
            &mut self.memory_read_records,
            &mut self.memory_write_records,
        );

        // Compute the permutation argument polynomials (sigma/id) and add them to proving key
        PlainProvingKey::compute_permutation_argument_polynomials(
            &mut self.polynomials.precomputed,
            builder,
            copy_cycles,
            self.circuit_size as usize,
            self.pub_inputs_offset as usize,
        );
    }
}
