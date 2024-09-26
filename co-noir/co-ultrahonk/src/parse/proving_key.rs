use std::marker::PhantomData;

use super::CoUltraCircuitBuilder;
use crate::types::ProvingKey;
use ark_ec::pairing::Pairing;
use eyre::Result;
use mpc_core::traits::PrimeFieldMpcProtocol;
use ultrahonk::{CrsParser, ProverCrs, Utils};

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
        todo!();
        // proving_key.populate_trace(&mut circuit, false);

        // // First and last lagrange polynomials (in the full circuit size)
        // proving_key.polynomials.precomputed.lagrange_first_mut()[0] = P::ScalarField::one();
        // proving_key.polynomials.precomputed.lagrange_last_mut()[dyadic_circuit_size - 1] =
        //     P::ScalarField::one();

        // proving_key.construct_lookup_table_polynomials(&circuit, dyadic_circuit_size, 0);
        // proving_key.construct_lookup_read_counts(&mut circuit, dyadic_circuit_size);

        // // Construct the public inputs array
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
        tracing::info!("Getting prover crs");
        const EXTRA_SRS_POINTS_FOR_ECCVM_IPA: usize = 1;

        let num_extra_gates =
            CoUltraCircuitBuilder::<T, P>::get_num_gates_added_to_ensure_nonzero_polynomials();
        let total_circuit_size = circuit.get_total_circuit_size();
        let srs_size = CoUltraCircuitBuilder::<T, P>::get_circuit_subgroup_size(
            total_circuit_size + num_extra_gates,
        );

        let srs_size = Utils::round_up_power_2(srs_size) + EXTRA_SRS_POINTS_FOR_ECCVM_IPA;
        CrsParser::<P>::get_crs_g1(path_g1, srs_size)
    }

    fn new(circuit_size: usize, num_public_inputs: usize, crs: ProverCrs<P>) -> Self {
        tracing::info!("ProvingKey new");
        // let polynomials = Polynomials::new(circuit_size);
        todo!("Polys");

        Self {
            crs,
            circuit_size: circuit_size as u32,
            public_inputs: Vec::with_capacity(num_public_inputs),
            num_public_inputs: num_public_inputs as u32,
            pub_inputs_offset: 0,
            // polynomials,
            memory_read_records: Vec::new(),
            memory_write_records: Vec::new(),
            phantom_data: PhantomData,
        }
    }
}
