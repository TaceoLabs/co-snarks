use std::sync::Arc;

use crate::{
    builder::{GenericUltraCircuitBuilder, UltraCircuitBuilder},
    crs::ProverCrs,
    polynomials::{
        polynomial::Polynomial,
        polynomial_types::{Polynomials, PrecomputedEntities},
    },
    types::types::{
        AggregationObjectPubInputIndices, CyclicPermutation, Mapping, PermutationMapping,
        TraceData, NUM_WIRES,
    },
    HonkProofResult,
};
use ark_ec::pairing::Pairing;
use ark_ff::One;
use co_acvm::{mpc::NoirWitnessExtensionProtocol, PlainAcvmSolver};
use num_bigint::BigUint;

pub struct ProvingKey<P: Pairing> {
    pub crs: Arc<ProverCrs<P>>,
    pub circuit_size: u32,
    pub public_inputs: Vec<P::ScalarField>,
    pub num_public_inputs: u32,
    pub pub_inputs_offset: u32,
    pub contains_pairing_point_accumulator: bool,
    pub pairing_point_accumulator_public_input_indices: AggregationObjectPubInputIndices,
    pub polynomials: Polynomials<P::ScalarField>,
    pub memory_read_records: Vec<u32>,
    pub memory_write_records: Vec<u32>,
    pub final_active_wire_idx: usize,
}

impl<P: Pairing> ProvingKey<P> {
    // We ignore the TraceStructure for now (it is None in barretenberg for UltraHonk)
    pub fn create<T: NoirWitnessExtensionProtocol<P::ScalarField>>(
        mut circuit: UltraCircuitBuilder<P>,
        crs: Arc<ProverCrs<P>>,
        driver: &mut PlainAcvmSolver<P::ScalarField>,
    ) -> HonkProofResult<Self> {
        tracing::trace!("ProvingKey create");

        assert!(
            circuit.circuit_finalized,
            "the circuit must be finalized before creating the  proving key"
        );

        let dyadic_circuit_size = circuit.compute_dyadic_size();

        // Complete the public inputs execution trace block from builder.public_inputs
        circuit.populate_public_inputs_block();
        circuit.blocks.compute_offsets(false);

        // Find index of last non-trivial wire value in the trace
        let mut final_active_wire_idx = 0;
        for block in circuit.blocks.get() {
            if block.len() > 0 {
                final_active_wire_idx = block.trace_offset as usize + block.len() - 1;
            }
        }

        // TACEO TODO BB allocates less memory for the different polynomials

        let mut proving_key = Self::new(
            dyadic_circuit_size,
            circuit.public_inputs.len(),
            crs,
            final_active_wire_idx,
        );
        // Construct and add to proving key the wire, selector and copy constraint polynomials
        proving_key.populate_trace(&mut circuit, false);

        // First and last lagrange polynomials (in the full circuit size)
        proving_key.polynomials.precomputed.lagrange_first_mut()[0] = P::ScalarField::one();
        proving_key.polynomials.precomputed.lagrange_last_mut()[final_active_wire_idx] =
            P::ScalarField::one();

        Self::construct_lookup_table_polynomials(
            proving_key
                .polynomials
                .precomputed
                .get_table_polynomials_mut(),
            &circuit,
            dyadic_circuit_size,
            0,
        );
        Self::construct_lookup_read_counts(
            driver,
            proving_key
                .polynomials
                .witness
                .lookup_read_counts_and_tags_mut()
                .try_into()
                .unwrap(),
            &mut circuit,
            dyadic_circuit_size,
        )?;

        // Construct the public inputs array
        for input in proving_key
            .polynomials
            .witness
            .w_r()
            .iter()
            .skip(proving_key.pub_inputs_offset as usize)
            .take(proving_key.num_public_inputs as usize)
        {
            proving_key.public_inputs.push(*input);
        }

        // Set the pairing point accumulator indices
        proving_key.pairing_point_accumulator_public_input_indices =
            circuit.pairing_point_accumulator_public_input_indices;
        proving_key.contains_pairing_point_accumulator = circuit.contains_pairing_point_accumulator;

        Ok(proving_key)
    }

    fn new(
        circuit_size: usize,
        num_public_inputs: usize,
        crs: Arc<ProverCrs<P>>,
        final_active_wire_idx: usize,
    ) -> Self {
        tracing::trace!("ProvingKey new");
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
            final_active_wire_idx,
            contains_pairing_point_accumulator: false,
            pairing_point_accumulator_public_input_indices: [0;
                crate::types::types::AGGREGATION_OBJECT_SIZE],
        }
    }

    fn populate_trace(&mut self, builder: &mut UltraCircuitBuilder<P>, is_structured: bool) {
        tracing::trace!("Populating trace");

        let mut trace_data = TraceData::new(builder, self);
        trace_data.construct_trace_data(builder, is_structured);

        let ram_rom_offset = trace_data.ram_rom_offset;
        let copy_cycles = trace_data.copy_cycles;
        self.pub_inputs_offset = trace_data.pub_inputs_offset;

        Self::add_memory_records_to_proving_key(
            ram_rom_offset,
            builder,
            &mut self.memory_read_records,
            &mut self.memory_write_records,
        );

        // Compute the permutation argument polynomials (sigma/id) and add them to proving key
        Self::compute_permutation_argument_polynomials(
            &mut self.polynomials.precomputed,
            builder,
            copy_cycles,
            self.circuit_size as usize,
            self.pub_inputs_offset as usize,
        );
    }

    pub fn add_memory_records_to_proving_key<T: NoirWitnessExtensionProtocol<P::ScalarField>>(
        ram_rom_offset: u32,
        builder: &GenericUltraCircuitBuilder<P, T>,
        memory_read_records: &mut Vec<u32>,
        memory_write_records: &mut Vec<u32>,
    ) {
        tracing::trace!("Adding memory records to proving key");

        assert!(memory_read_records.is_empty());
        assert!(memory_write_records.is_empty());

        for index in builder.memory_read_records.iter() {
            memory_read_records.push(*index + ram_rom_offset);
        }

        for index in builder.memory_write_records.iter() {
            memory_write_records.push(*index + ram_rom_offset);
        }
    }

    pub fn compute_permutation_argument_polynomials<
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        polys: &mut PrecomputedEntities<Polynomial<P::ScalarField>>,
        circuit: &GenericUltraCircuitBuilder<P, T>,
        copy_cycles: Vec<CyclicPermutation>,
        circuit_size: usize,
        pub_inputs_offset: usize,
    ) {
        tracing::trace!("Computing permutation argument polynomials");
        let mapping = Self::compute_permutation_mapping(
            circuit_size,
            pub_inputs_offset,
            circuit,
            copy_cycles,
        );

        // Compute Honk-style sigma and ID polynomials from the corresponding mappings
        Self::compute_honk_style_permutation_lagrange_polynomials_from_mapping(
            polys.get_sigmas_mut(),
            mapping.sigmas,
            circuit_size,
        );
        Self::compute_honk_style_permutation_lagrange_polynomials_from_mapping(
            polys.get_ids_mut(),
            mapping.ids,
            circuit_size,
        );
    }

    fn compute_permutation_mapping<T: NoirWitnessExtensionProtocol<P::ScalarField>>(
        circuit_size: usize,
        pub_inputs_offset: usize,
        circuit_constructor: &GenericUltraCircuitBuilder<P, T>,
        wire_copy_cycles: Vec<CyclicPermutation>,
    ) -> PermutationMapping {
        // Initialize the table of permutations so that every element points to itself
        let mut mapping = PermutationMapping::new(circuit_size);

        // Represents the index of a variable in circuit_constructor.variables (needed only for generalized)
        let real_variable_tags = &circuit_constructor.real_variable_tags;

        for (cycle_index, copy_cycle) in wire_copy_cycles.into_iter().enumerate() {
            let copy_cycle_size = copy_cycle.len();
            for (node_idx, current_cycle_node) in copy_cycle.iter().enumerate() {
                // Get the indices of the current node and next node in the cycle
                // If current node is the last one in the cycle, then the next one is the first one
                let next_cycle_node_index = if node_idx == copy_cycle_size - 1 {
                    0
                } else {
                    node_idx + 1
                };
                let next_cycle_node = &copy_cycle[next_cycle_node_index];
                let current_row = current_cycle_node.gate_index as usize;
                let next_row = next_cycle_node.gate_index;

                let current_column = current_cycle_node.wire_index as usize;
                let next_column = next_cycle_node.wire_index;
                // Point current node to the next node
                mapping.sigmas[current_column][current_row].row_index = next_row;
                mapping.sigmas[current_column][current_row].column_index = next_column;

                let first_node = node_idx == 0;
                let last_node = next_cycle_node_index == 0;

                if first_node {
                    mapping.ids[current_column][current_row].is_tag = true;
                    mapping.ids[current_column][current_row].row_index =
                        real_variable_tags[cycle_index];
                }
                if last_node {
                    mapping.sigmas[current_column][current_row].is_tag = true;

                    // AZTEC TODO(Zac): yikes, std::maps (tau) are expensive. Can we find a way to get rid of this?
                    mapping.sigmas[current_column][current_row].row_index = *circuit_constructor
                        .tau
                        .get(&real_variable_tags[cycle_index])
                        .expect("tau must be present  ");
                }
            }
        }

        // Add information about public inputs so that the cycles can be altered later; See the construction of the
        // permutation polynomials for details.
        let num_public_inputs = circuit_constructor.public_inputs.len();

        for i in 0..num_public_inputs {
            let idx = i + pub_inputs_offset;
            mapping.sigmas[0][idx].row_index = idx as u32;
            mapping.sigmas[0][idx].column_index = 0;
            mapping.sigmas[0][idx].is_public_input = true;
            if mapping.sigmas[0][idx].is_tag {
                tracing::warn!("MAPPING IS BOTH A TAG AND A PUBLIC INPUT");
            }
        }

        mapping
    }

    fn compute_honk_style_permutation_lagrange_polynomials_from_mapping(
        permutation_polynomials: &mut [Polynomial<P::ScalarField>],
        permutation_mappings: Mapping,
        circuit_size: usize,
    ) {
        let num_gates = circuit_size;

        for (current_permutation_mappings, current_permutation_poly) in permutation_mappings
            .into_iter()
            .zip(permutation_polynomials)
        {
            debug_assert_eq!(current_permutation_mappings.len(), num_gates);
            debug_assert_eq!(current_permutation_poly.len(), num_gates);

            // TACEO TODO Barrettenberg uses multithreading here
            for (current_mapping, current_poly) in current_permutation_mappings
                .into_iter()
                .zip(current_permutation_poly.iter_mut())
            {
                if current_mapping.is_public_input {
                    // We intentionally want to break the cycles of the public input variables.
                    // During the witness generation, the left and right wire polynomials at index i contain the i-th public
                    // input. The CyclicPermutation created for these variables always start with (i) -> (n+i), followed by
                    // the indices of the variables in the "real" gates. We make i point to -(i+1), so that the only way of
                    // repairing the cycle is add the mapping
                    //  -(i+1) -> (n+i)
                    // These indices are chosen so they can easily be computed by the verifier. They can expect the running
                    // product to be equal to the "public input delta" that is computed in <honk/utils/grand_product_delta.hpp>
                    *current_poly = -P::ScalarField::from(
                        current_mapping.row_index
                            + 1
                            + num_gates as u32 * current_mapping.column_index,
                    );
                } else if current_mapping.is_tag {
                    // Set evaluations to (arbitrary) values disjoint from non-tag values
                    *current_poly = P::ScalarField::from(
                        num_gates as u32 * NUM_WIRES as u32 + current_mapping.row_index,
                    );
                } else {
                    // For the regular permutation we simply point to the next location by setting the evaluation to its
                    // index
                    *current_poly = P::ScalarField::from(
                        current_mapping.row_index + num_gates as u32 * current_mapping.column_index,
                    );
                }
            }
        }
    }

    pub fn construct_lookup_table_polynomials<T: NoirWitnessExtensionProtocol<P::ScalarField>>(
        table_polynomials: &mut [Polynomial<P::ScalarField>],
        circuit: &GenericUltraCircuitBuilder<P, T>,
        dyadic_circuit_size: usize,
        additional_offset: usize,
    ) {
        // Create lookup selector polynomials which interpolate each table column.
        // Our selector polys always need to interpolate the full subgroup size, so here we offset so as to
        // put the table column's values at the end. (The first gates are for non-lookup constraints).
        // [0, ..., 0, ...table, 0, 0, 0, x]
        //  ^^^^^^^^^  ^^^^^^^^  ^^^^^^^  ^nonzero to ensure uniqueness and to avoid infinity commitments
        //  |          table     randomness
        //  ignored, as used for regular constraints and padding to the next power of 2.
        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1033): construct tables and counts at top of trace
        assert!(dyadic_circuit_size > circuit.get_tables_size() + additional_offset);
        let mut offset = dyadic_circuit_size - circuit.get_tables_size() - additional_offset;

        for table in circuit.lookup_tables.iter() {
            let table_index = table.table_index;

            for i in 0..table.len() {
                table_polynomials[0][offset] = table.column_1[i];
                table_polynomials[1][offset] = table.column_2[i];
                table_polynomials[2][offset] = table.column_3[i];
                table_polynomials[3][offset] = P::ScalarField::from(table_index as u64);
                offset += 1;
            }
        }
    }

    pub fn construct_lookup_read_counts<T: NoirWitnessExtensionProtocol<P::ScalarField>>(
        driver: &mut T,
        witness: &mut [Polynomial<T::ArithmeticShare>; 2],
        circuit: &mut GenericUltraCircuitBuilder<P, T>,
        dyadic_circuit_size: usize,
    ) -> std::io::Result<()> {
        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1033): construct tables and counts at top of trace
        let offset = dyadic_circuit_size - circuit.get_tables_size();

        let mut table_offset = offset; // offset of the present table in the table polynomials
                                       // loop over all tables used in the circuit; each table contains data about the lookups made on it
        for table in circuit.lookup_tables.iter_mut() {
            // table.initialize_index_map(); // We calculate indices from keys

            for (i, gate_data) in table.lookup_gates.iter().enumerate() {
                // convert lookup gate data to an array of three field elements, one for each of the 3 columns
                // let table_entry = gate_data.to_table_components(table.use_twin_keys); // We calculate indices from keys

                // find the index of the entry in the table
                // let index_in_table = table.index_map[table_entry]; // We calculate indices from keys
                let index_in_table = gate_data.calculate_table_index(
                    driver,
                    table.use_twin_keys,
                    table.column_2_step_size,
                );

                if T::is_shared(&index_in_table) {
                    let index_in_table =
                        T::get_shared(&index_in_table).expect("Already checked it is shared");
                    let ohv =
                        driver.one_hot_vector_from_shared_index(index_in_table, table.len())?;

                    // increment the read count at the corresponding index in the full polynomial
                    for (src, des) in ohv
                        .iter()
                        .zip(witness[0].iter_mut().skip(table_offset).take(table.len()))
                    {
                        let wit = T::AcvmType::from(des.to_owned());
                        let src = T::AcvmType::from(src.to_owned());
                        let added = driver.add(wit, src);
                        *des = if T::is_shared(&added) {
                            T::get_shared(&added).unwrap()
                        } else {
                            driver.promote_to_trivial_share(T::get_public(&added).unwrap())
                        }; // Read count
                    }

                    // Set the read tag
                    // Read tag is 1 if entry has been read 1 or more times
                    if i == 0 {
                        // Just assign, no cmux needed
                        for (src, des) in ohv
                            .into_iter()
                            .zip(witness[1].iter_mut().skip(table_offset).take(table.len()))
                        {
                            *des = src
                        }
                    } else {
                        // Assign the value via a cmux
                        let lut =
                            &mut witness[1].as_mut()[table_offset..table_offset + table.len()];
                        let one = driver.promote_to_trivial_share(P::ScalarField::one());
                        driver.write_to_shared_lut_from_ohv(&ohv, one, lut)?;
                    }
                } else {
                    // Index is public
                    let index_in_table: BigUint = T::get_public(&index_in_table)
                        .expect("Already checked it is public")
                        .into();
                    let index_in_table =
                        usize::try_from(index_in_table).expect("index is too large for usize?");

                    let index_in_poly = table_offset + index_in_table;

                    // increment the read count at the corresponding index in the full polynomial
                    let mut wit0 = T::AcvmType::from(witness[0][index_in_poly].to_owned());
                    driver.add_assign_with_public(P::ScalarField::one(), &mut wit0);
                    witness[0][index_in_poly] = if T::is_shared(&wit0) {
                        T::get_shared(&wit0).unwrap()
                    } else {
                        driver.promote_to_trivial_share(T::get_public(&wit0).unwrap())
                    }; // Read count

                    // Set the read tag
                    witness[1][index_in_poly] =
                        driver.promote_to_trivial_share(P::ScalarField::one());
                    // Read tag is 1 if entry has been read 1 or more times
                }
            }
            table_offset += table.len(); // set the offset of the next table within the polynomials
        }

        Ok(())
    }
}
