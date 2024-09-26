use ark_ec::pairing::Pairing;
use ark_ff::{One, Zero};
use mpc_core::traits::PrimeFieldMpcProtocol;
use num_bigint::BigUint;
use std::collections::HashMap;
use ultrahonk::{
    parse::{
        field_from_hex_string,
        types::{RamTranscript, RangeList, RomTranscript},
    },
    AcirFormat, UltraCircuitBuilder,
};

use crate::parse::types::GateCounter;

#[derive(Clone, Debug)]
pub enum BuilderFieldType<T, P: Pairing>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    Public(P::ScalarField),
    Shared(T::FieldShare),
}

pub struct CoUltraCircuitBuilder<T, P: Pairing>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    pub(crate) driver: T,
    pub(crate) variables: Vec<BuilderFieldType<T, P>>,
    variable_names: HashMap<u32, String>,
    next_var_index: Vec<u32>,
    prev_var_index: Vec<u32>,
    pub(crate) real_variable_index: Vec<u32>,
    pub(crate) real_variable_tags: Vec<u32>,
    pub(crate) public_inputs: Vec<u32>,
    is_recursive_circuit: bool,
    pub(crate) tau: HashMap<u32, u32>,
    // constant_variable_indices: HashMap<P::ScalarField, u32>,
    pub(crate) zero_idx: u32,
    one_idx: u32,
    // pub(crate) blocks: GateBlocks<P::ScalarField>, // Storage for wires and selectors for all gate types
    num_gates: usize,
    circuit_finalized: bool,
    contains_recursive_proof: bool,
    // recursive_proof_public_input_indices: AggregationObjectPubInputIndices,
    rom_arrays: Vec<RomTranscript>,
    ram_arrays: Vec<RamTranscript>,
    // pub(crate) lookup_tables: Vec<PlookupBasicTable<P::ScalarField>>,
    // plookup: Plookup<P::ScalarField>,
    range_lists: HashMap<u64, RangeList>,
    // cached_partial_non_native_field_multiplications:
    //     Vec<CachedPartialNonNativeFieldMultiplication<P::ScalarField>>,
    // Stores gate index of ROM and RAM reads (required by proving key)
    pub(crate) memory_read_records: Vec<u32>,
    // Stores gate index of RAM writes (required by proving key)
    pub(crate) memory_write_records: Vec<u32>,
}

impl<T, P: Pairing> CoUltraCircuitBuilder<T, P>
where
    T: PrimeFieldMpcProtocol<P::ScalarField>,
{
    pub const DUMMY_TAG: u32 = UltraCircuitBuilder::<P>::DUMMY_TAG;
    pub const REAL_VARIABLE: u32 = UltraCircuitBuilder::<P>::REAL_VARIABLE;
    pub const FIRST_VARIABLE_IN_CLASS: u32 = UltraCircuitBuilder::<P>::FIRST_VARIABLE_IN_CLASS;
    pub const UNINITIALIZED_MEMORY_RECORD: u32 =
        UltraCircuitBuilder::<P>::UNINITIALIZED_MEMORY_RECORD;
    pub const NUMBER_OF_GATES_PER_RAM_ACCESS: usize =
        UltraCircuitBuilder::<P>::NUMBER_OF_GATES_PER_RAM_ACCESS;
    pub const NUMBER_OF_ARITHMETIC_GATES_PER_RAM_ARRAY: usize =
        UltraCircuitBuilder::<P>::NUMBER_OF_ARITHMETIC_GATES_PER_RAM_ARRAY;
    pub const NUM_RESERVED_GATES: usize = UltraCircuitBuilder::<P>::NUM_RESERVED_GATES;
    // number of gates created per non-native field operation in process_non_native_field_multiplications
    pub const GATES_PER_NON_NATIVE_FIELD_MULTIPLICATION_ARITHMETIC: usize =
        UltraCircuitBuilder::<P>::GATES_PER_NON_NATIVE_FIELD_MULTIPLICATION_ARITHMETIC;

    pub fn promote_public_witness_vector(
        witness: Vec<P::ScalarField>,
    ) -> Vec<BuilderFieldType<T, P>> {
        witness
            .into_iter()
            .map(|w| BuilderFieldType::Public(w))
            .collect()
    }

    pub fn create_circuit(
        driver: T,
        constraint_system: AcirFormat<P::ScalarField>,
        size_hint: usize,
        witness: Vec<BuilderFieldType<T, P>>,
        honk_recursion: bool,           // true for ultrahonk
        collect_gates_per_opcode: bool, // false for ultrahonk
    ) -> Self {
        tracing::info!("Builder create circuit");

        let has_valid_witness_assignments = !witness.is_empty();

        let mut builder = Self::init(
            driver,
            size_hint,
            witness,
            constraint_system.public_inputs.to_owned(),
            constraint_system.varnum as usize,
            constraint_system.recursive,
        );

        builder.build_constraints(
            constraint_system,
            has_valid_witness_assignments,
            honk_recursion,
            collect_gates_per_opcode,
        );

        builder
    }

    fn new(driver: T, size_hint: usize) -> Self {
        tracing::info!("Builder new");
        let variables = Vec::with_capacity(size_hint * 3);
        let variable_names = HashMap::with_capacity(size_hint * 3);
        let next_var_index = Vec::with_capacity(size_hint * 3);
        let prev_var_index = Vec::with_capacity(size_hint * 3);
        let real_variable_index = Vec::with_capacity(size_hint * 3);
        let real_variable_tags = Vec::with_capacity(size_hint * 3);

        Self {
            driver,
            variables,
            variable_names,
            next_var_index,
            prev_var_index,
            real_variable_index,
            real_variable_tags,
            public_inputs: Vec::new(),
            is_recursive_circuit: false,
            tau: HashMap::new(),
            // constant_variable_indices: HashMap::new(),
            zero_idx: 0,
            one_idx: 1,
            // blocks: GateBlocks::default(),
            num_gates: 0,
            circuit_finalized: false,
            contains_recursive_proof: false,
            // recursive_proof_public_input_indices: Default::default(),
            rom_arrays: Vec::new(),
            ram_arrays: Vec::new(),
            // lookup_tables: Vec::new(),
            // plookup: Default::default(),
            range_lists: HashMap::new(),
            // cached_partial_non_native_field_multiplications: Vec::new(),
            memory_read_records: Vec::new(),
            memory_write_records: Vec::new(),
        }
    }

    /**
     * @brief Constructor from data generated from ACIR
     *
     * @param size_hint
     * @param witness_values witnesses values known to acir
     * @param public_inputs indices of public inputs in witness array
     * @param varnum number of known witness
     *
     * @note The size of witness_values may be less than varnum. The former is the set of actual witness values known at
     * the time of acir generation. The latter may be larger and essentially acounts for placeholders for witnesses that
     * we know will exist but whose values are not known during acir generation. Both are in general less than the total
     * number of variables/witnesses that might be present for a circuit generated from acir, since many gates will
     * depend on the details of the bberg implementation (or more generally on the backend used to process acir).
     */
    fn init(
        driver: T,
        size_hint: usize,
        witness_values: Vec<BuilderFieldType<T, P>>,
        public_inputs: Vec<u32>,
        varnum: usize,
        recursive: bool,
    ) -> Self {
        tracing::info!("Builder init");
        let mut builder = Self::new(driver, size_hint);

        // TODO(https://github.com/AztecProtocol/barretenberg/issues/870): reserve space in blocks here somehow?

        let len = witness_values.len();
        for witness in witness_values.into_iter().take(varnum) {
            builder.add_variable(witness);
        }
        // Zeros are added for variables whose existence is known but whose values are not yet known. The values may
        // be "set" later on via the assert_equal mechanism.
        for _ in len..varnum {
            builder.add_variable(BuilderFieldType::Public(P::ScalarField::zero()));
        }

        // Add the public_inputs from acir
        builder.public_inputs = public_inputs;

        // Add the const zero variable after the acir witness has been
        // incorporated into variables.
        // builder.zero_idx = builder.put_constant_variable(P::ScalarField::zero());
        builder.tau.insert(Self::DUMMY_TAG, Self::DUMMY_TAG); // TODO(luke): explain this

        builder.is_recursive_circuit = recursive;
        builder
    }

    pub(crate) fn add_variable(&mut self, value: BuilderFieldType<T, P>) -> u32 {
        let idx = self.variables.len() as u32;
        self.variables.push(value);
        self.real_variable_index.push(idx);
        self.next_var_index.push(Self::REAL_VARIABLE);
        self.prev_var_index.push(Self::FIRST_VARIABLE_IN_CLASS);
        self.real_variable_tags.push(Self::DUMMY_TAG);
        idx
    }

    fn build_constraints(
        &mut self,
        mut constraint_system: AcirFormat<P::ScalarField>,
        has_valid_witness_assignments: bool,
        honk_recursion: bool,
        collect_gates_per_opcode: bool,
    ) {
        tracing::info!("Builder build constraints");
        if collect_gates_per_opcode {
            constraint_system
                .gates_per_opcode
                .resize(constraint_system.num_acir_opcodes as usize, 0);
        }

        let mut gate_counter = GateCounter::new(collect_gates_per_opcode);

        // Add arithmetic gates
        for (i, constraint) in constraint_system.poly_triple_constraints.iter().enumerate() {
            self.create_poly_gate(constraint);
            gate_counter.track_diff(
                self,
                &mut constraint_system.gates_per_opcode,
                constraint_system
                    .original_opcode_indices
                    .poly_triple_constraints[i],
            );
        }
        for (i, constraint) in constraint_system.quad_constraints.iter().enumerate() {
            self.create_big_mul_gate(constraint);
            gate_counter.track_diff(
                self,
                &mut constraint_system.gates_per_opcode,
                constraint_system.original_opcode_indices.quad_constraints[i],
            );
        }

        // Add logic constraint
        // for (i, constraint) in constraint_system.logic_constraints.iter().enumerate() {
        //     todo!("Logic gates");
        // }

        // Add range constraint
        // for (i, constraint) in constraint_system.range_constraints.iter().enumerate() {
        //     todo!("rage gates");
        // }

        // Add aes128 constraints
        // for (i, constraint) in constraint_system.aes128_constraints.iter().enumerate() {
        //     todo!("aes128 gates");
        // }

        // Add sha256 constraints
        // for (i, constraint) in constraint_system.sha256_constraints.iter().enumerate() {
        //     todo!("sha256 gates");
        // }

        // for (i, constraint) in constraint_system.sha256_compression.iter().enumerate() {
        //     todo!("sha256 compression gates");
        // }

        // Add schnorr constraints
        // for (i, constraint) in constraint_system.schnorr_constraints.iter().enumerate() {
        //     todo!("schnorr gates");
        // }

        // Add ECDSA k1 constraints
        // for (i, constraint) in constraint_system.ecdsa_k1_constraints.iter().enumerate() {
        //     todo!("ecdsa k1 gates");
        // }

        // Add ECDSA r1 constraints
        // for (i, constraint) in constraint_system.ecdsa_r1_constraints.iter().enumerate() {
        //     todo!("ecdsa r1 gates");
        // }

        // Add blake2s constraints
        // for (i, constraint) in constraint_system.blake2s_constraints.iter().enumerate() {
        //     todo!("blake2s gates");
        // }

        // Add blake3 constraints
        // for (i, constraint) in constraint_system.blake3_constraints.iter().enumerate() {
        //     todo!("blake3 gates");
        // }

        // Add keccak constraints
        // for (i, constraint) in constraint_system.keccak_constraints.iter().enumerate() {
        //     todo!("keccak gates");
        // }

        // for (i, constraint) in constraint_system.keccak_permutations.iter().enumerate() {
        //     todo!("keccak permutation gates");
        // }

        // Add pedersen constraints
        // for (i, constraint) in constraint_system.pedersen_constraints.iter().enumerate() {
        //     todo!("pederson gates");
        // }

        // for (i, constraint) in constraint_system.pedersen_hash_constraints.iter().enumerate() {
        //     todo!("pedersen hash gates");
        // }

        // Add poseidon2 constraints
        // for (i, constraint) in constraint_system.poseidon2_constraints.iter().enumerate() {
        //     todo!("poseidon2 gates");
        // }

        // Add multi scalar mul constraints
        // for (i, constraint) in constraint_system.multi_scalar_mul_constraints.iter().enumerate() {
        //     todo!("multi scalar mul gates");
        // }

        // Add ec add constraints
        // for (i, constraint) in constraint_system.ec_add_constraints.iter().enumerate() {
        //     todo!("ec add gates");
        // }

        // Add block constraints
        for (i, constraint) in constraint_system.block_constraints.iter().enumerate() {
            self.create_block_constraints(constraint, has_valid_witness_assignments);
            if collect_gates_per_opcode {
                let avg_gates_per_opcode = gate_counter.compute_diff(self)
                    / constraint_system.original_opcode_indices.block_constraints[i].len();
                for opcode_index in constraint_system.original_opcode_indices.block_constraints[i]
                    .iter()
                    .cloned()
                {
                    constraint_system.gates_per_opcode[opcode_index] = avg_gates_per_opcode;
                }
            }
        }

        // Add big_int constraints
        // for (i, constraint) in constraint_system.bigint_from_le_bytes_constraints.iter().enumerate() {
        //     todo!("bigint from le bytes gates");
        // }

        // for (i, constraint) in constraint_system.bigint_operations.iter().enumerate() {
        //     todo!("bigint operations gates");
        // }

        // for (i, constraint) in constraint_system.bigint_to_le_bytes_constraints.iter().enumerate() {
        //     todo!("bigint to le bytes gates");
        // }

        // assert equals
        for (i, constraint) in constraint_system.assert_equalities.iter().enumerate() {
            todo!("assert equalities gates");
        }

        // RecursionConstraints
        self.process_plonk_recursion_constraints(
            &constraint_system,
            has_valid_witness_assignments,
            &mut gate_counter,
        );
        self.process_honk_recursion_constraints(
            &constraint_system,
            has_valid_witness_assignments,
            &mut gate_counter,
        );

        // If the circuit does not itself contain honk recursion constraints but is going to be
        // proven with honk then recursively verified, add a default aggregation object
        if constraint_system.honk_recursion_constraints.is_empty()
            && honk_recursion
            && self.is_recursive_circuit
        {
            // Set a default aggregation object if we don't have one.
            let current_aggregation_object = self.init_default_agg_obj_indices();
            // Make sure the verification key records the public input indices of the
            // final recursion output.
            self.add_recursive_proof(current_aggregation_object);
        }
    }

    fn process_plonk_recursion_constraints(
        &mut self,
        constraint_system: &AcirFormat<P::ScalarField>,
        has_valid_witness_assignments: bool,
        gate_counter: &mut GateCounter,
    ) {
        for (i, constraint) in constraint_system.recursion_constraints.iter().enumerate() {
            todo!("Plonk recursion");
        }
    }

    fn process_honk_recursion_constraints(
        &mut self,
        constraint_system: &AcirFormat<P::ScalarField>,
        has_valid_witness_assignments: bool,
        gate_counter: &mut GateCounter,
    ) {
        {
            for (i, constraint) in constraint_system
                .honk_recursion_constraints
                .iter()
                .enumerate()
            {
                todo!("Honk recursion");
            }
        }
    }

    pub(crate) fn get_num_gates(&self) -> usize {
        // if circuit finalized already added extra gates
        if self.circuit_finalized {
            return self.num_gates;
        }
        let mut count = 0;
        let mut rangecount = 0;
        let mut romcount = 0;
        let mut ramcount = 0;
        let mut nnfcount = 0;
        self.get_num_gates_split_into_components(
            &mut count,
            &mut rangecount,
            &mut romcount,
            &mut ramcount,
            &mut nnfcount,
        );
        count + romcount + ramcount + rangecount + nnfcount
    }

    pub(crate) fn get_tables_size(&self) -> usize {
        let mut tables_size = 0;
        for table in self.lookup_tables.iter() {
            tables_size += table.len();
        }

        tables_size
    }

    fn get_lookups_size(&self) -> usize {
        let mut lookups_size = 0;
        for table in self.lookup_tables.iter() {
            lookups_size += table.lookup_gates.len();
        }
        lookups_size
    }

    fn get_num_gates_split_into_components(
        &self,
        count: &mut usize,
        rangecount: &mut usize,
        romcount: &mut usize,
        ramcount: &mut usize,
        nnfcount: &mut usize,
    ) {
        *count = self.num_gates;

        // each ROM gate adds +1 extra gate due to the rom reads being copied to a sorted list set
        for rom_array in self.rom_arrays.iter() {
            for state in rom_array.state.iter() {
                if state[0] == Self::UNINITIALIZED_MEMORY_RECORD {
                    *romcount += 2;
                }
            }
            *romcount += rom_array.records.len();
            *romcount += 1; // we add an addition gate after procesing a rom array
        }

        // each RAM gate adds +2 extra gates due to the ram reads being copied to a sorted list set,
        // as well as an extra gate to validate timestamps
        let mut ram_timestamps = Vec::with_capacity(self.ram_arrays.len());
        let mut ram_range_sizes = Vec::with_capacity(self.ram_arrays.len());
        let mut ram_range_exists = Vec::with_capacity(self.ram_arrays.len());
        for ram_array in self.ram_arrays.iter() {
            for state in ram_array.state.iter() {
                if *state == Self::UNINITIALIZED_MEMORY_RECORD {
                    *ramcount += Self::NUMBER_OF_GATES_PER_RAM_ACCESS;
                }
            }
            *ramcount += ram_array.records.len() * Self::NUMBER_OF_GATES_PER_RAM_ACCESS;
            *ramcount += Self::NUMBER_OF_ARITHMETIC_GATES_PER_RAM_ARRAY; // we add an addition gate after procesing a ram array

            // there will be 'max_timestamp' number of range checks, need to calculate.
            let max_timestamp = ram_array.access_count - 1;

            // if a range check of length `max_timestamp` already exists, we are double counting.
            // We record `ram_timestamps` to detect and correct for this error when we process range lists.
            ram_timestamps.push(max_timestamp);
            let mut padding = (NUM_WIRES - (max_timestamp % NUM_WIRES)) % NUM_WIRES;
            if max_timestamp == NUM_WIRES {
                padding += NUM_WIRES;
            }
            let ram_range_check_list_size = max_timestamp + padding;

            let mut ram_range_check_gate_count = ram_range_check_list_size / NUM_WIRES;
            ram_range_check_gate_count += 1; // we need to add 1 extra addition gates for every distinct range list

            ram_range_sizes.push(ram_range_check_gate_count);
            ram_range_exists.push(false);
        }
        for list in self.range_lists.iter() {
            let mut list_size = list.1.variable_indices.len();
            let mut padding = (NUM_WIRES - (list_size % NUM_WIRES)) % NUM_WIRES;
            if list_size == NUM_WIRES {
                padding += NUM_WIRES;
            }
            list_size += padding;

            for (time_stamp, ram_range_exist) in ram_timestamps
                .iter()
                .cloned()
                .zip(ram_range_exists.iter_mut())
            {
                if list.1.target_range as usize == time_stamp {
                    *ram_range_exist = true;
                }
            }

            *rangecount += list_size / NUM_WIRES;
            *rangecount += 1; // we need to add 1 extra addition gates for every distinct range list
        }
        // update rangecount to include the ram range checks the composer will eventually be creating
        for (ram_range_sizes, ram_range_exist) in ram_range_sizes
            .into_iter()
            .zip(ram_range_exists.into_iter())
        {
            if !ram_range_exist {
                *rangecount += ram_range_sizes;
            }
        }

        let mut nnf_copy = self.cached_partial_non_native_field_multiplications.clone();
        // update nnfcount
        nnf_copy.sort();

        nnf_copy.dedup();
        let num_nnf_ops = nnf_copy.len();
        *nnfcount = num_nnf_ops * Self::GATES_PER_NON_NATIVE_FIELD_MULTIPLICATION_ARITHMETIC;
    }

    fn add_recursive_proof(&mut self, proof_output_witness_indices: AggregationObjectIndices) {
        if self.contains_recursive_proof {
            panic!("added recursive proof when one already exists");
        }
        self.contains_recursive_proof = true;

        for (i, idx) in proof_output_witness_indices.into_iter().enumerate() {
            self.set_public_input(idx);
            self.recursive_proof_public_input_indices[i] = self.public_inputs.len() as u32 - 1;
        }
    }

    fn set_public_input(&mut self, witness_index: u32) {
        for public_input in self.public_inputs.iter().cloned() {
            if public_input == witness_index {
                panic!("Attempted to set a public input that is already public!");
            }
        }
        self.public_inputs.push(witness_index);
    }

    fn init_default_agg_obj_indices(&mut self) -> AggregationObjectIndices {
        const NUM_LIMBS: usize = 4;
        const NUM_LIMB_BITS: u32 = 68;

        let mask = (BigUint::one() << NUM_LIMB_BITS) - BigUint::one();

        // TODO(https://github.com/AztecProtocol/barretenberg/issues/911): These are pairing points extracted from a valid
        // proof. This is a workaround because we can't represent the point at infinity in biggroup yet.
        let mut agg_obj_indices = AggregationObjectIndices::default();
        let x0 = field_from_hex_string::<P::BaseField>(
            "0x031e97a575e9d05a107acb64952ecab75c020998797da7842ab5d6d1986846cf",
        )
        .expect("x0 works");
        let y0 = field_from_hex_string::<P::BaseField>(
            "0x178cbf4206471d722669117f9758a4c410db10a01750aebb5666547acf8bd5a4",
        )
        .expect("y0 works");
        let x1 = field_from_hex_string::<P::BaseField>(
            "0x0f94656a2ca489889939f81e9c74027fd51009034b3357f0e91b8a11e7842c38",
        )
        .expect("x1 works");
        let y1 = field_from_hex_string::<P::BaseField>(
            "0x1b52c2020d7464a0c80c0da527a08193fe27776f50224bd6fb128b46c1ddb67f",
        )
        .expect("y1 works");

        let mut agg_obj_indices_idx = 0;
        let aggregation_object_fq_values = [x0, y0, x1, y1];

        for val in aggregation_object_fq_values {
            let mut x: BigUint = val.into();
            let x0 = &x & &mask;
            x >>= NUM_LIMB_BITS;
            let x1 = &x & &mask;
            x >>= NUM_LIMB_BITS;
            let x2 = &x & &mask;
            x >>= NUM_LIMB_BITS;
            let x3 = x;

            let val_limbs: [P::ScalarField; NUM_LIMBS] = [
                P::ScalarField::from(x0),
                P::ScalarField::from(x1),
                P::ScalarField::from(x2),
                P::ScalarField::from(x3),
            ];

            for val in val_limbs {
                let idx = self.add_variable(val);
                agg_obj_indices[agg_obj_indices_idx] = idx;
                agg_obj_indices_idx += 1;
            }
        }
        agg_obj_indices
    }
}
