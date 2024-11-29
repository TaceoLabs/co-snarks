use crate::{
    acir_format::AcirFormat,
    crs::{Crs, ProverCrs},
    keys::{
        proving_key::ProvingKey,
        verification_key::{VerifyingKey, VerifyingKeyBarretenberg},
    },
    polynomials::polynomial_types::PrecomputedEntities,
    types::{
        plookup::{BasicTableId, MultiTableId, Plookup},
        types::{
            AddQuad, AddTriple, AggregationObjectIndices, AggregationObjectPubInputIndices,
            AuxSelectors, BlockConstraint, BlockType, CachedPartialNonNativeFieldMultiplication,
            ColumnIdx, FieldCT, GateCounter, MulQuad, PlookupBasicTable, PolyTriple, RamTranscript,
            RangeList, ReadData, RomRecord, RomTable, RomTranscript, UltraTraceBlock,
            UltraTraceBlocks, NUM_WIRES,
        },
    },
    utils::Utils,
    HonkProofError, HonkProofResult,
};
use ark_ec::pairing::Pairing;
use ark_ff::{One, Zero};
use co_acvm::{mpc::NoirWitnessExtensionProtocol, PlainAcvmSolver};
use num_bigint::BigUint;
use std::collections::BTreeMap;

type GateBlocks<F> = UltraTraceBlocks<UltraTraceBlock<F>>;

pub type UltraCircuitBuilder<P> =
    GenericUltraCircuitBuilder<P, PlainAcvmSolver<<P as Pairing>::ScalarField>>;

impl<P: Pairing> UltraCircuitBuilder<P> {
    pub fn create_vk_barretenberg(
        self,
        crs: ProverCrs<P>,
        driver: &mut PlainAcvmSolver<P::ScalarField>,
    ) -> HonkProofResult<VerifyingKeyBarretenberg<P>> {
        let contains_recursive_proof = self.contains_recursive_proof;
        let recursive_proof_public_input_indices = self.recursive_proof_public_input_indices;

        let pk = ProvingKey::create::<PlainAcvmSolver<_>>(self, crs, driver)?;
        let circuit_size = pk.circuit_size;

        let mut commitments = PrecomputedEntities::default();
        for (des, src) in commitments
            .iter_mut()
            .zip(pk.polynomials.precomputed.iter())
        {
            let comm = Utils::commit(src.as_ref(), &pk.crs)?;
            *des = P::G1Affine::from(comm);
        }

        let vk = VerifyingKeyBarretenberg {
            circuit_size: circuit_size as u64,
            log_circuit_size: Utils::get_msb64(circuit_size as u64) as u64,
            num_public_inputs: pk.num_public_inputs as u64,
            pub_inputs_offset: pk.pub_inputs_offset as u64,
            contains_recursive_proof,
            recursive_proof_public_input_indices,
            commitments,
        };

        Ok(vk)
    }

    pub fn create_keys(
        self,
        crs: Crs<P>,
        driver: &mut PlainAcvmSolver<P::ScalarField>,
    ) -> HonkProofResult<(ProvingKey<P>, VerifyingKey<P>)> {
        let prover_crs = ProverCrs {
            monomials: crs.monomials,
        };
        let verifier_crs = crs.g2_x;

        let pk = ProvingKey::create::<PlainAcvmSolver<_>>(self, prover_crs, driver)?;
        let circuit_size = pk.circuit_size;

        let mut commitments = PrecomputedEntities::default();
        for (des, src) in commitments
            .iter_mut()
            .zip(pk.polynomials.precomputed.iter())
        {
            let comm = Utils::commit(src.as_ref(), &pk.crs)?;
            *des = P::G1Affine::from(comm);
        }

        // Create and return the VerifyingKey instance
        let vk = VerifyingKey {
            crs: verifier_crs,
            circuit_size,
            num_public_inputs: pk.num_public_inputs,
            pub_inputs_offset: pk.pub_inputs_offset,
            commitments,
        };

        Ok((pk, vk))
    }

    pub fn create_keys_barretenberg(
        self,
        crs: ProverCrs<P>,
        driver: &mut PlainAcvmSolver<P::ScalarField>,
    ) -> HonkProofResult<(ProvingKey<P>, VerifyingKeyBarretenberg<P>)> {
        let contains_recursive_proof = self.contains_recursive_proof;
        let recursive_proof_public_input_indices = self.recursive_proof_public_input_indices;

        let pk = ProvingKey::create::<PlainAcvmSolver<_>>(self, crs, driver)?;
        let circuit_size = pk.circuit_size;

        let mut commitments = PrecomputedEntities::default();
        for (des, src) in commitments
            .iter_mut()
            .zip(pk.polynomials.precomputed.iter())
        {
            let comm = Utils::commit(src.as_ref(), &pk.crs)?;
            *des = P::G1Affine::from(comm);
        }

        // Create and return the VerifyingKey instance
        let vk = VerifyingKeyBarretenberg {
            circuit_size: circuit_size as u64,
            log_circuit_size: Utils::get_msb64(circuit_size as u64) as u64,
            num_public_inputs: pk.num_public_inputs as u64,
            pub_inputs_offset: pk.pub_inputs_offset as u64,
            contains_recursive_proof,
            recursive_proof_public_input_indices,
            commitments,
        };

        Ok((pk, vk))
    }
}

pub struct GenericUltraCircuitBuilder<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> {
    pub variables: Vec<T::AcvmType>,
    _variable_names: BTreeMap<u32, String>,
    next_var_index: Vec<u32>,
    prev_var_index: Vec<u32>,
    pub real_variable_index: Vec<u32>,
    pub(crate) real_variable_tags: Vec<u32>,
    pub(crate) current_tag: u32,
    pub public_inputs: Vec<u32>,
    is_recursive_circuit: bool,
    pub(crate) tau: BTreeMap<u32, u32>,
    constant_variable_indices: BTreeMap<P::ScalarField, u32>,
    pub(crate) zero_idx: u32,
    one_idx: u32,
    pub blocks: GateBlocks<P::ScalarField>, // Storage for wires and selectors for all gate types
    num_gates: usize,
    circuit_finalized: bool,
    pub contains_recursive_proof: bool,
    pub recursive_proof_public_input_indices: AggregationObjectPubInputIndices,
    rom_arrays: Vec<RomTranscript>,
    ram_arrays: Vec<RamTranscript>,
    pub(crate) lookup_tables: Vec<PlookupBasicTable<P::ScalarField>>,
    plookup: Plookup<P::ScalarField>,
    range_lists: BTreeMap<u64, RangeList>,
    cached_partial_non_native_field_multiplications:
        Vec<CachedPartialNonNativeFieldMultiplication<P::ScalarField>>,
    // Stores gate index of ROM and RAM reads (required by proving key)
    pub(crate) memory_read_records: Vec<u32>,
    // Stores gate index of RAM writes (required by proving key)
    pub(crate) memory_write_records: Vec<u32>,
}

// This workaround is required due to mutability issues
macro_rules! create_dummy_gate {
    ($builder:expr, $block:expr, $ixd_1:expr, $ixd_2:expr, $ixd_3:expr, $ixd_4:expr, ) => {
        Self::create_dummy_gate($block, $ixd_1, $ixd_2, $ixd_3, $ixd_4);
        $builder.check_selector_length_consistency();
        $builder.num_gates += 1; // necessary because create dummy gate cannot increment num_gates itself
    };
}

impl<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> GenericUltraCircuitBuilder<P, T> {
    pub(crate) const DUMMY_TAG: u32 = 0;
    pub(crate) const REAL_VARIABLE: u32 = u32::MAX - 1;
    pub(crate) const FIRST_VARIABLE_IN_CLASS: u32 = u32::MAX - 2;
    pub(crate) const UNINITIALIZED_MEMORY_RECORD: u32 = u32::MAX;
    pub(crate) const NUMBER_OF_GATES_PER_RAM_ACCESS: usize = 2;
    pub(crate) const NUMBER_OF_ARITHMETIC_GATES_PER_RAM_ARRAY: usize = 1;
    pub(crate) const NUM_RESERVED_GATES: usize = 4;
    pub(crate) const DEFAULT_PLOOKUP_RANGE_BITNUM: usize = 14;
    pub(crate) const DEFAULT_PLOOKUP_RANGE_STEP_SIZE: usize = 3;
    // number of gates created per non-native field operation in process_non_native_field_multiplications
    pub(crate) const GATES_PER_NON_NATIVE_FIELD_MULTIPLICATION_ARITHMETIC: usize = 7;

    pub fn create_circuit(
        constraint_system: AcirFormat<P::ScalarField>,
        recursive: bool,
        size_hint: usize,
        witness: Vec<T::AcvmType>,
        honk_recursion: bool,           // true for ultrahonk
        collect_gates_per_opcode: bool, // false for ultrahonk
        driver: &mut T,
    ) -> std::io::Result<Self> {
        tracing::trace!("Builder create circuit");

        let has_valid_witness_assignments = !witness.is_empty();

        let mut builder = Self::init(
            size_hint,
            witness,
            constraint_system.public_inputs.to_owned(),
            constraint_system.varnum as usize,
            recursive,
        );

        builder.build_constraints(
            driver,
            constraint_system,
            has_valid_witness_assignments,
            honk_recursion,
            collect_gates_per_opcode,
        )?;

        Ok(builder)
    }

    fn new(size_hint: usize) -> Self {
        tracing::trace!("Builder new");
        let variables = Vec::with_capacity(size_hint * 3);
        // let _variable_names = BTreeMap::with_capacity(size_hint * 3);
        let next_var_index = Vec::with_capacity(size_hint * 3);
        let prev_var_index = Vec::with_capacity(size_hint * 3);
        let real_variable_index = Vec::with_capacity(size_hint * 3);
        let real_variable_tags = Vec::with_capacity(size_hint * 3);

        Self {
            variables,
            _variable_names: BTreeMap::new(),
            next_var_index,
            prev_var_index,
            real_variable_index,
            real_variable_tags,
            public_inputs: Vec::new(),
            is_recursive_circuit: false,
            tau: BTreeMap::new(),
            constant_variable_indices: BTreeMap::new(),
            zero_idx: 0,
            one_idx: 1,
            blocks: GateBlocks::default(),
            num_gates: 0,
            circuit_finalized: false,
            contains_recursive_proof: false,
            recursive_proof_public_input_indices: Default::default(),
            rom_arrays: Vec::new(),
            ram_arrays: Vec::new(),
            lookup_tables: Vec::new(),
            plookup: Default::default(),
            range_lists: BTreeMap::new(),
            cached_partial_non_native_field_multiplications: Vec::new(),
            memory_read_records: Vec::new(),
            memory_write_records: Vec::new(),
            current_tag: 0,
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
        size_hint: usize,
        witness_values: Vec<T::AcvmType>,
        public_inputs: Vec<u32>,
        varnum: usize,
        recursive: bool,
    ) -> Self {
        tracing::trace!("Builder init");
        let mut builder = Self::new(size_hint);

        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/870): reserve space in blocks here somehow?
        let len = witness_values.len();
        for witness in witness_values.into_iter().take(varnum) {
            builder.add_variable(witness);
        }

        // Zeros are added for variables whose existence is known but whose values are not yet known. The values may
        // be "set" later on via the assert_equal mechanism.
        for _ in len..varnum {
            builder.add_variable(T::AcvmType::from(P::ScalarField::zero()));
        }

        // Add the public_inputs from acir
        builder.public_inputs = public_inputs;

        // Add the const zero variable after the acir witness has been
        // incorporated into variables.
        builder.zero_idx = builder.put_constant_variable(P::ScalarField::zero());
        builder.tau.insert(Self::DUMMY_TAG, Self::DUMMY_TAG); // AZTEC TODO(luke): explain this

        builder.is_recursive_circuit = recursive;
        builder
    }

    pub(crate) fn add_variable(&mut self, value: T::AcvmType) -> u32 {
        let idx = self.variables.len() as u32;
        self.variables.push(value);
        self.real_variable_index.push(idx);
        self.next_var_index.push(Self::REAL_VARIABLE);
        self.prev_var_index.push(Self::FIRST_VARIABLE_IN_CLASS);
        self.real_variable_tags.push(Self::DUMMY_TAG);
        idx
    }

    pub(crate) fn put_constant_variable(&mut self, variable: P::ScalarField) -> u32 {
        if let Some(val) = self.constant_variable_indices.get(&variable) {
            *val
        } else {
            let variable_index = self.add_variable(T::AcvmType::from(variable));
            self.fix_witness(variable_index, variable);
            self.constant_variable_indices
                .insert(variable, variable_index);
            variable_index
        }
    }

    fn create_poly_gate(&mut self, inp: &PolyTriple<P::ScalarField>) {
        self.assert_valid_variables(&[inp.a, inp.b, inp.c]);

        self.blocks
            .arithmetic
            .populate_wires(inp.a, inp.b, inp.c, self.zero_idx);
        self.blocks.arithmetic.q_m().push(inp.q_m);
        self.blocks.arithmetic.q_1().push(inp.q_l);
        self.blocks.arithmetic.q_2().push(inp.q_r);
        self.blocks.arithmetic.q_3().push(inp.q_o);
        self.blocks.arithmetic.q_c().push(inp.q_c);
        self.blocks
            .arithmetic
            .q_delta_range()
            .push(P::ScalarField::zero());

        self.blocks.arithmetic.q_arith().push(P::ScalarField::one());
        self.blocks.arithmetic.q_4().push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_lookup_type()
            .push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_elliptic()
            .push(P::ScalarField::zero());
        self.blocks.arithmetic.q_aux().push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_poseidon2_external()
            .push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_poseidon2_internal()
            .push(P::ScalarField::zero());

        self.check_selector_length_consistency();
        self.num_gates += 1;
    }

    fn create_big_mul_gate(&mut self, inp: &MulQuad<P::ScalarField>) {
        self.assert_valid_variables(&[inp.a, inp.b, inp.c, inp.d]);

        self.blocks
            .arithmetic
            .populate_wires(inp.a, inp.b, inp.c, inp.d);
        self.blocks.arithmetic.q_m().push(inp.mul_scaling);
        self.blocks.arithmetic.q_1().push(inp.a_scaling);
        self.blocks.arithmetic.q_2().push(inp.b_scaling);
        self.blocks.arithmetic.q_3().push(inp.c_scaling);
        self.blocks.arithmetic.q_c().push(inp.const_scaling);
        self.blocks.arithmetic.q_arith().push(P::ScalarField::one());
        self.blocks.arithmetic.q_4().push(inp.d_scaling);
        self.blocks
            .arithmetic
            .q_delta_range()
            .push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_lookup_type()
            .push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_elliptic()
            .push(P::ScalarField::zero());
        self.blocks.arithmetic.q_aux().push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_poseidon2_external()
            .push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_poseidon2_internal()
            .push(P::ScalarField::zero());

        self.check_selector_length_consistency();
        self.num_gates += 1;
    }

    pub(crate) fn create_add_gate(&mut self, inp: &AddTriple<P::ScalarField>) {
        self.assert_valid_variables(&[inp.a, inp.b, inp.c]);

        self.blocks
            .arithmetic
            .populate_wires(inp.a, inp.b, inp.c, self.zero_idx);
        self.blocks.arithmetic.q_m().push(P::ScalarField::zero());
        self.blocks.arithmetic.q_1().push(inp.a_scaling);
        self.blocks.arithmetic.q_2().push(inp.b_scaling);
        self.blocks.arithmetic.q_3().push(inp.c_scaling);
        self.blocks.arithmetic.q_c().push(inp.const_scaling);
        self.blocks.arithmetic.q_arith().push(P::ScalarField::one());
        self.blocks.arithmetic.q_4().push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_delta_range()
            .push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_lookup_type()
            .push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_elliptic()
            .push(P::ScalarField::zero());
        self.blocks.arithmetic.q_aux().push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_poseidon2_external()
            .push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_poseidon2_internal()
            .push(P::ScalarField::zero());

        self.check_selector_length_consistency();
        self.num_gates += 1;
    }

    pub(crate) fn create_big_mul_add_gate(
        &mut self,
        inp: &MulQuad<P::ScalarField>,
        include_next_gate_w_4: bool,
    ) {
        self.assert_valid_variables(&[inp.a, inp.b, inp.c, inp.d]);
        self.blocks
            .arithmetic
            .populate_wires(inp.a, inp.b, inp.c, inp.d);
        self.blocks.arithmetic.q_m().push(if include_next_gate_w_4 {
            inp.mul_scaling * P::ScalarField::from(2u64)
        } else {
            inp.mul_scaling
        });
        self.blocks.arithmetic.q_1().push(inp.a_scaling);
        self.blocks.arithmetic.q_2().push(inp.b_scaling);
        self.blocks.arithmetic.q_3().push(inp.c_scaling);
        self.blocks.arithmetic.q_c().push(inp.const_scaling);
        self.blocks
            .arithmetic
            .q_arith()
            .push(if include_next_gate_w_4 {
                P::ScalarField::from(2u64)
            } else {
                P::ScalarField::one()
            });
        self.blocks.arithmetic.q_4().push(inp.d_scaling);
        self.blocks
            .arithmetic
            .q_delta_range()
            .push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_lookup_type()
            .push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_elliptic()
            .push(P::ScalarField::zero());
        self.blocks.arithmetic.q_aux().push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_poseidon2_external()
            .push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_poseidon2_internal()
            .push(P::ScalarField::zero());

        self.check_selector_length_consistency();

        self.num_gates += 1;
    }

    pub(crate) fn create_big_add_gate(
        &mut self,
        inp: &AddQuad<P::ScalarField>,
        include_next_gate_w_4: bool,
    ) {
        self.assert_valid_variables(&[inp.a, inp.b, inp.c, inp.d]);

        self.blocks
            .arithmetic
            .populate_wires(inp.a, inp.b, inp.c, inp.d);
        self.blocks.arithmetic.q_m().push(P::ScalarField::zero());
        self.blocks.arithmetic.q_1().push(inp.a_scaling);
        self.blocks.arithmetic.q_2().push(inp.b_scaling);
        self.blocks.arithmetic.q_3().push(inp.c_scaling);
        self.blocks.arithmetic.q_c().push(inp.const_scaling);
        self.blocks
            .arithmetic
            .q_arith()
            .push(if include_next_gate_w_4 {
                P::ScalarField::from(2u64)
            } else {
                P::ScalarField::one()
            });
        self.blocks.arithmetic.q_4().push(inp.d_scaling);
        self.blocks
            .arithmetic
            .q_delta_range()
            .push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_lookup_type()
            .push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_elliptic()
            .push(P::ScalarField::zero());
        self.blocks.arithmetic.q_aux().push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_poseidon2_external()
            .push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_poseidon2_internal()
            .push(P::ScalarField::zero());

        self.check_selector_length_consistency();
        self.num_gates += 1;
    }

    fn create_block_constraints(
        &mut self,
        constraint: &BlockConstraint<P::ScalarField>,
        has_valid_witness_assignments: bool,
        driver: &mut T,
    ) {
        let mut init = Vec::with_capacity(constraint.init.len());
        for inp in constraint.init.iter() {
            let value = self.poly_to_field_ct(inp);
            init.push(value);
        }

        // Note: CallData/ReturnData not supported by Ultra; interpreted as ROM ops instead
        match constraint.type_ {
            BlockType::CallData | BlockType::ReturnData | BlockType::ROM => {
                self.process_rom_operations(constraint, has_valid_witness_assignments, init, driver)
            }
            BlockType::RAM => todo!("BLOCK RAM constraint"),
        }
    }

    fn fix_witness(&mut self, witness_index: u32, witness_value: P::ScalarField) {
        self.assert_valid_variables(&[witness_index]);

        self.blocks.arithmetic.populate_wires(
            witness_index,
            self.zero_idx,
            self.zero_idx,
            self.zero_idx,
        );
        self.blocks.arithmetic.q_m().push(P::ScalarField::zero());
        self.blocks.arithmetic.q_1().push(P::ScalarField::one());
        self.blocks.arithmetic.q_2().push(P::ScalarField::zero());
        self.blocks.arithmetic.q_3().push(P::ScalarField::zero());
        self.blocks.arithmetic.q_c().push(-witness_value);
        self.blocks.arithmetic.q_arith().push(P::ScalarField::one());
        self.blocks.arithmetic.q_4().push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_delta_range()
            .push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_lookup_type()
            .push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_elliptic()
            .push(P::ScalarField::zero());
        self.blocks.arithmetic.q_aux().push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_poseidon2_external()
            .push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_poseidon2_internal()
            .push(P::ScalarField::zero());

        self.check_selector_length_consistency();
        self.num_gates += 1;
    }

    fn assert_valid_variables(&self, variable_indices: &[u32]) {
        for variable_index in variable_indices.iter().cloned() {
            assert!(self.is_valid_variable(variable_index as usize));
        }
    }

    fn is_valid_variable(&self, variable_index: usize) -> bool {
        variable_index < self.variables.len()
    }

    fn check_selector_length_consistency(&self) {
        for block in self.blocks.get() {
            let nominal_size = block.selectors[0].len();
            for selector in block.selectors.iter().skip(1) {
                debug_assert_eq!(selector.len(), nominal_size);
            }
        }
    }

    fn build_constraints(
        &mut self,
        driver: &mut T,
        mut constraint_system: AcirFormat<P::ScalarField>,
        has_valid_witness_assignments: bool,
        honk_recursion: bool,
        collect_gates_per_opcode: bool,
    ) -> std::io::Result<()> {
        tracing::trace!("Builder build constraints");
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

        // Oversize gates are a vector of mul_quad gates.
        for constraint in constraint_system.big_quad_constraints.iter_mut() {
            let mut next_w4_wire_value = T::AcvmType::default();
            // Define the 4th wire of these mul_quad gates, which is implicitly used by the previous gate.
            let constraint_size = constraint.len();
            for (j, small_constraint) in constraint.iter_mut().enumerate().take(constraint_size - 1)
            {
                if j == 0 {
                    next_w4_wire_value = self.get_variable(small_constraint.d.try_into().unwrap());
                } else {
                    let next_w4_wire = self.add_variable(next_w4_wire_value.to_owned());
                    small_constraint.d = next_w4_wire;
                    small_constraint.d_scaling = -P::ScalarField::one();
                }

                self.create_big_mul_add_gate(small_constraint, true);

                let var_a = self.get_variable(small_constraint.a.try_into().unwrap());
                let var_b = self.get_variable(small_constraint.b.try_into().unwrap());
                let var_c = self.get_variable(small_constraint.c.try_into().unwrap());

                let term1 = driver.mul(var_a.to_owned(), var_b.to_owned())?;
                let term1 = driver.mul_with_public(small_constraint.mul_scaling, term1);
                let term2 = driver.mul_with_public(small_constraint.a_scaling, var_a);
                let term3 = driver.mul_with_public(small_constraint.b_scaling, var_b);
                let term4 = driver.mul_with_public(small_constraint.c_scaling, var_c);
                let term5 = driver.mul_with_public(small_constraint.d_scaling, next_w4_wire_value);
                next_w4_wire_value = small_constraint.const_scaling.into();
                driver.add_assign(&mut next_w4_wire_value, term1);
                driver.add_assign(&mut next_w4_wire_value, term2);
                driver.add_assign(&mut next_w4_wire_value, term3);
                driver.add_assign(&mut next_w4_wire_value, term4);
                driver.add_assign(&mut next_w4_wire_value, term5);

                driver.negate_inplace(&mut next_w4_wire_value);
            }

            let next_w4_wire = self.add_variable(next_w4_wire_value);

            constraint.last_mut().unwrap().d = next_w4_wire;
            constraint.last_mut().unwrap().d_scaling = -P::ScalarField::one();

            self.create_big_mul_add_gate(constraint.last_mut().unwrap(), false);
        }

        // Add logic constraint
        // for (i, constraint) in constraint_system.logic_constraints.iter().enumerate() {
        //     todo!("Logic gates");
        // }

        for (i, constraint) in constraint_system.range_constraints.iter().enumerate() {
            self.create_range_constraint(driver, constraint.witness, constraint.num_bits)?;
            gate_counter.track_diff(
                self,
                &mut constraint_system.gates_per_opcode,
                constraint_system.original_opcode_indices.range_constraints[i],
            );
        }

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
            self.create_block_constraints(constraint, has_valid_witness_assignments, driver);
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
            self.assert_equal(
                constraint.a.try_into().unwrap(),
                constraint.b.try_into().unwrap(),
            );
            gate_counter.track_diff(
                self,
                &mut constraint_system.gates_per_opcode,
                constraint_system.original_opcode_indices.assert_equalities[i],
            );
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
        self.process_avm_recursion_constraints(
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
        Ok(())
    }

    fn process_plonk_recursion_constraints(
        &mut self,
        constraint_system: &AcirFormat<P::ScalarField>,
        _has_valid_witness_assignments: bool,
        _gate_counter: &mut GateCounter,
    ) {
        for _constraint in constraint_system.recursion_constraints.iter() {
            todo!("Plonk recursion");
        }
    }

    fn process_honk_recursion_constraints(
        &mut self,
        constraint_system: &AcirFormat<P::ScalarField>,
        _has_valid_witness_assignments: bool,
        _gate_counter: &mut GateCounter,
    ) {
        {
            for _constraint in constraint_system.honk_recursion_constraints.iter() {
                todo!("Honk recursion");
            }
        }
    }

    fn process_avm_recursion_constraints(
        &mut self,
        constraint_system: &AcirFormat<P::ScalarField>,
        _has_valid_witness_assignments: bool,
        _gate_counter: &mut GateCounter,
    ) {
        let _current_aggregation_object = self.init_default_agg_obj_indices();

        for _constraint in constraint_system.avm_recursion_constraints.iter() {
            todo!("avm recursion");
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

        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/911): These are pairing points extracted from a valid
        // proof. This is a workaround because we can't represent the point at infinity in biggroup yet.
        let mut agg_obj_indices = AggregationObjectIndices::default();
        let x0 = Utils::field_from_hex_string::<P::BaseField>(
            "0x031e97a575e9d05a107acb64952ecab75c020998797da7842ab5d6d1986846cf",
        )
        .expect("x0 works");
        let y0 = Utils::field_from_hex_string::<P::BaseField>(
            "0x178cbf4206471d722669117f9758a4c410db10a01750aebb5666547acf8bd5a4",
        )
        .expect("y0 works");
        let x1 = Utils::field_from_hex_string::<P::BaseField>(
            "0x0f94656a2ca489889939f81e9c74027fd51009034b3357f0e91b8a11e7842c38",
        )
        .expect("x1 works");
        let y1 = Utils::field_from_hex_string::<P::BaseField>(
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
                let idx = self.add_variable(T::AcvmType::from(val));
                agg_obj_indices[agg_obj_indices_idx] = idx;
                agg_obj_indices_idx += 1;
            }
        }
        agg_obj_indices
    }

    fn poly_to_field_ct(&self, poly: &PolyTriple<P::ScalarField>) -> FieldCT<P::ScalarField> {
        assert!(poly.q_m.is_zero());
        assert!(poly.q_r.is_zero());
        assert!(poly.q_o.is_zero());
        if poly.q_l.is_zero() {
            return FieldCT::from(poly.q_c);
        }

        let mut x = FieldCT::from_witness_index(poly.a);
        x.additive_constant = poly.q_c;
        x.multiplicative_constant = poly.q_l;
        x
    }

    fn process_rom_operations(
        &mut self,
        constraint: &BlockConstraint<P::ScalarField>,
        has_valid_witness_assignments: bool,
        init: Vec<FieldCT<P::ScalarField>>,
        driver: &mut T,
    ) {
        let mut table = RomTable::new(init);

        for op in constraint.trace.iter() {
            assert_eq!(op.access_type, 0);
            let value = self.poly_to_field_ct(&op.value);
            let index = self.poly_to_field_ct(&op.index);
            // For a ROM table, constant read should be optimized out:
            // The rom_table won't work with a constant read because the table may not be initialized
            assert!(!op.index.q_l.is_zero());
            // We create a new witness w to avoid issues with non-valid witness assignements:
            // if witness are not assigned, then w will be zero and table[w] will work
            let w_value = if has_valid_witness_assignments {
                // If witness are assigned, we use the correct value for w
                index.get_value(self, driver)
            } else {
                T::AcvmType::from(P::ScalarField::zero())
            };
            let w = FieldCT::from_witness(w_value, self);

            let extract = &table.index_field_ct(&w, self, driver);
            value.assert_equal(extract, self, driver);
            w.assert_equal(&index, self, driver);
        }
    }

    pub fn get_variable(&self, index: usize) -> T::AcvmType {
        assert!(self.variables.len() > index);
        self.variables[self.real_variable_index[index] as usize].to_owned()
    }

    fn update_variable(&mut self, index: usize, value: T::AcvmType) {
        assert!(self.variables.len() > index);
        self.variables[self.real_variable_index[index] as usize] = value;
    }

    pub(crate) fn assert_equal_constant(&mut self, a_idx: usize, b: P::ScalarField) {
        assert_eq!(self.variables[a_idx], T::AcvmType::from(b));
        let b_idx = self.put_constant_variable(b);
        self.assert_equal(a_idx, b_idx as usize);
    }

    pub(crate) fn assert_equal(&mut self, a_idx: usize, b_idx: usize) {
        self.is_valid_variable(a_idx);
        self.is_valid_variable(b_idx);

        let a = T::get_public(&self.get_variable(a_idx));

        let b = T::get_public(&self.get_variable(b_idx));

        match (a, b) {
            (Some(a), Some(b)) => {
                assert_eq!(a, b);
            }

            (Some(a), None) => {
                // The values are supposed to be equal. One is public though, one is private, so we can just set the private value to be the public one
                self.update_variable(b_idx, T::AcvmType::from(a));
            }
            (None, Some(b)) => {
                // The values are supposed to be equal. One is public though, one is private, so we can just set the private value to be the public one
                self.update_variable(a_idx, T::AcvmType::from(b));
            }
            _ => {
                // We can not check the equality of the witnesses since they are secret shared, but the proof will fail if they are not equal
            }
        }

        let a_real_idx = self.real_variable_index[a_idx] as usize;
        let b_real_idx = self.real_variable_index[b_idx] as usize;
        // If a==b is already enforced, exit method
        if a_real_idx == b_real_idx {
            return;
        }
        // Otherwise update the real_idx of b-chain members to that of a

        let b_start_idx = self.get_first_variable_in_class(b_idx);

        self.update_real_variable_indices(b_start_idx, a_real_idx as u32);

        // Now merge equivalence classes of a and b by tying last (= real) element of b-chain to first element of a-chain
        let a_start_idx = self.get_first_variable_in_class(a_idx);
        self.next_var_index[b_real_idx] = a_start_idx as u32;
        self.prev_var_index[a_start_idx] = b_real_idx as u32;
        assert!(
            self.real_variable_tags[a_real_idx] == Self::DUMMY_TAG
                || self.real_variable_tags[b_real_idx] == Self::DUMMY_TAG
                || self.real_variable_tags[a_real_idx] == self.real_variable_tags[b_real_idx]
        );

        if self.real_variable_tags[a_real_idx] == Self::DUMMY_TAG {
            self.real_variable_tags[a_real_idx] = self.real_variable_tags[b_real_idx];
        }
    }

    fn get_first_variable_in_class(&self, mut index: usize) -> usize {
        while self.prev_var_index[index] != Self::FIRST_VARIABLE_IN_CLASS {
            index = self.prev_var_index[index] as usize;
        }
        index
    }

    fn update_real_variable_indices(&mut self, index: usize, new_real_index: u32) {
        let mut cur_index = index;
        loop {
            self.real_variable_index[cur_index] = new_real_index;
            cur_index = self.next_var_index[cur_index] as usize;
            if cur_index == Self::REAL_VARIABLE as usize {
                break;
            }
        }
    }

    pub(crate) fn create_rom_array(&mut self, array_size: usize) -> usize {
        let mut new_transcript = RomTranscript::default();
        for _ in 0..array_size {
            new_transcript.state.push([
                Self::UNINITIALIZED_MEMORY_RECORD,
                Self::UNINITIALIZED_MEMORY_RECORD,
            ]);
        }
        self.rom_arrays.push(new_transcript);
        self.rom_arrays.len() - 1
    }

    pub(crate) fn set_rom_element(
        &mut self,
        rom_id: usize,
        index_value: usize,
        value_witness: u32,
    ) {
        assert!(self.rom_arrays.len() > rom_id);
        let index_witness = if index_value == 0 {
            self.zero_idx
        } else {
            self.put_constant_variable(P::ScalarField::from(index_value as u64))
        };

        assert!(self.rom_arrays[rom_id].state.len() > index_value);
        assert!(self.rom_arrays[rom_id].state[index_value][0] == Self::UNINITIALIZED_MEMORY_RECORD);
        // /**
        // * The structure MemoryRecord contains the following members in this order:
        // *   uint32_t index_witness;
        // *   uint32_t timestamp_witness;
        // *   uint32_t value_witness;
        // *   uint32_t index;
        // *   uint32_t timestamp;
        // *   uint32_t record_witness;
        // *   size_t gate_index;
        // * The second initialization value here is the witness, because in ROM it doesn't matter. We will decouple this
        // * logic later.
        // */
        let mut new_record = RomRecord {
            index_witness,
            value_column1_witness: value_witness,
            value_column2_witness: self.zero_idx,
            index: index_value as u32,
            record_witness: 0,
            gate_index: 0,
        };

        self.rom_arrays[rom_id].state[index_value][0] = value_witness;
        self.rom_arrays[rom_id].state[index_value][1] = self.zero_idx;
        self.create_rom_gate(&mut new_record);
        self.rom_arrays[rom_id].records.push(new_record);
    }

    fn set_rom_element_pair(
        &mut self,
        rom_id: usize,
        index_value: usize,
        value_witnesses: [u32; 2],
    ) {
        assert!(self.rom_arrays.len() > rom_id);
        let index_witness = if index_value == 0 {
            self.zero_idx
        } else {
            self.put_constant_variable(P::ScalarField::from(index_value as u64))
        };

        assert!(self.rom_arrays[rom_id].state.len() > index_value);
        assert!(self.rom_arrays[rom_id].state[index_value][0] == Self::UNINITIALIZED_MEMORY_RECORD);

        let mut new_record = RomRecord {
            index_witness,
            value_column1_witness: value_witnesses[0],
            value_column2_witness: value_witnesses[1],
            index: index_value as u32,
            record_witness: 0,
            gate_index: 0,
        };

        self.rom_arrays[rom_id].state[index_value][0] = value_witnesses[0];
        self.rom_arrays[rom_id].state[index_value][1] = value_witnesses[1];
        self.create_rom_gate(&mut new_record);
        self.rom_arrays[rom_id].records.push(new_record);
    }

    fn create_rom_gate(&mut self, record: &mut RomRecord) {
        // Record wire value can't yet be computed
        record.record_witness = self.add_variable(T::AcvmType::from(P::ScalarField::zero()));
        self.apply_aux_selectors(AuxSelectors::RomRead);
        self.blocks.aux.populate_wires(
            record.index_witness,
            record.value_column1_witness,
            record.value_column2_witness,
            record.record_witness,
        );

        // Note: record the index into the block that contains the RAM/ROM gates
        record.gate_index = self.blocks.aux.len() - 1;
        self.num_gates += 1;
    }

    pub(crate) fn read_rom_array(
        &mut self,
        rom_id: usize,
        index_witness: u32,
    ) -> HonkProofResult<u32> {
        assert!(self.rom_arrays.len() > rom_id);
        let val: BigUint = T::get_public(&self.get_variable(index_witness as usize))
            .ok_or(HonkProofError::ExpectedPublicWitness)?
            .into();
        let index: usize = val.try_into().unwrap();

        assert!(self.rom_arrays[rom_id].state.len() > index);
        assert!(self.rom_arrays[rom_id].state[index][0] != Self::UNINITIALIZED_MEMORY_RECORD);
        let value = self.get_variable(self.rom_arrays[rom_id].state[index][0] as usize);
        let value_witness = self.add_variable(value);

        let mut new_record = RomRecord {
            index_witness,
            value_column1_witness: value_witness,
            value_column2_witness: self.zero_idx,
            index: index as u32,
            record_witness: 0,
            gate_index: 0,
        };
        self.create_rom_gate(&mut new_record);
        self.rom_arrays[rom_id].records.push(new_record);

        // create_read_gate
        Ok(value_witness)
    }

    fn apply_aux_selectors(&mut self, type_: AuxSelectors) {
        let block = &mut self.blocks.aux;
        block.q_aux().push(if type_ == AuxSelectors::None {
            P::ScalarField::zero()
        } else {
            P::ScalarField::one()
        });
        // Set to zero the selectors that are not enabled for this gate
        block.q_delta_range().push(P::ScalarField::zero());
        block.q_lookup_type().push(P::ScalarField::zero());
        block.q_elliptic().push(P::ScalarField::zero());
        block.q_poseidon2_external().push(P::ScalarField::zero());
        block.q_poseidon2_internal().push(P::ScalarField::zero());

        match type_ {
            AuxSelectors::RomRead => {
                // Memory read gate for reading memory cells.
                // Validates record witness computation (r = read_write_flag + index * \eta + timestamp * \eta^2 + value *
                // \eta^3)
                block.q_1().push(P::ScalarField::one());
                block.q_2().push(P::ScalarField::zero());
                block.q_3().push(P::ScalarField::zero());
                block.q_4().push(P::ScalarField::zero());
                block.q_m().push(P::ScalarField::one()); // validate record witness is correctly computed
                block.q_c().push(P::ScalarField::zero()); // read/write flag stored in q_c
                block.q_arith().push(P::ScalarField::zero());

                self.check_selector_length_consistency();
            }
            AuxSelectors::RomConsistencyCheck => {
                // Memory read gate used with the sorted list of memory reads.
                // Apply sorted memory read checks with the following additional check:
                // 1. Assert that if index field across two gates does not change, the value field does not change.
                // Used for ROM reads and RAM reads across write/read boundaries
                block.q_1().push(P::ScalarField::one());
                block.q_2().push(P::ScalarField::one());
                block.q_3().push(P::ScalarField::zero());
                block.q_4().push(P::ScalarField::zero());
                block.q_m().push(P::ScalarField::zero());
                block.q_c().push(P::ScalarField::zero());
                block.q_arith().push(P::ScalarField::zero());
                self.check_selector_length_consistency();
            }
            _ => todo!("Aux selectors"),
        }
    }

    fn create_dummy_gate(
        // &mut self,
        block: &mut UltraTraceBlock<P::ScalarField>,
        idx_1: u32,
        idx_2: u32,
        idx_3: u32,
        idx_4: u32,
    ) {
        block.populate_wires(idx_1, idx_2, idx_3, idx_4);
        block.q_m().push(P::ScalarField::zero());
        block.q_1().push(P::ScalarField::zero());
        block.q_2().push(P::ScalarField::zero());
        block.q_3().push(P::ScalarField::zero());
        block.q_c().push(P::ScalarField::zero());
        block.q_arith().push(P::ScalarField::zero());
        block.q_4().push(P::ScalarField::zero());
        block.q_delta_range().push(P::ScalarField::zero());
        block.q_elliptic().push(P::ScalarField::zero());
        block.q_lookup_type().push(P::ScalarField::zero());
        block.q_aux().push(P::ScalarField::zero());
        block.q_poseidon2_external().push(P::ScalarField::zero());
        block.q_poseidon2_internal().push(P::ScalarField::zero());

        // TACEO TODO these are uncommented due to mutability issues
        // Taken care of by the caller uisng the create_dummy_gate! macro
        // self.check_selector_length_consistency();
        // self.num_gates += 1;
    }

    pub fn add_gates_to_ensure_all_polys_are_non_zero(&mut self) {
        // q_m, q_1, q_2, q_3, q_4
        self.blocks.arithmetic.populate_wires(
            self.zero_idx,
            self.zero_idx,
            self.zero_idx,
            self.zero_idx,
        );
        self.blocks.arithmetic.q_m().push(P::ScalarField::one());
        self.blocks.arithmetic.q_1().push(P::ScalarField::one());
        self.blocks.arithmetic.q_2().push(P::ScalarField::one());
        self.blocks.arithmetic.q_3().push(P::ScalarField::one());
        self.blocks.arithmetic.q_4().push(P::ScalarField::one());
        self.blocks.arithmetic.q_c().push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_delta_range()
            .push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_arith()
            .push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_lookup_type()
            .push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_elliptic()
            .push(P::ScalarField::zero());
        self.blocks.arithmetic.q_aux().push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_poseidon2_external()
            .push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_poseidon2_internal()
            .push(P::ScalarField::zero());

        self.check_selector_length_consistency();
        self.num_gates += 1;

        // q_delta_range
        self.blocks.delta_range.populate_wires(
            self.zero_idx,
            self.zero_idx,
            self.zero_idx,
            self.zero_idx,
        );
        self.blocks.delta_range.q_m().push(P::ScalarField::zero());
        self.blocks.delta_range.q_1().push(P::ScalarField::zero());
        self.blocks.delta_range.q_2().push(P::ScalarField::zero());
        self.blocks.delta_range.q_3().push(P::ScalarField::zero());
        self.blocks.delta_range.q_4().push(P::ScalarField::zero());
        self.blocks.delta_range.q_c().push(P::ScalarField::zero());
        self.blocks
            .delta_range
            .q_delta_range()
            .push(P::ScalarField::one());
        self.blocks
            .delta_range
            .q_arith()
            .push(P::ScalarField::zero());
        self.blocks
            .delta_range
            .q_lookup_type()
            .push(P::ScalarField::zero());
        self.blocks
            .delta_range
            .q_elliptic()
            .push(P::ScalarField::zero());
        self.blocks.delta_range.q_aux().push(P::ScalarField::zero());
        self.blocks
            .delta_range
            .q_poseidon2_external()
            .push(P::ScalarField::zero());
        self.blocks
            .delta_range
            .q_poseidon2_internal()
            .push(P::ScalarField::zero());

        self.check_selector_length_consistency();
        self.num_gates += 1;

        create_dummy_gate!(
            self,
            &mut self.blocks.delta_range,
            self.zero_idx,
            self.zero_idx,
            self.zero_idx,
            self.zero_idx,
        );

        // q_elliptic
        self.blocks.elliptic.populate_wires(
            self.zero_idx,
            self.zero_idx,
            self.zero_idx,
            self.zero_idx,
        );
        self.blocks.elliptic.q_m().push(P::ScalarField::zero());
        self.blocks.elliptic.q_1().push(P::ScalarField::zero());
        self.blocks.elliptic.q_2().push(P::ScalarField::zero());
        self.blocks.elliptic.q_3().push(P::ScalarField::zero());
        self.blocks.elliptic.q_4().push(P::ScalarField::zero());
        self.blocks.elliptic.q_c().push(P::ScalarField::zero());
        self.blocks
            .elliptic
            .q_delta_range()
            .push(P::ScalarField::zero());
        self.blocks.elliptic.q_arith().push(P::ScalarField::zero());
        self.blocks
            .elliptic
            .q_lookup_type()
            .push(P::ScalarField::zero());
        self.blocks
            .elliptic
            .q_elliptic()
            .push(P::ScalarField::one());
        self.blocks.elliptic.q_aux().push(P::ScalarField::zero());
        self.blocks
            .elliptic
            .q_poseidon2_external()
            .push(P::ScalarField::zero());
        self.blocks
            .elliptic
            .q_poseidon2_internal()
            .push(P::ScalarField::zero());

        self.check_selector_length_consistency();
        self.num_gates += 1;

        create_dummy_gate!(
            self,
            &mut self.blocks.elliptic,
            self.zero_idx,
            self.zero_idx,
            self.zero_idx,
            self.zero_idx,
        );

        // q_aux
        self.blocks
            .aux
            .populate_wires(self.zero_idx, self.zero_idx, self.zero_idx, self.zero_idx);
        self.blocks.aux.q_m().push(P::ScalarField::zero());
        self.blocks.aux.q_1().push(P::ScalarField::zero());
        self.blocks.aux.q_2().push(P::ScalarField::zero());
        self.blocks.aux.q_3().push(P::ScalarField::zero());
        self.blocks.aux.q_4().push(P::ScalarField::zero());
        self.blocks.aux.q_c().push(P::ScalarField::zero());
        self.blocks.aux.q_delta_range().push(P::ScalarField::zero());
        self.blocks.aux.q_arith().push(P::ScalarField::zero());
        self.blocks.aux.q_lookup_type().push(P::ScalarField::zero());
        self.blocks.aux.q_elliptic().push(P::ScalarField::zero());
        self.blocks.aux.q_aux().push(P::ScalarField::one());
        self.blocks
            .aux
            .q_poseidon2_external()
            .push(P::ScalarField::zero());
        self.blocks
            .aux
            .q_poseidon2_internal()
            .push(P::ScalarField::zero());

        self.check_selector_length_consistency();
        self.num_gates += 1;

        create_dummy_gate!(
            self,
            &mut self.blocks.aux,
            self.zero_idx,
            self.zero_idx,
            self.zero_idx,
            self.zero_idx,
        );

        // Add nonzero values in w_4 and q_c (q_4*w_4 + q_c --> 1*1 - 1 = 0)
        self.one_idx = self.put_constant_variable(P::ScalarField::one());
        self.create_big_add_gate(
            &AddQuad {
                a: self.zero_idx,
                b: self.zero_idx,
                c: self.zero_idx,
                d: self.one_idx,
                a_scaling: P::ScalarField::zero(),
                b_scaling: P::ScalarField::zero(),
                c_scaling: P::ScalarField::zero(),
                d_scaling: P::ScalarField::one(),
                const_scaling: -P::ScalarField::one(),
            },
            false,
        );

        // Take care of all polys related to lookups (q_lookup, tables, sorted, etc)
        // by doing a dummy lookup with a special table.
        // Note: the 4th table poly is the table index: this is not the value of the table
        // type enum but rather the index of the table in the list of all tables utilized
        // in the circuit. Therefore we naively need two different basic tables (indices 0, 1)
        // to get a non-zero value in table_4.
        // The multitable operates on 2-bit values, so the maximum is 3
        let left_value = 3;
        let right_value = 3;

        let left_witness_value = P::ScalarField::from(left_value as u64);
        let right_witness_value = P::ScalarField::from(right_value as u64);

        let left_witness_index = self.add_variable(T::AcvmType::from(left_witness_value));
        let right_witness_index = self.add_variable(T::AcvmType::from(right_witness_value));

        let dummy_accumulators = self.plookup.get_lookup_accumulators(
            MultiTableId::HonkDummyMulti,
            left_witness_value,
            right_witness_value,
            true,
        );
        self.create_gates_from_plookup_accumulators(
            MultiTableId::HonkDummyMulti,
            dummy_accumulators,
            left_witness_index,
            Some(right_witness_index),
        );

        // mock a poseidon external gate, with all zeros as input
        self.blocks.poseidon2_external.populate_wires(
            self.zero_idx,
            self.zero_idx,
            self.zero_idx,
            self.zero_idx,
        );
        self.blocks
            .poseidon2_external
            .q_m()
            .push(P::ScalarField::zero());
        self.blocks
            .poseidon2_external
            .q_1()
            .push(P::ScalarField::zero());
        self.blocks
            .poseidon2_external
            .q_2()
            .push(P::ScalarField::zero());
        self.blocks
            .poseidon2_external
            .q_3()
            .push(P::ScalarField::zero());
        self.blocks
            .poseidon2_external
            .q_c()
            .push(P::ScalarField::zero());
        self.blocks
            .poseidon2_external
            .q_arith()
            .push(P::ScalarField::zero());
        self.blocks
            .poseidon2_external
            .q_4()
            .push(P::ScalarField::zero());
        self.blocks
            .poseidon2_external
            .q_delta_range()
            .push(P::ScalarField::zero());
        self.blocks
            .poseidon2_external
            .q_lookup_type()
            .push(P::ScalarField::zero());
        self.blocks
            .poseidon2_external
            .q_elliptic()
            .push(P::ScalarField::zero());
        self.blocks
            .poseidon2_external
            .q_aux()
            .push(P::ScalarField::zero());
        self.blocks
            .poseidon2_external
            .q_poseidon2_external()
            .push(P::ScalarField::one());
        self.blocks
            .poseidon2_external
            .q_poseidon2_internal()
            .push(P::ScalarField::zero());

        self.check_selector_length_consistency();
        self.num_gates += 1;

        // dummy gate to be read into by previous poseidon external gate via shifts
        create_dummy_gate!(
            self,
            &mut self.blocks.poseidon2_external,
            self.zero_idx,
            self.zero_idx,
            self.zero_idx,
            self.zero_idx,
        );

        // mock a poseidon internal gate, with all zeros as input
        self.blocks.poseidon2_internal.populate_wires(
            self.zero_idx,
            self.zero_idx,
            self.zero_idx,
            self.zero_idx,
        );
        self.blocks
            .poseidon2_internal
            .q_m()
            .push(P::ScalarField::zero());
        self.blocks
            .poseidon2_internal
            .q_1()
            .push(P::ScalarField::zero());
        self.blocks
            .poseidon2_internal
            .q_2()
            .push(P::ScalarField::zero());
        self.blocks
            .poseidon2_internal
            .q_3()
            .push(P::ScalarField::zero());
        self.blocks
            .poseidon2_internal
            .q_c()
            .push(P::ScalarField::zero());
        self.blocks
            .poseidon2_internal
            .q_arith()
            .push(P::ScalarField::zero());
        self.blocks
            .poseidon2_internal
            .q_4()
            .push(P::ScalarField::zero());
        self.blocks
            .poseidon2_internal
            .q_delta_range()
            .push(P::ScalarField::zero());
        self.blocks
            .poseidon2_internal
            .q_lookup_type()
            .push(P::ScalarField::zero());
        self.blocks
            .poseidon2_internal
            .q_elliptic()
            .push(P::ScalarField::zero());
        self.blocks
            .poseidon2_internal
            .q_aux()
            .push(P::ScalarField::zero());
        self.blocks
            .poseidon2_internal
            .q_poseidon2_external()
            .push(P::ScalarField::zero());
        self.blocks
            .poseidon2_internal
            .q_poseidon2_internal()
            .push(P::ScalarField::one());

        self.check_selector_length_consistency();
        self.num_gates += 1;

        // dummy gate to be read into by previous poseidon internal gate via shifts
        create_dummy_gate!(
            self,
            &mut self.blocks.poseidon2_internal,
            self.zero_idx,
            self.zero_idx,
            self.zero_idx,
            self.zero_idx,
        );
    }

    pub fn get_num_gates_added_to_ensure_nonzero_polynomials() -> usize {
        let mut builder = Self::new(0);
        let num_gates_prior = builder.get_num_gates();
        builder.add_gates_to_ensure_all_polys_are_non_zero();
        let num_gates_post = builder.get_num_gates(); // accounts for finalization gates

        num_gates_post - num_gates_prior
    }

    pub fn get_circuit_subgroup_size(num_gates: usize) -> usize {
        let mut log2_n = Utils::get_msb64(num_gates as u64);
        if (1 << log2_n) != num_gates {
            log2_n += 1;
        }
        1 << log2_n
    }

    pub fn get_total_circuit_size(&self) -> usize {
        let minimum_circuit_size = self.get_tables_size() + self.get_lookups_size();
        let num_filled_gates = self.get_num_gates() + self.public_inputs.len();
        std::cmp::max(minimum_circuit_size, num_filled_gates) + Self::NUM_RESERVED_GATES
    }

    fn get_table(&mut self, id: BasicTableId) -> &mut PlookupBasicTable<P::ScalarField> {
        let mut index = self.lookup_tables.len();
        for (i, table) in self.lookup_tables.iter().enumerate() {
            if table.id == id {
                index = i;
                break;
            }
        }

        let len = self.lookup_tables.len();
        if index == len {
            // Table doesn't exist! So try to create it.
            self.lookup_tables
                .push(PlookupBasicTable::create_basic_table(id, len));
            self.lookup_tables.last_mut().unwrap()
        } else {
            &mut self.lookup_tables[index]
        }
    }

    fn create_gates_from_plookup_accumulators(
        &mut self,
        id: MultiTableId,
        read_values: ReadData<P::ScalarField>,
        key_a_index: u32,
        key_b_index: Option<u32>,
    ) -> ReadData<u32> {
        let id_usize = id as usize;

        let num_lookups = read_values[ColumnIdx::C1].len();
        let mut read_data = ReadData::default();

        for i in 0..num_lookups {
            // get basic lookup table; construct and add to builder.lookup_tables if not already present

            let basic_table_id = self.plookup.multi_tables[id_usize].basic_table_ids[i].clone();
            let table = self.get_table(basic_table_id);

            table
                .lookup_gates
                .push(read_values.lookup_entries[i].to_owned()); // used for constructing sorted polynomials
            let table_index = table.table_index;

            let first_idx = if i == 0 {
                key_a_index
            } else {
                self.add_variable(T::AcvmType::from(read_values[ColumnIdx::C1][i]))
            };

            #[expect(clippy::unnecessary_unwrap)]
            let second_idx = if i == 0 && (key_b_index.is_some()) {
                key_b_index.unwrap()
            } else {
                self.add_variable(T::AcvmType::from(read_values[ColumnIdx::C2][i]))
            };
            let third_idx = self.add_variable(T::AcvmType::from(read_values[ColumnIdx::C3][i]));

            read_data[ColumnIdx::C1].push(first_idx);
            read_data[ColumnIdx::C2].push(second_idx);
            read_data[ColumnIdx::C3].push(third_idx);
            self.assert_valid_variables(&[first_idx, second_idx, third_idx]);

            self.blocks
                .lookup
                .q_lookup_type()
                .push(P::ScalarField::one());
            self.blocks
                .lookup
                .q_3()
                .push(P::ScalarField::from(table_index as u64));
            self.blocks
                .lookup
                .populate_wires(first_idx, second_idx, third_idx, self.zero_idx);
            self.blocks.lookup.q_1().push(P::ScalarField::zero());
            self.blocks.lookup.q_2().push(if i == (num_lookups - 1) {
                P::ScalarField::zero()
            } else {
                -self.plookup.multi_tables[id_usize].column_1_step_sizes[i + 1]
            });
            self.blocks.lookup.q_m().push(if i == (num_lookups - 1) {
                P::ScalarField::zero()
            } else {
                -self.plookup.multi_tables[id_usize].column_2_step_sizes[i + 1]
            });
            self.blocks.lookup.q_c().push(if i == (num_lookups - 1) {
                P::ScalarField::zero()
            } else {
                -self.plookup.multi_tables[id_usize].column_3_step_sizes[i + 1]
            });
            self.blocks.lookup.q_arith().push(P::ScalarField::zero());
            self.blocks.lookup.q_4().push(P::ScalarField::zero());
            self.blocks
                .lookup
                .q_delta_range()
                .push(P::ScalarField::zero());
            self.blocks.lookup.q_elliptic().push(P::ScalarField::zero());
            self.blocks.lookup.q_aux().push(P::ScalarField::zero());
            self.blocks
                .lookup
                .q_poseidon2_external()
                .push(P::ScalarField::zero());
            self.blocks
                .lookup
                .q_poseidon2_internal()
                .push(P::ScalarField::zero());

            self.check_selector_length_consistency();
            self.num_gates += 1;
        }
        read_data
    }

    pub fn finalize_circuit(
        &mut self,
        ensure_nonzero: bool,
        driver: &mut T,
    ) -> std::io::Result<()> {
        // /**
        //  * First of all, add the gates related to ROM arrays and range lists.
        //  * Note that the total number of rows in an UltraPlonk program can be divided as following:
        //  *  1. arithmetic gates:  n_computation (includes all computation gates)
        //  *  2. rom/memory gates:  n_rom
        //  *  3. range list gates:  n_range
        //  *  4. public inputs:     n_pub
        //  *
        //  * Now we have two variables referred to as `n` in the code:
        //  *  1. ComposerBase::n => refers to the size of the witness of a given program,
        //  *  2. proving_key::n => the next power of two ≥ total witness size.
        //  *
        //  * In this case, we have composer.num_gates = n_computation before we execute the following two functions.
        //  * After these functions are executed, the composer's `n` is incremented to include the ROM
        //  * and range list gates. Therefore we have:
        //  * composer.num_gates = n_computation + n_rom + n_range.
        //  *
        //  * Its necessary to include the (n_rom + n_range) gates at this point because if we already have a
        //  * proving key, and we just return it without including these ROM and range list gates, the overall
        //  * circuit size would not be correct (resulting in the code crashing while performing FFT
        //  * operations).
        //  *
        //  * Therefore, we introduce a boolean flag `circuit_finalized` here. Once we add the rom and range gates,
        //  * our circuit is finalized, and we must not to execute these functions again.
        //  */
        if self.circuit_finalized {
            // Gates added after first call to finalize will not be processed since finalization is only performed once
            tracing::warn!("WARNING: Redundant call to finalize_circuit(). Is this intentional?");
        } else {
            if ensure_nonzero {
                self.add_gates_to_ensure_all_polys_are_non_zero();
            }

            self.process_non_native_field_multiplications();
            self.process_rom_arrays()?;
            self.process_ram_arrays();
            self.process_range_lists(driver)?;
            self.circuit_finalized = true;
        }
        Ok(())
    }

    fn process_rom_arrays(&mut self) -> std::io::Result<()> {
        for i in 0..self.rom_arrays.len() {
            self.process_rom_array(i)?;
        }
        Ok(())
    }

    fn process_ram_arrays(&mut self) {
        for _ in self.ram_arrays.iter() {
            todo!("process ram array");
        }
    }

    fn process_range_lists(&mut self, driver: &mut T) -> std::io::Result<()> {
        // We copy due to mutability issues
        let mut lists = self
            .range_lists
            .iter_mut()
            .map(|(_, list)| list.clone())
            .collect::<Vec<_>>();

        for list in lists.iter_mut() {
            self.process_range_list(list, driver)?;
        }
        // We copy back (not strictly necessary, but should take no performance)
        for (src, des) in lists.into_iter().zip(self.range_lists.iter_mut()) {
            *des.1 = src;
        }
        Ok(())
    }

    fn process_rom_array(&mut self, rom_id: usize) -> std::io::Result<()> {
        let read_tag = self.get_new_tag(); // current_tag + 1;
        let sorted_list_tag = self.get_new_tag(); // current_tag + 2;
        self.create_tag(read_tag, sorted_list_tag);
        self.create_tag(sorted_list_tag, read_tag);

        // Make sure that every cell has been initialized
        for i in 0..self.rom_arrays[rom_id].state.len() {
            if self.rom_arrays[rom_id].state[i][0] == Self::UNINITIALIZED_MEMORY_RECORD {
                self.set_rom_element_pair(rom_id, i, [self.zero_idx, self.zero_idx]);
            }
        }
        self.rom_arrays[rom_id].records.sort();
        let records = self.rom_arrays[rom_id].records.clone();
        for record in records {
            let index = record.index;
            let value1 = self.get_variable(record.value_column1_witness.try_into().unwrap());
            let value2 = self.get_variable(record.value_column2_witness.try_into().unwrap());
            let index_witness = self.add_variable(T::AcvmType::from(P::ScalarField::from(index)));

            let value1_witness = self.add_variable(value1);

            let value2_witness = self.add_variable(value2);

            let mut sorted_record = RomRecord {
                index_witness,
                value_column1_witness: value1_witness,
                value_column2_witness: value2_witness,
                index,
                record_witness: 0,
                gate_index: 0,
            };
            self.create_sorted_rom_gate(&mut sorted_record);

            self.assign_tag(record.record_witness, read_tag);
            self.assign_tag(sorted_record.record_witness, sorted_list_tag);

            // For ROM/RAM gates, the 'record' wire value (wire column 4) is a linear combination of the first 3 wire
            // values. However...the record value uses the random challenge 'eta', generated after the first 3 wires are
            // committed to. i.e. we can't compute the record witness here because we don't know what `eta` is! Take the
            // gate indices of the two rom gates (original read gate + sorted gate) and store in `memory_records`. Once
            // we
            // generate the `eta` challenge, we'll use `memory_records` to figure out which gates need a record wire
            // value
            // to be computed.
            // record (w4) = w3 * eta^3 + w2 * eta^2 + w1 * eta + read_write_flag (0 for reads, 1 for writes)
            // Separate containers used to store gate indices of reads and writes. Need to differentiate because of
            // `read_write_flag` (N.B. all ROM accesses are considered reads. Writes are for RAM operations)
            self.memory_read_records
                .push(sorted_record.gate_index as u32);
            self.memory_read_records.push(record.gate_index as u32);
        }
        // One of the checks we run on the sorted list, is to validate the difference between
        // the index field across two gates is either 0 or 1.
        // If we add a dummy gate at the end of the sorted list, where we force the first wire to
        // equal `m + 1`, where `m` is the maximum allowed index in the sorted list,
        // we have validated that all ROM reads are correctly constrained
        let max_index_value = self.rom_arrays[rom_id].state.len() as u64;
        let max_index: u32 =
            self.add_variable(T::AcvmType::from(P::ScalarField::from(max_index_value)));

        // TODO(https://github.com/AztecProtocol/barretenberg/issues/879): This was formerly a single arithmetic gate. A
        // dummy gate has been added to allow the previous gate to access the required wire data via shifts, allowing the
        // arithmetic gate to occur out of sequence.
        create_dummy_gate!(
            self,
            &mut self.blocks.aux,
            max_index,
            self.zero_idx,
            self.zero_idx,
            self.zero_idx,
        );
        self.create_big_add_gate(
            &AddQuad {
                a: max_index,
                b: self.zero_idx,
                c: self.zero_idx,
                d: self.zero_idx,
                a_scaling: P::ScalarField::one(),
                b_scaling: P::ScalarField::zero(),
                c_scaling: P::ScalarField::zero(),
                d_scaling: P::ScalarField::zero(),
                const_scaling: -P::ScalarField::from(max_index_value),
            },
            false,
        );
        // N.B. If the above check holds, we know the sorted list begins with an index value of 0,
        // because the first cell is explicitly initialized using zero_idx as the index field.
        Ok(())
    }
    fn create_sorted_rom_gate(&mut self, record: &mut RomRecord) {
        record.record_witness = self.add_variable(T::AcvmType::from(P::ScalarField::zero()));

        self.apply_aux_selectors(AuxSelectors::RomConsistencyCheck);
        self.blocks.aux.populate_wires(
            record.index_witness,
            record.value_column1_witness,
            record.value_column2_witness,
            record.record_witness,
        );

        // Note: record the index into the block that contains the RAM/ROM gates
        record.gate_index = self.blocks.aux.len() - 1;
        self.num_gates += 1;
    }

    fn process_range_list(&mut self, list: &mut RangeList, driver: &mut T) -> std::io::Result<()> {
        self.assert_valid_variables(&list.variable_indices);

        assert!(
            !list.variable_indices.is_empty(),
            "variable_indices must not be empty"
        );

        // replace witness index in variable_indices with the real variable index i.e. if a copy constraint has been
        // applied on a variable after it was range constrained, this makes sure the indices in list point to the updated
        // index in the range list so the set equivalence does not fail
        for x in list.variable_indices.iter_mut() {
            *x = self.real_variable_index[*x as usize];
        }

        // remove duplicate witness indices to prevent the sorted list set size being wrong!
        list.variable_indices.sort();
        list.variable_indices.dedup();
        // go over variables
        // iterate over each variable and create mirror variable with same value - with tau tag
        // need to make sure that, in original list, increments of at most 3
        let mut sorted_list = Vec::with_capacity(list.variable_indices.len());
        for &variable_index in &list.variable_indices {
            let field_element = self.get_variable(variable_index as usize);

            let field_element = if T::is_shared(&field_element) {
                T::get_shared(&field_element).expect("Already checked it is shared")
            } else {
                T::promote_to_trivial_share(
                    driver,
                    T::get_public(&field_element).expect("Already checked it is public"),
                )
            };
            sorted_list.push(field_element);
        }

        let sorted_list = T::sort(
            driver,
            &sorted_list,
            Utils::get_msb64(list.target_range.next_power_of_two()) as usize,
        )?;

        // list must be padded to a multipe of 4 and larger than 4 (gate_width)
        const GATE_WIDTH: usize = NUM_WIRES;
        let mut padding = (GATE_WIDTH - (list.variable_indices.len() % GATE_WIDTH)) % GATE_WIDTH;
        let mut indices = Vec::with_capacity(padding + sorted_list.len());

        // Ensure the list size is greater than GATE_WIDTH and pad it

        if list.variable_indices.len() <= GATE_WIDTH {
            padding += GATE_WIDTH;
        }
        for _ in 0..padding {
            indices.push(self.zero_idx);
        }
        for sorted_value in sorted_list {
            let promoted = T::AcvmType::from(sorted_value);
            let index = self.add_variable(promoted);
            self.assign_tag(index, list.tau_tag);
            indices.push(index);
        }

        self.create_sort_constraint_with_edges(
            &indices,
            P::ScalarField::zero(),
            list.target_range.into(),
        );
        Ok(())
    }

    fn process_non_native_field_multiplications(&mut self) {
        for c in self
            .cached_partial_non_native_field_multiplications
            .iter_mut()
        {
            for i in 0..5 {
                c.a[i] = self.real_variable_index[c.a[i] as usize];
                c.b[i] = self.real_variable_index[c.b[i] as usize];
            }
        }
        let mut dedup = CachedPartialNonNativeFieldMultiplication::deduplicate(
            &self.cached_partial_non_native_field_multiplications,
        );

        // iterate over the cached items and create constraints
        for input in dedup.iter() {
            let input_lo_0: BigUint = input.lo_0.into();
            let input_lo_0: u32 = input_lo_0.try_into().expect("Invalid index");

            self.blocks
                .aux
                .populate_wires(input.a[1], input.b[1], self.zero_idx, input_lo_0);
            self.apply_aux_selectors(AuxSelectors::NonNativeField1);
            self.num_gates += 1;

            self.blocks
                .aux
                .populate_wires(input.a[0], input.b[0], input.a[3], input.b[3]);
            self.apply_aux_selectors(AuxSelectors::NonNativeField2);
            self.num_gates += 1;

            let input_hi_0: BigUint = input.hi_0.into();
            let input_hi_0: u32 = input_hi_0.try_into().expect("Invalid index");

            self.blocks
                .aux
                .populate_wires(input.a[2], input.b[2], self.zero_idx, input_hi_0);
            self.apply_aux_selectors(AuxSelectors::NonNativeField2);
            self.num_gates += 1;

            let input_hi_1: BigUint = input.hi_1.into();
            let input_hi_1: u32 = input_hi_1.try_into().expect("Invalid index");

            self.blocks
                .aux
                .populate_wires(input.a[1], input.b[1], self.zero_idx, input_hi_1);
            self.apply_aux_selectors(AuxSelectors::None);
            self.num_gates += 1;
        }
        std::mem::swap(
            &mut self.cached_partial_non_native_field_multiplications,
            &mut dedup,
        );
    }

    pub fn compute_dyadic_size(&self) -> usize {
        // for the lookup argument the circuit size must be at least as large as the sum of all tables used
        let min_size_due_to_lookups = self.get_tables_size();

        // minimum size of execution trace due to everything else
        let min_size_of_execution_trace = self.public_inputs.len() + self.num_gates;

        // The number of gates is the maximum required by the lookup argument or everything else, plus an optional zero row
        // to allow for shifts.
        let num_zero_rows = 1;
        let total_num_gates =
            num_zero_rows + std::cmp::max(min_size_due_to_lookups, min_size_of_execution_trace);

        // Next power of 2 (dyadic circuit size)
        Self::get_circuit_subgroup_size(total_num_gates)
    }

    pub fn populate_public_inputs_block(&mut self) {
        tracing::debug!("Populating public inputs block");

        // Update the public inputs block
        for idx in self.public_inputs.iter() {
            for (wire_idx, wire) in self.blocks.pub_inputs.wires.iter_mut().enumerate() {
                if wire_idx < 2 {
                    // first two wires get a copy of the public inputs
                    wire.push(*idx);
                } else {
                    // the remaining wires get zeros
                    wire.push(self.zero_idx);
                }
            }
            for selector in self.blocks.pub_inputs.selectors.iter_mut() {
                selector.push(P::ScalarField::zero());
            }
        }
    }

    fn create_range_constraint(
        &mut self,
        driver: &mut T,
        variable_index: u32,
        num_bits: u32,
    ) -> std::io::Result<()> {
        if num_bits == 1 {
            self.create_bool_gate(variable_index);
        } else if num_bits <= Self::DEFAULT_PLOOKUP_RANGE_BITNUM as u32 {
            // /**
            //  * N.B. if `variable_index` is not used in any arithmetic constraints, this will create an unsatisfiable
            //  *      circuit!
            //  *      this range constraint will increase the size of the 'sorted set' of range-constrained integers by 1.
            //  *      The 'non-sorted set' of range-constrained integers is a subset of the wire indices of all arithmetic
            //  *      gates. No arithmetic gate => size imbalance between sorted and non-sorted sets. Checking for this
            //  *      and throwing an error would require a refactor of the Composer to catelog all 'orphan' variables not
            //  *      assigned to gates.
            //  *
            //  * TODO(Suyash):
            //  *    The following is a temporary fix to make sure the range constraints on numbers with
            //  *    num_bits <= DEFAULT_PLOOKUP_RANGE_BITNUM is correctly enforced in the circuit.
            //  *    Longer term, as Zac says, we would need to refactor the composer to fix this.
            //  **/
            self.create_poly_gate(&PolyTriple::<P::ScalarField> {
                a: variable_index,
                b: variable_index,
                c: variable_index,
                q_m: P::ScalarField::zero(),
                q_l: P::ScalarField::one(),
                q_r: -P::ScalarField::one(),
                q_o: P::ScalarField::zero(),
                q_c: P::ScalarField::zero(),
            });

            self.create_new_range_constraint(variable_index, (1u64 << num_bits) - 1);
        } else {
            self.decompose_into_default_range(
                driver,
                variable_index,
                num_bits as u64,
                Self::DEFAULT_PLOOKUP_RANGE_BITNUM as u64,
            )?;
        }
        Ok(())
    }

    fn create_new_range_constraint(&mut self, variable_index: u32, target_range: u64) {
        // We ignore this check because it is definitely more expensive in MPC, the proof will just not verify if this constraint is not given
        // if (uint256_t(self.get_variable(variable_index)).data[0] > target_range) {
        //     if (!self.failed()) {
        //         self.failure(msg);
        //     }
        // }
        #[expect(clippy::map_entry)] // Required due to borrowing self twice otherwise
        if !self.range_lists.contains_key(&target_range) {
            let new_range_list = self.create_range_list(target_range);
            self.range_lists.insert(target_range, new_range_list);
        }

        let existing_tag =
            self.real_variable_tags[self.real_variable_index[variable_index as usize] as usize];
        // If the variable's tag matches the target range list's tag, do nothing.
        if existing_tag != self.range_lists[&target_range].range_tag {
            // If the variable is 'untagged' (i.e., it has the dummy tag), assign it the appropriate tag.
            // Otherwise, find the range for which the variable has already been tagged.
            if existing_tag != Self::DUMMY_TAG {
                let found_tag = false;
                for (range, range_list) in &self.range_lists {
                    if range_list.range_tag == existing_tag {
                        // found_tag = true;
                        if *range < target_range {
                            // The variable already has a more restrictive range check, so do nothing.
                            return;
                        } else {
                            // The range constraint we are trying to impose is more restrictive than the existing range
                            // constraint. It would be difficult to remove an existing range check. Instead deep-copy the
                            // variable and apply a range check to new variable.
                            let copied_witness =
                                self.add_variable(self.get_variable(variable_index as usize));
                            self.create_add_gate(&AddTriple::<P::ScalarField> {
                                a: variable_index,
                                b: copied_witness,
                                c: self.zero_idx,
                                a_scaling: P::ScalarField::one(),
                                b_scaling: -P::ScalarField::one(),
                                c_scaling: P::ScalarField::zero(),
                                const_scaling: P::ScalarField::zero(),
                            });
                            // Recurse with new witness that has no tag attached.
                            self.create_new_range_constraint(copied_witness, target_range);
                            return;
                        }
                    }
                }
                assert!(found_tag);
            }

            self.assign_tag(variable_index, self.range_lists[&target_range].range_tag);
            self.range_lists
                .get_mut(&target_range)
                .unwrap()
                .variable_indices
                .push(variable_index);
        }
    }

    fn decompose_into_default_range(
        &mut self,
        driver: &mut T,
        variable_index: u32,
        num_bits: u64,
        target_range_bitnum: u64,
    ) -> std::io::Result<Vec<u32>> {
        assert!(self.is_valid_variable(variable_index as usize));

        assert!(num_bits > 0);
        let val = self.get_variable(variable_index as usize);
        // We cannot check that easily in MPC:
        // If the value is out of range, set the composer error to the given msg.
        // if val.msb() >= num_bits && !self.failed() {
        //     self.failure(msg);
        // }
        let sublimb_mask: u64 = (1u64 << target_range_bitnum) - 1;
        // /**
        //  * AZTEC TODO: Support this commented-out code!
        //  * At the moment, `decompose_into_default_range` generates a minimum of 1 arithmetic gate.
        //  * This is not strictly required iff num_bits <= target_range_bitnum.
        //  * However, this produces an edge-case where a variable is range-constrained but NOT present in an arithmetic gate.
        //  * This in turn produces an unsatisfiable circuit (see `create_new_range_constraint`). We would need to check for
        //  * and accommodate/reject this edge case to support not adding addition gates here if not reqiured
        //  * if (num_bits <= target_range_bitnum) {
        //  *     const uint64_t expected_range = (1ULL << num_bits) - 1ULL;
        //  *     create_new_range_constraint(variable_index, expected_range);
        //  *     return { variable_index };
        //  * }
        //  **/
        let has_remainder_bits = num_bits % target_range_bitnum != 0;
        let num_limbs = num_bits / target_range_bitnum + if has_remainder_bits { 1 } else { 0 };
        let last_limb_size = num_bits - (num_bits / target_range_bitnum * target_range_bitnum);
        let last_limb_range = (1u64 << last_limb_size) - 1;

        let mut sublimb_indices: Vec<u32> = Vec::with_capacity(num_limbs as usize);
        let sublimbs = if T::is_shared(&val) {
            let decomp = T::decompose_arithmetic(
                driver,
                T::get_shared(&val).expect("Already checked it is shared"),
                num_bits as usize,
                target_range_bitnum as usize,
            )?;
            decomp.into_iter().map(T::AcvmType::from).collect()
        } else {
            let mut sublimbs = Vec::with_capacity(num_limbs as usize);
            let mut accumulator: BigUint = T::get_public(&val)
                .expect("Already checked it is public")
                .into();
            for _ in 0..num_limbs {
                let sublimb_value = P::ScalarField::from(&accumulator & &sublimb_mask.into());
                sublimbs.push(T::AcvmType::from(sublimb_value));
                accumulator >>= target_range_bitnum;
            }

            sublimbs
        };

        for (i, sublimb) in sublimbs.iter().enumerate() {
            let limb_idx = self.add_variable(sublimb.clone());

            sublimb_indices.push(limb_idx);
            if i == sublimbs.len() - 1 && has_remainder_bits {
                self.create_new_range_constraint(limb_idx, last_limb_range);
            } else {
                self.create_new_range_constraint(limb_idx, sublimb_mask);
            }
        }

        let num_limb_triples = num_limbs / 3 + if num_limbs % 3 != 0 { 1 } else { 0 };
        let leftovers = if num_limbs % 3 == 0 { 3 } else { num_limbs % 3 };

        let mut accumulator_idx = variable_index;
        let mut accumulator = val;

        for i in 0..num_limb_triples {
            let real_limbs = [
                !(i == num_limb_triples - 1 && leftovers < 1),
                !(i == num_limb_triples - 1 && leftovers < 2),
                !(i == num_limb_triples - 1 && leftovers < 3),
            ];

            let round_sublimbs = [
                if real_limbs[0] {
                    sublimbs[3 * i as usize].clone()
                } else {
                    T::public_zero()
                },
                if real_limbs[1] {
                    sublimbs[(3 * i + 1) as usize].clone()
                } else {
                    T::public_zero()
                },
                if real_limbs[2] {
                    sublimbs[(3 * i + 2) as usize].clone()
                } else {
                    T::public_zero()
                },
            ];

            let new_limbs = [
                if real_limbs[0] {
                    sublimb_indices[3 * i as usize]
                } else {
                    self.zero_idx
                },
                if real_limbs[1] {
                    sublimb_indices[(3 * i + 1) as usize]
                } else {
                    self.zero_idx
                },
                if real_limbs[2] {
                    sublimb_indices[(3 * i + 2) as usize]
                } else {
                    self.zero_idx
                },
            ];

            let shifts = [
                target_range_bitnum * (3 * i),
                target_range_bitnum * (3 * i + 1),
                target_range_bitnum * (3 * i + 2),
            ];

            let mut subtrahend = T::mul_with_public(
                driver,
                P::ScalarField::from(BigUint::one() << shifts[0]),
                round_sublimbs[0].clone(),
            );
            let term0 = T::mul_with_public(
                driver,
                P::ScalarField::from(BigUint::one() << shifts[1]),
                round_sublimbs[1].clone(),
            );
            let term1 = T::mul_with_public(
                driver,
                P::ScalarField::from(BigUint::one() << shifts[2]),
                round_sublimbs[2].clone(),
            );
            T::add_assign(driver, &mut subtrahend, term0);
            T::add_assign(driver, &mut subtrahend, term1);

            let new_accumulator = T::sub(driver, accumulator.clone(), subtrahend);
            self.create_big_add_gate(
                &AddQuad {
                    a: new_limbs[0],
                    b: new_limbs[1],
                    c: new_limbs[2],
                    d: accumulator_idx,
                    a_scaling: (BigUint::one() << shifts[0]).into(),
                    b_scaling: (BigUint::one() << shifts[1]).into(),
                    c_scaling: (BigUint::one() << shifts[2]).into(),
                    d_scaling: -P::ScalarField::one(),
                    const_scaling: P::ScalarField::zero(),
                },
                i != num_limb_triples - 1,
            );
            accumulator_idx = self.add_variable(new_accumulator.clone());

            accumulator = new_accumulator;
        }

        Ok(sublimb_indices)
    }

    fn assign_tag(&mut self, variable_index: u32, tag: u32) {
        assert!(
            tag <= self.current_tag,
            "Tag is greater than the current tag"
        );

        // If we've already assigned this tag to this variable, return (can happen due to copy constraints)
        let index = self.real_variable_index[variable_index as usize] as usize;
        if self.real_variable_tags[index] == tag {
            return;
        }

        assert!(
            self.real_variable_tags[index] == Self::DUMMY_TAG,
            "Tag mismatch: expected DUMMY_TAG"
        );
        self.real_variable_tags[index] = tag;
    }

    fn get_new_tag(&mut self) -> u32 {
        self.current_tag += 1;

        self.current_tag
    }

    fn create_tag(&mut self, tag_index: u32, tau_index: u32) -> u32 {
        self.tau.insert(tag_index, tau_index);
        self.current_tag += 1;
        self.current_tag
    }

    fn create_range_list(&mut self, target_range: u64) -> RangeList {
        let range_tag = self.get_new_tag();
        let tau_tag = self.get_new_tag();
        self.create_tag(range_tag, tau_tag);
        self.create_tag(tau_tag, range_tag);

        let num_multiples_of_three = target_range / Self::DEFAULT_PLOOKUP_RANGE_STEP_SIZE as u64;
        let mut variable_indices = Vec::with_capacity(num_multiples_of_three as usize + 2);
        for i in 0..=num_multiples_of_three {
            let index = self.add_variable(T::AcvmType::from(P::ScalarField::from(
                i * Self::DEFAULT_PLOOKUP_RANGE_STEP_SIZE as u64,
            )));

            variable_indices.push(index);
            self.assign_tag(index, range_tag);
        }
        let index = self.add_variable(T::AcvmType::from(P::ScalarField::from(target_range)));
        variable_indices.push(index);

        self.assign_tag(index, range_tag);
        self.create_dummy_constraints(&variable_indices);

        RangeList {
            target_range,
            range_tag,
            tau_tag,
            variable_indices,
        }
    }

    fn create_dummy_constraints(&mut self, variable_index: &[u32]) {
        let mut padded_list = variable_index.to_owned();
        const GATE_WIDTH: usize = NUM_WIRES;
        let padding = (GATE_WIDTH - (padded_list.len() % GATE_WIDTH)) % GATE_WIDTH;

        for _ in 0..padding {
            padded_list.push(self.zero_idx);
        }

        self.assert_valid_variables(variable_index);
        self.assert_valid_variables(&padded_list);

        for chunk in padded_list.chunks(GATE_WIDTH) {
            create_dummy_gate!(
                self,
                &mut self.blocks.arithmetic,
                chunk[0],
                chunk[1],
                chunk[2],
                chunk[3],
            );
        }
    }

    fn create_sort_constraint_with_edges(
        &mut self,
        variable_index: &[u32],
        start: P::ScalarField,
        end: P::ScalarField,
    ) {
        // Convenient to assume size is at least 8 (gate_width = 4) for separate gates for start and end conditions
        const GATE_WIDTH: usize = NUM_WIRES;
        assert!(
            variable_index.len() % GATE_WIDTH == 0 && variable_index.len() > GATE_WIDTH,
            "Variable index size ({}) must be a multiple of {} and greater than {}",
            variable_index.len(),
            GATE_WIDTH,
            GATE_WIDTH
        );

        self.assert_valid_variables(variable_index);

        // Add an arithmetic gate to ensure the first input is equal to the start value of the range being checked
        self.create_add_gate(&AddTriple {
            a: variable_index[0],
            b: self.zero_idx,
            c: self.zero_idx,
            a_scaling: P::ScalarField::one(),
            b_scaling: P::ScalarField::zero(),
            c_scaling: P::ScalarField::zero(),
            const_scaling: (-start),
        });
        // enforce range check for all but the final row
        for i in (0..variable_index.len() - GATE_WIDTH).step_by(GATE_WIDTH) {
            self.blocks.delta_range.populate_wires(
                variable_index[i],
                variable_index[i + 1],
                variable_index[i + 2],
                variable_index[i + 3],
            );
            self.num_gates += 1;
            self.blocks.delta_range.q_m().push(P::ScalarField::zero());
            self.blocks.delta_range.q_1().push(P::ScalarField::zero());
            self.blocks.delta_range.q_2().push(P::ScalarField::zero());
            self.blocks.delta_range.q_3().push(P::ScalarField::zero());
            self.blocks.delta_range.q_c().push(P::ScalarField::zero());
            self.blocks
                .delta_range
                .q_arith()
                .push(P::ScalarField::zero());
            self.blocks.delta_range.q_4().push(P::ScalarField::zero());
            self.blocks
                .delta_range
                .q_delta_range()
                .push(P::ScalarField::one());
            self.blocks
                .delta_range
                .q_elliptic()
                .push(P::ScalarField::zero());
            self.blocks
                .delta_range
                .q_lookup_type()
                .push(P::ScalarField::zero());
            self.blocks.delta_range.q_aux().push(P::ScalarField::zero());
            self.blocks
                .delta_range
                .q_poseidon2_external()
                .push(P::ScalarField::zero());
            self.blocks
                .delta_range
                .q_poseidon2_internal()
                .push(P::ScalarField::zero());

            self.check_selector_length_consistency();
        }

        // enforce range checks of last row and ending at end
        if variable_index.len() > GATE_WIDTH {
            self.blocks.delta_range.populate_wires(
                variable_index[variable_index.len() - 4],
                variable_index[variable_index.len() - 3],
                variable_index[variable_index.len() - 2],
                variable_index[variable_index.len() - 1],
            );
            self.num_gates += 1;
            self.blocks.delta_range.q_m().push(P::ScalarField::zero());
            self.blocks.delta_range.q_1().push(P::ScalarField::zero());
            self.blocks.delta_range.q_2().push(P::ScalarField::zero());
            self.blocks.delta_range.q_3().push(P::ScalarField::zero());
            self.blocks.delta_range.q_c().push(P::ScalarField::zero());
            self.blocks
                .delta_range
                .q_arith()
                .push(P::ScalarField::zero());
            self.blocks.delta_range.q_4().push(P::ScalarField::zero());
            self.blocks
                .delta_range
                .q_delta_range()
                .push(P::ScalarField::one());
            self.blocks
                .delta_range
                .q_elliptic()
                .push(P::ScalarField::zero());
            self.blocks
                .delta_range
                .q_lookup_type()
                .push(P::ScalarField::zero());
            self.blocks.delta_range.q_aux().push(P::ScalarField::zero());
            self.blocks
                .delta_range
                .q_poseidon2_external()
                .push(P::ScalarField::zero());
            self.blocks
                .delta_range
                .q_poseidon2_internal()
                .push(P::ScalarField::zero());

            self.check_selector_length_consistency();
        }

        // dummy gate needed because of sort widget's check of next row
        // use this gate to check end condition
        // TODO(https://github.com/AztecProtocol/barretenberg/issues/879): This was formerly a single arithmetic gate. A
        // dummy gate has been added to allow the previous gate to access the required wire data via shifts, allowing the
        // arithmetic gate to occur out of sequence.

        create_dummy_gate!(
            self,
            &mut self.blocks.delta_range,
            variable_index[variable_index.len() - 1],
            self.zero_idx,
            self.zero_idx,
            self.zero_idx,
        );

        self.create_add_gate(&AddTriple {
            a: variable_index[variable_index.len() - 1],
            b: self.zero_idx,
            c: self.zero_idx,
            a_scaling: P::ScalarField::one(),
            b_scaling: P::ScalarField::zero(),
            c_scaling: P::ScalarField::zero(),
            const_scaling: (-end),
        });
    }

    fn create_bool_gate(&mut self, variable_index: u32) {
        self.is_valid_variable(variable_index as usize);

        self.blocks.arithmetic.populate_wires(
            variable_index,
            variable_index,
            self.zero_idx,
            self.zero_idx,
        );

        self.blocks.arithmetic.q_m().push(P::ScalarField::one());
        self.blocks.arithmetic.q_1().push(-P::ScalarField::one());
        self.blocks.arithmetic.q_2().push(P::ScalarField::zero());
        self.blocks.arithmetic.q_3().push(P::ScalarField::zero());
        self.blocks.arithmetic.q_c().push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_delta_range()
            .push(P::ScalarField::zero());

        self.blocks.arithmetic.q_arith().push(P::ScalarField::one());
        self.blocks.arithmetic.q_4().push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_lookup_type()
            .push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_elliptic()
            .push(P::ScalarField::zero());
        self.blocks.arithmetic.q_aux().push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_poseidon2_external()
            .push(P::ScalarField::zero());
        self.blocks
            .arithmetic
            .q_poseidon2_internal()
            .push(P::ScalarField::zero());

        self.check_selector_length_consistency();
        self.num_gates += 1;
    }
}
