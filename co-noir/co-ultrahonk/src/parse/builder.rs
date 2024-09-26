use ark_ec::pairing::Pairing;
use ark_ff::Zero;
use mpc_core::traits::PrimeFieldMpcProtocol;
use std::collections::HashMap;
use ultrahonk::{
    parse::types::{RamTranscript, RangeList, RomTranscript},
    AcirFormat, UltraCircuitBuilder,
};

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
    // pub(crate) variables: Vec<P::ScalarField>,
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
    // num_gates: usize,
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
    phantom_pairing: std::marker::PhantomData<P>,
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

        // builder.build_constraints(
        //     constraint_system,
        //     has_valid_witness_assignments,
        //     honk_recursion,
        //     collect_gates_per_opcode,
        // );

        builder
    }

    fn new(driver: T, size_hint: usize) -> Self {
        tracing::info!("Builder new");
        // let variables = Vec::with_capacity(size_hint * 3);
        let variable_names = HashMap::with_capacity(size_hint * 3);
        let next_var_index = Vec::with_capacity(size_hint * 3);
        let prev_var_index = Vec::with_capacity(size_hint * 3);
        let real_variable_index = Vec::with_capacity(size_hint * 3);
        let real_variable_tags = Vec::with_capacity(size_hint * 3);

        Self {
            driver,
            // variables,
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
            // num_gates: 0,
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
            phantom_pairing: std::marker::PhantomData,
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

        // for idx in 0..varnum {
        //     // Zeros are added for variables whose existence is known but whose values are not yet known. The values may
        //     // be "set" later on via the assert_equal mechanism.
        //     let value = if idx < witness_values.len() {
        //         witness_values[idx]
        //     } else {
        //         P::ScalarField::zero()
        //     };
        //     builder.add_variable(value);
        // }

        // Add the public_inputs from acir
        builder.public_inputs = public_inputs;

        // Add the const zero variable after the acir witness has been
        // incorporated into variables.
        // builder.zero_idx = builder.put_constant_variable(P::ScalarField::zero());
        builder.tau.insert(Self::DUMMY_TAG, Self::DUMMY_TAG); // TODO(luke): explain this

        builder.is_recursive_circuit = recursive;
        builder
    }
}
