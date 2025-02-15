use super::plookup::MultiTableId;
use crate::builder::{GenericUltraCircuitBuilder, UltraCircuitBuilder};
use crate::keys::proving_key::ProvingKey;
use crate::polynomials::polynomial::Polynomial;
use crate::prelude::{PrecomputedEntities, ProverWitnessEntities};
use crate::types::plookup::BasicTableId;
use crate::utils::Utils;
use ark_ec::pairing::Pairing;
use ark_ff::Zero;
use ark_ff::{One, PrimeField};
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use itertools::izip;
use mpc_core::lut::LookupTableProvider;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::array;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::ops::{Index, IndexMut};

#[derive(Default, PartialEq, Eq)]
pub(crate) struct PolyTriple<F: PrimeField> {
    pub(crate) a: u32,
    pub(crate) b: u32,
    pub(crate) c: u32,
    pub(crate) q_m: F,
    pub(crate) q_l: F,
    pub(crate) q_r: F,
    pub(crate) q_o: F,
    pub(crate) q_c: F,
}

#[derive(Default, PartialEq, Eq)]
pub(crate) struct AddTriple<F: PrimeField> {
    pub(crate) a: u32,
    pub(crate) b: u32,
    pub(crate) c: u32,
    pub(crate) a_scaling: F,
    pub(crate) b_scaling: F,
    pub(crate) c_scaling: F,
    pub(crate) const_scaling: F,
}

#[derive(Default, PartialEq, Eq)]
pub(crate) struct AddQuad<F: PrimeField> {
    pub(crate) a: u32,
    pub(crate) b: u32,
    pub(crate) c: u32,
    pub(crate) d: u32,
    pub(crate) a_scaling: F,
    pub(crate) b_scaling: F,
    pub(crate) c_scaling: F,
    pub(crate) d_scaling: F,
    pub(crate) const_scaling: F,
}

#[derive(Default, PartialEq, Eq, Clone)]
pub(crate) struct MulQuad<F: PrimeField> {
    pub(crate) a: u32,
    pub(crate) b: u32,
    pub(crate) c: u32,
    pub(crate) d: u32,
    pub(crate) mul_scaling: F,
    pub(crate) a_scaling: F,
    pub(crate) b_scaling: F,
    pub(crate) c_scaling: F,
    pub(crate) d_scaling: F,
    pub(crate) const_scaling: F,
}

#[derive(Default, PartialEq, Eq)]
pub(crate) struct Poseidon2ExternalGate {
    pub(crate) a: u32,
    pub(crate) b: u32,
    pub(crate) c: u32,
    pub(crate) d: u32,
    pub(crate) round_idx: usize,
}

#[derive(Default, PartialEq, Eq)]
pub(crate) struct Poseidon2InternalGate {
    pub(crate) a: u32,
    pub(crate) b: u32,
    pub(crate) c: u32,
    pub(crate) d: u32,
    pub(crate) round_idx: usize,
}

pub(crate) struct MemOp<F: PrimeField> {
    pub(crate) access_type: u8,
    pub(crate) index: PolyTriple<F>,
    pub(crate) value: PolyTriple<F>,
}

#[derive(Debug, PartialEq, Eq)]
#[expect(clippy::upper_case_acronyms)]
pub(crate) enum BlockType {
    ROM = 0,
    RAM = 1,
    CallData = 2,
    ReturnData = 3,
}

impl Default for BlockType {
    fn default() -> Self {
        Self::ROM
    }
}

#[derive(Default)]
pub(crate) struct BlockConstraint<F: PrimeField> {
    pub(crate) init: Vec<PolyTriple<F>>,
    pub(crate) trace: Vec<MemOp<F>>,
    pub(crate) type_: BlockType,
    pub(crate) calldata: u32,
}

#[derive(Default)]
pub(crate) struct AcirFormatOriginalOpcodeIndices {
    pub(crate) logic_constraints: Vec<usize>,
    pub(crate) range_constraints: Vec<usize>,
    // pub(crate) aes128_constraints: Vec<usize>,
    // pub(crate) sha256_constraints: Vec<usize>,
    // pub(crate) sha256_compression: Vec<usize>,
    // pub(crate) schnorr_constraints: Vec<usize>,
    // pub(crate) ecdsa_k1_constraints: Vec<usize>,
    // pub(crate) ecdsa_r1_constraints: Vec<usize>,
    // pub(crate) blake2s_constraints: Vec<usize>,
    // pub(crate) blake3_constraints: Vec<usize>,
    // pub(crate) keccak_constraints: Vec<usize>,
    // pub(crate) keccak_permutations: Vec<usize>,
    // pub(crate) pedersen_constraints: Vec<usize>,
    // pub(crate) pedersen_hash_constraints: Vec<usize>,
    pub(crate) poseidon2_constraints: Vec<usize>,
    // pub(crate) multi_scalar_mul_constraints: Vec<usize>,
    // pub(crate) ec_add_constraints: Vec<usize>,
    // pub(crate) recursion_constraints: Vec<usize>,
    // pub(crate) honk_recursion_constraints: Vec<usize>,
    // pub(crate) avm_recursion_constraints: Vec<usize>,
    // pub(crate) ivc_recursion_constraints: Vec<usize>,
    // pub(crate) bigint_from_le_bytes_constraints: Vec<usize>,
    // pub(crate) bigint_to_le_bytes_constraints: Vec<usize>,
    // pub(crate) bigint_operations: Vec<usize>,
    pub(crate) assert_equalities: Vec<usize>,
    pub(crate) poly_triple_constraints: Vec<usize>,
    pub(crate) quad_constraints: Vec<usize>,
    // Multiple opcode indices per block:
    pub(crate) block_constraints: Vec<Vec<usize>>,
}

pub struct UltraTraceBlocks<T: Default> {
    pub(crate) pub_inputs: T,
    pub(crate) lookup: T,
    pub(crate) arithmetic: T,
    pub(crate) delta_range: T,
    pub(crate) elliptic: T,
    pub(crate) aux: T,
    pub(crate) poseidon2_external: T,
    pub(crate) poseidon2_internal: T,
}

impl<T: Default> UltraTraceBlocks<T> {
    pub fn get(&self) -> [&T; 8] {
        [
            &self.pub_inputs,
            &self.lookup,
            &self.arithmetic,
            &self.delta_range,
            &self.elliptic,
            &self.aux,
            &self.poseidon2_external,
            &self.poseidon2_internal,
        ]
    }

    pub fn get_mut(&mut self) -> [&mut T; 8] {
        [
            &mut self.pub_inputs,
            &mut self.lookup,
            &mut self.arithmetic,
            &mut self.delta_range,
            &mut self.elliptic,
            &mut self.aux,
            &mut self.poseidon2_external,
            &mut self.poseidon2_internal,
        ]
    }

    pub fn get_pub_inputs(&self) -> &T {
        &self.pub_inputs
    }
}

pub const NUM_WIRES: usize = 4;
pub const NUM_SELECTORS: usize = 13;
pub type UltraTraceBlock<F> = ExecutionTraceBlock<F, NUM_WIRES, NUM_SELECTORS>;

pub struct ExecutionTraceBlock<F: PrimeField, const NUM_WIRES: usize, const NUM_SELECTORS: usize> {
    pub wires: [Vec<u32>; NUM_WIRES], // vectors of indices into a witness variables array
    pub selectors: [Vec<F>; NUM_SELECTORS],
    pub has_ram_rom: bool,      // does the block contain RAM/ROM gates
    pub is_pub_inputs: bool,    // is this the public inputs block
    pub trace_offset: u32,      // where this block starts in the trace
    pub(crate) fixed_size: u32, // Fixed size for use in structured trace
}

impl<F: PrimeField, const NUM_WIRES: usize, const NUM_SELECTORS: usize> Default
    for ExecutionTraceBlock<F, NUM_WIRES, NUM_SELECTORS>
{
    fn default() -> Self {
        Self {
            wires: array::from_fn(|_| Vec::new()),
            selectors: array::from_fn(|_| Vec::new()),
            has_ram_rom: false,
            is_pub_inputs: false,
            trace_offset: 0,
            fixed_size: 0,
        }
    }
}

impl<F: PrimeField> Default for UltraTraceBlocks<UltraTraceBlock<F>> {
    fn default() -> Self {
        let mut res = Self {
            pub_inputs: Default::default(),
            arithmetic: Default::default(),
            delta_range: Default::default(),
            elliptic: Default::default(),
            aux: Default::default(),
            lookup: Default::default(),
            poseidon2_external: Default::default(),
            poseidon2_internal: Default::default(),
        };

        res.pub_inputs.is_pub_inputs = true;
        res.aux.has_ram_rom = true;
        res
    }
}

impl<F: PrimeField> UltraTraceBlocks<UltraTraceBlock<F>> {
    pub fn compute_offsets(&mut self, is_structured: bool) {
        assert!(
            !is_structured,
            "Trace is structuring not implemented for UltraHonk",
        );

        let mut offset = 1; // start at 1 because the 0th row is unused for selectors for Honk
        for block in self.get_mut() {
            block.trace_offset = offset;
            offset += block.get_fixed_size(is_structured);
        }
    }
}

impl<F: PrimeField> UltraTraceBlock<F> {
    const W_L: usize = ProverWitnessEntities::<F>::W_L;
    const W_R: usize = ProverWitnessEntities::<F>::W_R;
    const W_O: usize = ProverWitnessEntities::<F>::W_O;
    const W_4: usize = ProverWitnessEntities::<F>::W_4;

    const Q_M: usize = PrecomputedEntities::<F>::Q_M;
    const Q_C: usize = PrecomputedEntities::<F>::Q_C;
    const Q_1: usize = PrecomputedEntities::<F>::Q_L;
    const Q_2: usize = PrecomputedEntities::<F>::Q_R;
    const Q_3: usize = PrecomputedEntities::<F>::Q_O;
    const Q_4: usize = PrecomputedEntities::<F>::Q_4;
    const Q_ARITH: usize = PrecomputedEntities::<F>::Q_ARITH;
    const Q_DELTA_RANGE: usize = PrecomputedEntities::<F>::Q_DELTA_RANGE;
    const Q_ELLIPTIC: usize = PrecomputedEntities::<F>::Q_ELLIPTIC;
    const Q_AUX: usize = PrecomputedEntities::<F>::Q_AUX;
    const Q_LOOKUP_TYPE: usize = PrecomputedEntities::<F>::Q_LOOKUP;
    const Q_POSEIDON2_EXTERNAL: usize = PrecomputedEntities::<F>::Q_POSEIDON2_EXTERNAL;
    const Q_POSEIDON2_INTERNAL: usize = PrecomputedEntities::<F>::Q_POSEIDON2_INTERNAL;

    pub(crate) fn w_l(&mut self) -> &mut Vec<u32> {
        &mut self.wires[Self::W_L]
    }

    pub(crate) fn w_r(&mut self) -> &mut Vec<u32> {
        &mut self.wires[Self::W_R]
    }

    pub(crate) fn w_o(&mut self) -> &mut Vec<u32> {
        &mut self.wires[Self::W_O]
    }

    pub(crate) fn w_4(&mut self) -> &mut Vec<u32> {
        &mut self.wires[Self::W_4]
    }

    pub(crate) fn q_m(&mut self) -> &mut Vec<F> {
        &mut self.selectors[Self::Q_M]
    }

    pub(crate) fn q_c(&mut self) -> &mut Vec<F> {
        &mut self.selectors[Self::Q_C]
    }

    pub(crate) fn q_1(&mut self) -> &mut Vec<F> {
        &mut self.selectors[Self::Q_1]
    }

    pub(crate) fn q_2(&mut self) -> &mut Vec<F> {
        &mut self.selectors[Self::Q_2]
    }

    pub(crate) fn q_3(&mut self) -> &mut Vec<F> {
        &mut self.selectors[Self::Q_3]
    }

    pub(crate) fn q_4(&mut self) -> &mut Vec<F> {
        &mut self.selectors[Self::Q_4]
    }

    pub(crate) fn q_arith(&mut self) -> &mut Vec<F> {
        &mut self.selectors[Self::Q_ARITH]
    }

    pub(crate) fn q_delta_range(&mut self) -> &mut Vec<F> {
        &mut self.selectors[Self::Q_DELTA_RANGE]
    }

    pub(crate) fn q_elliptic(&mut self) -> &mut Vec<F> {
        &mut self.selectors[Self::Q_ELLIPTIC]
    }

    pub(crate) fn q_aux(&mut self) -> &mut Vec<F> {
        &mut self.selectors[Self::Q_AUX]
    }

    pub(crate) fn q_lookup_type(&mut self) -> &mut Vec<F> {
        &mut self.selectors[Self::Q_LOOKUP_TYPE]
    }

    pub(crate) fn q_poseidon2_external(&mut self) -> &mut Vec<F> {
        &mut self.selectors[Self::Q_POSEIDON2_EXTERNAL]
    }

    pub(crate) fn q_poseidon2_internal(&mut self) -> &mut Vec<F> {
        &mut self.selectors[Self::Q_POSEIDON2_INTERNAL]
    }

    pub(crate) fn populate_wires(&mut self, idx1: u32, idx2: u32, idx3: u32, idx4: u32) {
        self.w_l().push(idx1);
        self.w_r().push(idx2);
        self.w_o().push(idx3);
        self.w_4().push(idx4);
    }

    pub fn get_fixed_size(&self, is_structured: bool) -> u32 {
        if is_structured {
            self.fixed_size
        } else {
            self.len() as u32
        }
    }

    pub fn len(&self) -> usize {
        self.wires[Self::W_L].len()
    }
}

pub(crate) struct RangeConstraint {
    pub(crate) witness: u32,
    pub(crate) num_bits: u32,
}

pub(crate) struct Poseidon2Constraint<F: PrimeField> {
    pub(crate) state: Vec<WitnessOrConstant<F>>,
    pub(crate) result: Vec<u32>,
    pub(crate) len: u32,
}

pub(crate) struct LogicConstraint<F: PrimeField> {
    pub(crate) a: WitnessOrConstant<F>,
    pub(crate) b: WitnessOrConstant<F>,
    pub(crate) result: u32,
    pub(crate) num_bits: u32,
    pub(crate) is_xor_gate: bool,
}

impl<F: PrimeField> LogicConstraint<F> {
    pub(crate) fn and_gate(
        a: WitnessOrConstant<F>,
        b: WitnessOrConstant<F>,
        result: u32,
        num_bits: u32,
    ) -> Self {
        Self {
            a,
            b,
            result,
            num_bits,
            is_xor_gate: false,
        }
    }

    pub(crate) fn xor_gate(
        a: WitnessOrConstant<F>,
        b: WitnessOrConstant<F>,
        result: u32,
        num_bits: u32,
    ) -> Self {
        Self {
            a,
            b,
            result,
            num_bits,
            is_xor_gate: true,
        }
    }
}

pub(crate) struct RecursionConstraint {
    // An aggregation state is represented by two G1 affine elements. Each G1 point has
    // two field element coordinates (x, y). Thus, four field elements
    key: Vec<u32>,
    proof: Vec<u32>,
    public_inputs: Vec<u32>,
    key_hash: u32,
    proof_type: u32,
}

impl RecursionConstraint {
    const NUM_AGGREGATION_ELEMENTS: usize = 4;
}

pub const AGGREGATION_OBJECT_SIZE: usize = 16;
pub(crate) type AggregationObjectIndices = [u32; AGGREGATION_OBJECT_SIZE];
pub type AggregationObjectPubInputIndices = [u32; AGGREGATION_OBJECT_SIZE];

pub(crate) struct RomTable<F: PrimeField> {
    raw_entries: Vec<FieldCT<F>>,
    entries: Vec<FieldCT<F>>,
    length: usize,
    rom_id: usize, // Builder identifier for this ROM table
    initialized: bool,
}

impl<F: PrimeField> RomTable<F> {
    pub(crate) fn new(table_entries: Vec<FieldCT<F>>) -> Self {
        let raw_entries = table_entries;
        let length = raw_entries.len();

        // do not initialize the table yet. The input entries might all be constant,
        // if this is the case we might not have a valid pointer to a Builder
        // We get around this, by initializing the table when `operator[]` is called
        // with a non-const field element.

        Self {
            raw_entries,
            entries: Vec::new(),
            length,
            rom_id: 0,
            initialized: false,
        }
    }

    pub(crate) fn index_field_ct<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &mut self,
        index: &FieldCT<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> FieldCT<F> {
        if index.is_constant() {
            let value = T::get_public(&index.get_value(builder, driver))
                .expect("Constant should be public");
            let val: BigUint = value.into();
            let val: usize = val.try_into().expect("Invalid index");
            return self[val].to_owned();
        }
        self.initialize_table(builder, driver);

        if !T::is_shared(&builder.get_variable(index.witness_index as usize)) {
            // Sanity check, only doable in plain
            let value = T::get_public(&index.get_value(builder, driver))
                .expect("Already checked it is public");
            let val: BigUint = value.into();
            assert!(val < BigUint::from(self.length));
        }

        let witness_index = index.normalize(builder, driver).get_witness_index();
        let output_idx = builder
            .read_rom_array(self.rom_id, witness_index, driver)
            .expect("Not implemented for other cases");
        FieldCT::from_witness_index(output_idx)
    }

    fn initialize_table<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &mut self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) {
        if self.initialized {
            return;
        }
        // populate table. Table entries must be normalized and cannot be constants
        for entry in self.raw_entries.iter() {
            if entry.is_constant() {
                let val = T::get_public(&entry.get_value(builder, driver))
                    .expect("Constant should be public");
                self.entries.push(FieldCT::from_witness_index(
                    builder.put_constant_variable(val),
                ));
            } else {
                self.entries.push(entry.normalize(builder, driver));
            }
        }
        self.rom_id = builder.create_rom_array(self.length);

        for i in 0..self.length {
            builder.set_rom_element(self.rom_id, i, self.entries[i].get_witness_index());
        }

        self.initialized = true;
    }
}

impl<F: PrimeField> Index<usize> for RomTable<F> {
    type Output = FieldCT<F>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.entries[index]
    }
}

pub(crate) struct RamTable<F: PrimeField> {
    raw_entries: Vec<FieldCT<F>>,
    index_initialized: Vec<bool>,
    length: usize,
    ram_id: usize, // Builder identifier for this RAM table
    ram_table_generated_in_builder: bool,
    all_entries_written_to_with_constant_index: bool,
}

impl<F: PrimeField> RamTable<F> {
    pub(crate) fn new(table_entries: Vec<FieldCT<F>>) -> Self {
        let raw_entries = table_entries;
        let length = raw_entries.len();
        let index_initialized = vec![false; length];

        // do not initialize the table yet. The input entries might all be constant,
        // if this is the case we might not have a valid pointer to a Builder
        // We get around this, by initializing the table when `read` or `write` operator is called
        // with a non-const field element.

        Self {
            raw_entries,
            index_initialized,
            length,
            ram_id: 0,
            ram_table_generated_in_builder: false,
            all_entries_written_to_with_constant_index: false,
        }
    }

    pub(crate) fn read<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &mut self,
        index: &FieldCT<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<FieldCT<F>> {
        let index_value = index.get_value(builder, driver);

        if let Some(native_index) = T::get_public(&index_value) {
            assert!(native_index < P::ScalarField::from(self.length as u64));
        }

        self.initialize_table(builder, driver)?;
        assert!(self.check_indices_initialized());

        let index_wire = if index.is_constant() {
            let nativ_index = T::get_public(&index_value).expect("Constant should be public");
            FieldCT::from_witness_index(builder.put_constant_variable(nativ_index))
        } else {
            index.to_owned()
        };

        let wit_index = index_wire.get_normalized_witness_index(builder, driver);
        let output_idx = builder.read_ram_array(self.ram_id, wit_index, driver)?;
        Ok(FieldCT::from_witness_index(output_idx))
    }

    pub(crate) fn write<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &mut self,
        index: &FieldCT<F>,
        value: &FieldCT<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<()> {
        let index_value = index.get_value(builder, driver);

        if let Some(native_index) = T::get_public(&index_value) {
            assert!(native_index < P::ScalarField::from(self.length as u64));
        }

        self.initialize_table(builder, driver)?;

        let index_wire = if index.is_constant() {
            let nativ_index = T::get_public(&index_value).expect("Constant should be public");
            FieldCT::from_witness_index(builder.put_constant_variable(nativ_index))
        } else {
            self.initialize_table(builder, driver)?;
            index.to_owned()
        };

        let value_value = value.get_value(builder, driver);
        let value_wire = if value.is_constant() {
            let native_wire = T::get_public(&value_value).expect("Constant should be public");
            FieldCT::from_witness_index(builder.put_constant_variable(native_wire))
        } else {
            value.to_owned()
        };

        if index.is_constant() {
            let cast_index: BigUint = T::get_public(&index_value)
                .expect("Constant should be public")
                .into();
            let cast_index = usize::try_from(cast_index).expect("Invalid index");
            if !self.index_initialized[cast_index] {
                // if index constant && not initialized
                builder.init_ram_element(
                    driver,
                    self.ram_id,
                    cast_index,
                    value_wire.get_witness_index(),
                )?;
                self.index_initialized[cast_index] = true;
                return Ok(());
            }
        }

        // else
        let index_ = index_wire.get_normalized_witness_index(builder, driver);
        let value_ = value_wire.get_normalized_witness_index(builder, driver);
        builder.write_ram_array(driver, self.ram_id, index_, value_)?;
        Ok(())
    }

    fn check_indices_initialized(&mut self) -> bool {
        if self.all_entries_written_to_with_constant_index {
            return true;
        }
        if self.length == 0 {
            return false;
        }
        let mut init = true;
        for i in self.index_initialized.iter() {
            init = init && *i;
        }
        self.all_entries_written_to_with_constant_index = init;
        self.all_entries_written_to_with_constant_index
    }

    fn initialize_table<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &mut self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<()> {
        if self.ram_table_generated_in_builder {
            return Ok(());
        }

        self.ram_id = builder.create_ram_array(self.length, driver);

        for (i, (raw, ind)) in self
            .raw_entries
            .iter_mut()
            .zip(self.index_initialized.iter_mut())
            .enumerate()
        {
            if *ind {
                continue;
            }
            let entry = if raw.is_constant() {
                let val = T::get_public(&raw.get_value(builder, driver))
                    .expect("Constant should be public");
                FieldCT::from_witness_index(builder.put_constant_variable(val))
            } else {
                raw.normalize(builder, driver)
            };
            builder.init_ram_element(driver, self.ram_id, i, entry.get_witness_index())?;
            *ind = true;
        }

        self.ram_table_generated_in_builder = true;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct FieldCT<F: PrimeField> {
    pub(crate) additive_constant: F,
    pub(crate) multiplicative_constant: F,
    pub(crate) witness_index: u32,
}

impl<F: PrimeField> FieldCT<F> {
    pub(crate) const IS_CONSTANT: u32 = u32::MAX;

    pub(crate) fn zero() -> Self {
        Self {
            additive_constant: F::zero(),
            multiplicative_constant: F::zero(),
            witness_index: Self::IS_CONSTANT,
        }
    }

    pub(crate) fn zero_with_additive(additive: F) -> Self {
        Self {
            additive_constant: additive,
            multiplicative_constant: F::zero(),
            witness_index: Self::IS_CONSTANT,
        }
    }

    pub(crate) fn from_witness_index(witness_index: u32) -> Self {
        Self {
            additive_constant: F::zero(),
            multiplicative_constant: F::one(),
            witness_index,
        }
    }

    pub(crate) fn from_witness<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        input: T::AcvmType,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
    ) -> Self {
        let witness = WitnessCT::from_acvm_type(input, builder);
        Self::from(witness)
    }

    pub(crate) fn get_value<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        builder: &GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> T::AcvmType {
        if !self.is_constant() {
            let variable = builder.get_variable(self.witness_index as usize);
            let mut res = driver.mul_with_public(self.multiplicative_constant, variable);
            driver.add_assign_with_public(self.additive_constant, &mut res);
            res
        } else {
            T::AcvmType::from(self.additive_constant)
        }
    }

    pub(crate) fn get_witness_index(&self) -> u32 {
        self.witness_index
    }

    /**
     * @brief Constrain that this field is equal to the given field.
     *
     * @warning: After calling this method, both field values *will* be equal, regardless of whether the constraint
     * succeeds or fails. This can lead to confusion when debugging. If you want to log the inputs, do so before
     * calling this method.
     */
    pub(crate) fn assert_equal<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) {
        if self.is_constant() && other.is_constant() {
            let left =
                T::get_public(&self.get_value(builder, driver)).expect("Constant should be public");
            let right = T::get_public(&other.get_value(builder, driver))
                .expect("Constant should be public");
            assert_eq!(left, right);
        } else if self.is_constant() {
            let right = other.normalize(builder, driver);
            let left =
                T::get_public(&self.get_value(builder, driver)).expect("Constant should be public");
            builder.assert_equal_constant(right.witness_index as usize, left);
        } else if other.is_constant() {
            let left = self.normalize(builder, driver);
            let right = T::get_public(&other.get_value(builder, driver))
                .expect("Constant should be public");
            builder.assert_equal_constant(left.witness_index as usize, right);
        } else {
            let left = self.normalize(builder, driver);
            let right = other.normalize(builder, driver);
            builder.assert_equal(left.witness_index as usize, right.witness_index as usize);
        }
    }

    pub(crate) fn is_constant(&self) -> bool {
        self.witness_index == Self::IS_CONSTANT
    }

    pub(crate) fn normalize<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> Self {
        if self.is_constant()
            || ((self.multiplicative_constant == F::one()) && (self.additive_constant == F::zero()))
        {
            return self.to_owned();
        }

        // Value of this = this.v * this.mul + this.add; // where this.v = context->variables[this.witness_index]
        // Normalised result = result.v * 1 + 0;         // where result.v = this.v * this.mul + this.add
        // We need a new gate to enforce that the `result` was correctly calculated from `this`.

        let mut result = FieldCT::default();
        let value = builder.get_variable(self.witness_index as usize);
        let mut out = driver.mul_with_public(self.multiplicative_constant, value);
        driver.add_assign_with_public(self.additive_constant, &mut out);

        result.witness_index = builder.add_variable(out);
        result.additive_constant = F::zero();
        result.multiplicative_constant = F::one();

        // Aim of new gate: this.v * this.mul + this.add == result.v
        // <=>                           this.v * [this.mul] +                  result.v * [ -1] + [this.add] == 0
        // <=> this.v * this.v * [ 0 ] + this.v * [this.mul] + this.v * [ 0 ] + result.v * [ -1] + [this.add] == 0
        // <=> this.v * this.v * [q_m] + this.v * [   q_l  ] + this.v * [q_r] + result.v * [q_o] + [   q_c  ] == 0

        builder.create_add_gate(&AddTriple {
            a: self.witness_index,
            b: self.witness_index,
            c: result.witness_index,
            a_scaling: self.multiplicative_constant,
            b_scaling: P::ScalarField::zero(),
            c_scaling: -P::ScalarField::one(),
            const_scaling: self.additive_constant,
        });
        result
    }

    pub(crate) fn get_normalized_witness_index<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> u32 {
        self.normalize(builder, driver).witness_index
    }

    pub(crate) fn multiply<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<Self> {
        let mut result = Self::default();

        if self.is_constant() && other.is_constant() {
            // Both inputs are constant - don't add a gate.
            // The value of a constant is tracked in `.additive_constant`.
            result.additive_constant = self.additive_constant * other.additive_constant;
        } else if !self.is_constant() && other.is_constant() {
            // One input is constant: don't add a gate, but update scaling factors.

            // /**
            //  * Let:
            //  *   a := this;
            //  *   b := other;
            //  *   a.v := ctx->variables[this.witness_index];
            //  *   b.v := ctx->variables[other.witness_index];
            //  *   .mul = .multiplicative_constant
            //  *   .add = .additive_constant
            //  */
            // /**
            //  * Value of this   = a.v * a.mul + a.add;
            //  * Value of other  = b.add
            //  * Value of result = a * b = a.v * [a.mul * b.add] + [a.add * b.add]
            //  *                             ^   ^result.mul       ^result.add
            //  *                             ^result.v
            //  */
            result.additive_constant = self.additive_constant * other.additive_constant;
            result.multiplicative_constant = self.multiplicative_constant * other.additive_constant;
            result.witness_index = self.witness_index;
        } else if self.is_constant() && !other.is_constant() {
            // One input is constant: don't add a gate, but update scaling factors.

            // /**
            //  * Value of this   = a.add;
            //  * Value of other  = b.v * b.mul + b.add
            //  * Value of result = a * b = b.v * [a.add * b.mul] + [a.add * b.add]
            //  *                             ^   ^result.mul       ^result.add
            //  *                             ^result.v
            //  */
            result.additive_constant = self.additive_constant * other.additive_constant;
            result.multiplicative_constant = other.multiplicative_constant * self.additive_constant;
            result.witness_index = other.witness_index;
        } else {
            // Both inputs map to circuit varaibles: create a `*` constraint.

            // /**
            //  * Value of this   = a.v * a.mul + a.add;
            //  * Value of other  = b.v * b.mul + b.add;
            //  * Value of result = a * b
            //  *            = [a.v * b.v] * [a.mul * b.mul] + a.v * [a.mul * b.add] + b.v * [a.add * b.mul] + [a.ac * b.add]
            //  *            = [a.v * b.v] * [     q_m     ] + a.v * [     q_l     ] + b.v * [     q_r     ] + [    q_c     ]
            //  *            ^               ^Notice the add/mul_constants form selectors when a gate is created.
            //  *            |                Only the witnesses (pointed-to by the witness_indexes) form the wires in/out of
            //  *            |                the gate.
            //  *            ^This entire value is pushed to ctx->variables as a new witness. The
            //  *             implied additive & multiplicative constants of the new witness are 0 & 1 resp.
            //  * Left wire value: a.v
            //  * Right wire value: b.v
            //  * Output wire value: result.v (with q_o = -1)
            //  */
            let q_c = self.additive_constant * other.additive_constant;
            let q_r = self.additive_constant * other.multiplicative_constant;
            let q_l = self.multiplicative_constant * other.additive_constant;
            let q_m = self.multiplicative_constant * other.multiplicative_constant;

            let left = builder.get_variable(self.witness_index as usize);
            let right = builder.get_variable(other.witness_index as usize);

            let out = driver.mul(left.to_owned(), right.to_owned())?;
            let mut out = driver.mul_with_public(q_m, out);

            let t0 = driver.mul_with_public(q_l, left);
            driver.add_assign(&mut out, t0);

            let t0 = driver.mul_with_public(q_r, right);
            driver.add_assign(&mut out, t0);
            driver.add_assign_with_public(q_c, &mut out);

            result.witness_index = builder.add_variable(out);
            builder.create_poly_gate(&PolyTriple::<P::ScalarField> {
                a: self.witness_index,
                b: other.witness_index,
                c: result.witness_index,
                q_m,
                q_l,
                q_r,
                q_o: -P::ScalarField::one(),
                q_c,
            });
        }
        Ok(result)
    }

    pub(crate) fn add<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> Self {
        let mut result = Self::default();

        if self.witness_index == other.witness_index {
            result.additive_constant = self.additive_constant + other.additive_constant;
            result.multiplicative_constant =
                self.multiplicative_constant + other.multiplicative_constant;
            result.witness_index = self.witness_index;
        } else if self.is_constant() && other.is_constant() {
            // both inputs are constant - don't add a gate
            result.additive_constant = self.additive_constant + other.additive_constant;
        } else if !self.is_constant() && other.is_constant() {
            // one input is constant - don't add a gate, but update scaling factors
            result.additive_constant = self.additive_constant + other.additive_constant;
            result.multiplicative_constant = self.multiplicative_constant;
            result.witness_index = self.witness_index;
        } else if self.is_constant() && !other.is_constant() {
            result.additive_constant = self.additive_constant + other.additive_constant;
            result.multiplicative_constant = other.multiplicative_constant;
            result.witness_index = other.witness_index;
        } else {
            let left = builder.get_variable(self.witness_index as usize);
            let right = builder.get_variable(other.witness_index as usize);
            let mut out = driver.mul_with_public(self.multiplicative_constant, left);
            let t0 = driver.mul_with_public(other.multiplicative_constant, right);
            driver.add_assign(&mut out, t0);
            driver.add_assign_with_public(self.additive_constant, &mut out);
            driver.add_assign_with_public(other.additive_constant, &mut out);

            result.witness_index = builder.add_variable(out);
            builder.create_add_gate(&AddTriple::<P::ScalarField> {
                a: self.witness_index,
                b: other.witness_index,
                c: result.witness_index,
                a_scaling: self.multiplicative_constant,
                b_scaling: other.multiplicative_constant,
                c_scaling: -P::ScalarField::one(),
                const_scaling: (self.additive_constant + other.additive_constant),
            });
        }
        result
    }

    pub(crate) fn add_assign<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &mut self,
        other: &Self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) {
        *self = self.add(other, builder, driver);
    }

    // Slices a `field_ct` at given indices (msb, lsb) both included in the slice,
    // returns three parts: [low, slice, high].
    pub(crate) fn slice<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        msb: u8,
        lsb: u8,
        total_bitsize: usize,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<[Self; 3]> {
        const GRUMPKIN_MAX_NO_WRAP_INTEGER_BIT_LENGTH: usize = 252;

        assert!(msb >= lsb);
        assert!((msb as usize) < GRUMPKIN_MAX_NO_WRAP_INTEGER_BIT_LENGTH);

        let msb_plus_one = msb as u32 + 1;

        let value = self.get_value(builder, driver);
        let (hi, lo, slice) = if T::is_shared(&value) {
            let value = T::get_shared(&value).expect("Already checked it is shared");
            let [lo, slice, hi] = driver.slice(value, msb, lsb, total_bitsize)?;
            (
                T::AcvmType::from(hi),
                T::AcvmType::from(lo),
                T::AcvmType::from(slice),
            )
        } else {
            let value: BigUint = T::get_public(&value)
                .expect("Already checked it is public")
                .into();

            let hi_mask = (BigUint::one() << (total_bitsize - msb as usize)) - BigUint::one();
            let hi = (&value >> msb_plus_one) & hi_mask;

            let lo_mask = (BigUint::one() << lsb) - BigUint::one();
            let lo = &value & lo_mask;

            let slice_mask = (BigUint::one() << ((msb - lsb) as u32 + 1)) - BigUint::one();
            let slice = (value >> lsb) & slice_mask;

            let hi_ = T::AcvmType::from(F::from(hi));
            let lo_ = T::AcvmType::from(F::from(lo));
            let slice_ = T::AcvmType::from(F::from(slice));
            (hi_, lo_, slice_)
        };

        let hi_wit = Self::from_witness(hi, builder);
        let lo_wit = Self::from_witness(lo, builder);
        let slice_wit = Self::from_witness(slice, builder);

        hi_wit.create_range_constraint(
            GRUMPKIN_MAX_NO_WRAP_INTEGER_BIT_LENGTH - msb as usize,
            builder,
            driver,
        )?;
        lo_wit.create_range_constraint(lsb as usize, builder, driver)?;
        slice_wit.create_range_constraint(msb_plus_one as usize - lsb as usize, builder, driver)?;

        let tmp_hi = hi_wit.multiply(
            &FieldCT::from(F::from(BigUint::one() << msb_plus_one)),
            builder,
            driver,
        )?;
        let mut other = tmp_hi.add(&lo_wit, builder, driver);
        let tmp_slice = slice_wit.multiply(
            &FieldCT::from(F::from(BigUint::one() << lsb)),
            builder,
            driver,
        )?;
        other.add_assign(&tmp_slice, builder, driver);
        self.assert_equal(&other, builder, driver);

        Ok([lo_wit, slice_wit, hi_wit])
    }

    fn create_range_constraint<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        num_bits: usize,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<()> {
        if num_bits == 0 {
            self.assert_is_zero(builder);
        } else if self.is_constant() {
            let val: BigUint = T::get_public(&self.get_value(builder, driver))
                .expect("Constants are public")
                .into();
            assert!((val.bits() as usize) < num_bits);
        } else {
            let index = self.normalize(builder, driver).get_witness_index();
            // We have plookup
            builder.decompose_into_default_range(
                driver,
                index,
                num_bits as u64,
                None,
                GenericUltraCircuitBuilder::<P, T>::DEFAULT_PLOOKUP_RANGE_BITNUM as u64,
            )?;
        }
        Ok(())
    }

    fn assert_is_zero<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
    ) {
        if self.is_constant() {
            assert!(self.additive_constant.is_zero());
            return;
        }

        let var = builder.get_variable(self.witness_index as usize);
        if !T::is_shared(&var) {
            // Sanity check
            let value = T::get_public(&var).expect("Already checked it is public");
            assert!((value * self.multiplicative_constant + self.additive_constant).is_zero())
        }

        builder.create_poly_gate(&PolyTriple::<P::ScalarField> {
            a: self.witness_index,
            b: builder.zero_idx,
            c: builder.zero_idx,
            q_m: P::ScalarField::zero(),
            q_l: self.multiplicative_constant,
            q_r: P::ScalarField::zero(),
            q_o: P::ScalarField::zero(),
            q_c: self.additive_constant,
        });
    }
}

impl<F: PrimeField> From<F> for FieldCT<F> {
    fn from(value: F) -> Self {
        Self {
            additive_constant: value,
            multiplicative_constant: F::one(),
            witness_index: Self::IS_CONSTANT,
        }
    }
}

impl<
        F: PrimeField,
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    > From<WitnessCT<P, T>> for FieldCT<F>
{
    fn from(value: WitnessCT<P, T>) -> Self {
        Self {
            additive_constant: F::zero(),
            multiplicative_constant: F::one(),
            witness_index: value.witness_index,
        }
    }
}

impl<F: PrimeField> Default for FieldCT<F> {
    fn default() -> Self {
        Self {
            additive_constant: F::zero(),
            multiplicative_constant: F::one(),
            witness_index: Self::IS_CONSTANT,
        }
    }
}

pub(crate) struct WitnessCT<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> {
    pub(crate) witness: T::AcvmType,
    pub(crate) witness_index: u32,
}

impl<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> WitnessCT<P, T> {
    const IS_CONSTANT: u32 = FieldCT::<P::ScalarField>::IS_CONSTANT;

    pub(crate) fn from_acvm_type(
        value: T::AcvmType,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
    ) -> Self {
        let witness_index = builder.add_variable(value.to_owned());
        Self {
            witness: value,
            witness_index,
        }
    }
}

#[derive(Default, Clone)]
pub(crate) struct RomRecord<F: Clone> {
    pub(crate) index_witness: u32,
    pub(crate) value_column1_witness: u32,
    pub(crate) value_column2_witness: u32,
    pub(crate) index: F,
    pub(crate) record_witness: u32,
    pub(crate) gate_index: usize,
}

impl<F: PrimeField> RomRecord<F> {
    fn less_than(&self, other: &Self) -> bool {
        self.index < other.index
    }

    fn equal(&self, other: &Self) -> bool {
        self.index_witness == other.index_witness
            && self.value_column1_witness == other.value_column1_witness
            && self.value_column2_witness == other.value_column2_witness
            && self.index == other.index
            && self.record_witness == other.record_witness
            && self.gate_index == other.gate_index
    }
}

impl<F: PrimeField> PartialEq for RomRecord<F> {
    fn eq(&self, other: &Self) -> bool {
        self.equal(other)
    }
}

impl<F: PrimeField> Eq for RomRecord<F> {}

impl<F: PrimeField> PartialOrd for RomRecord<F> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: PrimeField> Ord for RomRecord<F> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.less_than(other) {
            Ordering::Less
        } else if self.equal(other) {
            Ordering::Equal
        } else {
            Ordering::Greater
        }
    }
}

#[derive(Default)]
pub(crate) struct RomTranscript<F: Clone> {
    // Contains the value of each index of the array
    pub(crate) state: Vec<[u32; 2]>,

    // A vector of records, each of which contains:
    // + The constant witness with the index
    // + The value in the memory slot
    // + The actual index value
    pub(crate) records: Vec<RomRecord<F>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RamAccessType {
    Read,
    Write,
}

impl Default for RamAccessType {
    fn default() -> Self {
        Self::Read
    }
}

#[derive(Clone)]
pub(crate) struct RamRecord<F: Clone> {
    pub(crate) index_witness: u32,
    pub(crate) timestamp_witness: u32,
    pub(crate) value_witness: u32,
    pub(crate) index: F,
    pub(crate) access_type: RamAccessType,
    pub(crate) timestamp: u32,
    pub(crate) record_witness: u32,
    pub(crate) gate_index: usize,
}

impl<F: Clone + Default> Default for RamRecord<F> {
    fn default() -> Self {
        Self {
            index_witness: 0,
            timestamp_witness: 0,
            value_witness: 0,
            index: F::default(),
            access_type: RamAccessType::Read,
            timestamp: 0,
            record_witness: 0,
            gate_index: 0,
        }
    }
}

impl<F: PrimeField> RamRecord<F> {
    fn less_than(&self, other: &Self) -> bool {
        let index_test = self.index < other.index;
        index_test || (self.index == other.index && self.timestamp < other.timestamp)
    }

    fn equal(&self, other: &Self) -> bool {
        self.index_witness == other.index_witness
            && self.timestamp_witness == other.timestamp_witness
            && self.value_witness == other.value_witness
            && self.index == other.index
            && self.timestamp == other.timestamp
            && self.access_type == other.access_type
            && self.record_witness == other.record_witness
            && self.gate_index == other.gate_index
    }
}

impl<F: PrimeField> PartialEq for RamRecord<F> {
    fn eq(&self, other: &Self) -> bool {
        self.equal(other)
    }
}

impl<F: PrimeField> Eq for RamRecord<F> {}

impl<F: PrimeField> PartialOrd for RamRecord<F> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: PrimeField> Ord for RamRecord<F> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.less_than(other) {
            Ordering::Less
        } else if self.equal(other) {
            Ordering::Equal
        } else {
            Ordering::Greater
        }
    }
}

#[derive(Default)]
pub(crate) struct RamTranscript<U: Clone + Default, F: PrimeField, L: LookupTableProvider<F>> {
    // Contains the value of each index of the array
    pub(crate) state: L::LutType,

    // A vector of records, each of which contains:
    // + The constant witness with the index
    // + The value in the memory slot
    // + The actual index value
    pub(crate) records: Vec<RamRecord<U>>,

    // used for RAM records, to compute the timestamp when performing a read/write
    pub(crate) access_count: usize,
}

impl<U: Clone + Default, F: PrimeField, L: LookupTableProvider<F>> RamTranscript<U, F, L> {
    pub(crate) fn from_lut(lut: L::LutType) -> Self {
        Self {
            state: lut,
            records: Vec::new(),
            access_count: 0,
        }
    }
}

#[derive(PartialEq, Eq)]
pub(crate) enum AuxSelectors {
    None,
    LimbAccumulate1,
    LimbAccumulate2,
    NonNativeField1,
    NonNativeField2,
    NonNativeField3,
    RamConsistencyCheck,
    RomConsistencyCheck,
    RamTimestampCheck,
    RomRead,
    RamRead,
    RamWrite,
}

#[derive(Clone)]
pub(crate) struct LookupEntry<F: Clone> {
    pub(crate) key: [F; 2],
    pub(crate) value: [F; 2],
}

impl<F: PrimeField> LookupEntry<F> {
    pub(crate) fn to_table_components(&self, use_two_key: bool) -> [F; 3] {
        [
            self.key[0],
            if use_two_key {
                self.key[1]
            } else {
                self.value[0]
            },
            if use_two_key {
                self.value[0]
            } else {
                self.value[1]
            },
        ]
    }
}

impl<C: Clone> LookupEntry<C> {
    pub(crate) fn calculate_table_index<
        F: PrimeField,
        T: NoirWitnessExtensionProtocol<F, AcvmType = C>,
    >(
        &self,
        driver: &mut T,
        use_two_key: bool,
        base: F,
    ) -> C {
        let mut index_b = self.key[0].to_owned();
        if use_two_key {
            index_b = driver.mul_with_public(base, index_b);
            driver.add_assign(&mut index_b, self.key[1].to_owned());
        }
        index_b
    }
}

pub(crate) struct PlookupBasicTable<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> {
    pub(crate) id: BasicTableId,
    pub(crate) table_index: usize,
    pub(crate) use_twin_keys: bool,
    pub(crate) column_1_step_size: P::ScalarField,
    pub(crate) column_2_step_size: P::ScalarField,
    pub(crate) column_3_step_size: P::ScalarField,
    pub(crate) column_1: Vec<P::ScalarField>,
    pub(crate) column_2: Vec<P::ScalarField>,
    pub(crate) column_3: Vec<P::ScalarField>,
    pub(crate) lookup_gates: Vec<LookupEntry<T::AcvmType>>,
    pub(crate) index_map: LookupHashMap<P::ScalarField>,
    pub(crate) get_values_from_key: fn([u64; 2]) -> [P::ScalarField; 2],
}

impl<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> Default
    for PlookupBasicTable<P, T>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> PlookupBasicTable<P, T> {
    fn new() -> Self {
        Self {
            id: BasicTableId::HonkDummyBasic1,
            table_index: 0,
            use_twin_keys: false,
            column_1_step_size: P::ScalarField::zero(),
            column_2_step_size: P::ScalarField::zero(),
            column_3_step_size: P::ScalarField::zero(),
            column_1: Vec::new(),
            column_2: Vec::new(),
            column_3: Vec::new(),
            lookup_gates: Vec::new(),
            index_map: LookupHashMap::default(),
            get_values_from_key: BasicTableId::get_value_from_key::<
                P::ScalarField,
                { BasicTableId::HonkDummyBasic1 as u64 },
            >,
        }
    }
}

impl<P: Pairing, T: NoirWitnessExtensionProtocol<P::ScalarField>> PlookupBasicTable<P, T> {
    pub(crate) fn len(&self) -> usize {
        assert_eq!(self.column_1.len(), self.column_2.len());
        assert_eq!(self.column_1.len(), self.column_3.len());
        self.column_1.len()
    }

    fn generate_honk_dummy_table<const ID: u64>(
        id: BasicTableId,
        table_index: usize,
    ) -> PlookupBasicTable<P, T> {
        // We do the assertion, since this function is templated, but the general API for these functions contains the id,
        // too. This helps us ensure that the correct instantion is used for a particular BasicTableId
        assert_eq!(ID, usize::from(id.to_owned()) as u64);
        let base = 1 << 1; // Probably has to be a power of 2
        let mut table = PlookupBasicTable::new();
        table.id = id;
        table.table_index = table_index;
        table.use_twin_keys = true;
        for i in 0..base {
            for j in 0..base {
                table.column_1.push(P::ScalarField::from(i));
                table.column_2.push(P::ScalarField::from(j));
                table
                    .column_3
                    .push(P::ScalarField::from(i * 3 + j * 4 + ID * 0x1337));
            }
        }

        table.get_values_from_key = BasicTableId::get_value_from_key::<P::ScalarField, ID>;
        let base = P::ScalarField::from(base);
        table.column_1_step_size = base;
        table.column_2_step_size = base;
        table.column_3_step_size = base;

        table
    }

    fn generate_and_rotate_table<const BITS_PER_SLICE: u64, const NUM_ROTATED_OUTPUT_BITS: u64>(
        id: BasicTableId,
        table_index: usize,
    ) -> PlookupBasicTable<P, T> {
        let base = 1 << BITS_PER_SLICE;
        let mut table = PlookupBasicTable::new();

        table.id = id;
        table.table_index = table_index;
        table.use_twin_keys = true;

        for i in 0..base {
            for j in 0..base {
                table.column_1.push(P::ScalarField::from(i));
                table.column_2.push(P::ScalarField::from(j));
                table.column_3.push(P::ScalarField::from(Utils::rotate64(
                    i & j,
                    NUM_ROTATED_OUTPUT_BITS,
                )));
            }
        }

        table.get_values_from_key =
            BasicTableId::get_and_rotate_values_from_key::<P::ScalarField, NUM_ROTATED_OUTPUT_BITS>;
        let base = P::ScalarField::from(base);
        table.column_1_step_size = base;
        table.column_2_step_size = base;
        table.column_3_step_size = base;

        table
    }

    fn generate_xor_rotate_table<const BITS_PER_SLICE: u64, const NUM_ROTATED_OUTPUT_BITS: u64>(
        id: BasicTableId,
        table_index: usize,
    ) -> PlookupBasicTable<P, T> {
        let base = 1 << BITS_PER_SLICE;
        let mut table = PlookupBasicTable::new();

        table.id = id;
        table.table_index = table_index;
        table.use_twin_keys = true;

        for i in 0..base {
            for j in 0..base {
                table.column_1.push(P::ScalarField::from(i));
                table.column_2.push(P::ScalarField::from(j));
                table.column_3.push(P::ScalarField::from(Utils::rotate64(
                    i ^ j,
                    NUM_ROTATED_OUTPUT_BITS,
                )));
            }
        }

        table.get_values_from_key =
            BasicTableId::get_xor_rotate_values_from_key::<P::ScalarField, NUM_ROTATED_OUTPUT_BITS>;
        let base = P::ScalarField::from(base);
        table.column_1_step_size = base;
        table.column_2_step_size = base;
        table.column_3_step_size = base;

        table
    }

    pub(crate) fn create_basic_table(id: BasicTableId, index: usize) -> Self {
        // TACEO TODO this is a dummy implementation
        assert!(
            matches!(
                id,
                BasicTableId::HonkDummyBasic1
                    | BasicTableId::HonkDummyBasic2
                    | BasicTableId::UintAndRotate0
                    | BasicTableId::UintXorRotate0
            ),
            "Create Basic Table for {:?} not implemented",
            id
        );

        match id {
            BasicTableId::HonkDummyBasic1 => Self::generate_honk_dummy_table::<
                { BasicTableId::HonkDummyBasic1 as u64 },
            >(id, index),
            BasicTableId::HonkDummyBasic2 => Self::generate_honk_dummy_table::<
                { BasicTableId::HonkDummyBasic2 as u64 },
            >(id, index),
            BasicTableId::UintAndRotate0 => Self::generate_and_rotate_table::<6, 0>(id, index),
            BasicTableId::UintXorRotate0 => Self::generate_xor_rotate_table::<6, 0>(id, index),
            _ => {
                todo!("Create other tables")
            }
        }
    }

    pub(crate) fn initialize_index_map(&mut self) {
        for (i, (c1, c2, c3)) in izip!(
            self.column_1.iter().cloned(),
            self.column_2.iter().cloned(),
            self.column_3.iter().cloned()
        )
        .enumerate()
        {
            self.index_map.index_map.insert([c1, c2, c3], i);
        }
    }
}

#[derive(Default)]
pub(crate) struct LookupHashMap<F: PrimeField> {
    pub(crate) index_map: HashMap<[F; 3], usize>,
}

impl<F: PrimeField> Index<[F; 3]> for LookupHashMap<F> {
    type Output = usize;

    fn index(&self, index: [F; 3]) -> &Self::Output {
        self.index_map.index(&index)
    }
}

pub(crate) struct PlookupMultiTable<F: PrimeField> {
    pub(crate) column_1_coefficients: Vec<F>,
    pub(crate) column_2_coefficients: Vec<F>,
    pub(crate) column_3_coefficients: Vec<F>,
    pub(crate) id: MultiTableId,
    pub(crate) basic_table_ids: Vec<BasicTableId>,
    pub(crate) slice_sizes: Vec<u64>,
    pub(crate) column_1_step_sizes: Vec<F>,
    pub(crate) column_2_step_sizes: Vec<F>,
    pub(crate) column_3_step_sizes: Vec<F>,
    pub(crate) get_table_values: Vec<fn([u64; 2]) -> [F; 2]>,
}

impl<F: PrimeField> Default for PlookupMultiTable<F> {
    fn default() -> Self {
        Self {
            column_1_coefficients: Vec::new(),
            column_2_coefficients: Vec::new(),
            column_3_coefficients: Vec::new(),
            id: MultiTableId::HonkDummyMulti,
            basic_table_ids: Vec::new(),
            slice_sizes: Vec::new(),
            column_1_step_sizes: Vec::new(),
            column_2_step_sizes: Vec::new(),
            column_3_step_sizes: Vec::new(),
            get_table_values: Vec::new(),
        }
    }
}

impl<F: PrimeField> PlookupMultiTable<F> {
    pub(crate) fn new(
        col1_repeated_coeff: F,
        col2_repeated_coeff: F,
        col3_repeated_coeff: F,
        num_lookups: usize,
    ) -> Self {
        let mut column_1_coefficients = Vec::with_capacity(num_lookups + 1);
        let mut column_2_coefficients = Vec::with_capacity(num_lookups + 1);
        let mut column_3_coefficients = Vec::with_capacity(num_lookups + 1);

        column_1_coefficients.push(F::one());
        column_2_coefficients.push(F::one());
        column_3_coefficients.push(F::one());

        for _ in 0..num_lookups {
            column_1_coefficients.push(col1_repeated_coeff * column_1_coefficients.last().unwrap());
            column_2_coefficients.push(col2_repeated_coeff * column_2_coefficients.last().unwrap());
            column_3_coefficients.push(col3_repeated_coeff * column_3_coefficients.last().unwrap());
        }

        let mut res = Self {
            column_1_coefficients,
            column_2_coefficients,
            column_3_coefficients,
            ..Default::default()
        };
        res.init_step_sizes();
        res
    }

    fn init_step_sizes(&mut self) {
        let num_lookups = self.column_1_coefficients.len();
        self.column_1_step_sizes.push(F::one());
        self.column_2_step_sizes.push(F::one());
        self.column_3_step_sizes.push(F::one());

        let mut coefficient_inverses = self.column_1_coefficients.clone();
        coefficient_inverses.extend(&self.column_2_coefficients);
        coefficient_inverses.extend(&self.column_3_coefficients);

        Utils::batch_invert(&mut coefficient_inverses);

        for i in 1..num_lookups {
            self.column_1_step_sizes
                .push(self.column_1_coefficients[i] * coefficient_inverses[i - 1]);
            self.column_2_step_sizes
                .push(self.column_2_coefficients[i] * coefficient_inverses[num_lookups + i - 1]);
            self.column_3_step_sizes.push(
                self.column_3_coefficients[i] * coefficient_inverses[2 * num_lookups + i - 1],
            );
        }
    }
}

#[derive(Default)]
pub(crate) struct ReadData<F: Clone> {
    pub(crate) lookup_entries: Vec<LookupEntry<F>>,
    pub(crate) columns: [Vec<F>; 3],
}

impl<F: Clone> Index<ColumnIdx> for ReadData<F> {
    type Output = Vec<F>;

    fn index(&self, index: ColumnIdx) -> &Self::Output {
        self.columns.index(index as usize)
    }
}

impl<F: Clone> IndexMut<ColumnIdx> for ReadData<F> {
    fn index_mut(&mut self, index: ColumnIdx) -> &mut Self::Output {
        self.columns.index_mut(index as usize)
    }
}

pub(crate) enum ColumnIdx {
    C1,
    C2,
    C3,
}
#[derive(Clone, Debug)]
pub(crate) struct RangeList {
    pub(crate) target_range: u64,
    pub(crate) range_tag: u32,
    pub(crate) tau_tag: u32,
    pub(crate) variable_indices: Vec<u32>,
}

#[derive(Clone)]
pub(crate) struct CachedPartialNonNativeFieldMultiplication<F: PrimeField> {
    pub(crate) a: [u32; 5],
    pub(crate) b: [u32; 5],
    pub(crate) lo_0: F,
    pub(crate) hi_0: F,
    pub(crate) hi_1: F,
}

impl<F: PrimeField> CachedPartialNonNativeFieldMultiplication<F> {
    fn equal(&self, other: &Self) -> bool {
        self.a == other.a && self.b == other.b
    }

    fn less_than(&self, other: &Self) -> bool {
        if self.a < other.a {
            return true;
        }
        if other.a < self.a {
            return false;
        }
        if self.b < other.b {
            return true;
        }
        other.b < self.b
    }

    pub(crate) fn deduplicate(inp: &[Self]) -> Vec<Self> {
        let mut hash_set = HashSet::new();
        let mut unique_vec = Vec::new();

        for element in inp.iter() {
            if hash_set.insert(element.clone()) {
                unique_vec.push(element.clone());
            }
        }
        unique_vec
    }
}

impl<F: PrimeField> PartialOrd for CachedPartialNonNativeFieldMultiplication<F> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: PrimeField> Ord for CachedPartialNonNativeFieldMultiplication<F> {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.eq(other) {
            Ordering::Equal
        } else if self.less_than(other) {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    }
}

impl<F: PrimeField> PartialEq for CachedPartialNonNativeFieldMultiplication<F> {
    fn eq(&self, other: &Self) -> bool {
        self.equal(other)
    }
}

impl<F: PrimeField> Eq for CachedPartialNonNativeFieldMultiplication<F> {}

impl<F: PrimeField> Hash for CachedPartialNonNativeFieldMultiplication<F> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.a.hash(state);
        self.b.hash(state);
    }
}

#[derive(Clone)]
pub struct CycleNode {
    pub wire_index: u32,
    pub gate_index: u32,
}
pub type CyclicPermutation = Vec<CycleNode>;

pub(crate) struct TraceData<'a, P: Pairing> {
    pub(crate) wires: &'a mut [Polynomial<P::ScalarField>; NUM_WIRES],
    pub(crate) selectors: &'a mut [Polynomial<P::ScalarField>; NUM_SELECTORS],
    pub(crate) copy_cycles: Vec<CyclicPermutation>,
    pub(crate) ram_rom_offset: u32,
    pub(crate) pub_inputs_offset: u32,
}

impl<'a, P: Pairing> TraceData<'a, P> {
    pub(crate) fn new(
        builder: &UltraCircuitBuilder<P>,
        proving_key: &'a mut ProvingKey<P>,
    ) -> Self {
        let copy_cycles = vec![vec![]; builder.variables.len()];

        Self {
            wires: proving_key
                .polynomials
                .witness
                .get_wires_mut()
                .try_into()
                .unwrap(),
            selectors: proving_key
                .polynomials
                .precomputed
                .get_selectors_mut()
                .try_into()
                .unwrap(),
            copy_cycles,
            ram_rom_offset: 0,
            pub_inputs_offset: 0,
        }
    }

    pub(crate) fn construct_trace_data(
        &mut self,
        builder: &mut UltraCircuitBuilder<P>,
        is_structured: bool,
        active_region_data: &mut ActiveRegionData,
    ) {
        tracing::trace!("Construct trace data");

        let mut offset = 1; // Offset at which to place each block in the trace polynomials
                            // For each block in the trace, populate wire polys, copy cycles and selector polys

        for block in builder.blocks.get() {
            let block_size = block.len();

            // Save ranges over which the blocks are "active" for use in structured commitments
            // Mega and Ultra
            if block_size > 0 {
                tracing::trace!("Construct active indices");
                active_region_data.add_range(offset, offset + block_size);
            }
            // Update wire polynomials and copy cycles
            // NB: The order of row/column loops is arbitrary but needs to be row/column to match old copy_cycle code

            for block_row_idx in 0..block_size {
                for wire_idx in 0..NUM_WIRES {
                    let var_idx = block.wires[wire_idx][block_row_idx] as usize; // an index into the variables array
                    let real_var_idx = builder.real_variable_index[var_idx] as usize;
                    let trace_row_idx = block_row_idx + offset;
                    // Insert the real witness values from this block into the wire polys at the correct offset
                    self.wires[wire_idx][trace_row_idx] = builder.get_variable(var_idx);
                    // Add the address of the witness value to its corresponding copy cycle
                    self.copy_cycles[real_var_idx].push(CycleNode {
                        wire_index: wire_idx as u32,
                        gate_index: trace_row_idx as u32,
                    });
                }
            }

            // Insert the selector values for this block into the selector polynomials at the correct offset
            // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/398): implicit arithmetization/flavor consistency
            for (selector_poly, selector) in self.selectors.iter_mut().zip(block.selectors.iter()) {
                debug_assert_eq!(selector.len(), block_size);

                for (src, des) in selector.iter().zip(selector_poly.iter_mut().skip(offset)) {
                    *des = *src;
                }
            }

            // Store the offset of the block containing RAM/ROM read/write gates for use in updating memory records
            if block.has_ram_rom {
                self.ram_rom_offset = offset as u32;
            }
            // Store offset of public inputs block for use in the pub(crate)input mechanism of the permutation argument
            if block.is_pub_inputs {
                self.pub_inputs_offset = offset as u32;
            }

            // If the trace is structured, we populate the data from the next block at a fixed block size offset
            // otherwise, the next block starts immediately following the previous one
            offset += block.get_fixed_size(is_structured) as usize;
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct PermutationSubgroupElement {
    pub(crate) row_index: u32,
    pub(crate) column_index: u32,
    pub(crate) is_public_input: bool,
    pub(crate) is_tag: bool,
}

impl PermutationSubgroupElement {
    fn new(row_index: u32, column_index: u32) -> Self {
        Self {
            row_index,
            column_index,
            is_public_input: false,
            is_tag: false,
        }
    }
}

pub(crate) type Mapping = [Vec<PermutationSubgroupElement>; NUM_WIRES];
pub(crate) struct PermutationMapping {
    pub(crate) sigmas: Mapping,
    pub(crate) ids: Mapping,
}

impl PermutationMapping {
    pub(crate) fn new(circuit_size: usize) -> Self {
        let mut sigmas = array::from_fn(|_| Vec::with_capacity(circuit_size));
        let mut ids = array::from_fn(|_| Vec::with_capacity(circuit_size));

        for col_idx in 0..NUM_WIRES {
            for row_idx in 0..circuit_size {
                let perm_el = PermutationSubgroupElement::new(row_idx as u32, col_idx as u32);
                sigmas[col_idx].push(perm_el.to_owned());
                ids[col_idx].push(perm_el);
            }
        }

        Self { sigmas, ids }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WitnessOrConstant<F: PrimeField> {
    index: u32,
    value: F,
    is_constant: bool,
}

impl<F: PrimeField> WitnessOrConstant<F> {
    pub(crate) fn from_index(index: u32) -> Self {
        Self {
            index,
            value: F::zero(),
            is_constant: false,
        }
    }

    pub(crate) fn from_constant(constant: F) -> Self {
        Self {
            index: 0,
            value: constant,
            is_constant: true,
        }
    }

    pub(crate) fn is_constant(&self) -> bool {
        self.is_constant
    }

    pub(crate) fn to_field_ct(&self) -> FieldCT<F> {
        if self.is_constant {
            FieldCT::from(self.value)
        } else {
            FieldCT::from_witness_index(self.index)
        }
    }
}
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ActiveRegionData {
    ranges: Vec<(usize, usize)>, // active ranges [start_i, end_i) of the execution trace
    idxs: Vec<usize>,            // full set of poly indices corresposponding to active ranges
    current_end: usize,          // end of last range; for ensuring monotonicity of ranges
}
impl ActiveRegionData {
    pub fn new() -> Self {
        Self {
            ranges: Vec::new(),
            idxs: Vec::new(),
            current_end: 0,
        }
    }

    pub fn add_range(&mut self, start: usize, end: usize) {
        assert!(
            start >= self.current_end,
            "Ranges should be non-overlapping and increasing"
        );

        self.ranges.push((start, end));
        self.idxs.extend(start..end);
        self.current_end = end;
    }

    pub fn get_ranges(&self) -> &Vec<(usize, usize)> {
        &self.ranges
    }

    pub fn get_idx(&self, idx: usize) -> usize {
        self.idxs[idx]
    }

    pub fn get_range(&self, idx: usize) -> (usize, usize) {
        self.ranges[idx]
    }

    pub fn size(&self) -> usize {
        self.idxs.len()
    }

    pub fn num_ranges(&self) -> usize {
        self.ranges.len()
    }
}
