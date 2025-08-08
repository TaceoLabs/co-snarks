use super::big_field::BigGroup;
use super::field_ct::{CycleGroupCT, FieldCT};
use crate::flavours::ultra_flavour::UltraFlavour;
use crate::keys::proving_key::ProvingKey;
use crate::polynomials::polynomial::Polynomial;
use crate::polynomials::polynomial_flavours::{
    PrecomputedEntitiesFlavour, ProverWitnessEntitiesFlavour,
};
use crate::prelude::GenericUltraCircuitBuilder;
use crate::prover_flavour::ProverFlavour;
use crate::ultra_builder::UltraCircuitBuilder;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::array;
use std::cmp::Ordering;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ZeroKnowledge {
    No,
    Yes,
}

impl From<bool> for ZeroKnowledge {
    fn from(value: bool) -> Self {
        if value {
            ZeroKnowledge::Yes
        } else {
            ZeroKnowledge::No
        }
    }
}

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

#[derive(Default, PartialEq, Eq)]
pub(crate) struct EccAddGate<F: PrimeField> {
    pub(crate) x1: u32,
    pub(crate) y1: u32,
    pub(crate) x2: u32,
    pub(crate) y2: u32,
    pub(crate) x3: u32,
    pub(crate) y3: u32,
    pub(crate) sign_coefficient: F,
}

#[derive(Default, PartialEq, Eq)]
pub(crate) struct EccDblGate {
    pub(crate) x1: u32,
    pub(crate) y1: u32,
    pub(crate) x3: u32,
    pub(crate) y3: u32,
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
    pub(crate) aes128_constraints: Vec<usize>,
    // pub(crate) sha256_constraints: Vec<usize>,
    pub(crate) sha256_compression: Vec<usize>,
    // pub(crate) schnorr_constraints: Vec<usize>,
    // pub(crate) ecdsa_k1_constraints: Vec<usize>,
    // pub(crate) ecdsa_r1_constraints: Vec<usize>,
    pub(crate) blake2s_constraints: Vec<usize>,
    pub(crate) blake3_constraints: Vec<usize>,
    // pub(crate) keccak_constraints: Vec<usize>,
    // pub(crate) keccak_permutations: Vec<usize>,
    // pub(crate) pedersen_constraints: Vec<usize>,
    // pub(crate) pedersen_hash_constraints: Vec<usize>,
    pub(crate) poseidon2_constraints: Vec<usize>,
    pub(crate) multi_scalar_mul_constraints: Vec<usize>,
    pub(crate) ec_add_constraints: Vec<usize>,
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

    pub(crate) fn get_total_content_size(&self) -> usize {
        let mut total_size = 0;
        for block in self.get() {
            total_size += block.len();
        }
        total_size
    }
}

impl<F: PrimeField> UltraTraceBlock<F> {
    const W_L: usize = UltraFlavour::W_L;
    const W_R: usize = UltraFlavour::W_R;
    const W_O: usize = UltraFlavour::W_O;
    const W_4: usize = UltraFlavour::W_4;
    const Q_M: usize = UltraFlavour::Q_M;
    const Q_C: usize = UltraFlavour::Q_C;
    const Q_1: usize = UltraFlavour::Q_L;
    const Q_2: usize = UltraFlavour::Q_R;
    const Q_3: usize = UltraFlavour::Q_O;
    const Q_4: usize = UltraFlavour::Q_4;
    const Q_ARITH: usize = UltraFlavour::Q_ARITH;
    const Q_DELTA_RANGE: usize = UltraFlavour::Q_DELTA_RANGE;
    const Q_ELLIPTIC: usize = UltraFlavour::Q_ELLIPTIC;
    const Q_AUX: usize = UltraFlavour::Q_AUX;
    const Q_LOOKUP_TYPE: usize = UltraFlavour::Q_LOOKUP;
    const Q_POSEIDON2_EXTERNAL: usize = UltraFlavour::Q_POSEIDON2_EXTERNAL;
    const Q_POSEIDON2_INTERNAL: usize = UltraFlavour::Q_POSEIDON2_INTERNAL;

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

pub(crate) struct MultiScalarMul<F: PrimeField> {
    pub(crate) points: Vec<WitnessOrConstant<F>>,
    pub(crate) scalars: Vec<WitnessOrConstant<F>>,
    pub(crate) out_point_x: u32,
    pub(crate) out_point_y: u32,
    pub(crate) out_point_is_infinity: u32,
}

pub(crate) struct EcAdd<F: PrimeField> {
    pub(crate) input1_x: WitnessOrConstant<F>,
    pub(crate) input1_y: WitnessOrConstant<F>,
    pub(crate) input1_infinite: WitnessOrConstant<F>,
    pub(crate) input2_x: WitnessOrConstant<F>,
    pub(crate) input2_y: WitnessOrConstant<F>,
    pub(crate) input2_infinite: WitnessOrConstant<F>,
    pub(crate) result_x: u32,
    pub(crate) result_y: u32,
    pub(crate) result_infinite: u32,
}

pub(crate) struct Sha256Compression<F: PrimeField> {
    pub(crate) inputs: Vec<WitnessOrConstant<F>>,
    pub(crate) hash_values: Vec<WitnessOrConstant<F>>,
    pub(crate) result: Vec<u32>,
}

pub(crate) struct LogicConstraint<F: PrimeField> {
    pub(crate) a: WitnessOrConstant<F>,
    pub(crate) b: WitnessOrConstant<F>,
    pub(crate) result: u32,
    pub(crate) num_bits: u32,
    pub(crate) is_xor_gate: bool,
}

pub(crate) struct AES128Constraint<F: PrimeField> {
    pub(crate) inputs: Vec<WitnessOrConstant<F>>,
    pub(crate) iv: Vec<WitnessOrConstant<F>>,
    pub(crate) key: Vec<WitnessOrConstant<F>>,
    pub(crate) outputs: Vec<u32>,
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

#[expect(dead_code)]
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
    #[expect(dead_code)]
    const NUM_AGGREGATION_ELEMENTS: usize = 4;
}

pub(crate) struct Blake2sInput<F: PrimeField> {
    pub(crate) blackbox_input: WitnessOrConstant<F>,
    pub(crate) num_bits: u32,
}

pub(crate) struct Blake2sConstraint<F: PrimeField> {
    pub(crate) inputs: Vec<Blake2sInput<F>>,
    pub(crate) result: [u32; 32],
}

pub(crate) struct Blake3Input<F: PrimeField> {
    pub(crate) blackbox_input: WitnessOrConstant<F>,
    pub(crate) num_bits: u32,
}

pub(crate) struct Blake3Constraint<F: PrimeField> {
    pub(crate) inputs: Vec<Blake3Input<F>>,
    pub(crate) result: [u32; 32],
}

pub(crate) struct AggregationState<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>> {
    p0: BigGroup<P, T>,
    p1: BigGroup<P, T>,
}
impl<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>> AggregationState<P, T> {
    pub(crate) fn new(p0: BigGroup<P, T>, p1: BigGroup<P, T>) -> Self {
        Self { p0, p1 }
    }
}

// An aggregation state is represented by two G1 affine elements. Each G1 point has
// two field element coordinates (x, y). Thus, four base field elements
// Four limbs are used when simulating a non-native field using the bigfield class, so 16 total field elements.
pub const PAIRING_POINT_ACCUMULATOR_SIZE: u32 = 16;

impl<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>> AggregationState<P, T> {
    pub fn set_public(
        &mut self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> usize {
        let start_idx = self.p0.set_public(driver, builder);
        self.p1.set_public(driver, builder);
        builder
            .pairing_inputs_public_input_key
            .set(start_idx as u32);

        start_idx
    }
}

pub const AGGREGATION_OBJECT_SIZE: usize = 16;

#[expect(dead_code)]
#[derive(PartialEq, Eq, Debug)]
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

pub(crate) struct TraceData<'a, P: CurveGroup> {
    pub(crate) wires: &'a mut [Polynomial<P::ScalarField>; NUM_WIRES],
    pub(crate) selectors: &'a mut [Polynomial<P::ScalarField>; NUM_SELECTORS],
    pub(crate) copy_cycles: Vec<CyclicPermutation>,
    pub(crate) ram_rom_offset: u32,
    pub(crate) pub_inputs_offset: u32,
}

impl<'a, P: CurveGroup> TraceData<'a, P> {
    pub(crate) fn new(
        builder: &UltraCircuitBuilder<P>,
        proving_key: &'a mut ProvingKey<P, UltraFlavour>,
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

    #[expect(dead_code)]
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

    pub(crate) fn to_grumpkin_point<
        P: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        input_x: &Self,
        input_y: &Self,
        input_infinity: &Self,
        has_valid_witness_assignments: bool,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> CycleGroupCT<P, T> {
        let point_x = input_x.to_field_ct();
        let point_y = input_y.to_field_ct();
        let infinity = input_infinity.to_field_ct().to_bool_ct(builder, driver);

        // When we do not have the witness assignments, we set is_infinite value to true if it is not constant
        // else default values would give a point which is not on the curve and this will fail verification
        if !has_valid_witness_assignments {
            if !input_infinity.is_constant {
                builder.variables[input_infinity.index as usize] = F::one().into();
            } else if input_infinity.value.is_zero()
                && !(input_x.is_constant || input_y.is_constant)
            {
                // else, if is_infinite is false, but the coordinates (x, y) are witness (and not constant)
                // then we set their value to an arbitrary valid curve point (in our case G1).
                builder.variables[input_x.index as usize] = F::one().into();
                let g1_y = F::from(BigUint::new(vec![
                    2185176876, 2201994381, 4044886676, 757534021, 111435107, 3474153077, 2,
                ]));
                builder.variables[input_y.index as usize] = g1_y.into();
            }
        }
        CycleGroupCT::new(point_x, point_y, infinity, builder, driver)
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub struct ActiveRegionData {
    pub ranges: Vec<(usize, usize)>, // active ranges [start_i, end_i) of the execution trace
    pub idxs: Vec<usize>,            // full set of poly indices corresposponding to active ranges
    pub current_end: usize,          // end of last range; for ensuring monotonicity of ranges
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
