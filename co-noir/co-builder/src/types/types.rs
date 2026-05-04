use super::big_group::BigGroup;
use super::field_ct::{CycleGroupCT, CycleScalarCT, FieldCT};
use crate::prelude::GenericUltraCircuitBuilder;
use crate::transcript_ct::{TranscriptCT, TranscriptFieldType, TranscriptHasherCT};
use crate::types::field_ct::BoolCT;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::constants::{NUM_SELECTORS, NUM_WIRES, PAIRING_POINT_ACCUMULATOR_SIZE};
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::polynomials::entities::{PrecomputedEntities, ProverWitnessEntities};
use num_bigint::BigUint;
use std::array;
use std::cmp::Ordering;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};

#[derive(Debug, Default, PartialEq, Eq)]
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

#[derive(Debug, Default, PartialEq, Eq, Clone)]
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

pub(crate) type QuadConstraint<F> = MulQuad<F>;
pub(crate) type BigQuadConstraint<F> = Vec<QuadConstraint<F>>;

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
pub(crate) struct EccAddGate {
    pub(crate) x1: u32,
    pub(crate) y1: u32,
    pub(crate) x2: u32,
    pub(crate) y2: u32,
    pub(crate) x3: u32,
    pub(crate) y3: u32,
    pub(crate) is_addition: bool, // else, subtraction
}

#[derive(Default, PartialEq, Eq)]
pub(crate) struct EccDblGate {
    pub(crate) x1: u32,
    pub(crate) y1: u32,
    pub(crate) x3: u32,
    pub(crate) y3: u32,
}

#[derive(Debug)]
pub(crate) struct MemOp<F: PrimeField> {
    pub(crate) access_type: u8,
    pub(crate) index: WitnessOrConstant<F>,
    pub(crate) value: WitnessOrConstant<F>,
}

#[derive(Debug, PartialEq, Eq, Default)]
#[expect(clippy::upper_case_acronyms)]
pub(crate) enum BlockType {
    #[default]
    ROM = 0,
    RAM = 1,
    CallData = 2,
    ReturnData = 3,
}

#[derive(Debug, Default)]
pub(crate) struct BlockConstraint<F: PrimeField> {
    pub(crate) init: Vec<PolyTriple<F>>,
    pub(crate) trace: Vec<MemOp<F>>,
    pub(crate) type_: BlockType,
    pub(crate) calldata: u32,
}

#[derive(Debug, Default)]
pub(crate) struct AcirFormatOriginalOpcodeIndices {
    pub(crate) logic_constraints: Vec<usize>,
    pub(crate) range_constraints: Vec<usize>,
    pub(crate) aes128_constraints: Vec<usize>,
    pub(crate) sha256_compression: Vec<usize>,
    // std::vector<size_t> ecdsa_k1_constraints;
    // std::vector<size_t> ecdsa_r1_constraints;
    pub(crate) blake2s_constraints: Vec<usize>,
    pub(crate) blake3_constraints: Vec<usize>,
    // std::vector<size_t> keccak_permutations;
    pub(crate) poseidon2_constraints: Vec<usize>,
    pub(crate) multi_scalar_mul_constraints: Vec<usize>,
    pub(crate) ec_add_constraints: Vec<usize>,
    pub(crate) honk_recursion_constraints: Vec<usize>,
    // std::vector<size_t> avm_recursion_constraints;
    // std::vector<size_t> hn_recursion_constraints;
    // std::vector<size_t> chonk_recursion_constraints;
    pub(crate) quad_constraints: Vec<usize>,
    pub(crate) big_quad_constraints: Vec<usize>,
    // Multiple opcode indices per block:
    pub(crate) block_constraints: Vec<Vec<usize>>,
}

pub struct UltraTraceBlocks<T: Default> {
    pub(crate) pub_inputs: T,
    pub(crate) lookup: T,
    pub(crate) arithmetic: T,
    pub(crate) delta_range: T,
    pub(crate) elliptic: T,
    pub(crate) memory: T,
    pub(crate) nnf: T,
    pub(crate) poseidon2_external: T,
    pub(crate) poseidon2_internal: T,
}

impl<T: Default> UltraTraceBlocks<T> {
    pub fn get(&self) -> [&T; 9] {
        [
            &self.pub_inputs,
            &self.lookup,
            &self.arithmetic,
            &self.delta_range,
            &self.elliptic,
            &self.memory,
            &self.nnf,
            &self.poseidon2_external,
            &self.poseidon2_internal,
        ]
    }

    pub fn get_mut(&mut self) -> [&mut T; 9] {
        [
            &mut self.pub_inputs,
            &mut self.lookup,
            &mut self.arithmetic,
            &mut self.delta_range,
            &mut self.elliptic,
            &mut self.memory,
            &mut self.nnf,
            &mut self.poseidon2_external,
            &mut self.poseidon2_internal,
        ]
    }

    pub fn get_pub_inputs(&self) -> &T {
        &self.pub_inputs
    }
}

pub type UltraTraceBlock<F> = ExecutionTraceBlock<F, NUM_WIRES, NUM_SELECTORS>;

pub struct ExecutionTraceBlock<F: PrimeField, const NUM_WIRES: usize, const NUM_SELECTORS: usize> {
    pub wires: [Vec<u32>; NUM_WIRES], // vectors of indices into a witness variables array
    pub selectors: [Vec<F>; NUM_SELECTORS],
    pub has_ram_rom: bool,   // does the block contain RAM/ROM gates
    pub is_pub_inputs: bool, // is this the public inputs block
    pub trace_offset: u32,   // where this block starts in the trace
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
            memory: Default::default(),
            nnf: Default::default(),
            lookup: Default::default(),
            poseidon2_external: Default::default(),
            poseidon2_internal: Default::default(),
        };
        res.pub_inputs.is_pub_inputs = true;
        res.memory.has_ram_rom = true;
        res
    }
}

impl<F: PrimeField> UltraTraceBlocks<UltraTraceBlock<F>> {
    pub fn compute_offsets(&mut self) {
        let mut offset = 1; // start at 1 because the 0th row is unused for selectors for Honk
        for block in self.get_mut() {
            block.trace_offset = offset;
            offset += block.len() as u32;
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
    const Q_MEMORY: usize = PrecomputedEntities::<F>::Q_MEMORY;
    const Q_NNF: usize = PrecomputedEntities::<F>::Q_NNF;
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

    pub(crate) fn q_memory(&mut self) -> &mut Vec<F> {
        &mut self.selectors[Self::Q_MEMORY]
    }

    pub(crate) fn q_nnf(&mut self) -> &mut Vec<F> {
        &mut self.selectors[Self::Q_NNF]
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

    pub fn len(&self) -> usize {
        self.wires[Self::W_L].len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Debug)]
pub(crate) struct RangeConstraint {
    pub(crate) witness: u32,
    pub(crate) num_bits: u32,
}

#[derive(Debug)]
pub(crate) struct Poseidon2Constraint<F: PrimeField> {
    pub(crate) state: Vec<WitnessOrConstant<F>>,
    pub(crate) result: Vec<u32>,
}

#[derive(Debug)]
pub(crate) struct MultiScalarMul<F: PrimeField> {
    pub(crate) points: Vec<WitnessOrConstant<F>>,
    pub(crate) scalars: Vec<WitnessOrConstant<F>>,
    // Predicate indicating whether the constraint should be disabled:
    // - true: the constraint is valid
    // - false: the constraint is disabled, i.e it must not fail and can return whatever.
    pub(crate) predicate: WitnessOrConstant<F>,
    pub(crate) out_point_x: u32,
    pub(crate) out_point_y: u32,
}

#[derive(Debug)]
pub(crate) struct EcAdd<F: PrimeField> {
    pub(crate) input1_x: WitnessOrConstant<F>,
    pub(crate) input1_y: WitnessOrConstant<F>,
    pub(crate) input1_infinite: WitnessOrConstant<F>,
    pub(crate) input2_x: WitnessOrConstant<F>,
    pub(crate) input2_y: WitnessOrConstant<F>,
    pub(crate) input2_infinite: WitnessOrConstant<F>,
    // Predicate indicating whether the constraint should be disabled:
    // - true: the constraint is valid
    // - false: the constraint is disabled, i.e it must not fail and can return whatever.
    pub(crate) predicate: WitnessOrConstant<F>,
    pub(crate) result_x: u32,
    pub(crate) result_y: u32,
}

#[derive(Debug)]
pub(crate) struct Sha256Compression<F: PrimeField> {
    pub(crate) inputs: Vec<WitnessOrConstant<F>>,
    pub(crate) hash_values: Vec<WitnessOrConstant<F>>,
    pub(crate) result: Vec<u32>,
}

#[derive(Debug)]
pub(crate) struct LogicConstraint<F: PrimeField> {
    pub(crate) a: WitnessOrConstant<F>,
    pub(crate) b: WitnessOrConstant<F>,
    pub(crate) result: u32,
    pub(crate) num_bits: u32,
    pub(crate) is_xor_gate: bool,
}

#[derive(Debug)]
pub(crate) struct AES128Constraint<F: PrimeField> {
    pub(crate) inputs: Vec<WitnessOrConstant<F>>,
    pub(crate) iv: Vec<WitnessOrConstant<F>>,
    pub(crate) key: Vec<WitnessOrConstant<F>>,
    pub(crate) outputs: Vec<u32>,
}

#[derive(Debug)]
pub(crate) struct RecursionConstraint<F: PrimeField> {
    // An aggregation state is represented by two G1 affine elements. Each G1 point has
    // two field element coordinates (x, y). Thus, four field elements
    pub(crate) key: Vec<u32>,
    pub(crate) proof: Vec<u32>,
    pub(crate) public_inputs: Vec<u32>,
    pub(crate) key_hash: u32,
    pub(crate) proof_type: u32,
    pub(crate) predicate: WitnessOrConstant<F>,
}

impl<F: PrimeField> RecursionConstraint<F> {
    #[expect(dead_code)]
    const NUM_AGGREGATION_ELEMENTS: usize = 4;
}

#[derive(Debug)]
pub(crate) struct Blake2sConstraint<F: PrimeField> {
    pub(crate) inputs: Vec<WitnessOrConstant<F>>,
    pub(crate) result: [u32; 32],
}

#[derive(Debug)]
pub(crate) struct Blake3Constraint<F: PrimeField> {
    pub(crate) inputs: Vec<WitnessOrConstant<F>>,
    pub(crate) result: [u32; 32],
}

#[derive(Clone)]
pub struct PairingPoints<C: CurveGroup, T: NoirWitnessExtensionProtocol<C::ScalarField>> {
    p0: BigGroup<C::ScalarField, T>,
    p1: BigGroup<C::ScalarField, T>,
    has_data: bool,
}

impl<C: CurveGroup, T: NoirWitnessExtensionProtocol<C::ScalarField>> Default
    for PairingPoints<C, T>
{
    fn default() -> Self {
        Self {
            p0: BigGroup::default(),
            p1: BigGroup::default(),
            has_data: false,
        }
    }
}
// An aggregation state is represented by two G1 affine elements. Each G1 point has
// two field element coordinates (x, y). Thus, four base field elements
// Four limbs are used when simulating a non-native field using the bigfield class, so 16 total field elements.

impl<C: CurveGroup, T: NoirWitnessExtensionProtocol<C::ScalarField>> PairingPoints<C, T> {
    pub fn new(p0: BigGroup<C::ScalarField, T>, p1: BigGroup<C::ScalarField, T>) -> Self {
        Self {
            p0,
            p1,
            has_data: true,
        }
    }

    pub fn reconstruct_from_public(
        public_inputs: &[FieldCT<C::ScalarField>],
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> eyre::Result<Self>
    where
        C::BaseField: PrimeField,
    {
        // Assumes that the app-io public inputs are at the end of the public_inputs vector
        let index = public_inputs.len() - PAIRING_POINT_ACCUMULATOR_SIZE as usize;
        let (p0_limbs, p1_limbs) =
            public_inputs[index..].split_at(PAIRING_POINT_ACCUMULATOR_SIZE as usize / 2);

        let result = Self {
            p0: BigGroup::reconstruct_from_public(p0_limbs, builder, driver)?,
            p1: BigGroup::reconstruct_from_public(p1_limbs, builder, driver)?,
            has_data: true,
        };
        Ok(result)
    }

    pub fn set_public(
        &mut self,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> usize
    where
        C::BaseField: PrimeField,
    {
        let start_idx = self.p0.set_public(driver, builder);
        self.p1.set_public(driver, builder);
        start_idx
    }
}
impl<C: HonkCurve<TranscriptFieldType>, T: NoirWitnessExtensionProtocol<C::ScalarField>>
    PairingPoints<C, T>
{
    pub fn update<H: TranscriptHasherCT<C>>(
        &mut self,
        other: Self,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        if self.has_data {
            self.aggregate::<H>(other, builder, driver)
        } else {
            *self = other;
            Ok(())
        }
    }
    pub fn aggregate<H: TranscriptHasherCT<C>>(
        &mut self,
        other: PairingPoints<C, T>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        assert!(other.has_data, "Cannot aggregate null pairing points.");

        // If LHS is empty, simply set it equal to the incoming pairing points
        if !self.has_data && other.has_data {
            *self = other;
            return Ok(());
        }
        let mut transcript = TranscriptCT::<C, H>::new();

        transcript.send_point_to_verifier(
            "Accumulator_P0".to_string(),
            &self.p0,
            builder,
            driver,
        )?;
        transcript.send_point_to_verifier(
            "Accumulator_P1".to_string(),
            &self.p1,
            builder,
            driver,
        )?;
        transcript.send_point_to_verifier(
            "Aggregated_P0".to_string(),
            &other.p0,
            builder,
            driver,
        )?;
        transcript.send_point_to_verifier(
            "Aggregated_P1".to_string(),
            &other.p1,
            builder,
            driver,
        )?;
        let recursion_separator =
            transcript.get_challenge("recursion_separator".to_string(), builder, driver)?;
        // Save gates using short scalars. We don't apply `bn254_endo_batch_mul` to the vector {1,
        // recursion_separator} directly to avoid edge cases.
        let mut point_to_aggregate =
            other
                .p0
                .clone()
                .scalar_mul(&recursion_separator, 128, builder, driver)?;
        self.p0
            .add_assign(&mut point_to_aggregate, builder, driver)?;

        point_to_aggregate =
            other
                .p1
                .clone()
                .scalar_mul(&recursion_separator, 128, builder, driver)?;
        self.p1
            .add_assign(&mut point_to_aggregate, builder, driver)?;

        Ok(())
    }
}

pub const AGGREGATION_OBJECT_SIZE: usize = 16;

#[derive(PartialEq, Eq, Debug)]
pub(crate) enum MemorySelectors {
    MemNone,
    RamConsistencyCheck,
    RomConsistencyCheck,
    RamTimestampCheck,
    RomRead,
    RamRead,
    RamWrite,
}

#[derive(PartialEq, Eq, Debug)]
pub(crate) enum NnfSelectors {
    NnfNone,
    LimbAccumulate1,
    LimbAccumulate2,
    NonNativeField1,
    NonNativeField2,
    NonNativeField3,
}

#[derive(Clone, Debug)]
pub(crate) struct RangeList {
    pub(crate) target_range: u64,
    pub(crate) range_tag: u32,
    pub(crate) tau_tag: u32,
    pub(crate) variable_indices: Vec<u32>,
}

#[derive(Clone)]
pub(crate) struct CachedPartialNonNativeFieldMultiplication {
    pub(crate) a: [u32; 4],
    pub(crate) b: [u32; 4],
    pub(crate) lo_0: u32,
    pub(crate) hi_0: u32,
    pub(crate) hi_1: u32,
}

impl CachedPartialNonNativeFieldMultiplication {
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

    pub(crate) fn deduplicate<
        F: PrimeField,
        C: CurveGroup<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<F>,
    >(
        builder: &mut GenericUltraCircuitBuilder<C, T>,
    ) -> Vec<Self> {
        let mut hash_set = HashSet::new();
        let mut unique_vec = Vec::new();

        for element in builder
            .cached_partial_non_native_field_multiplications
            .clone()
            .iter()
        {
            if hash_set.insert(element.clone()) {
                unique_vec.push(element.clone());
            } else {
                let existing_entry = hash_set.get(element).unwrap();
                builder.assert_equal(element.lo_0 as usize, existing_entry.lo_0 as usize);
                builder.assert_equal(element.hi_0 as usize, existing_entry.hi_0 as usize);
                builder.assert_equal(element.hi_1 as usize, existing_entry.hi_1 as usize);
            }
        }
        unique_vec
    }
}

impl PartialOrd for CachedPartialNonNativeFieldMultiplication {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CachedPartialNonNativeFieldMultiplication {
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

impl PartialEq for CachedPartialNonNativeFieldMultiplication {
    fn eq(&self, other: &Self) -> bool {
        self.equal(other)
    }
}

impl Eq for CachedPartialNonNativeFieldMultiplication {}

impl Hash for CachedPartialNonNativeFieldMultiplication {
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
    pub(crate) index: u32,
    pub(crate) value: F,
    pub(crate) is_constant: bool,
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
            index: u32::MAX,
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
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        input_x: &Self,
        input_y: &Self,
        input_infinity: &Self,
        predicate: &BoolCT<P::ScalarField, T>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<CycleGroupCT<P, T>> {
        let constant_coordinates = input_x.is_constant && input_y.is_constant;
        let mut point_x = input_x.to_field_ct();
        let mut point_y = input_y.to_field_ct();
        let infinity = input_infinity.to_field_ct().to_bool_ct(builder, driver);

        // If a witness is not provided (we are in a write_vk scenario) we ensure the coordinates correspond to a valid
        // point to avoid erroneous failures during circuit construction. We only do this if the coordinates are
        // non-constant since otherwise no variable indices exist. Note that there is no need to assign the infinite flag
        // because native on-curve checks will always pass as long x and y coordinates correspond to a valid point on
        // Grumpkin.
        let g1_y = F::from(BigUint::new(vec![
            2185176876, 2201994381, 4044886676, 757534021, 111435107, 3474153077, 2,
        ]));
        if builder.is_write_vk_mode && !constant_coordinates {
            builder.set_variable(input_x.index, F::one().into());
            builder.set_variable(input_y.index, g1_y.into());
            if !input_infinity.is_constant {
                builder.set_variable(input_infinity.index, F::zero().into());
            }
        }

        if !predicate.is_constant() {
            point_x = FieldCT::conditional_assign(
                predicate,
                &point_x,
                &FieldCT::from(F::one()),
                builder,
                driver,
            )?;
            point_y = FieldCT::conditional_assign(
                predicate,
                &point_y,
                &FieldCT::from(g1_y),
                builder,
                driver,
            )?;
            let _ = BoolCT::conditional_assign(
                predicate,
                &infinity,
                &BoolCT::from(false),
                builder,
                driver,
            )?;
        }

        CycleGroupCT::new(point_x, point_y, true, builder, driver)
    }

    pub(crate) fn to_grumpkin_scalar<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        scalar_lo: &Self,
        scalar_hi: &Self,
        predicate: &BoolCT<P::ScalarField, T>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<CycleScalarCT<F>> {
        let mut lo_as_field = scalar_lo.to_field_ct();
        let mut hi_as_field = scalar_hi.to_field_ct();

        assert!(
            !scalar_lo.is_constant || scalar_hi.is_constant,
            "to_grumpkin_scalar: scalar_lo is constant while scalar_hi is not."
        );

        if builder.is_write_vk_mode {
            if !scalar_lo.is_constant {
                builder.set_variable(scalar_lo.index, F::one().into());
            }
            if !scalar_hi.is_constant {
                builder.set_variable(scalar_hi.index, F::zero().into());
            }
        }

        if !predicate.is_constant() {
            lo_as_field = FieldCT::conditional_assign(
                predicate,
                &lo_as_field,
                &FieldCT::from(F::one()),
                builder,
                driver,
            )?;
            hi_as_field = FieldCT::conditional_assign(
                predicate,
                &hi_as_field,
                &FieldCT::from(F::zero()),
                builder,
                driver,
            )?;
        } else {
            let predicate_value = predicate.get_value(driver);
            let predicate_value = T::get_public(&predicate_value).expect("Constants are public");
            assert!(
                !predicate_value.is_zero(),
                "Creating Grumpkin scalar with a constant predicate equal to false."
            );
        }

        CycleScalarCT::new(lo_as_field, hi_as_field, false, builder, driver)
    }
}

pub(crate) type AddSimple<F> = (
    (u32, F), // Scaled witness
    (u32, F), // Scaled witness
    F,
);

pub(crate) struct NonNativeMultiplicationFieldWitnesses<F: PrimeField> {
    pub(crate) a: [u32; 4],
    pub(crate) b: [u32; 4],
    pub(crate) q: [u32; 4],
    pub(crate) r: [u32; 4],
    pub(crate) neg_modulus: [F; 4],
}
