use crate::{
    NUM_BINARY_LIMBS, NUM_MICRO_LIMBS, NUM_RELATION_WIDE_LIMBS, NUM_Z_LIMBS,
    eccvm::ecc_op_queue::ECCOpQueue, prelude::UltraOp,
};
use ark_ec::CurveGroup;
use ark_ff::Zero;
use co_builder::{TranscriptFieldType, prelude::HonkCurve};
use num_bigint::BigUint;

const NUM_WIRES: usize = 81;
const ZERO_IDX: usize = 0;
const ONE_IDX: usize = 1;

struct TranslatorBuilder<P: CurveGroup> {
    pub variables: Vec<P::ScalarField>,
    next_var_index: Vec<u32>,
    prev_var_index: Vec<u32>,
    pub real_variable_index: Vec<u32>,
    pub(crate) real_variable_tags: Vec<u32>,
    batching_challenge_v: P::BaseField,
    evaluation_input_x: P::BaseField,
    wires: [Vec<u32>; NUM_WIRES],
    num_gates: usize,
}
impl<P: HonkCurve<TranscriptFieldType>> TranslatorBuilder<P> {
    pub(crate) const DUMMY_TAG: u32 = 0;
    pub(crate) const REAL_VARIABLE: u32 = u32::MAX - 1;
    pub(crate) const FIRST_VARIABLE_IN_CLASS: u32 = u32::MAX - 2;
    pub(crate) fn add_variable(&mut self, value: P::ScalarField) -> u32 {
        let idx = self.variables.len() as u32;
        self.variables.push(value);
        self.real_variable_index.push(idx);
        self.next_var_index.push(Self::REAL_VARIABLE);
        self.prev_var_index.push(Self::FIRST_VARIABLE_IN_CLASS);
        self.real_variable_tags.push(Self::DUMMY_TAG);
        idx
    }
    fn feed_ecc_op_queue_into_circuit(
        &mut self,
        batching_challenge_v: P::BaseField,
        evaluation_input_x: P::BaseField,
        ecc_op_queue: &mut ECCOpQueue<P>,
    ) {
        self.evaluation_input_x = evaluation_input_x;
        self.batching_challenge_v = batching_challenge_v;
        let ultra_ops = ecc_op_queue.get_ultra_ops();
        let mut accumulator_trace: Vec<P::BaseField> = Vec::new();
        let current_accumulator = P::BaseField::zero();
        if ultra_ops.is_empty() {
            return;
        }

        // Process the first UltraOp - a no-op - and populate with zeros the beginning of all other wires to ensure all wire
        // polynomials in translator start with 0 (required for shifted polynomials in the proving system). Technically,
        // we'd need only first index to be a zero but, given each "real" UltraOp populates two indices in a polynomial we
        // add two zeros for consistency.
        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1360): We'll also have to eventually process random
        // data in the merge protocol (added for zero knowledge)/
        self.populate_wires_from_ultra_op(&ultra_ops[0]);
        for wire in self.wires.iter_mut() {
            // Push two zeros to each wire to ensure the first two indices are zero
            if wire.is_empty() {
                wire.push(ZERO_IDX as u32);
                wire.push(ZERO_IDX as u32);
            }
        }

        self.num_gates += 2;

        // We need to precompute the accumulators at each step, because in the actual circuit we compute the values starting
        // from the later indices. We need to know the previous accumulator to create the gate
        let mut current_accumulator = current_accumulator;
        for i in 1..ultra_ops.len() {
            let ultra_op = &ultra_ops[ultra_ops.len() - i];
            current_accumulator *= evaluation_input_x;
            let (x_256, y_256) = ultra_op.get_base_point_standard_form();
            let z1: BigUint = ultra_op.z_1.into();
            let z2: BigUint = ultra_op.z_2.into();
            let z1: P::BaseField = z1.into();
            let z2: P::BaseField = z2.into();
            current_accumulator += P::BaseField::from(ultra_op.op_code.value())
                + batching_challenge_v
                    * (x_256
                        + batching_challenge_v
                            * (y_256 + batching_challenge_v * (z1 + batching_challenge_v * z2)));
            accumulator_trace.push(current_accumulator);
        }

        // We don't care about the last value since we'll recompute it during witness generation anyway
        accumulator_trace.pop();

        // Generate witness values from all the UltraOps
        for i in 1..ultra_ops.len() {
            let ultra_op = &ultra_ops[i];
            let mut previous_accumulator = P::BaseField::zero();
            // Pop the last value from accumulator trace and use it as previous accumulator
            if let Some(last) = accumulator_trace.pop() {
                previous_accumulator = last;
            }
            // Compute witness values
            let one_accumulation_step = self.generate_witness_values(
                ultra_op,
                previous_accumulator,
                batching_challenge_v,
                evaluation_input_x,
            );

            // And put them into the wires
            self.create_accumulation_gate(one_accumulation_step);
        }
    }

    fn populate_wires_from_ultra_op(&mut self, ultra_op: &UltraOp<P>) {
        let idx = self.add_variable(P::ScalarField::from(ultra_op.op_code.value()));
        self.wires[WireIds::OP.as_usize()].push(idx);
        // Similarly to the ColumnPolynomials in the merge protocol, the op_wire is 0 at every second index
        self.wires[WireIds::OP.as_usize()].push(ZERO_IDX as u32);

        self.insert_pair_into_wire(WireIds::X_LOW_Y_HI, ultra_op.x_lo, ultra_op.y_hi);
        self.insert_pair_into_wire(WireIds::X_HIGH_Z_1, ultra_op.x_hi, ultra_op.z_1);
        self.insert_pair_into_wire(WireIds::Y_LOW_Z_2, ultra_op.y_lo, ultra_op.z_2);
    }
    fn insert_pair_into_wire(
        &mut self,
        wire_index: WireIds,
        first: P::ScalarField,
        second: P::ScalarField,
    ) {
        let first_idx = self.add_variable(first);
        let second_idx = self.add_variable(second);
        let wire = &mut self.wires[wire_index.as_usize()];
        wire.push(first_idx);
        wire.push(second_idx);
    }
}

#[allow(non_camel_case_types)]
#[repr(usize)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WireIds {
    OP, // The first 4 wires contain the standard values from the EccQueue wire
    X_LOW_Y_HI,
    X_HIGH_Z_1,
    Y_LOW_Z_2,
    P_X_LOW_LIMBS,               // P.xₗₒ split into 2 68 bit limbs
    P_X_HIGH_LIMBS,              // P.xₕᵢ split into a 68 and a 50 bit limb
    P_Y_LOW_LIMBS,               // P.yₗₒ split into 2 68 bit limbs
    P_Y_HIGH_LIMBS,              // P.yₕᵢ split into a 68 and a 50 bit limb
    Z_LOW_LIMBS,                 // Low limbs of z_1 and z_2 (68 bits each)
    Z_HIGH_LIMBS,                // High Limbs of z_1 and z_2 (60 bits each)
    ACCUMULATORS_BINARY_LIMBS_0, // Contain 68-bit limbs of current and previous accumulator (previous at higher
    // indices because of the nuances of KZG commitment).
    ACCUMULATORS_BINARY_LIMBS_1,
    ACCUMULATORS_BINARY_LIMBS_2,
    ACCUMULATORS_BINARY_LIMBS_3, // Highest limb is 50 bits (254 mod 68)    P_X_LOW_LIMBS_RANGE_CONSTRAINT_0, // Low
    // limbs split further into smaller chunks for range constraints
    QUOTIENT_LOW_BINARY_LIMBS, // Quotient limbs
    QUOTIENT_HIGH_BINARY_LIMBS,
    RELATION_WIDE_LIMBS, // Limbs for checking the correctness of  mod 2²⁷² relations.
    P_X_LOW_LIMBS_RANGE_CONSTRAINT_0, // Low limbs split further into smaller chunks for range constraints
    P_X_LOW_LIMBS_RANGE_CONSTRAINT_1,
    P_X_LOW_LIMBS_RANGE_CONSTRAINT_2,
    P_X_LOW_LIMBS_RANGE_CONSTRAINT_3,
    P_X_LOW_LIMBS_RANGE_CONSTRAINT_4,
    P_X_LOW_LIMBS_RANGE_CONSTRAINT_TAIL,
    P_X_HIGH_LIMBS_RANGE_CONSTRAINT_0, // High limbs split into chunks for range constraints
    P_X_HIGH_LIMBS_RANGE_CONSTRAINT_1,
    P_X_HIGH_LIMBS_RANGE_CONSTRAINT_2,
    P_X_HIGH_LIMBS_RANGE_CONSTRAINT_3,
    P_X_HIGH_LIMBS_RANGE_CONSTRAINT_4,
    P_X_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL,
    P_Y_LOW_LIMBS_RANGE_CONSTRAINT_0, // Low limbs split into chunks for range constraints
    P_Y_LOW_LIMBS_RANGE_CONSTRAINT_1,
    P_Y_LOW_LIMBS_RANGE_CONSTRAINT_2,
    P_Y_LOW_LIMBS_RANGE_CONSTRAINT_3,
    P_Y_LOW_LIMBS_RANGE_CONSTRAINT_4,
    P_Y_LOW_LIMBS_RANGE_CONSTRAINT_TAIL,
    P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_0, // High limbs split into chunks for range constraints
    P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_1,
    P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_2,
    P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_3,
    P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_4,
    P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL,
    Z_LOW_LIMBS_RANGE_CONSTRAINT_0, // Range constraints for low limbs of z_1 and z_2
    Z_LOW_LIMBS_RANGE_CONSTRAINT_1,
    Z_LOW_LIMBS_RANGE_CONSTRAINT_2,
    Z_LOW_LIMBS_RANGE_CONSTRAINT_3,
    Z_LOW_LIMBS_RANGE_CONSTRAINT_4,
    Z_LOW_LIMBS_RANGE_CONSTRAINT_TAIL,
    Z_HIGH_LIMBS_RANGE_CONSTRAINT_0, // Range constraints for high limbs of z_1 and z_2
    Z_HIGH_LIMBS_RANGE_CONSTRAINT_1,
    Z_HIGH_LIMBS_RANGE_CONSTRAINT_2,
    Z_HIGH_LIMBS_RANGE_CONSTRAINT_3,
    Z_HIGH_LIMBS_RANGE_CONSTRAINT_4,
    Z_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL,

    ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_0, // Range constraints for the current accumulator limbs (no need to
    // redo previous accumulator)
    ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_1,
    ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_2,
    ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_3,
    ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_4,
    ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_TAIL,
    ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_0,
    ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_1,
    ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_2,
    ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_3,
    ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_4,
    ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_TAIL,

    QUOTIENT_LOW_LIMBS_RANGE_CONSTRAIN_0, // Range constraints for quotient
    QUOTIENT_LOW_LIMBS_RANGE_CONSTRAIN_1,
    QUOTIENT_LOW_LIMBS_RANGE_CONSTRAIN_2,
    QUOTIENT_LOW_LIMBS_RANGE_CONSTRAIN_3,
    QUOTIENT_LOW_LIMBS_RANGE_CONSTRAIN_4,
    QUOTIENT_LOW_LIMBS_RANGE_CONSTRAIN_TAIL,
    QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAIN_0,
    QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAIN_1,
    QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAIN_2,
    QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAIN_3,
    QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAIN_4,
    QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAIN_TAIL,
    RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_0,
    RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_1,
    RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_2,
    RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_3,

    TOTAL_COUNT,
}

impl WireIds {
    pub const fn as_usize(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Debug)]
struct AccumulationInput<P: HonkCurve<TranscriptFieldType>> {
    // Members necessary for the gate creation
    ultra_op: UltraOp<P>,

    p_x_limbs: [P::ScalarField; NUM_BINARY_LIMBS],
    p_x_microlimbs: [[P::ScalarField; NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS],

    p_y_limbs: [P::ScalarField; NUM_BINARY_LIMBS],
    p_y_microlimbs: [[P::ScalarField; NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS],

    z_1_limbs: [P::ScalarField; NUM_Z_LIMBS],
    z_1_microlimbs: [[P::ScalarField; NUM_MICRO_LIMBS]; NUM_Z_LIMBS],
    z_2_limbs: [P::ScalarField; NUM_Z_LIMBS],
    z_2_microlimbs: [[P::ScalarField; NUM_MICRO_LIMBS]; NUM_Z_LIMBS],

    previous_accumulator: [P::ScalarField; NUM_BINARY_LIMBS],
    current_accumulator: [P::ScalarField; NUM_BINARY_LIMBS],
    current_accumulator_microlimbs: [[P::ScalarField; NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS],

    quotient_binary_limbs: [P::ScalarField; NUM_BINARY_LIMBS],
    quotient_microlimbs: [[P::ScalarField; NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS],

    relation_wide_limbs: [P::ScalarField; NUM_RELATION_WIDE_LIMBS],
    relation_wide_microlimbs: [[P::ScalarField; NUM_MICRO_LIMBS]; 2],
}

impl<P: HonkCurve<TranscriptFieldType>> AccumulationInput<P> {
    fn new(ultra_op: UltraOp<P>, zero: P::ScalarField) -> Self {
        Self {
            ultra_op,
            p_x_limbs: [zero; NUM_BINARY_LIMBS],
            p_x_microlimbs: [[zero; NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS],
            p_y_limbs: [zero; NUM_BINARY_LIMBS],
            p_y_microlimbs: [[zero; NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS],
            z_1_limbs: [zero; NUM_Z_LIMBS],
            z_1_microlimbs: [[zero; NUM_MICRO_LIMBS]; NUM_Z_LIMBS],
            z_2_limbs: [zero; NUM_Z_LIMBS],
            z_2_microlimbs: [[zero; NUM_MICRO_LIMBS]; NUM_Z_LIMBS],
            previous_accumulator: [zero; NUM_BINARY_LIMBS],
            current_accumulator: [zero; NUM_BINARY_LIMBS],
            current_accumulator_microlimbs: [[zero; NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS],
            quotient_binary_limbs: [zero; NUM_BINARY_LIMBS],
            quotient_microlimbs: [[zero; NUM_MICRO_LIMBS]; NUM_BINARY_LIMBS],
            relation_wide_limbs: [zero; NUM_RELATION_WIDE_LIMBS],
            relation_wide_microlimbs: [[zero; NUM_MICRO_LIMBS]; 2],
        }
    }
}
