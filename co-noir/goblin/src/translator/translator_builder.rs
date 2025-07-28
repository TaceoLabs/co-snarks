use crate::eccvm::ecc_op_queue::ECCOpQueue;
use ark_ec::CurveGroup;
use ark_ff::Zero;
use co_builder::{TranscriptFieldType, prelude::HonkCurve};

struct TranslatorBuilder<P: CurveGroup> {
    pub variables: Vec<P::ScalarField>,
    next_var_index: Vec<u32>,
    prev_var_index: Vec<u32>,
    pub real_variable_index: Vec<u32>,
    pub(crate) real_variable_tags: Vec<u32>,
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
    fn feed_ecc_op_queue_into_circuit(&mut self, ecc_op_queue: &mut ECCOpQueue<P>) {
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
        // populate_wires_from_ultra_op(ultra_ops[0]);
        // for (auto& wire : wires) {
        //     if (wire.empty()) {
        //         wire.push_back(zero_idx);
        //         wire.push_back(zero_idx);
        //     }
        // }
        // num_gates += 2;

        // // We need to precompute the accumulators at each step, because in the actual circuit we compute the values starting
        // // from the later indices. We need to know the previous accumulator to create the gate
        // for (size_t i = 1; i < ultra_ops.size(); i++) {
        //     const auto& ultra_op = ultra_ops[ultra_ops.size() - i];
        //     current_accumulator *= evaluation_input_x;
        //     const auto [x_256, y_256] = ultra_op.get_base_point_standard_form();
        //     current_accumulator +=
        //         Fq(ultra_op.op_code.value()) +
        //         batching_challenge_v *
        //             (x_256 + batching_challenge_v *
        //                          (y_256 + batching_challenge_v *
        //                                       (uint256_t(ultra_op.z_1) + batching_challenge_v * uint256_t(ultra_op.z_2))));
        //     accumulator_trace.push_back(current_accumulator);
        // }

        // // We don't care about the last value since we'll recompute it during witness generation anyway
        // accumulator_trace.pop_back();

        // // Generate witness values from all the UltraOps
        // for (size_t i = 1; i < ultra_ops.size(); i++) {
        //     const auto& ultra_op = ultra_ops[i];
        //     Fq previous_accumulator = 0;
        //     // Pop the last value from accumulator trace and use it as previous accumulator
        //     if (!accumulator_trace.empty()) {
        //         previous_accumulator = accumulator_trace.back();
        //         accumulator_trace.pop_back();
        //     }
        //     // Compute witness values
        //     AccumulationInput one_accumulation_step =
        //         generate_witness_values(ultra_op, previous_accumulator, batching_challenge_v, evaluation_input_x);

        //     // And put them into the wires
        //     create_accumulation_gate(one_accumulation_step);
        // }
    }

    //     fn populate_wires_from_ultra_op(&mut self,  ultra_op: &mut UltraOp<P::ScalarField>) {
    // {
    //     auto& op_wire = std::get<WireIds::OP>(wires);
    //     op_wire.push_back(add_variable(ultra_op.op_code.value()));
    //     // Similarly to the ColumnPolynomials in the merge protocol, the op_wire is 0 at every second index
    //     op_wire.push_back(zero_idx);

    //     insert_pair_into_wire(WireIds::X_LOW_Y_HI, ultra_op.x_lo, ultra_op.y_hi);

    //     insert_pair_into_wire(WireIds::X_HIGH_Z_1, ultra_op.x_hi, ultra_op.z_1);

    //     insert_pair_into_wire(WireIds::Y_LOW_Z_2, ultra_op.y_lo, ultra_op.z_2);
    // }
    //    void insert_pair_into_wire(WireIds wire_index, Fr first, Fr second)
    //     {
    //         auto& current_wire = wires[wire_index];
    //         current_wire.push_back(add_variable(first));
    //         current_wire.push_back(add_variable(second));
    //     }
}
