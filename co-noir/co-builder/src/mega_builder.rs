use std::collections::BTreeMap;

use ark_ec::CurveGroup;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use common::{honk_curve::HonkCurve, honk_proof::TranscriptFieldType};

use crate::{eccvm::ecc_op_queue::{ECCOpQueue, ECCOpTuple, EccOpCode, UltraOp}, types::types::{MegaTraceBlock, MegaTraceBlocks}};
use ark_ff::Zero;
use ark_ff::One;

type GateBlocks<F> = MegaTraceBlocks<MegaTraceBlock<F>>;

pub struct MegaCircuitBuilder<
    P: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<P::ScalarField>,
> {
    pub variables: Vec<T::AcvmType>,
    next_var_index: Vec<u32>,
    prev_var_index: Vec<u32>,
    pub real_variable_index: Vec<u32>,
    constant_variable_indices: BTreeMap<P::ScalarField, u32>,
    pub(crate) public_inputs: Vec<u32>,
    pub(crate) num_gates: usize,
    pub(crate) real_variable_tags: Vec<u32>,
    pub(crate) current_tag: u32,
    pub(crate) blocks: GateBlocks<P::ScalarField>,
    pub(crate) ecc_op_queue: ECCOpQueue<P>,
    pub(crate) null_op_idx: u32,
    pub(crate) add_accum_op_idx: u32,
    pub(crate) mul_accum_op_idx: u32,
    pub(crate) equality_op_idx: u32,
}

impl<P: HonkCurve<TranscriptFieldType>, T: NoirWitnessExtensionProtocol<P::ScalarField>> MegaCircuitBuilder<P, T> {

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

    pub(crate) fn new(mut ecc_op_queue: ECCOpQueue<P>) -> Self {
        ecc_op_queue.initialize_new_subtable();
        let builder = Self {
            variables: vec![],
            next_var_index: vec![],
            prev_var_index: vec![],
            real_variable_index: vec![],
            real_variable_tags: vec![],
            constant_variable_indices: BTreeMap::new(),
            public_inputs: vec![],
            num_gates: 0,
            current_tag: Self::DUMMY_TAG + 1,
            blocks: GateBlocks::default(),
            ecc_op_queue,
        };
        builder.set_goblin_ecc_op_code_constant_variables();
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

    fn is_valid_variable(&self, variable_index: usize) -> bool {
        variable_index < self.variables.len()
    }

    fn assert_valid_variables(&self, variable_indices: &[u32]) {
        for variable_index in variable_indices.iter().cloned() {
            assert!(self.is_valid_variable(variable_index as usize));
        }
    }

    fn fix_witness(&mut self, witness_index: u32, witness_value: P::ScalarField) {
        self.assert_valid_variables(&[witness_index]);

        self.blocks.arithmetic.populate_wires(
            witness_index,
            self.null_op_idx,
            self.null_op_idx,
            self.null_op_idx,
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

    pub(crate) fn check_selector_length_consistency(&self) {
        for block in self.blocks.get() {
            let nominal_size = block.selectors[0].len();
            for selector in block.selectors.iter().skip(1) {
                debug_assert_eq!(selector.len(), nominal_size);
            }
        }
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

    fn set_goblin_ecc_op_code_constant_variables(&mut self) {
        self.null_op_idx = 0; // constant 0 is is associated with the zero index
        self.add_accum_op_idx = self.put_constant_variable(P::ScalarField::from(EccOpCode {add: true, ..Default::default()}.value()));
        self.mul_accum_op_idx = self.put_constant_variable(P::ScalarField::from(EccOpCode {mul: true, ..Default::default()}.value()));
        self.equality_op_idx = self.put_constant_variable(P::ScalarField::from(EccOpCode {eq: true, reset: true, ..Default::default()}.value()));
    }

    /**
     * @brief Add goblin ecc op gates for a single operation
     *
     * @param ultra_op Operation data expressed in the ultra format
     * @note All selectors are set to 0 since the ecc op selector is derived later based on the block size/location.
     */
    fn populate_ecc_op_wires(&mut self, ultra_op: &UltraOp<P>) -> ECCOpTuple {
        // TODO CESAR: Should this be arithmetic shared
        let op = self.get_ecc_op_idx(&ultra_op.op_code);
        let x_lo = self.add_variable(ultra_op.x_lo.into());
        let x_hi = self.add_variable(ultra_op.x_hi.into());
        let y_lo = self.add_variable(ultra_op.y_lo.into());
        let y_hi = self.add_variable(ultra_op.y_hi.into());
        let z_1 = self.add_variable(ultra_op.z_1.into());
        let z_2 = self.add_variable(ultra_op.z_2.into());

        // First set of wires
        self.blocks.ecc_op.populate_wires(op, x_lo, x_hi, y_lo);
        for selector in self.blocks.ecc_op.selectors.iter_mut() {
            selector.push(P::ScalarField::zero());
        }

        // Second set of wires
        self.blocks.ecc_op.populate_wires(self.null_op_idx, y_hi, z_1, z_2);
        for selector in self.blocks.ecc_op.selectors.iter_mut() {
            selector.push(P::ScalarField::zero());
        }

        ECCOpTuple {
            op,
            x_lo,
            x_hi,
            y_lo,
            y_hi,
            z_1,
            z_2,
            // TODO CESAR: Check
            return_is_infinity: Default::default(),
        }
    }

    fn get_ecc_op_idx(&self, op_code: &EccOpCode) -> u32 {
        if op_code.add {
            self.add_accum_op_idx
        } else if op_code.mul {
            self.mul_accum_op_idx
        } else if op_code.eq && op_code.reset {
            self.equality_op_idx
        } else if !op_code.add && !op_code.mul && !op_code.eq && !op_code.reset {
            self.null_op_idx
        } else {
            panic!("Invalid op code");
        }
    }

    /**
     * Add point mul-then-accumulate operation to the op queue and add corresponding gates.
     *
     * @param point The affine point to multiply.
     * @param scalar The scalar by which point is multiplied prior to being accumulated.
     * @return ECCOpTuple encoding the point and scalar inputs to the mul accum.
     */
    pub fn queue_ecc_mul_accum(
        &mut self,
        point: P::Affine,
        scalar: P::ScalarField,
    ) -> ECCOpTuple {
        // Add the operation to the op queue
        let ultra_op = self.ecc_op_queue.mul_accumulate(point, scalar);

        // Add corresponding gates for the operation
        self.populate_ecc_op_wires(&ultra_op)
    }

    /**
     * @brief Add point equality operation to the op queue based on the value of the internal accumulator and add
     * corresponding gates
     *
     * @return ecc_op_tuple encoding the point to which equality has been asserted
     */
    pub fn queue_ecc_eq(&mut self) -> ECCOpTuple {
        // Add the operation to the op queue
        let ultra_op = self.ecc_op_queue.eq_and_reset();

        // Add corresponding gates for the operation
        let mut op_tuple = self.populate_ecc_op_wires(&ultra_op);
        op_tuple.return_is_infinity = ultra_op.return_is_infinity;
        op_tuple
    }

    /**
     * @brief Logic for a no-op operation.
     *
     * @return ecc_op_tuple with all its fields set to zero
     */
    fn queue_ecc_no_op(&mut self) -> ECCOpTuple{
        // Add the operation to the op queue
        let ultra_op = self.ecc_op_queue.no_op_ultra_only();

        // Add corresponding gates for the operation
        self.populate_ecc_op_wires(&ultra_op)
    }

    pub fn add_public_variable(&mut self, value: T::AcvmType) -> u32 {
        let index = self.add_variable(value);
        self.public_inputs.push(index);
        index
    }
}  