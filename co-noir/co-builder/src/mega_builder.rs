use std::collections::BTreeMap;

use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
};
use mpc_core::gadgets::poseidon2::POSEIDON2_BN254_T4_PARAMS;
use num_bigint::BigUint;

use crate::{
    eccvm::{
        co_ecc_op_queue::{CoECCOpQueue, CoEccOpTuple, CoUltraOp, CoVMOperation, precompute_flags},
        ecc_op_queue::EccOpCode,
    },
    generic_builder::GenericBuilder,
    prelude::NUM_WIRES,
    types::types::{
        AddQuad, AddTriple, MegaTraceBlock, MegaTraceBlocks, MulQuad, PolyTriple,
        Poseidon2ExternalGate, Poseidon2InternalGate, RangeList,
    },
};
use ark_ff::One;
use ark_ff::Zero;

type GateBlocks<F> = MegaTraceBlocks<MegaTraceBlock<F>>;

pub struct MegaCircuitBuilder<
    P: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<P::ScalarField>,
> {
    pub variables: Vec<T::AcvmType>,
    next_var_index: Vec<u32>,
    prev_var_index: Vec<u32>,
    pub real_variable_index: Vec<u32>,
    constant_variable_indices: BTreeMap<P::ScalarField, u32>,
    has_dummy_witnesses: bool,
    range_lists: BTreeMap<u64, RangeList>,
    pub(crate) public_inputs: Vec<u32>,
    pub(crate) num_gates: usize,
    pub(crate) real_variable_tags: Vec<u32>,
    pub(crate) current_tag: u32,
    pub(crate) blocks: GateBlocks<P::ScalarField>,
    pub ecc_op_queue: CoECCOpQueue<T, P>,
    pub(crate) zero_idx: u32,
    pub(crate) add_accum_op_idx: u32,
    pub(crate) mul_accum_op_idx: u32,
    pub(crate) equality_op_idx: u32,
    pub(crate) tau: BTreeMap<u32, u32>,
}

#[expect(private_interfaces)]
impl<P, T> GenericBuilder<P, T> for MegaCircuitBuilder<P, T>
where
    P: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<P::ScalarField>,
{
    type TraceBlock = MegaTraceBlock<P::ScalarField>;

    fn get_new_tag(&mut self) -> u32 {
        self.current_tag += 1;

        self.current_tag
    }

    fn create_tag(&mut self, tag_index: u32, tau_index: u32) -> u32 {
        self.tau.insert(tag_index, tau_index);
        self.current_tag += 1;
        self.current_tag
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
            Self::create_dummy_gate(
                &mut self.blocks.arithmetic,
                chunk[0],
                chunk[1],
                chunk[2],
                chunk[3],
            );
            self.check_selector_length_consistency();
            self.num_gates += 1; // necessary because create dummy gate cannot increment num_gates itself
        }
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

    fn get_poseidon2_external_mut(&mut self) -> &mut Self::TraceBlock {
        &mut self.blocks.poseidon2_external
    }

    fn get_poseidon2_internal_mut(&mut self) -> &mut Self::TraceBlock {
        &mut self.blocks.poseidon2_internal
    }
    fn get_variable(&self, index: usize) -> T::AcvmType {
        assert!(self.variables.len() > index);
        self.variables[self.real_variable_index[index] as usize].to_owned()
    }

    fn add_variable(&mut self, value: T::AcvmType) -> u32 {
        let idx = self.variables.len() as u32;
        self.variables.push(value);
        self.real_variable_index.push(idx);
        self.next_var_index.push(Self::REAL_VARIABLE);
        self.prev_var_index.push(Self::FIRST_VARIABLE_IN_CLASS);
        self.real_variable_tags.push(Self::DUMMY_TAG);
        idx
    }
    fn create_add_gate(&mut self, inp: &AddTriple<P::ScalarField>) {
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
        self.blocks
            .arithmetic
            .q_busread()
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
        self.blocks
            .arithmetic
            .q_busread()
            .push(P::ScalarField::zero());

        self.check_selector_length_consistency();
        self.num_gates += 1;
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
        self.blocks
            .arithmetic
            .q_busread()
            .push(P::ScalarField::zero());

        self.check_selector_length_consistency();
        self.num_gates += 1;
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
        self.blocks
            .arithmetic
            .q_busread()
            .push(P::ScalarField::zero());

        self.check_selector_length_consistency();
        self.num_gates += 1;
    }

    fn create_big_add_gate(&mut self, inp: &AddQuad<P::ScalarField>, include_next_gate_w_4: bool) {
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
        self.blocks
            .arithmetic
            .q_busread()
            .push(P::ScalarField::zero());

        self.check_selector_length_consistency();
        self.num_gates += 1;
    }

    fn create_poseidon2_external_gate(&mut self, inp: &Poseidon2ExternalGate) {
        self.blocks
            .poseidon2_external
            .populate_wires(inp.a, inp.b, inp.c, inp.d);
        self.blocks
            .poseidon2_external
            .q_m()
            .push(P::ScalarField::zero());
        self.blocks
            .poseidon2_external
            .q_1()
            .push(P::ScalarField::from(BigUint::from(
                POSEIDON2_BN254_T4_PARAMS.round_constants_external[inp.round_idx][0],
            )));
        self.blocks
            .poseidon2_external
            .q_2()
            .push(P::ScalarField::from(BigUint::from(
                POSEIDON2_BN254_T4_PARAMS.round_constants_external[inp.round_idx][1],
            )));
        self.blocks
            .poseidon2_external
            .q_3()
            .push(P::ScalarField::from(BigUint::from(
                POSEIDON2_BN254_T4_PARAMS.round_constants_external[inp.round_idx][2],
            )));
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
            .push(P::ScalarField::from(BigUint::from(
                POSEIDON2_BN254_T4_PARAMS.round_constants_external[inp.round_idx][3],
            )));
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
        self.blocks
            .poseidon2_external
            .q_busread()
            .push(P::ScalarField::zero());

        self.check_selector_length_consistency();
        self.num_gates += 1;
    }

    fn create_poseidon2_internal_gate(&mut self, inp: &Poseidon2InternalGate) {
        self.blocks
            .poseidon2_internal
            .populate_wires(inp.a, inp.b, inp.c, inp.d);
        self.blocks
            .poseidon2_internal
            .q_m()
            .push(P::ScalarField::zero());
        self.blocks
            .poseidon2_internal
            .q_1()
            .push(P::ScalarField::from(BigUint::from(
                POSEIDON2_BN254_T4_PARAMS.round_constants_internal[inp.round_idx],
            )));
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
        self.blocks
            .poseidon2_internal
            .q_busread()
            .push(P::ScalarField::zero());

        self.check_selector_length_consistency();
        self.num_gates += 1;
    }

    fn check_selector_length_consistency(&self) {
        for block in self.blocks.get() {
            let nominal_size = block.selectors[0].len();
            for selector in block.selectors.iter().skip(1) {
                debug_assert_eq!(selector.len(), nominal_size);
            }
        }
    }

    fn assert_if_has_witness(&self, input: bool) {
        if self.has_dummy_witnesses {
            return;
        }
        assert!(input)
    }

    fn assert_equal_constant(&mut self, a_idx: usize, b: P::ScalarField) {
        self.assert_if_has_witness(self.variables[a_idx] == T::AcvmType::from(b));
        let b_idx = self.put_constant_variable(b);
        self.assert_equal(a_idx, b_idx as usize);
    }

    fn assert_equal(&mut self, a_idx: usize, b_idx: usize) {
        self.assert_valid_variables(&[a_idx as u32, b_idx as u32]);

        let a = T::get_public(&self.get_variable(a_idx));

        let b = T::get_public(&self.get_variable(b_idx));

        match (a, b) {
            (Some(a), Some(b)) => {
                self.assert_if_has_witness(a == b);
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
        let no_tag_clash = self.real_variable_tags[a_real_idx] == Self::DUMMY_TAG
            || self.real_variable_tags[b_real_idx] == Self::DUMMY_TAG
            || self.real_variable_tags[a_real_idx] == self.real_variable_tags[b_real_idx];
        self.assert_if_has_witness(no_tag_clash);

        if self.real_variable_tags[a_real_idx] == Self::DUMMY_TAG {
            self.real_variable_tags[a_real_idx] = self.real_variable_tags[b_real_idx];
        }
    }

    fn zero_idx(&self) -> u32 {
        self.zero_idx
    }

    fn create_dummy_gate(
        block: &mut MegaTraceBlock<P::ScalarField>,
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
        block.q_busread().push(P::ScalarField::zero());

        // TACEO TODO these are uncommented due to mutability issues
        // Taken care of by the caller uisng the create_dummy_gate! macro
        // self.check_selector_length_consistency();
        // self.num_gates += 1;
    }

    fn update_variable(&mut self, index: usize, value: T::AcvmType) {
        assert!(self.variables.len() > index);
        self.variables[self.real_variable_index[index] as usize] = value;
    }

    fn decompose_into_default_range(
        &mut self,
        driver: &mut T,
        variable_index: u32,
        num_bits: u64,
        decompose: Option<&[T::ArithmeticShare]>, // If already decomposed, values are here
        target_range_bitnum: u64,
    ) -> eyre::Result<Vec<u32>> {
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
        let sublimbs: Vec<T::AcvmType> = match decompose {
            // Already decomposed, i.e., we just take the values
            Some(decomposed) => decomposed
                .iter()
                .map(|item| T::AcvmType::from(item.clone()))
                .collect(),
            None => {
                // Not yet decomposed
                if T::is_shared(&val) {
                    let decomp = T::decompose_arithmetic(
                        driver,
                        T::get_shared(&val).expect("Already checked it is shared"),
                        num_bits as usize,
                        target_range_bitnum as usize,
                    )?;
                    decomp.into_iter().map(T::AcvmType::from).collect()
                } else {
                    let mut accumulator: BigUint = T::get_public(&val)
                        .expect("Already checked it is public")
                        .into();
                    let sublimb_mask: BigUint = sublimb_mask.into();
                    (0..num_limbs)
                        .map(|_| {
                            let sublimb_value = P::ScalarField::from(&accumulator & &sublimb_mask);
                            accumulator >>= target_range_bitnum;
                            T::AcvmType::from(sublimb_value)
                        })
                        .collect()
                }
            }
        };
        for (i, sublimb) in sublimbs.iter().enumerate() {
            let limb_idx = self.add_variable(sublimb.to_owned());

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
                    sublimbs[3 * i as usize]
                } else {
                    T::public_zero()
                },
                if real_limbs[1] {
                    sublimbs[(3 * i + 1) as usize]
                } else {
                    T::public_zero()
                },
                if real_limbs[2] {
                    sublimbs[(3 * i + 2) as usize]
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
            let shiftmask = (BigUint::one() << 256) - BigUint::one(); // Simulate u256
            let shift0 = P::ScalarField::from((BigUint::one() << shifts[0]) & &shiftmask);
            let shift1 = P::ScalarField::from((BigUint::one() << shifts[1]) & &shiftmask);
            let shift2 = P::ScalarField::from((BigUint::one() << shifts[2]) & shiftmask);

            let mut subtrahend = T::mul_with_public(driver, shift0, round_sublimbs[0]);
            let term0 = T::mul_with_public(driver, shift1, round_sublimbs[1]);
            let term1 = T::mul_with_public(driver, shift2, round_sublimbs[2]);
            T::add_assign(driver, &mut subtrahend, term0);
            T::add_assign(driver, &mut subtrahend, term1);

            let new_accumulator = T::sub(driver, accumulator, subtrahend);

            self.create_big_add_gate(
                &AddQuad {
                    a: new_limbs[0],
                    b: new_limbs[1],
                    c: new_limbs[2],
                    d: accumulator_idx,
                    a_scaling: shift0,
                    b_scaling: shift1,
                    c_scaling: shift2,
                    d_scaling: -P::ScalarField::one(),
                    const_scaling: P::ScalarField::zero(),
                },
                i != num_limb_triples - 1,
            );
            accumulator_idx = self.add_variable(new_accumulator);
            accumulator = new_accumulator;
        }

        Ok(sublimb_indices)
    }

    fn create_new_range_constraint(&mut self, variable_index: u32, target_range: u64) {
        // We ignore this check because it is definitely more expensive in MPC, the proof will just not verify if this constraint is not given
        // if (uint256_t(self.get_variable(variable_index)).data[0] > target_range) {
        //     if (!self.failed()) {
        //         self.failure(msg);
        //     }
        // }
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
}

impl<P, T> MegaCircuitBuilder<P, T>
where
    P: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<TranscriptFieldType>,
{
    pub(crate) const DUMMY_TAG: u32 = 0;
    pub(crate) const REAL_VARIABLE: u32 = u32::MAX - 1;
    pub(crate) const FIRST_VARIABLE_IN_CLASS: u32 = u32::MAX - 2;
    pub(crate) const DEFAULT_PLOOKUP_RANGE_STEP_SIZE: usize = 3;

    pub fn new(mut ecc_op_queue: CoECCOpQueue<T, P>) -> Self {
        ecc_op_queue.initialize_new_subtable();
        let mut builder = Self {
            variables: vec![],
            next_var_index: vec![],
            prev_var_index: vec![],
            real_variable_index: vec![],
            constant_variable_indices: BTreeMap::new(),
            public_inputs: vec![],
            num_gates: 0,
            real_variable_tags: vec![],
            current_tag: Self::DUMMY_TAG + 1,
            blocks: GateBlocks::default(),
            ecc_op_queue,
            zero_idx: 0,
            add_accum_op_idx: 0,
            mul_accum_op_idx: 0,
            equality_op_idx: 0,
            has_dummy_witnesses: false,
            tau: BTreeMap::new(),
            range_lists: BTreeMap::new(),
        };
        let zero_idx = builder.put_constant_variable(P::ScalarField::zero());
        builder.zero_idx = zero_idx; // constant 0 is is associated with the zero index
        builder.set_goblin_ecc_op_code_constant_variables();
        builder
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
        self.blocks
            .arithmetic
            .q_busread()
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
        self.zero_idx = 0; // constant 0 is is associated with the zero index
        self.add_accum_op_idx = self.put_constant_variable(P::ScalarField::from(
            EccOpCode {
                add: true,
                ..Default::default()
            }
            .value(),
        ));
        self.mul_accum_op_idx = self.put_constant_variable(P::ScalarField::from(
            EccOpCode {
                mul: true,
                ..Default::default()
            }
            .value(),
        ));
        self.equality_op_idx = self.put_constant_variable(P::ScalarField::from(
            EccOpCode {
                eq: true,
                reset: true,
                ..Default::default()
            }
            .value(),
        ));
    }

    /**
     * @brief Add goblin ecc op gates for a single operation
     *
     * @param ultra_op Operation data expressed in the ultra format
     * @note All selectors are set to 0 since the ecc op selector is derived later based on the block size/location.
     */
    fn populate_ecc_op_wires(&mut self, ultra_op: &CoUltraOp<T, P>) -> CoEccOpTuple<T, P> {
        let op = self.get_ecc_op_idx(&ultra_op.op_code);
        let x_lo = self.add_variable(ultra_op.x_lo);
        let x_hi = self.add_variable(ultra_op.x_hi);
        let y_lo = self.add_variable(ultra_op.y_lo);
        let y_hi = self.add_variable(ultra_op.y_hi);
        let z_1 = self.add_variable(ultra_op.z_1);
        let z_2 = self.add_variable(ultra_op.z_2);

        // First set of wires
        self.blocks.ecc_op.populate_wires(op, x_lo, x_hi, y_lo);
        for selector in self.blocks.ecc_op.selectors.iter_mut() {
            selector.push(P::ScalarField::zero());
        }

        // Second set of wires
        self.blocks
            .ecc_op
            .populate_wires(self.zero_idx, y_hi, z_1, z_2);
        for selector in self.blocks.ecc_op.selectors.iter_mut() {
            selector.push(P::ScalarField::zero());
        }

        CoEccOpTuple {
            op,
            x_lo,
            x_hi,
            y_lo,
            y_hi,
            z_1,
            z_2,
            ..Default::default()
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
            self.zero_idx
        } else {
            panic!("Invalid op code");
        }
    }

    /**
     * @brief Add simple point addition operation to the op queue and add corresponding gates
     *
     * @param point Point to be added into the accumulator
     */
    pub fn queue_ecc_add_accum(
        &mut self,
        point: T::NativeAcvmPoint<P>,
        precomputed_point_limbs: Option<[T::AcvmType; 5]>,
        driver: &mut T,
    ) -> HonkProofResult<CoEccOpTuple<T, P>> {
        // Add the operation to the op queue
        let ultra_op = self
            .ecc_op_queue
            .add_accumulate(point, precomputed_point_limbs, driver)?;

        // Add corresponding gates for the operation
        Ok(self.populate_ecc_op_wires(&ultra_op))
    }

    /**
     * @brief Add simple point addition operation to the op queue and add corresponding gates
     *
     * @param point Point to be added into the accumulator
     */
    pub fn queue_ecc_add_accum_no_store(
        &mut self,
        point: T::NativeAcvmPoint<P>,
        precomputed_point_limbs: Option<[T::AcvmType; 5]>,
        driver: &mut T,
    ) -> HonkProofResult<(CoEccOpTuple<T, P>, CoVMOperation<T, P>)> {
        // Add the operation to the op queue
        let (ultra_op, eccvm_op) =
            self.ecc_op_queue
                .add_accumulate_no_store(point, precomputed_point_limbs, driver)?;

        // Add corresponding gates for the operation
        Ok((self.populate_ecc_op_wires(&ultra_op), eccvm_op))
    }

    /**
     * Add point mul-then-accumulate operation to the op queue and add corresponding gates.
     *
     * @param point The affine point to multiply.
     * @param scalar The scalar by which point is multiplied prior to being accumulated.
     * @return ECCOpTuple encoding the point and scalar inputs to the mul accum.
     */
    pub fn queue_ecc_mul_accum_store(
        &mut self,
        point: T::NativeAcvmPoint<P>,
        precomputed_point_limbs: Option<[T::AcvmType; 5]>,
        scalar: T::AcvmType,
        driver: &mut T,
    ) -> HonkProofResult<CoEccOpTuple<T, P>> {
        // Add the operation to the op queue
        let (ultra_op, eccvm_op) = self.ecc_op_queue.mul_accumulate_no_store(
            point,
            precomputed_point_limbs,
            scalar,
            driver,
        )?;

        let mut ops = vec![eccvm_op];
        precompute_flags(&mut ops, driver)?;
        self.ecc_op_queue.append_eccvm_op(ops.pop().unwrap());

        // Add corresponding gates for the operation
        Ok(self.populate_ecc_op_wires(&ultra_op))
    }

    /**
     * Add point mul-then-accumulate operation to the op queue and add corresponding gates.
     *
     * @param point The affine point to multiply.
     * @param scalar The scalar by which point is multiplied prior to being accumulated.
     * @return ECCOpTuple encoding the point and scalar inputs to the mul accum.
     */
    pub fn queue_ecc_mul_accum_no_store(
        &mut self,
        point: T::NativeAcvmPoint<P>,
        precomputed_point_limbs: Option<[T::AcvmType; 5]>,
        scalar: T::AcvmType,
        driver: &mut T,
    ) -> HonkProofResult<(CoEccOpTuple<T, P>, CoVMOperation<T, P>)> {
        // Add the operation to the op queue
        let (ultra_op, eccvm_op) = self.ecc_op_queue.mul_accumulate_no_store(
            point,
            precomputed_point_limbs,
            scalar,
            driver,
        )?;

        // Add corresponding gates for the operation
        Ok((self.populate_ecc_op_wires(&ultra_op), eccvm_op))
    }

    /**
     * @brief Add point equality operation to the op queue based on the value of the internal accumulator and add
     * corresponding gates
     *
     * @return ecc_op_tuple encoding the point to which equality has been asserted
     */
    pub fn queue_ecc_eq(&mut self, driver: &mut T) -> HonkProofResult<CoEccOpTuple<T, P>> {
        // Add the operation to the op queue
        let ultra_op = self.ecc_op_queue.eq_and_reset(driver)?;

        // Add corresponding gates for the operation
        let mut op_tuple = self.populate_ecc_op_wires(&ultra_op);
        op_tuple.return_is_infinity = ultra_op.return_is_infinity;
        Ok(op_tuple)
    }

    /**
     * @brief Logic for a no-op operation.
     *
     * @return ecc_op_tuple with all its fields set to zero
     */
    pub fn queue_ecc_no_op(&mut self, driver: &mut T) -> HonkProofResult<CoEccOpTuple<T, P>> {
        // Add the operation to the op queue
        let ultra_op = self.ecc_op_queue.no_op_ultra_only(driver)?;

        // Add corresponding gates for the operation
        Ok(self.populate_ecc_op_wires(&ultra_op))
    }

    pub fn add_public_variable(&mut self, value: T::AcvmType) -> u32 {
        let index = self.add_variable(value);
        self.public_inputs.push(index);
        index
    }

    pub(crate) fn assert_if_has_witness(&self, input: bool) {
        if self.has_dummy_witnesses {
            return;
        }
        assert!(input)
    }

    pub(crate) fn update_variable(&mut self, index: usize, value: T::AcvmType) {
        assert!(self.variables.len() > index);
        self.variables[self.real_variable_index[index] as usize] = value;
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

    pub(crate) fn assert_equal(&mut self, a_idx: usize, b_idx: usize) {
        self.assert_valid_variables(&[a_idx as u32, b_idx as u32]);

        let a = T::get_public(&self.get_variable(a_idx));

        let b = T::get_public(&self.get_variable(b_idx));

        match (a, b) {
            (Some(a), Some(b)) => {
                self.assert_if_has_witness(a == b);
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
        let no_tag_clash = self.real_variable_tags[a_real_idx] == Self::DUMMY_TAG
            || self.real_variable_tags[b_real_idx] == Self::DUMMY_TAG
            || self.real_variable_tags[a_real_idx] == self.real_variable_tags[b_real_idx];
        self.assert_if_has_witness(no_tag_clash);

        if self.real_variable_tags[a_real_idx] == Self::DUMMY_TAG {
            self.real_variable_tags[a_real_idx] = self.real_variable_tags[b_real_idx];
        }
    }
}
