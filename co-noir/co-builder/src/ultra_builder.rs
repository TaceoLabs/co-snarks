use crate::acir_format::{HonkRecursion, ProgramMetadata};
use crate::flavours::ultra_flavour::UltraFlavour;
use crate::generic_builder::GenericBuilder;
use crate::keys::verification_key::PublicComponentKey;
use crate::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use crate::prover_flavour::ProverFlavour;
use crate::types::aes128;
use crate::types::big_field::{BigField, BigGroup};
use crate::types::blake2s::Blake2s;
use crate::types::blake3::blake3s;
use crate::types::field_ct::{CycleGroupCT, CycleScalarCT};
use crate::types::sha_compression::SHA256;
use crate::types::types::AES128Constraint;
use crate::types::types::{
    AggregationState, EcAdd, EccAddGate, MultiScalarMul, Sha256Compression, WitnessOrConstant,
};
use crate::{
    acir_format::AcirFormat,
    keys::{
        proving_key::ProvingKey,
        verification_key::{VerifyingKey, VerifyingKeyBarretenberg},
    },
    types::{
        field_ct::{ByteArray, FieldCT},
        plookup::{BasicTableId, ColumnIdx, MultiTableId, Plookup, PlookupBasicTable, ReadData},
        poseidon2::Poseidon2CT,
        rom_ram::{
            RamAccessType, RamRecord, RamTable, RamTranscript, RomRecord, RomTable, RomTranscript,
        },
        types::{
            AddQuad, AddTriple, AuxSelectors, Blake2sConstraint, Blake3Constraint, BlockConstraint,
            BlockType, CachedPartialNonNativeFieldMultiplication, EccDblGate, LogicConstraint,
            MulQuad, NUM_WIRES, PolyTriple, Poseidon2Constraint, Poseidon2ExternalGate,
            Poseidon2InternalGate, RangeList, UltraTraceBlock, UltraTraceBlocks,
        },
    },
};
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{One, Zero};
use co_acvm::{PlainAcvmSolver, mpc::NoirWitnessExtensionProtocol};
use co_noir_common::crs::ProverCrs;
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::{
    honk_proof::{HonkProofResult, TranscriptFieldType},
    polynomials::polynomial::NUM_DISABLED_ROWS_IN_SUMCHECK,
    utils::Utils,
};
use itertools::izip;
use mpc_core::gadgets::poseidon2::POSEIDON2_BN254_T4_PARAMS;
use num_bigint::BigUint;
use std::{
    array,
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

type GateBlocks<F> = UltraTraceBlocks<UltraTraceBlock<F>>;

pub type UltraCircuitBuilder<P> =
    GenericUltraCircuitBuilder<P, PlainAcvmSolver<<P as PrimeGroup>::ScalarField>>;

#[expect(private_interfaces)]
impl<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>> GenericBuilder<P, T>
    for GenericUltraCircuitBuilder<P, T>
{
    type TraceBlock = UltraTraceBlock<P::ScalarField>;

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

        self.check_selector_length_consistency();
        self.num_gates += 1;
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
            let limb_idx = self.add_variable(*sublimb);

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
}

impl<C: CurveGroup> UltraCircuitBuilder<C> {
    pub fn create_vk_barretenberg(
        self,
        crs: Arc<ProverCrs<C>>,
        driver: &mut PlainAcvmSolver<C::ScalarField>,
    ) -> HonkProofResult<VerifyingKeyBarretenberg<C, UltraFlavour>> {
        let pk = ProvingKey::create::<PlainAcvmSolver<_>>(self, crs, driver)?;
        let circuit_size = pk.circuit_size;

        let mut commitments =
            <UltraFlavour as ProverFlavour>::PrecomputedEntities::<C::Affine>::default();
        for (des, src) in commitments
            .iter_mut()
            .zip(pk.polynomials.precomputed.iter())
        {
            let comm = Utils::commit(src.as_ref(), &pk.crs)?;
            *des = C::Affine::from(comm);
        }

        let vk = VerifyingKeyBarretenberg {
            circuit_size: circuit_size as u64,
            log_circuit_size: Utils::get_msb64(circuit_size as u64) as u64,
            num_public_inputs: pk.num_public_inputs as u64,
            pub_inputs_offset: pk.pub_inputs_offset as u64,
            commitments,
            pairing_inputs_public_input_key: pk.pairing_inputs_public_input_key,
        };

        Ok(vk)
    }

    pub fn create_keys<P: Pairing<G1 = C>>(
        self,
        prover_crs: Arc<ProverCrs<C>>,
        verifier_crs: P::G2Affine,
        driver: &mut PlainAcvmSolver<C::ScalarField>,
    ) -> HonkProofResult<(ProvingKey<C, UltraFlavour>, VerifyingKey<P, UltraFlavour>)> {
        let pk = ProvingKey::create::<PlainAcvmSolver<_>>(self, prover_crs, driver)?;
        let circuit_size = pk.circuit_size;

        let mut commitments =
            <UltraFlavour as ProverFlavour>::PrecomputedEntities::<P::G1Affine>::default();

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
            pairing_inputs_public_input_key: pk.pairing_inputs_public_input_key,
        };

        Ok((pk, vk))
    }

    pub fn create_keys_barretenberg(
        self,
        crs: Arc<ProverCrs<C>>,
        driver: &mut PlainAcvmSolver<C::ScalarField>,
    ) -> HonkProofResult<(
        ProvingKey<C, UltraFlavour>,
        VerifyingKeyBarretenberg<C, UltraFlavour>,
    )> {
        let pk = ProvingKey::create::<PlainAcvmSolver<_>>(self, crs, driver)?;
        let circuit_size = pk.circuit_size;

        let mut commitments =
            <UltraFlavour as ProverFlavour>::PrecomputedEntities::<C::Affine>::default();
        for (des, src) in commitments
            .iter_mut()
            .zip(pk.polynomials.precomputed.iter())
        {
            let comm = Utils::commit(src.as_ref(), &pk.crs)?;
            *des = C::Affine::from(comm);
        }

        // Create and return the VerifyingKey instance
        let vk = VerifyingKeyBarretenberg {
            circuit_size: circuit_size as u64,
            log_circuit_size: Utils::get_msb64(circuit_size as u64) as u64,
            num_public_inputs: pk.num_public_inputs as u64,
            pub_inputs_offset: pk.pub_inputs_offset as u64,
            commitments,
            pairing_inputs_public_input_key: pk.pairing_inputs_public_input_key,
        };

        Ok((pk, vk))
    }
}

pub struct GenericUltraCircuitBuilder<
    P: CurveGroup,
    T: NoirWitnessExtensionProtocol<P::ScalarField>,
> {
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
    pub(crate) num_gates: usize,
    pub circuit_finalized: bool,
    rom_arrays: Vec<RomTranscript<T::AcvmType>>,
    ram_arrays: Vec<RamTranscript<T::AcvmType, P::ScalarField, T::Lookup>>,
    pub(crate) lookup_tables: Vec<PlookupBasicTable<P, T>>,
    pub(crate) plookup: Plookup<P::ScalarField>,
    range_lists: BTreeMap<u64, RangeList>,
    cached_partial_non_native_field_multiplications:
        Vec<CachedPartialNonNativeFieldMultiplication<P::ScalarField>>,
    // Stores gate index of ROM and RAM reads (required by proving key)
    pub(crate) memory_read_records: Vec<u32>,
    // Stores gate index of RAM writes (required by proving key)
    pub(crate) memory_write_records: Vec<u32>,
    // Stores gate index where Read/Write type is shared
    pub memory_records_shared: BTreeMap<u32, T::AcvmType>, // order does not matter
    has_dummy_witnesses: bool,
    pub pairing_inputs_public_input_key: PublicComponentKey,
}

// This workaround is required due to mutability issues
macro_rules! create_dummy_gate {
    ($builder:expr, $block:expr, $ixd_1:expr, $ixd_2:expr, $ixd_3:expr, $ixd_4:expr) => {
        Self::create_dummy_gate($block, $ixd_1, $ixd_2, $ixd_3, $ixd_4);
        $builder.check_selector_length_consistency();
        $builder.num_gates += 1; // necessary because create dummy gate cannot increment num_gates itself
    };
}

impl<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>>
    GenericUltraCircuitBuilder<P, T>
{
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

    pub(crate) fn create_ecc_add_gate(&mut self, inp: &EccAddGate<P::ScalarField>) {
        //      /**
        //  * gate structure:
        //  * | 1  | 2  | 3  | 4  |
        //  * | -- | x1 | y1 | -- |
        //  * | x2 | x3 | y3 | y2 |
        //  * we can chain successive ecc_add_gates if x3 y3 of previous gate equals x1 y1 of current gate
        //  **/
        self.assert_valid_variables(&[inp.x1, inp.x2, inp.x3, inp.y1, inp.y2, inp.y3]);

        let size = self.blocks.elliptic.len();
        let previous_elliptic_gate_exists = size > 0;
        let mut can_fuse_into_previous_gate = previous_elliptic_gate_exists;
        if can_fuse_into_previous_gate {
            can_fuse_into_previous_gate =
                can_fuse_into_previous_gate && (self.blocks.elliptic.w_r()[size - 1] == inp.x1);
            can_fuse_into_previous_gate =
                can_fuse_into_previous_gate && (self.blocks.elliptic.w_o()[size - 1] == inp.y1);
            can_fuse_into_previous_gate =
                can_fuse_into_previous_gate && (self.blocks.elliptic.q_3()[size - 1].is_zero());
            can_fuse_into_previous_gate =
                can_fuse_into_previous_gate && (self.blocks.elliptic.q_4()[size - 1].is_zero());
            can_fuse_into_previous_gate =
                can_fuse_into_previous_gate && (self.blocks.elliptic.q_1()[size - 1].is_zero());
            can_fuse_into_previous_gate =
                can_fuse_into_previous_gate && (self.blocks.elliptic.q_arith()[size - 1].is_zero());
            can_fuse_into_previous_gate =
                can_fuse_into_previous_gate && (self.blocks.elliptic.q_m()[size - 1].is_zero());
        }

        if can_fuse_into_previous_gate {
            self.blocks.elliptic.q_1()[size - 1] = inp.sign_coefficient;
            self.blocks.elliptic.q_elliptic()[size - 1] = P::ScalarField::one();
        } else {
            self.blocks
                .elliptic
                .populate_wires(self.zero_idx, inp.x1, inp.y1, self.zero_idx);
            self.blocks.elliptic.q_3().push(P::ScalarField::zero());
            self.blocks.elliptic.q_4().push(P::ScalarField::zero());
            self.blocks.elliptic.q_1().push(inp.sign_coefficient);

            self.blocks.elliptic.q_arith().push(P::ScalarField::zero());
            self.blocks.elliptic.q_2().push(P::ScalarField::zero());
            self.blocks.elliptic.q_m().push(P::ScalarField::zero());
            self.blocks.elliptic.q_c().push(P::ScalarField::zero());
            self.blocks
                .elliptic
                .q_delta_range()
                .push(P::ScalarField::zero());
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
        }
        create_dummy_gate!(
            self,
            &mut self.blocks.elliptic,
            inp.x2,
            inp.x3,
            inp.y3,
            inp.y2
        );
    }

    pub(crate) fn create_ecc_dbl_gate(&mut self, inp: &EccDblGate) {
        // /**
        //  * gate structure:
        //  * | 1  | 2  | 3  | 4  |
        //  * | -  | x1 | y1 | -  |
        //  * | -  | x3 | y3 | -  |
        //  * we can chain an ecc_add_gate + an ecc_dbl_gate if x3 y3 of previous add_gate equals x1 y1 of current gate
        //  * can also chain double gates together
        //  **/
        self.assert_valid_variables(&[inp.x1, inp.x3, inp.y1, inp.y3]);

        let size = self.blocks.elliptic.len();
        let previous_elliptic_gate_exists = size > 0;
        let mut can_fuse_into_previous_gate = previous_elliptic_gate_exists;
        if can_fuse_into_previous_gate {
            can_fuse_into_previous_gate =
                can_fuse_into_previous_gate && (self.blocks.elliptic.w_r()[size - 1] == inp.x1);
            can_fuse_into_previous_gate =
                can_fuse_into_previous_gate && (self.blocks.elliptic.w_o()[size - 1] == inp.y1);
            can_fuse_into_previous_gate =
                can_fuse_into_previous_gate && (self.blocks.elliptic.q_arith()[size - 1].is_zero());
            can_fuse_into_previous_gate = can_fuse_into_previous_gate
                && (self.blocks.elliptic.q_lookup_type()[size - 1].is_zero());
            can_fuse_into_previous_gate =
                can_fuse_into_previous_gate && (self.blocks.elliptic.q_aux()[size - 1].is_zero());
        }

        if can_fuse_into_previous_gate {
            self.blocks.elliptic.q_elliptic()[size - 1] = P::ScalarField::one();
            self.blocks.elliptic.q_m()[size - 1] = P::ScalarField::one();
        } else {
            self.blocks
                .elliptic
                .populate_wires(self.zero_idx, inp.x1, inp.y1, self.zero_idx);
            self.blocks
                .elliptic
                .q_elliptic()
                .push(P::ScalarField::one());
            self.blocks.elliptic.q_m().push(P::ScalarField::one());
            self.blocks.elliptic.q_1().push(P::ScalarField::zero());
            self.blocks.elliptic.q_2().push(P::ScalarField::zero());
            self.blocks.elliptic.q_3().push(P::ScalarField::zero());
            self.blocks.elliptic.q_c().push(P::ScalarField::zero());
            self.blocks.elliptic.q_arith().push(P::ScalarField::zero());
            self.blocks.elliptic.q_4().push(P::ScalarField::zero());
            self.blocks
                .elliptic
                .q_delta_range()
                .push(P::ScalarField::zero());
            self.blocks
                .elliptic
                .q_lookup_type()
                .push(P::ScalarField::zero());
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
        }
        create_dummy_gate!(
            self,
            &mut self.blocks.elliptic,
            self.zero_idx,
            inp.x3,
            inp.y3,
            self.zero_idx
        );
    }

    fn create_block_constraints(
        &mut self,
        constraint: &BlockConstraint<P::ScalarField>,
        has_valid_witness_assignments: bool,
        driver: &mut T,
    ) -> eyre::Result<()> {
        let mut init = Vec::with_capacity(constraint.init.len());
        for inp in constraint.init.iter() {
            let value: FieldCT<P::ScalarField> = self.poly_to_field_ct(inp);
            init.push(value);
        }

        // Note: CallData/ReturnData not supported by Ultra; interpreted as ROM ops instead
        match constraint.type_ {
            BlockType::CallData | BlockType::ReturnData | BlockType::ROM => {
                self.process_rom_operations(
                    constraint,
                    has_valid_witness_assignments,
                    init,
                    driver,
                );
                Ok(())
            }
            BlockType::RAM => {
                self.process_ram_operations(constraint, has_valid_witness_assignments, init, driver)
            }
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

    // decomposes the shared values in batches, separated into the corresponding number of bits the values have
    #[expect(clippy::type_complexity)]
    fn prepare_for_range_decompose(
        &mut self,
        driver: &mut T,
        constraint_system: &AcirFormat<P::ScalarField>,
    ) -> eyre::Result<(
        HashMap<u32, usize>,
        Vec<Vec<Vec<T::ArithmeticShare>>>,
        Vec<(bool, usize)>,
    )> {
        let mut to_decompose: Vec<Vec<T::ArithmeticShare>> = vec![];
        let mut decompose_indices: Vec<(bool, usize)> = vec![];
        let mut bits_locations: HashMap<u32, usize> = HashMap::new();

        for constraint in constraint_system.range_constraints.iter() {
            let val = &self.get_variable(constraint.witness as usize);

            let mut num_bits = constraint.num_bits;
            if let Some(r) = constraint_system.minimal_range.get(&constraint.witness) {
                num_bits = *r;
            }
            if num_bits > Self::DEFAULT_PLOOKUP_RANGE_BITNUM as u32 && T::is_shared(val) {
                let share_val = T::get_shared(val).expect("Already checked it is shared");
                if let Some(&idx) = bits_locations.get(&num_bits) {
                    to_decompose[idx].push(share_val);
                    decompose_indices.push((true, to_decompose[idx].len() - 1));
                } else {
                    let new_idx = to_decompose.len();
                    to_decompose.push(vec![share_val]);
                    decompose_indices.push((true, 0));
                    bits_locations.insert(num_bits, new_idx);
                }
            } else {
                decompose_indices.push((false, 0));
            }
        }

        let mut decomposed = Vec::with_capacity(to_decompose.len());

        for (i, inp) in to_decompose.into_iter().enumerate() {
            let num_bits = bits_locations
                .iter()
                .find_map(|(&key, &value)| if value == i { Some(key) } else { None })
                .expect("Index not found in bitsloc");

            decomposed.push(T::decompose_arithmetic_many(
                driver,
                &inp,
                num_bits as usize,
                Self::DEFAULT_PLOOKUP_RANGE_BITNUM,
            )?);
        }
        Ok((bits_locations, decomposed, decompose_indices))
    }

    fn process_plonk_recursion_constraints(
        &mut self,
        constraint_system: &AcirFormat<P::ScalarField>,
        _has_valid_witness_assignments: bool,
    ) {
        for _constraint in constraint_system.recursion_constraints.iter() {
            todo!("Plonk recursion");
        }
    }

    fn process_honk_recursion_constraints(
        &mut self,
        constraint_system: &AcirFormat<P::ScalarField>,
        _has_valid_witness_assignments: bool,
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
    ) {
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
            // If the LUT is not public, then it is definetly not uninitialized, since it gets initialized with every read/write
            if T::is_public_lut(&ram_array.state) {
                let lut_pub =
                    T::get_public_lut(&ram_array.state).expect("Already checked it is public");
                for &value in lut_pub.iter() {
                    if value == P::ScalarField::from(Self::UNINITIALIZED_MEMORY_RECORD) {
                        *ramcount += Self::NUMBER_OF_GATES_PER_RAM_ACCESS;
                    }
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

            #[expect(unused_mut)] // TACEO TODO: This is for the linter, remove once its fixed...
            for (time_stamp, mut ram_range_exist) in ram_timestamps
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

    pub(crate) fn set_public_input(&mut self, witness_index: u32) {
        for public_input in self.public_inputs.iter().cloned() {
            if public_input == witness_index {
                panic!("Attempted to set a public input that is already public!");
            }
        }
        self.public_inputs.push(witness_index);
    }

    fn construct_default(&mut self, driver: &mut T) -> eyre::Result<AggregationState<P, T>> {
        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/911): These are pairing points extracted from a valid
        // proof. This is a workaround because we can't represent the point at infinity in biggroup yet.
        let x0_val = Utils::field_from_hex_string::<P::ScalarField>(
            "0x031e97a575e9d05a107acb64952ecab75c020998797da7842ab5d6d1986846cf",
        )
        .expect("x0 works");
        let y0_val = Utils::field_from_hex_string::<P::ScalarField>(
            "0x178cbf4206471d722669117f9758a4c410db10a01750aebb5666547acf8bd5a4",
        )
        .expect("y0 works");
        let x1_val = Utils::field_from_hex_string::<P::ScalarField>(
            "0x0f94656a2ca489889939f81e9c74027fd51009034b3357f0e91b8a11e7842c38",
        )
        .expect("x1 works");
        let y1_val = Utils::field_from_hex_string::<P::ScalarField>(
            "0x1b52c2020d7464a0c80c0da527a08193fe27776f50224bd6fb128b46c1ddb67f",
        )
        .expect("y1 works");

        // This internally calls functions that assume we are working with public values (i.e. they are only implemented for public values)
        let x0 = BigField::from_witness(&x0_val.into(), driver, self)?;
        let y0 = BigField::from_witness(&y0_val.into(), driver, self)?;
        let x1 = BigField::from_witness(&x1_val.into(), driver, self)?;
        let y1 = BigField::from_witness(&y1_val.into(), driver, self)?;

        let p0 = BigGroup::<P, T>::new(x0, y0);
        let p1 = BigGroup::<P, T>::new(x1, y1);

        Ok(AggregationState::new(p0, p1))
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
                T::public_zero()
            };
            let w = FieldCT::from_witness(w_value, self);

            let extract = &table.index_field_ct(&w, self, driver);
            value.assert_equal(extract, self, driver);
            w.assert_equal(&index, self, driver);
        }
    }

    fn process_ram_operations(
        &mut self,
        constraint: &BlockConstraint<P::ScalarField>,
        has_valid_witness_assignments: bool,
        init: Vec<FieldCT<P::ScalarField>>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        let mut table = RamTable::new(init);

        for op in constraint.trace.iter() {
            let value = self.poly_to_field_ct(&op.value);
            let index = self.poly_to_field_ct(&op.index);

            // We create a new witness w to avoid issues with non-valid witness assignements.
            // If witness are not assigned, then index will be zero and table[index] won't hit bounds check.
            // If witness are assigned, we use the correct value for index
            let index_value = if has_valid_witness_assignments {
                index.get_value(self, driver)
            } else {
                T::public_zero()
            };
            // Create new witness and ensure equal to index.
            let w = FieldCT::from_witness(index_value, self);
            w.assert_equal(&index, self, driver);

            if op.access_type == 0 {
                let read = table.read(&index, self, driver)?;
                value.assert_equal(&read, self, driver);
            } else {
                assert_eq!(op.access_type, 1);
                table.write(&index, &value, self, driver)?;
            }
        }
        Ok(())
    }

    pub fn get_variable_shared(
        &self,
        index: T::AcvmType,
        driver: &mut T,
        min_wit_index: u32, // Specify to reduce LUT size
        max_wit_index: u32, // Specify to reduce LUT size
    ) -> eyre::Result<T::AcvmType> {
        debug_assert!(max_wit_index >= min_wit_index);
        let direct_variables = self
            .real_variable_index
            .iter()
            .skip(min_wit_index as usize)
            .take((max_wit_index - min_wit_index + 1) as usize)
            .map(|x| self.variables[*x as usize])
            .collect();
        let lut = T::init_lut_by_acvm_type(driver, direct_variables);
        let corrected_index = driver.sub(index, P::ScalarField::from(min_wit_index as u64).into());
        T::read_lut_by_acvm_type(driver, corrected_index, &lut)
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

    pub(crate) fn create_ram_array(&mut self, array_size: usize, driver: &mut T) -> usize {
        let el: T::AcvmType = P::ScalarField::from(Self::UNINITIALIZED_MEMORY_RECORD).into();
        let lut = T::init_lut_by_acvm_type(driver, vec![el; array_size]);

        let new_transcript = RamTranscript::from_lut(lut);

        self.ram_arrays.push(new_transcript);
        self.ram_arrays.len() - 1
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
        let mut new_record = RomRecord::<T::AcvmType> {
            index_witness,
            value_column1_witness: value_witness,
            value_column2_witness: self.zero_idx,
            index: P::ScalarField::from(index_value as u64).into(),
            record_witness: 0,
            gate_index: 0,
        };

        self.rom_arrays[rom_id].state[index_value][0] = value_witness;
        self.rom_arrays[rom_id].state[index_value][1] = self.zero_idx;
        self.create_rom_gate(&mut new_record);
        self.rom_arrays[rom_id].records.push(new_record);
    }

    pub(crate) fn set_rom_element_pair(
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

        let mut new_record = RomRecord::<T::AcvmType> {
            index_witness,
            value_column1_witness: value_witnesses[0],
            value_column2_witness: value_witnesses[1],
            index: P::ScalarField::from(index_value as u32).into(),
            record_witness: 0,
            gate_index: 0,
        };

        self.rom_arrays[rom_id].state[index_value][0] = value_witnesses[0];
        self.rom_arrays[rom_id].state[index_value][1] = value_witnesses[1];
        self.create_rom_gate(&mut new_record);
        self.rom_arrays[rom_id].records.push(new_record);
    }

    pub(crate) fn init_ram_element(
        &mut self,
        driver: &mut T,
        ram_id: usize,
        index_value: usize,
        value_witness: u32,
    ) -> eyre::Result<()> {
        assert!(self.ram_arrays.len() > ram_id);
        let index_witness = if index_value == 0 {
            self.zero_idx
        } else {
            self.put_constant_variable(P::ScalarField::from(index_value as u64))
        };

        assert!(T::get_length_of_lut(&self.ram_arrays[ram_id].state) > index_value);
        if T::is_public_lut(&self.ram_arrays[ram_id].state) {
            let lut_pub = T::get_public_lut(&self.ram_arrays[ram_id].state)
                .expect("Already checked it is public");
            // Check the value if public
            assert!(
                lut_pub[index_value] == P::ScalarField::from(Self::UNINITIALIZED_MEMORY_RECORD)
            );
        }

        let mut new_record = RamRecord::<T::AcvmType> {
            index_witness,
            timestamp_witness: self.put_constant_variable(P::ScalarField::from(
                self.ram_arrays[ram_id].access_count as u64,
            )),
            value_witness,
            index: P::ScalarField::from(index_value as u32).into(),
            timestamp: self.ram_arrays[ram_id].access_count as u32,
            access_type: RamAccessType::Write,
            record_witness: 0,
            gate_index: 0,
        };

        T::write_lut_by_acvm_type(
            driver,
            P::ScalarField::from(index_value as u32).into(),
            P::ScalarField::from(value_witness).into(),
            &mut self.ram_arrays[ram_id].state,
        )?;
        // self.ram_arrays[ram_id].state[index_value] = value_witness;
        self.ram_arrays[ram_id].access_count += 1;
        self.create_ram_gate(&mut new_record);
        self.ram_arrays[ram_id].records.push(new_record);
        Ok(())
    }

    fn create_rom_gate(&mut self, record: &mut RomRecord<T::AcvmType>) {
        // Record wire value can't yet be computed
        record.record_witness = self.add_variable(T::public_zero());
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

    fn create_ram_gate<U: Clone>(&mut self, record: &mut RamRecord<U>) {
        // Record wire value can't yet be computed (uses randomnes generated during proof construction).
        // However it needs a distinct witness index,
        // we will be applying copy constraints + set membership constraints.
        // Later on during proof construction we will compute the record wire value + assign it
        record.record_witness = self.add_variable(T::public_zero());
        self.apply_aux_selectors(if record.access_type == RamAccessType::Read {
            AuxSelectors::RamRead
        } else {
            AuxSelectors::RamWrite
        });
        self.blocks.aux.populate_wires(
            record.index_witness,
            record.timestamp_witness,
            record.value_witness,
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
        driver: &mut T,
    ) -> eyre::Result<u32> {
        assert!(self.rom_arrays.len() > rom_id);
        let val = self.get_variable(index_witness as usize);

        if !T::is_shared(&val) {
            // Sanity check only doable in plain
            let val: BigUint = T::get_public(&val)
                .expect("Already checked it is public")
                .into();
            let index: usize = val.try_into().unwrap();
            assert!(self.rom_arrays[rom_id].state.len() > index);
            assert!(self.rom_arrays[rom_id].state[index][0] != Self::UNINITIALIZED_MEMORY_RECORD);
        }

        let fields = self.rom_arrays[rom_id]
            .state
            .iter()
            .map(|x| self.get_variable(x[0] as usize))
            .collect();

        let lut = T::init_lut_by_acvm_type(driver, fields);
        let value = T::read_lut_by_acvm_type(driver, val.to_owned(), &lut)?;

        let value_witness = self.add_variable(value);

        let mut new_record = RomRecord::<T::AcvmType> {
            index_witness,
            value_column1_witness: value_witness,
            value_column2_witness: self.zero_idx,
            index: val,
            record_witness: 0,
            gate_index: 0,
        };
        self.create_rom_gate(&mut new_record);
        self.rom_arrays[rom_id].records.push(new_record);

        // create_read_gate
        Ok(value_witness)
    }

    pub(crate) fn read_rom_array_pair(
        &mut self,
        rom_id: usize,
        index_witness: u32,
        driver: &mut T,
    ) -> eyre::Result<[u32; 2]> {
        assert!(self.rom_arrays.len() > rom_id);
        let val = self.get_variable(index_witness as usize);

        if !T::is_shared(&val) {
            // Sanity check only doable in plain
            let val: BigUint = T::get_public(&val)
                .expect("Already checked it is public")
                .into();
            let index: usize = val.try_into().unwrap();
            assert!(self.rom_arrays[rom_id].state.len() > index);
            assert!(self.rom_arrays[rom_id].state[index][0] != Self::UNINITIALIZED_MEMORY_RECORD);
            assert!(self.rom_arrays[rom_id].state[index][1] != Self::UNINITIALIZED_MEMORY_RECORD);
        }

        let fields1 = self.rom_arrays[rom_id]
            .state
            .iter()
            .map(|x| self.get_variable(x[0] as usize))
            .collect();
        let fields2 = self.rom_arrays[rom_id]
            .state
            .iter()
            .map(|x| self.get_variable(x[1] as usize))
            .collect();

        let lut1 = T::init_lut_by_acvm_type(driver, fields1);
        let lut2 = T::init_lut_by_acvm_type(driver, fields2);
        // TACEO TODO batch that
        let value1 = T::read_lut_by_acvm_type(driver, val.to_owned(), &lut1)?;
        let value2 = T::read_lut_by_acvm_type(driver, val.to_owned(), &lut2)?;

        let value_witness1 = self.add_variable(value1);
        let value_witness2 = self.add_variable(value2);

        let mut new_record = RomRecord::<T::AcvmType> {
            index_witness,
            value_column1_witness: value_witness1,
            value_column2_witness: value_witness2,
            index: val,
            record_witness: 0,
            gate_index: 0,
        };
        self.create_rom_gate(&mut new_record);
        self.rom_arrays[rom_id].records.push(new_record);

        // create_read_gate
        Ok([value_witness1, value_witness2])
    }

    pub(crate) fn read_ram_array(
        &mut self,
        ram_id: usize,
        index_witness: u32,
        driver: &mut T,
    ) -> eyre::Result<u32> {
        assert!(self.ram_arrays.len() > ram_id);
        let index = self.get_variable(index_witness as usize);

        if !T::is_shared(&index) && T::is_public_lut(&self.ram_arrays[ram_id].state) {
            // Sanity check only doable in plain
            let val: BigUint = T::get_public(&index)
                .expect("Already checked it is public")
                .into();
            let ind: usize = val.try_into().unwrap();
            let len = T::get_length_of_lut(&self.ram_arrays[ram_id].state);
            assert!(len > ind);
            assert!(
                T::get_public(&T::read_lut_by_acvm_type(
                    driver,
                    index,
                    &self.ram_arrays[ram_id].state
                )?)
                .expect("Already checked it is public")
                    != P::ScalarField::from(Self::UNINITIALIZED_MEMORY_RECORD)
            );
        }

        let lut = &self.ram_arrays[ram_id].state;

        // We get the minimum and maximum of the write recors to reduce the size of LUTs required to read the variable
        let min_witness = self.ram_arrays[ram_id]
            .records
            .iter()
            .filter(|x| x.access_type == RamAccessType::Write)
            .map(|x| x.value_witness)
            .min()
            .unwrap_or(0);
        let max_witness = self.ram_arrays[ram_id]
            .records
            .iter()
            .filter(|x| x.access_type == RamAccessType::Write)
            .map(|x| x.value_witness)
            .max()
            .unwrap_or(0);

        let index_ram = T::read_lut_by_acvm_type(driver, index, lut)?;
        let value = self.get_variable_shared(index_ram, driver, min_witness, max_witness)?;
        let value_witness = self.add_variable(value);

        let mut new_record = RamRecord::<T::AcvmType> {
            index_witness,
            timestamp_witness: self.put_constant_variable(P::ScalarField::from(
                self.ram_arrays[ram_id].access_count as u64,
            )),
            value_witness,
            index,
            timestamp: self.ram_arrays[ram_id].access_count as u32,
            access_type: RamAccessType::Read,
            record_witness: 0,
            gate_index: 0,
        };
        self.create_ram_gate(&mut new_record);
        self.ram_arrays[ram_id].records.push(new_record);

        // increment ram array's access count
        self.ram_arrays[ram_id].access_count += 1;

        // return witness index of the value in the array
        Ok(value_witness)
    }

    pub(crate) fn write_ram_array(
        &mut self,
        driver: &mut T,
        ram_id: usize,
        index_witness: u32,
        value_witness: u32,
    ) -> eyre::Result<()> {
        assert!(self.ram_arrays.len() > ram_id);
        let index = self.get_variable(index_witness as usize);

        if !T::is_shared(&index) && T::is_public_lut(&self.ram_arrays[ram_id].state) {
            // Sanity check only doable in plain
            let val: BigUint = T::get_public(&index)
                .expect("Already checked it is public")
                .into();
            let ind: usize = val.try_into().unwrap();
            let len = T::get_length_of_lut(&self.ram_arrays[ram_id].state);
            assert!(len > ind);
            assert!(
                T::get_public(&T::read_lut_by_acvm_type(
                    driver,
                    index,
                    &self.ram_arrays[ram_id].state
                )?)
                .expect("Already checked it is public")
                    != P::ScalarField::from(Self::UNINITIALIZED_MEMORY_RECORD)
            );
        }

        let mut new_record = RamRecord::<T::AcvmType> {
            index_witness,
            timestamp_witness: self.put_constant_variable(P::ScalarField::from(
                self.ram_arrays[ram_id].access_count as u64,
            )),
            value_witness,
            index,
            timestamp: self.ram_arrays[ram_id].access_count as u32,
            access_type: RamAccessType::Write,
            record_witness: 0,
            gate_index: 0,
        };
        self.create_ram_gate(&mut new_record);
        self.ram_arrays[ram_id].records.push(new_record);

        // increment ram array's access count
        self.ram_arrays[ram_id].access_count += 1;

        // update Composer's current state of RAM array
        T::write_lut_by_acvm_type(
            driver,
            index,
            P::ScalarField::from(value_witness).into(),
            &mut self.ram_arrays[ram_id].state,
        )?;

        Ok(())
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
            AuxSelectors::RamConsistencyCheck => {
                // Memory read gate used with the sorted list of memory reads.
                // 1. Validate adjacent index values across 2 gates increases by 0 or 1
                // 2. Validate record computation (r = read_write_flag + index * \eta + \timestamp * \eta^2 + value * \eta^3)
                // 3. If adjacent index values across 2 gates does not change, and the next gate's read_write_flag is set to
                // 'read', validate adjacent values do not change Used for ROM reads and RAM reads across read/write boundaries
                block.q_1().push(P::ScalarField::zero());
                block.q_2().push(P::ScalarField::zero());
                block.q_3().push(P::ScalarField::zero());
                block.q_4().push(P::ScalarField::zero());
                block.q_m().push(P::ScalarField::zero());
                block.q_c().push(P::ScalarField::zero());
                block.q_arith().push(P::ScalarField::one());
                self.check_selector_length_consistency();
            }
            AuxSelectors::RamTimestampCheck => {
                // For two adjacent RAM entries that share the same index, validate the timestamp value is monotonically
                // increasing
                block.q_1().push(P::ScalarField::one());
                block.q_2().push(P::ScalarField::zero());
                block.q_3().push(P::ScalarField::zero());
                block.q_4().push(P::ScalarField::one());
                block.q_m().push(P::ScalarField::zero());
                block.q_c().push(P::ScalarField::zero());
                block.q_arith().push(P::ScalarField::zero());
                self.check_selector_length_consistency();
            }
            AuxSelectors::RamRead => {
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
            AuxSelectors::RamWrite => {
                // Memory read gate for writing memory cells.
                // Validates record witness computation (r = read_write_flag + index * \eta + timestamp * \eta^2 + value *
                // \eta^3)
                block.q_1().push(P::ScalarField::one());
                block.q_2().push(P::ScalarField::zero());
                block.q_3().push(P::ScalarField::zero());
                block.q_4().push(P::ScalarField::zero());
                block.q_m().push(P::ScalarField::one()); // validate record witness is correctly computed
                block.q_c().push(P::ScalarField::one()); // read/write flag stored in q_c
                block.q_arith().push(P::ScalarField::zero());
                self.check_selector_length_consistency();
            }
            AuxSelectors::LimbAccumulate1 => {
                block.q_1().push(P::ScalarField::zero());
                block.q_2().push(P::ScalarField::zero());
                block.q_3().push(P::ScalarField::one());
                block.q_4().push(P::ScalarField::one());
                block.q_m().push(P::ScalarField::zero());
                block.q_c().push(P::ScalarField::zero());
                block.q_arith().push(P::ScalarField::zero());
                self.check_selector_length_consistency();
            }
            AuxSelectors::LimbAccumulate2 => {
                block.q_1().push(P::ScalarField::zero());
                block.q_2().push(P::ScalarField::zero());
                block.q_3().push(P::ScalarField::one());
                block.q_4().push(P::ScalarField::zero());
                block.q_m().push(P::ScalarField::one());
                block.q_c().push(P::ScalarField::zero());
                block.q_arith().push(P::ScalarField::zero());
                self.check_selector_length_consistency();
            }
            AuxSelectors::None => {
                block.q_1().push(P::ScalarField::zero());
                block.q_2().push(P::ScalarField::zero());
                block.q_3().push(P::ScalarField::zero());
                block.q_4().push(P::ScalarField::zero());
                block.q_m().push(P::ScalarField::zero());
                block.q_c().push(P::ScalarField::zero());
                block.q_arith().push(P::ScalarField::zero());
                self.check_selector_length_consistency();
            }
            _ => todo!("Aux selector {:?} not implemented", type_),
        }
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

    fn create_poseidon2_permutations(
        &mut self,
        constraint: &Poseidon2Constraint<P::ScalarField>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        const STATE_T: usize = 4;
        const D: u64 = 5;

        assert_eq!(constraint.state.len(), constraint.len as usize);
        assert_eq!(constraint.result.len(), constraint.len as usize);
        assert_eq!(constraint.len as usize, STATE_T);
        // Get the witness assignment for each witness index
        // Write the witness assignment to the byte_array state
        let mut state = array::from_fn(|i| constraint.state[i].to_field_ct());

        let poseidon2 = Poseidon2CT::<P::ScalarField, STATE_T, D>::default();
        poseidon2.permutation_in_place(&mut state, self, driver)?;

        for (out, res) in state.into_iter().zip(constraint.result.iter()) {
            let assert_equal = PolyTriple {
                a: out.normalize(self, driver).witness_index,
                b: *res,
                c: 0,
                q_m: P::ScalarField::zero(),
                q_l: P::ScalarField::one(),
                q_r: -P::ScalarField::one(),
                q_o: P::ScalarField::zero(),
                q_c: P::ScalarField::zero(),
            };
            self.create_poly_gate(&assert_equal);
        }
        Ok(())
    }

    fn process_rom_arrays(&mut self, driver: &mut T) -> eyre::Result<()> {
        for i in 0..self.rom_arrays.len() {
            self.process_rom_array(i, driver)?;
        }
        Ok(())
    }

    fn process_ram_arrays(&mut self, driver: &mut T) -> eyre::Result<()> {
        for i in 0..self.ram_arrays.len() {
            self.process_ram_array(i, driver)?;
        }
        Ok(())
    }

    fn process_range_lists(&mut self, driver: &mut T) -> eyre::Result<()> {
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

    fn process_rom_array_public_inner(
        &mut self,
        rom_id: usize,
        read_tag: u32,
        sorted_list_tag: u32,
    ) {
        let records = &self.rom_arrays[rom_id].records;
        let mut records: Vec<_> = records
            .iter()
            .map(|x| RomRecord::<P::ScalarField> {
                index_witness: x.index_witness,
                value_column1_witness: x.value_column1_witness,
                value_column2_witness: x.value_column2_witness,
                index: T::get_public(&x.index).expect("Already checked it is public"),
                record_witness: x.record_witness,
                gate_index: x.gate_index,
            })
            .collect();
        records.sort();
        for record in records {
            let index = record.index;
            let value1 = self.get_variable(record.value_column1_witness.try_into().unwrap());
            let value2 = self.get_variable(record.value_column2_witness.try_into().unwrap());
            let index_witness = self.add_variable(T::AcvmType::from(index));
            let value1_witness = self.add_variable(value1);
            let value2_witness = self.add_variable(value2);
            let mut sorted_record = RomRecord::<T::AcvmType> {
                index_witness,
                value_column1_witness: value1_witness,
                value_column2_witness: value2_witness,
                index: index.into(),
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
    }

    fn process_rom_array_shared_inner(
        &mut self,
        rom_id: usize,
        read_tag: u32,
        sorted_list_tag: u32,
        driver: &mut T,
    ) -> eyre::Result<()> {
        let records = &self.rom_arrays[rom_id].records;
        let key: Vec<_> = records.iter().map(|y| y.index).collect();
        let to_sort1: Vec<_> = records
            .iter()
            .map(|y| driver.get_as_shared(&y.index))
            .collect();
        let to_sort2: Vec<_> = records
            .iter()
            .map(|y| driver.get_as_shared(&self.get_variable(y.value_column1_witness as usize)))
            .collect();
        let to_sort3: Vec<_> = records
            .iter()
            .map(|y| driver.get_as_shared(&self.get_variable(y.value_column2_witness as usize)))
            .collect();
        let inputs = vec![to_sort1.as_ref(), to_sort2.as_ref(), to_sort3.as_ref()];

        let sorted = T::sort_vec_by(driver, &key, inputs, 32)?;
        let records = self.rom_arrays[rom_id].records.clone();
        for (record, index, col1, col2) in izip!(records, &sorted[0], &sorted[1], &sorted[2]) {
            let index_witness = self.add_variable(index.clone().into());
            let value1_witness = self.add_variable(col1.clone().into());
            let value2_witness = self.add_variable(col2.clone().into());
            let mut sorted_record = RomRecord::<T::AcvmType> {
                index_witness,
                value_column1_witness: value1_witness,
                value_column2_witness: value2_witness,
                index: index.clone().into(),
                record_witness: 0,
                gate_index: 0,
            };
            self.create_sorted_rom_gate(&mut sorted_record);
            self.assign_tag(record.record_witness, read_tag);
            self.assign_tag(sorted_record.record_witness, sorted_list_tag);
            // These elements don't need to be sorted, since the ordering does not play a role during the prover
            self.memory_read_records
                .push(sorted_record.gate_index as u32);
            self.memory_read_records.push(record.gate_index as u32);
        }
        Ok(())
    }

    fn process_rom_array(&mut self, rom_id: usize, driver: &mut T) -> eyre::Result<()> {
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

        let records = &self.rom_arrays[rom_id].records;
        let all_public = records.iter().all(|record| !T::is_shared(&record.index));
        if all_public {
            self.process_rom_array_public_inner(rom_id, read_tag, sorted_list_tag);
        } else {
            // The MPC case, we only need to sort some parts of the RomRecord, so we prepare these indices.
            self.process_rom_array_shared_inner(rom_id, read_tag, sorted_list_tag, driver)?;
        }

        // One of the checks we run on the sorted list, is to validate the difference between
        // the index field across two gates is either 0 or 1.
        // If we add a dummy gate at the end of the sorted list, where we force the first wire to
        // equal `m + 1`, where `m` is the maximum allowed index in the sorted list,
        // we have validated that all ROM reads are correctly constrained
        let max_index_value = self.rom_arrays[rom_id].state.len() as u64;
        let max_index: u32 =
            self.add_variable(T::AcvmType::from(P::ScalarField::from(max_index_value)));
        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/879): This was formerly a single arithmetic gate. A
        // dummy gate has been added to allow the previous gate to access the required wire data via shifts, allowing the
        // arithmetic gate to occur out of sequence.
        create_dummy_gate!(
            self,
            &mut self.blocks.aux,
            max_index,
            self.zero_idx,
            self.zero_idx,
            self.zero_idx
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

    fn process_ram_array_public_inner(
        &mut self,
        ram_id: usize,
        access_tag: u32,
        sorted_list_tag: u32,
    ) -> (u32, u32, Vec<u32>) {
        let mut sorted_ram_records = Vec::with_capacity(self.ram_arrays[ram_id].records.len());

        let records = &self.ram_arrays[ram_id].records;
        let mut records: Vec<_> = records
            .iter()
            .map(|x| RamRecord::<P::ScalarField> {
                index_witness: x.index_witness,
                timestamp_witness: x.timestamp_witness,
                value_witness: x.value_witness,
                index: T::get_public(&x.index).expect("Already checked it is public"),
                access_type: x.access_type.clone(),
                timestamp: x.timestamp,
                record_witness: x.record_witness,
                gate_index: x.gate_index,
            })
            .collect();
        records.sort();

        // Iterate over all but final RAM record.
        for (i, record) in records.into_iter().enumerate() {
            let index = record.index;
            let value = self.get_variable(record.value_witness.try_into().unwrap());
            let index_witness = self.add_variable(T::AcvmType::from(index));

            let timestamp_witness =
                self.add_variable(T::AcvmType::from(P::ScalarField::from(record.timestamp)));

            let value_witness = self.add_variable(value);
            let mut sorted_record = RamRecord::<T::AcvmType> {
                index_witness,
                timestamp_witness,
                value_witness,
                index: index.into(),
                timestamp: record.timestamp,
                access_type: record.access_type.to_owned(),
                record_witness: 0,
                gate_index: 0,
            };

            // create a list of sorted ram records
            sorted_ram_records.push(sorted_record.to_owned());

            // We don't apply the RAM consistency check gate to the final record,
            // as this gate expects a RAM record to be present at the next gate
            if i < self.ram_arrays[ram_id].records.len() - 1 {
                self.create_sorted_ram_gate(&mut sorted_record);
            } else {
                // For the final record in the sorted list, we do not apply the full consistency check gate.
                // Only need to check the index value = RAM array size - 1.
                let len = T::get_length_of_lut(&self.ram_arrays[ram_id].state);
                self.create_final_sorted_ram_gate(&mut sorted_record, len);
            }

            self.assign_tag(record.record_witness, access_tag);
            self.assign_tag(sorted_record.record_witness, sorted_list_tag);

            // For ROM/RAM gates, the 'record' wire value (wire column 4) is a linear combination of the first 3 wire
            // values. However...the record value uses the random challenge 'eta', generated after the first 3 wires are
            // committed to. i.e. we can't compute the record witness here because we don't know what `eta` is! Take the
            // gate indices of the two rom gates (original read gate + sorted gate) and store in `memory_records`. Once
            // we
            // generate the `eta` challenge, we'll use `memory_records` to figure out which gates need a record wire
            // value
            // to be computed.
            match record.access_type {
                RamAccessType::Read => {
                    self.memory_read_records
                        .push(sorted_record.gate_index as u32);
                    self.memory_read_records.push(record.gate_index as u32);
                }
                RamAccessType::Write => {
                    self.memory_write_records
                        .push(sorted_record.gate_index as u32);
                    self.memory_write_records.push(record.gate_index as u32);
                }
            }
        }

        // Step 2: Create gates that validate correctness of RAM timestamps
        let mut timestamp_deltas = Vec::with_capacity(sorted_ram_records.len() - 1);
        for i in 0..sorted_ram_records.len() - 1 {
            let current = &sorted_ram_records[i];
            let next = &sorted_ram_records[i + 1];

            let share_index = current.index == next.index;
            let timestamp_delta = if share_index {
                assert!(next.timestamp > current.timestamp);
                P::ScalarField::from(next.timestamp - current.timestamp)
            } else {
                P::ScalarField::zero()
            };

            let timestamp_delta_witness = self.add_variable(T::AcvmType::from(timestamp_delta));

            self.apply_aux_selectors(AuxSelectors::RamTimestampCheck);
            self.blocks.aux.populate_wires(
                current.index_witness,
                current.timestamp_witness,
                timestamp_delta_witness,
                self.zero_idx,
            );

            self.num_gates += 1;

            // store timestamp offsets for later. Need to apply range checks to them, but calling
            // `create_new_range_constraint` can add gates. Would ruin the structure of our sorted timestamp list.
            timestamp_deltas.push(timestamp_delta_witness);
        }

        let last = &sorted_ram_records[self.ram_arrays[ram_id].records.len() - 1];

        (last.index_witness, last.timestamp_witness, timestamp_deltas)
    }

    fn process_ram_array_shared_inner(
        &mut self,
        ram_id: usize,
        access_tag: u32,
        sorted_list_tag: u32,
        driver: &mut T,
    ) -> eyre::Result<(u32, u32, Vec<u32>)> {
        let mut sorted_ram_records = Vec::with_capacity(self.ram_arrays[ram_id].records.len());

        let records = &self.ram_arrays[ram_id].records;
        let mut indexed_to_sort3: Vec<_> = records
            .iter()
            .enumerate()
            .map(|(i, y)| (i, P::ScalarField::from(y.timestamp)))
            .collect();

        // here we sort two times, since the ordering should be according to this: self.index < other.index || (self.index == other.index && self.timestamp < other.timestamp), hence we first sort along timestamp (which is public), then along index
        indexed_to_sort3.sort_by(|a, b| a.1.cmp(&b.1));

        let mut key = Vec::with_capacity(indexed_to_sort3.len());
        let mut to_sort1 = Vec::with_capacity(indexed_to_sort3.len());
        let mut to_sort2 = Vec::with_capacity(indexed_to_sort3.len());
        let mut to_sort3 = Vec::with_capacity(indexed_to_sort3.len());
        let mut to_sort4 = Vec::with_capacity(indexed_to_sort3.len());
        for (i, val) in indexed_to_sort3 {
            key.push(records[i].index.to_owned());
            to_sort1.push(driver.get_as_shared(&records[i].index));
            to_sort2
                .push(driver.get_as_shared(&self.get_variable(records[i].value_witness as usize)));
            to_sort3.push(driver.promote_to_trivial_share(val));
            to_sort4.push(driver.promote_to_trivial_share(
                if records[i].access_type == RamAccessType::Read {
                    P::ScalarField::zero()
                } else {
                    P::ScalarField::one()
                },
            ));
        }

        let inputs = vec![
            to_sort1.as_ref(),
            to_sort2.as_ref(),
            to_sort3.as_ref(),
            to_sort4.as_ref(),
        ];

        // Second sort along the index
        let sorted = T::sort_vec_by(driver, &key, inputs, 32)?;

        let records = self.ram_arrays[ram_id].records.clone();
        let stamps = &sorted[2];
        // Iterate over all but final RAM record.
        for (i, (record, index, value, stamp, access_type)) in
            izip!(records, &sorted[0], &sorted[1], &sorted[2], &sorted[3]).enumerate()
        {
            let index_witness = self.add_variable(index.clone().into());
            let timestamp_witness = self.add_variable(stamp.clone().into());
            let value_witness = self.add_variable(value.clone().into());
            let mut sorted_record = RamRecord::<T::AcvmType> {
                index_witness,
                timestamp_witness,
                value_witness,
                index: index.clone().into(),
                timestamp: record.timestamp, // NOTE: these values are not the correct ones, but we do not need them
                access_type: record.access_type.to_owned(), // NOTE: these values are not the correct ones, but we do not need them
                record_witness: 0,
                gate_index: 0,
            };

            // create a list of sorted ram records
            sorted_ram_records.push(sorted_record.to_owned());

            // We don't apply the RAM consistency check gate to the final record,
            // as this gate expects a RAM record to be present at the next gate
            if i < self.ram_arrays[ram_id].records.len() - 1 {
                self.create_sorted_ram_gate(&mut sorted_record);
            } else {
                // For the final record in the sorted list, we do not apply the full consistency check gate.
                // Only need to check the index value = RAM array size - 1.
                let len = T::get_length_of_lut(&self.ram_arrays[ram_id].state);
                self.create_final_sorted_ram_gate(&mut sorted_record, len);
            }

            self.assign_tag(record.record_witness, access_tag);
            self.assign_tag(sorted_record.record_witness, sorted_list_tag);

            // For ROM/RAM gates, the 'record' wire value (wire column 4) is a linear combination of the first 3 wire
            // values. However...the record value uses the random challenge 'eta', generated after the first 3 wires are
            // committed to. i.e. we can't compute the record witness here because we don't know what `eta` is! Take the
            // gate indices of the two rom gates (original read gate + sorted gate) and store in `memory_records`. Once
            // we
            // generate the `eta` challenge, we'll use `memory_records` to figure out which gates need a record wire
            // value
            // to be computed.

            // Note: these values are not really inserted in the correct order, but order does not matter in the prover
            match record.access_type {
                RamAccessType::Read => {
                    self.memory_read_records.push(record.gate_index as u32);
                }
                RamAccessType::Write => {
                    self.memory_write_records.push(record.gate_index as u32);
                }
            }
            // Note: For these we need to sorted order, so we insert them in this new container which gets a special treatment in the prover.
            self.memory_records_shared
                .insert(sorted_record.gate_index as u32, access_type.clone().into());
        }

        // Step 2: Create gates that validate correctness of RAM timestamps
        let mut timestamp_deltas = Vec::with_capacity(sorted_ram_records.len() - 1);
        for i in 0..sorted_ram_records.len() - 1 {
            let current = &sorted_ram_records[i];
            let next = &sorted_ram_records[i + 1];
            let current_timestamp = stamps[i].clone();
            let next_timestamp = stamps[i + 1].clone();

            let share_index = T::equal(driver, &current.index, &next.index)?;
            let timestamp_delta = T::sub(driver, next_timestamp.into(), current_timestamp.into());
            let timestamp_delta = T::mul(driver, timestamp_delta, share_index)?;

            let timestamp_delta_witness = self.add_variable(timestamp_delta);

            self.apply_aux_selectors(AuxSelectors::RamTimestampCheck);
            self.blocks.aux.populate_wires(
                current.index_witness,
                current.timestamp_witness,
                timestamp_delta_witness,
                self.zero_idx,
            );

            self.num_gates += 1;

            // store timestamp offsets for later. Need to apply range checks to them, but calling
            // `create_new_range_constraint` can add gates. Would ruin the structure of our sorted timestamp list.
            timestamp_deltas.push(timestamp_delta_witness);
        }

        let last = &sorted_ram_records[self.ram_arrays[ram_id].records.len() - 1];

        Ok((last.index_witness, last.timestamp_witness, timestamp_deltas))
    }

    fn process_ram_array(&mut self, ram_id: usize, driver: &mut T) -> eyre::Result<()> {
        let access_tag = self.get_new_tag(); // current_tag + 1;
        let sorted_list_tag = self.get_new_tag(); // current_tag + 2;
        self.create_tag(access_tag, sorted_list_tag);
        self.create_tag(sorted_list_tag, access_tag);

        // Make sure that every cell has been initialized
        // AZTEC TODO: throw some kind of error here? Circuit should initialize all RAM elements to prevent errors.
        // e.g. if a RAM record is uninitialized but the index of that record is a function of public/private inputs,
        // different public iputs will produce different circuit constraints.

        // We need to initialize the RAM if it is uninitialized. Since RAM gets initialized on every read/write, it can only be uninitialized if it is public
        if T::is_public_lut(&self.ram_arrays[ram_id].state) {
            let len = T::get_length_of_lut(&self.ram_arrays[ram_id].state);
            for i in 0..len {
                if T::get_public_lut(&self.ram_arrays[ram_id].state)
                    .expect("Already checked it is public")[i]
                    == P::ScalarField::from(Self::UNINITIALIZED_MEMORY_RECORD)
                {
                    self.init_ram_element(driver, ram_id, i, self.zero_idx)?;
                }
            }
        }

        let records = &self.ram_arrays[ram_id].records;
        let all_public = records.iter().all(|record| !T::is_shared(&record.index));
        let (last_index_witness, last_timestamp_witness, timestamp_deltas) = if all_public {
            self.process_ram_array_public_inner(ram_id, access_tag, sorted_list_tag)
        } else {
            // The MPC case, we only need to sort some parts of the RomRecord, so we prepare these indices.
            self.process_ram_array_shared_inner(ram_id, access_tag, sorted_list_tag, driver)?
        };

        // add the index/timestamp values of the last sorted record in an empty add gate.
        // (the previous gate will access the wires on this gate and requires them to be those of the last record)
        create_dummy_gate!(
            self,
            &mut self.blocks.aux,
            last_index_witness,
            last_timestamp_witness,
            self.zero_idx,
            self.zero_idx
        );

        // Step 3: validate difference in timestamps is monotonically increasing. i.e. is <= maximum timestamp
        let max_timestamp = self.ram_arrays[ram_id].access_count - 1;
        for w in timestamp_deltas {
            self.create_new_range_constraint(w, max_timestamp as u64);
        }
        Ok(())
    }

    fn create_sorted_rom_gate(&mut self, record: &mut RomRecord<T::AcvmType>) {
        record.record_witness = self.add_variable(T::public_zero());
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

    fn create_sorted_ram_gate(&mut self, record: &mut RamRecord<T::AcvmType>) {
        record.record_witness = self.add_variable(T::public_zero());
        self.apply_aux_selectors(AuxSelectors::RamConsistencyCheck);
        self.blocks.aux.populate_wires(
            record.index_witness,
            record.timestamp_witness,
            record.value_witness,
            record.record_witness,
        );

        // Note: record the index into the block that contains the RAM/ROM gates
        record.gate_index = self.blocks.aux.len() - 1;
        self.num_gates += 1;
    }

    fn create_final_sorted_ram_gate(
        &mut self,
        record: &mut RamRecord<T::AcvmType>,
        ram_array_size: usize,
    ) {
        record.record_witness = self.add_variable(T::public_zero());
        // Note: record the index into the block that contains the RAM/ROM gates
        record.gate_index = self.blocks.aux.len(); // no -1 since we havent added the gate yet

        // Aztec TODO(https://github.com/AztecProtocol/barretenberg/issues/879): This method used to add a single arithmetic gate
        // with two purposes: (1) to provide wire values to the previous RAM gate via shifts, and (2) to perform a
        // consistency check on the value in wire 1. These two purposes have been split into a dummy gate and a simplified
        // arithmetic gate, respectively. This allows both purposes to be served even after arithmetic gates are sorted out
        // of sequence with the RAM gates.

        // Create a final gate with all selectors zero; wire values are accessed by the previous RAM gate via shifted wires
        create_dummy_gate!(
            self,
            &mut self.blocks.aux,
            record.index_witness,
            record.timestamp_witness,
            record.value_witness,
            record.record_witness
        );
        // Create an add gate ensuring the final index is consistent with the size of the RAM array
        self.create_big_add_gate(
            &AddQuad {
                a: record.index_witness,
                b: self.zero_idx,
                c: self.zero_idx,
                d: self.zero_idx,
                a_scaling: P::ScalarField::one(),
                b_scaling: P::ScalarField::zero(),
                c_scaling: P::ScalarField::zero(),
                d_scaling: P::ScalarField::zero(),
                const_scaling: -P::ScalarField::from(ram_array_size as u64 - 1),
            },
            false,
        );
    }

    fn process_range_list(&mut self, list: &mut RangeList, driver: &mut T) -> eyre::Result<()> {
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
            sorted_list.push(field_element);
        }

        let sorted_list = T::sort(
            driver,
            &sorted_list,
            Utils::get_msb64((list.target_range + 1).next_power_of_two()) as usize,
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
        let min_size_of_execution_trace = self.blocks.get_total_content_size();

        // The number of gates is the maximum required by the lookup argument or everything else, plus an optional zero row
        // to allow for shifts.
        let num_zero_rows = 1;
        let total_num_gates = NUM_DISABLED_ROWS_IN_SUMCHECK as usize
            + num_zero_rows
            + std::cmp::max(min_size_due_to_lookups, min_size_of_execution_trace);

        // Next power of 2 (dyadic circuit size)
        Self::get_circuit_subgroup_size(total_num_gates)
    }

    pub fn populate_public_inputs_block(&mut self) {
        tracing::debug!("Populating public inputs block");

        // Update the public inputs block
        for idx in self.public_inputs.iter() {
            // first two wires get a copy of the public inputs
            self.blocks
                .pub_inputs
                .populate_wires(*idx, *idx, self.zero_idx, self.zero_idx);
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
    ) -> eyre::Result<()> {
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
            //  * AZTEC TODO(Suyash):
            //  *    The following is a temporary fix to make sure the range constraints on numbers with
            //  *    num_bits <= DEFAULT_PLOOKUP_RANGE_BITNUM is correctly enforced in the circuit.
            //  *    Longer term, as Zac says, we would need to refactor the composer to fix this.
            //  **/
            self.create_poly_gate(&PolyTriple {
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
            // The value must be public, otherwise it would have been batch decomposed already
            self.decompose_into_default_range(
                driver,
                variable_index,
                num_bits as u64,
                None,
                Self::DEFAULT_PLOOKUP_RANGE_BITNUM as u64,
            )?;
        }
        Ok(())
    }

    pub(crate) fn create_new_range_constraint(&mut self, variable_index: u32, target_range: u64) {
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

    pub(crate) fn decompose_into_default_range(
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
            let limb_idx = self.add_variable(*sublimb);

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

    // for now we only need this function for public values
    pub fn decompose_non_native_field_double_width_limb(
        &mut self,
        limb_idx: u32,
        num_limb_bits: usize,
    ) -> eyre::Result<[u32; 2]> {
        // we skip this assert
        // ASSERT(uint256_t(this->get_variable_reference(limb_idx)) < (uint256_t(1) << num_limb_bits));

        const DEFAULT_NON_NATIVE_FIELD_LIMB_BITS: usize = 68;
        let limb_mask = (BigUint::one() << DEFAULT_NON_NATIVE_FIELD_LIMB_BITS) - BigUint::one();
        let value = self.get_variable(limb_idx as usize);
        if T::is_shared(&value) {
            panic!("This function should not have been called on a shared value");
        } else {
            let value: BigUint = T::get_public(&value)
                .expect("Already checked it is public")
                .into();
            let low = &value & &limb_mask;
            let hi = &value >> DEFAULT_NON_NATIVE_FIELD_LIMB_BITS;

            assert!(&low + (&hi << DEFAULT_NON_NATIVE_FIELD_LIMB_BITS) == value);

            let low_idx = self.add_variable(P::ScalarField::from(low).into());
            let hi_idx = self.add_variable(P::ScalarField::from(hi).into());

            assert!(num_limb_bits > DEFAULT_NON_NATIVE_FIELD_LIMB_BITS);

            let lo_bits = DEFAULT_NON_NATIVE_FIELD_LIMB_BITS;
            let hi_bits = num_limb_bits - DEFAULT_NON_NATIVE_FIELD_LIMB_BITS;
            self.range_constrain_two_limbs(low_idx, hi_idx, lo_bits, hi_bits)?;
            Ok([low_idx, hi_idx])
        }
    }

    // for now we only need this function for public values
    pub(crate) fn range_constrain_two_limbs(
        &mut self,
        lo_idx: u32,
        hi_idx: u32,
        lo_limb_bits: usize,
        hi_limb_bits: usize,
    ) -> eyre::Result<()> {
        // Validate limbs are <= 70 bits. If limbs are larger we require more witnesses and cannot use our limb accumulation
        // custom gate
        assert!(lo_limb_bits <= (14 * 5));
        assert!(hi_limb_bits <= (14 * 5));

        // Sometimes we try to use limbs that are too large. It's easier to catch this issue here
        let mut get_sublimbs = |limb_idx: u32, sublimb_masks: [u64; 5]| -> [u32; 5] {
            let limb = self.get_variable(limb_idx as usize);
            if T::is_shared(&limb) {
                panic!("This function should not have been called on a shared value");
            } else {
                // we can use constant 2^14 - 1 mask here. If the sublimb value exceeds the expected value then witness will
                // fail the range check below
                // We also use zero_idx to substitute variables that should be zero
                let limb: BigUint = T::get_public(&limb)
                    .expect("Already checked it is public")
                    .into();
                const MAX_SUBLIMB_MASK: u64 = (1u64 << 14) - 1;
                let mut sublimb_indices = [self.zero_idx; 5];
                sublimb_indices[0] = if sublimb_masks[0] != 0 {
                    self.add_variable(
                        P::ScalarField::from(limb.clone() & &MAX_SUBLIMB_MASK.into()).into(),
                    )
                } else {
                    self.zero_idx
                };
                sublimb_indices[1] = if sublimb_masks[1] != 0 {
                    self.add_variable(
                        P::ScalarField::from((limb.clone() >> 14) & &MAX_SUBLIMB_MASK.into())
                            .into(),
                    )
                } else {
                    self.zero_idx
                };
                sublimb_indices[2] = if sublimb_masks[2] != 0 {
                    self.add_variable(
                        P::ScalarField::from((limb.clone() >> 28) & &MAX_SUBLIMB_MASK.into())
                            .into(),
                    )
                } else {
                    self.zero_idx
                };
                sublimb_indices[3] = if sublimb_masks[3] != 0 {
                    self.add_variable(
                        P::ScalarField::from((limb.clone() >> 42) & &MAX_SUBLIMB_MASK.into())
                            .into(),
                    )
                } else {
                    self.zero_idx
                };
                sublimb_indices[4] = if sublimb_masks[4] != 0 {
                    self.add_variable(
                        P::ScalarField::from((limb >> 56) & &MAX_SUBLIMB_MASK.into()).into(),
                    )
                } else {
                    self.zero_idx
                };
                sublimb_indices
            }
        };

        let get_limb_masks = |limb_bits: usize| -> [u64; 5] {
            let mut sublimb_masks = [0u64; 5];
            sublimb_masks[0] = if limb_bits >= 14 { 14 } else { limb_bits } as u64;
            sublimb_masks[1] = if limb_bits >= 28 {
                14
            } else if limb_bits > 14 {
                (limb_bits - 14) as u64
            } else {
                0
            };
            sublimb_masks[2] = if limb_bits >= 42 {
                14
            } else if limb_bits > 28 {
                (limb_bits - 28) as u64
            } else {
                0
            };
            sublimb_masks[3] = if limb_bits >= 56 {
                14
            } else if limb_bits > 42 {
                (limb_bits - 42) as u64
            } else {
                0
            };
            sublimb_masks[4] = if limb_bits > 56 {
                (limb_bits - 56) as u64
            } else {
                0
            };

            for mask in &mut sublimb_masks {
                *mask = (1u64 << *mask) - 1;
            }
            sublimb_masks
        };

        let lo_masks = get_limb_masks(lo_limb_bits);
        let hi_masks = get_limb_masks(hi_limb_bits);
        let lo_sublimbs = get_sublimbs(lo_idx, lo_masks);
        let hi_sublimbs = get_sublimbs(hi_idx, hi_masks);

        self.blocks
            .aux
            .populate_wires(lo_sublimbs[0], lo_sublimbs[1], lo_sublimbs[2], lo_idx);
        self.blocks.aux.populate_wires(
            lo_sublimbs[3],
            lo_sublimbs[4],
            hi_sublimbs[0],
            hi_sublimbs[1],
        );
        self.blocks
            .aux
            .populate_wires(hi_sublimbs[2], hi_sublimbs[3], hi_sublimbs[4], hi_idx);

        self.apply_aux_selectors(AuxSelectors::LimbAccumulate1);
        self.apply_aux_selectors(AuxSelectors::LimbAccumulate2);
        self.apply_aux_selectors(AuxSelectors::None);
        self.num_gates += 3;

        for i in 0..5 {
            if lo_masks[i] != 0 {
                self.create_new_range_constraint(lo_sublimbs[i], lo_masks[i]);
            }
            if hi_masks[i] != 0 {
                self.create_new_range_constraint(hi_sublimbs[i], hi_masks[i]);
            }
        }
        Ok(())
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
        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/879): This was formerly a single arithmetic gate. A
        // dummy gate has been added to allow the previous gate to access the required wire data via shifts, allowing the
        // arithmetic gate to occur out of sequence.

        create_dummy_gate!(
            self,
            &mut self.blocks.delta_range,
            variable_index[variable_index.len() - 1],
            self.zero_idx,
            self.zero_idx,
            self.zero_idx
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
}

impl<P: HonkCurve<TranscriptFieldType>> UltraCircuitBuilder<P> {
    pub fn get_num_gates_added_to_ensure_nonzero_polynomials() -> usize {
        let mut builder = Self::new(0);
        let num_gates_prior = builder.get_num_gates();
        builder.add_gates_to_ensure_all_polys_are_non_zero(&mut PlainAcvmSolver::default());
        let num_gates_post = builder.get_num_gates(); // accounts for finalization gates

        num_gates_post - num_gates_prior
    }
}

impl<P: HonkCurve<TranscriptFieldType>, T: NoirWitnessExtensionProtocol<P::ScalarField>>
    GenericUltraCircuitBuilder<P, T>
{
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

        builder.has_dummy_witnesses = witness_values.is_empty();

        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/870): reserve space in blocks here somehow?
        let len = witness_values.len();
        for witness in witness_values.into_iter().take(varnum) {
            builder.add_variable(witness);
        }

        // Zeros are added for variables whose existence is known but whose values are not yet known. The values may
        // be "set" later on via the assert_equal mechanism.
        for _ in len..varnum {
            builder.add_variable(T::public_zero());
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
            rom_arrays: Vec::new(),
            ram_arrays: Vec::new(),
            lookup_tables: Vec::new(),
            plookup: Plookup::new::<P>(),
            range_lists: BTreeMap::new(),
            cached_partial_non_native_field_multiplications: Vec::new(),
            memory_read_records: Vec::new(),
            memory_write_records: Vec::new(),
            memory_records_shared: BTreeMap::new(),
            current_tag: 0,
            has_dummy_witnesses: true,
            pairing_inputs_public_input_key: PublicComponentKey::default(),
        }
    }

    pub fn create_circuit(
        constraint_system: &AcirFormat<P::ScalarField>,
        recursive: bool,
        size_hint: usize,
        witness: Vec<T::AcvmType>,
        honk_recursion: HonkRecursion, // 1 for ultrahonk
        driver: &mut T,
    ) -> eyre::Result<Self> {
        tracing::trace!("Builder create circuit");

        let has_valid_witness_assignments = !witness.is_empty();

        let mut builder = Self::init(
            size_hint,
            witness,
            constraint_system.public_inputs.to_owned(),
            constraint_system.varnum as usize,
            recursive,
        );
        let metadata = ProgramMetadata {
            recursive,
            honk_recursion,
            size_hint,
        };
        builder.build_constraints(
            driver,
            constraint_system,
            has_valid_witness_assignments,
            &metadata,
        )?;

        builder.finalize_circuit(true, driver)?;

        Ok(builder)
    }

    pub fn circuit_size(
        constraint_system: &AcirFormat<P::ScalarField>,
        recursive: bool,
        size_hint: usize,
        honk_recursion: HonkRecursion, // 1 for ultrahonk
        driver: &mut T,
    ) -> eyre::Result<usize> {
        tracing::trace!("Builder create circuit");

        let mut builder = Self::init(
            size_hint,
            vec![],
            constraint_system.public_inputs.to_owned(),
            constraint_system.varnum as usize,
            recursive,
        );
        let metadata = ProgramMetadata {
            recursive,
            honk_recursion,
            size_hint,
        };
        builder.build_constraints(driver, constraint_system, false, &metadata)?;

        builder.finalize_circuit(true, driver)?;

        Ok(builder.compute_dyadic_size())
    }

    pub fn finalize_circuit(&mut self, ensure_nonzero: bool, driver: &mut T) -> eyre::Result<()> {
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
                self.add_gates_to_ensure_all_polys_are_non_zero(driver);
            }

            self.process_non_native_field_multiplications();
            self.process_rom_arrays(driver)?;
            self.process_ram_arrays(driver)?;
            self.process_range_lists(driver)?;
            self.populate_public_inputs_block();
            self.circuit_finalized = true;
        }
        Ok(())
    }

    fn build_constraints(
        &mut self,
        driver: &mut T,
        constraint_system: &AcirFormat<P::ScalarField>,
        has_valid_witness_assignments: bool,
        metadata: &ProgramMetadata,
    ) -> eyre::Result<()> {
        tracing::trace!("Builder build constraints");

        // Add arithmetic gates
        for constraint in constraint_system.poly_triple_constraints.iter() {
            self.create_poly_gate(constraint);
        }
        for constraint in constraint_system.quad_constraints.iter() {
            self.create_big_mul_gate(constraint);
        }

        // Oversize gates are a vector of mul_quad gates.
        for constraint in constraint_system.big_quad_constraints.iter() {
            let mut next_w4_wire_value = T::AcvmType::default();
            // Define the 4th wire of these mul_quad gates, which is implicitly used by the previous gate.
            let constraint_size = constraint.len();
            for (j, small_constraint) in constraint.iter().enumerate().take(constraint_size - 1) {
                let mut small_constraint = small_constraint.clone();
                if j == 0 {
                    next_w4_wire_value = self.get_variable(small_constraint.d.try_into().unwrap());
                } else {
                    let next_w4_wire = self.add_variable(next_w4_wire_value.to_owned());
                    small_constraint.d = next_w4_wire;
                    small_constraint.d_scaling = -P::ScalarField::one();
                }

                self.create_big_mul_add_gate(&small_constraint, true);

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

            let mut last_constraint = constraint.last().unwrap().clone();
            last_constraint.d = next_w4_wire;
            last_constraint.d_scaling = -P::ScalarField::one();

            self.create_big_mul_add_gate(&last_constraint, false);
        }

        // Add logic constraint
        for constraint in constraint_system.logic_constraints.iter() {
            self.create_logic_constraint(driver, constraint)?;
        }

        // Add range constraints
        // We want to decompose all shared elements in parallel
        let (bits_locations, decomposed, decompose_indices) =
            self.prepare_for_range_decompose(driver, constraint_system)?;

        for (i, constraint) in constraint_system.range_constraints.iter().enumerate() {
            let mut range = constraint.num_bits;
            if let Some(r) = constraint_system.minimal_range.get(&constraint.witness) {
                range = *r;
            }

            let idx_option = bits_locations.get(&range);
            if let Some(idx) = idx_option
                && decompose_indices[i].0
            {
                // Already decomposed
                let idx = idx.to_owned();
                self.decompose_into_default_range(
                    driver,
                    constraint.witness,
                    range as u64,
                    Some(&decomposed[idx][decompose_indices[i].1]),
                    Self::DEFAULT_PLOOKUP_RANGE_BITNUM as u64,
                )?;
            } else {
                // Either we do not have to decompose or the value is public
                self.create_range_constraint(driver, constraint.witness, range)?;
            }
        }

        // Add aes128 constraints
        for constraint in constraint_system.aes128_constraints.iter() {
            self.create_aes128_constraints(driver, constraint)?;
        }

        // Add sha256 constraints
        for constraint in constraint_system.sha256_compression.iter() {
            self.create_sha256_compression_constraints(driver, constraint)?;
        }

        // Add ECDSA k1 constraints
        // for (i, constraint) in constraint_system.ecdsa_k1_constraints.iter().enumerate() {
        //     todo!("ecdsa k1 gates");
        // }

        // Add ECDSA r1 constraints
        // for (i, constraint) in constraint_system.ecdsa_r1_constraints.iter().enumerate() {
        //     todo!("ecdsa r1 gates");
        // }

        // Add blake2s constraints
        for constraint in constraint_system.blake2s_constraints.iter() {
            self.create_blake2s_constraints(driver, constraint)?;
        }

        // Add blake3 constraints
        for constraint in constraint_system.blake3_constraints.iter() {
            self.create_blake3_constraints(driver, constraint)?;
        }

        // Add keccak constraints
        // for (i, constraint) in constraint_system.keccak_constraints.iter().enumerate() {
        //     todo!("keccak gates");
        // }

        // for (i, constraint) in constraint_system.keccak_permutations.iter().enumerate() {
        //     todo!("keccak permutation gates");
        // }

        // Add poseidon2 constraints
        for constraint in constraint_system.poseidon2_constraints.iter() {
            self.create_poseidon2_permutations(constraint, driver)?;
        }

        // Add multi scalar mul constraints
        for constraint in constraint_system.multi_scalar_mul_constraints.iter() {
            self.create_multi_scalar_mul_constraint(
                constraint,
                has_valid_witness_assignments,
                driver,
            )?;
        }

        // Add ec add constraints
        for constraint in constraint_system.ec_add_constraints.iter() {
            self.create_ec_add_constraint(constraint, has_valid_witness_assignments, driver)?;
        }

        // Add block constraints
        for constraint in constraint_system.block_constraints.iter() {
            self.create_block_constraints(constraint, has_valid_witness_assignments, driver)?;
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
        for constraint in constraint_system.assert_equalities.iter() {
            self.assert_equal(
                constraint.a.try_into().unwrap(),
                constraint.b.try_into().unwrap(),
            );
        }

        // RecursionConstraints
        self.process_plonk_recursion_constraints(constraint_system, has_valid_witness_assignments);
        let mut current_aggregation_object = self.construct_default(driver)?;
        self.process_honk_recursion_constraints(constraint_system, has_valid_witness_assignments);
        self.process_avm_recursion_constraints(constraint_system, has_valid_witness_assignments);
        // If the circuit has either honk or avm recursion constraints, add the aggregation object. Otherwise, add a
        // default one if the circuit is recursive and honk_recursion is true.
        if !constraint_system.honk_recursion_constraints.is_empty()
            || !constraint_system.avm_recursion_constraints.is_empty()
        {
            // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1336): Delete this if statement
            //    if constexpr (!IsMegaBuilder<Builder>) {
            assert!(metadata.honk_recursion != HonkRecursion::NotHonk);
            current_aggregation_object.set_public(self, driver);
            // }
        } else if metadata.honk_recursion != HonkRecursion::NotHonk {
            current_aggregation_object.set_public(self, driver);
        }

        Ok(())
    }

    fn get_table(&mut self, id: BasicTableId) -> &mut PlookupBasicTable<P, T> {
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

    pub(crate) fn create_gates_from_plookup_accumulators(
        &mut self,
        id: MultiTableId,
        read_values: ReadData<T::AcvmType>,
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
                self.add_variable(read_values[ColumnIdx::C1][i])
            };
            #[expect(clippy::unnecessary_unwrap)]
            let second_idx = if i == 0 && (key_b_index.is_some()) {
                key_b_index.unwrap()
            } else {
                self.add_variable(read_values[ColumnIdx::C2][i])
            };
            let third_idx = self.add_variable(read_values[ColumnIdx::C3][i]);
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

    fn create_aes128_constraints(
        &mut self,
        driver: &mut T,
        constraint: &AES128Constraint<P::ScalarField>,
    ) -> eyre::Result<()> {
        let padding_size = 16 - (constraint.inputs.len() % 16);

        // Perform the conversions from array of bytes to field elements
        let mut converted_inputs = Vec::with_capacity(constraint.inputs.len().div_ceil(16));
        for chunk in constraint.inputs.chunks(16) {
            let to_add = if chunk.len() < 16 {
                aes128::pack_input_bytes_into_field(chunk, padding_size, self, driver)?
            } else {
                aes128::pack_input_bytes_into_field(chunk, 0, self, driver)?
            };
            converted_inputs.push(to_add);
        }

        let mut converted_outputs = Vec::with_capacity(constraint.outputs.len() / 16);
        for chunk in constraint.outputs.chunks(16) {
            let outputs: [u32; 16] = chunk
                .try_into()
                .expect("Output chunk must have 16 elements");
            converted_outputs.push(aes128::pack_output_bytes_into_field(
                &outputs, self, driver,
            )?);
        }

        let output_bytes = aes128::AES128::encrypt_buffer_cbc(
            &converted_inputs,
            &aes128::pack_input_bytes_into_field(&constraint.iv, 0, self, driver)?,
            &aes128::pack_input_bytes_into_field(&constraint.key, 0, self, driver)?,
            self,
            driver,
        )?;

        for (i, output_byte) in output_bytes.iter().enumerate() {
            let expected_output = converted_outputs[i].normalize(self, driver);
            let actual_output = output_byte.normalize(self, driver);
            self.assert_equal(
                actual_output.witness_index as usize,
                expected_output.witness_index as usize,
            );
        }

        Ok(())
    }

    fn create_multi_scalar_mul_constraint(
        &mut self,
        constraint: &MultiScalarMul<P::ScalarField>,
        has_valid_witness_assignments: bool,
        driver: &mut T,
    ) -> eyre::Result<()> {
        let len = constraint.points.len() / 3;
        debug_assert_eq!(len * 3, constraint.points.len());
        debug_assert_eq!(len * 2, constraint.scalars.len());

        let mut points = Vec::with_capacity(len);
        let mut scalars = Vec::with_capacity(len);

        for (p, s) in constraint
            .points
            .chunks_exact(3)
            .zip(constraint.scalars.chunks_exact(2))
        {
            // Instantiate the input point/variable base as `cycle_group_ct`
            let input_point = WitnessOrConstant::to_grumpkin_point(
                &p[0],
                &p[1],
                &p[2],
                has_valid_witness_assignments,
                self,
                driver,
            );

            //  Reconstruct the scalar from the low and high limbs
            let scalar_low_as_field = s[0].to_field_ct();
            let scalar_high_as_field = s[1].to_field_ct();
            let scalar = CycleScalarCT::new(scalar_low_as_field, scalar_high_as_field);
            points.push(input_point);
            scalars.push(scalar);
        }

        let output_point = CycleGroupCT::batch_mul(points, scalars, self, driver)?
            .get_standard_form(self, driver)?;

        // Add the constraints and handle constant values
        if output_point.is_point_at_infinity().is_constant() {
            let value = output_point.is_point_at_infinity().get_value(driver);
            self.fix_witness(
                constraint.out_point_is_infinity,
                T::get_public(&value).expect("Constants should be public"),
            );
        } else {
            self.assert_equal(
                output_point.is_point_at_infinity().witness_index as usize,
                constraint.out_point_is_infinity as usize,
            );
        }

        if output_point.x.is_constant() {
            let value = output_point.x.get_value(self, driver);
            self.fix_witness(
                constraint.out_point_x,
                T::get_public(&value).expect("Constants should be public"),
            );
        } else {
            self.assert_equal(
                output_point.x.get_witness_index() as usize,
                constraint.out_point_x as usize,
            );
        }

        if output_point.y.is_constant() {
            let value = output_point.y.get_value(self, driver);
            self.fix_witness(
                constraint.out_point_y,
                T::get_public(&value).expect("Constants should be public"),
            );
        } else {
            self.assert_equal(
                output_point.y.get_witness_index() as usize,
                constraint.out_point_y as usize,
            );
        }

        Ok(())
    }

    fn create_ec_add_constraint(
        &mut self,
        constraint: &EcAdd<P::ScalarField>,
        has_valid_witness_assignments: bool,
        driver: &mut T,
    ) -> eyre::Result<()> {
        // Input to cycle_group points
        let input1_point = WitnessOrConstant::to_grumpkin_point(
            &constraint.input1_x,
            &constraint.input1_y,
            &constraint.input1_infinite,
            has_valid_witness_assignments,
            self,
            driver,
        );

        let input2_point = WitnessOrConstant::to_grumpkin_point(
            &constraint.input2_x,
            &constraint.input2_y,
            &constraint.input2_infinite,
            has_valid_witness_assignments,
            self,
            driver,
        );

        // Addition
        let result = input1_point.add(&input2_point, self, driver)?;
        let standard_result = result.get_standard_form(self, driver)?;
        let x_normalized = standard_result.x.normalize(self, driver);
        let y_normalized = standard_result.y.normalize(self, driver);
        let infinite = standard_result
            .is_point_at_infinity()
            .normalize(self, driver);

        if x_normalized.is_constant() {
            let value = x_normalized.get_value(self, driver);
            self.fix_witness(
                constraint.result_x,
                T::get_public(&value).expect("Constants should be public"),
            );
        } else {
            self.assert_equal(
                x_normalized.witness_index as usize,
                constraint.result_x as usize,
            );
        }

        if y_normalized.is_constant() {
            let value = y_normalized.get_value(self, driver);
            self.fix_witness(
                constraint.result_y,
                T::get_public(&value).expect("Constants should be public"),
            );
        } else {
            self.assert_equal(
                y_normalized.witness_index as usize,
                constraint.result_y as usize,
            );
        }

        if infinite.is_constant() {
            let value = infinite.get_value(driver);
            self.fix_witness(
                constraint.result_infinite,
                T::get_public(&value).expect("Constants should be public"),
            );
        } else {
            self.assert_equal(
                infinite.witness_index as usize,
                constraint.result_infinite as usize,
            );
        }
        Ok(())
    }

    fn create_sha256_compression_constraints(
        &mut self,
        driver: &mut T,
        constraint: &Sha256Compression<P::ScalarField>,
    ) -> eyre::Result<()> {
        let mut inputs: [FieldCT<P::ScalarField>; 16] =
            array::from_fn(|_| FieldCT::<P::ScalarField>::default());
        let mut hash_inputs: [FieldCT<P::ScalarField>; 8] =
            array::from_fn(|_| FieldCT::<P::ScalarField>::default());

        // Get the witness assignment for each witness index
        // Note that we do not range-check the inputs, which should be 32 bits,
        // because of the lookup-tables.
        for (i, witness_index_num_bits) in constraint.inputs.iter().enumerate() {
            inputs[i] = witness_index_num_bits.to_field_ct();
        }
        for (i, witness_index_num_bits) in constraint.hash_values.iter().enumerate() {
            hash_inputs[i] = witness_index_num_bits.to_field_ct();
        }

        // Compute sha256 compression
        let output_bytes = SHA256::sha256_block(hash_inputs, inputs, self, driver)?;

        for (i, output_byte) in output_bytes.iter().enumerate() {
            let normalised_output = output_byte.normalize(self, driver);
            if normalised_output.is_constant() {
                let value = normalised_output.get_value(self, driver);
                self.fix_witness(
                    constraint.result[i],
                    T::get_public(&value).expect("Constants should be public"),
                );
            } else {
                let assert_equal = PolyTriple {
                    a: normalised_output.witness_index,
                    b: constraint.result[i],
                    c: 0,
                    q_m: P::ScalarField::zero(),
                    q_l: P::ScalarField::one(),
                    q_r: -P::ScalarField::one(),
                    q_o: P::ScalarField::zero(),
                    q_c: P::ScalarField::zero(),
                };
                self.create_poly_gate(&assert_equal);
            }
        }
        Ok(())
    }

    fn create_blake2s_constraints(
        &mut self,
        driver: &mut T,
        constraint: &Blake2sConstraint<P::ScalarField>,
    ) -> eyre::Result<()> {
        // Create byte array struct
        let mut arr = ByteArray::<P::ScalarField>::new();

        // Get the witness assignment for each witness index
        // Write the witness assignment to the byte_array
        for witness_index_num_bits in &constraint.inputs {
            let witness_index = &witness_index_num_bits.blackbox_input;
            let num_bits = witness_index_num_bits.num_bits;

            // XXX: The implementation requires us to truncate the element to the nearest byte and not bit
            let num_bytes = Utils::round_to_nearest_byte(num_bits);
            let element = WitnessOrConstant::to_field_ct(witness_index);
            let element_bytes =
                ByteArray::from_field_ct(&element, num_bytes as usize, self, driver)?;

            arr.write(&element_bytes);
        }
        let output_bytes = Blake2s::blake2s_init(&arr, self, driver)?;

        // Convert byte array to vector of field_t
        let bytes = output_bytes.values;

        for (i, byte) in bytes.iter().enumerate() {
            let wtns_index = byte.normalize(self, driver).witness_index;
            self.assert_equal(wtns_index as usize, constraint.result[i] as usize);
        }

        Ok(())
    }

    fn create_blake3_constraints(
        &mut self,
        driver: &mut T,
        constraint: &Blake3Constraint<P::ScalarField>,
    ) -> eyre::Result<()> {
        // Create byte array struct
        let mut arr = ByteArray::<P::ScalarField>::new();

        // Get the witness assignment for each witness index
        // Write the witness assignment to the byte_array
        for witness_index_num_bits in &constraint.inputs {
            let witness_index = &witness_index_num_bits.blackbox_input;
            let num_bits = witness_index_num_bits.num_bits;

            // XXX: The implementation requires us to truncate the element to the nearest byte and not bit
            let num_bytes = Utils::round_to_nearest_byte(num_bits);
            let element = WitnessOrConstant::to_field_ct(witness_index);
            let element_bytes =
                ByteArray::from_field_ct(&element, num_bytes as usize, self, driver)?;

            arr.write(&element_bytes);
        }
        let output_bytes = blake3s(&arr, self, driver)?;

        // Convert byte array to vector of field_t
        let bytes = output_bytes.values;

        for (i, byte) in bytes.iter().enumerate() {
            let wtns_index = byte.normalize(self, driver).witness_index;
            self.assert_equal(wtns_index as usize, constraint.result[i] as usize);
        }

        Ok(())
    }

    fn create_logic_constraint(
        &mut self,
        driver: &mut T,
        constraint: &LogicConstraint<P::ScalarField>,
    ) -> eyre::Result<()> {
        let left = constraint.a.to_field_ct();
        let right = constraint.b.to_field_ct();

        let res = self.create_logic_constraint_inner(
            driver,
            left,
            right,
            constraint.num_bits as usize,
            constraint.is_xor_gate,
        )?;
        let our_res = FieldCT::from_witness_index(constraint.result);
        res.assert_equal(&our_res, self, driver);
        Ok(())
    }

    fn create_logic_constraint_inner(
        &mut self,
        driver: &mut T,
        a: FieldCT<P::ScalarField>,
        b: FieldCT<P::ScalarField>,
        num_bits: usize,
        is_xor_gate: bool,
    ) -> eyre::Result<FieldCT<P::ScalarField>> {
        // ensure the number of bits doesn't exceed field size and is not negative
        assert!(num_bits < 254);
        assert!(num_bits > 0);

        assert!(!a.is_constant() || !b.is_constant());

        if a.is_constant() && !b.is_constant() {
            let a_native =
                T::get_public(&a.get_value(self, driver)).expect("Constant should be public");
            let a_witness =
                FieldCT::<P::ScalarField>::from_witness_index(self.put_constant_variable(a_native));
            return self.create_logic_constraint_inner(driver, a_witness, b, num_bits, is_xor_gate);
        }

        if !a.is_constant() && b.is_constant() {
            let b_native =
                T::get_public(&b.get_value(self, driver)).expect("Constant should be public");
            let b_witness =
                FieldCT::<P::ScalarField>::from_witness_index(self.put_constant_variable(b_native));
            return self.create_logic_constraint_inner(driver, a, b_witness, num_bits, is_xor_gate);
        }

        // We have Plookup!
        let num_chunks = (num_bits / 32) + if num_bits % 32 == 0 { 0 } else { 1 };
        let left = a.get_value(self, driver);
        let right = b.get_value(self, driver);

        // Decompose the values
        let mut decomp_left = Vec::new();
        let mut decomp_right = Vec::new();
        let mut to_mpc_decompose = Vec::new();

        if !T::is_shared(&left) {
            let sublimb_mask = (BigUint::one() << 32) - BigUint::one();
            let mut left_: BigUint = T::get_public(&left)
                .expect("Already checked it is public")
                .into();

            decomp_left = (0..num_chunks)
                .map(|_| {
                    let sublimb_value = P::ScalarField::from(&left_ & &sublimb_mask);
                    left_ >>= 32;
                    T::AcvmType::from(sublimb_value)
                })
                .collect();
        } else {
            to_mpc_decompose.push(T::get_shared(&left).expect("Already checked it is shared"))
        }

        if !T::is_shared(&right) {
            let sublimb_mask = (BigUint::one() << 32) - BigUint::one();
            let mut right_: BigUint = T::get_public(&right)
                .expect("Already checked it is public")
                .into();

            decomp_right = (0..num_chunks)
                .map(|_| {
                    let sublimb_value = P::ScalarField::from(&right_ & &sublimb_mask);
                    right_ >>= 32;
                    T::AcvmType::from(sublimb_value)
                })
                .collect();
        } else {
            to_mpc_decompose.push(T::get_shared(&right).expect("Already checked it is shared"))
        }

        if !to_mpc_decompose.is_empty() {
            // TACEO TODO can this be batched as well?
            let decomp = T::decompose_arithmetic_many(driver, &to_mpc_decompose, num_bits, 32)?;
            if T::is_shared(&left) {
                decomp_left = decomp[0]
                    .iter()
                    .map(|val| T::AcvmType::from(val.to_owned()))
                    .collect();
            }
            if T::is_shared(&right) {
                decomp_right = decomp
                    .last()
                    .expect("Is there")
                    .iter()
                    .map(|val| T::AcvmType::from(val.to_owned()))
                    .collect();
            }
        }

        let mut a_accumulator = FieldCT::default();
        let mut b_accumulator = FieldCT::default();
        let mut res = FieldCT::default();

        for (i, (left_chunk, right_chunk)) in decomp_left.into_iter().zip(decomp_right).enumerate()
        {
            let chunk_size = if i != num_chunks - 1 {
                32
            } else {
                num_bits - i * 32
            };

            let a_chunk = FieldCT::from_witness(left_chunk, self);
            let b_chunk = FieldCT::from_witness(right_chunk, self);

            let result_chunk = if is_xor_gate {
                Plookup::read_from_2_to_1_table(
                    self,
                    driver,
                    MultiTableId::Uint32Xor,
                    &a_chunk,
                    &b_chunk,
                )?
            } else {
                Plookup::read_from_2_to_1_table(
                    self,
                    driver,
                    MultiTableId::Uint32And,
                    &a_chunk,
                    &b_chunk,
                )?
            };

            let scaling_factor = FieldCT::from(P::ScalarField::from(BigUint::one() << (32 * i)));
            a_accumulator.add_assign(
                &a_chunk.multiply(&scaling_factor, self, driver)?,
                self,
                driver,
            );
            b_accumulator.add_assign(
                &b_chunk.multiply(&scaling_factor, self, driver)?,
                self,
                driver,
            );
            if chunk_size != 32 {
                // TACEO TODO can the decompose in here be batched as well?
                self.create_range_constraint(driver, a_chunk.witness_index, chunk_size as u32)?;
                self.create_range_constraint(driver, b_chunk.witness_index, chunk_size as u32)?;
            }

            res.add_assign(
                &result_chunk.multiply(&scaling_factor, self, driver)?,
                self,
                driver,
            );
        }

        let a_slice = &a.slice((num_bits - 1) as u8, 0, num_bits, self, driver)?[1];
        let b_slice = &b.slice((num_bits - 1) as u8, 0, num_bits, self, driver)?[1];
        a_slice.assert_equal(&a_accumulator, self, driver);
        b_slice.assert_equal(&b_accumulator, self, driver);

        Ok(res)
    }

    pub fn add_gates_to_ensure_all_polys_are_non_zero(&mut self, driver: &mut T) {
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
            self.zero_idx
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
            self.zero_idx
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
            self.zero_idx
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

        let left_witness_value = T::AcvmType::from(P::ScalarField::from(left_value as u64));
        let right_witness_value = T::AcvmType::from(P::ScalarField::from(right_value as u64));

        let left_witness_index = self.add_variable(left_witness_value.to_owned());
        let right_witness_index = self.add_variable(right_witness_value.to_owned());
        let dummy_accumulators = Plookup::get_lookup_accumulators(
            self,
            driver,
            MultiTableId::HonkDummyMulti,
            left_witness_value,
            right_witness_value,
            true,
        )
        .expect("Values are public so no network needed");
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
            self.zero_idx
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
            self.zero_idx
        );
    }
}
