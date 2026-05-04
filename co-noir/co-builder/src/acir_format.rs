use acir::{
    acir_field::GenericFieldElement,
    circuit::{
        Circuit,
        opcodes::{BlackBoxFuncCall, FunctionInput, MemOp as AcirMemOp},
    },
    native_types::{Expression, Witness, WitnessMap},
};
use ark_ff::PrimeField;
use co_noir_common::{constants::MOCK_PROOF_DYADIC_SIZE, honk_curve::HonkCurve};
use std::{array, cmp::max, collections::BTreeMap};

use crate::{
    transcript_ct::TranscriptFieldType,
    types::types::{
        AES128Constraint, AcirFormatOriginalOpcodeIndices, BigQuadConstraint, Blake2sConstraint,
        Blake3Constraint, BlockConstraint, BlockType, EcAdd, LogicConstraint, MemOp, MulQuad,
        MultiScalarMul, PolyTriple, Poseidon2Constraint, QuadConstraint, RangeConstraint,
        RecursionConstraint, Sha256Compression, WitnessOrConstant,
    },
};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ProofType {
    Honk,
    Oink,
    Hn,
    Avm,
    RollupHonk,
    RootRollupHonk,
    HonkZk,
    HnFinal,
    HnTail,
    Chonk,
}

impl From<u32> for ProofType {
    fn from(value: u32) -> Self {
        match value {
            0 => ProofType::Honk,
            1 => ProofType::Oink,
            2 => ProofType::Hn,
            3 => ProofType::Avm,
            4 => ProofType::RollupHonk,
            5 => ProofType::RootRollupHonk,
            6 => ProofType::HonkZk,
            7 => ProofType::HnFinal,
            8 => ProofType::HnTail,
            9 => ProofType::Chonk,
            _ => panic!("Invalid proof type"),
        }
    }
}

pub(crate) const _PROOF_TYPE_ROOT_ROLLUP_HONK: u32 = 4; //keep for reference
#[expect(dead_code)]
pub struct ProgramMetadata {
    // The proof produced when this flag is true should be friendly for recursive verification
    // inside of another SNARK. For example, a recursive friendly proof may use Blake3Pedersen
    // for hashing in its transcript, while we still want a prove that uses Keccak for its
    // transcript in order to be able to verify SNARKs on Ethereum.
    pub(crate) honk_recursion: HonkRecursion, // honk_recursion means we will honk to recursively verify this
    // circuit. This distinction is needed to not add the default
    // aggregation object when we're not using the honk RV.
    pub(crate) size_hint: usize,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HonkRecursion {
    NotHonk,     // 0 means we are not proving with honk
    UltraHonk,   // 1 means we are using the UltraHonk flavor
    UltraRollup, // 2 means we are using the UltraRollupHonk flavor
}
/// Barretenberg's representation of ACIR constraints
///
/// ACIR constraints are deserialized from bytes and stored in this format before being passed to the function
/// create_circuit, which constructs a circuit out of the constraints. An AcirFormat instance records all the constraints
/// that have to be added, plus some metadata:
/// 1. the maximum witness index (used in write_vk situations to fill the circuit with dummy variables)
/// 2. the number of original acir opcodes
/// 3. the indices of the public inputs
/// 4. the number of gates added to the circuit by each opcode (if calculated)
/// 5. the original indices of the opcodes (recording the order in which the opcodes were added to the struct)
///
///
#[derive(Debug, Default)]
pub struct AcirFormat<F: PrimeField> {
    pub(crate) max_witness_index: u32,
    pub(crate) num_acir_opcodes: u32,

    pub public_inputs: Vec<u32>,

    pub(crate) logic_constraints: Vec<LogicConstraint<F>>,
    pub(crate) range_constraints: Vec<RangeConstraint>,
    pub(crate) aes128_constraints: Vec<AES128Constraint<F>>,
    pub(crate) sha256_compression: Vec<Sha256Compression<F>>,
    //  std::vector<EcdsaSecp256k1Constraint> ecdsa_k1_constraints;
    //  std::vector<EcdsaSecp256r1Constraint> ecdsa_r1_constraints;
    pub(crate) blake2s_constraints: Vec<Blake2sConstraint<F>>,
    pub(crate) blake3_constraints: Vec<Blake3Constraint<F>>,
    //  std::vector<KeccakConstraint> keccak_constraints;
    //  std::vector<Keccakf1600> keccak_permutations;
    pub(crate) poseidon2_constraints: Vec<Poseidon2Constraint<F>>,
    pub(crate) multi_scalar_mul_constraints: Vec<MultiScalarMul<F>>,
    pub(crate) ec_add_constraints: Vec<EcAdd<F>>,
    pub(crate) honk_recursion_constraints: Vec<RecursionConstraint<F>>,
    pub(crate) avm_recursion_constraints: Vec<RecursionConstraint<F>>,
    pub(crate) hn_recursion_constraints: Vec<RecursionConstraint<F>>,
    pub(crate) chonk_recursion_constraints: Vec<RecursionConstraint<F>>,
    pub(crate) quad_constraints: Vec<QuadConstraint<F>>,
    pub(crate) big_quad_constraints: Vec<BigQuadConstraint<F>>,
    pub(crate) block_constraints: Vec<BlockConstraint<F>>,

    /// Number of gates added to the circuit per original opcode.
    /// Has length equal to num_acir_opcodes.
    pub(crate) _gates_per_opcode: Vec<usize>,

    /// Indices of the original opcode that originated each constraint in AcirFormat.
    pub(crate) original_opcode_indices: AcirFormatOriginalOpcodeIndices,
}

impl<F: PrimeField> AcirFormat<F> {
    pub fn update_max_witness_index(&mut self, witness_index: u32) {
        // If the witness index is not a constant
        if witness_index != u32::MAX {
            self.max_witness_index = self.max_witness_index.max(witness_index);
        }
    }

    pub fn update_max_witness_index_from_expression(
        &mut self,
        expr: &Expression<GenericFieldElement<F>>,
    ) {
        // Process multiplication terms: each term has two witness indices
        for (_, w1, w2) in &expr.mul_terms {
            self.update_max_witness_index(w1.0);
            self.update_max_witness_index(w2.0);
        }

        // Process linear combinations: each term has one witness index
        for (_, w1) in &expr.linear_combinations {
            self.update_max_witness_index(w1.0);
        }
    }
    pub fn update_max_witness_index_from_opcode(
        &mut self,
        opcode: &acir::circuit::Opcode<GenericFieldElement<F>>,
    ) {
        fn update_max_witness_index_from_function_input<F: PrimeField>(
            af: &mut AcirFormat<F>,
            input: &FunctionInput<GenericFieldElement<F>>,
        ) {
            if let FunctionInput::Witness(witness) = input {
                af.update_max_witness_index(witness.0);
            }
        }

        fn update_max_witness_index_from_witness<F: PrimeField>(
            af: &mut AcirFormat<F>,
            witness: &Witness,
        ) {
            af.update_max_witness_index(witness.0);
        }

        match opcode {
            acir::circuit::Opcode::AssertZero(expression) => {
                self.update_max_witness_index_from_expression(expression);
            }
            acir::circuit::Opcode::BlackBoxFuncCall(bb_call) => match bb_call {
                BlackBoxFuncCall::AND {
                    lhs, rhs, output, ..
                }
                | BlackBoxFuncCall::XOR {
                    lhs, rhs, output, ..
                } => {
                    update_max_witness_index_from_function_input(self, lhs);
                    update_max_witness_index_from_function_input(self, rhs);
                    update_max_witness_index_from_witness(self, output);
                }
                BlackBoxFuncCall::RANGE { input, .. } => {
                    update_max_witness_index_from_function_input(self, input);
                }
                BlackBoxFuncCall::AES128Encrypt {
                    inputs,
                    iv,
                    key,
                    outputs,
                } => {
                    for input in inputs {
                        update_max_witness_index_from_function_input(self, input);
                    }
                    for input in iv.iter() {
                        update_max_witness_index_from_function_input(self, input);
                    }
                    for input in key.iter() {
                        update_max_witness_index_from_function_input(self, input);
                    }
                    for output in outputs {
                        update_max_witness_index_from_witness(self, output);
                    }
                }
                BlackBoxFuncCall::Sha256Compression {
                    inputs,
                    hash_values,
                    outputs,
                } => {
                    for input in inputs.iter() {
                        update_max_witness_index_from_function_input(self, input);
                    }
                    for input in hash_values.iter() {
                        update_max_witness_index_from_function_input(self, input);
                    }
                    for output in outputs.iter() {
                        update_max_witness_index_from_witness(self, output);
                    }
                }
                BlackBoxFuncCall::Blake2s { inputs, outputs }
                | BlackBoxFuncCall::Blake3 { inputs, outputs } => {
                    for input in inputs {
                        update_max_witness_index_from_function_input(self, input);
                    }
                    for output in outputs.iter() {
                        update_max_witness_index_from_witness(self, output);
                    }
                }
                BlackBoxFuncCall::EcdsaSecp256k1 {
                    public_key_x,
                    public_key_y,
                    signature,
                    hashed_message,
                    predicate,
                    output,
                }
                | BlackBoxFuncCall::EcdsaSecp256r1 {
                    public_key_x,
                    public_key_y,
                    signature,
                    hashed_message,
                    predicate,
                    output,
                } => {
                    for input in public_key_x.iter() {
                        update_max_witness_index_from_function_input(self, input);
                    }
                    for input in public_key_y.iter() {
                        update_max_witness_index_from_function_input(self, input);
                    }
                    for input in signature.iter() {
                        update_max_witness_index_from_function_input(self, input);
                    }
                    for input in hashed_message.iter() {
                        update_max_witness_index_from_function_input(self, input);
                    }
                    update_max_witness_index_from_function_input(self, predicate);
                    update_max_witness_index_from_witness(self, output);
                }
                BlackBoxFuncCall::MultiScalarMul {
                    points,
                    scalars,
                    predicate,
                    outputs,
                    ..
                } => {
                    for input in points {
                        update_max_witness_index_from_function_input(self, input);
                    }
                    for input in scalars {
                        update_max_witness_index_from_function_input(self, input);
                    }
                    update_max_witness_index_from_function_input(self, predicate);
                    update_max_witness_index_from_witness(self, &outputs.0);
                    update_max_witness_index_from_witness(self, &outputs.1);
                    update_max_witness_index_from_witness(self, &outputs.2);
                }
                BlackBoxFuncCall::EmbeddedCurveAdd {
                    input1,
                    input2,
                    predicate,
                    outputs,
                    ..
                } => {
                    for input in input1.iter() {
                        update_max_witness_index_from_function_input(self, input);
                    }
                    for input in input2.iter() {
                        update_max_witness_index_from_function_input(self, input);
                    }
                    update_max_witness_index_from_function_input(self, predicate);
                    update_max_witness_index_from_witness(self, &outputs.0);
                    update_max_witness_index_from_witness(self, &outputs.1);
                    update_max_witness_index_from_witness(self, &outputs.2);
                }
                BlackBoxFuncCall::Keccakf1600 { inputs, outputs } => {
                    for input in inputs.iter() {
                        update_max_witness_index_from_function_input(self, input);
                    }
                    for output in outputs.iter() {
                        update_max_witness_index_from_witness(self, output);
                    }
                }
                BlackBoxFuncCall::RecursiveAggregation {
                    verification_key,
                    proof,
                    public_inputs,
                    key_hash,
                    predicate,
                    ..
                } => {
                    for input in verification_key {
                        update_max_witness_index_from_function_input(self, input);
                    }
                    for input in proof {
                        update_max_witness_index_from_function_input(self, input);
                    }
                    for input in public_inputs {
                        update_max_witness_index_from_function_input(self, input);
                    }
                    update_max_witness_index_from_function_input(self, key_hash);
                    update_max_witness_index_from_function_input(self, predicate);
                }
                BlackBoxFuncCall::Poseidon2Permutation { inputs, outputs } => {
                    for input in inputs {
                        update_max_witness_index_from_function_input(self, input);
                    }
                    for output in outputs {
                        update_max_witness_index_from_witness(self, output);
                    }
                }
            },
            acir::circuit::Opcode::MemoryInit { init, .. } => {
                for witness in init {
                    update_max_witness_index_from_witness(self, witness);
                }
            }
            acir::circuit::Opcode::MemoryOp { op, .. } => {
                self.update_max_witness_index_from_expression(&op.index);
                self.update_max_witness_index_from_expression(&op.value);
                self.update_max_witness_index_from_expression(&op.operation);
            }
            acir::circuit::Opcode::BrilligCall {
                inputs,
                outputs,
                predicate,
                ..
            } => {
                for input in inputs {
                    match input {
                        acir::circuit::brillig::BrilligInputs::Single(expr) => {
                            self.update_max_witness_index_from_expression(expr);
                        }
                        acir::circuit::brillig::BrilligInputs::Array(exprs) => {
                            for expr in exprs {
                                self.update_max_witness_index_from_expression(expr);
                            }
                        }
                        acir::circuit::brillig::BrilligInputs::MemoryArray(_) => {}
                    }
                }
                for output in outputs {
                    match output {
                        acir::circuit::brillig::BrilligOutputs::Simple(witness) => {
                            update_max_witness_index_from_witness(self, witness);
                        }
                        acir::circuit::brillig::BrilligOutputs::Array(witnesses) => {
                            for witness in witnesses {
                                update_max_witness_index_from_witness(self, witness);
                            }
                        }
                    }
                }
                self.update_max_witness_index_from_expression(predicate);
            }
            acir::circuit::Opcode::Call { .. } => {
                panic!(
                    "acir_format::update_max_witness_index_from_opcode: Call opcode is not supported."
                );
            }
        }
    }

    pub fn witness_map_to_witness_vector(
        witness_map: WitnessMap<GenericFieldElement<F>>,
    ) -> Vec<F> {
        let mut wv = Vec::new();
        let mut index = 0;
        for (w, f) in witness_map.into_iter() {
            // ACIR uses a sparse format for WitnessMap where unused witness indices may be left unassigned.
            // To ensure that witnesses sit at the correct indices in the `WitnessVector`, we fill any indices
            // which do not exist within the `WitnessMap` with the dummy value of zero.
            while index < w.0 {
                wv.push(F::zero());
                index += 1;
            }
            wv.push(f.into_repr());
            index += 1;
        }
        wv
    }

    pub fn circuit_serde_to_acir_format(circuit: Circuit<GenericFieldElement<F>>) -> Self {
        assert!(
            circuit.opcodes.len() as u32 <= u32::MAX,
            "AcirFormat::circuit_serde_to_acir_format: Number of opcodes exceeds maximum allowed"
        );

        let mut af = AcirFormat::default();

        af.num_acir_opcodes = circuit.opcodes.len() as u32;

        af.public_inputs = circuit
            .public_parameters
            .0
            .iter()
            .chain(circuit.return_values.0.iter())
            .map(|x| {
                af.update_max_witness_index(x.0);
                x.0
            })
            .collect();

        // Map to a pair of: BlockConstraint, and list of opcodes associated with that BlockConstraint
        // TACEO TODO: THIS IS NOT DETERMINISTIC IN Barrettenberg (use of unordered_map), thus some tests may produce different circuits! We need to make it deterministic though since the MPC parties may produce different circuits and MPC will fail...
        let mut block_id_to_block_constraint: BTreeMap<u32, (BlockConstraint<F>, Vec<usize>)> =
            BTreeMap::new();
        for (i, gate) in circuit.opcodes.into_iter().enumerate() {
            af.update_max_witness_index_from_opcode(&gate);
            match gate {
                acir::circuit::Opcode::AssertZero(expression) => {
                    Self::assert_zero_to_quad_constraints(&expression, &mut af, i)
                }
                acir::circuit::Opcode::BlackBoxFuncCall(black_box_func_call) => {
                    Self::add_blackbox_func_call_to_acir_format(black_box_func_call, &mut af, i)
                }
                acir::circuit::Opcode::MemoryInit {
                    block_id,
                    init,
                    block_type,
                } => {
                    let block = Self::memory_init_to_block_constraint(init, block_type);
                    let block_id = block_id.0;
                    let opcode_indices = vec![i];
                    block_id_to_block_constraint.insert(block_id, (block, opcode_indices));
                }
                acir::circuit::Opcode::MemoryOp { block_id, op } => {
                    let block = block_id_to_block_constraint.get_mut(&block_id.0);
                    if block.is_none() {
                        panic!(
                            "acir_format::circuit_serde_to_acir_format: uninitialized MemoryOp."
                        );
                    }
                    let block = block.unwrap();
                    Self::add_memory_op_to_block_constraint(op, &mut block.0);
                    block.1.push(i);
                }
                acir::circuit::Opcode::Call { .. } => {
                    panic!(
                        "acir_format::circuit_serde_to_acir_format: Call opcode is not supported."
                    );
                }
                _ => {}
            }
        }

        for (_, (block_constraint, opcode_indices)) in block_id_to_block_constraint {
            af.block_constraints.push(block_constraint);
            af.original_opcode_indices
                .block_constraints
                .push(opcode_indices);
        }

        af
    }

    // ========= ACIR OPCODE HANDLERS =========
    fn split_into_mul_quad_gates(
        arg: &Expression<GenericFieldElement<F>>,
        linear_terms: &mut BTreeMap<u32, F>,
    ) -> Vec<MulQuad<F>> {
        let add_linear_term_and_erase =
            |idx: &mut u32, scaling: &mut F, linear_terms: &mut BTreeMap<u32, F>| {
                assert_eq!(
                    *idx,
                    u32::MAX,
                    "Attempting to override a non-constant witness index in mul_quad_ gate"
                );
                let (witness_idx, coeff) = linear_terms
                    .pop_first()
                    .expect("add_linear_term_and_erase called with empty linear_terms");
                *idx = witness_idx;
                *scaling += coeff;
            };

        let mut result = Vec::new();

        // We cannot precompute the exact number of gates that will result from the expression. Therefore, we reserve the
        // maximum number of gates that could ever be needed: one per multiplication term plus one per linear term. The real
        // number of gates will in general be lower than this.
        assert!(
            arg.mul_terms.len() <= usize::MAX - linear_terms.len(),
            "split_into_mul_quad_gates: overflow when reserving space for mul_quad_ gates."
        );
        result.reserve(arg.mul_terms.len() + linear_terms.len());

        // Step 1. Add multiplication terms and linear terms with the same witness index.
        for mul_term in &arg.mul_terms {
            result.push(MulQuad {
                a: mul_term.1.0,
                b: mul_term.2.0,
                c: u32::MAX,
                d: u32::MAX,
                mul_scaling: mul_term.0.into_repr(),
                a_scaling: F::zero(),
                b_scaling: F::zero(),
                c_scaling: F::zero(),
                d_scaling: F::zero(),
                const_scaling: F::zero(),
            });

            // Add linear terms corresponding to the witnesses involved in the multiplication term
            let mul_quad = result
                .last_mut()
                .expect("split_into_mul_quad_gates: just pushed gate");
            if let Some(coeff) = linear_terms.remove(&mul_quad.a) {
                mul_quad.a_scaling += coeff;
            }
            if let Some(coeff) = linear_terms.remove(&mul_quad.b) {
                // Note that we enter here only if b is different from a
                mul_quad.b_scaling += coeff;
            }
        }

        // Step 2. Add linear terms to existing gates.
        let mut is_first_gate = true;
        for mul_quad in result.iter_mut() {
            if !linear_terms.is_empty() {
                add_linear_term_and_erase(&mut mul_quad.c, &mut mul_quad.c_scaling, linear_terms);
            }
            if is_first_gate {
                // First gate contains the constant term and uses all four wires.
                mul_quad.const_scaling = arg.q_c.into_repr();
                if !linear_terms.is_empty() {
                    add_linear_term_and_erase(
                        &mut mul_quad.d,
                        &mut mul_quad.d_scaling,
                        linear_terms,
                    );
                }
                is_first_gate = false;
            }
        }

        // Step 3. Add remaining linear terms.
        while !linear_terms.is_empty() {
            let mut mul_quad = MulQuad {
                a: u32::MAX,
                b: u32::MAX,
                c: u32::MAX,
                d: u32::MAX,
                mul_scaling: F::zero(),
                a_scaling: F::zero(),
                b_scaling: F::zero(),
                c_scaling: F::zero(),
                d_scaling: F::zero(),
                const_scaling: F::zero(),
            };

            if !linear_terms.is_empty() {
                add_linear_term_and_erase(&mut mul_quad.a, &mut mul_quad.a_scaling, linear_terms);
            }
            if !linear_terms.is_empty() {
                add_linear_term_and_erase(&mut mul_quad.b, &mut mul_quad.b_scaling, linear_terms);
            }
            if !linear_terms.is_empty() {
                add_linear_term_and_erase(&mut mul_quad.c, &mut mul_quad.c_scaling, linear_terms);
            }
            if is_first_gate {
                // First gate contains the constant term and uses all four wires.
                mul_quad.const_scaling = arg.q_c.into_repr();
                if !linear_terms.is_empty() {
                    add_linear_term_and_erase(
                        &mut mul_quad.d,
                        &mut mul_quad.d_scaling,
                        linear_terms,
                    );
                }
                is_first_gate = false;
            }

            result.push(mul_quad);
        }

        assert!(
            !result.is_empty(),
            "split_into_mul_quad_gates: resulted in zero gates. This means that there is an expression with no multiplication terms and no linear terms."
        );
        result.shrink_to_fit();
        result
    }

    fn assert_zero_to_quad_constraints(
        arg: &Expression<GenericFieldElement<F>>,
        af: &mut AcirFormat<F>,
        opcode_index: usize,
    ) {
        let is_zero_gate = |gate: &MulQuad<F>| {
            gate.mul_scaling.is_zero()
                && gate.a_scaling.is_zero()
                && gate.b_scaling.is_zero()
                && gate.c_scaling.is_zero()
                && gate.d_scaling.is_zero()
                && gate.const_scaling.is_zero()
        };

        let mut linear_terms = Self::process_linear_terms(arg);
        let is_single_gate = Self::is_single_arithmetic_gate(arg, &linear_terms);
        let mul_quads = Self::split_into_mul_quad_gates(arg, &mut linear_terms);

        for mul_quad in &mul_quads {
            assert!(
                !is_zero_gate(mul_quad),
                "acir_format::assert_zero_to_quad_constraints: produced an arithmetic zero gate."
            );
        }

        if is_single_gate {
            assert_eq!(
                mul_quads.len(),
                1,
                "acir_format::assert_zero_to_quad_constraints: expected a single gate."
            );
            af.quad_constraints.push(mul_quads[0].clone());
            af.original_opcode_indices
                .quad_constraints
                .push(opcode_index);
        } else {
            assert!(
                mul_quads.len() > 1,
                "acir_format::assert_zero_to_quad_constraints: expected multiple gates but found one."
            );
            af.big_quad_constraints.push(mul_quads);
            af.original_opcode_indices
                .big_quad_constraints
                .push(opcode_index);
        }
    }

    fn add_blackbox_func_call_to_acir_format(
        arg: BlackBoxFuncCall<GenericFieldElement<F>>,
        af: &mut AcirFormat<F>,
        opcode_index: usize,
    ) {
        let to_witness_or_constant =
            |e: FunctionInput<GenericFieldElement<F>>| Self::parse_input(e);
        let to_witness = |e: Witness| e.0;
        let to_witness_from_input =
            |e: FunctionInput<GenericFieldElement<F>>| e.to_witness().witness_index();

        match arg {
            BlackBoxFuncCall::AND {
                lhs,
                rhs,
                output,
                num_bits,
            } => {
                af.logic_constraints.push(LogicConstraint {
                    a: Self::parse_input(lhs),
                    b: Self::parse_input(rhs),
                    result: to_witness(output),
                    num_bits,
                    is_xor_gate: false,
                });
                af.original_opcode_indices
                    .logic_constraints
                    .push(opcode_index);
            }
            BlackBoxFuncCall::XOR {
                lhs,
                rhs,
                output,
                num_bits,
            } => {
                af.logic_constraints.push(LogicConstraint {
                    a: Self::parse_input(lhs),
                    b: Self::parse_input(rhs),
                    result: to_witness(output),
                    num_bits,
                    is_xor_gate: true,
                });
                af.original_opcode_indices
                    .logic_constraints
                    .push(opcode_index);
            }
            BlackBoxFuncCall::RANGE { input, num_bits } => {
                af.range_constraints.push(RangeConstraint {
                    witness: to_witness_from_input(input),
                    num_bits,
                });
                af.original_opcode_indices
                    .range_constraints
                    .push(opcode_index);
            }
            BlackBoxFuncCall::AES128Encrypt {
                inputs,
                iv,
                key,
                outputs,
            } => {
                af.aes128_constraints.push(AES128Constraint {
                    inputs: inputs.into_iter().map(to_witness_or_constant).collect(),
                    iv: iv.into_iter().map(to_witness_or_constant).collect(),
                    key: key.into_iter().map(to_witness_or_constant).collect(),
                    outputs: outputs.into_iter().map(to_witness).collect(),
                });
                af.original_opcode_indices
                    .aes128_constraints
                    .push(opcode_index);
            }
            BlackBoxFuncCall::Sha256Compression {
                inputs,
                hash_values,
                outputs,
            } => {
                af.sha256_compression.push(Sha256Compression {
                    inputs: inputs.into_iter().map(to_witness_or_constant).collect(),
                    hash_values: hash_values
                        .into_iter()
                        .map(to_witness_or_constant)
                        .collect(),
                    result: outputs.into_iter().map(to_witness).collect(),
                });
                af.original_opcode_indices
                    .sha256_compression
                    .push(opcode_index);
            }
            BlackBoxFuncCall::Blake2s { inputs, outputs } => {
                af.blake2s_constraints.push(Blake2sConstraint {
                    inputs: inputs.into_iter().map(&to_witness_or_constant).collect(),
                    result: array::from_fn(|i| to_witness(outputs[i])),
                });
                af.original_opcode_indices
                    .blake2s_constraints
                    .push(opcode_index);
            }
            BlackBoxFuncCall::Blake3 { inputs, outputs } => {
                af.blake3_constraints.push(Blake3Constraint {
                    inputs: inputs.into_iter().map(&to_witness_or_constant).collect(),
                    result: array::from_fn(|i| to_witness(outputs[i])),
                });
                af.original_opcode_indices
                    .blake3_constraints
                    .push(opcode_index);
            }
            BlackBoxFuncCall::EcdsaSecp256k1 {
                public_key_x: _,
                public_key_y: _,
                signature: _,
                hashed_message: _,
                output: _,
                predicate: _,
            } => todo!("BlackBoxFuncCall::EcdsaSecp256k1"),
            BlackBoxFuncCall::EcdsaSecp256r1 {
                public_key_x: _,
                public_key_y: _,
                signature: _,
                hashed_message: _,
                output: _,
                ..
            } => todo!("BlackBoxFuncCall::EcdsaSecp256r1"),
            BlackBoxFuncCall::MultiScalarMul {
                points,
                scalars,
                outputs,
                predicate,
                ..
            } => {
                af.multi_scalar_mul_constraints.push(MultiScalarMul {
                    points: points.into_iter().map(to_witness_or_constant).collect(),
                    scalars: scalars.into_iter().map(to_witness_or_constant).collect(),
                    predicate: Self::parse_input(predicate),
                    out_point_x: to_witness(outputs.0),
                    out_point_y: to_witness(outputs.1),
                });
                af.original_opcode_indices
                    .multi_scalar_mul_constraints
                    .push(opcode_index);
            }
            BlackBoxFuncCall::EmbeddedCurveAdd {
                input1,
                input2,
                outputs,
                predicate,
                ..
            } => {
                af.ec_add_constraints.push(EcAdd {
                    input1_x: Self::parse_input(input1[0]),
                    input1_y: Self::parse_input(input1[1]),
                    input1_infinite: Self::parse_input(input1[2]),
                    input2_x: Self::parse_input(input2[0]),
                    input2_y: Self::parse_input(input2[1]),
                    input2_infinite: Self::parse_input(input2[2]),
                    predicate: Self::parse_input(predicate),
                    result_x: to_witness(outputs.0),
                    result_y: to_witness(outputs.1),
                });
                af.original_opcode_indices
                    .ec_add_constraints
                    .push(opcode_index);
            }
            BlackBoxFuncCall::Keccakf1600 {
                inputs: _,
                outputs: _,
            } => todo!("BlackBoxFuncCall::Keccakf1600"),
            BlackBoxFuncCall::RecursiveAggregation {
                verification_key,
                proof,
                public_inputs,
                key_hash,
                proof_type,
                predicate,
            } => {
                let predicate = Self::parse_input(predicate);
                if predicate.is_constant && predicate.value.is_zero() {
                    // No constraint if recursion is disabled.
                    return;
                }

                let c = RecursionConstraint {
                    key: verification_key
                        .into_iter()
                        .map(to_witness_from_input)
                        .collect(),
                    proof: proof.into_iter().map(to_witness_from_input).collect(),
                    public_inputs: public_inputs
                        .into_iter()
                        .map(to_witness_from_input)
                        .collect(),
                    key_hash: to_witness_from_input(key_hash),
                    proof_type,
                    predicate,
                };

                match ProofType::from(c.proof_type) {
                    ProofType::Honk
                    | ProofType::HonkZk
                    | ProofType::RollupHonk
                    | ProofType::RootRollupHonk => {
                        af.honk_recursion_constraints.push(c);
                        af.original_opcode_indices
                            .honk_recursion_constraints
                            .push(opcode_index);
                    }
                    ProofType::Oink | ProofType::Hn | ProofType::HnTail | ProofType::HnFinal => {
                        af.hn_recursion_constraints.push(c);
                    }
                    ProofType::Avm => {
                        af.avm_recursion_constraints.push(c);
                    }
                    ProofType::Chonk => {
                        af.chonk_recursion_constraints.push(c);
                    }
                }
            }
            BlackBoxFuncCall::Poseidon2Permutation { inputs, outputs } => {
                af.poseidon2_constraints.push(Poseidon2Constraint {
                    state: inputs.into_iter().map(to_witness_or_constant).collect(),
                    result: outputs.into_iter().map(to_witness).collect(),
                });
                af.original_opcode_indices
                    .poseidon2_constraints
                    .push(opcode_index);
            }
        }
    }

    fn memory_init_to_block_constraint(
        mem_init: Vec<Witness>,
        block_type: acir::circuit::opcodes::BlockType,
    ) -> BlockConstraint<F> {
        const CALLDATA_NONE: u32 = u32::MAX;
        const CALLDATA_PRIMARY: u32 = 0;
        const CALLDATA_SECONDARY: u32 = 1;

        // Noir doesn't distinguish between ROM and RAM table. Therefore, we initialize every table as a ROM table, and
        // then we make it a RAM table if there is at least one write operation.
        let mut block = BlockConstraint {
            init: Vec::new(),
            trace: Vec::new(),
            type_: BlockType::ROM,
            calldata: CALLDATA_NONE,
        };
        block.init.reserve(mem_init.len());

        for val in mem_init {
            block.init.push(PolyTriple {
                a: val.0,
                b: 0,
                c: 0,
                q_m: F::zero(),
                q_l: F::one(),
                q_r: F::zero(),
                q_o: F::zero(),
                q_c: F::zero(),
            });
        }

        // Databus is only supported for Goblin, non Goblin builders will treat call_data and return_data as normal array.
        match block_type {
            acir::circuit::opcodes::BlockType::Memory => {}
            acir::circuit::opcodes::BlockType::CallData(val) => {
                assert!(
                    val == CALLDATA_PRIMARY || val == CALLDATA_SECONDARY,
                    "acir_format::memory_init_to_block_constraint: Unsupported calldata id"
                );
                block.type_ = BlockType::CallData;
                block.calldata = if val == CALLDATA_PRIMARY {
                    CALLDATA_PRIMARY
                } else {
                    CALLDATA_SECONDARY
                };
            }
            acir::circuit::opcodes::BlockType::ReturnData => block.type_ = BlockType::ReturnData,
        }

        block
    }

    fn add_memory_op_to_block_constraint(
        mem_op: AcirMemOp<GenericFieldElement<F>>,
        block: &mut BlockConstraint<F>,
    ) {
        // Convert an Acir expression to witness index
        let acir_expression_to_witness_or_constant =
            |expr: &Expression<GenericFieldElement<F>>| -> WitnessOrConstant<F> {
                // Noir gives us witnesses or constants for read/write operations. We use the following assertions to ensure
                // that the data coming from Noir is in the correct form.
                assert!(
                    expr.mul_terms.is_empty(),
                    "MemoryOp should not have multiplication terms"
                );
                assert!(
                    expr.linear_combinations.len() <= 1,
                    "MemoryOp should have at most one linear term"
                );

                let a_scaling = if expr.linear_combinations.len() == 1 {
                    expr.linear_combinations[0].0.into_repr()
                } else {
                    F::zero()
                };
                let constant_term = expr.q_c.into_repr();

                let is_witness = a_scaling.is_one() && constant_term.is_zero();
                let is_constant = a_scaling.is_zero();
                assert!(
                    is_witness || is_constant,
                    "MemoryOp expression must be a witness or a constant"
                );

                WitnessOrConstant {
                    index: if is_witness {
                        expr.linear_combinations[0].1.0
                    } else {
                        u32::MAX
                    },
                    value: if is_constant {
                        constant_term
                    } else {
                        F::zero()
                    },
                    is_constant,
                }
            };

        // Determine whether this op is read or write.
        let is_read_operation = |expr: &Expression<GenericFieldElement<F>>| -> bool {
            assert!(
                expr.mul_terms.is_empty(),
                "MemoryOp expression should not have multiplication terms"
            );
            assert!(
                expr.linear_combinations.is_empty(),
                "MemoryOp expression should not have linear terms"
            );

            let const_term = expr.q_c.into_repr();
            assert!(
                const_term.is_one() || const_term.is_zero(),
                "MemoryOp expression should be either zero or one"
            );

            // A read operation is encoded by a zero expression.
            const_term.is_zero()
        };

        let access_type = if is_read_operation(&mem_op.operation) {
            0 // Read
        } else {
            1 // Write
        };

        if access_type == 1 {
            // We are not allowed to write on the databus.
            assert!((block.type_ != BlockType::CallData) && (block.type_ != BlockType::ReturnData));
            // Mark the table as RAM table
            block.type_ = BlockType::RAM;
        }

        let index = acir_expression_to_witness_or_constant(&mem_op.index);
        let value = acir_expression_to_witness_or_constant(&mem_op.value);

        let acir_mem_op = MemOp {
            access_type,
            index,
            value,
        };
        block.trace.push(acir_mem_op);
    }

    fn process_linear_terms(arg: &Expression<GenericFieldElement<F>>) -> BTreeMap<u32, F> {
        let mut linear_terms = BTreeMap::new();

        for linear_term in &arg.linear_combinations {
            let selector_value: F = linear_term.0.into_repr();
            let witness_idx = linear_term.1.0;
            if let Some(existing) = linear_terms.get_mut(&witness_idx) {
                *existing += selector_value; // Accumulate coefficients for duplicate witnesses
            } else {
                linear_terms.insert(witness_idx, selector_value);
            }
        }

        linear_terms
    }

    fn is_single_arithmetic_gate(
        arg: &Expression<GenericFieldElement<F>>,
        linear_terms: &BTreeMap<u32, F>,
    ) -> bool {
        const NUM_WIRES: usize = 4;

        // If there are more than 4 distinct witnesses in the linear terms, then we need multiple arithmetic gates.
        if linear_terms.len() > NUM_WIRES {
            return false;
        }

        if arg.mul_terms.len() > 1 {
            // If there is more than one multiplication term, then we need multiple arithmetic gates.
            return false;
        }

        if arg.mul_terms.len() == 1 {
            // In this case we have two witnesses coming from the multiplication term plus the linear terms.
            // We proceed as follows:
            //  0. Start from the assumption that all witnesses (from linear terms and multiplication) are distinct
            //  1. Check if the lhs and rhs witness in the multiplication are already contained in the linear terms
            //  2. Check if the lhs witness and the rhs witness are equal
            //     2.a If they are distinct, update the total number of witnesses to be added to wires according to result
            //         of the check at step 1: each distinct witness already in the linear terms subtracts one from the
            //         total
            //     2.b If they are equal, update the total number of witnesses to be added to wires according to result of
            //         the check at step 1: if the witness is already in the linear terms, it removes one from the total

            // Number of witnesses to be put in wires if the witnesses from the linear terms and the multiplication term are
            // all different
            let mut num_witnesses_to_be_put_in_wires = 2 + linear_terms.len();

            let witness_idx_lhs = arg.mul_terms[0].1.0;
            let witness_idx_rhs = arg.mul_terms[0].2.0;

            let lhs_is_distinct_from_linear_terms = !linear_terms.contains_key(&witness_idx_lhs);
            let rhs_is_distinct_from_linear_terms = !linear_terms.contains_key(&witness_idx_rhs);

            if witness_idx_lhs != witness_idx_rhs {
                if !lhs_is_distinct_from_linear_terms {
                    num_witnesses_to_be_put_in_wires -= 1;
                }
                if !rhs_is_distinct_from_linear_terms {
                    num_witnesses_to_be_put_in_wires -= 1;
                }
            } else if !lhs_is_distinct_from_linear_terms {
                num_witnesses_to_be_put_in_wires -= 1;
            }

            return num_witnesses_to_be_put_in_wires <= NUM_WIRES;
        }

        linear_terms.len() <= NUM_WIRES
    }

    fn parse_input(input: FunctionInput<GenericFieldElement<F>>) -> WitnessOrConstant<F> {
        match input {
            FunctionInput::Witness(witness) => WitnessOrConstant::from_index(witness.0),
            FunctionInput::Constant(value) => WitnessOrConstant::from_constant(value.into_repr()),
        }
    }

    pub fn get_honk_recursion_public_inputs_size<
        C: HonkCurve<TranscriptFieldType, ScalarField = F>,
    >(
        &self,
    ) -> usize {
        let mut total_size = 0;
        if !self.honk_recursion_constraints.is_empty() {
            for constraint in &self.honk_recursion_constraints {
                let mut size =
                    (constraint.public_inputs.len() + MOCK_PROOF_DYADIC_SIZE).next_power_of_two(); // the circuit is at least size 64 (we take next power of 2 to be safe)
                assert!(
                    constraint.proof_type == ProofType::Honk as u32
                        || constraint.proof_type == ProofType::HonkZk as u32
                );
                size = if constraint.proof_type == ProofType::Honk as u32 {
                    size
                } else {
                    max(size, C::SUBGROUP_SIZE * 2)
                };
                total_size = max(total_size, size);
            }
        }
        total_size
    }

    pub fn is_recursive_verification_circuit(&self) -> bool {
        !self.honk_recursion_constraints.is_empty()
    }
}
