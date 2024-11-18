use acir::{
    acir_field::GenericFieldElement,
    circuit::{
        opcodes::{BlackBoxFuncCall, MemOp},
        Circuit,
    },
    native_types::{Expression, Witness, WitnessMap},
    AcirField,
};
use ark_ff::{PrimeField, Zero};
use std::collections::{BTreeMap, HashMap, HashSet};

use crate::types::types::{
    AcirFormatOriginalOpcodeIndices, BlockConstraint, BlockType, MulQuad, PolyTriple,
    RangeConstraint, RecursionConstraint,
};

#[derive(Default)]
pub struct AcirFormat<F: PrimeField> {
    /// The number of witnesses in the circuit
    pub(crate) varnum: u32,
    /// Specifies whether a prover that produces SNARK recursion friendly proofs should be used.
    /// The proof produced when this flag is true should be friendly for recursive verification inside
    /// of another SNARK. For example, a recursive friendly proof may use Blake3Pedersen for
    /// hashing in its transcript, while we still want a prove that uses Keccak for its transcript in order
    /// to be able to verify SNARKs on Ethereum.
    pub(crate) recursive: bool,
    pub(crate) num_acir_opcodes: u32,
    //  using PolyTripleConstraint = bb::poly_triple_<bb::curve::BN254::ScalarField>;
    pub public_inputs: Vec<u32>,
    pub(crate) range_constraints: Vec<RangeConstraint>,
    //  std::vector<LogicConstraint> logic_constraints;
    //  std::vector<AES128Constraint> aes128_constraints;
    //  std::vector<Sha256Constraint> sha256_constraints;
    //  std::vector<Sha256Compression> sha256_compression;
    //  std::vector<SchnorrConstraint> schnorr_constraints;
    //  std::vector<EcdsaSecp256k1Constraint> ecdsa_k1_constraints;
    //  std::vector<EcdsaSecp256r1Constraint> ecdsa_r1_constraints;
    //  std::vector<Blake2sConstraint> blake2s_constraints;
    //  std::vector<Blake3Constraint> blake3_constraints;
    //  std::vector<KeccakConstraint> keccak_constraints;
    //  std::vector<Keccakf1600> keccak_permutations;
    //  std::vector<PedersenConstraint> pedersen_constraints;
    //  std::vector<PedersenHashConstraint> pedersen_hash_constraints;
    //  std::vector<Poseidon2Constraint> poseidon2_constraints;
    //  std::vector<MultiScalarMul> multi_scalar_mul_constraints;
    //  std::vector<EcAdd> ec_add_constraints;
    pub(crate) recursion_constraints: Vec<RecursionConstraint>,
    pub(crate) honk_recursion_constraints: Vec<RecursionConstraint>,
    pub(crate) avm_recursion_constraints: Vec<RecursionConstraint>,
    //  std::vector<RecursionConstraint> ivc_recursion_constraints;
    //  std::vector<BigIntFromLeBytes> bigint_from_le_bytes_constraints;
    //  std::vector<BigIntToLeBytes> bigint_to_le_bytes_constraints;
    //  std::vector<BigIntOperation> bigint_operations;
    pub(crate) assert_equalities: Vec<PolyTriple<F>>,

    /// A standard plonk arithmetic constraint, as defined in the poly_triple struct, consists of selector values
    /// for q_M,q_L,q_R,q_O,q_C and indices of three variables taking the role of left, right and output wire
    /// This could be a large vector, we don't expect the blackbox implementations to be so large.
    pub(crate) poly_triple_constraints: Vec<PolyTriple<F>>,
    pub(crate) quad_constraints: Vec<MulQuad<F>>,
    pub(crate) big_quad_constraints: Vec<Vec<MulQuad<F>>>,
    pub(crate) block_constraints: Vec<BlockConstraint<F>>,

    /// Number of gates added to the circuit per original opcode.
    /// Has length equal to num_acir_opcodes.
    pub(crate) gates_per_opcode: Vec<usize>,

    /// Set of constrained witnesses
    pub(crate) constrained_witness: HashSet<u32>,
    pub(crate) minimal_range: BTreeMap<u32, u32>,
    /// Indices of the original opcode that originated each constraint in AcirFormat.
    pub(crate) original_opcode_indices: AcirFormatOriginalOpcodeIndices,
}

impl<F: PrimeField> AcirFormat<F> {
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

    #[allow(clippy::field_reassign_with_default)]
    pub fn circuit_serde_to_acir_format(
        circuit: Circuit<GenericFieldElement<F>>,
        honk_recursion: bool,
    ) -> Self {
        let mut af = AcirFormat::default();

        // `varnum` is the true number of variables, thus we add one to the index which starts at zero
        af.varnum = circuit.current_witness_index + 1;
        af.recursive = circuit.recursive;
        af.num_acir_opcodes = circuit.opcodes.len() as u32;

        af.public_inputs = circuit
            .public_parameters
            .0
            .iter()
            .chain(circuit.return_values.0.iter())
            .map(|x| x.0)
            .collect();

        // Map to a pair of: BlockConstraint, and list of opcodes associated with that BlockConstraint
        let mut block_id_to_block_constraint: HashMap<u32, (BlockConstraint<F>, Vec<usize>)> =
            HashMap::new();
        for (i, gate) in circuit.opcodes.into_iter().enumerate() {
            match gate {
                acir::circuit::Opcode::AssertZero(expression) => {
                    Self::handle_arithmetic(expression, &mut af, i)
                }
                acir::circuit::Opcode::BlackBoxFuncCall(black_box_func_call) => {
                    Self::handle_blackbox_func_call(black_box_func_call, &mut af, honk_recursion, i)
                }
                acir::circuit::Opcode::MemoryOp {
                    block_id,
                    op,
                    predicate: _,
                } => {
                    let block = block_id_to_block_constraint.get_mut(&block_id.0);
                    if block.is_none() {
                        panic!("unitialized MemoryOp");
                    }
                    let block = block.unwrap();
                    Self::handle_memory_op(op, &mut block.0);
                    block.1.push(i);
                }
                acir::circuit::Opcode::MemoryInit {
                    block_id,
                    init,
                    block_type: _,
                } => {
                    let block = Self::handle_memory_init(init);
                    let block_id = block_id.0;
                    let opcode_indices = vec![i];
                    block_id_to_block_constraint.insert(block_id, (block, opcode_indices));
                }
                _ => {}
            }
        }

        for (_, (block_constraint, opcode_indices)) in block_id_to_block_constraint {
            // Note: the trace will always be empty for ReturnData since it cannot be explicitly read from in noir
            if !block_constraint.trace.is_empty()
                || block_constraint.type_ == BlockType::ReturnData
                || block_constraint.type_ == BlockType::CallData
            {
                af.block_constraints.push(block_constraint);
                af.original_opcode_indices
                    .block_constraints
                    .push(opcode_indices);
            }
        }

        af
    }

    fn handle_arithmetic(
        arg: Expression<GenericFieldElement<F>>,
        af: &mut AcirFormat<F>,
        opcode_index: usize,
    ) {
        if arg.linear_combinations.len() <= 3 && arg.mul_terms.len() <= 1 {
            let mut pt = Self::serialize_arithmetic_gate(&arg);

            let (w1, w2) = Self::is_assert_equal(&arg, &pt, af);

            if !w1.is_zero() {
                if w1 != w2 {
                    if !af.constrained_witness.contains(&pt.a) {
                        // we mark it as constrained because it is going to be asserted to be equal to a constrained one.
                        af.constrained_witness.insert(pt.a);
                        // swap the witnesses so that the first one is always properly constrained.
                        std::mem::swap(&mut pt.a, &mut pt.b);
                    }
                    if !af.constrained_witness.contains(&pt.b) {
                        // we mark it as constrained because it is going to be asserted to be equal to a constrained one.
                        af.constrained_witness.insert(pt.b);
                    }
                    // minimal_range of a witness is the smallest range of the witness and the witness that are
                    // 'assert_equal' to it
                    if af.minimal_range.contains_key(&pt.b) && af.minimal_range.contains_key(&pt.a)
                    {
                        if af.minimal_range[&pt.a] < af.minimal_range[&pt.b] {
                            af.minimal_range.insert(pt.a, af.minimal_range[&pt.b]);
                        } else {
                            af.minimal_range.insert(pt.b, af.minimal_range[&pt.a]);
                        }
                    } else if af.minimal_range.contains_key(&pt.b) {
                        af.minimal_range.insert(pt.a, af.minimal_range[&pt.b]);
                    } else if af.minimal_range.contains_key(&pt.a) {
                        af.minimal_range.insert(pt.b, af.minimal_range[&pt.a]);
                    }

                    af.assert_equalities.push(pt);
                    af.original_opcode_indices
                        .assert_equalities
                        .push(opcode_index);
                }
                return;
            }
            // Even if the number of linear terms is less than 3, we might not be able to fit it into a width-3 arithmetic
            // gate. This is the case if the linear terms are all disctinct witness from the multiplication term. In that
            // case, the serialize_arithmetic_gate() function will return a poly_triple with all 0's, and we use a width-4
            // gate instead. We could probably always use a width-4 gate in fact.
            if pt == PolyTriple::default() {
                af.quad_constraints
                    .push(Self::serialize_mul_quad_gate(&arg));
                af.original_opcode_indices
                    .quad_constraints
                    .push(opcode_index);
            } else {
                af.poly_triple_constraints.push(pt);
                af.original_opcode_indices
                    .poly_triple_constraints
                    .push(opcode_index);
            }
        } else {
            let mut mul_quads = Vec::new();
            // We try to use a single mul_quad gate to represent the expression.
            if arg.mul_terms.len() <= 1 {
                let quad = Self::serialize_mul_quad_gate(&arg);

                // add it to the result vector if it worked
                if !quad.a.is_zero() || !quad.mul_scaling.is_zero() || !quad.a_scaling.is_zero() {
                    mul_quads.push(quad);
                }
            }
            if mul_quads.is_empty() {
                // If not, we need to split the expression into multiple gates
                mul_quads = Self::split_into_mul_quad_gates(&arg);
            }
            if mul_quads.len() == 1 {
                af.quad_constraints.push(mul_quads[0].clone());
                af.original_opcode_indices
                    .quad_constraints
                    .push(opcode_index);
            }
            if mul_quads.len() > 1 {
                af.big_quad_constraints.push(mul_quads);
            }
        }
        Self::constrain_witnesses(arg, af);
    }

    /**
     * @brief Construct a poly_tuple for a standard width-3 arithmetic gate from its acir representation
     *
     * @param arg acir representation of an 3-wire arithmetic operation
     * @return poly_triple
     * @note In principle Program::Expression can accommodate arbitrarily many quadratic and linear terms but in practice
     * the ones processed here have a max of 1 and 3 respectively, in accordance with the standard width-3 arithmetic gate.
     */
    fn serialize_arithmetic_gate(arg: &Expression<GenericFieldElement<F>>) -> PolyTriple<F> {
        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/816): The initialization of the witness indices a,b,c
        // to 0 is implicitly assuming that (builder.zero_idx == 0) which is no longer the case. Now, witness idx 0 in
        // general will correspond to some non-zero value and some witnesses which are not explicitly set below will be
        // erroneously populated with this value. This does not cause failures however because the corresponding selector
        // will indeed be 0 so the gate will be satisfied. Still, its a bad idea to have erroneous wire values
        // even if they dont break the relation. They'll still add cost in commitments, for example.
        let mut pt = PolyTriple::default();

        // Flags indicating whether each witness index for the present poly_tuple has been set
        let mut a_set = false;
        let mut b_set = false;
        let mut c_set = false;

        // If necessary, set values for quadratic term (q_m * w_l * w_r)
        assert!(arg.mul_terms.len() <= 1); // We can only accommodate 1 quadratic term
                                           // Note: mul_terms are tuples of the form {selector_value, witness_idx_1, witness_idx_2}
        if !arg.mul_terms.is_empty() {
            let mul_term = &arg.mul_terms[0];
            pt.q_m = mul_term.0.into_repr();
            pt.a = mul_term.1 .0;
            pt.b = mul_term.2 .0;
            a_set = true;
            b_set = true;
        }

        // If necessary, set values for linears terms q_l * w_l, q_r * w_r and q_o * w_o
        assert!(arg.linear_combinations.len() <= 3); // We can only accommodate 3 linear terms
        for linear_term in arg.linear_combinations.iter() {
            let selector_value = linear_term.0.into_repr();
            let witness_idx = linear_term.1 .0;

            // If the witness index has not yet been set or if the corresponding linear term is active, set the witness
            // index and the corresponding selector value.
            // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/816): May need to adjust the pt.a == witness_idx
            // check (and the others like it) since we initialize a,b,c with 0 but 0 is a valid witness index once the
            // +1 offset is removed from noir.
            if !a_set || pt.a == witness_idx {
                // q_l * w_l
                pt.a = witness_idx;
                pt.q_l = selector_value;
                a_set = true;
            } else if !b_set || pt.b == witness_idx {
                // q_r * w_r
                pt.b = witness_idx;
                pt.q_r = selector_value;
                b_set = true;
            } else if !c_set || pt.c == witness_idx {
                // q_o * w_o
                pt.c = witness_idx;
                pt.q_o = selector_value;
                c_set = true;
            } else {
                return PolyTriple::default();
            }
        }

        // Set constant value q_c
        pt.q_c = arg.q_c.into_repr();
        pt
    }

    fn is_assert_equal(
        arg: &Expression<GenericFieldElement<F>>,
        pt: &PolyTriple<F>,
        af: &AcirFormat<F>,
    ) -> (u32, u32) {
        if !arg.mul_terms.is_empty() || arg.linear_combinations.len() != 2 {
            return (0, 0);
        }
        if (pt.q_l == -pt.q_r && !pt.q_l.is_zero() && pt.q_c.is_zero())
            &&
             // we require that one of the 2 witnesses to be constrained in an arithmetic gate
            (af.constrained_witness.contains(&pt.a) || af.constrained_witness.contains(&pt.b))
        {
            return (pt.a, pt.b);
        }
        (0, 0)
    }

    fn serialize_mul_quad_gate(arg: &Expression<GenericFieldElement<F>>) -> MulQuad<F> {
        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/816): The initialization of the witness indices a,b,c
        // to 0 is implicitly assuming that (builder.zero_idx == 0) which is no longer the case. Now, witness idx 0 in
        // general will correspond to some non-zero value and some witnesses which are not explicitly set below will be
        // erroneously populated with this value. This does not cause failures however because the corresponding selector
        // will indeed be 0 so the gate will be satisfied. Still, its a bad idea to have erroneous wire values
        // even if they dont break the relation. They'll still add cost in commitments, for example.
        let mut quad = MulQuad::default();

        // Flags indicating whether each witness index for the present mul_quad has been set
        let mut a_set = false;
        let mut b_set = false;
        let mut c_set = false;
        let mut d_set = false;
        assert!(arg.mul_terms.len() <= 1); // We can only accommodate 1 quadratic term
                                           // Note: mul_terms are tuples of the form {selector_value, witness_idx_1, witness_idx_2}
        if !arg.mul_terms.is_empty() {
            let mul_term = &arg.mul_terms[0];
            quad.mul_scaling = mul_term.0.into_repr();
            quad.a = mul_term.1 .0;
            quad.b = mul_term.2 .0;
            a_set = true;
            b_set = true;
        }
        // If necessary, set values for linears terms q_l * w_l, q_r * w_r and q_o * w_o
        // assert!(arg.linear_combinations.len() <= 4); // We can only accommodate 4 linear terms
        for linear_term in arg.linear_combinations.iter() {
            let selector_value = linear_term.0.into_repr();
            let witness_idx = linear_term.1 .0;

            // If the witness index has not yet been set or if the corresponding linear term is active, set the witness
            // index and the corresponding selector value.
            // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/816): May need to adjust the quad.a == witness_idx
            // check (and the others like it) since we initialize a,b,c with 0 but 0 is a valid witness index once the
            // +1 offset is removed from noir.
            if !a_set || quad.a == witness_idx {
                quad.a = witness_idx;
                quad.a_scaling = selector_value;
                a_set = true;
            } else if !b_set || quad.b == witness_idx {
                quad.b = witness_idx;
                quad.b_scaling = selector_value;
                b_set = true;
            } else if !c_set || quad.c == witness_idx {
                quad.c = witness_idx;
                quad.c_scaling = selector_value;
                c_set = true;
            } else if !d_set || quad.d == witness_idx {
                quad.d = witness_idx;
                quad.d_scaling = selector_value;
                d_set = true;
            } else {
                return MulQuad::default();
            }
        }

        // Set constant value q_c
        quad.const_scaling = arg.q_c.into_repr();
        quad
    }

    fn split_into_mul_quad_gates(arg: &Expression<GenericFieldElement<F>>) -> Vec<MulQuad<F>> {
        let mut result = Vec::new();

        let mut current_mul_term_iter = arg.mul_terms.iter();
        let mut current_mul_term = current_mul_term_iter.next();
        let mut current_linear_term_iter = arg.linear_combinations.iter();
        let mut current_linear_term = current_linear_term_iter.next();

        // number of wires to use in the intermediate gate
        let mut max_size = 4;
        let mut done = false;
        // the intermediate 'big add' gates. The first one contains the constant term.
        let mut mul_gate = MulQuad {
            a: 0,
            b: 0,
            c: 0,
            d: 0,
            mul_scaling: F::zero(),
            a_scaling: F::zero(),
            b_scaling: F::zero(),
            c_scaling: F::zero(),
            d_scaling: F::zero(),
            const_scaling: arg.q_c.into_repr(),
        };

        // list of witnesses that are part of mul terms
        let mut all_mul_terms = HashSet::new();
        for term in &arg.mul_terms {
            all_mul_terms.insert(term.1 .0);
            all_mul_terms.insert(term.2 .0);
        }
        // The 'mul term' witnesses that have been processed
        let mut processed_mul_terms = HashSet::new();

        while !done {
            let mut i = 0; // index of the current free wire in the new intermediate gate

            // we add a mul term (if there are some) to every intermediate gate
            if let Some(mul_term) = current_mul_term {
                mul_gate.mul_scaling = mul_term.0.into_repr();
                mul_gate.a = mul_term.1 .0;
                mul_gate.b = mul_term.2 .0;
                mul_gate.a_scaling = F::zero();
                mul_gate.b_scaling = F::zero();
                // Try to add corresponding linear terms, only if they were not already added
                if !processed_mul_terms.contains(&mul_gate.a)
                    || !processed_mul_terms.contains(&mul_gate.b)
                {
                    for lin_term in &arg.linear_combinations {
                        let w = lin_term.1 .0;
                        if w == mul_gate.a {
                            if !processed_mul_terms.contains(&mul_gate.a) {
                                mul_gate.a_scaling = lin_term.0.into_repr();
                                processed_mul_terms.insert(w);
                            }
                            if mul_gate.a == mul_gate.b {
                                break;
                            }
                        } else if w == mul_gate.b {
                            if !processed_mul_terms.contains(&mul_gate.b) {
                                mul_gate.b_scaling = lin_term.0.into_repr();
                                processed_mul_terms.insert(w);
                            }
                            break;
                        }
                    }
                }
                i = 2; // a and b are used because of the mul term
                current_mul_term = current_mul_term_iter.next();
            }
            // We need to process all the mul terms before being done.
            done = current_mul_term.is_none();

            // Assign available wires with the remaining linear terms which are not also a 'mul term'
            while current_linear_term.is_some() {
                let current_term = current_linear_term.unwrap();
                let w = current_term.1 .0;
                if !all_mul_terms.contains(&w) {
                    if i < max_size {
                        Self::assign_linear_term(&mut mul_gate, i, w, current_term.0.into_repr()); // * fr(-1)));
                        i += 1;
                    } else {
                        // No more available wire, but there is still some linear terms; we need another mul_gate
                        done = false;
                        break;
                    }
                }
                current_linear_term = current_linear_term_iter.next();
            }

            // Index 4 of the next gate will be used
            max_size = 3;
            result.push(mul_gate);
            mul_gate = MulQuad::default();
        }
        result
    }

    fn assign_linear_term(gate: &mut MulQuad<F>, index: usize, witness_index: u32, scaling: F) {
        match index {
            0 => {
                gate.a = witness_index;
                gate.a_scaling = scaling;
            }
            1 => {
                gate.b = witness_index;
                gate.b_scaling = scaling;
            }
            2 => {
                gate.c = witness_index;
                gate.c_scaling = scaling;
            }
            3 => {
                gate.d = witness_index;
                gate.d_scaling = scaling;
            }
            _ => panic!("Invalid index in assign_linear_term"),
        }
    }
    fn constrain_witnesses(arg: Expression<GenericFieldElement<F>>, af: &mut AcirFormat<F>) {
        for linear_term in arg.linear_combinations {
            let witness_idx = linear_term.1 .0;
            af.constrained_witness.insert(witness_idx);
        }
        for linear_term in arg.mul_terms {
            let witness_idx = linear_term.1 .0;
            af.constrained_witness.insert(witness_idx);
            let witness_idx = linear_term.2 .0;
            af.constrained_witness.insert(witness_idx);
        }
    }

    fn handle_memory_init(mem_init: Vec<Witness>) -> BlockConstraint<F> {
        let mut block = BlockConstraint::default();
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

        // Databus is only supported for Goblin, non Goblin builders will treat call_data and return_data as normal
        // array.
        block.type_ = BlockType::ReturnData;
        block
    }

    fn is_rom(mem_op: &MemOp<GenericFieldElement<F>>) -> bool {
        mem_op.operation.mul_terms.is_empty()
            && mem_op.operation.linear_combinations.is_empty()
            && mem_op.operation.q_c.is_zero()
    }

    fn handle_memory_op(mem_op: MemOp<GenericFieldElement<F>>, block: &mut BlockConstraint<F>) {
        let access_type = if Self::is_rom(&mem_op) { 0 } else { 1 };
        if access_type == 1 {
            // We are not allowed to write on the databus
            assert!((block.type_ != BlockType::CallData) && (block.type_ != BlockType::ReturnData));
            block.type_ = BlockType::RAM;
        }

        let acir_mem_op = super::types::types::MemOp {
            access_type,
            index: Self::serialize_arithmetic_gate(&mem_op.index),
            value: Self::serialize_arithmetic_gate(&mem_op.value),
        };

        block.trace.push(acir_mem_op);
    }

    #[allow(unused)] // TACEO TODO remove later
    fn handle_blackbox_func_call(
        arg: BlackBoxFuncCall<GenericFieldElement<F>>,
        af: &mut AcirFormat<F>,
        honk_recursive: bool,
        opcode_index: usize,
    ) {
        match arg {
            BlackBoxFuncCall::AES128Encrypt {
                inputs,
                iv,
                key,
                outputs,
            } => todo!("BlackBoxFuncCall::AES128Encrypt "),
            BlackBoxFuncCall::AND { lhs, rhs, output } => todo!("BlackBoxFuncCall::AND"),
            BlackBoxFuncCall::XOR { lhs, rhs, output } => todo!("BlackBoxFuncCall::XOR"),
            BlackBoxFuncCall::RANGE { input } => {
                let witness_input = input.to_witness().witness_index();
                af.range_constraints.push(RangeConstraint {
                    witness: witness_input,
                    num_bits: input.num_bits(),
                });
                af.original_opcode_indices
                    .range_constraints
                    .push(opcode_index);

                if (af.minimal_range.contains_key(&witness_input)) {
                    if (af.minimal_range[&witness_input] > input.num_bits()) {
                        af.minimal_range.insert(witness_input, input.num_bits());
                    }
                } else {
                    af.minimal_range
                        .insert(input.to_witness().witness_index(), input.num_bits());
                }
            }
            BlackBoxFuncCall::Blake2s { inputs, outputs } => todo!("BlackBoxFuncCall::Blake2s"),
            BlackBoxFuncCall::Blake3 { inputs, outputs } => todo!("BlackBoxFuncCall::Blake3"),
            BlackBoxFuncCall::SchnorrVerify {
                public_key_x,
                public_key_y,
                signature,
                message,
                output,
            } => todo!("BlackBoxFuncCall::SchnorrVerify"),
            BlackBoxFuncCall::EcdsaSecp256k1 {
                public_key_x,
                public_key_y,
                signature,
                hashed_message,
                output,
            } => todo!("BlackBoxFuncCall::EcdsaSecp256k1"),
            BlackBoxFuncCall::EcdsaSecp256r1 {
                public_key_x,
                public_key_y,
                signature,
                hashed_message,
                output,
            } => todo!("BlackBoxFuncCall::EcdsaSecp256r1"),
            BlackBoxFuncCall::MultiScalarMul {
                points,
                scalars,
                outputs,
            } => todo!(),
            BlackBoxFuncCall::EmbeddedCurveAdd {
                input1,
                input2,
                outputs,
            } => todo!("BlackBoxFuncCall::EmbeddedCurveAdd"),
            BlackBoxFuncCall::Keccakf1600 { inputs, outputs } => {
                todo!("BlackBoxFuncCall::Keccakf1600")
            }
            BlackBoxFuncCall::BigIntAdd { lhs, rhs, output } => {
                todo!("BlackBoxFuncCall::BigIntAdd")
            }
            BlackBoxFuncCall::BigIntSub { lhs, rhs, output } => {
                todo!("BlackBoxFuncCall::BigIntSub")
            }
            BlackBoxFuncCall::BigIntMul { lhs, rhs, output } => {
                todo!("BlackBoxFuncCall::BigIntMul")
            }
            BlackBoxFuncCall::BigIntDiv { lhs, rhs, output } => {
                todo!("BlackBoxFuncCall::BigIntDiv")
            }
            BlackBoxFuncCall::BigIntFromLeBytes {
                inputs,
                modulus,
                output,
            } => todo!("BlackBoxFuncCall::BigIntFromLeBytes"),
            BlackBoxFuncCall::BigIntToLeBytes { input, outputs } => todo!(),
            BlackBoxFuncCall::Poseidon2Permutation {
                inputs,
                outputs,
                len,
            } => todo!("BlackBoxFuncCall::Poseidon2Permutation"),
            BlackBoxFuncCall::Sha256Compression {
                inputs,
                hash_values,
                outputs,
            } => todo!("BlackBoxFuncCall::Sha256Compression"),
            BlackBoxFuncCall::RecursiveAggregation {
                verification_key,
                proof,
                public_inputs,
                key_hash,
                proof_type,
            } => todo!("BlackBoxFuncCall::RecursiveAggregation"),
        }
    }
}
