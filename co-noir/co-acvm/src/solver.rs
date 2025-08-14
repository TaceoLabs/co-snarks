use acir::{
    acir_field::GenericFieldElement,
    circuit::{Circuit, ExpressionWidth, Opcode},
    native_types::{Witness, WitnessMap, WitnessStack},
};
use ark_ff::PrimeField;
use co_brillig::CoBrilligVM;
use intmap::IntMap;
use mpc_core::{
    lut::LookupTableProvider,
    protocols::{
        rep3::conversion::A2BType,
        shamir::{ShamirPreprocessing, ShamirState},
    },
};
use mpc_net::Network;
use noirc_abi::Abi;
use noirc_artifacts::program::ProgramArtifact;
use std::{collections::BTreeMap, fs::File, io, path::Path};

use crate::{
    mpc::{
        NoirWitnessExtensionProtocol, plain::PlainAcvmSolver, rep3::Rep3AcvmSolver,
        shamir::ShamirAcvmSolver,
    },
    pss_store::PssStore,
};

/// The default expression width defined used by the ACVM.
pub(crate) const _CO_EXPRESSION_WIDTH: ExpressionWidth = ExpressionWidth::Bounded { width: 4 };

mod assert_zero_solver;
mod blackbox_solver;
mod brillig_call_solver;
mod memory_solver;

pub type PlainCoSolver<F> = CoSolver<PlainAcvmSolver<F>, F>;
pub type Rep3CoSolver<'a, F, N> = CoSolver<Rep3AcvmSolver<'a, F, N>, F>;
pub type ShamirCoSolver<'a, F, N> = CoSolver<ShamirAcvmSolver<'a, F, N>, F>;

type CoAcvmResult<T> = std::result::Result<T, CoAcvmError>;

pub(crate) mod solver_utils {
    use acir::native_types::Expression;

    pub(crate) fn expr_to_string<F: std::fmt::Display>(expr: &Expression<F>) -> String {
        let mul_terms = expr
            .mul_terms
            .iter()
            .map(|(q_m, w_l, w_r)| format!("({q_m} * _{w_l:?} * _{w_r:?})"))
            .collect::<Vec<String>>()
            .join(" + ");
        let linear_terms = expr
            .linear_combinations
            .iter()
            .map(|(coef, w)| format!("({coef} * _{w:?})"))
            .collect::<Vec<String>>()
            .join(" + ");
        format!("EXPR [({mul_terms}) + ({linear_terms}) + {}]", expr.q_c)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CoAcvmError {
    #[error("Got failed from Brillig-VM")]
    BrilligVmFailed,
    #[error(transparent)]
    IOError(#[from] io::Error),
    #[error(transparent)]
    UnrecoverableError(#[from] eyre::Report),
}

pub struct CoSolver<T, F>
where
    T: NoirWitnessExtensionProtocol<F>,
    F: PrimeField,
{
    driver: T,
    brillig: CoBrilligVM<T::BrilligDriver, F>,
    abi: Abi,
    functions: Vec<Circuit<GenericFieldElement<F>>>,
    value_store: PssStore<T, F>,
    // maybe this can be an array. lets see..
    witness_map: Vec<WitnessMap<T::AcvmType>>,
    // there will a more fields added as we add functionality
    function_index: usize,
    // the memory blocks
    memory_access: IntMap<u64, <T::Lookup as LookupTableProvider<F>>::LutType>,
    // pedantic solving
    pedantic_solving: bool,
}

impl<T> CoSolver<T, ark_bn254::Fr>
where
    T: NoirWitnessExtensionProtocol<ark_bn254::Fr>,
{
    const DEFAULT_FUNCTION_INDEX: usize = 0;

    pub fn read_abi_bn254(
        path: impl AsRef<Path>,
        abi: &Abi,
    ) -> eyre::Result<WitnessMap<T::AcvmType>> {
        let initial_witness = noir_types::read_abi_bn254_fieldelement(File::open(path)?, abi)?;
        let mut witnesses = WitnessMap::<T::AcvmType>::default();
        for (witness, v) in initial_witness.into_iter() {
            witnesses.insert(witness, T::AcvmType::from(v.into_repr()));
        }
        Ok(witnesses)
    }

    pub fn new_bn254(
        mut driver: T,
        compiled_program: ProgramArtifact,
        prover_path: impl AsRef<Path>,
    ) -> eyre::Result<Self> {
        let mut witness_map =
            vec![WitnessMap::default(); compiled_program.bytecode.functions.len()];
        witness_map[Self::DEFAULT_FUNCTION_INDEX] =
            Self::read_abi_bn254(prover_path, &compiled_program.abi)?;
        let brillig = CoBrilligVM::init(
            driver.init_brillig_driver()?,
            compiled_program.bytecode.unconstrained_functions,
        );
        Ok(Self {
            brillig,
            driver,
            abi: compiled_program.abi,
            value_store: PssStore::new(),
            functions: compiled_program
                .bytecode
                .functions
                .into_iter()
                // ignore the transformation mapping for now
                //.map(|function| acvm::compiler::transform(function, CO_EXPRESSION_WIDTH).0)
                .collect::<Vec<_>>(),
            witness_map,
            function_index: Self::DEFAULT_FUNCTION_INDEX,
            memory_access: IntMap::new(),
            pedantic_solving: true,
        })
    }

    pub fn new_bn254_with_witness(
        mut driver: T,
        compiled_program: ProgramArtifact,
        witness: WitnessMap<T::AcvmType>,
    ) -> eyre::Result<Self> {
        let mut witness_map =
            vec![WitnessMap::default(); compiled_program.bytecode.functions.len()];
        witness_map[Self::DEFAULT_FUNCTION_INDEX] = witness;

        let brillig = CoBrilligVM::init(
            driver.init_brillig_driver()?,
            compiled_program.bytecode.unconstrained_functions,
        );
        Ok(Self {
            driver,
            brillig,
            abi: compiled_program.abi,
            value_store: PssStore::new(),
            functions: compiled_program
                .bytecode
                .functions
                .into_iter()
                // ignore the transformation mapping for now
                //.map(|function| acvm::compiler::transform(function, CO_EXPRESSION_WIDTH).0)
                .collect::<Vec<_>>(),
            witness_map,
            function_index: Self::DEFAULT_FUNCTION_INDEX,
            memory_access: IntMap::new(),
            pedantic_solving: true,
        })
    }
}

impl<'a, N: Network> Rep3CoSolver<'a, ark_bn254::Fr, N> {
    pub fn new(
        net0: &'a N,
        net1: &'a N,
        compiled_program: ProgramArtifact,
        prover_path: impl AsRef<Path>,
    ) -> eyre::Result<Self> {
        Self::new_bn254(
            Rep3AcvmSolver::new(net0, net1, A2BType::default())?,
            compiled_program,
            prover_path,
        )
    }

    pub fn new_with_witness(
        net0: &'a N,
        net1: &'a N,
        compiled_program: ProgramArtifact,
        witness: WitnessMap<
            <Rep3AcvmSolver<ark_bn254::Fr, N> as NoirWitnessExtensionProtocol::<ark_bn254::Fr>>::AcvmType,
        >,
    ) -> eyre::Result<Self> {
        Self::new_bn254_with_witness(
            Rep3AcvmSolver::new(net0, net1, A2BType::default())?,
            compiled_program,
            witness,
        )
    }
}

impl<'a, N: Network> ShamirCoSolver<'a, ark_bn254::Fr, N> {
    pub fn new(
        net: &'a N,
        num_parties: usize,
        threshold: usize,
        compiled_program: ProgramArtifact,
        prover_path: impl AsRef<Path>,
    ) -> eyre::Result<Self> {
        // TODO we are not creating any randomness here
        let preprocessing = ShamirPreprocessing::new(num_parties, threshold, 0, net)?;
        let state = ShamirState::from(preprocessing);

        Self::new_bn254(
            ShamirAcvmSolver::new(net, state),
            compiled_program,
            prover_path,
        )
    }

    pub fn new_with_witness(
        net: &'a N,
        num_parties: usize,
        threshold: usize,
        compiled_program: ProgramArtifact,
        witness: WitnessMap<
            <ShamirAcvmSolver<ark_bn254::Fr, N> as NoirWitnessExtensionProtocol::<ark_bn254::Fr>>::AcvmType,
        >,
    ) -> eyre::Result<Self> {
        // TODO we are not creating any randomness here
        let preprocessing = ShamirPreprocessing::new(num_parties, threshold, 0, net)?;
        let state = ShamirState::from(preprocessing);

        Self::new_bn254_with_witness(ShamirAcvmSolver::new(net, state), compiled_program, witness)
    }
}

impl<F: PrimeField> PlainCoSolver<F> {
    pub fn convert_to_plain_acvm_witness(
        mut shared_witness: WitnessStack<F>,
    ) -> WitnessStack<GenericFieldElement<F>> {
        let length = shared_witness.length();
        let mut vec = Vec::with_capacity(length);
        for _ in 0..length {
            let stack_item = shared_witness.pop().unwrap();
            vec.push((
                stack_item.index,
                stack_item
                    .witness
                    .into_iter()
                    .map(|(k, v)| (k, GenericFieldElement::from_repr(v)))
                    .collect::<BTreeMap<_, _>>(),
            ))
        }
        let mut witness = WitnessStack::default();
        //push again in reverse order
        for (index, witness_map) in vec.into_iter().rev() {
            witness.push(index, WitnessMap::from(witness_map));
        }
        witness
    }
}

impl PlainCoSolver<ark_bn254::Fr> {
    pub fn init_plain_driver(
        compiled_program: ProgramArtifact,
        prover_path: impl AsRef<Path>,
    ) -> eyre::Result<Self> {
        Self::new_bn254(PlainAcvmSolver::default(), compiled_program, prover_path)
    }

    pub fn solve_and_print_output(self) {
        let abi = self.abi.clone();
        let result = self.solve().unwrap();
        let mut result = Self::convert_to_plain_acvm_witness(result);
        let main_witness = result.pop().unwrap();
        let (_, ret_val) = abi.decode(&main_witness.witness).unwrap();
        if let Some(ret_val) = ret_val {
            println!("circuit produced: {ret_val:?}");
        } else {
            println!("no output for circuit")
        }
    }
}

impl<T, F> CoSolver<T, F>
where
    T: NoirWitnessExtensionProtocol<F>,
    F: PrimeField,
{
    pub fn pedantic_solving(&self) -> bool {
        self.pedantic_solving
    }

    #[inline(always)]
    fn witness(&mut self) -> &mut WitnessMap<T::AcvmType> {
        &mut self.witness_map[self.function_index]
    }

    fn open_results(
        &mut self,
        function: &Circuit<GenericFieldElement<F>>,
    ) -> CoAcvmResult<Vec<T::AcvmType>> {
        let witness_map = &mut self.witness_map[self.function_index];

        let mut vec = Vec::with_capacity(function.return_values.0.len());
        for index in function.return_values.0.iter() {
            let val = witness_map.get(index).expect("witness should be present");
            if let Some(val) = T::get_shared(val) {
                vec.push(val.clone());
            };
        }
        let mut opened = self.driver.open_many(&vec)?;
        let mut result = Vec::with_capacity(function.return_values.0.len());
        for index in function.return_values.0.iter().rev() {
            let val = witness_map.get(index).expect("witness should be present");
            if T::is_shared(val) {
                let opened_val = opened.pop().expect("opened value should be present");
                let opened_val = T::AcvmType::from(opened_val);
                witness_map.insert(*index, opened_val.clone());
                result.push(opened_val);
            } else {
                result.push(val.to_owned());
            }
        }
        Ok(result)
    }

    #[allow(clippy::type_complexity)]
    pub fn solve_with_output(
        mut self,
    ) -> CoAcvmResult<(WitnessStack<T::AcvmType>, PssStore<T, F>)> {
        let functions = std::mem::take(&mut self.functions);

        for opcode in functions[self.function_index].opcodes.iter() {
            match opcode {
                Opcode::AssertZero(expr) => self.solve_assert_zero(expr)?,
                Opcode::MemoryInit {
                    block_id,
                    init,
                    block_type: _, // apparently not used
                } => self.solve_memory_init_block(*block_id, init)?,
                Opcode::MemoryOp {
                    block_id,
                    op,
                    predicate,
                } => self.solve_memory_op(*block_id, op, predicate.to_owned())?,
                Opcode::BlackBoxFuncCall(bb_func) => self.solve_blackbox(bb_func)?,
                Opcode::BrilligCall {
                    id,
                    inputs,
                    outputs,
                    predicate,
                } => self.brillig_call(id, inputs, outputs, predicate)?,
                _ => todo!("opcode {} detected, not supported yet", opcode),
            }
        }
        tracing::trace!("we are done! Opening results...");
        let output = self.open_results(&functions[self.function_index])?;
        self.value_store.set_output(output);
        tracing::trace!("Done! Wrap things up.");

        let mut witness_stack = WitnessStack::default();
        for (idx, witness) in self.witness_map.into_iter().rev().enumerate() {
            witness_stack.push(u32::try_from(idx).expect("usize fits into u32"), witness);
        }
        Ok((witness_stack, self.value_store))
    }

    pub fn solve(self) -> CoAcvmResult<WitnessStack<T::AcvmType>> {
        let (witness_stack, _) = self.solve_with_output()?;
        Ok(witness_stack)
    }

    #[allow(clippy::type_complexity)]
    pub fn solve_r1cs_with_helper(
        mut self,
        mut traces: Vec<Vec<T::AcvmType>>,
    ) -> CoAcvmResult<WitnessStack<T::AcvmType>> {
        let functions = std::mem::take(&mut self.functions);

        let mut current_trace = vec![];
        let mut current_trace_idx = 0;
        let mut manual_trace = false;
        for (i, opcode) in functions[self.function_index].opcodes.iter().enumerate() {
            match opcode {
                Opcode::AssertZero(expr) => {
                    if manual_trace && !current_trace.is_empty() {
                        let witness = current_trace.remove(0);
                        self.witness().insert(Witness(current_trace_idx), witness);
                        current_trace_idx += 1;
                        continue;
                    }
                    self.solve_assert_zero(expr)?
                }
                Opcode::BrilligCall {
                    id,
                    inputs: _,
                    outputs: _,
                    predicate: _,
                } => {
                    match id.as_usize() {
                        0 => {
                            if manual_trace {
                                Err(eyre::eyre!("Order of marker functions is not correct"))?;
                            }
                            // We get the trace index from the next opcode
                            let next_expression = &functions[self.function_index].opcodes[i + 1];
                            let mut max_witness = 0;
                            match next_expression {
                                Opcode::AssertZero(expr) => {
                                    for el in expr.mul_terms.iter() {
                                        max_witness = max_witness.max(el.1.0);
                                        max_witness = max_witness.max(el.2.0);
                                    }
                                    for el in expr.linear_combinations.iter() {
                                        max_witness = max_witness.max(el.1.0);
                                    }
                                }
                                _ => Err(eyre::eyre!(
                                    "Expected AssertZero after opening marker function, got {next_expression:?}"
                                ))?,
                            }

                            current_trace = traces.remove(0);
                            manual_trace = true;
                            current_trace_idx = max_witness;
                        }
                        1 => {
                            if !manual_trace {
                                Err(eyre::eyre!("Order of marker functions is not correct"))?;
                            }
                            manual_trace = false;
                        }
                        _ => {
                            Err(eyre::eyre!(
                                "Brillig call with id {} is not supported in R1CS solving",
                                id
                            ))?;
                        }
                    }
                }
                _ => todo!("opcode {} detected, not supported", opcode),
            }
        }
        assert!(
            traces.is_empty(),
            "There should be no traces left after solving R1CS"
        );
        tracing::trace!("we are done! Opening results...");
        let output = self.open_results(&functions[self.function_index])?;
        self.value_store.set_output(output);
        tracing::trace!("Done! Wrap things up.");

        let mut witness_stack = WitnessStack::default();
        for (idx, witness) in self.witness_map.into_iter().rev().enumerate() {
            witness_stack.push(u32::try_from(idx).expect("usize fits into u32"), witness);
        }
        Ok(witness_stack)
    }
}
