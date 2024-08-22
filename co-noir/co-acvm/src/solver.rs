use acir::{
    circuit::{Circuit, ExpressionWidth, Opcode},
    native_types::{WitnessMap, WitnessStack},
    AcirField, FieldElement,
};
use mpc_core::{
    protocols::{
        plain::PlainDriver,
        rep3::{network::Rep3Network, Rep3Protocol},
    },
    traits::NoirWitnessExtensionProtocol,
};
use noirc_abi::{input_parser::Format, Abi, MAIN_RETURN_NAME};
use noirc_artifacts::program::ProgramArtifact;
use num_bigint::BigUint;
use num_traits::One;
use std::{io, path::PathBuf};
/// The default expression width defined used by the ACVM.
pub(crate) const CO_EXPRESSION_WIDTH: ExpressionWidth = ExpressionWidth::Bounded { width: 4 };

mod assert_zero_solver;
pub type PlainCoSolver<F> = CoSolver<PlainDriver<F>, F>;
pub type Rep3CoSolver<F, N> = CoSolver<Rep3Protocol<F, N>, F>;

type CoAcvmResult<T> = std::result::Result<T, CoAcvmError>;

#[derive(Debug, thiserror::Error)]
pub enum CoAcvmError {
    #[error("Expected at most one mul term, but got {0}")]
    TooManyMulTerm(usize),
    #[error(transparent)]
    IOError(#[from] io::Error),
    #[error("unsolvable, too many unknown terms")]
    TooManyUnknowns,
}

pub struct CoSolver<T, F>
where
    T: NoirWitnessExtensionProtocol<F>,
    F: AcirField,
{
    driver: T,
    abi: Abi,
    functions: Vec<Circuit<F>>,
    // maybe this can be an array. lets see..
    witness_map: Vec<WitnessMap<T::AcvmType>>,
    // there will a more fields added as we add functionality
    function_index: usize,
}

impl<T> CoSolver<T, FieldElement>
where
    T: NoirWitnessExtensionProtocol<FieldElement>,
{
    pub fn read_abi<P>(path: P, abi: &Abi) -> eyre::Result<WitnessMap<T::AcvmType>>
    where
        PathBuf: From<P>,
    {
        if abi.is_empty() {
            Ok(WitnessMap::default())
        } else {
            let input_string = std::fs::read_to_string(PathBuf::from(path))?;
            let mut input_map = Format::Toml.parse(&input_string, abi)?;
            let return_value = input_map.remove(MAIN_RETURN_NAME);
            // TODO the return value can be none for the witness extension
            // do we want to keep it like that? Seems not necessary but maybe
            // we need it for proving/verifying
            let initial_witness = abi.encode(&input_map, return_value.clone())?;
            let mut witnesses = WitnessMap::<T::AcvmType>::default();
            for (witness, v) in initial_witness.into_iter() {
                witnesses.insert(witness, T::AcvmType::from(v));
            }
            Ok(witnesses)
        }
    }

    pub fn new<P>(
        driver: T,
        compiled_program: ProgramArtifact,
        prover_path: P,
    ) -> eyre::Result<Self>
    where
        PathBuf: From<P>,
    {
        let mut witness_map =
            vec![WitnessMap::default(); compiled_program.bytecode.functions.len()];
        witness_map[0] = Self::read_abi(prover_path, &compiled_program.abi)?;
        Ok(Self {
            driver,
            abi: compiled_program.abi,
            functions: compiled_program
                .bytecode
                .functions
                .into_iter()
                // ignore the transformation mapping for now
                .map(|function| acvm::compiler::transform(function, CO_EXPRESSION_WIDTH).0)
                .collect::<Vec<_>>(),
            witness_map,
            function_index: 0,
        })
    }
}

impl<N: Rep3Network> Rep3CoSolver<FieldElement, N> {
    pub fn from_network<P>(
        network: N,
        compiled_program: ProgramArtifact,
        prover_path: P,
    ) -> eyre::Result<Self>
    where
        PathBuf: From<P>,
    {
        Self::new(Rep3Protocol::new(network)?, compiled_program, prover_path)
    }
}

impl PlainCoSolver<FieldElement> {
    pub fn init_plain_driver<P>(
        compiled_program: ProgramArtifact,
        prover_path: P,
    ) -> eyre::Result<Self>
    where
        PathBuf: From<P>,
    {
        let modulus = FieldElement::modulus();
        let one = BigUint::one();
        let two = BigUint::from(2u64);
        // FIXME find something better
        let negative_one = FieldElement::from_be_bytes_reduce(&(modulus / two + one).to_bytes_be());
        Self::new(
            PlainDriver::new(negative_one),
            compiled_program,
            prover_path,
        )
    }

    pub fn solve_and_print_output(self) {
        let abi = self.abi.clone();
        let result = self.solve().unwrap();
        let main_witness = result.peek().unwrap();
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
    F: AcirField,
{
    fn witness(&mut self) -> &mut WitnessMap<T::AcvmType> {
        &mut self.witness_map[self.function_index]
    }
}

impl<T> CoSolver<T, FieldElement>
where
    T: NoirWitnessExtensionProtocol<FieldElement>,
{
    pub fn solve(mut self) -> CoAcvmResult<WitnessStack<T::AcvmType>> {
        let functions = std::mem::take(&mut self.functions);

        for opcode in functions[self.function_index].opcodes.iter() {
            match opcode {
                Opcode::AssertZero(expr) => self.solve_assert_zero(expr)?,
                _ => todo!("non assert zero opcode detected, not supported yet"),
                //Opcode::Call {
                //    id,
                //    inputs,
                //    outputs,
                //    predicate,
                //} => todo!(),
            }
        }
        // TODO this is most likely not correct.
        // We'll see what happens here.
        let mut witness_stack = WitnessStack::default();
        for (idx, witness) in self.witness_map.into_iter().rev().enumerate() {
            witness_stack.push(u32::try_from(idx).expect("usize fits into u32"), witness);
        }
        Ok(witness_stack)
    }
}

/*
  let binary_packages = workspace.into_iter().filter(|package| package.is_binary());
    for package in binary_packages {
*/
