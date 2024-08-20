use acir::{circuit::Opcode, AcirField, FieldElement};
use mpc_core::{protocols::plain::PlainDriver, traits::NoirWitnessExtensionProtocol};
use num_bigint::BigUint;
use num_traits::One;
use std::io;

use crate::types::{CoWitnessMap, FullWitness};

mod assert_zero_solver;
pub type PlainCoSolver<F> = CoSolver<PlainDriver<F>, F>;

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
    //there will a more fields added as we add functionality
    opcodes: Vec<Opcode<F>>,
    //maybe this can be an array. lets see..
    witness_map: CoWitnessMap<T::AcvmType>,
}

impl PlainCoSolver<FieldElement> {
    pub fn new(
        opcodes: Vec<Opcode<FieldElement>>,
        initial_witness: CoWitnessMap<FieldElement>,
    ) -> Self {
        let modulus = FieldElement::modulus();
        let one = BigUint::one();
        let two = BigUint::from(2u64);
        // FIXME find something better
        let negative_one = FieldElement::from_be_bytes_reduce(&(modulus / two + one).to_bytes_be());
        Self {
            driver: PlainDriver::new(negative_one),
            opcodes,
            witness_map: initial_witness,
        }
    }
}

impl<T, F> CoSolver<T, F>
where
    T: NoirWitnessExtensionProtocol<F>,
    F: AcirField,
{
    pub fn solve(mut self) -> CoAcvmResult<Vec<T::AcvmType>> {
        let opcodes = std::mem::take(&mut self.opcodes);
        for opcode in opcodes.iter() {
            match opcode {
                Opcode::AssertZero(expr) => self.solve_assert_zero(expr)?,
                _ => todo!("non assert zero opcode detected, not supported yet"),
            }
        }
        // we do not have any unknowns in the CoWitnessMap after we solved everything.
        // Therefore expect is OK.
        Ok(FullWitness::try_from(self.witness_map)
            .expect("must be known at this time")
            .0)
    }
}

#[cfg(test)]
pub mod tests {
    use crate::{solver::PlainCoSolver, types::CoWitnessMap, CO_EXPRESSION_WIDTH};
    use noirc_artifacts::program::ProgramArtifact;
    use std::str::FromStr;

    #[test]
    pub fn test_simple_addition_and_multiplication() {
        let program =
            std::fs::read_to_string("../../test_vectors/noir/addition_multiplication.json")
                .unwrap();

        let program_artifact = serde_json::from_str::<ProgramArtifact>(&program)
            .expect("failed to parse program artifact");
        let (circuit, _) = crate::transform(
            program_artifact.bytecode.functions[0].clone(),
            CO_EXPRESSION_WIDTH,
        );

        let initial_witness =
            CoWitnessMap::read_abi("../../test_vectors/noir/inputs.toml", &program_artifact.abi)
                .unwrap();
        let solver = PlainCoSolver::new(circuit.opcodes, initial_witness);
        let result = solver.solve().unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].into_repr(), ark_bn254::Fr::from_str("1").unwrap());
        assert_eq!(result[1].into_repr(), ark_bn254::Fr::from_str("1").unwrap());
        assert_eq!(
            result[2].into_repr(),
            ark_bn254::Fr::from_str("359").unwrap()
        );
    }
}
