use acir::{native_types::WitnessStack, FieldElement};
use co_acvm::solver::PlainCoSolver;
use noirc_artifacts::program::ProgramArtifact;

use super::add_plain_acvm_test;

add_plain_acvm_test!("addition_multiplication");
add_plain_acvm_test!("poseidon");
add_plain_acvm_test!("poseidon2");
add_plain_acvm_test!("poseidon_stdlib");
