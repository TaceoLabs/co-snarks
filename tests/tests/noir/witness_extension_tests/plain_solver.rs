use acir::{native_types::WitnessStack, FieldElement};
use co_acvm::solver::PlainCoSolver;
use noirc_artifacts::program::ProgramArtifact;

use super::add_plain_acvm_test;

// bassic assert zero tests
add_plain_acvm_test!("addition_multiplication");
add_plain_acvm_test!("poseidon");
add_plain_acvm_test!("poseidon2");
add_plain_acvm_test!("poseidon_stdlib");

// memory tests
add_plain_acvm_test!("slice");
add_plain_acvm_test!("random_access");
