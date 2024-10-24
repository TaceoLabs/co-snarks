use std::thread;

use acir::{native_types::WitnessStack, FieldElement};
use co_acvm::solver::PlainCoSolver;
use co_acvm::solver::Rep3CoSolver;
use itertools::izip;
use noirc_artifacts::program::ProgramArtifact;
use tests::rep3_network::Rep3TestNetwork;

use super::add_rep3_acvm_test;

// basic assert zero tests
add_rep3_acvm_test!("addition_multiplication");
add_rep3_acvm_test!("poseidon");
add_rep3_acvm_test!("poseidon2");
add_rep3_acvm_test!("poseidon_stdlib");

// memory tests
add_rep3_acvm_test!("slice");
add_rep3_acvm_test!("random_access");
add_rep3_acvm_test!("write_access");
