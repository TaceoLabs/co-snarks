use acir::native_types::WitnessStack;
use co_acvm::solver::PlainCoSolver;
use co_acvm::solver::ShamirCoSolver;
use itertools::izip;
use mpc_net::local::LocalNetwork;
use noirc_artifacts::program::ProgramArtifact;
use std::path::PathBuf;

use super::add_shamir_acvm_test;

add_shamir_acvm_test!("add3u64");
add_shamir_acvm_test!("addition_multiplication");
add_shamir_acvm_test!("assert");
add_shamir_acvm_test!("if_then");
add_shamir_acvm_test!("negative");
add_shamir_acvm_test!("poseidon");
add_shamir_acvm_test!("poseidon2");
add_shamir_acvm_test!("poseidon_input2");
add_shamir_acvm_test!("poseidon_stdlib");
add_shamir_acvm_test!("unconstrained_fn_field");
add_shamir_acvm_test!("blackbox_poseidon2");
