use std::thread;

use acir::{native_types::WitnessStack, FieldElement};
use ark_bn254::Bn254;
use co_acvm::solver::PlainCoSolver;
use co_acvm::solver::Rep3CoSolver;
use itertools::izip;
use noirc_artifacts::program::ProgramArtifact;
use std::path::PathBuf;
use tests::rep3_network::PartyTestNetwork;
use tests::rep3_network::Rep3TestNetwork;

use super::add_rep3_acvm_test;

add_rep3_acvm_test!("add3u64");
add_rep3_acvm_test!("addition_multiplication");
add_rep3_acvm_test!("approx_sigmoid");
add_rep3_acvm_test!("assert");
add_rep3_acvm_test!("get_bytes");
add_rep3_acvm_test!("if_then");
add_rep3_acvm_test!("negative");
add_rep3_acvm_test!("poseidon");
add_rep3_acvm_test!("poseidon2");
add_rep3_acvm_test!("poseidon_assert");
add_rep3_acvm_test!("poseidon_input2");
add_rep3_acvm_test!("poseidon_stdlib");
add_rep3_acvm_test!("quantized");
add_rep3_acvm_test!("random_access");
add_rep3_acvm_test!("slice");
add_rep3_acvm_test!("to_radix32");
add_rep3_acvm_test!("unconstrained_fn");
add_rep3_acvm_test!("unconstrained_fn_field");
add_rep3_acvm_test!("write_access");
