use acir::{native_types::WitnessStack, FieldElement};
use co_acvm::solver::PlainCoSolver;
use noirc_artifacts::program::ProgramArtifact;

use super::add_plain_acvm_test;

add_plain_acvm_test!("add3u64");
add_plain_acvm_test!("addition_multiplication");
add_plain_acvm_test!("approx_sigmoid");
add_plain_acvm_test!("assert");
add_plain_acvm_test!("get_bytes");
add_plain_acvm_test!("if_then");
add_plain_acvm_test!("negative");
add_plain_acvm_test!("poseidon");
add_plain_acvm_test!("poseidon2");
add_plain_acvm_test!("poseidon_assert");
add_plain_acvm_test!("poseidon_input2");
add_plain_acvm_test!("poseidon_stdlib");
add_plain_acvm_test!("quantized");
add_plain_acvm_test!("random_access");
add_plain_acvm_test!("slice");
add_plain_acvm_test!("to_radix32");
add_plain_acvm_test!("unconstrained_fn");
add_plain_acvm_test!("unconstrained_fn_field");
add_plain_acvm_test!("write_access");
add_plain_acvm_test!("bb_sha256_compression");
