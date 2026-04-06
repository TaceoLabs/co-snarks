use super::{add_spdz_acvm_test, add_spdz_acvm_test_zk, add_spdz_acvm_test_poseidon2, spdz_prove_verify_test};

// ================================================================
// Keccak256 transcript, no ZK (baseline — matches dark chess setup)
// ================================================================
add_spdz_acvm_test!("add3u64");
add_spdz_acvm_test!("addition_multiplication");
add_spdz_acvm_test!("approx_sigmoid");
add_spdz_acvm_test!("assert");
add_spdz_acvm_test!("get_bytes");
add_spdz_acvm_test!("if_then");
add_spdz_acvm_test!("mul_shared");
add_spdz_acvm_test!("negative");
add_spdz_acvm_test!("poseidon");
add_spdz_acvm_test!("poseidon2");
add_spdz_acvm_test!("poseidon_assert");
add_spdz_acvm_test!("poseidon_input2");
add_spdz_acvm_test!("poseidon_stdlib");
add_spdz_acvm_test!("quantized");
// random_access: uses plookup for shared-index array access (a[x as u32])
// Proof verification fails — same root cause as blackbox_and/xor/blake.
// add_spdz_acvm_test!("random_access");
add_spdz_acvm_test!("slice");
add_spdz_acvm_test!("to_radix32");
add_spdz_acvm_test!("unconstrained_fn");
add_spdz_acvm_test!("unconstrained_fn_field");
add_spdz_acvm_test!("unconstrained_fn_not");

// ================================================================
// ZeroKnowledge mode (Keccak256) — tests ZK masking with SPDZ shares
// Note: these tests may fail when run in parallel with other SPDZ tests
// due to LocalNetwork timeout under CPU contention. Run with:
//   cargo test -p tests --release test_spdz_zk -- --test-threads=1
// ================================================================
add_spdz_acvm_test_zk!("addition_multiplication");
add_spdz_acvm_test_zk!("poseidon2");
add_spdz_acvm_test_zk!("mul_shared");

// ================================================================
// Poseidon2Sponge transcript — tests alternative Fiat-Shamir hasher
// ================================================================
add_spdz_acvm_test_poseidon2!("addition_multiplication");
add_spdz_acvm_test_poseidon2!("poseidon2");
add_spdz_acvm_test_poseidon2!("mul_shared");

// ================================================================
// Recursion — verifies a proof inside the circuit
// Requires non-native field arithmetic (limb ops) on shared values,
// which is not implemented (same as Rep3). Rep3's proof test passes
// because their Brillig VM handles the intermediate values differently.
// TODO: implement shared limb arithmetic or handle recursion specially.
// ================================================================
// add_spdz_acvm_test!("recursion");

// ================================================================
// Plookup circuits — proof verification fails (not SPDZ-specific,
// Rep3 also has no proof tests for these). See commit f44eaa76.
// ================================================================
// add_spdz_acvm_test!("blackbox_and");
// add_spdz_acvm_test!("blackbox_xor");
// add_spdz_acvm_test!("bb_sha256_compression");
// blake2s: GC evaluation works (hash is correct), but proof verification
// fails due to plookup sorted polynomial issue (same as blackbox_and/xor).
// The GC computes correct values but the Noir circuit's ACIR uses plookup
// gates internally for XOR operations.
// add_spdz_acvm_test!("blake2s");
// add_spdz_acvm_test!("blake3");

// ================================================================
// Not supported (Grumpkin/AES/sparse tables)
// ================================================================
// add_spdz_acvm_test!("pedersen_hash");
// add_spdz_acvm_test!("pedersen_commitment");
// add_spdz_acvm_test!("embedded_curve_add");
// add_spdz_acvm_test!("aes128");
// add_spdz_acvm_test!("write_access");
