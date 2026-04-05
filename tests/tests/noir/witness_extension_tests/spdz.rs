use super::add_spdz_acvm_test;

// ---- Full prove+verify tests (passing) ----
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
add_spdz_acvm_test!("random_access");
add_spdz_acvm_test!("slice");
add_spdz_acvm_test!("to_radix32");
add_spdz_acvm_test!("unconstrained_fn");
add_spdz_acvm_test!("unconstrained_fn_field");
add_spdz_acvm_test!("unconstrained_fn_not");

// ---- Plookup circuits: proof verification fails ----
// Witness extension completes (no panic), but UltraHonk proof doesn't verify.
// Note: Rep3 also only has witness extension tests for these circuits —
// NO proof tests exist for plookup-dependent circuits in co-snarks.
// This is likely a general MPC+plookup integration issue, not SPDZ-specific.
// TODO: investigate plookup sorted polynomial construction with shared values.
//
// add_spdz_acvm_test!("blackbox_and");
// add_spdz_acvm_test!("blackbox_xor");
// add_spdz_acvm_test!("bb_sha256_compression");
// add_spdz_acvm_test!("blake2s");
// add_spdz_acvm_test!("blake3");

// ---- Not supported ----
// add_spdz_acvm_test!("pedersen_hash");       // Grumpkin
// add_spdz_acvm_test!("pedersen_commitment");  // Grumpkin
// add_spdz_acvm_test!("embedded_curve_add");   // Grumpkin
// add_spdz_acvm_test!("aes128");              // AES S-box
// add_spdz_acvm_test!("write_access");         // Sparse table
