use super::add_spdz_acvm_test;

// ---- PASSING: Core arithmetic, control flow, Poseidon2 ----
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

// ---- KNOWN FAILURES: plookup table panic in builder ----
// These circuits use lookup tables (AND/XOR gates, SHA256/Blake round functions).
// Witness extension works, but the UltraHonk builder panics at plookup.rs:1790
// when constructing the proving key with SPDZ shares.
// TODO: investigate plookup compatibility with SPDZ share types.
//
// add_spdz_acvm_test!("blackbox_and");
// add_spdz_acvm_test!("blackbox_xor");
// add_spdz_acvm_test!("bb_sha256_compression");
// add_spdz_acvm_test!("blake2s");
// add_spdz_acvm_test!("blake3");

// ---- NOT SUPPORTED: Grumpkin / AES / sparse tables ----
// add_spdz_acvm_test!("pedersen_hash");
// add_spdz_acvm_test!("pedersen_commitment");
// add_spdz_acvm_test!("embedded_curve_add");
// add_spdz_acvm_test!("aes128");
// add_spdz_acvm_test!("write_access");
