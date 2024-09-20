# split input into shares
cargo run --release --bin co-circom -- split-witness --witness groth16/test_vectors/poseidon/witness.wtns --r1cs groth16/test_vectors/poseidon/poseidon.r1cs --protocol SHAMIR --curve BN254 --out-dir groth16/test_vectors/poseidon
# run proving in MPC
cargo run --release --bin co-circom -- generate-proof groth16 --witness groth16/test_vectors/poseidon/witness.wtns.0.shared --zkey groth16/test_vectors/poseidon/poseidon.zkey --protocol SHAMIR --curve BN254 --config ../configs/party1.toml --out proof.0.json --public-input public_input.json &
cargo run --release --bin co-circom -- generate-proof groth16 --witness groth16/test_vectors/poseidon/witness.wtns.1.shared --zkey groth16/test_vectors/poseidon/poseidon.zkey --protocol SHAMIR --curve BN254 --config ../configs/party2.toml --out proof.1.json &
cargo run --release --bin co-circom -- generate-proof groth16 --witness groth16/test_vectors/poseidon/witness.wtns.2.shared --zkey groth16/test_vectors/poseidon/poseidon.zkey --protocol SHAMIR --curve BN254 --config ../configs/party3.toml --out proof.2.json
# verify proof
cargo run --release --bin co-circom -- verify groth16 --proof proof.0.json --vk groth16/test_vectors/poseidon/verification_key.json --public-input public_input.json --curve BN254
