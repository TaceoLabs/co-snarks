# split input into shares
cargo run --release --bin co-circom -- split-input --circuit groth16/test_vectors/poseidon/circuit.circom --input groth16/test_vectors/poseidon/input.json --protocol REP3 --curve BN254 --out-dir groth16/test_vectors/poseidon --config groth16/test_vectors/kyc/config.toml
# run witness extension in MPC
cargo run --release --bin co-circom -- generate-witness --input groth16/test_vectors/poseidon/input.json.0.shared --circuit groth16/test_vectors/poseidon/circuit.circom --protocol REP3 --curve BN254 --config ../configs/party1.toml --out groth16/test_vectors/poseidon/witness.wtns.0.shared &
cargo run --release --bin co-circom -- generate-witness --input groth16/test_vectors/poseidon/input.json.1.shared --circuit groth16/test_vectors/poseidon/circuit.circom --protocol REP3 --curve BN254 --config ../configs/party2.toml --out groth16/test_vectors/poseidon/witness.wtns.1.shared &
cargo run --release --bin co-circom -- generate-witness --input groth16/test_vectors/poseidon/input.json.2.shared --circuit groth16/test_vectors/poseidon/circuit.circom --protocol REP3 --curve BN254 --config ../configs/party3.toml --out groth16/test_vectors/poseidon/witness.wtns.2.shared
# run translation from REP3 to Shamir
cargo run --release --bin co-circom -- translate-witness --witness groth16/test_vectors/poseidon/witness.wtns.0.shared --src-protocol REP3 --target-protocol SHAMIR --curve BN254 --config ../configs/party1.toml --out groth16/test_vectors/poseidon/shamir_witness.wtns.0.shared &
cargo run --release --bin co-circom -- translate-witness --witness groth16/test_vectors/poseidon/witness.wtns.1.shared --src-protocol REP3 --target-protocol SHAMIR --curve BN254 --config ../configs/party2.toml --out groth16/test_vectors/poseidon/shamir_witness.wtns.1.shared &
cargo run --release --bin co-circom -- translate-witness --witness groth16/test_vectors/poseidon/witness.wtns.2.shared --src-protocol REP3 --target-protocol SHAMIR --curve BN254 --config ../configs/party3.toml --out groth16/test_vectors/poseidon/shamir_witness.wtns.2.shared
# run proving in MPC
cargo run --release --bin co-circom -- generate-proof groth16 --witness groth16/test_vectors/poseidon/shamir_witness.wtns.0.shared --zkey groth16/test_vectors/poseidon/poseidon.zkey --protocol SHAMIR --curve BN254 --config ../configs/party1.toml --out proof.0.json --public-input public_input.json &
cargo run --release --bin co-circom -- generate-proof groth16 --witness groth16/test_vectors/poseidon/shamir_witness.wtns.1.shared --zkey groth16/test_vectors/poseidon/poseidon.zkey --protocol SHAMIR --curve BN254 --config ../configs/party2.toml --out proof.1.json &
cargo run --release --bin co-circom -- generate-proof groth16 --witness groth16/test_vectors/poseidon/shamir_witness.wtns.2.shared --zkey groth16/test_vectors/poseidon/poseidon.zkey --protocol SHAMIR --curve BN254 --config ../configs/party3.toml --out proof.2.json
# verify proof
cargo run --release --bin co-circom -- verify groth16 --proof proof.0.json --vk groth16/test_vectors/poseidon/verification_key.json --public-input public_input.json --curve BN254
