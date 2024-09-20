EXAMPLE_NAME=multiplier2

# split inputs into shares
cargo run --release --bin co-circom -- split-input --circuit groth16/test_vectors/$EXAMPLE_NAME/circuit.circom --input groth16/test_vectors/$EXAMPLE_NAME/input0.json --protocol REP3 --curve BN254 --out-dir groth16/test_vectors/$EXAMPLE_NAME --config groth16/test_vectors/$EXAMPLE_NAME/config.toml  
cargo run --release --bin co-circom -- split-input --circuit groth16/test_vectors/$EXAMPLE_NAME/circuit.circom --input groth16/test_vectors/$EXAMPLE_NAME/input1.json --protocol REP3 --curve BN254 --out-dir groth16/test_vectors/$EXAMPLE_NAME --config groth16/test_vectors/$EXAMPLE_NAME/config.toml 
# merge inputs into single input file
cargo run --release --bin co-circom -- merge-input-shares --inputs groth16/test_vectors/$EXAMPLE_NAME/input0.json.0.shared --inputs groth16/test_vectors/$EXAMPLE_NAME/input1.json.0.shared --protocol REP3 --curve BN254 --out groth16/test_vectors/$EXAMPLE_NAME/input.json.0.shared
cargo run --release --bin co-circom -- merge-input-shares --inputs groth16/test_vectors/$EXAMPLE_NAME/input0.json.1.shared --inputs groth16/test_vectors/$EXAMPLE_NAME/input1.json.1.shared --protocol REP3 --curve BN254 --out groth16/test_vectors/$EXAMPLE_NAME/input.json.1.shared
cargo run --release --bin co-circom -- merge-input-shares --inputs groth16/test_vectors/$EXAMPLE_NAME/input0.json.2.shared --inputs groth16/test_vectors/$EXAMPLE_NAME/input1.json.2.shared --protocol REP3 --curve BN254 --out groth16/test_vectors/$EXAMPLE_NAME/input.json.2.shared
# run witness extension in MPC
cargo run --release --bin co-circom -- generate-witness --input groth16/test_vectors/$EXAMPLE_NAME/input.json.0.shared --circuit groth16/test_vectors/$EXAMPLE_NAME/circuit.circom --protocol REP3 --curve BN254 --config configs/party1.toml --out groth16/test_vectors/$EXAMPLE_NAME/witness.wtns.0.shared &
cargo run --release --bin co-circom -- generate-witness --input groth16/test_vectors/$EXAMPLE_NAME/input.json.1.shared --circuit groth16/test_vectors/$EXAMPLE_NAME/circuit.circom --protocol REP3 --curve BN254 --config configs/party2.toml --out groth16/test_vectors/$EXAMPLE_NAME/witness.wtns.1.shared &
cargo run --release --bin co-circom -- generate-witness --input groth16/test_vectors/$EXAMPLE_NAME/input.json.2.shared --circuit groth16/test_vectors/$EXAMPLE_NAME/circuit.circom --protocol REP3 --curve BN254 --config configs/party3.toml --out groth16/test_vectors/$EXAMPLE_NAME/witness.wtns.2.shared
# run proving in MPC
cargo run --release --bin co-circom -- generate-proof groth16 --witness groth16/test_vectors/$EXAMPLE_NAME/witness.wtns.0.shared --zkey groth16/test_vectors/$EXAMPLE_NAME/$EXAMPLE_NAME.zkey --protocol REP3 --curve BN254 --config configs/party1.toml --out proof.0.json --public-input public_input.json &
cargo run --release --bin co-circom -- generate-proof groth16 --witness groth16/test_vectors/$EXAMPLE_NAME/witness.wtns.1.shared --zkey groth16/test_vectors/$EXAMPLE_NAME/$EXAMPLE_NAME.zkey --protocol REP3 --curve BN254 --config configs/party2.toml --out proof.1.json &
cargo run --release --bin co-circom -- generate-proof groth16 --witness groth16/test_vectors/$EXAMPLE_NAME/witness.wtns.2.shared --zkey groth16/test_vectors/$EXAMPLE_NAME/$EXAMPLE_NAME.zkey --protocol REP3 --curve BN254 --config configs/party3.toml --out proof.2.json
# verify proof
cargo run --release --bin co-circom -- verify groth16 --proof proof.0.json --vk groth16/test_vectors/$EXAMPLE_NAME/verification_key.json --public-input public_input.json --curve BN254
