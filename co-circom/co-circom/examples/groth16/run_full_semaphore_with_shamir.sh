# split input into shares
cargo run --release --bin co-circom -- split-input --circuit test_vectors/semaphore/circuit.circom --input test_vectors/semaphore/input.json --protocol REP3 --curve BN254 --out-dir test_vectors/semaphore --config test_vectors/semaphore/config.toml 
# run witness extension in MPC
cargo run --release --bin co-circom -- generate-witness -O2 --input test_vectors/semaphore/input.json.0.shared --circuit test_vectors/semaphore/circuit.circom --protocol REP3 --curve BN254 --config ../configs/party1.toml --out test_vectors/semaphore/witness.wtns.0.shared &
cargo run --release --bin co-circom -- generate-witness -O2 --input test_vectors/semaphore/input.json.1.shared --circuit test_vectors/semaphore/circuit.circom --protocol REP3 --curve BN254 --config ../configs/party2.toml --out test_vectors/semaphore/witness.wtns.1.shared &
cargo run --release --bin co-circom -- generate-witness -O2 --input test_vectors/semaphore/input.json.2.shared --circuit test_vectors/semaphore/circuit.circom --protocol REP3 --curve BN254 --config ../configs/party3.toml --out test_vectors/semaphore/witness.wtns.2.shared
wait $(jobs -p)
# translate witness from REP3 to SHAMIR
cargo run --release --bin co-circom -- translate-witness --witness test_vectors/semaphore/witness.wtns.0.shared --src-protocol REP3 --target-protocol SHAMIR --curve BN254 --config ../configs/party1.toml --out test_vectors/semaphore/witness.wtns.0.shamir.shared &
cargo run --release --bin co-circom -- translate-witness --witness test_vectors/semaphore/witness.wtns.1.shared --src-protocol REP3 --target-protocol SHAMIR --curve BN254 --config ../configs/party2.toml --out test_vectors/semaphore/witness.wtns.1.shamir.shared &
cargo run --release --bin co-circom -- translate-witness --witness test_vectors/semaphore/witness.wtns.2.shared --src-protocol REP3 --target-protocol SHAMIR --curve BN254 --config ../configs/party3.toml --out test_vectors/semaphore/witness.wtns.2.shamir.shared
wait $(jobs -p)
# run proving in MPC
cargo run --release --bin co-circom -- generate-proof groth16 --witness test_vectors/semaphore/witness.wtns.0.shamir.shared --zkey test_vectors/semaphore/semaphore.zkey --protocol SHAMIR --curve BN254 --config ../configs/party1.toml --out proof.0.json --public-input public_input.json &
cargo run --release --bin co-circom -- generate-proof groth16 --witness test_vectors/semaphore/witness.wtns.1.shamir.shared --zkey test_vectors/semaphore/semaphore.zkey --protocol SHAMIR --curve BN254 --config ../configs/party2.toml --out proof.1.json &
cargo run --release --bin co-circom -- generate-proof groth16 --witness test_vectors/semaphore/witness.wtns.2.shamir.shared --zkey test_vectors/semaphore/semaphore.zkey --protocol SHAMIR --curve BN254 --config ../configs/party3.toml --out proof.2.json
wait $(jobs -p)
# verify proof
cargo run --release --bin co-circom -- verify groth16 --proof proof.2.json --vk test_vectors/semaphore/verification_key.json --public-input public_input.json --curve BN254 --config test_vectors/semaphore/config.toml 
