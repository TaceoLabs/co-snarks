# split input into shares
cargo run --release --bin co-noir -- split-witness --witness test_vectors/poseidon/poseidon.gz --circuit test_vectors/poseidon/poseidon.json --protocol REP3 --out-dir test_vectors/poseidon
# run proving in MPC
cargo run --release --bin co-noir -- generate-proof --witness test_vectors/poseidon/witness.wtns.0.shared --protocol REP3 --config configs/party1.toml --out proof.0.json &
cargo run --release --bin co-noir -- generate-proof --witness test_vectors/poseidon/witness.wtns.1.shared --protocol REP3 --config configs/party2.toml --out proof.1.json &
cargo run --release --bin co-noir -- generate-proof --witness test_vectors/poseidon/witness.wtns.2.shared --protocol REP3 --config configs/party3.toml --out proof.2.json
# verify proof
# cargo run --release --bin co-circom -- verify groth16 --proof proof.0.json --vk test_vectors/poseidon/verification_key.json --public-input public_input.json --curve BN254
