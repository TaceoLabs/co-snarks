# split input into shares
cargo run --release --bin co-circom -- split-input --input test_vectors/poseidon/input.json --protocol bla --out-dir test_vectors/poseidon
# run witness extension in MPC
cargo run --release --bin co-circom -- generate-witness --input test_vectors/poseidon/input.json.0.shared --circuit test_vectors/poseidon/poseidon_hash.circom --link-library test_vectors/poseidon/lib --protocol bla --config configs/party1.toml --out test_vectors/poseidon/witness.wtns.0.shared &
cargo run --release --bin co-circom -- generate-witness --input test_vectors/poseidon/input.json.1.shared --circuit test_vectors/poseidon/poseidon_hash.circom --link-library test_vectors/poseidon/lib --protocol bla --config configs/party2.toml --out test_vectors/poseidon/witness.wtns.1.shared &
cargo run --release --bin co-circom -- generate-witness --input test_vectors/poseidon/input.json.2.shared --circuit test_vectors/poseidon/poseidon_hash.circom --link-library test_vectors/poseidon/lib --protocol bla --config configs/party3.toml --out test_vectors/poseidon/witness.wtns.2.shared
# run proving in MPC
cargo run --release --bin co-circom -- generate-proof --witness test_vectors/poseidon/witness.wtns.0.shared --r1cs test_vectors/poseidon/poseidon.r1cs --zkey test_vectors/poseidon/circuit_0000.zkey --protocol bla --config configs/party1.toml --out proof.0.json &
cargo run --release --bin co-circom -- generate-proof --witness test_vectors/poseidon/witness.wtns.1.shared --r1cs test_vectors/poseidon/poseidon.r1cs --zkey test_vectors/poseidon/circuit_0000.zkey --protocol bla --config configs/party2.toml --out proof.1.json &
cargo run --release --bin co-circom -- generate-proof --witness test_vectors/poseidon/witness.wtns.2.shared --r1cs test_vectors/poseidon/poseidon.r1cs --zkey test_vectors/poseidon/circuit_0000.zkey --protocol bla --config configs/party3.toml --out proof.2.json
# verify proof
cargo run --release --bin co-circom -- verify --proof proof.0.json --vk test_vectors/poseidon/verification_key.json --public-inputs test_vectors/poseidon/witness.wtns.0.shared
