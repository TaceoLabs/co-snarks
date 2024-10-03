# split input into shares
cargo run --release --bin co-noir -- split-input --circuit test_vectors/poseidon/poseidon.json --input test_vectors/poseidon/Prover.toml --protocol REP3 --out-dir test_vectors/poseidon
# run witness extension in MPC
cargo run --release --bin co-noir -- generate-witness --input test_vectors/poseidon/Prover.toml.0.shared --circuit test_vectors/poseidon/poseidon.json --protocol REP3 --config configs/party1.toml --out test_vectors/poseidon/poseidon.gz.0.shared &
cargo run --release --bin co-noir -- generate-witness --input test_vectors/poseidon/Prover.toml.1.shared --circuit test_vectors/poseidon/poseidon.json --protocol REP3 --config configs/party2.toml --out test_vectors/poseidon/poseidon.gz.1.shared &
cargo run --release --bin co-noir -- generate-witness --input test_vectors/poseidon/Prover.toml.2.shared --circuit test_vectors/poseidon/poseidon.json --protocol REP3 --config configs/party3.toml --out test_vectors/poseidon/poseidon.gz.2.shared
# run translation from REP3 to Shamir
cargo run --release --bin co-noir -- translate-witness --witness test_vectors/poseidon/poseidon.gz.0.shared --src-protocol REP3 --target-protocol SHAMIR --config configs/party1.toml --out test_vectors/poseidon/shamir_poseidon.gz.0.shared &
cargo run --release --bin co-noir -- translate-witness --witness test_vectors/poseidon/poseidon.gz.1.shared --src-protocol REP3 --target-protocol SHAMIR --config configs/party2.toml --out test_vectors/poseidon/shamir_poseidon.gz.1.shared &
cargo run --release --bin co-noir -- translate-witness --witness test_vectors/poseidon/poseidon.gz.2.shared --src-protocol REP3 --target-protocol SHAMIR --config configs/party3.toml --out test_vectors/poseidon/shamir_poseidon.gz.2.shared
# run proving in MPC
cargo run --release --bin co-noir -- generate-proof --witness test_vectors/poseidon/shamir_poseidon.gz.0.shared --circuit test_vectors/poseidon/poseidon.json --crs test_vectors/bn254_g1.dat --protocol SHAMIR --config configs/party1.toml --out proof.0.proof --public-input public_input.json &
cargo run --release --bin co-noir -- generate-proof --witness test_vectors/poseidon/shamir_poseidon.gz.1.shared --circuit test_vectors/poseidon/poseidon.json --crs test_vectors/bn254_g1.dat --protocol SHAMIR --config configs/party2.toml --out proof.1.proof &
cargo run --release --bin co-noir -- generate-proof --witness test_vectors/poseidon/shamir_poseidon.gz.2.shared --circuit test_vectors/poseidon/poseidon.json --crs test_vectors/bn254_g1.dat --protocol SHAMIR --config configs/party3.toml --out proof.2.proof
# Create verification key
cargo run --release --bin co-noir -- create-vk --circuit test_vectors/poseidon/poseidon.json --crs test_vectors/bn254_g1.dat --vk test_vectors/poseidon/verification_key
# verify proof
cargo run --release --bin co-noir -- verify --proof proof.0.proof --vk test_vectors/poseidon/verification_key --crs test_vectors/bn254_g2.dat
