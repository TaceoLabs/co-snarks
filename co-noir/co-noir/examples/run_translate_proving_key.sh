# split proving_key into shares
cargo run --release --bin co-noir -- split-proving-key --witness test_vectors/poseidon/poseidon.gz --circuit test_vectors/poseidon/poseidon.json --crs test_vectors/bn254_g1.dat --protocol REP3 --out-dir .
# run translation from REP3 to Shamir
cargo run --release --bin co-noir -- translate-proving-key --proving-key proving_key.0.shared --src-protocol REP3 --target-protocol SHAMIR --config configs/party1.toml --out shamir_proving_key.0.shared &
cargo run --release --bin co-noir -- translate-proving-key --proving-key proving_key.1.shared --src-protocol REP3 --target-protocol SHAMIR --config configs/party2.toml --out shamir_proving_key.1.shared &
cargo run --release --bin co-noir -- translate-proving-key --proving-key proving_key.2.shared --src-protocol REP3 --target-protocol SHAMIR --config configs/party3.toml --out shamir_proving_key.2.shared
wait $(jobs -p)
# run proving in MPC
cargo run --release --bin co-noir -- generate-proof --proving-key shamir_proving_key.0.shared --protocol SHAMIR --hasher KECCAK --crs test_vectors/bn254_g1.dat --config configs/party1.toml --out proof.0.proof --public-input public_input &
cargo run --release --bin co-noir -- generate-proof --proving-key shamir_proving_key.1.shared --protocol SHAMIR --hasher KECCAK --crs test_vectors/bn254_g1.dat --config configs/party2.toml --out proof.1.proof &
cargo run --release --bin co-noir -- generate-proof --proving-key shamir_proving_key.2.shared --protocol SHAMIR --hasher KECCAK --crs test_vectors/bn254_g1.dat --config configs/party3.toml --out proof.2.proof
wait $(jobs -p)
# Create verification key
cargo run --release --bin co-noir -- create-vk --circuit test_vectors/poseidon/poseidon.json --crs test_vectors/bn254_g1.dat --hasher KECCAK --vk test_vectors/poseidon/verification_key
# verify proof
cargo run --release --bin co-noir -- verify --proof proof.0.proof --public-input public_input --vk test_vectors/poseidon/verification_key --hasher KECCAK --crs test_vectors/bn254_g2.dat
