# split input into shares
cargo run --release --bin co-noir -- split-witness --witness test_vectors/poseidon/poseidon.gz --circuit test_vectors/poseidon/poseidon.json --protocol SHAMIR --out-dir test_vectors/poseidon
# run proving in MPC
cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/poseidon/poseidon.gz.0.shared --circuit test_vectors/poseidon/poseidon.json --crs test_vectors/bn254_g1.dat --protocol SHAMIR --hasher KECCAK --config configs/party1.toml --out proof.0.proof --public-input public_input &
cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/poseidon/poseidon.gz.1.shared --circuit test_vectors/poseidon/poseidon.json --crs test_vectors/bn254_g1.dat --protocol SHAMIR --hasher KECCAK --config configs/party2.toml --out proof.1.proof &
cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/poseidon/poseidon.gz.2.shared --circuit test_vectors/poseidon/poseidon.json --crs test_vectors/bn254_g1.dat --protocol SHAMIR --hasher KECCAK --config configs/party3.toml --out proof.2.proof
wait $(jobs -p)
# Create verification key
cargo run --release --bin co-noir -- create-vk --circuit test_vectors/poseidon/poseidon.json --crs test_vectors/bn254_g1.dat --hasher KECCAK --vk test_vectors/poseidon/verification_key
# verify proof
cargo run --release --bin co-noir -- verify --proof proof.0.proof --public-input public_input --vk test_vectors/poseidon/verification_key --hasher KECCAK --crs test_vectors/bn254_g2.dat
