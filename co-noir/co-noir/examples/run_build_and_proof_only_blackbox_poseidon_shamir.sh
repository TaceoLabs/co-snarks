# split input into shares
cargo run --release --bin co-noir -- split-witness --witness test_vectors/blackbox_poseidon2/blackbox_poseidon2.gz --circuit test_vectors/blackbox_poseidon2/blackbox_poseidon2.json --protocol SHAMIR --out-dir test_vectors/blackbox_poseidon2
# run proving in MPC
cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/blackbox_poseidon2/blackbox_poseidon2.gz.0.shared --circuit test_vectors/blackbox_poseidon2/blackbox_poseidon2.json --crs test_vectors/bn254_g1.dat --protocol SHAMIR --hasher keccak --config configs/party1.toml --out proof.0.proof --public-input public_input &
cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/blackbox_poseidon2/blackbox_poseidon2.gz.1.shared --circuit test_vectors/blackbox_poseidon2/blackbox_poseidon2.json --crs test_vectors/bn254_g1.dat --protocol SHAMIR --hasher keccak --config configs/party2.toml --out proof.1.proof &
cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/blackbox_poseidon2/blackbox_poseidon2.gz.2.shared --circuit test_vectors/blackbox_poseidon2/blackbox_poseidon2.json --crs test_vectors/bn254_g1.dat --protocol SHAMIR --hasher keccak --config configs/party3.toml --out proof.2.proof
wait $(jobs -p)
# Create verification key
cargo run --release --bin co-noir -- create-vk --circuit test_vectors/blackbox_poseidon2/blackbox_poseidon2.json --crs test_vectors/bn254_g1.dat --hasher keccak --vk test_vectors/blackbox_poseidon2/verification_key
# verify proof
cargo run --release --bin co-noir -- verify --proof proof.0.proof --public-input public_input --vk test_vectors/blackbox_poseidon2/verification_key --hasher keccak --crs test_vectors/bn254_g2.dat
