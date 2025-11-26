# split proving_key into shares
cargo run --release --bin co-noir -- split-proving-key --witness test_vectors/poseidon/poseidon.gz --circuit test_vectors/poseidon/poseidon.json --crs ../../co-noir-common/src/crs/bn254_g1.dat --protocol REP3 --out-dir .
# Create verification key
cargo run --release --bin co-noir -- create-vk --circuit test_vectors/poseidon/poseidon.json --crs ../../co-noir-common/src/crs/bn254_g1.dat --hasher keccak --vk test_vectors/poseidon/verification_key
# run proving in MPC
cargo run --release --bin co-noir -- generate-proof --proving-key proving_key.0.shared --protocol REP3 --hasher keccak --crs ../../co-noir-common/src/crs/bn254_g1.dat --config configs/party1.toml --out proof.0.proof --vk test_vectors/poseidon/verification_key --public-input public_input &
cargo run --release --bin co-noir -- generate-proof --proving-key proving_key.1.shared --protocol REP3 --hasher keccak --crs ../../co-noir-common/src/crs/bn254_g1.dat --config configs/party2.toml --out proof.1.proof --vk test_vectors/poseidon/verification_key &
cargo run --release --bin co-noir -- generate-proof --proving-key proving_key.2.shared --protocol REP3 --hasher keccak --crs ../../co-noir-common/src/crs/bn254_g1.dat --config configs/party3.toml --out proof.2.proof --vk test_vectors/poseidon/verification_key
wait $(jobs -p)
# verify proof
cargo run --release --bin co-noir -- verify --proof proof.0.proof --public-input public_input --vk test_vectors/poseidon/verification_key --hasher keccak --crs ../../co-noir-common/src/crs/bn254_g2.dat
