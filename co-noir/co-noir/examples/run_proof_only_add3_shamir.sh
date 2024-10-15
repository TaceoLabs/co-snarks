# split input into shares
cargo run --release --bin co-noir -- split-witness --witness test_vectors/add3/add3.gz --circuit test_vectors/add3/add3.json --protocol SHAMIR --out-dir test_vectors/add3
# run proving in MPC
cargo run --release --bin co-noir -- generate-proof --witness test_vectors/add3/add3.gz.0.shared --circuit test_vectors/add3/add3.json --crs test_vectors/bn254_g1.dat --protocol SHAMIR --config configs/party1.toml --out proof.0.proof --public-input public_input.json &
cargo run --release --bin co-noir -- generate-proof --witness test_vectors/add3/add3.gz.1.shared --circuit test_vectors/add3/add3.json --crs test_vectors/bn254_g1.dat --protocol SHAMIR --config configs/party2.toml --out proof.1.proof &
cargo run --release --bin co-noir -- generate-proof --witness test_vectors/add3/add3.gz.2.shared --circuit test_vectors/add3/add3.json --crs test_vectors/bn254_g1.dat --protocol SHAMIR --config configs/party3.toml --out proof.2.proof
wait $(jobs -p)
# Create verification key
cargo run --release --bin co-noir -- create-vk --circuit test_vectors/add3/add3.json --crs test_vectors/bn254_g1.dat --vk test_vectors/add3/verification_key
# verify proof
cargo run --release --bin co-noir -- verify --proof proof.0.proof --vk test_vectors/add3/verification_key --crs test_vectors/bn254_g2.dat
