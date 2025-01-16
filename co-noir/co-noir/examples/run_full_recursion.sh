# split input into shares
# cargo run --release --bin co-noir -- split-input --circuit test_vectors/recursion/recursion.json --input test_vectors/recursion/Prover.toml --protocol REP3 --out-dir test_vectors/recursion
# # run witness extension in MPC
# cargo run --release --bin co-noir -- generate-witness --input test_vectors/recursion/Prover.toml.0.shared --circuit test_vectors/recursion/recursion.json --protocol REP3 --config configs/party1.toml --out test_vectors/recursion/recursion.gz.0.shared &
# cargo run --release --bin co-noir -- generate-witness --input test_vectors/recursion/Prover.toml.1.shared --circuit test_vectors/recursion/recursion.json --protocol REP3 --config configs/party2.toml --out test_vectors/recursion/recursion.gz.1.shared &
# cargo run --release --bin co-noir -- generate-witness --input test_vectors/recursion/Prover.toml.2.shared --circuit test_vectors/recursion/recursion.json --protocol REP3 --config configs/party3.toml --out test_vectors/recursion/recursion.gz.2.shared
# wait $(jobs -p)
# # run proving in MPC
# cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/recursion/recursion.gz.0.shared --circuit test_vectors/recursion/recursion.json --crs test_vectors/bn254_g1.dat --protocol REP3 --hasher POSEIDON --config configs/party1.toml --out proof.0.proof --recursive --public-input public_input.json &
# cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/recursion/recursion.gz.1.shared --circuit test_vectors/recursion/recursion.json --crs test_vectors/bn254_g1.dat --protocol REP3 --hasher POSEIDON --config configs/party2.toml --out proof.1.proof --recursive &
# cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/recursion/recursion.gz.2.shared --circuit test_vectors/recursion/recursion.json --crs test_vectors/bn254_g1.dat --protocol REP3 --hasher POSEIDON --config configs/party3.toml --out proof.2.proof --recursive
# wait $(jobs -p)
# Create verification key
cargo run --release --bin co-noir -- create-vk --circuit test_vectors/recursion/recursion.json --crs test_vectors/bn254_g1.dat --hasher POSEIDON --vk test_vectors/recursion/verification_key --recursive
# verify proof
cargo run --release --bin co-noir -- verify --proof proof.0.proof --vk test_vectors/recursion/verification_key --hasher POSEIDON --crs test_vectors/bn254_g2.dat

