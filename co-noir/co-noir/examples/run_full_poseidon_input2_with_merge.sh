# split input into shares
cargo run --release --bin co-noir -- split-input --circuit test_vectors/poseidon_input2/poseidon_input2.json --input test_vectors/poseidon_input2/Prover1.toml --protocol REP3 --out-dir test_vectors/poseidon_input2
cargo run --release --bin co-noir -- split-input --circuit test_vectors/poseidon_input2/poseidon_input2.json --input test_vectors/poseidon_input2/Prover2.toml --protocol REP3 --out-dir test_vectors/poseidon_input2
# merge inputs into single input file
cargo run --release --bin co-noir -- merge-input-shares --circuit test_vectors/poseidon_input2/poseidon_input2.json --inputs test_vectors/poseidon_input2/Prover1.toml.0.shared --inputs test_vectors/poseidon_input2/Prover2.toml.0.shared --protocol REP3 --out test_vectors/poseidon_input2/Prover.toml.0.shared
cargo run --release --bin co-noir -- merge-input-shares --circuit test_vectors/poseidon_input2/poseidon_input2.json --inputs test_vectors/poseidon_input2/Prover1.toml.1.shared --inputs test_vectors/poseidon_input2/Prover2.toml.1.shared --protocol REP3 --out test_vectors/poseidon_input2/Prover.toml.1.shared
cargo run --release --bin co-noir -- merge-input-shares --circuit test_vectors/poseidon_input2/poseidon_input2.json --inputs test_vectors/poseidon_input2/Prover1.toml.2.shared --inputs test_vectors/poseidon_input2/Prover2.toml.2.shared --protocol REP3 --out test_vectors/poseidon_input2/Prover.toml.2.shared
# run witness extension in MPC
cargo run --release --bin co-noir -- generate-witness --input test_vectors/poseidon_input2/Prover.toml.0.shared --circuit test_vectors/poseidon_input2/poseidon_input2.json --protocol REP3 --config configs/party1.toml --out test_vectors/poseidon_input2/poseidon_input2.gz.0.shared &
cargo run --release --bin co-noir -- generate-witness --input test_vectors/poseidon_input2/Prover.toml.1.shared --circuit test_vectors/poseidon_input2/poseidon_input2.json --protocol REP3 --config configs/party2.toml --out test_vectors/poseidon_input2/poseidon_input2.gz.1.shared &
cargo run --release --bin co-noir -- generate-witness --input test_vectors/poseidon_input2/Prover.toml.2.shared --circuit test_vectors/poseidon_input2/poseidon_input2.json --protocol REP3 --config configs/party3.toml --out test_vectors/poseidon_input2/poseidon_input2.gz.2.shared
wait $(jobs -p)
# run proving in MPC
cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/poseidon_input2/poseidon_input2.gz.0.shared --circuit test_vectors/poseidon_input2/poseidon_input2.json --crs test_vectors/bn254_g1.dat --protocol REP3 --hasher keccak --config configs/party1.toml --out proof.0.proof --public-input public_input &
cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/poseidon_input2/poseidon_input2.gz.1.shared --circuit test_vectors/poseidon_input2/poseidon_input2.json --crs test_vectors/bn254_g1.dat --protocol REP3 --hasher keccak --config configs/party2.toml --out proof.1.proof &
cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/poseidon_input2/poseidon_input2.gz.2.shared --circuit test_vectors/poseidon_input2/poseidon_input2.json --crs test_vectors/bn254_g1.dat --protocol REP3 --hasher keccak --config configs/party3.toml --out proof.2.proof
wait $(jobs -p)
# Create verification key
cargo run --release --bin co-noir -- create-vk --circuit test_vectors/poseidon_input2/poseidon_input2.json --crs test_vectors/bn254_g1.dat --hasher keccak --vk test_vectors/poseidon_input2/verification_key
# verify proof
cargo run --release --bin co-noir -- verify --proof proof.0.proof --public-input public_input --vk test_vectors/poseidon_input2/verification_key --hasher keccak --crs test_vectors/bn254_g2.dat
