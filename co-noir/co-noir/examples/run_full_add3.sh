# split input into shares
cargo run --release --bin co-noir -- split-input --circuit test_vectors/add3/add3.json --input test_vectors/add3/Alice.toml --protocol REP3 --out-dir test_vectors/add3
cargo run --release --bin co-noir -- split-input --circuit test_vectors/add3/add3.json --input test_vectors/add3/Bob.toml --protocol REP3 --out-dir test_vectors/add3
cargo run --release --bin co-noir -- split-input --circuit test_vectors/add3/add3.json --input test_vectors/add3/Davina.toml --protocol REP3 --out-dir test_vectors/add3
# merge inputs into single input file
cargo run --release --bin co-noir -- merge-input-shares --inputs test_vectors/add3/Alice.toml.0.shared --inputs test_vectors/add3/Bob.toml.0.shared --inputs test_vectors/add3/Davina.toml.0.shared --protocol REP3 --out test_vectors/add3/Prover.toml.0.shared
cargo run --release --bin co-noir -- merge-input-shares --inputs test_vectors/add3/Alice.toml.2.shared --inputs test_vectors/add3/Bob.toml.2.shared --inputs test_vectors/add3/Davina.toml.2.shared --protocol REP3 --out test_vectors/add3/Prover.toml.2.shared
cargo run --release --bin co-noir -- merge-input-shares --inputs test_vectors/add3/Alice.toml.1.shared --inputs test_vectors/add3/Bob.toml.1.shared --inputs test_vectors/add3/Davina.toml.1.shared --protocol REP3 --out test_vectors/add3/Prover.toml.1.shared
# run witness extension in MPC
cargo run --release --bin co-noir -- generate-witness --input test_vectors/add3/Prover.toml.0.shared --circuit test_vectors/add3/add3.json --protocol REP3 --config configs/party1.toml --out test_vectors/add3/add3.gz.0.shared &
cargo run --release --bin co-noir -- generate-witness --input test_vectors/add3/Prover.toml.1.shared --circuit test_vectors/add3/add3.json --protocol REP3 --config configs/party2.toml --out test_vectors/add3/add3.gz.1.shared &
cargo run --release --bin co-noir -- generate-witness --input test_vectors/add3/Prover.toml.2.shared --circuit test_vectors/add3/add3.json --protocol REP3 --config configs/party3.toml --out test_vectors/add3/add3.gz.2.shared
wait $(jobs -p)
# run proving in MPC
cargo run --release --bin co-noir -- generate-proof --witness test_vectors/add3/add3.gz.0.shared --circuit test_vectors/add3/add3.json --crs test_vectors/bn254_g1.dat --protocol REP3 --hasher KECCAK --config configs/party1.toml --out proof.0.proof --public-input public_input.json &
cargo run --release --bin co-noir -- generate-proof --witness test_vectors/add3/add3.gz.1.shared --circuit test_vectors/add3/add3.json --crs test_vectors/bn254_g1.dat --protocol REP3 --hasher KECCAK --config configs/party2.toml --out proof.1.proof &
cargo run --release --bin co-noir -- generate-proof --witness test_vectors/add3/add3.gz.2.shared --circuit test_vectors/add3/add3.json --crs test_vectors/bn254_g1.dat --protocol REP3 --hasher KECCAK --config configs/party3.toml --out proof.2.proof
wait $(jobs -p)
# Create verification key
cargo run --release --bin co-noir -- create-vk --circuit test_vectors/add3/add3.json --crs test_vectors/bn254_g1.dat --hasher KECCAK --vk test_vectors/add3/verification_key
# verify proof
cargo run --release --bin co-noir -- verify --proof proof.0.proof --vk test_vectors/add3/verification_key --hasher KECCAK --crs test_vectors/bn254_g2.dat
