# split input into shares
cargo run --release --bin co-noir -- split-input --circuit test_vectors/add3u64/add3u64.json --input test_vectors/add3u64/Prover.toml --protocol REP3 --out-dir test_vectors/add3u64
cargo run --release --bin co-noir -- split-input --circuit test_vectors/add3u64/add3u64.json --input test_vectors/add3u64/Prover.toml --protocol REP3 --out-dir test_vectors/add3u64
cargo run --release --bin co-noir -- split-input --circuit test_vectors/add3u64/add3u64.json --input test_vectors/add3u64/Prover.toml --protocol REP3 --out-dir test_vectors/add3u64
# run witness extension in MPC
cargo run --release --bin co-noir -- generate-witness --input test_vectors/add3u64/Prover.toml.0.shared --circuit test_vectors/add3u64/add3u64.json --protocol REP3 --config configs/party1.toml --out test_vectors/add3u64/add3u64.gz.0.shared &
cargo run --release --bin co-noir -- generate-witness --input test_vectors/add3u64/Prover.toml.1.shared --circuit test_vectors/add3u64/add3u64.json --protocol REP3 --config configs/party2.toml --out test_vectors/add3u64/add3u64.gz.1.shared &
cargo run --release --bin co-noir -- generate-witness --input test_vectors/add3u64/Prover.toml.2.shared --circuit test_vectors/add3u64/add3u64.json --protocol REP3 --config configs/party3.toml --out test_vectors/add3u64/add3u64.gz.2.shared
wait $(jobs -p)
# run proving in MPC
cargo run --release --bin co-noir -- generate-proof --witness test_vectors/add3u64/add3u64.gz.0.shared --circuit test_vectors/add3u64/add3u64.json --crs test_vectors/bn254_g1.dat --protocol REP3 --config configs/party1.toml --out add3u64proof.0.proof --public-input public_input.json &
cargo run --release --bin co-noir -- generate-proof --witness test_vectors/add3u64/add3u64.gz.1.shared --circuit test_vectors/add3u64/add3u64.json --crs test_vectors/bn254_g1.dat --protocol REP3 --config configs/party2.toml --out add3u64proof.1.proof &
cargo run --release --bin co-noir -- generate-proof --witness test_vectors/add3u64/add3u64.gz.2.shared --circuit test_vectors/add3u64/add3u64.json --crs test_vectors/bn254_g1.dat --protocol REP3 --config configs/party3.toml --out add3u64proof.2.proof
wait $(jobs -p)
# Create verification key
cargo run --release --bin co-noir -- create-vk --circuit test_vectors/add3u64/add3u64.json --crs test_vectors/bn254_g1.dat --vk test_vectors/add3u64/verification_key
# verify proof
cargo run --release --bin co-noir -- verify --proof add3u64proof.0.proof --vk test_vectors/add3u64/verification_key --crs test_vectors/bn254_g2.dat
