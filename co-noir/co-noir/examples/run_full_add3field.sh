# split input into shares
cargo run --release --bin co-noir -- split-input --circuit test_vectors/add3field/add3field.json --input test_vectors/add3field/Prover.toml --protocol REP3 --out-dir test_vectors/add3field
cargo run --release --bin co-noir -- split-input --circuit test_vectors/add3field/add3field.json --input test_vectors/add3field/Prover.toml --protocol REP3 --out-dir test_vectors/add3field
cargo run --release --bin co-noir -- split-input --circuit test_vectors/add3field/add3field.json --input test_vectors/add3field/Prover.toml --protocol REP3 --out-dir test_vectors/add3field
# run witness extension in MPC
cargo run --release --bin co-noir -- generate-witness --input test_vectors/add3field/Prover.toml.0.shared --circuit test_vectors/add3field/add3field.json --protocol REP3 --config configs/party1.toml --out test_vectors/add3field/add3field.gz.0.shared &
cargo run --release --bin co-noir -- generate-witness --input test_vectors/add3field/Prover.toml.1.shared --circuit test_vectors/add3field/add3field.json --protocol REP3 --config configs/party2.toml --out test_vectors/add3field/add3field.gz.1.shared &
cargo run --release --bin co-noir -- generate-witness --input test_vectors/add3field/Prover.toml.2.shared --circuit test_vectors/add3field/add3field.json --protocol REP3 --config configs/party3.toml --out test_vectors/add3field/add3field.gz.2.shared
wait $(jobs -p)
# run proving in MPC
cargo run --release --bin co-noir -- generate-proof --witness test_vectors/add3field/add3field.gz.0.shared --circuit test_vectors/add3field/add3field.json --crs test_vectors/bn254_g1.dat --protocol REP3 --config configs/party1.toml --out add3_fieldproof.0.proof --public-input add3_fieldpublic_input.json &
cargo run --release --bin co-noir -- generate-proof --witness test_vectors/add3field/add3field.gz.1.shared --circuit test_vectors/add3field/add3field.json --crs test_vectors/bn254_g1.dat --protocol REP3 --config configs/party2.toml --out add3_fieldproof.1.proof &
cargo run --release --bin co-noir -- generate-proof --witness test_vectors/add3field/add3field.gz.2.shared --circuit test_vectors/add3field/add3field.json --crs test_vectors/bn254_g1.dat --protocol REP3 --config configs/party3.toml --out add3_fieldproof.2.proof
wait $(jobs -p)
# Create verification key
cargo run --release --bin co-noir -- create-vk --circuit test_vectors/add3field/add3field.json --crs test_vectors/bn254_g1.dat --vk test_vectors/add3field/verification_key_add3_field
# verify proof
cargo run --release --bin co-noir -- verify --proof add3_fieldproof.0.proof --vk test_vectors/add3field/verification_key --crs test_vectors/bn254_g2.dat
