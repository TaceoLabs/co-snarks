EXAMPLE_NAME=multiplier2

cargo run --release --bin co-circom -- split-witness --witness test_vectors/$EXAMPLE_NAME/witness.wtns --r1cs test_vectors/$EXAMPLE_NAME/$EXAMPLE_NAME.r1cs --protocol bla --out-dir test_vectors/$EXAMPLE_NAME
cargo run --release --bin co-circom -- generate-proof --witness test_vectors/$EXAMPLE_NAME/witness.wtns.0.shared --zkey test_vectors/$EXAMPLE_NAME/$EXAMPLE_NAME.zkey --protocol bla --config configs/party1.toml --out proof.0.json --public-input public_input.json &
cargo run --release --bin co-circom -- generate-proof --witness test_vectors/$EXAMPLE_NAME/witness.wtns.1.shared --zkey test_vectors/$EXAMPLE_NAME/$EXAMPLE_NAME.zkey --protocol bla --config configs/party2.toml --out proof.1.json &
cargo run --release --bin co-circom -- generate-proof --witness test_vectors/$EXAMPLE_NAME/witness.wtns.2.shared --zkey test_vectors/$EXAMPLE_NAME/$EXAMPLE_NAME.zkey --protocol bla --config configs/party3.toml --out proof.2.json
cargo run --release --bin co-circom -- verify --proof proof.0.json --vk test_vectors/$EXAMPLE_NAME/verification_key.json --public-input public_input.json
