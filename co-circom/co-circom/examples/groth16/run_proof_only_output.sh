# split input into shares
cargo run --release --bin co-circom -- split-witness --witness test_vectors/output/witness.wtns --num-inputs 3 --protocol REP3 --curve BLS12-377 --out-dir test_vectors/output
# run proving in MPC
cargo run --release --bin co-circom -- generate-proof groth16 --groth16-reduction libsnark --witness test_vectors/output/witness.wtns.0.shared --zkey test_vectors/output/output.pk --matrices test_vectors/output/a.bin,test_vectors/output/b.bin,test_vectors/output/c.bin --protocol REP3 --curve BLS12-377 --config ../configs/party1.toml --out proof.0.json --public-input public_input.json &
cargo run --release --bin co-circom -- generate-proof groth16 --groth16-reduction libsnark --witness test_vectors/output/witness.wtns.1.shared --zkey test_vectors/output/output.pk --matrices test_vectors/output/a.bin,test_vectors/output/b.bin,test_vectors/output/c.bin  --protocol REP3 --curve BLS12-377 --config ../configs/party2.toml --out proof.1.json &
cargo run --release --bin co-circom -- generate-proof groth16 --groth16-reduction libsnark --witness test_vectors/output/witness.wtns.2.shared --zkey test_vectors/output/output.pk --matrices test_vectors/output/a.bin,test_vectors/output/b.bin,test_vectors/output/c.bin --protocol REP3 --curve BLS12-377 --config ../configs/party3.toml --out proof.2.json
wait $(jobs -p)
# verify proof
cargo run --release --bin co-circom -- verify groth16 --proof proof.0.json --vk test_vectors/output/output.vk --public-input public_input.json --curve BLS12-377
