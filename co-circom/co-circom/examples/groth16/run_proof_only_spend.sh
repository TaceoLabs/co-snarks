# split input into shares
cargo run --release --bin co-circom -- split-witness --witness test_vectors/spend/witness.wtns --num-inputs 5 --protocol REP3 --curve BLS12-377 --out-dir test_vectors/spend
# run proving in MPC
cargo run --release --bin co-circom -- generate-proof groth16 --groth16-reduction libsnark --witness test_vectors/spend/witness.wtns.0.shared --zkey test_vectors/spend/spend.pk --matrices test_vectors/spend/a.bin,test_vectors/spend/b.bin,test_vectors/spend/c.bin --protocol REP3 --curve BLS12-377 --config ../configs/party1.toml --out proof.0.json --public-input public_input.json &
cargo run --release --bin co-circom -- generate-proof groth16 --groth16-reduction libsnark --witness test_vectors/spend/witness.wtns.1.shared --zkey test_vectors/spend/spend.pk --matrices test_vectors/spend/a.bin,test_vectors/spend/b.bin,test_vectors/spend/c.bin  --protocol REP3 --curve BLS12-377 --config ../configs/party2.toml --out proof.1.json &
cargo run --release --bin co-circom -- generate-proof groth16 --groth16-reduction libsnark --witness test_vectors/spend/witness.wtns.2.shared --zkey test_vectors/spend/spend.pk --matrices test_vectors/spend/a.bin,test_vectors/spend/b.bin,test_vectors/spend/c.bin --protocol REP3 --curve BLS12-377 --config ../configs/party3.toml --out proof.2.json
wait $(jobs -p)
# verify proof
cargo run --release --bin co-circom -- verify groth16 --proof proof.0.json --vk test_vectors/spend/spend.vk --public-input public_input.json --curve BLS12-377
