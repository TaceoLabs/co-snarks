# Poseidon

[Poseidon](https://eprint.iacr.org/2019/458.pdf) is a cryptographic hash
function optimized for efficiency in ZK. Circom comes with an
[implementation of Poseidon](https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom)
that can be used in
[your circuits](https://github.com/TaceoLabs/collaborative-circom/blob/main/co-circom/examples/test_vectors/poseidon/circuit.circom).

The Poseidon sponge construction takes inputs from a prime field and produces a
single output element from the same field. In this example, we process two field
elements for the BN-254 curve and condense them into a single element, with both
inputs originating from the same party.

To quickly get started, we provide a bash script that runs the Poseidon circuit
using co-circom. After cloning the repository, navigate to the
`/co-circom/examples` directory and execute the following command:

```bash
sh run_full_poseidon.sh
```

The script will execute all the necessary steps to generate a proof for the
Poseidon circuit. We can inspect the script to understand the steps involved in
generating a proof for the Poseidon circuit.

```bash
# split input into shares
cargo run --release --bin co-circom -- split-input --circuit test_vectors/poseidon/circuit.circom --link-library test_vectors/poseidon/lib --input test_vectors/poseidon/input.json --protocol REP3 --curve BN254 --out-dir test_vectors/poseidon
# run witness extension in MPC
cargo run --release --bin co-circom -- generate-witness --input test_vectors/poseidon/input.json.0.shared --circuit test_vectors/poseidon/circuit.circom --link-library test_vectors/poseidon/lib --protocol REP3 --curve BN254 --config configs/party1.toml --out test_vectors/poseidon/witness.wtns.0.shared &
cargo run --release --bin co-circom -- generate-witness --input test_vectors/poseidon/input.json.1.shared --circuit test_vectors/poseidon/circuit.circom --link-library test_vectors/poseidon/lib --protocol REP3 --curve BN254 --config configs/party2.toml --out test_vectors/poseidon/witness.wtns.1.shared &
cargo run --release --bin co-circom -- generate-witness --input test_vectors/poseidon/input.json.2.shared --circuit test_vectors/poseidon/circuit.circom --link-library test_vectors/poseidon/lib --protocol REP3 --curve BN254 --config configs/party3.toml --out test_vectors/poseidon/witness.wtns.2.shared
# run proving in MPC
cargo run --release --bin co-circom -- generate-proof --witness test_vectors/poseidon/witness.wtns.0.shared --zkey test_vectors/poseidon/poseidon.zkey --protocol REP3 --curve BN254 --config configs/party1.toml --out proof.0.json --public-input public_input.json &
cargo run --release --bin co-circom -- generate-proof --witness test_vectors/poseidon/witness.wtns.1.shared --zkey test_vectors/poseidon/poseidon.zkey --protocol REP3 --curve BN254 --config configs/party2.toml --out proof.1.json &
cargo run --release --bin co-circom -- generate-proof --witness test_vectors/poseidon/witness.wtns.2.shared --zkey test_vectors/poseidon/poseidon.zkey --protocol REP3 --curve BN254 --config configs/party3.toml --out proof.2.json
# verify proof
cargo run --release --bin co-circom -- verify --proof proof.0.json --vk test_vectors/poseidon/verification_key.json --public-input public_input.json --curve BN254
```
