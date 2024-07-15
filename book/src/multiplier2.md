# Multiplier 2 From Multiple Parties

One of the most compelling applications of co-SNARKs is enabling distrusting
parties to jointly compute a ZK proof for private shared state. This example
illustrates generating a proof for a simple multiplication circuit involving two
parties, each providing inputs.

We reuse the circuit introduced in our [Quick Start](./quick_start.md) guide
[^1].

In this scenario, two input files are needed, one from each party. Both parties
locally split (secret share) their respective inputs and submit them to
computing nodes, which may or may not be part of the input nodes. These nodes
then generate the witness and compute the proof.

To view the necessary steps, execute:

```bash
sh run_full_with_merge.sh
```

To understand the process involved in generating the proof, inspect the relevant
part of the script:

```bash
EXAMPLE_NAME=multiplier2

# split inputs into shares
cargo run --release --bin co-circom -- split-input --circuit test_vectors/$EXAMPLE_NAME/circuit.circom --link-library test_vectors/$EXAMPLE_NAME/lib --input test_vectors/$EXAMPLE_NAME/input0.json --protocol REP3 --curve BN254 --out-dir test_vectors/$EXAMPLE_NAME
cargo run --release --bin co-circom -- split-input --circuit test_vectors/$EXAMPLE_NAME/circuit.circom --link-library test_vectors/$EXAMPLE_NAME/lib --input test_vectors/$EXAMPLE_NAME/input1.json --protocol REP3 --curve BN254 --out-dir test_vectors/$EXAMPLE_NAME
# merge inputs into single input file
cargo run --release --bin co-circom -- merge-input-shares --inputs test_vectors/$EXAMPLE_NAME/input0.json.0.shared --inputs test_vectors/$EXAMPLE_NAME/input1.json.0.shared --protocol REP3 --curve BN254 --out test_vectors/$EXAMPLE_NAME/input.json.0.shared
cargo run --release --bin co-circom -- merge-input-shares --inputs test_vectors/$EXAMPLE_NAME/input0.json.1.shared --inputs test_vectors/$EXAMPLE_NAME/input1.json.1.shared --protocol REP3 --curve BN254 --out test_vectors/$EXAMPLE_NAME/input.json.1.shared
cargo run --release --bin co-circom -- merge-input-shares --inputs test_vectors/$EXAMPLE_NAME/input0.json.2.shared --inputs test_vectors/$EXAMPLE_NAME/input1.json.2.shared --protocol REP3 --curve BN254 --out test_vectors/$EXAMPLE_NAME/input.json.2.shared
```

This sequence illustrates the secret-sharing of inputs by both parties and the
subsequent [merging](./merge-input-shares.md) of these inputs into a single file, executed by the computing
nodes.

[^1]:
    The multiplier circuit designates one of the inputs as public, bypassing
    the need for MPC. Nevertheless, this example is for demonstration purposes only,
    to show the necessary steps for generating a proof in a multi-party scenario.
