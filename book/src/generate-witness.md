# generate-witness

The aim of the `generate-witness` command is to generate a secret-shared witness file in MPC using secret shares of the input.

## Example

```bash
co-circom generate-witness --input test_vectors/poseidon/input.json.0.shared --circuit test_vectors/poseidon/circuit.circom --link-library test_vectors/poseidon/lib --protocol REP3 --config configs/party1.toml --out test_vectors/poseidon/witness.wtns.0.shared
```

The above command takes a shared input file `input.json.0.shared` for the circuit `circuit.circom` with required circom library files in `test_vectors/poseidon/lib`  with the [network config](./network-config.md) and outputs the witness share to `test_vectors/poseidon/witness.wtns.0.shared`.

## Reference

```txt
$ co-circom generate-witness --help
Evaluates the extended witness generation for the specified circuit and input share in MPC

Usage: co-circom generate-witness [OPTIONS] --input <INPUT> --circuit <CIRCUIT> --protocol <PROTOCOL> --config <CONFIG> --out <OUT>

Options:
      --input <INPUT>                The path to the input share file
      --circuit <CIRCUIT>            The path to the circuit file
      --link-library <LINK_LIBRARY>  The path to Circom library files
      --protocol <PROTOCOL>          The MPC protocol to be used [possible values: REP3]
      --config <CONFIG>              The path to MPC network configuration file
      --out <OUT>                    The output file where the final witness share is written to
  -h, --help                         Print help
```
