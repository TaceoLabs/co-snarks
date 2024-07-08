# split-input

The aim of the `split-input` command is to take a traditional circom `input.json` file and secret-share it to a number of participants.

## Example

```bash
co-circom split-input --circuit test_vectors/poseidon/circuit.circom --link-library test_vectors/poseidon/lib --input test_vectors/poseidon/input.json --protocol REP3 --out-dir test_vectors/poseidon
```

The above command takes the input `test_vectors/poseidon/input.json` for the circom circuit defined in `test_vectors/poseidon/circuit.circom`, with additional required circom library files in `test_vectors/poseidon/lib`, and secret shares them using the `REP3` MPC protocol. This produces 3 shares `input.json.0.shared`, `input.json.1.shared`, `input.json.2.shared` in the output directory.

These shares can be handed to the 3 different MPC parties for the witness generation phase.

## Reference

```txt
$ co-circom split-input --help
Splits a JSON input file into secret shares for use in MPC

Usage: co-circom split-input [OPTIONS] --input <INPUT> --circuit <CIRCUIT> --protocol <PROTOCOL> --out-dir <OUT_DIR>

Options:
      --input <INPUT>                The path to the input JSON file
      --circuit <CIRCUIT>            The path to the circuit file
      --link-library <LINK_LIBRARY>  The path to Circom library files
      --protocol <PROTOCOL>          The MPC protocol to be used [possible values: REP3]
      --out-dir <OUT_DIR>            The path to the (existing) output directory
  -h, --help                         Print help
```
