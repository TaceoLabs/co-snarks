# verify

The aim of the `verify` command is to verify a Groth16 Circom proof using the provided verification key and public inputs.

## Example

```bash
co-circom verify --proof proof.json --vk test_vectors/multiplier2/verification_key.json --public-input public_input.json
```

The above command verifies the proof in `proof.json` using the verification key `test_vectors/multiplier2/verification_key.json` and public input `public_input.json`.

## Reference

```txt
co-circom verify --help`
Verification of a Circom proof

Usage: co-circom verify --proof <PROOF> --vk <VK> --public-input <PUBLIC_INPUT>

Options:
      --proof <PROOF>                The path to the proof file
      --vk <VK>                      The path to the verification key file
      --public-input <PUBLIC_INPUT>  The path to the public input JSON file
  -h, --help                         Print help
```