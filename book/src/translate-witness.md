# translate-witness

The aim of the `translate-witness` command is to take a witness file `witness.wtns` generated with one MPC protocol and translate it to a witness file of a different MPC protocol

## Example

```bash
co-circom translate-witness --witness test_vectors/poseidon/witness.wtns --src-protocol REP3 --target-protocol SHAMIR --curve BN254 --config configs/party1.toml --out test_vectors/poseidon/shamir_witness.wtns
```

The above command takes the witness file `test_vectors/poseidon/witness.wtns` which was generated with the source MPC protocol `REP3` and translates it to the witness file `test_vectors/poseidon/shamir_witness.wtns` which is suitable for the target MPC protocol `SHAMIR`. The translation process requires network interaction, thus a [networking config](./network-config.md) is required as well.

## Reference

```txt
$ co-circom translate-witness --help
Translates the witness generated with one MPC protocol to a witness for a different one

Usage: co-circom translate-witness --witness <WITNESS> --src-protocol <SRC_PROTOCOL> --target-protocol <TARGET_PROTOCOL> --curve <CURVE> --config <CONFIG> --out <OUT>

Options:
      --witness <WITNESS>
          The path to the witness share file
      --src-protocol <SRC_PROTOCOL>
          The MPC protocol that was used for the witness generation [possible values: REP3, SHAMIR]
      --target-protocol <TARGET_PROTOCOL>
          The MPC protocol to be used for the proof generation [possible values: REP3, SHAMIR]
      --curve <CURVE>
          The pairing friendly curve to be used [possible values: BN254, BLS12-381]
      --config <CONFIG>
          The path to MPC network configuration file
      --out <OUT>
          The output file where the final witness share is written to
  -h, --help
          Print help
```
