# generate-witness

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
