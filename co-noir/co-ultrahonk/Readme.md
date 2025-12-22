# UltraHonk

This crate is a MPC version of Atec's UltraHonk prover in Rust. It is compatible with Barretenberg v3.0.0-nightly.20251104. To get Barretenberg with this version, use the following commands:

```bash
git clone https://github.com/AztecProtocol/aztec-packages.git
cd aztec-packages
git checkout tags/v3.0.0-nightly.20251104
```

To compile Barretenberg, one can use:

```bash
cd barretenberg/cpp
bash ./scripts/docker_interactive.sh ubuntu
mkdir build
cd build
cmake --preset clang16 -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
cmake --build .
```

The prover in this repository, i.e., ``UltraHonk::prove`` in `src/prover.rs`, is compatible with `UltraProver_<UltraFlavor>` in Barretenberg. For our Rust version of this prover see `co-snarks/co-noir/ultrahonk`.

Currently, the circuit builder related code in `ollaborative-circom/co-noir/ultrahonk/src/parse/` is only compatible with basic field arithmetic gates from Noir, stay tuned for more features.

## Usage

For examples and corresponding Barretenberg operations we refer to `collaborative-circom/co-noir/co-noir/Readme.md`.
