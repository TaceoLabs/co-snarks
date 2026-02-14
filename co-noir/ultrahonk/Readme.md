# UltraHonk

This crate is a rewrite of Atec's UltraHonk prover and verifier in Rust. It is compatible with Barretenberg v3.0.0-nightly.20251104. To get Barretenberg with this version, use the following commands:

```bash
git clone https://github.com/AztecProtocol/aztec-packages.git
cd aztec-packages
git checkout tags/v3.0.0-nightly.20251104
```

To compile Barretenberg, one can use:

```bash
cd barretenberg/cpp
mkdir build
cmake --preset default
cmake --build --preset default --parallel --target bb
```

The prover in this repository, i.e., ``UltraHonk::prove`` in `src/prover.rs`, is compatible with `UltraProver_<UltraFlavor>/UltraProver_<UltraZKFlavor>/UltraProver_<UltraKeccakFlavor>/UltraProver_<UltraKeccakZKFlavor>` in Barretenberg. Similar, the ``UltraHonk::verify`` verifier in `src/verifier.rs` is compatible with `UltraVerifier_<UltraFlavor>/UltraVerifier_<UltraZKFlavor>/UltraVerifier_<UltraKeccakFlavor>/UltraVerifier_<UltraKeccakZKFlavor>` in Barretenberg.

## Usage

For examples and corresponding Barretenberg operations we refer to [this README.md](../co-noir/Readme.md).
