# coSNARKs

[![X (formerly Twitter) Follow](https://img.shields.io/badge/X-%23000000.svg?style=for-the-badge&logo=X&logoColor=white)](https://twitter.com/TACEO_IO)
[![Telegram](https://img.shields.io/badge/Telegram-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/collaborativeSNARK)
[![Discord](https://img.shields.io/badge/Discord-%235865F2.svg?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/gWZW2TANpk)

[![docs.io](https://img.shields.io/badge/coCircom-docs-green)](https://docs.taceo.io/)

<!--[![crates.io](https://img.shields.io/badge/crates.io-v0.1.0-blue)](https://crates.io/)-->

**coCircom** and **coNoir** are tools for building **coSNARKs**, a new technology that enables
multiple distrusting parties to collaboratively compute a **zero-knowledge
proof** (ZKP). They leverage the existing domain-specific languages
[circom](https://github.com/iden3/circom) and [Noir](https://github.com/noir-lang/noir) to define arithmetic circuits. With
coCircom, all existing circom circuits can be promoted to coSNARKs without any
modification to the original circuit.

Additionally, **coCircom** is fully compatible with the **Groth16** and **Plonk** backends of
[snarkjs](https://github.com/iden3/snarkjs), the native proving systems for
circom. Proofs generated with **coCircom** can be verified using snarkjs, and vice
versa.
The same applies to **coNoir**, generated proofs can be verified with Barretenberg, and vice versa.

The project is built with pure Rust and consists of multiple libraries:

- **coCircom**:
  - **co-circom**: The main library that exposes the functionality of **coCircom**.
  - **circom-mpc-vm**: A MPC-VM that executes the circom file in a distributed
    manner (building the extended witness).
  - **circom-mpc-compiler**: A compiler that generates the MPC-VM code from the
    circom file.
  - **circom-types**: A library for serialization and deserialization of snarkjs
    artifacts, such as ZKeys and R1CS files.
  - **co-groth16**: A library for verifying and proving a Groth16
    coSNARK, verifiable by snarkjs.
  - **co-plonk**: A library for verifying and proving a Plonk
    coSNARK, verifiable by snarkjs.
  - **co-circom-types**: A library for the shared types and code of co-plonk and co-groth16.

- **coNoir**:
  - **co-noir**: The main library that exposes the functionality of **coNoir**.
  - **co-acvm**: A MPC version of Noir's ACVM that executes ACIR.
  - **co-brillig**: A MPC version of Noir's Brillig VM that executes unconstrained functions.
  - **co-builder**: A library that transforms the generated shared witness into a shared proving key.
  - **co-ultrahonk**: A MPC version of Aztec's UltraHonk prover, compatible with Barretenberg.
  - **ultrahonk**: A Rust rewrite of Aztec's UltraHonk prover, compatible with Barretenberg.

The following libraries are agnostic to **coCircom**/**coNoir** and will be used in the future
for other coSNARKs:

- **mpc-core**: Implementation of MPC protocols.
- **mpc-net**: Network library for MPC protocols.

The `co-circom` and `co-noir` binaries are CLI tools that use these libraries to build a **coSNARK**.
Both libraries also expose all functionality used by the binaries, so that you can integrate them into your projects.
Check out the [coCircom examples](./co-circom/co-circom/examples) and [coNoir examples](./co-noir/co-noir/examples) to see more.

## Installation

### Prerequisites

1. Install Rust. You can find the instructions
   [here](https://www.rust-lang.org/tools/install).
2. Install the circom ecosystem. You can find the instructions
   [here](https://docs.circom.io/getting-started/installation/).

### Install from Source

- **coCircom**

```bash
cargo install --git https://github.com/TaceoLabs/co-snarks --branch main co-circom
```

- **coNoir**

```bash
cargo install --git https://github.com/TaceoLabs/co-snarks --branch main co-noir
```

### Download Binary from Release

1. You can find the latest release
   [here](https://github.com/TaceoLabs/co-snarks/releases/latest).
2. Download the binary for your operating system.

3. Extract the binary from the archive

```bash
tar xf co-circom-YOUR_ARCHITECTURE.tar.gz
```

4. Make the binary executable (if necessary):

```bash
chmod +x co-circom
```

## Documentation

You can find the documentation of coCircom [here](https://docs.taceo.io/).

## Contributing

If you would like to contribute to the project, please refer to the [contribution page](CONTRIBUTING.md).

## License

This project is licensed under either the [MIT License](LICENSE-MIT) or the
[Apache](LICENSE-APACHE), at your choice.

`SPDX-License-Identifier: Apache-2.0 OR MIT`

Select sub-libraries within this project have different licenses, reflecting
their dependencies on
[circom](https://github.com/iden3/circom?tab=GPL-3.0-1-ov-file).

- **co-circom**: Licensed under [GPL-3.0](LICENSE-GPL) `SPDX-License-Identifier: GPL-3.0-only`.
- **circom-mpc-compiler**: Licensed under [GPL-3.0](LICENSE-GPL) `SPDX-License-Identifier: GPL-3.0-only`.

## Disclaimer

This software is **experimental** and **un-audited**, provided on an "as is" and
"as available" basis. We do **not provide any warranties**, express or implied,
including but not limited to warranties of merchantability or fitness for a
particular purpose. We will **not be liable for any losses, damages, or issues**
arising from the use of this software, whether direct or indirect.

Users are encouraged to exercise caution and conduct their own independent
assessments and testing. **By using this software, you acknowledge and accept
the risks associated with its experimental** nature and **agree that the
developers and contributors are not responsible for any consequences** resulting
from its use.
