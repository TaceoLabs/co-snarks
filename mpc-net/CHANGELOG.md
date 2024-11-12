# Changelog

## [0.2.0](https://github.com/TaceoLabs/co-snarks/compare/mpc-net-v0.1.2...mpc-net-v0.2.0) (2024-11-12)


### ⚠ BREAKING CHANGES

* MpcNetworkHandler::establish now takes the config with already read certs and key.
* Refactor to better handle new networking with forks

### Bug Fixes

* add gracefull shutdown ensure all data received from the quinn stack ([a9cbcbf](https://github.com/TaceoLabs/co-snarks/commit/a9cbcbf8a5fa00f01c94cd80eae45cbf7f65390f))
* fixed read task breaking too early, caused error during proof gen ([6a8e829](https://github.com/TaceoLabs/co-snarks/commit/6a8e82913b88414ee05a7159fbd390a32db70b9d))
* install rustls default crypto provider in our main binaries & examples ([#238](https://github.com/TaceoLabs/co-snarks/issues/238)) ([78757e4](https://github.com/TaceoLabs/co-snarks/commit/78757e46d8622360377d27c5d475d417bed95c5a))
* now quinn server timeouts after 60 seconds ([#256](https://github.com/TaceoLabs/co-snarks/issues/256)) ([cbc5905](https://github.com/TaceoLabs/co-snarks/commit/cbc5905a2a704bdcca3b9fed1a5fea7a95b4b6b5))


### Code Refactoring

* Refactor to better handle new networking with forks ([ce8fef9](https://github.com/TaceoLabs/co-snarks/commit/ce8fef922327db1e0d87b0546dd089100edf643f))
* split network config into two types ([dca1756](https://github.com/TaceoLabs/co-snarks/commit/dca175603a5d6a2f75ccd987cb0b19cc3d965b00))

## [0.1.2](https://github.com/TaceoLabs/collaborative-circom/compare/mpc-net-v0.1.1...mpc-net-v0.1.2) (2024-07-10)


### Bug Fixes

* better handling of ipv4 and ipv6 in networking ([#119](https://github.com/TaceoLabs/collaborative-circom/issues/119)) ([090227d](https://github.com/TaceoLabs/collaborative-circom/commit/090227d372215e9459c06777064b04ec4865bdb6))

## [0.1.1](https://github.com/TaceoLabs/collaborative-circom/compare/mpc-net-v0.1.0...mpc-net-v0.1.1) (2024-07-09)


### Bug Fixes

* allow frames of 1GB per default ([57b09af](https://github.com/TaceoLabs/collaborative-circom/commit/57b09afd8b858dfd803c8f0bbb51a47d549fa8e7))

## [0.1.0](https://github.com/TaceoLabs/collaborative-circom/compare/mpc-net-v0.0.1...mpc-net-v0.1.0) (2024-06-14)


### Features

* added skeleton for mpc/collab-groth16 ([#12](https://github.com/TaceoLabs/collaborative-circom/issues/12)) ([9c03331](https://github.com/TaceoLabs/collaborative-circom/commit/9c03331171429f061ead8cddda292cd97d498f1a))
* first version of command line interface ([#36](https://github.com/TaceoLabs/collaborative-circom/issues/36)) ([6abe716](https://github.com/TaceoLabs/collaborative-circom/commit/6abe716268f1e165cdae07a10f4d2dafd010cc04))
* integrate witness extension via MPC VM into CLI binary ([f526081](https://github.com/TaceoLabs/collaborative-circom/commit/f526081a01e3faa6b48fb463f3690f968218a1a4))


### Bug Fixes

* eddsa_verify does work now ([#29](https://github.com/TaceoLabs/collaborative-circom/issues/29)) ([1ab0a80](https://github.com/TaceoLabs/collaborative-circom/commit/1ab0a806b8a9f32d2783ce9838826fe71a48d78f))
