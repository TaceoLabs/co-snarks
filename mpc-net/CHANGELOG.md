# Changelog

## [0.5.0](https://github.com/TaceoLabs/co-snarks/compare/mpc-net-v0.4.0...mpc-net-v0.5.0) (2025-11-06)


### ⚠ BREAKING CHANGES

* rework MPC trait to return unified connection stats struct
* unify MPC networks, split protocol state and networking to allow fork of state without network, replace io::Error with eyre, merge mpc-core and mpc-types with feature gated mpc-net

### Features

* allow to specify timeouts for the testnetwork ([e835dfc](https://github.com/TaceoLabs/co-snarks/commit/e835dfcfd086a2d03ae9b9d84c1fe416ed961568))
* dont use rayon::join for networking - added std::thread::scope based join functions ([758b069](https://github.com/TaceoLabs/co-snarks/commit/758b0699ad0ef7bca7401afe9063848eb084873f))
* impl clone for NetworkConfigs ([09e65bc](https://github.com/TaceoLabs/co-snarks/commit/09e65bc4864aaeca7ea40f10cb40f616e821ebc2))
* improve mpc-net usability for Network trait implementors ([0f7c4ce](https://github.com/TaceoLabs/co-snarks/commit/0f7c4ceacd8a046c6041c7b8f136667e07201bdf))
* rework MPC trait to return unified connection stats struct ([f24933b](https://github.com/TaceoLabs/co-snarks/commit/f24933b570bc6c287d038934fe1592e367c80cce))
* update rust edition to 2024 ([6ea0ba9](https://github.com/TaceoLabs/co-snarks/commit/6ea0ba9f9f34063e8ab859c1d4ae41d05629a1c0))


### Bug Fixes

* add feature flags to mpc-net example scripts, add rustls to quic net for installing provider in example ([fd5df9b](https://github.com/TaceoLabs/co-snarks/commit/fd5df9b750f802a2a600b757b52feba18f727f46))
* setting duplicate length_field_length in LengthDelimitedCodec ([070d6ec](https://github.com/TaceoLabs/co-snarks/commit/070d6ec31f9f2dfd494ac04f47c1cd51d4813d88))
* sort parties in tcp and tls nets ([3decee1](https://github.com/TaceoLabs/co-snarks/commit/3decee1f7e0008a34cffca571d23dcda3bf0a964))


### Code Refactoring

* unify MPC networks, split protocol state and networking to allow fork of state without network, replace io::Error with eyre, merge mpc-core and mpc-types with feature gated mpc-net ([16dbf54](https://github.com/TaceoLabs/co-snarks/commit/16dbf546d8f2d80ad4fa9f5053da19edc7270d3c))

## [0.4.0](https://github.com/TaceoLabs/co-snarks/compare/mpc-net-v0.3.0...mpc-net-v0.4.0) (2025-04-03)


### Features

* add optional connect timeout to network config ([#356](https://github.com/TaceoLabs/co-snarks/issues/356)) ([1acd639](https://github.com/TaceoLabs/co-snarks/commit/1acd639a1bfc4e0fea58b291346200a9c82fb487))

## [0.3.0](https://github.com/Taceolabs/co-snarks/compare/mpc-net-v0.2.1...mpc-net-v0.3.0) (2025-02-20)


### ⚠ BREAKING CHANGES

* a lot of APIs and types changed
* ChannelHandle no longer takes `&mut self` on send/recv methods, but now just takes `&self` ([#303](https://github.com/Taceolabs/co-snarks/issues/303))

### Code Refactoring

* ChannelHandle no longer takes `&mut self` on send/recv methods, but now just takes `&self` ([#303](https://github.com/Taceolabs/co-snarks/issues/303)) ([538b89e](https://github.com/Taceolabs/co-snarks/commit/538b89ebd11c21701b72f8025586655781574a52))
* co-circom lib usability improvents, added lib usage examples ([5768011](https://github.com/Taceolabs/co-snarks/commit/576801192076a27c75cd07fe1ec62244700bb934))

## [0.2.1](https://github.com/TaceoLabs/co-snarks/compare/mpc-net-v0.2.0...mpc-net-v0.2.1) (2024-12-16)


### Bug Fixes

* dont ignore network write errors in tokio taks, log them instead ([0823a5c](https://github.com/TaceoLabs/co-snarks/commit/0823a5ca0e851e609753b6c5134477ad530d0f3f))
* increase max frame length to 1Tb ([f50ab33](https://github.com/TaceoLabs/co-snarks/commit/f50ab33033b7a030345dadf32b6879fc74e2d53a))

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
