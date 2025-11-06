# Changelog

## renamed to co-circom-types

## [0.6.0](https://github.com/TaceoLabs/co-snarks/compare/co-circom-types-v0.5.0...co-circom-types-v0.6.0) (2025-11-06)


### ⚠ BREAKING CHANGES

* rework co-circom input splitting (now same as co-noir)
* unify MPC networks, split protocol state and networking to allow fork of state without network, replace io::Error with eyre, merge mpc-core and mpc-types with feature gated mpc-net
* move MPC types and share/combine into new mpc-types crate, rename co-circom-snarks to co-circom-types

### Features

* rework co-circom input splitting (now same as co-noir) ([933bead](https://github.com/TaceoLabs/co-snarks/commit/933bead6b06b5140089978814e8612fd871f4a0b))
* update rust edition to 2024 ([6ea0ba9](https://github.com/TaceoLabs/co-snarks/commit/6ea0ba9f9f34063e8ab859c1d4ae41d05629a1c0))


### Code Refactoring

* move MPC types and share/combine into new mpc-types crate, rename co-circom-snarks to co-circom-types ([31b773a](https://github.com/TaceoLabs/co-snarks/commit/31b773aa71a5e872c25754de7805b02647b65688))
* unify MPC networks, split protocol state and networking to allow fork of state without network, replace io::Error with eyre, merge mpc-core and mpc-types with feature gated mpc-net ([16dbf54](https://github.com/TaceoLabs/co-snarks/commit/16dbf546d8f2d80ad4fa9f5053da19edc7270d3c))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-types bumped from 0.9.0 to 0.10.0
    * mpc-core bumped from 0.9.0 to 0.10.0

## [0.5.0](https://github.com/TaceoLabs/co-snarks/compare/co-circom-snarks-v0.4.0...co-circom-snarks-v0.5.0) (2025-04-03)


### ⚠ BREAKING CHANGES

* added a batched version for plain witness extension and a chacha test case for it

### Features

* added a batched version for plain witness extension and a chacha test case for it ([36e69cc](https://github.com/TaceoLabs/co-snarks/commit/36e69cc7621b8689e3c829c8f1489344a1298899))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-types bumped from 0.8.0 to 0.9.0
    * mpc-core bumped from 0.8.0 to 0.9.0

## [0.4.0](https://github.com/Taceolabs/co-snarks/compare/co-circom-snarks-v0.3.0...co-circom-snarks-v0.4.0) (2025-02-20)


### ⚠ BREAKING CHANGES

* a lot of APIs and types changed
* compressed inputs shares are no longer supported, only compressed witness shares are allowed

### Code Refactoring

* co-circom lib usability improvents, added lib usage examples ([5768011](https://github.com/Taceolabs/co-snarks/commit/576801192076a27c75cd07fe1ec62244700bb934))
* input shares are always rep3 and not compressed ([e760ec0](https://github.com/Taceolabs/co-snarks/commit/e760ec0c47f2432a137f1fa74e57d0c5bdbcf902))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-types bumped from 0.7.0 to 0.8.0
    * mpc-core bumped from 0.7.0 to 0.8.0

## [0.3.0](https://github.com/TaceoLabs/co-snarks/compare/co-circom-snarks-v0.2.0...co-circom-snarks-v0.3.0) (2024-12-16)


### ⚠ BREAKING CHANGES

* Now the verify impls from groth16/plonk circom return an error indicating whether it was a success or not

### Bug Fixes

* added a check during groth16 prover for public inputs ([76466eb](https://github.com/TaceoLabs/co-snarks/commit/76466eb2d662efa4d5061e53e09470740763c77f))
* default maybe_shared_inputs field while deserializing ([#276](https://github.com/TaceoLabs/co-snarks/issues/276)) ([b029f37](https://github.com/TaceoLabs/co-snarks/commit/b029f3778cf3d0be7ef00c51dbcffbb59e61a305))


### Code Refactoring

* Removed ark_relations deps. Also changed verify impls to not return bool but a common error ([b4f4bf1](https://github.com/TaceoLabs/co-snarks/commit/b4f4bf16beaa83108bc2ae6c6f972ab4e4da4473))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-types bumped from 0.6.0 to 0.7.0
    * mpc-core bumped from 0.6.0 to 0.7.0

## [0.2.0](https://github.com/TaceoLabs/co-snarks/compare/co-circom-snarks-v0.1.2...co-circom-snarks-v0.2.0) (2024-11-12)


### ⚠ BREAKING CHANGES

* serialization format of shared inputs has changed to allow for optional values used to indicate missing elements of an array
* refactor API because of changes in other crates

### Features

* add support for merging input arrays ([#260](https://github.com/TaceoLabs/co-snarks/issues/260)) ([2c72231](https://github.com/TaceoLabs/co-snarks/commit/2c722317efee4b07fef92dcc7c6218033a25f04b))
* prepare functions for compressed rep3 sharing ([55bef10](https://github.com/TaceoLabs/co-snarks/commit/55bef10313378e8ca14f2f22f312c84462a92a7e))


### Code Refactoring

* refactor API because of changes in other crates ([a58d8f1](https://github.com/TaceoLabs/co-snarks/commit/a58d8f1d1852ece862ed9d9164ee96e66fba1da8))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-types bumped from 0.5.0 to 0.6.0
    * mpc-core bumped from 0.5.0 to 0.6.0

## 0.1.0 (2024-08-14)


### ⚠ BREAKING CHANGES

* moved common code for PLONK and Groth16 into separate crate. Most notably the SharedWitness and SharedInput

### Code Refactoring

* added new crate co-circom-snarks ([ea3190f](https://github.com/TaceoLabs/collaborative-circom/commit/ea3190f4d731893e6fcce71976c32b3bbac6b89b))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-types bumped from 0.3.0 to 0.4.0
    * mpc-core bumped from 0.2.1 to 0.3.0
