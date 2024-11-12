# Changelog

* The following workspace dependencies were updated
  * dependencies
    * circom-types bumped from 0.4.0 to 0.5.0
    * mpc-core bumped from 0.3.0 to 0.4.0

* The following workspace dependencies were updated
  * dependencies
    * mpc-core bumped from 0.4.0 to 0.5.0

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
