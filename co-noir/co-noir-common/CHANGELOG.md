# Changelog

## [0.2.0](https://github.com/TaceoLabs/co-snarks/compare/co-noir-common-v0.1.0...co-noir-common-v0.2.0) (2025-11-06)


### ⚠ BREAKING CHANGES

* upgrade to Noir 1.0.0-beta.14 and BB 3.0.0-nightly.20250916 ([#480](https://github.com/TaceoLabs/co-snarks/issues/480))
* remove ClientIVC and Mega flavour
* add functionality to compute transcript in MPC and integrate it ([#472](https://github.com/TaceoLabs/co-snarks/issues/472))
* intial implementation of MergeRecursiveVerifier ([#449](https://github.com/TaceoLabs/co-snarks/issues/449))
* Introduce initial implementation of MegaCircuitBuilder for construct_hiding_circuit_key ([#443](https://github.com/TaceoLabs/co-snarks/issues/443))

### Features

* add functionality to compute transcript in MPC and integrate it ([#472](https://github.com/TaceoLabs/co-snarks/issues/472)) ([e636308](https://github.com/TaceoLabs/co-snarks/commit/e636308efdf115149d53e05e70b157cfe5babb6c))
* initial MPC Translator prover and builder implementation ([#467](https://github.com/TaceoLabs/co-snarks/issues/467)) ([ff92fcb](https://github.com/TaceoLabs/co-snarks/commit/ff92fcbe8fa3f2cbc3904d3c28f0890aee3be7fb))
* intial implementation of MergeRecursiveVerifier ([#449](https://github.com/TaceoLabs/co-snarks/issues/449)) ([f7f2158](https://github.com/TaceoLabs/co-snarks/commit/f7f2158a2c3d5db704250ea94b88eb984fa23420))
* Introduce initial implementation of MegaCircuitBuilder for construct_hiding_circuit_key ([#443](https://github.com/TaceoLabs/co-snarks/issues/443)) ([c3104a1](https://github.com/TaceoLabs/co-snarks/commit/c3104a1cf28a34372e10a79a08d667b70000c737))


### Miscellaneous Chores

* upgrade to Noir 1.0.0-beta.14 and BB 3.0.0-nightly.20250916 ([#480](https://github.com/TaceoLabs/co-snarks/issues/480)) ([9bdad27](https://github.com/TaceoLabs/co-snarks/commit/9bdad2793e3ca7f82a291f9e9932cf877ef657eb))


### Code Refactoring

* remove ClientIVC and Mega flavour ([8ac7719](https://github.com/TaceoLabs/co-snarks/commit/8ac7719023577a899fd430886d541c660f0b6b83))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * mpc-core bumped from 0.9.0 to 0.10.0
    * mpc-net bumped from 0.4.0 to 0.5.0
    * noir-types bumped from 0.1.0 to 0.1.1
  * dev-dependencies
    * mpc-net bumped from 0.4.0 to 0.5.0
