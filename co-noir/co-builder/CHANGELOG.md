# Changelog

## [0.4.0](https://github.com/TaceoLabs/co-snarks/compare/co-builder-v0.3.0...co-builder-v0.4.0) (2025-04-03)


### ⚠ BREAKING CHANGES

* bump to BB 0.82.0
* The API of several functions that previously took a `VerificationKey` has changed to now take a `&VerificationKey`.
* batched versions only gather elements they really need
* batched sum check now skips skippable rows

### Features

* add MPC ZK prover for coNoir ([#335](https://github.com/TaceoLabs/co-snarks/issues/335)) ([056b2b4](https://github.com/TaceoLabs/co-snarks/commit/056b2b4e10ef822de253ac646e88e2dd5f50edcb))
* add plain zk prover and zk verifier ([#333](https://github.com/TaceoLabs/co-snarks/issues/333)) ([7681649](https://github.com/TaceoLabs/co-snarks/commit/76816491c81e474e710977fa9f3450a3210b57dc))
* batched sum check now performs edge extension in 2^20 batches ([f815976](https://github.com/TaceoLabs/co-snarks/commit/f81597601bbb5ee9b501cecd61b479425f05ebc0))
* batched sum check now skips skippable rows ([2ae6d29](https://github.com/TaceoLabs/co-snarks/commit/2ae6d2961670060c1f75b1759f98d4e02f5c0c25))
* bump to BB 0.82.0 ([28500cc](https://github.com/TaceoLabs/co-snarks/commit/28500ccf1feb0cbca2d06881056705f3a6a9ef6a))
* remove some duplicate structs ([0e6b17a](https://github.com/TaceoLabs/co-snarks/commit/0e6b17a827449696613ab12baa246d1a79dd5456))


### Code Refactoring

* batched versions only gather elements they really need ([c32fd90](https://github.com/TaceoLabs/co-snarks/commit/c32fd9043e0397736a809b3059ae862522a7abe1))
* take uh-vk by reference ([#344](https://github.com/TaceoLabs/co-snarks/issues/344)) ([af9028a](https://github.com/TaceoLabs/co-snarks/commit/af9028a949fe4685f811da7c80a64c67c49a9150))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-acvm bumped from 0.5.0 to 0.6.0
    * mpc-core bumped from 0.8.0 to 0.9.0

## [0.3.0](https://github.com/Taceolabs/co-snarks/compare/co-builder-v0.2.0...co-builder-v0.3.0) (2025-02-20)


### ⚠ BREAKING CHANGES

* adapt prover and verifier to BB 0.72.1
* ark to 0.5.0, co-noir witext works with 1.0.0-beta.2
* optimize radix sort to take private and public inputs, such that public inputs do not have to be decomposed/bitinjected ([#319](https://github.com/Taceolabs/co-snarks/issues/319))
* a lot of APIs and types changed
* add RAM operations on shared indices ([#314](https://github.com/Taceolabs/co-snarks/issues/314))
* Move poseidon2 from ultrahonk to mpc-core
* Add extra functionality to rewrite the lookup_read_counts_tags to shared LUTs
* Adapt the ultrahonk mpc prover to also have the lookup related
* implemented bitwise_and, bitwise_xor and bitwise_not in the
* Bump Nargo to version v1.0.0-beta.1

### Features

* adapt prover and verifier to BB 0.72.1 ([2cc64ec](https://github.com/Taceolabs/co-snarks/commit/2cc64ec49f6b7b83e425d3f70ece1da52ecde172))
* Adapt the construct_lookup_read_counts for private lookup tables ([89bc455](https://github.com/Taceolabs/co-snarks/commit/89bc455d4002d3da3314dccf30734688c953269f))
* Adapt the ultrahonk mpc prover to also have the lookup related ([126fd57](https://github.com/Taceolabs/co-snarks/commit/126fd5750aeb507505207cf2ca9fb292590de5ca))
* Add bitwise blackbox functions to the acir_format parser ([db1e449](https://github.com/Taceolabs/co-snarks/commit/db1e4499ab6946035bb3a3eade29b80578f9de29))
* Add blackbox_poseidon2 handling to co-noir ([3c2e811](https://github.com/Taceolabs/co-snarks/commit/3c2e81133b2a5b3a360918bc7d597277d091fb15))
* add command to download a CRS with a given number of points to the co-noir binary ([#301](https://github.com/Taceolabs/co-snarks/issues/301)) ([3b7b562](https://github.com/Taceolabs/co-snarks/commit/3b7b562a377ceb54c60ab02661226b1430d0837d))
* Add extra functionality to rewrite the lookup_read_counts_tags to shared LUTs ([6fc80f7](https://github.com/Taceolabs/co-snarks/commit/6fc80f7a1a3a2a4f65180edccf03b6ef6b247c37))
* add generating recursive friendly vk; rename stuff to match bb ([6913f52](https://github.com/Taceolabs/co-snarks/commit/6913f52ece6efe2f17362f19ee183aea1d5aa017))
* add possibility to generate recursive proofs ([ffc8ac4](https://github.com/Taceolabs/co-snarks/commit/ffc8ac4d0b8ad834566154524bf8e9eab362ba0b))
* add RAM operations on shared indices ([#314](https://github.com/Taceolabs/co-snarks/issues/314)) ([c3367a5](https://github.com/Taceolabs/co-snarks/commit/c3367a55b95c3132cfbb6401c6ec1230f46e099c))
* Add RAM operations to plain coNoir ([2045471](https://github.com/Taceolabs/co-snarks/commit/2045471fb1cc013934d43063be5ed5ae2a80fcf0))
* ark to 0.5.0, co-noir witext works with 1.0.0-beta.2 ([8a466df](https://github.com/Taceolabs/co-snarks/commit/8a466dffde68d64bed8265e1336e454559898602))
* Bridge the co-builder and adapted proving-key generation and fix ([9df797b](https://github.com/Taceolabs/co-snarks/commit/9df797b21af60b7fb3030c58a7739003a627f6fd))
* Bump Nargo to version v1.0.0-beta.1 ([2e0a307](https://github.com/Taceolabs/co-snarks/commit/2e0a307524cd6b7a14fd3fc4dd2c00466c378534))
* Cleanup the mpc-core and builder after shared LUT integration ([a691090](https://github.com/Taceolabs/co-snarks/commit/a691090d4933b2e93b9707a48ed430687d2911ba))
* Extend ROM access for coNoir to the MPC setting of having shared indices ([c50809e](https://github.com/Taceolabs/co-snarks/commit/c50809eb891bfa29cb93406781fa4431aec1205b))
* Fixes and cleanup in shared LUTs ([59ac86e](https://github.com/Taceolabs/co-snarks/commit/59ac86ec7cd1d4faf033ffd1ea1ca6ad12d6d2d5))
* handle different num_bits ([2d545ab](https://github.com/Taceolabs/co-snarks/commit/2d545abe592fb6a6a85da5d0993c6db95b6d49b7))
* implement one lookup_acc case ([e91ffe1](https://github.com/Taceolabs/co-snarks/commit/e91ffe17b50497ee11c54af29de44d2f622fc9aa))
* implemented bitwise_and, bitwise_xor and bitwise_not in the ([57b8fef](https://github.com/Taceolabs/co-snarks/commit/57b8fef7dd4ea837cbccdc30718833ba72767253))
* Modify co-builder to allow logic constraints (only working in plain so far) ([1115986](https://github.com/Taceolabs/co-snarks/commit/11159866ba8275e63d7bccee6523efe71ac13e6f))
* move batch decompose into a separate fct ([f02fd38](https://github.com/Taceolabs/co-snarks/commit/f02fd38b69fab24808f6a2b8a64af4d0e4c96cf6))
* Move poseidon2 from ultrahonk to mpc-core ([380fc4d](https://github.com/Taceolabs/co-snarks/commit/380fc4d7541053c06992b13a1e9fb1c42d4600e2))
* optimize radix sort to take private and public inputs, such that public inputs do not have to be decomposed/bitinjected ([#319](https://github.com/Taceolabs/co-snarks/issues/319)) ([bd1b6b4](https://github.com/Taceolabs/co-snarks/commit/bd1b6b400c3342b40b40d2532d6fbde1135c109d))
* replace getting table index from LUT with calculating it from keys ([4e45372](https://github.com/Taceolabs/co-snarks/commit/4e45372f00c55cde82cfa8af5f9def60341cdcc3))
* Starting to adapt the co-builder for handling shared LUTs ([5fda228](https://github.com/Taceolabs/co-snarks/commit/5fda22875cfaca240f23f2b5744997c5da4b93f2))
* works for unique num_bits ([4249c3f](https://github.com/Taceolabs/co-snarks/commit/4249c3fd10209e0feebd025a1287489c4cf74334))


### Bug Fixes

* Fix a bug with shifting BigUints in Range constraints ([#318](https://github.com/Taceolabs/co-snarks/issues/318)) ([06c114a](https://github.com/Taceolabs/co-snarks/commit/06c114a00a58a01ef777473bc8991334b561c3cc))
* Fix splitting/reading proving key in co-noir binary ([df6a658](https://github.com/Taceolabs/co-snarks/commit/df6a658b6abeb08d3f4fd3d404aa7643fa2d6552))
* replace Hashmap with BTreeMap in circuit parsing of coNoir to make circuits deterministic. BB is not deterministic here... ([dee0972](https://github.com/Taceolabs/co-snarks/commit/dee0972b38565fa42f91b0e897ace89bbeb35a2a))


### Code Refactoring

* co-noir lib usability improvents, added lib usage examples ([18e644e](https://github.com/Taceolabs/co-snarks/commit/18e644ecdf18419fb9b4a071562210c5b0eee0a7))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-acvm bumped from 0.4.0 to 0.5.0
    * mpc-core bumped from 0.7.0 to 0.8.0

## [0.2.0](https://github.com/TaceoLabs/co-snarks/compare/co-builder-v0.1.0...co-builder-v0.2.0) (2024-12-16)


### ⚠ BREAKING CHANGES

* removed acvm in trait names of solver
* Align to upstream bb behavior of calculating the grand product argument only over the relevant trace size, which leads to a different proof being output.
* Bump Noir to v0.38.0, implement range checks, and allow nargo-asserts

### Features

* Add process ROM gate stuff for co-noir and some fixes ([9f0a9fa](https://github.com/TaceoLabs/co-snarks/commit/9f0a9fa905684afc9eaeee4ce6f2e7b0ce5e6769))
* Bump Noir to v0.38.0, implement range checks, and allow nargo-asserts ([d1a5d83](https://github.com/TaceoLabs/co-snarks/commit/d1a5d83d4b17f1e1a5ad2ffcb6e2dba40733a0c9))
* Bump versions to Nargo v0.39.0 and Barretenberg v0.63.1 ([#275](https://github.com/TaceoLabs/co-snarks/issues/275)) ([db255e6](https://github.com/TaceoLabs/co-snarks/commit/db255e63ef8ea64176b86f7c258c4f7a1bec7160))
* implement tool to compare output of upstream BB with our implementation ([8af8540](https://github.com/TaceoLabs/co-snarks/commit/8af8540e40749f61aa7a6a08be05a2e836467948))


### Code Refactoring

* removed acvm in trait names of solver ([6d07de3](https://github.com/TaceoLabs/co-snarks/commit/6d07de3f5afd759752cfda5e0898a48139450d6c))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-acvm bumped from 0.3.0 to 0.4.0
    * mpc-core bumped from 0.6.0 to 0.7.0

## [0.1.0](https://github.com/TaceoLabs/co-snarks/compare/co-builder-v0.0.1...co-builder-v0.1.0) (2024-11-12)


### ⚠ BREAKING CHANGES

* Add more commands to co-noir binary to prepare for cases where
* Use ACVMType in co-builder
* Move builder to new co-builder crate

### Features

* Add more commands to co-noir binary to prepare for cases where ([268ebe9](https://github.com/TaceoLabs/co-snarks/commit/268ebe9f243146cc6ea251e6b8fdef28cc8ca035))


### Code Refactoring

* Move builder to new co-builder crate ([3cd8955](https://github.com/TaceoLabs/co-snarks/commit/3cd89551d9fd58fad994942aa9a9660737db19b8))
* Use ACVMType in co-builder ([e078c22](https://github.com/TaceoLabs/co-snarks/commit/e078c22e4d19580b4a0531c0ac4232e7dd9f3bae))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-acvm bumped from 0.2.0 to 0.3.0
    * mpc-core bumped from 0.5.0 to 0.6.0
