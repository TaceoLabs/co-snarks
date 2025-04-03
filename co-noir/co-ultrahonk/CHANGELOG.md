# Changelog

## [0.5.0](https://github.com/TaceoLabs/co-snarks/compare/co-ultrahonk-v0.4.0...co-ultrahonk-v0.5.0) (2025-04-03)


### ⚠ BREAKING CHANGES

* bump to BB 0.82.0
* The API of several functions that previously took a `VerificationKey` has changed to now take a `&VerificationKey`.
* ultra arith relation now uses mt and half shares
* batched versions only gather elements they really need
* removed old unbatched versions for sum check.
* batched sum check now skips skippable rows
* adds batched versions of relation in sumcheck for MPC friendliness
* removed self references for linear operations in co-noir

### Features

* ! switched to batched versions of relations and removed old code ([d8b76f0](https://github.com/TaceoLabs/co-snarks/commit/d8b76f04207cae954deb96d74cfe1906d121f01d))
* add MPC ZK prover for coNoir ([#335](https://github.com/TaceoLabs/co-snarks/issues/335)) ([056b2b4](https://github.com/TaceoLabs/co-snarks/commit/056b2b4e10ef822de253ac646e88e2dd5f50edcb))
* add plain zk prover and zk verifier ([#333](https://github.com/TaceoLabs/co-snarks/issues/333)) ([7681649](https://github.com/TaceoLabs/co-snarks/commit/76816491c81e474e710977fa9f3450a3210b57dc))
* adds batched versions of relation in sumcheck for MPC friendliness ([475cd84](https://github.com/TaceoLabs/co-snarks/commit/475cd841811be0ee38d76f82a8d5bec8d712cee0))
* batched sum check now performs edge extension in 2^20 batches ([f815976](https://github.com/TaceoLabs/co-snarks/commit/f81597601bbb5ee9b501cecd61b479425f05ebc0))
* batched sum check now skips skippable rows ([2ae6d29](https://github.com/TaceoLabs/co-snarks/commit/2ae6d2961670060c1f75b1759f98d4e02f5c0c25))
* bump to BB 0.82.0 ([28500cc](https://github.com/TaceoLabs/co-snarks/commit/28500ccf1feb0cbca2d06881056705f3a6a9ef6a))
* rayon in DeltaRelation ([537b1d8](https://github.com/TaceoLabs/co-snarks/commit/537b1d8f5b7d411bb5f656fed71df1922d208c17))
* remove some duplicate structs ([0e6b17a](https://github.com/TaceoLabs/co-snarks/commit/0e6b17a827449696613ab12baa246d1a79dd5456))
* ultra arith relation now uses mt and half shares ([d7a6b9a](https://github.com/TaceoLabs/co-snarks/commit/d7a6b9a319124204a8fa9d94e4197a6dbf08ede4))


### Bug Fixes

* fixed the batched version for zk ([d50f1b6](https://github.com/TaceoLabs/co-snarks/commit/d50f1b601a688f11d33219d011862e4fd532cc1e))


### Code Refactoring

* batched versions only gather elements they really need ([c32fd90](https://github.com/TaceoLabs/co-snarks/commit/c32fd9043e0397736a809b3059ae862522a7abe1))
* removed old unbatched versions for sum check. ([b800c54](https://github.com/TaceoLabs/co-snarks/commit/b800c54bcc86bdcea634e4fecda69e805f9e59c1))
* removed self references for linear operations in co-noir ([cf1a62b](https://github.com/TaceoLabs/co-snarks/commit/cf1a62b4910e4bb369d61078332514fdc308eada))
* take uh-vk by reference ([#344](https://github.com/TaceoLabs/co-snarks/issues/344)) ([af9028a](https://github.com/TaceoLabs/co-snarks/commit/af9028a949fe4685f811da7c80a64c67c49a9150))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-acvm bumped from 0.5.0 to 0.6.0
    * co-builder bumped from 0.3.0 to 0.4.0
    * mpc-core bumped from 0.8.0 to 0.9.0
    * ultrahonk bumped from 0.4.0 to 0.5.0

## [0.4.0](https://github.com/Taceolabs/co-snarks/compare/co-ultrahonk-v0.3.0...co-ultrahonk-v0.4.0) (2025-02-20)


### ⚠ BREAKING CHANGES

* adapt prover and verifier to BB 0.72.1
* ark to 0.5.0, co-noir witext works with 1.0.0-beta.2
* a lot of APIs and types changed
* add RAM operations on shared indices ([#314](https://github.com/Taceolabs/co-snarks/issues/314))
* Move poseidon2 from ultrahonk to mpc-core
* Adapt the ultrahonk mpc prover to also have the lookup related
* Bump Nargo to version v1.0.0-beta.1

### Features

* adapt prover and verifier to BB 0.72.1 ([2cc64ec](https://github.com/Taceolabs/co-snarks/commit/2cc64ec49f6b7b83e425d3f70ece1da52ecde172))
* Adapt the construct_lookup_read_counts for private lookup tables ([89bc455](https://github.com/Taceolabs/co-snarks/commit/89bc455d4002d3da3314dccf30734688c953269f))
* Adapt the ultrahonk mpc prover to also have the lookup related ([126fd57](https://github.com/Taceolabs/co-snarks/commit/126fd5750aeb507505207cf2ca9fb292590de5ca))
* add generating recursive friendly vk; rename stuff to match bb ([6913f52](https://github.com/Taceolabs/co-snarks/commit/6913f52ece6efe2f17362f19ee183aea1d5aa017))
* add possibility to generate recursive proofs ([ffc8ac4](https://github.com/Taceolabs/co-snarks/commit/ffc8ac4d0b8ad834566154524bf8e9eab362ba0b))
* add RAM operations on shared indices ([#314](https://github.com/Taceolabs/co-snarks/issues/314)) ([c3367a5](https://github.com/Taceolabs/co-snarks/commit/c3367a55b95c3132cfbb6401c6ec1230f46e099c))
* ark to 0.5.0, co-noir witext works with 1.0.0-beta.2 ([8a466df](https://github.com/Taceolabs/co-snarks/commit/8a466dffde68d64bed8265e1336e454559898602))
* Bump Nargo to version v1.0.0-beta.1 ([2e0a307](https://github.com/Taceolabs/co-snarks/commit/2e0a307524cd6b7a14fd3fc4dd2c00466c378534))
* Move poseidon2 from ultrahonk to mpc-core ([380fc4d](https://github.com/Taceolabs/co-snarks/commit/380fc4d7541053c06992b13a1e9fb1c42d4600e2))


### Bug Fixes

* Fix splitting/reading proving key in co-noir binary ([df6a658](https://github.com/Taceolabs/co-snarks/commit/df6a658b6abeb08d3f4fd3d404aa7643fa2d6552))


### Code Refactoring

* co-noir lib usability improvents, added lib usage examples ([18e644e](https://github.com/Taceolabs/co-snarks/commit/18e644ecdf18419fb9b4a071562210c5b0eee0a7))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-acvm bumped from 0.4.0 to 0.5.0
    * co-builder bumped from 0.2.0 to 0.3.0
    * mpc-core bumped from 0.7.0 to 0.8.0
    * ultrahonk bumped from 0.3.0 to 0.4.0

## [0.3.0](https://github.com/TaceoLabs/co-snarks/compare/co-ultrahonk-v0.2.0...co-ultrahonk-v0.3.0) (2024-12-16)


### ⚠ BREAKING CHANGES

* Align to upstream bb behavior of calculating the grand product argument only over the relevant trace size, which leads to a different proof being output.
* Bump Noir to v0.38.0, implement range checks, and allow nargo-asserts

### Features

* Add process ROM gate stuff for co-noir and some fixes ([9f0a9fa](https://github.com/TaceoLabs/co-snarks/commit/9f0a9fa905684afc9eaeee4ce6f2e7b0ce5e6769))
* Bump Noir to v0.38.0, implement range checks, and allow nargo-asserts ([d1a5d83](https://github.com/TaceoLabs/co-snarks/commit/d1a5d83d4b17f1e1a5ad2ffcb6e2dba40733a0c9))
* Bump versions to Nargo v0.39.0 and Barretenberg v0.63.1 ([#275](https://github.com/TaceoLabs/co-snarks/issues/275)) ([db255e6](https://github.com/TaceoLabs/co-snarks/commit/db255e63ef8ea64176b86f7c258c4f7a1bec7160))
* implement tool to compare output of upstream BB with our implementation ([8af8540](https://github.com/TaceoLabs/co-snarks/commit/8af8540e40749f61aa7a6a08be05a2e836467948))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-acvm bumped from 0.3.0 to 0.4.0
    * co-builder bumped from 0.1.0 to 0.2.0
    * mpc-core bumped from 0.6.0 to 0.7.0
    * ultrahonk bumped from 0.2.0 to 0.3.0

## [0.2.0](https://github.com/TaceoLabs/co-snarks/compare/co-ultrahonk-v0.1.0...co-ultrahonk-v0.2.0) (2024-11-12)


### ⚠ BREAKING CHANGES

* Add more commands to co-noir binary to prepare for cases where
* Use ACVMType in co-builder
* Move builder to new co-builder crate
* removed point G2 from ultra-honk prover
* The interface of the UltraCircuitVariable trait has change. Thus, also ProvingKey::create() throws an error now.
* The produced proofs are now different due to new transcript handling in bb 0.55.1, and they are no longer backwards compatible.

### Features

* Add more commands to co-noir binary to prepare for cases where ([268ebe9](https://github.com/TaceoLabs/co-snarks/commit/268ebe9f243146cc6ea251e6b8fdef28cc8ca035))
* Replace a panic from the ultracircuitbuilder with an Error ([#217](https://github.com/TaceoLabs/co-snarks/issues/217)) ([5d9c870](https://github.com/TaceoLabs/co-snarks/commit/5d9c8703525e90ee3d9215006df527ad6a6ae777))
* squashed commit of co-noir ([b132afc](https://github.com/TaceoLabs/co-snarks/commit/b132afcadb96914cd85070f87d7aa03bf9f87bfd))
* Update UltraHonk to BB v0.62.0, required to replace zeromorph with shplemini ([#251](https://github.com/TaceoLabs/co-snarks/issues/251)) ([f35cdd4](https://github.com/TaceoLabs/co-snarks/commit/f35cdd490f8a3daa8bb44f6aa502f42147efb4b6))
* Upgrade UltraHonk to be compatible with Barretenberg v0.55.1  ([#211](https://github.com/TaceoLabs/co-snarks/issues/211)) ([f817d76](https://github.com/TaceoLabs/co-snarks/commit/f817d768760ffbbf6b58489562aed5327567c561))


### Code Refactoring

* Move builder to new co-builder crate ([3cd8955](https://github.com/TaceoLabs/co-snarks/commit/3cd89551d9fd58fad994942aa9a9660737db19b8))
* removed point G2 from ultra-honk prover ([1840fb4](https://github.com/TaceoLabs/co-snarks/commit/1840fb4821c597b7ad2d2c0ae83217582b1b5ad5))
* Use ACVMType in co-builder ([e078c22](https://github.com/TaceoLabs/co-snarks/commit/e078c22e4d19580b4a0531c0ac4232e7dd9f3bae))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-acvm bumped from 0.2.0 to 0.3.0
    * mpc-core bumped from 0.5.0 to 0.6.0
    * ultrahonk bumped from 0.1.0 to 0.2.0

## [0.1.0](https://github.com/TaceoLabs/collaborative-circom/compare/co-ultrahonk-v0.0.1...co-ultrahonk-v0.1.0) (2024-10-03)


### Features

* Add co-noir binary ([#201](https://github.com/TaceoLabs/collaborative-circom/issues/201)) ([3163aec](https://github.com/TaceoLabs/collaborative-circom/commit/3163aec0795dd7b357f532e4da9e232ea164f064))
* Add co-oink prover ([#194](https://github.com/TaceoLabs/collaborative-circom/issues/194)) ([b5fbd85](https://github.com/TaceoLabs/collaborative-circom/commit/b5fbd85b32cdb01c8865777c2238e159fc9b2553))
* Add co-zeromorph to co-ultrahonk ([#195](https://github.com/TaceoLabs/collaborative-circom/issues/195)) ([e7df56e](https://github.com/TaceoLabs/collaborative-circom/commit/e7df56e5af49938166e9ce4a2bbc49eaa8977acc))
* Add MPC tests for co-ultrahonk ([#199](https://github.com/TaceoLabs/collaborative-circom/issues/199)) ([5a36ad5](https://github.com/TaceoLabs/collaborative-circom/commit/5a36ad5d5226cf25b8c8ffe377dd30efe6133725))
* Add sumcheck prover (without relations) ([be44986](https://github.com/TaceoLabs/collaborative-circom/commit/be449861f4e1d9eda20dda28c5f6add4dfd54fea))
* Add the sumcheck relations to the co-ultrahonk prover ([#198](https://github.com/TaceoLabs/collaborative-circom/issues/198)) ([846c4f0](https://github.com/TaceoLabs/collaborative-circom/commit/846c4f0342cc24b47947de17aec5e5cc99b4d90f))
* Add Ultrahonk verifier ([5c5b5d8](https://github.com/TaceoLabs/collaborative-circom/commit/5c5b5d8d8eefe6478954ed912498a63bb1e532cb))
* Add Verifying key serialization and add verification to co-noir binary ([#202](https://github.com/TaceoLabs/collaborative-circom/issues/202)) ([3467425](https://github.com/TaceoLabs/collaborative-circom/commit/34674255f764f8df1f862d600ebba46314566233))
* Make builder generic for both shares and plain, add shared proving key and start with MPC prover ([#193](https://github.com/TaceoLabs/collaborative-circom/issues/193)) ([e3559a0](https://github.com/TaceoLabs/collaborative-circom/commit/e3559a0a38a61b1de4b29ea9fa820066ed00ddc0))
* skip creating unnecessary beta products ([118f2bf](https://github.com/TaceoLabs/collaborative-circom/commit/118f2bf30e97039e72138cf9bf2c63a1544e046a))


### Bug Fixes

* correct size in MSM for the debug assert ([d3ac74e](https://github.com/TaceoLabs/collaborative-circom/commit/d3ac74e3b2b4ae7e15ddfc60ba5f8a803dce6dd6))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * mpc-core bumped from 0.4.0 to 0.5.0
