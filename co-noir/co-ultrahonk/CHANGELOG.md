# Changelog

* The following workspace dependencies were updated
  * dependencies
    * co-acvm bumped from 0.3.0 to 0.4.0
    * co-builder bumped from 0.1.0 to 0.1.1
    * ultrahonk bumped from 0.2.0 to 0.3.0

## [0.2.0](https://github.com/TaceoLabs/co-snarks/compare/co-ultrahonk-v0.1.0...co-ultrahonk-v0.2.0) (2024-11-11)


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
