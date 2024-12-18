# Changelog

## [0.3.0](https://github.com/TaceoLabs/co-snarks/compare/ultrahonk-v0.2.0...ultrahonk-v0.3.0) (2024-12-16)


### ⚠ BREAKING CHANGES

* Align to upstream bb behavior of calculating the grand product argument only over the relevant trace size, which leads to a different proof being output.
* Bump Noir to v0.38.0, implement range checks, and allow nargo-asserts
* Move builder to new co-builder crate
* The interface of the UltraCircuitVariable trait has change. Thus, also ProvingKey::create() throws an error now.
* co-noir now stores shared inputs in a different format (`BTreeMap<String, Rep3AcvmType<ark_bn254::Fr>>` instead of `BTreeMap<String, Rep3PrimeFieldShare<ark_bn254::Fr>>`)
* The produced proofs are now different due to new transcript handling in bb 0.55.1, and they are no longer backwards compatible.

### Features

* Add builder for ultrahonk and fix prover ([929dd1d](https://github.com/TaceoLabs/co-snarks/commit/929dd1d39f3048fd91ccab229e9ae8a500b92df6))
* Add co-noir binary ([#201](https://github.com/TaceoLabs/co-snarks/issues/201)) ([3163aec](https://github.com/TaceoLabs/co-snarks/commit/3163aec0795dd7b357f532e4da9e232ea164f064))
* Add co-oink prover ([#194](https://github.com/TaceoLabs/co-snarks/issues/194)) ([b5fbd85](https://github.com/TaceoLabs/co-snarks/commit/b5fbd85b32cdb01c8865777c2238e159fc9b2553))
* Add co-zeromorph to co-ultrahonk ([#195](https://github.com/TaceoLabs/co-snarks/issues/195)) ([e7df56e](https://github.com/TaceoLabs/co-snarks/commit/e7df56e5af49938166e9ce4a2bbc49eaa8977acc))
* Add first version of a (untested) UltraHonk prover ([9f2911f](https://github.com/TaceoLabs/co-snarks/commit/9f2911f61f10d40217145a6802ccaf577aa7995f))
* Add MPC tests for co-ultrahonk ([#199](https://github.com/TaceoLabs/co-snarks/issues/199)) ([5a36ad5](https://github.com/TaceoLabs/co-snarks/commit/5a36ad5d5226cf25b8c8ffe377dd30efe6133725))
* Add sumcheck prover (without relations) ([be44986](https://github.com/TaceoLabs/co-snarks/commit/be449861f4e1d9eda20dda28c5f6add4dfd54fea))
* Add the sumcheck relations to the co-ultrahonk prover ([#198](https://github.com/TaceoLabs/co-snarks/issues/198)) ([846c4f0](https://github.com/TaceoLabs/co-snarks/commit/846c4f0342cc24b47947de17aec5e5cc99b4d90f))
* Add Ultrahonk verifier ([5c5b5d8](https://github.com/TaceoLabs/co-snarks/commit/5c5b5d8d8eefe6478954ed912498a63bb1e532cb))
* Add Verifying key serialization and add verification to co-noir binary ([#202](https://github.com/TaceoLabs/co-snarks/issues/202)) ([3467425](https://github.com/TaceoLabs/co-snarks/commit/34674255f764f8df1f862d600ebba46314566233))
* Bump Noir to v0.38.0, implement range checks, and allow nargo-asserts ([d1a5d83](https://github.com/TaceoLabs/co-snarks/commit/d1a5d83d4b17f1e1a5ad2ffcb6e2dba40733a0c9))
* Bump versions to Nargo v0.39.0 and Barretenberg v0.63.1 ([#275](https://github.com/TaceoLabs/co-snarks/issues/275)) ([db255e6](https://github.com/TaceoLabs/co-snarks/commit/db255e63ef8ea64176b86f7c258c4f7a1bec7160))
* Make builder generic for both shares and plain, add shared proving key and start with MPC prover ([#193](https://github.com/TaceoLabs/co-snarks/issues/193)) ([e3559a0](https://github.com/TaceoLabs/co-snarks/commit/e3559a0a38a61b1de4b29ea9fa820066ed00ddc0))
* Replace a panic from the ultracircuitbuilder with an Error ([#217](https://github.com/TaceoLabs/co-snarks/issues/217)) ([5d9c870](https://github.com/TaceoLabs/co-snarks/commit/5d9c8703525e90ee3d9215006df527ad6a6ae777))
* skip creating unnecessary beta products ([118f2bf](https://github.com/TaceoLabs/co-snarks/commit/118f2bf30e97039e72138cf9bf2c63a1544e046a))
* Update UltraHonk to BB v0.62.0, required to replace zeromorph with shplemini ([#251](https://github.com/TaceoLabs/co-snarks/issues/251)) ([f35cdd4](https://github.com/TaceoLabs/co-snarks/commit/f35cdd490f8a3daa8bb44f6aa502f42147efb4b6))
* Upgrade UltraHonk to be compatible with Barretenberg v0.55.1  ([#211](https://github.com/TaceoLabs/co-snarks/issues/211)) ([f817d76](https://github.com/TaceoLabs/co-snarks/commit/f817d768760ffbbf6b58489562aed5327567c561))


### Bug Fixes

* Adapt co-noir binary to handle public noir inputs correctly ([#216](https://github.com/TaceoLabs/co-snarks/issues/216)) ([bed3996](https://github.com/TaceoLabs/co-snarks/commit/bed399621558ca5d2ee22e9bdaa42f14f66b74d9))
* clippy ([e43534a](https://github.com/TaceoLabs/co-snarks/commit/e43534aafefb4811bdf1f7fe1fa1493ab5c9152d))
* Fix reading ultrahonk proof ([f16ef68](https://github.com/TaceoLabs/co-snarks/commit/f16ef68663669f5406e1ef789fe8e3817fe27401))
* simplify path handling in co-noir binary ([26fae55](https://github.com/TaceoLabs/co-snarks/commit/26fae552badf72f8105ce0736e594d2398f1aca5))


### Code Refactoring

* Move builder to new co-builder crate ([3cd8955](https://github.com/TaceoLabs/co-snarks/commit/3cd89551d9fd58fad994942aa9a9660737db19b8))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-builder bumped from 0.1.0 to 0.2.0

## [0.2.0](https://github.com/TaceoLabs/co-snarks/compare/ultrahonk-v0.1.0...ultrahonk-v0.2.0) (2024-11-12)


### ⚠ BREAKING CHANGES

* Move builder to new co-builder crate
* The interface of the UltraCircuitVariable trait has change. Thus, also ProvingKey::create() throws an error now.
* co-noir now stores shared inputs in a different format (`BTreeMap<String, Rep3AcvmType<ark_bn254::Fr>>` instead of `BTreeMap<String, Rep3PrimeFieldShare<ark_bn254::Fr>>`)
* The produced proofs are now different due to new transcript handling in bb 0.55.1, and they are no longer backwards compatible.

### Features

* Replace a panic from the ultracircuitbuilder with an Error ([#217](https://github.com/TaceoLabs/co-snarks/issues/217)) ([5d9c870](https://github.com/TaceoLabs/co-snarks/commit/5d9c8703525e90ee3d9215006df527ad6a6ae777))
* Update UltraHonk to BB v0.62.0, required to replace zeromorph with shplemini ([#251](https://github.com/TaceoLabs/co-snarks/issues/251)) ([f35cdd4](https://github.com/TaceoLabs/co-snarks/commit/f35cdd490f8a3daa8bb44f6aa502f42147efb4b6))
* Upgrade UltraHonk to be compatible with Barretenberg v0.55.1  ([#211](https://github.com/TaceoLabs/co-snarks/issues/211)) ([f817d76](https://github.com/TaceoLabs/co-snarks/commit/f817d768760ffbbf6b58489562aed5327567c561))


### Bug Fixes

* Adapt co-noir binary to handle public noir inputs correctly ([#216](https://github.com/TaceoLabs/co-snarks/issues/216)) ([bed3996](https://github.com/TaceoLabs/co-snarks/commit/bed399621558ca5d2ee22e9bdaa42f14f66b74d9))


### Code Refactoring

* Move builder to new co-builder crate ([3cd8955](https://github.com/TaceoLabs/co-snarks/commit/3cd89551d9fd58fad994942aa9a9660737db19b8))

## [0.1.0](https://github.com/TaceoLabs/collaborative-circom/compare/ultrahonk-v0.0.1...ultrahonk-v0.1.0) (2024-10-03)


### Features

* Add builder for ultrahonk and fix prover ([929dd1d](https://github.com/TaceoLabs/collaborative-circom/commit/929dd1d39f3048fd91ccab229e9ae8a500b92df6))
* Add co-noir binary ([#201](https://github.com/TaceoLabs/collaborative-circom/issues/201)) ([3163aec](https://github.com/TaceoLabs/collaborative-circom/commit/3163aec0795dd7b357f532e4da9e232ea164f064))
* Add co-oink prover ([#194](https://github.com/TaceoLabs/collaborative-circom/issues/194)) ([b5fbd85](https://github.com/TaceoLabs/collaborative-circom/commit/b5fbd85b32cdb01c8865777c2238e159fc9b2553))
* Add co-zeromorph to co-ultrahonk ([#195](https://github.com/TaceoLabs/collaborative-circom/issues/195)) ([e7df56e](https://github.com/TaceoLabs/collaborative-circom/commit/e7df56e5af49938166e9ce4a2bbc49eaa8977acc))
* Add first version of a (untested) UltraHonk prover ([9f2911f](https://github.com/TaceoLabs/collaborative-circom/commit/9f2911f61f10d40217145a6802ccaf577aa7995f))
* Add MPC tests for co-ultrahonk ([#199](https://github.com/TaceoLabs/collaborative-circom/issues/199)) ([5a36ad5](https://github.com/TaceoLabs/collaborative-circom/commit/5a36ad5d5226cf25b8c8ffe377dd30efe6133725))
* Add sumcheck prover (without relations) ([be44986](https://github.com/TaceoLabs/collaborative-circom/commit/be449861f4e1d9eda20dda28c5f6add4dfd54fea))
* Add the sumcheck relations to the co-ultrahonk prover ([#198](https://github.com/TaceoLabs/collaborative-circom/issues/198)) ([846c4f0](https://github.com/TaceoLabs/collaborative-circom/commit/846c4f0342cc24b47947de17aec5e5cc99b4d90f))
* Add Ultrahonk verifier ([5c5b5d8](https://github.com/TaceoLabs/collaborative-circom/commit/5c5b5d8d8eefe6478954ed912498a63bb1e532cb))
* Add Verifying key serialization and add verification to co-noir binary ([#202](https://github.com/TaceoLabs/collaborative-circom/issues/202)) ([3467425](https://github.com/TaceoLabs/collaborative-circom/commit/34674255f764f8df1f862d600ebba46314566233))
* Make builder generic for both shares and plain, add shared proving key and start with MPC prover ([#193](https://github.com/TaceoLabs/collaborative-circom/issues/193)) ([e3559a0](https://github.com/TaceoLabs/collaborative-circom/commit/e3559a0a38a61b1de4b29ea9fa820066ed00ddc0))
* skip creating unnecessary beta products ([118f2bf](https://github.com/TaceoLabs/collaborative-circom/commit/118f2bf30e97039e72138cf9bf2c63a1544e046a))


### Bug Fixes

* clippy ([e43534a](https://github.com/TaceoLabs/collaborative-circom/commit/e43534aafefb4811bdf1f7fe1fa1493ab5c9152d))
* Fix reading ultrahonk proof ([f16ef68](https://github.com/TaceoLabs/collaborative-circom/commit/f16ef68663669f5406e1ef789fe8e3817fe27401))
* simplify path handling in co-noir binary ([26fae55](https://github.com/TaceoLabs/collaborative-circom/commit/26fae552badf72f8105ce0736e594d2398f1aca5))
