# Changelog

## [0.4.0](https://github.com/TaceoLabs/co-snarks/compare/co-noir-v0.3.0...co-noir-v0.4.0) (2024-11-11)


### ⚠ BREAKING CHANGES

* Add more commands to co-noir binary to prepare for cases where
* co-noir adapted to ACVMType instead of sharedbuildervariable
* Use ACVMType in co-builder
* MpcNetworkHandler::establish now takes the config with already read certs and key.
* The interface of the UltraCircuitVariable trait has change. Thus, also ProvingKey::create() throws an error now.
* co-noir now stores shared inputs in a different format (`BTreeMap<String, Rep3AcvmType<ark_bn254::Fr>>` instead of `BTreeMap<String, Rep3PrimeFieldShare<ark_bn254::Fr>>`)
* The produced proofs are now different due to new transcript handling in bb 0.55.1, and they are no longer backwards compatible.
* Add merging inputs to co-noir binary ([#208](https://github.com/TaceoLabs/co-snarks/issues/208))

### Features

* Add co-noir binary ([#201](https://github.com/TaceoLabs/co-snarks/issues/201)) ([3163aec](https://github.com/TaceoLabs/co-snarks/commit/3163aec0795dd7b357f532e4da9e232ea164f064))
* Add merging inputs to co-noir binary ([#208](https://github.com/TaceoLabs/co-snarks/issues/208)) ([9365fdc](https://github.com/TaceoLabs/co-snarks/commit/9365fdc1d3111cb7d17873e14fe7b5ee4b7db4fe))
* Add more commands to co-noir binary to prepare for cases where ([268ebe9](https://github.com/TaceoLabs/co-snarks/commit/268ebe9f243146cc6ea251e6b8fdef28cc8ca035))
* Add Verifying key serialization and add verification to co-noir binary ([#202](https://github.com/TaceoLabs/co-snarks/issues/202)) ([3467425](https://github.com/TaceoLabs/co-snarks/commit/34674255f764f8df1f862d600ebba46314566233))
* Do not use the builder in co-noir split witness ([d304986](https://github.com/TaceoLabs/co-snarks/commit/d304986495f4f6f94db60d4ad15e5f4cd29c0e32))
* Replace a panic from the ultracircuitbuilder with an Error ([#217](https://github.com/TaceoLabs/co-snarks/issues/217)) ([5d9c870](https://github.com/TaceoLabs/co-snarks/commit/5d9c8703525e90ee3d9215006df527ad6a6ae777))
* squashed commit of co-noir ([b132afc](https://github.com/TaceoLabs/co-snarks/commit/b132afcadb96914cd85070f87d7aa03bf9f87bfd))
* Update UltraHonk to BB v0.62.0, required to replace zeromorph with shplemini ([#251](https://github.com/TaceoLabs/co-snarks/issues/251)) ([f35cdd4](https://github.com/TaceoLabs/co-snarks/commit/f35cdd490f8a3daa8bb44f6aa502f42147efb4b6))
* Upgrade UltraHonk to be compatible with Barretenberg v0.55.1  ([#211](https://github.com/TaceoLabs/co-snarks/issues/211)) ([f817d76](https://github.com/TaceoLabs/co-snarks/commit/f817d768760ffbbf6b58489562aed5327567c561))


### Bug Fixes

* Adapt co-noir binary to handle public noir inputs correctly ([#216](https://github.com/TaceoLabs/co-snarks/issues/216)) ([bed3996](https://github.com/TaceoLabs/co-snarks/commit/bed399621558ca5d2ee22e9bdaa42f14f66b74d9))
* install rustls default crypto provider in our main binaries & examples ([#238](https://github.com/TaceoLabs/co-snarks/issues/238)) ([78757e4](https://github.com/TaceoLabs/co-snarks/commit/78757e46d8622360377d27c5d475d417bed95c5a))
* simplify path handling in co-noir binary ([26fae55](https://github.com/TaceoLabs/co-snarks/commit/26fae552badf72f8105ce0736e594d2398f1aca5))


### Code Refactoring

* co-noir adapted to ACVMType instead of sharedbuildervariable ([e6518a7](https://github.com/TaceoLabs/co-snarks/commit/e6518a7eb1bf6d5440b9dba815ae3342d93a4d4f))
* split network config into two types ([dca1756](https://github.com/TaceoLabs/co-snarks/commit/dca175603a5d6a2f75ccd987cb0b19cc3d965b00))
* Use ACVMType in co-builder ([e078c22](https://github.com/TaceoLabs/co-snarks/commit/e078c22e4d19580b4a0531c0ac4232e7dd9f3bae))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-acvm bumped from 0.3.0 to 0.4.0
    * co-ultrahonk bumped from 0.2.0 to 0.2.1

## [0.3.0](https://github.com/TaceoLabs/co-snarks/compare/co-noir-v0.2.0...co-noir-v0.3.0) (2024-11-11)


### ⚠ BREAKING CHANGES

* Add more commands to co-noir binary to prepare for cases where
* co-noir adapted to ACVMType instead of sharedbuildervariable
* Use ACVMType in co-builder
* MpcNetworkHandler::establish now takes the config with already read certs and key.
* The interface of the UltraCircuitVariable trait has change. Thus, also ProvingKey::create() throws an error now.
* co-noir now stores shared inputs in a different format (`BTreeMap<String, Rep3AcvmType<ark_bn254::Fr>>` instead of `BTreeMap<String, Rep3PrimeFieldShare<ark_bn254::Fr>>`)
* The produced proofs are now different due to new transcript handling in bb 0.55.1, and they are no longer backwards compatible.

### Features

* Add more commands to co-noir binary to prepare for cases where ([268ebe9](https://github.com/TaceoLabs/co-snarks/commit/268ebe9f243146cc6ea251e6b8fdef28cc8ca035))
* Do not use the builder in co-noir split witness ([d304986](https://github.com/TaceoLabs/co-snarks/commit/d304986495f4f6f94db60d4ad15e5f4cd29c0e32))
* Replace a panic from the ultracircuitbuilder with an Error ([#217](https://github.com/TaceoLabs/co-snarks/issues/217)) ([5d9c870](https://github.com/TaceoLabs/co-snarks/commit/5d9c8703525e90ee3d9215006df527ad6a6ae777))
* squashed commit of co-noir ([b132afc](https://github.com/TaceoLabs/co-snarks/commit/b132afcadb96914cd85070f87d7aa03bf9f87bfd))
* Update UltraHonk to BB v0.62.0, required to replace zeromorph with shplemini ([#251](https://github.com/TaceoLabs/co-snarks/issues/251)) ([f35cdd4](https://github.com/TaceoLabs/co-snarks/commit/f35cdd490f8a3daa8bb44f6aa502f42147efb4b6))
* Upgrade UltraHonk to be compatible with Barretenberg v0.55.1  ([#211](https://github.com/TaceoLabs/co-snarks/issues/211)) ([f817d76](https://github.com/TaceoLabs/co-snarks/commit/f817d768760ffbbf6b58489562aed5327567c561))


### Bug Fixes

* Adapt co-noir binary to handle public noir inputs correctly ([#216](https://github.com/TaceoLabs/co-snarks/issues/216)) ([bed3996](https://github.com/TaceoLabs/co-snarks/commit/bed399621558ca5d2ee22e9bdaa42f14f66b74d9))
* install rustls default crypto provider in our main binaries & examples ([#238](https://github.com/TaceoLabs/co-snarks/issues/238)) ([78757e4](https://github.com/TaceoLabs/co-snarks/commit/78757e46d8622360377d27c5d475d417bed95c5a))


### Code Refactoring

* co-noir adapted to ACVMType instead of sharedbuildervariable ([e6518a7](https://github.com/TaceoLabs/co-snarks/commit/e6518a7eb1bf6d5440b9dba815ae3342d93a4d4f))
* split network config into two types ([dca1756](https://github.com/TaceoLabs/co-snarks/commit/dca175603a5d6a2f75ccd987cb0b19cc3d965b00))
* Use ACVMType in co-builder ([e078c22](https://github.com/TaceoLabs/co-snarks/commit/e078c22e4d19580b4a0531c0ac4232e7dd9f3bae))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-acvm bumped from 0.2.0 to 0.3.0
    * co-ultrahonk bumped from 0.1.0 to 0.2.0
    * mpc-core bumped from 0.5.0 to 0.6.0
    * mpc-net bumped from 0.1.2 to 0.2.0

## [0.2.0](https://github.com/TaceoLabs/collaborative-circom/compare/co-noir-v0.1.0...co-noir-v0.2.0) (2024-10-04)


### ⚠ BREAKING CHANGES

* Add merging inputs to co-noir binary ([#208](https://github.com/TaceoLabs/collaborative-circom/issues/208))

### Features

* Add merging inputs to co-noir binary ([#208](https://github.com/TaceoLabs/collaborative-circom/issues/208)) ([9365fdc](https://github.com/TaceoLabs/collaborative-circom/commit/9365fdc1d3111cb7d17873e14fe7b5ee4b7db4fe))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-acvm bumped from 0.1.0 to 0.2.0

## [0.1.0](https://github.com/TaceoLabs/collaborative-circom/compare/co-noir-v0.0.1...co-noir-v0.1.0) (2024-10-04)


### Features

* Add co-noir binary ([#201](https://github.com/TaceoLabs/collaborative-circom/issues/201)) ([3163aec](https://github.com/TaceoLabs/collaborative-circom/commit/3163aec0795dd7b357f532e4da9e232ea164f064))
* Add Verifying key serialization and add verification to co-noir binary ([#202](https://github.com/TaceoLabs/collaborative-circom/issues/202)) ([3467425](https://github.com/TaceoLabs/collaborative-circom/commit/34674255f764f8df1f862d600ebba46314566233))


### Bug Fixes

* simplify path handling in co-noir binary ([26fae55](https://github.com/TaceoLabs/collaborative-circom/commit/26fae552badf72f8105ce0736e594d2398f1aca5))

## [0.1.0](https://github.com/TaceoLabs/collaborative-circom/compare/co-noir-v0.0.1...co-noir-v0.1.0) (2024-10-03)


### Features

* Add co-noir binary ([#201](https://github.com/TaceoLabs/collaborative-circom/issues/201)) ([3163aec](https://github.com/TaceoLabs/collaborative-circom/commit/3163aec0795dd7b357f532e4da9e232ea164f064))
* Add Verifying key serialization and add verification to co-noir binary ([#202](https://github.com/TaceoLabs/collaborative-circom/issues/202)) ([3467425](https://github.com/TaceoLabs/collaborative-circom/commit/34674255f764f8df1f862d600ebba46314566233))


### Bug Fixes

* simplify path handling in co-noir binary ([26fae55](https://github.com/TaceoLabs/collaborative-circom/commit/26fae552badf72f8105ce0736e594d2398f1aca5))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * mpc-core bumped from 0.4.0 to 0.5.0
