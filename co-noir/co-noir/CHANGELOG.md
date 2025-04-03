# Changelog

## [0.6.0](https://github.com/TaceoLabs/co-snarks/compare/co-noir-v0.5.0...co-noir-v0.6.0) (2025-04-03)


### ⚠ BREAKING CHANGES

* bump to BB 0.82.0
* added a meaningful struct name for brillig succecss
* acvm now can store values and returns the output of circuit
* The API of several functions that previously took a `VerificationKey` has changed to now take a `&VerificationKey`.

### Features

* acvm now can store values and returns the output of circuit ([3df88fb](https://github.com/TaceoLabs/co-snarks/commit/3df88fb244b191e03bbd6e6aaede86eaaf7f3d6b))
* add MPC ZK prover for coNoir ([#335](https://github.com/TaceoLabs/co-snarks/issues/335)) ([056b2b4](https://github.com/TaceoLabs/co-snarks/commit/056b2b4e10ef822de253ac646e88e2dd5f50edcb))
* add optional connect timeout to network config ([#356](https://github.com/TaceoLabs/co-snarks/issues/356)) ([1acd639](https://github.com/TaceoLabs/co-snarks/commit/1acd639a1bfc4e0fea58b291346200a9c82fb487))
* add plain zk prover and zk verifier ([#333](https://github.com/TaceoLabs/co-snarks/issues/333)) ([7681649](https://github.com/TaceoLabs/co-snarks/commit/76816491c81e474e710977fa9f3450a3210b57dc))
* bump to BB 0.82.0 ([28500cc](https://github.com/TaceoLabs/co-snarks/commit/28500ccf1feb0cbca2d06881056705f3a6a9ef6a))
* update noir to version 1.0.0-beta.3 ([65d8284](https://github.com/TaceoLabs/co-snarks/commit/65d82847d14903740a0e980cdf1f441832b69610))


### Code Refactoring

* added a meaningful struct name for brillig succecss ([e0af901](https://github.com/TaceoLabs/co-snarks/commit/e0af901e2999cc7e38215f36fe2a647b18d94e0e))
* take uh-vk by reference ([#344](https://github.com/TaceoLabs/co-snarks/issues/344)) ([af9028a](https://github.com/TaceoLabs/co-snarks/commit/af9028a949fe4685f811da7c80a64c67c49a9150))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-acvm bumped from 0.5.0 to 0.6.0
    * co-ultrahonk bumped from 0.4.0 to 0.5.0
    * mpc-core bumped from 0.8.0 to 0.9.0
    * mpc-net bumped from 0.3.0 to 0.4.0

## [0.5.0](https://github.com/Taceolabs/co-snarks/compare/co-noir-v0.4.0...co-noir-v0.5.0) (2025-02-20)


### ⚠ BREAKING CHANGES

* adapt prover and verifier to BB 0.72.1
* ark to 0.5.0, co-noir witext works with 1.0.0-beta.2
* a lot of APIs and types changed
* add RAM operations on shared indices ([#314](https://github.com/Taceolabs/co-snarks/issues/314))
* Adapt the ultrahonk mpc prover to also have the lookup related
* implemented bitwise_and, bitwise_xor and bitwise_not in the
* Bump Nargo to version v1.0.0-beta.1

### Features

* adapt compare_MPC to include blackbox_and/xor ([1556e71](https://github.com/Taceolabs/co-snarks/commit/1556e7178618c767e64d50b4dee10024d1c2c5b9))
* adapt prover and verifier to BB 0.72.1 ([2cc64ec](https://github.com/Taceolabs/co-snarks/commit/2cc64ec49f6b7b83e425d3f70ece1da52ecde172))
* Adapt the ultrahonk mpc prover to also have the lookup related ([126fd57](https://github.com/Taceolabs/co-snarks/commit/126fd5750aeb507505207cf2ca9fb292590de5ca))
* add command to download a CRS with a given number of points to the co-noir binary ([#301](https://github.com/Taceolabs/co-snarks/issues/301)) ([3b7b562](https://github.com/Taceolabs/co-snarks/commit/3b7b562a377ceb54c60ab02661226b1430d0837d))
* add generating recursive friendly vk; rename stuff to match bb ([6913f52](https://github.com/Taceolabs/co-snarks/commit/6913f52ece6efe2f17362f19ee183aea1d5aa017))
* Add poseidon2 testcases (with and without blackbox function) ([6ed485e](https://github.com/Taceolabs/co-snarks/commit/6ed485e2c22d6473b5e82621972a2094890480ec))
* add possibility to generate recursive proofs ([ffc8ac4](https://github.com/Taceolabs/co-snarks/commit/ffc8ac4d0b8ad834566154524bf8e9eab362ba0b))
* add RAM operations on shared indices ([#314](https://github.com/Taceolabs/co-snarks/issues/314)) ([c3367a5](https://github.com/Taceolabs/co-snarks/commit/c3367a55b95c3132cfbb6401c6ec1230f46e099c))
* Add RAM operations to plain coNoir ([2045471](https://github.com/Taceolabs/co-snarks/commit/2045471fb1cc013934d43063be5ed5ae2a80fcf0))
* add shamir proving testcase for bb_poseidon2 ([4cfff0e](https://github.com/Taceolabs/co-snarks/commit/4cfff0e145417cfabc6eb1added91ce4fd844664))
* Add testcase for blackbox and/not/xor ([3444851](https://github.com/Taceolabs/co-snarks/commit/3444851b92e6fc5f469eb1c2064725d1ad2e0534))
* ark to 0.5.0, co-noir witext works with 1.0.0-beta.2 ([8a466df](https://github.com/Taceolabs/co-snarks/commit/8a466dffde68d64bed8265e1336e454559898602))
* Bump Nargo to version v1.0.0-beta.1 ([2e0a307](https://github.com/Taceolabs/co-snarks/commit/2e0a307524cd6b7a14fd3fc4dd2c00466c378534))
* Extend ROM access for coNoir to the MPC setting of having shared indices ([c50809e](https://github.com/Taceolabs/co-snarks/commit/c50809eb891bfa29cb93406781fa4431aec1205b))
* implemented bitwise_and, bitwise_xor and bitwise_not in the ([57b8fef](https://github.com/Taceolabs/co-snarks/commit/57b8fef7dd4ea837cbccdc30718833ba72767253))
* test case with diff. uints ([4362304](https://github.com/Taceolabs/co-snarks/commit/4362304ed3948510c31e297b0fc295be3b460975))


### Bug Fixes

* Fix a bug with shifting BigUints in Range constraints ([#318](https://github.com/Taceolabs/co-snarks/issues/318)) ([06c114a](https://github.com/Taceolabs/co-snarks/commit/06c114a00a58a01ef777473bc8991334b561c3cc))
* Fix splitting/reading proving key in co-noir binary ([df6a658](https://github.com/Taceolabs/co-snarks/commit/df6a658b6abeb08d3f4fd3d404aa7643fa2d6552))
* no longer measure quinn network shutdown ([3fc63dd](https://github.com/Taceolabs/co-snarks/commit/3fc63dd405b26343055e25eafc8945b4e12812f6))


### Code Refactoring

* co-noir lib usability improvents, added lib usage examples ([18e644e](https://github.com/Taceolabs/co-snarks/commit/18e644ecdf18419fb9b4a071562210c5b0eee0a7))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-acvm bumped from 0.4.0 to 0.5.0
    * co-ultrahonk bumped from 0.3.0 to 0.4.0
    * mpc-core bumped from 0.7.0 to 0.8.0
    * mpc-net bumped from 0.2.1 to 0.3.0

## [0.4.0](https://github.com/TaceoLabs/co-snarks/compare/co-noir-v0.3.0...co-noir-v0.4.0) (2024-12-16)


### ⚠ BREAKING CHANGES

* Align to upstream bb behavior of calculating the grand product argument only over the relevant trace size, which leads to a different proof being output.
* Bump Noir to v0.38.0, implement range checks, and allow nargo-asserts
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
* Add process ROM gate stuff for co-noir and some fixes ([9f0a9fa](https://github.com/TaceoLabs/co-snarks/commit/9f0a9fa905684afc9eaeee4ce6f2e7b0ce5e6769))
* Add Verifying key serialization and add verification to co-noir binary ([#202](https://github.com/TaceoLabs/co-snarks/issues/202)) ([3467425](https://github.com/TaceoLabs/co-snarks/commit/34674255f764f8df1f862d600ebba46314566233))
* Bump Nargo to version v1.0.0-beta.0 ([#286](https://github.com/TaceoLabs/co-snarks/issues/286)) ([f7cbae8](https://github.com/TaceoLabs/co-snarks/commit/f7cbae8943e009a91d422b7125b7629e19d257fe))
* Bump Noir to v0.38.0, implement range checks, and allow nargo-asserts ([d1a5d83](https://github.com/TaceoLabs/co-snarks/commit/d1a5d83d4b17f1e1a5ad2ffcb6e2dba40733a0c9))
* Bump versions to Nargo v0.39.0 and Barretenberg v0.63.1 ([#275](https://github.com/TaceoLabs/co-snarks/issues/275)) ([db255e6](https://github.com/TaceoLabs/co-snarks/commit/db255e63ef8ea64176b86f7c258c4f7a1bec7160))
* Do not use the builder in co-noir split witness ([d304986](https://github.com/TaceoLabs/co-snarks/commit/d304986495f4f6f94db60d4ad15e5f4cd29c0e32))
* implement many featuers for the co-brillig rep3 backend ([#284](https://github.com/TaceoLabs/co-snarks/issues/284)) ([11e0b03](https://github.com/TaceoLabs/co-snarks/commit/11e0b03b8ca437e48e0ac80e2cff870f530c58c0))
* implement tool to compare output of upstream BB with our implementation ([8af8540](https://github.com/TaceoLabs/co-snarks/commit/8af8540e40749f61aa7a6a08be05a2e836467948))
* Replace a panic from the ultracircuitbuilder with an Error ([#217](https://github.com/TaceoLabs/co-snarks/issues/217)) ([5d9c870](https://github.com/TaceoLabs/co-snarks/commit/5d9c8703525e90ee3d9215006df527ad6a6ae777))
* squashed commit of co-noir ([b132afc](https://github.com/TaceoLabs/co-snarks/commit/b132afcadb96914cd85070f87d7aa03bf9f87bfd))
* Update UltraHonk to BB v0.62.0, required to replace zeromorph with shplemini ([#251](https://github.com/TaceoLabs/co-snarks/issues/251)) ([f35cdd4](https://github.com/TaceoLabs/co-snarks/commit/f35cdd490f8a3daa8bb44f6aa502f42147efb4b6))
* Upgrade UltraHonk to be compatible with Barretenberg v0.55.1  ([#211](https://github.com/TaceoLabs/co-snarks/issues/211)) ([f817d76](https://github.com/TaceoLabs/co-snarks/commit/f817d768760ffbbf6b58489562aed5327567c561))


### Bug Fixes

* Adapt co-noir binary to handle public noir inputs correctly ([#216](https://github.com/TaceoLabs/co-snarks/issues/216)) ([bed3996](https://github.com/TaceoLabs/co-snarks/commit/bed399621558ca5d2ee22e9bdaa42f14f66b74d9))
* fixed a bug where the constant for linear terms was ignored ([23883ff](https://github.com/TaceoLabs/co-snarks/commit/23883ff69bc96db0bbdd53125a58e140e21ed972))
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
    * co-ultrahonk bumped from 0.2.0 to 0.3.0
    * mpc-core bumped from 0.6.0 to 0.7.0
    * mpc-net bumped from 0.2.0 to 0.2.1

## [0.3.0](https://github.com/TaceoLabs/co-snarks/compare/co-noir-v0.2.0...co-noir-v0.3.0) (2024-11-12)


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
