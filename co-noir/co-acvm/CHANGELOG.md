# Changelog

## [0.4.0](https://github.com/TaceoLabs/co-snarks/compare/co-acvm-v0.3.0...co-acvm-v0.4.0) (2024-12-16)


### ⚠ BREAKING CHANGES

* removed acvm in trait names of solver
* **!:** Added functionality to traits of brillig/acvm
* Added docs for brillig. Also updated the trait to better match the functionallity
* added more impls to brillig trait
* modified traits for ACVM
* Moved MPC impl for NoirWitnessExtension to co-brillig. This is SubjectToChange!
* Bump Noir to v0.38.0, implement range checks, and allow nargo-asserts
* Use ACVMType in co-builder
* co-noir now stores shared inputs in a different format (`BTreeMap<String, Rep3AcvmType<ark_bn254::Fr>>` instead of `BTreeMap<String, Rep3PrimeFieldShare<ark_bn254::Fr>>`)
* Add merging inputs to co-noir binary ([#208](https://github.com/TaceoLabs/co-snarks/issues/208))
* removed acvm_impl. now uses old driver for ACVM
* added mpc-core trait for Acvm witness extension. Therfore, we changed trait bounds for Rep3Protocol

### Features

* **!:** first version of shared if by forking brillig ([a25e4a5](https://github.com/TaceoLabs/co-snarks/commit/a25e4a5cb5cdc912197871803c5872c08777b8a7))
* Add co-noir binary ([#201](https://github.com/TaceoLabs/co-snarks/issues/201)) ([3163aec](https://github.com/TaceoLabs/co-snarks/commit/3163aec0795dd7b357f532e4da9e232ea164f064))
* Add merging inputs to co-noir binary ([#208](https://github.com/TaceoLabs/co-snarks/issues/208)) ([9365fdc](https://github.com/TaceoLabs/co-snarks/commit/9365fdc1d3111cb7d17873e14fe7b5ee4b7db4fe))
* Added co-brillig crate and first impl ([94d5978](https://github.com/TaceoLabs/co-snarks/commit/94d5978454f8b9f1b278ef1d7ad42e58361b2c11))
* added LUT provider stub and plain impl for MemOps ([3d2377f](https://github.com/TaceoLabs/co-snarks/commit/3d2377f073a7a6b1c4b88e1d752ebc3ef60724ed))
* added more functionality for Brillig-VM, two tests working ([b9778a0](https://github.com/TaceoLabs/co-snarks/commit/b9778a0b1f346f7a3160456f06e71d4173a9d616))
* added predicate handling in memory op ([220414f](https://github.com/TaceoLabs/co-snarks/commit/220414fbc1084658ffa73f0171a4c4493a97d7ca))
* added rep3 implementation for AssertZeroOpCode ([8e51505](https://github.com/TaceoLabs/co-snarks/commit/8e515052539227cf44860390a8d6736f9e456c91))
* added sanity checks for memopcodes ([6914611](https://github.com/TaceoLabs/co-snarks/commit/6914611ad5a7597e4785f8ef67ecfbf479f3dd7c))
* added trivial LUT impl for Rep3. Also modified some code in MPC-core ([bcb4749](https://github.com/TaceoLabs/co-snarks/commit/bcb4749e168807f5f16ae80bd1aeaa6e1f9da157))
* Bump Noir to v0.38.0, implement range checks, and allow nargo-asserts ([d1a5d83](https://github.com/TaceoLabs/co-snarks/commit/d1a5d83d4b17f1e1a5ad2ffcb6e2dba40733a0c9))
* first plain unconstrained fn working ([56e1c80](https://github.com/TaceoLabs/co-snarks/commit/56e1c801e6d51c8e35f1f1b1b2b007d80f050999))
* implement a radix sort in MPC and use it for range checks in co-noir ([#290](https://github.com/TaceoLabs/co-snarks/issues/290)) ([bc8c458](https://github.com/TaceoLabs/co-snarks/commit/bc8c45859f02932666c5306c00d2666011311505))
* implement many featuers for the co-brillig rep3 backend ([#284](https://github.com/TaceoLabs/co-snarks/issues/284)) ([11e0b03](https://github.com/TaceoLabs/co-snarks/commit/11e0b03b8ca437e48e0ac80e2cff870f530c58c0))
* Make builder generic for both shares and plain, add shared proving key and start with MPC prover ([#193](https://github.com/TaceoLabs/co-snarks/issues/193)) ([e3559a0](https://github.com/TaceoLabs/co-snarks/commit/e3559a0a38a61b1de4b29ea9fa820066ed00ddc0))
* noir witness extension works for our poseidon impl ([92800d3](https://github.com/TaceoLabs/co-snarks/commit/92800d3a272a22c080ffd9bb51bd9cbd6ac9b256))
* predicate check for brillig, all tests working now ([64b88ce](https://github.com/TaceoLabs/co-snarks/commit/64b88cee4f6e437e8eb32f453410030231fab7c6))
* shamir impls ([064ca06](https://github.com/TaceoLabs/co-snarks/commit/064ca06b25d9acd0a04e0a892f1b47ee94a16f39))
* some more opcodes and started bin int ops ([e99d9a4](https://github.com/TaceoLabs/co-snarks/commit/e99d9a4af52c84b0f54864c06218b2b23154df85))
* squashed commit of co-noir ([b132afc](https://github.com/TaceoLabs/co-snarks/commit/b132afcadb96914cd85070f87d7aa03bf9f87bfd))
* started witness extension Noir ([43e6535](https://github.com/TaceoLabs/co-snarks/commit/43e653545cd6e797becefbb76f7757dde43a5030))


### Bug Fixes

* Adapt co-noir binary to handle public noir inputs correctly ([#216](https://github.com/TaceoLabs/co-snarks/issues/216)) ([bed3996](https://github.com/TaceoLabs/co-snarks/commit/bed399621558ca5d2ee22e9bdaa42f14f66b74d9))
* fixed a bug where the constant for linear terms was ignored ([23883ff](https://github.com/TaceoLabs/co-snarks/commit/23883ff69bc96db0bbdd53125a58e140e21ed972))
* removed compiler transform as it breaks with nargo execute ([7274420](https://github.com/TaceoLabs/co-snarks/commit/72744204f93c6ab6911cb26257b2334e9d314329))


### Documentation

* Added docs for brillig. Also updated the trait to better match the functionallity ([a2df63a](https://github.com/TaceoLabs/co-snarks/commit/a2df63aa1048364e484bde31013a1c5bbe4a9da3))


### Code Refactoring

* removed acvm in trait names of solver ([6d07de3](https://github.com/TaceoLabs/co-snarks/commit/6d07de3f5afd759752cfda5e0898a48139450d6c))
* removed acvm_impl. now uses old driver for ACVM ([d37c5bb](https://github.com/TaceoLabs/co-snarks/commit/d37c5bbd00e932a97d64a6e924b8c092b71f30d2))
* Use ACVMType in co-builder ([e078c22](https://github.com/TaceoLabs/co-snarks/commit/e078c22e4d19580b4a0531c0ac4232e7dd9f3bae))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * mpc-core bumped from 0.6.0 to 0.7.0

## [0.3.0](https://github.com/TaceoLabs/co-snarks/compare/co-acvm-v0.2.0...co-acvm-v0.3.0) (2024-11-12)


### ⚠ BREAKING CHANGES

* Use ACVMType in co-builder
* co-noir now stores shared inputs in a different format (`BTreeMap<String, Rep3AcvmType<ark_bn254::Fr>>` instead of `BTreeMap<String, Rep3PrimeFieldShare<ark_bn254::Fr>>`)

### Features

* squashed commit of co-noir ([b132afc](https://github.com/TaceoLabs/co-snarks/commit/b132afcadb96914cd85070f87d7aa03bf9f87bfd))


### Bug Fixes

* Adapt co-noir binary to handle public noir inputs correctly ([#216](https://github.com/TaceoLabs/co-snarks/issues/216)) ([bed3996](https://github.com/TaceoLabs/co-snarks/commit/bed399621558ca5d2ee22e9bdaa42f14f66b74d9))


### Code Refactoring

* Use ACVMType in co-builder ([e078c22](https://github.com/TaceoLabs/co-snarks/commit/e078c22e4d19580b4a0531c0ac4232e7dd9f3bae))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * mpc-core bumped from 0.5.0 to 0.6.0

## [0.2.0](https://github.com/TaceoLabs/collaborative-circom/compare/co-acvm-v0.1.0...co-acvm-v0.2.0) (2024-10-04)


### ⚠ BREAKING CHANGES

* Add merging inputs to co-noir binary ([#208](https://github.com/TaceoLabs/collaborative-circom/issues/208))

### Features

* Add merging inputs to co-noir binary ([#208](https://github.com/TaceoLabs/collaborative-circom/issues/208)) ([9365fdc](https://github.com/TaceoLabs/collaborative-circom/commit/9365fdc1d3111cb7d17873e14fe7b5ee4b7db4fe))

## [0.1.0](https://github.com/TaceoLabs/collaborative-circom/compare/co-acvm-v0.0.1...co-acvm-v0.1.0) (2024-10-03)


### ⚠ BREAKING CHANGES

* removed acvm_impl. now uses old driver for ACVM
* added mpc-core trait for Acvm witness extension. Therfore, we changed trait bounds for Rep3Protocol

### Features

* Add co-noir binary ([#201](https://github.com/TaceoLabs/collaborative-circom/issues/201)) ([3163aec](https://github.com/TaceoLabs/collaborative-circom/commit/3163aec0795dd7b357f532e4da9e232ea164f064))
* added LUT provider stub and plain impl for MemOps ([3d2377f](https://github.com/TaceoLabs/collaborative-circom/commit/3d2377f073a7a6b1c4b88e1d752ebc3ef60724ed))
* added predicate handling in memory op ([220414f](https://github.com/TaceoLabs/collaborative-circom/commit/220414fbc1084658ffa73f0171a4c4493a97d7ca))
* added rep3 implementation for AssertZeroOpCode ([8e51505](https://github.com/TaceoLabs/collaborative-circom/commit/8e515052539227cf44860390a8d6736f9e456c91))
* added sanity checks for memopcodes ([6914611](https://github.com/TaceoLabs/collaborative-circom/commit/6914611ad5a7597e4785f8ef67ecfbf479f3dd7c))
* added trivial LUT impl for Rep3. Also modified some code in MPC-core ([bcb4749](https://github.com/TaceoLabs/collaborative-circom/commit/bcb4749e168807f5f16ae80bd1aeaa6e1f9da157))
* Make builder generic for both shares and plain, add shared proving key and start with MPC prover ([#193](https://github.com/TaceoLabs/collaborative-circom/issues/193)) ([e3559a0](https://github.com/TaceoLabs/collaborative-circom/commit/e3559a0a38a61b1de4b29ea9fa820066ed00ddc0))
* noir witness extension works for our poseidon impl ([92800d3](https://github.com/TaceoLabs/collaborative-circom/commit/92800d3a272a22c080ffd9bb51bd9cbd6ac9b256))
* started witness extension Noir ([43e6535](https://github.com/TaceoLabs/collaborative-circom/commit/43e653545cd6e797becefbb76f7757dde43a5030))


### Code Refactoring

* removed acvm_impl. now uses old driver for ACVM ([d37c5bb](https://github.com/TaceoLabs/collaborative-circom/commit/d37c5bbd00e932a97d64a6e924b8c092b71f30d2))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * mpc-core bumped from 0.4.0 to 0.5.0
