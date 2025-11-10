# Changelog

## [0.7.0](https://github.com/TaceoLabs/co-snarks/compare/co-acvm-v0.6.0...co-acvm-v0.7.0) (2025-11-06)


### ⚠ BREAKING CHANGES

* upgrade to Noir 1.0.0-beta.14 and BB 3.0.0-nightly.20250916 ([#480](https://github.com/TaceoLabs/co-snarks/issues/480))
* remove ClientIVC and Mega flavour
* initial implementation of ProtogalaxyRecursiveVerifier ([#460](https://github.com/TaceoLabs/co-snarks/issues/460))
* intial implementation of MergeRecursiveVerifier ([#449](https://github.com/TaceoLabs/co-snarks/issues/449))
* Introduce initial implementation of MegaCircuitBuilder for construct_hiding_circuit_key ([#443](https://github.com/TaceoLabs/co-snarks/issues/443))
* add MPC version of ECCVM builder and prover ([#456](https://github.com/TaceoLabs/co-snarks/issues/456))
* move witness and input parsing/sharing to new crates for wasm comp
* unify MPC networks, split protocol state and networking to allow fork of state without network, replace io::Error with eyre, merge mpc-core and mpc-types with feature gated mpc-net
* bump to Barretenberg 0.86.0 ([#373](https://github.com/TaceoLabs/co-snarks/issues/373))
* Add support for the embedded_curve_add blackbox function to co-noir ([#367](https://github.com/TaceoLabs/co-snarks/issues/367))
* Performance improvements and cleanup for blake2/blake3
* add BLAKE3 blackbox function to coNoir
* add BLAKE2s blackbox function to coNoir
* add Bristol Fashion parsing for GC, also adds the SHA256 blackbox ([#359](https://github.com/TaceoLabs/co-snarks/issues/359))
* Add the MSM blackbox function to co-noir, which allows to use pedersen hash/commitment

### Features

* adapt the r1cs solver to allow range blackbox function ([#466](https://github.com/TaceoLabs/co-snarks/issues/466)) ([b8d2992](https://github.com/TaceoLabs/co-snarks/commit/b8d299289f70c9b0371fa3639ccd133532e74974))
* Add AES blackbox functionality ([fd7cd49](https://github.com/TaceoLabs/co-snarks/commit/fd7cd496a1fd21e85aa70c0bd2c5cd7aed69fece))
* add BLAKE2s blackbox function to coNoir ([e98fb7d](https://github.com/TaceoLabs/co-snarks/commit/e98fb7dd60f52d936f07b3e3a74797dfb091e9f3))
* add BLAKE3 blackbox function to coNoir ([ddcb10e](https://github.com/TaceoLabs/co-snarks/commit/ddcb10e5d685072279b8f11b6935636fb74ecaf0))
* add Bristol Fashion parsing for GC, also adds the SHA256 blackbox ([#359](https://github.com/TaceoLabs/co-snarks/issues/359)) ([f8509ef](https://github.com/TaceoLabs/co-snarks/commit/f8509ef8147bf29072ba67b4ac0f489546eea2c9))
* add builder type transcript for recursion ([#433](https://github.com/TaceoLabs/co-snarks/issues/433)) ([2177ad5](https://github.com/TaceoLabs/co-snarks/commit/2177ad54a18c7deeb0d525379095b22ed24f3269))
* add CoNoir solver which allows some precomputed witnesses ([6d7d85e](https://github.com/TaceoLabs/co-snarks/commit/6d7d85eea200a33507d4e6c22c7055d776cb6dae))
* add extension traits for REP3 and Shamir networks ([0c15da8](https://github.com/TaceoLabs/co-snarks/commit/0c15da81550f35c7aaef77d5143824a9436d5731))
* add MAESTRO style lut protocol for curve points ([4da5f74](https://github.com/TaceoLabs/co-snarks/commit/4da5f74bed1350c4574bf3f3301c522ae068a096))
* add MPC version of ECCVM builder and prover ([#456](https://github.com/TaceoLabs/co-snarks/issues/456)) ([0230ccb](https://github.com/TaceoLabs/co-snarks/commit/0230ccb52bb52bf6ebe291103f8945e4fea61ed2))
* Add support for the embedded_curve_add blackbox function to co-noir ([#367](https://github.com/TaceoLabs/co-snarks/issues/367)) ([0533f22](https://github.com/TaceoLabs/co-snarks/commit/0533f22a8a50e14eb756ee9bf82cfad857dd9722))
* Add the MSM blackbox function to co-noir, which allows to use pedersen hash/commitment ([ffeaa32](https://github.com/TaceoLabs/co-snarks/commit/ffeaa32f754fa16c77bf050486ce871a77908653))
* bump to Barretenberg 0.86.0 ([#373](https://github.com/TaceoLabs/co-snarks/issues/373)) ([55f4ca3](https://github.com/TaceoLabs/co-snarks/commit/55f4ca3211a944cb755e541cfabc4519697ce665))
* dont use rayon::join for networking - added std::thread::scope based join functions ([758b069](https://github.com/TaceoLabs/co-snarks/commit/758b0699ad0ef7bca7401afe9063848eb084873f))
* initial implementation of ProtogalaxyRecursiveVerifier ([#460](https://github.com/TaceoLabs/co-snarks/issues/460)) ([34f38ea](https://github.com/TaceoLabs/co-snarks/commit/34f38ea1c159f95ca8fb803495d1b8da4299788e))
* initial MPC Translator prover and builder implementation ([#467](https://github.com/TaceoLabs/co-snarks/issues/467)) ([ff92fcb](https://github.com/TaceoLabs/co-snarks/commit/ff92fcbe8fa3f2cbc3904d3c28f0890aee3be7fb))
* intial implementation of MergeRecursiveVerifier ([#449](https://github.com/TaceoLabs/co-snarks/issues/449)) ([f7f2158](https://github.com/TaceoLabs/co-snarks/commit/f7f2158a2c3d5db704250ea94b88eb984fa23420))
* Introduce initial implementation of MegaCircuitBuilder for construct_hiding_circuit_key ([#443](https://github.com/TaceoLabs/co-snarks/issues/443)) ([c3104a1](https://github.com/TaceoLabs/co-snarks/commit/c3104a1cf28a34372e10a79a08d667b70000c737))
* move witness and input parsing/sharing to new crates for wasm comp ([333785e](https://github.com/TaceoLabs/co-snarks/commit/333785e275bc9256fb82fd8e2dcf18689bd92862))
* Performance improvements and cleanup for blake2/blake3 ([435fcd3](https://github.com/TaceoLabs/co-snarks/commit/435fcd333080201c7c0274519ff6f6b26fb62d50))
* Rewrite Noir-R1CS solver to get max witness from next constraint ([9d85ce1](https://github.com/TaceoLabs/co-snarks/commit/9d85ce1df31d92ec035ef3dcc599243ac18be46e))
* update rust edition to 2024 ([6ea0ba9](https://github.com/TaceoLabs/co-snarks/commit/6ea0ba9f9f34063e8ab859c1d4ae41d05629a1c0))


### Bug Fixes

* add runtime curve type check in field_shares_to_pointshare in co-acvm ([#423](https://github.com/TaceoLabs/co-snarks/issues/423)) ([819a6ee](https://github.com/TaceoLabs/co-snarks/commit/819a6eeda09b4bc9d0785b46ebf6b7f7b5366b3a))


### Miscellaneous Chores

* upgrade to Noir 1.0.0-beta.14 and BB 3.0.0-nightly.20250916 ([#480](https://github.com/TaceoLabs/co-snarks/issues/480)) ([9bdad27](https://github.com/TaceoLabs/co-snarks/commit/9bdad2793e3ca7f82a291f9e9932cf877ef657eb))


### Code Refactoring

* remove ClientIVC and Mega flavour ([8ac7719](https://github.com/TaceoLabs/co-snarks/commit/8ac7719023577a899fd430886d541c660f0b6b83))
* unify MPC networks, split protocol state and networking to allow fork of state without network, replace io::Error with eyre, merge mpc-core and mpc-types with feature gated mpc-net ([16dbf54](https://github.com/TaceoLabs/co-snarks/commit/16dbf546d8f2d80ad4fa9f5053da19edc7270d3c))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-brillig bumped from 0.3.0 to 0.4.0
    * co-noir-types bumped from 0.1.0 to 0.1.1
    * noir-types bumped from 0.1.0 to 0.1.1
    * co-noir-common bumped from 0.1.0 to 0.2.0
    * mpc-core bumped from 0.9.0 to 0.10.0
    * mpc-net bumped from 0.4.0 to 0.5.0

## [0.6.0](https://github.com/TaceoLabs/co-snarks/compare/co-acvm-v0.5.0...co-acvm-v0.6.0) (2025-04-03)


### ⚠ BREAKING CHANGES

* added a meaningful struct name for brillig success
* acvm now can store values and returns the output of circuit

### Features

* acvm now can store values and returns the output of circuit ([3df88fb](https://github.com/TaceoLabs/co-snarks/commit/3df88fb244b191e03bbd6e6aaede86eaaf7f3d6b))


### Bug Fixes

* Fix brillig int-div for field in plain ([fe55afa](https://github.com/TaceoLabs/co-snarks/commit/fe55afa14cc6e5afa817454a40d4e783bae49b6a))


### Code Refactoring

* added a meaningful struct name for brillig success ([e0af901](https://github.com/TaceoLabs/co-snarks/commit/e0af901e2999cc7e38215f36fe2a647b18d94e0e))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-brillig bumped from 0.2.0 to 0.3.0
    * mpc-core bumped from 0.8.0 to 0.9.0

## [0.5.0](https://github.com/Taceolabs/co-snarks/compare/co-acvm-v0.4.0...co-acvm-v0.5.0) (2025-02-20)


### ⚠ BREAKING CHANGES

* optimize radix sort to take private and public inputs, such that public inputs do not have to be decomposed/bitinjected ([#319](https://github.com/Taceolabs/co-snarks/issues/319))
* a lot of APIs and types changed
* add RAM operations on shared indices ([#314](https://github.com/Taceolabs/co-snarks/issues/314))
* Add extra functionality to rewrite the lookup_read_counts_tags to shared LUTs
* Changed the interface of `LookupTableProvider` trait.
* implemented bitwise_and, bitwise_xor and bitwise_not in the

### Features

* Add blackbox_poseidon2 handling to co-noir ([3c2e811](https://github.com/Taceolabs/co-snarks/commit/3c2e81133b2a5b3a360918bc7d597277d091fb15))
* Add extra functionality to rewrite the lookup_read_counts_tags to shared LUTs ([6fc80f7](https://github.com/Taceolabs/co-snarks/commit/6fc80f7a1a3a2a4f65180edccf03b6ef6b247c37))
* add generating recursive friendly vk; rename stuff to match bb ([6913f52](https://github.com/Taceolabs/co-snarks/commit/6913f52ece6efe2f17362f19ee183aea1d5aa017))
* Add lookup table based on MAESTRO to the MPC core ([#307](https://github.com/Taceolabs/co-snarks/issues/307)) ([2eb6916](https://github.com/Taceolabs/co-snarks/commit/2eb691604c431fa19affe7812e135e5e7dcf5f2e))
* Add packed rep3 version of poseidon2 ([027782f](https://github.com/Taceolabs/co-snarks/commit/027782f48618e68b732e0cf36b9cdf03072452f3))
* Add packed shamir version of poseidon2 ([3ca7426](https://github.com/Taceolabs/co-snarks/commit/3ca742683218d446cf8ce31ab010f33bfbbbe617))
* add RAM operations on shared indices ([#314](https://github.com/Taceolabs/co-snarks/issues/314)) ([c3367a5](https://github.com/Taceolabs/co-snarks/commit/c3367a55b95c3132cfbb6401c6ec1230f46e099c))
* Bridge the co-builder and adapted proving-key generation and fix ([9df797b](https://github.com/Taceolabs/co-snarks/commit/9df797b21af60b7fb3030c58a7739003a627f6fd))
* Cleanup the mpc-core and builder after shared LUT integration ([a691090](https://github.com/Taceolabs/co-snarks/commit/a691090d4933b2e93b9707a48ed430687d2911ba))
* Extend ROM access for coNoir to the MPC setting of having shared indices ([c50809e](https://github.com/Taceolabs/co-snarks/commit/c50809eb891bfa29cb93406781fa4431aec1205b))
* Fixes and cleanup in shared LUTs ([59ac86e](https://github.com/Taceolabs/co-snarks/commit/59ac86ec7cd1d4faf033ffd1ea1ca6ad12d6d2d5))
* implemented bitwise_and, bitwise_xor and bitwise_not in the ([57b8fef](https://github.com/Taceolabs/co-snarks/commit/57b8fef7dd4ea837cbccdc30718833ba72767253))
* Modify co-builder to allow logic constraints (only working in plain so far) ([1115986](https://github.com/Taceolabs/co-snarks/commit/11159866ba8275e63d7bccee6523efe71ac13e6f))
* optimize radix sort to take private and public inputs, such that public inputs do not have to be decomposed/bitinjected ([#319](https://github.com/Taceolabs/co-snarks/issues/319)) ([bd1b6b4](https://github.com/Taceolabs/co-snarks/commit/bd1b6b400c3342b40b40d2532d6fbde1135c109d))
* Starting to adapt the co-builder for handling shared LUTs ([5fda228](https://github.com/Taceolabs/co-snarks/commit/5fda22875cfaca240f23f2b5744997c5da4b93f2))
* works for unique num_bits ([4249c3f](https://github.com/Taceolabs/co-snarks/commit/4249c3fd10209e0feebd025a1287489c4cf74334))


### Bug Fixes

* Fix a bug with shifting BigUints in Range constraints ([#318](https://github.com/Taceolabs/co-snarks/issues/318)) ([06c114a](https://github.com/Taceolabs/co-snarks/commit/06c114a00a58a01ef777473bc8991334b561c3cc))


### Code Refactoring

* co-noir lib usability improvements, added lib usage examples ([18e644e](https://github.com/Taceolabs/co-snarks/commit/18e644ecdf18419fb9b4a071562210c5b0eee0a7))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-brillig bumped from 0.1.0 to 0.2.0
    * mpc-core bumped from 0.7.0 to 0.8.0

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
