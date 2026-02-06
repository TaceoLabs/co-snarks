# Changelog

## [0.6.0](https://github.com/TaceoLabs/co-snarks/compare/co-builder-v0.5.0...co-builder-v0.6.0) (2026-02-06)


### ⚠ BREAKING CHANGES

* plain and ZK Rep3 UltraHonk recursive verifier ([#491](https://github.com/TaceoLabs/co-snarks/issues/491))

### Features

* plain and ZK Rep3 UltraHonk recursive verifier ([#491](https://github.com/TaceoLabs/co-snarks/issues/491)) ([7ce7200](https://github.com/TaceoLabs/co-snarks/commit/7ce720060794b9d878b6cf412c493c4e3461b87d))
* upgrade to Noir 1.0.0-beta.15 and BB 3.0.0-nightly.20251104 ([#485](https://github.com/TaceoLabs/co-snarks/issues/485)) ([cd1fb5b](https://github.com/TaceoLabs/co-snarks/commit/cd1fb5b260ba80b81eba2a37e036d180eedc090a))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-acvm bumped from 0.7.0 to 0.8.0
    * noir-types bumped from 0.1.1 to 0.1.2
    * mpc-core bumped from 0.10.0 to 0.11.0
    * co-noir-common bumped from 0.2.0 to 0.3.0
    * co-ultrahonk bumped from 0.6.0 to 0.7.0

## [0.5.0](https://github.com/TaceoLabs/co-snarks/compare/co-builder-v0.4.0...co-builder-v0.5.0) (2025-11-06)


### ⚠ BREAKING CHANGES

* upgrade to Noir 1.0.0-beta.14 and BB 3.0.0-nightly.20250916 ([#480](https://github.com/TaceoLabs/co-snarks/issues/480))
* remove ClientIVC and Mega flavour
* add functionality to compute transcript in MPC and integrate it ([#472](https://github.com/TaceoLabs/co-snarks/issues/472))
* initial implementation of DeciderRecursiveVerifier ([#464](https://github.com/TaceoLabs/co-snarks/issues/464))
* initial implementation of ProtogalaxyRecursiveVerifier ([#460](https://github.com/TaceoLabs/co-snarks/issues/460))
* intial implementation of MergeRecursiveVerifier ([#449](https://github.com/TaceoLabs/co-snarks/issues/449))
* Introduce initial implementation of MegaCircuitBuilder for construct_hiding_circuit_key ([#443](https://github.com/TaceoLabs/co-snarks/issues/443))
* add MPC version of ECCVM builder and prover ([#456](https://github.com/TaceoLabs/co-snarks/issues/456))
* move HonkProof and the corresponding field serde to noir-types
* move witness and input parsing/sharing to new crates for wasm comp
* plain protogalaxy prover ([#410](https://github.com/TaceoLabs/co-snarks/issues/410))
* Add MegaFlavour to the Prover and Verifier
* unify MPC networks, split protocol state and networking to allow fork of state without network, replace io::Error with eyre, merge mpc-core and mpc-types with feature gated mpc-net
* bump to Barretenberg 0.86.0 ([#373](https://github.com/TaceoLabs/co-snarks/issues/373))
* Add support for the embedded_curve_add blackbox function to co-noir ([#367](https://github.com/TaceoLabs/co-snarks/issues/367))
* Performance improvements and cleanup for blake2/blake3
* add BLAKE3 blackbox function to coNoir
* add BLAKE2s blackbox function to coNoir
* add Bristol Fashion parsing for GC, also adds the SHA256 blackbox ([#359](https://github.com/TaceoLabs/co-snarks/issues/359))
* Add the MSM blackbox function to co-noir, which allows to use pedersen hash/commitment

### Features

* Add AES blackbox functionality ([fd7cd49](https://github.com/TaceoLabs/co-snarks/commit/fd7cd496a1fd21e85aa70c0bd2c5cd7aed69fece))
* add BLAKE2s blackbox function to coNoir ([e98fb7d](https://github.com/TaceoLabs/co-snarks/commit/e98fb7dd60f52d936f07b3e3a74797dfb091e9f3))
* add BLAKE3 blackbox function to coNoir ([ddcb10e](https://github.com/TaceoLabs/co-snarks/commit/ddcb10e5d685072279b8f11b6935636fb74ecaf0))
* add Bristol Fashion parsing for GC, also adds the SHA256 blackbox ([#359](https://github.com/TaceoLabs/co-snarks/issues/359)) ([f8509ef](https://github.com/TaceoLabs/co-snarks/commit/f8509ef8147bf29072ba67b4ac0f489546eea2c9))
* add builder type transcript for recursion ([#433](https://github.com/TaceoLabs/co-snarks/issues/433)) ([2177ad5](https://github.com/TaceoLabs/co-snarks/commit/2177ad54a18c7deeb0d525379095b22ed24f3269))
* add functionality to compute transcript in MPC and integrate it ([#472](https://github.com/TaceoLabs/co-snarks/issues/472)) ([e636308](https://github.com/TaceoLabs/co-snarks/commit/e636308efdf115149d53e05e70b157cfe5babb6c))
* add MAESTRO style lut protocol for curve points ([4da5f74](https://github.com/TaceoLabs/co-snarks/commit/4da5f74bed1350c4574bf3f3301c522ae068a096))
* Add MegaFlavour to the Prover and Verifier ([06ab1a9](https://github.com/TaceoLabs/co-snarks/commit/06ab1a95f0a8204e377f8e07ee2e0c898fbf6379))
* add MPC version of ECCVM builder and prover ([#456](https://github.com/TaceoLabs/co-snarks/issues/456)) ([0230ccb](https://github.com/TaceoLabs/co-snarks/commit/0230ccb52bb52bf6ebe291103f8945e4fea61ed2))
* add plain ECCVM Prover ([#409](https://github.com/TaceoLabs/co-snarks/issues/409)) ([dc5f175](https://github.com/TaceoLabs/co-snarks/commit/dc5f175c1f1c61a95731129d10995b0f6122a1c1))
* Add support for the embedded_curve_add blackbox function to co-noir ([#367](https://github.com/TaceoLabs/co-snarks/issues/367)) ([0533f22](https://github.com/TaceoLabs/co-snarks/commit/0533f22a8a50e14eb756ee9bf82cfad857dd9722))
* Add the MSM blackbox function to co-noir, which allows to use pedersen hash/commitment ([ffeaa32](https://github.com/TaceoLabs/co-snarks/commit/ffeaa32f754fa16c77bf050486ce871a77908653))
* bump to Barretenberg 0.86.0 ([#373](https://github.com/TaceoLabs/co-snarks/issues/373)) ([55f4ca3](https://github.com/TaceoLabs/co-snarks/commit/55f4ca3211a944cb755e541cfabc4519697ce665))
* initial implementation of DeciderRecursiveVerifier ([#464](https://github.com/TaceoLabs/co-snarks/issues/464)) ([74df287](https://github.com/TaceoLabs/co-snarks/commit/74df28773c269f067253e70822c6f96806b32e48))
* initial implementation of ProtogalaxyRecursiveVerifier ([#460](https://github.com/TaceoLabs/co-snarks/issues/460)) ([34f38ea](https://github.com/TaceoLabs/co-snarks/commit/34f38ea1c159f95ca8fb803495d1b8da4299788e))
* initial MPC Translator prover and builder implementation ([#467](https://github.com/TaceoLabs/co-snarks/issues/467)) ([ff92fcb](https://github.com/TaceoLabs/co-snarks/commit/ff92fcbe8fa3f2cbc3904d3c28f0890aee3be7fb))
* intial implementation of MergeRecursiveVerifier ([#449](https://github.com/TaceoLabs/co-snarks/issues/449)) ([f7f2158](https://github.com/TaceoLabs/co-snarks/commit/f7f2158a2c3d5db704250ea94b88eb984fa23420))
* Introduce initial implementation of MegaCircuitBuilder for construct_hiding_circuit_key ([#443](https://github.com/TaceoLabs/co-snarks/issues/443)) ([c3104a1](https://github.com/TaceoLabs/co-snarks/commit/c3104a1cf28a34372e10a79a08d667b70000c737))
* move HonkProof and the corresponding field serde to noir-types ([b9821e5](https://github.com/TaceoLabs/co-snarks/commit/b9821e5202855bb9cd931ae32fe9e7d3e5b01378))
* move witness and input parsing/sharing to new crates for wasm comp ([333785e](https://github.com/TaceoLabs/co-snarks/commit/333785e275bc9256fb82fd8e2dcf18689bd92862))
* Performance improvements and cleanup for blake2/blake3 ([435fcd3](https://github.com/TaceoLabs/co-snarks/commit/435fcd333080201c7c0274519ff6f6b26fb62d50))
* plain protogalaxy prover ([#410](https://github.com/TaceoLabs/co-snarks/issues/410)) ([42d49f5](https://github.com/TaceoLabs/co-snarks/commit/42d49f55a93b48e01c133f7ca5d7fefc559fd470))
* plain translator prover ([#425](https://github.com/TaceoLabs/co-snarks/issues/425)) ([14167b3](https://github.com/TaceoLabs/co-snarks/commit/14167b33e5b15e3d35bc3971913573d29eb92da9))
* update rust edition to 2024 ([6ea0ba9](https://github.com/TaceoLabs/co-snarks/commit/6ea0ba9f9f34063e8ab859c1d4ae41d05629a1c0))


### Bug Fixes

* factor_roots for r=0 to reduce length by 1 ([#434](https://github.com/TaceoLabs/co-snarks/issues/434)) ([a4f0b9c](https://github.com/TaceoLabs/co-snarks/commit/a4f0b9c09fddf7f863fa66dfbfd7c7d129475638))


### Miscellaneous Chores

* upgrade to Noir 1.0.0-beta.14 and BB 3.0.0-nightly.20250916 ([#480](https://github.com/TaceoLabs/co-snarks/issues/480)) ([9bdad27](https://github.com/TaceoLabs/co-snarks/commit/9bdad2793e3ca7f82a291f9e9932cf877ef657eb))


### Code Refactoring

* remove ClientIVC and Mega flavour ([8ac7719](https://github.com/TaceoLabs/co-snarks/commit/8ac7719023577a899fd430886d541c660f0b6b83))
* unify MPC networks, split protocol state and networking to allow fork of state without network, replace io::Error with eyre, merge mpc-core and mpc-types with feature gated mpc-net ([16dbf54](https://github.com/TaceoLabs/co-snarks/commit/16dbf546d8f2d80ad4fa9f5053da19edc7270d3c))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-acvm bumped from 0.6.0 to 0.7.0
    * noir-types bumped from 0.1.0 to 0.1.1
    * mpc-core bumped from 0.9.0 to 0.10.0
    * co-noir-common bumped from 0.1.0 to 0.2.0
    * mpc-net bumped from 0.4.0 to 0.5.0
  * dev-dependencies
    * mpc-net bumped from 0.4.0 to 0.5.0

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
