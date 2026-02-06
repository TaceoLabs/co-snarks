# Changelog

## [0.7.0](https://github.com/TaceoLabs/co-snarks/compare/co-ultrahonk-v0.6.0...co-ultrahonk-v0.7.0) (2026-02-06)


### ⚠ BREAKING CHANGES

* plain and ZK Rep3 UltraHonk recursive verifier ([#491](https://github.com/TaceoLabs/co-snarks/issues/491))

### Features

* plain and ZK Rep3 UltraHonk recursive verifier ([#491](https://github.com/TaceoLabs/co-snarks/issues/491)) ([7ce7200](https://github.com/TaceoLabs/co-snarks/commit/7ce720060794b9d878b6cf412c493c4e3461b87d))
* upgrade to Noir 1.0.0-beta.15 and BB 3.0.0-nightly.20251104 ([#485](https://github.com/TaceoLabs/co-snarks/issues/485)) ([cd1fb5b](https://github.com/TaceoLabs/co-snarks/commit/cd1fb5b260ba80b81eba2a37e036d180eedc090a))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * noir-types bumped from 0.1.1 to 0.1.2
    * mpc-core bumped from 0.10.0 to 0.11.0
    * ultrahonk bumped from 0.6.0 to 0.7.0
    * co-noir-common bumped from 0.2.0 to 0.3.0

## [0.6.0](https://github.com/TaceoLabs/co-snarks/compare/co-ultrahonk-v0.5.0...co-ultrahonk-v0.6.0) (2025-11-06)


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
* co-protogalaxy prover ([#422](https://github.com/TaceoLabs/co-snarks/issues/422))
* move witness and input parsing/sharing to new crates for wasm comp
* plain protogalaxy prover ([#410](https://github.com/TaceoLabs/co-snarks/issues/410))
* grand product computation with inactive regions ([#411](https://github.com/TaceoLabs/co-snarks/issues/411))
* moves several components from the `ultrahonk` and `co-ultrahonk` crates into the `common` crate
* Add MegaFlavour to the Prover and Verifier
* unify MPC networks, split protocol state and networking to allow fork of state without network, replace io::Error with eyre, merge mpc-core and mpc-types with feature gated mpc-net
* bump to Barretenberg 0.86.0 ([#373](https://github.com/TaceoLabs/co-snarks/issues/373))
* rename io_mul_vec to reshare_vec
* move MPC types and share/combine into new mpc-types crate, rename co-circom-snarks to co-circom-types

### Features

* add (co-)merge-prover and common crates ([f7eea60](https://github.com/TaceoLabs/co-snarks/commit/f7eea60e71e23ff31aa9e48c801eb3d193a3a4ad))
* add extension traits for REP3 and Shamir networks ([0c15da8](https://github.com/TaceoLabs/co-snarks/commit/0c15da81550f35c7aaef77d5143824a9436d5731))
* add functionality to compute transcript in MPC and integrate it ([#472](https://github.com/TaceoLabs/co-snarks/issues/472)) ([e636308](https://github.com/TaceoLabs/co-snarks/commit/e636308efdf115149d53e05e70b157cfe5babb6c))
* Add MegaFlavour to the Prover and Verifier ([06ab1a9](https://github.com/TaceoLabs/co-snarks/commit/06ab1a95f0a8204e377f8e07ee2e0c898fbf6379))
* add MPC version of ECCVM builder and prover ([#456](https://github.com/TaceoLabs/co-snarks/issues/456)) ([0230ccb](https://github.com/TaceoLabs/co-snarks/commit/0230ccb52bb52bf6ebe291103f8945e4fea61ed2))
* add plain ECCVM Prover ([#409](https://github.com/TaceoLabs/co-snarks/issues/409)) ([dc5f175](https://github.com/TaceoLabs/co-snarks/commit/dc5f175c1f1c61a95731129d10995b0f6122a1c1))
* bump to Barretenberg 0.86.0 ([#373](https://github.com/TaceoLabs/co-snarks/issues/373)) ([55f4ca3](https://github.com/TaceoLabs/co-snarks/commit/55f4ca3211a944cb755e541cfabc4519697ce665))
* co-protogalaxy prover ([#422](https://github.com/TaceoLabs/co-snarks/issues/422)) ([4de48e8](https://github.com/TaceoLabs/co-snarks/commit/4de48e8b99fef2c531111a828622731ba3d43de9))
* initial implementation of DeciderRecursiveVerifier ([#464](https://github.com/TaceoLabs/co-snarks/issues/464)) ([74df287](https://github.com/TaceoLabs/co-snarks/commit/74df28773c269f067253e70822c6f96806b32e48))
* initial implementation of ProtogalaxyRecursiveVerifier ([#460](https://github.com/TaceoLabs/co-snarks/issues/460)) ([34f38ea](https://github.com/TaceoLabs/co-snarks/commit/34f38ea1c159f95ca8fb803495d1b8da4299788e))
* initial MPC Translator prover and builder implementation ([#467](https://github.com/TaceoLabs/co-snarks/issues/467)) ([ff92fcb](https://github.com/TaceoLabs/co-snarks/commit/ff92fcbe8fa3f2cbc3904d3c28f0890aee3be7fb))
* intial implementation of MergeRecursiveVerifier ([#449](https://github.com/TaceoLabs/co-snarks/issues/449)) ([f7f2158](https://github.com/TaceoLabs/co-snarks/commit/f7f2158a2c3d5db704250ea94b88eb984fa23420))
* Introduce initial implementation of MegaCircuitBuilder for construct_hiding_circuit_key ([#443](https://github.com/TaceoLabs/co-snarks/issues/443)) ([c3104a1](https://github.com/TaceoLabs/co-snarks/commit/c3104a1cf28a34372e10a79a08d667b70000c737))
* move HonkProof and the corresponding field serde to noir-types ([b9821e5](https://github.com/TaceoLabs/co-snarks/commit/b9821e5202855bb9cd931ae32fe9e7d3e5b01378))
* move witness and input parsing/sharing to new crates for wasm comp ([333785e](https://github.com/TaceoLabs/co-snarks/commit/333785e275bc9256fb82fd8e2dcf18689bd92862))
* plain protogalaxy prover ([#410](https://github.com/TaceoLabs/co-snarks/issues/410)) ([42d49f5](https://github.com/TaceoLabs/co-snarks/commit/42d49f55a93b48e01c133f7ca5d7fefc559fd470))
* update rust edition to 2024 ([6ea0ba9](https://github.com/TaceoLabs/co-snarks/commit/6ea0ba9f9f34063e8ab859c1d4ae41d05629a1c0))


### Bug Fixes

* grand product computation with inactive regions ([#411](https://github.com/TaceoLabs/co-snarks/issues/411)) ([a2501da](https://github.com/TaceoLabs/co-snarks/commit/a2501da24ad594f334645d23f7ab5311f98721e1))


### Miscellaneous Chores

* upgrade to Noir 1.0.0-beta.14 and BB 3.0.0-nightly.20250916 ([#480](https://github.com/TaceoLabs/co-snarks/issues/480)) ([9bdad27](https://github.com/TaceoLabs/co-snarks/commit/9bdad2793e3ca7f82a291f9e9932cf877ef657eb))


### Code Refactoring

* move MPC types and share/combine into new mpc-types crate, rename co-circom-snarks to co-circom-types ([31b773a](https://github.com/TaceoLabs/co-snarks/commit/31b773aa71a5e872c25754de7805b02647b65688))
* remove ClientIVC and Mega flavour ([8ac7719](https://github.com/TaceoLabs/co-snarks/commit/8ac7719023577a899fd430886d541c660f0b6b83))
* rename io_mul_vec to reshare_vec ([7067486](https://github.com/TaceoLabs/co-snarks/commit/70674869e91950a59b68272127781ecf56d77094))
* unify MPC networks, split protocol state and networking to allow fork of state without network, replace io::Error with eyre, merge mpc-core and mpc-types with feature gated mpc-net ([16dbf54](https://github.com/TaceoLabs/co-snarks/commit/16dbf546d8f2d80ad4fa9f5053da19edc7270d3c))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-acvm bumped from 0.6.0 to 0.7.0
    * co-builder bumped from 0.4.0 to 0.5.0
    * noir-types bumped from 0.1.0 to 0.1.1
    * mpc-core bumped from 0.9.0 to 0.10.0
    * mpc-net bumped from 0.4.0 to 0.5.0
    * ultrahonk bumped from 0.5.0 to 0.6.0
    * co-noir-common bumped from 0.1.0 to 0.2.0

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
