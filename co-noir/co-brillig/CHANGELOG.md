# Changelog

## [0.4.1](https://github.com/TaceoLabs/co-snarks/compare/co-brillig-v0.4.0...co-brillig-v0.4.1) (2026-02-06)


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * mpc-core bumped from 0.10.0 to 0.11.0

## [0.4.0](https://github.com/TaceoLabs/co-snarks/compare/co-brillig-v0.3.0...co-brillig-v0.4.0) (2025-11-06)


### ⚠ BREAKING CHANGES

* upgrade to Noir 1.0.0-beta.14 and BB 3.0.0-nightly.20250916 ([#480](https://github.com/TaceoLabs/co-snarks/issues/480))
* unify MPC networks, split protocol state and networking to allow fork of state without network, replace io::Error with eyre, merge mpc-core and mpc-types with feature gated mpc-net

### Features

* add Brillig Opcode Not ([#479](https://github.com/TaceoLabs/co-snarks/issues/479)) ([51560be](https://github.com/TaceoLabs/co-snarks/commit/51560be38f3ad272703f1dc614143ed0201c69d2))
* add CoNoir solver which allows some precomputed witnesses ([6d7d85e](https://github.com/TaceoLabs/co-snarks/commit/6d7d85eea200a33507d4e6c22c7055d776cb6dae))
* bump to Noir-1.0.0-beta.4 ([9403dae](https://github.com/TaceoLabs/co-snarks/commit/9403daeaf977120a581d9265bea9ed5df8203f3a))
* update rust edition to 2024 ([6ea0ba9](https://github.com/TaceoLabs/co-snarks/commit/6ea0ba9f9f34063e8ab859c1d4ae41d05629a1c0))


### Miscellaneous Chores

* upgrade to Noir 1.0.0-beta.14 and BB 3.0.0-nightly.20250916 ([#480](https://github.com/TaceoLabs/co-snarks/issues/480)) ([9bdad27](https://github.com/TaceoLabs/co-snarks/commit/9bdad2793e3ca7f82a291f9e9932cf877ef657eb))


### Code Refactoring

* unify MPC networks, split protocol state and networking to allow fork of state without network, replace io::Error with eyre, merge mpc-core and mpc-types with feature gated mpc-net ([16dbf54](https://github.com/TaceoLabs/co-snarks/commit/16dbf546d8f2d80ad4fa9f5053da19edc7270d3c))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * mpc-core bumped from 0.9.0 to 0.10.0
    * mpc-net bumped from 0.4.0 to 0.5.0

## [0.3.0](https://github.com/TaceoLabs/co-snarks/compare/co-brillig-v0.2.0...co-brillig-v0.3.0) (2025-04-03)


### ⚠ BREAKING CHANGES

* added a meaningful struct name for brillig succecss
* acvm now can store values and returns the output of circuit

### Features

* acvm now can store values and returns the output of circuit ([3df88fb](https://github.com/TaceoLabs/co-snarks/commit/3df88fb244b191e03bbd6e6aaede86eaaf7f3d6b))


### Bug Fixes

* Fix brillig int-div for field in plain ([fe55afa](https://github.com/TaceoLabs/co-snarks/commit/fe55afa14cc6e5afa817454a40d4e783bae49b6a))


### Code Refactoring

* added a meaningful struct name for brillig succecss ([e0af901](https://github.com/TaceoLabs/co-snarks/commit/e0af901e2999cc7e38215f36fe2a647b18d94e0e))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * mpc-core bumped from 0.8.0 to 0.9.0

## [0.2.0](https://github.com/Taceolabs/co-snarks/compare/co-brillig-v0.1.0...co-brillig-v0.2.0) (2025-02-20)


### ⚠ BREAKING CHANGES

* ark to 0.5.0, co-noir witext works with 1.0.0-beta.2
* add RAM operations on shared indices ([#314](https://github.com/Taceolabs/co-snarks/issues/314))
* implemented bitwise_and, bitwise_xor and bitwise_not in the

### Features

* add public/shared int division ([4286c6a](https://github.com/Taceolabs/co-snarks/commit/4286c6a7d7e42335c056c2b3a858a7dbd51bf107))
* add RAM operations on shared indices ([#314](https://github.com/Taceolabs/co-snarks/issues/314)) ([c3367a5](https://github.com/Taceolabs/co-snarks/commit/c3367a55b95c3132cfbb6401c6ec1230f46e099c))
* add shared/public int division ([d1d2121](https://github.com/Taceolabs/co-snarks/commit/d1d21215997e1a854d2919db47a8b7bbbc541747))
* add shared/shared to co-brillig ([b54b4ee](https://github.com/Taceolabs/co-snarks/commit/b54b4eeea091431a7f06eb0a87eb5e0e87ceb2b4))
* Add some more missing BinaryIntOps to co-brillig ([#315](https://github.com/Taceolabs/co-snarks/issues/315)) ([e96a712](https://github.com/Taceolabs/co-snarks/commit/e96a712dfa987fb39e17232ef11d067b29b62aef))
* ark to 0.5.0, co-noir witext works with 1.0.0-beta.2 ([8a466df](https://github.com/Taceolabs/co-snarks/commit/8a466dffde68d64bed8265e1336e454559898602))
* bits case for shared/public ([4beb691](https://github.com/Taceolabs/co-snarks/commit/4beb6910f037055a0bc08aae30dbe2995aae5bf4))
* implemented bitwise_and, bitwise_xor and bitwise_not in the ([57b8fef](https://github.com/Taceolabs/co-snarks/commit/57b8fef7dd4ea837cbccdc30718833ba72767253))
* Modify co-builder to allow logic constraints (only working in plain so far) ([1115986](https://github.com/Taceolabs/co-snarks/commit/11159866ba8275e63d7bccee6523efe71ac13e6f))
* to_radix for public radix ([8ccd753](https://github.com/Taceolabs/co-snarks/commit/8ccd753975d8a4e11fe8ed90cc757d9739d988dd))
* to_radix for public val/shared radix ([540780b](https://github.com/Taceolabs/co-snarks/commit/540780b81d4ee4772df09a7997c42af6f476ff6d))
* to_radix for shared val/shared radix ([ecbb1d7](https://github.com/Taceolabs/co-snarks/commit/ecbb1d7137713939cab0ed5010f00404e81f626a))


### Bug Fixes

* to_radix for weird constelations ([24c20c1](https://github.com/Taceolabs/co-snarks/commit/24c20c1ecc62dcc2f168ff8e0150a0c38fe31fed))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * mpc-core bumped from 0.7.0 to 0.8.0

## [0.1.0](https://github.com/TaceoLabs/co-snarks/compare/co-brillig-v0.0.1...co-brillig-v0.1.0) (2024-12-16)


### ⚠ BREAKING CHANGES

* **!:** Added functionality to traits of brillig/acvm
* Added docs for brillig. Also updated the trait to better match the functionallity
* Moved the brillig VM from lib to seperate module
* modified brillig driver trait
* added more impls to brillig trait
* modified traits for ACVM
* Moved MPC impl for NoirWitnessExtension to co-brillig. This is SubjectToChange!

### Features

* **!:** first version of shared if by forking brillig ([a25e4a5](https://github.com/TaceoLabs/co-snarks/commit/a25e4a5cb5cdc912197871803c5872c08777b8a7))
* Added co-brillig crate and first impl ([94d5978](https://github.com/TaceoLabs/co-snarks/commit/94d5978454f8b9f1b278ef1d7ad42e58361b2c11))
* added more functionality for Brillig-VM, two tests working ([b9778a0](https://github.com/TaceoLabs/co-snarks/commit/b9778a0b1f346f7a3160456f06e71d4173a9d616))
* first plain unconstrained fn working ([56e1c80](https://github.com/TaceoLabs/co-snarks/commit/56e1c801e6d51c8e35f1f1b1b2b007d80f050999))
* get_bytes test works with plain driver ([3f28bc5](https://github.com/TaceoLabs/co-snarks/commit/3f28bc576f13f700d6d9628968b00d4eaf6350f4))
* implement many featuers for the co-brillig rep3 backend ([#284](https://github.com/TaceoLabs/co-snarks/issues/284)) ([11e0b03](https://github.com/TaceoLabs/co-snarks/commit/11e0b03b8ca437e48e0ac80e2cff870f530c58c0))
* predicate check for brillig, all tests working now ([64b88ce](https://github.com/TaceoLabs/co-snarks/commit/64b88cee4f6e437e8eb32f453410030231fab7c6))
* shamir impls ([064ca06](https://github.com/TaceoLabs/co-snarks/commit/064ca06b25d9acd0a04e0a892f1b47ee94a16f39))
* some more opcodes and started bin int ops ([e99d9a4](https://github.com/TaceoLabs/co-snarks/commit/e99d9a4af52c84b0f54864c06218b2b23154df85))
* start bin_field_ops and add more test vectors ([736a6bd](https://github.com/TaceoLabs/co-snarks/commit/736a6bde98836614416e7f7b1d45efc417e15b43))


### Documentation

* Added docs for brillig. Also updated the trait to better match the functionallity ([a2df63a](https://github.com/TaceoLabs/co-snarks/commit/a2df63aa1048364e484bde31013a1c5bbe4a9da3))


### Code Refactoring

* Moved the brillig VM from lib to seperate module ([36f241b](https://github.com/TaceoLabs/co-snarks/commit/36f241b46c6a973b3a43e24872e38da9605011fa))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * mpc-core bumped from 0.6.0 to 0.7.0
