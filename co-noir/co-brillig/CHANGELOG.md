# Changelog

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
