# Changelog

* The following workspace dependencies were updated
  * dependencies
    * circom-mpc-vm bumped from 0.4.1 to 0.4.2
  * dev-dependencies
    * co-groth16 bumped from 0.5.0 to 0.5.1
    * mpc-core bumped from 0.4.0 to 0.5.0

## [0.9.1](https://github.com/TaceoLabs/co-snarks/compare/circom-mpc-compiler-v0.9.0...circom-mpc-compiler-v0.9.1) (2025-04-03)


### Bug Fixes

* added possibility for mul ret vals in circom wtns extension from compute bucket ([06bc96b](https://github.com/TaceoLabs/co-snarks/commit/06bc96b7048a95756ba535c23d132fc9eae369a5))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-types bumped from 0.8.0 to 0.9.0
    * circom-mpc-vm bumped from 0.7.0 to 0.8.0
  * dev-dependencies
    * co-groth16 bumped from 0.8.0 to 0.9.0
    * mpc-core bumped from 0.8.0 to 0.9.0

## [0.9.0](https://github.com/Taceolabs/co-snarks/compare/circom-mpc-compiler-v0.8.0...circom-mpc-compiler-v0.9.0) (2025-02-20)


### ⚠ BREAKING CHANGES

* a lot of APIs and types changed

### Code Refactoring

* co-circom lib usability improvents, added lib usage examples ([5768011](https://github.com/Taceolabs/co-snarks/commit/576801192076a27c75cd07fe1ec62244700bb934))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-types bumped from 0.7.0 to 0.8.0
    * circom-mpc-vm bumped from 0.6.0 to 0.7.0
  * dev-dependencies
    * co-groth16 bumped from 0.7.0 to 0.8.0
    * mpc-core bumped from 0.7.0 to 0.8.0

## [0.8.0](https://github.com/TaceoLabs/co-snarks/compare/circom-mpc-compiler-v0.7.0...circom-mpc-compiler-v0.8.0) (2024-12-16)


### ⚠ BREAKING CHANGES

* Opcode:Eq now holds the number of elements to compare.

### Bug Fixes

* fixed a bug where eq checks for array did not work properly ([#283](https://github.com/TaceoLabs/co-snarks/issues/283)) ([3193574](https://github.com/TaceoLabs/co-snarks/commit/319357417be28cbe4da82b3dc4d2903b4183afb1))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-types bumped from 0.6.0 to 0.7.0
    * circom-mpc-vm bumped from 0.5.0 to 0.6.0
  * dev-dependencies
    * co-groth16 bumped from 0.6.0 to 0.7.0
    * mpc-core bumped from 0.6.0 to 0.7.0

## [0.7.0](https://github.com/TaceoLabs/co-snarks/compare/circom-mpc-compiler-v0.6.1...circom-mpc-compiler-v0.7.0) (2024-11-12)


### ⚠ BREAKING CHANGES

* MPC accelerator changed public API. Also now stores #output signals in component
* Also added name of cmp to Component Init instead of only symbol
* input to compiler now takes PathBuf
* In accordance to the circom 2.2.0 release, the default simplification level is now O1
* run and run_with_flat methods on WitnessExtension now consume self again
* Small refactor to use API changes

### Features

* added run_and_get_network to CircomRep3VmWitnessExtension, changed run and run_with_flat back to consume self ([b362504](https://github.com/TaceoLabs/co-snarks/commit/b362504d8a5affa8a5e8eca3f214c04951ad5b50))
* added stub for cmp accelerator ([bc1525e](https://github.com/TaceoLabs/co-snarks/commit/bc1525effdd38e9308cc4a0050b7e20c97be1974))
* allow to set circom simplification level via CLI ([b0d64ba](https://github.com/TaceoLabs/co-snarks/commit/b0d64ba683c1dbab67102d31f1e1ab80108fb7d9))
* num2bits accelerator working ([13cdf10](https://github.com/TaceoLabs/co-snarks/commit/13cdf100b79c642649d31501833ed182dd7e8b90))
* provide binary to inline circom sources ([#232](https://github.com/TaceoLabs/co-snarks/issues/232)) ([2f4722e](https://github.com/TaceoLabs/co-snarks/commit/2f4722ee95905f9c5c280e197a1c0113cffadff1))


### Bug Fixes

* get the size from new SizeOption type ([9417877](https://github.com/TaceoLabs/co-snarks/commit/941787746d9bdc60d5327a009bd3b766bf74ea2e))
* handle new AccessType type ([bc519ba](https://github.com/TaceoLabs/co-snarks/commit/bc519ba7d48d9bd7995c485568dadcd3e4d1eaf9))
* map new circom type to our own type ([95abe2e](https://github.com/TaceoLabs/co-snarks/commit/95abe2e473c400439d81c12c612f352f4ae55fe5))
* pass field into circom parser ([a8ed24e](https://github.com/TaceoLabs/co-snarks/commit/a8ed24ef204934eb3892781db205f4d30acec6ba))


### Code Refactoring

* input to compiler now takes PathBuf ([9f36774](https://github.com/TaceoLabs/co-snarks/commit/9f36774f0ff93c3c3abd28efae6599fc531bb1fb))
* Small refactor to use API changes ([639f438](https://github.com/TaceoLabs/co-snarks/commit/639f438adc9480e1b6c0e2d1f068ed82adee3cf1))
* update to circom 2.2.0 behavior ([2b4dbc9](https://github.com/TaceoLabs/co-snarks/commit/2b4dbc9d34155cde2d7e2e30b6a4068170954804))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-types bumped from 0.5.0 to 0.6.0
    * circom-mpc-vm bumped from 0.4.2 to 0.5.0
  * dev-dependencies
    * co-groth16 bumped from 0.5.1 to 0.6.0
    * mpc-core bumped from 0.5.0 to 0.6.0

## [0.6.0](https://github.com/TaceoLabs/collaborative-circom/compare/circom-mpc-compiler-v0.5.0...circom-mpc-compiler-v0.6.0) (2024-08-21)


### ⚠ BREAKING CHANGES

* we hardcoded bn128 as prime for the compiler. We now give either bn128 or bls12381 depending on curve. Introduces new trait bounds therefore breaking change
* Removed the builder step for the compiler as we now have a config anyways. Moved some stuff to the config

### Bug Fixes

* fixes prime for the mpc compiler ([5712184](https://github.com/TaceoLabs/collaborative-circom/commit/5712184748488b7bab735b456be25e9cbbdb5ff7))


### Code Refactoring

* Removed builder pattern for compiler ([260d5e8](https://github.com/TaceoLabs/collaborative-circom/commit/260d5e89d9ba5e3e4487b9f660bdac455f1fe450))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-types bumped from 0.4.0 to 0.5.0
    * circom-mpc-vm bumped from 0.4.0 to 0.4.1
  * dev-dependencies
    * co-groth16 bumped from 0.4.0 to 0.5.0
    * mpc-core bumped from 0.3.0 to 0.4.0

## [0.5.0](https://github.com/TaceoLabs/collaborative-circom/compare/circom-mpc-compiler-v0.4.0...circom-mpc-compiler-v0.5.0) (2024-08-14)


### ⚠ BREAKING CHANGES

* We renamed all crate names from collaborative-* to co-* for brevity, and also shortened `Collaborative` to `Co` in many types.

### Code Refactoring

* renamed crates to co-* ([#161](https://github.com/TaceoLabs/collaborative-circom/issues/161)) ([37f3493](https://github.com/TaceoLabs/collaborative-circom/commit/37f3493b25e41b43bbc8a89e281ae2dcb4b95484))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-mpc-vm bumped from 0.3.0 to 0.4.0
  * dev-dependencies
    * co-groth16 bumped from 0.3.0 to 0.4.0

## [0.4.0](https://github.com/TaceoLabs/collaborative-circom/compare/circom-mpc-compiler-v0.3.0...circom-mpc-compiler-v0.4.0) (2024-08-14)


### ⚠ BREAKING CHANGES

* new config implementation, config option to allow leaking of secret values in logs ([#132](https://github.com/TaceoLabs/collaborative-circom/issues/132))
* the function signature of the two run methods of the witness extension now changed. To retrieve the shared witness now another call `into_shared_witness()` is necessary.

### Features

* can now retrieve certain outputs after witness extension by name ([d9e3399](https://github.com/TaceoLabs/collaborative-circom/commit/d9e33996d10cea5f8197d507a13ed9087f0f4c20))
* plonk support ([9b65797](https://github.com/TaceoLabs/collaborative-circom/commit/9b6579724f6f5ba4fc6af8a98d386b96818dc08b))


### Code Refactoring

* new config implementation, config option to allow leaking of secret values in logs ([#132](https://github.com/TaceoLabs/collaborative-circom/issues/132)) ([964b04f](https://github.com/TaceoLabs/collaborative-circom/commit/964b04f47e8d491ae140cb7c10c596e1c40b6b5c))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-mpc-vm bumped from 0.2.0 to 0.3.0
  * dev-dependencies
    * circom-types bumped from 0.3.0 to 0.4.0
    * collaborative-groth16 bumped from 0.2.1 to 0.3.0
    * mpc-core bumped from 0.2.1 to 0.3.0

## [0.3.0](https://github.com/TaceoLabs/collaborative-circom/compare/circom-mpc-compiler-v0.2.0...circom-mpc-compiler-v0.3.0) (2024-07-10)


### ⚠ BREAKING CHANGES

* has_inputs element for CreateCmp opcode

### Code Refactoring

* has_inputs element for CreateCmp opcode ([3c88182](https://github.com/TaceoLabs/collaborative-circom/commit/3c8818205e60b765ffa70b0ddc59c939569209e6))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-mpc-vm bumped from 0.1.1 to 0.2.0
  * dev-dependencies
    * circom-types bumped from 0.2.0 to 0.3.0
    * collaborative-groth16 bumped from 0.2.0 to 0.2.1
    * mpc-core bumped from 0.2.0 to 0.2.1

## [0.2.0](https://github.com/TaceoLabs/collaborative-circom/compare/circom-mpc-compiler-v0.1.0...circom-mpc-compiler-v0.2.0) (2024-07-09)


### ⚠ BREAKING CHANGES

* removed link_libraries call for CompilerBuilder

### Bug Fixes

* correct order input array for sub_comp and naively creates all components even if not necessary ([6d40a94](https://github.com/TaceoLabs/collaborative-circom/commit/6d40a9465b5351f0d30ac9f19c2ee61f09ccdbbb))
* vector in/outputs for sub component ([#90](https://github.com/TaceoLabs/collaborative-circom/issues/90)) ([f148375](https://github.com/TaceoLabs/collaborative-circom/commit/f148375c3ca8674f1ecd08bb30c1e6bcf2dbb4a9))


### Code Refactoring

* removed link_libraries call for CompilerBuilder ([e5583e6](https://github.com/TaceoLabs/collaborative-circom/commit/e5583e6f3f8851f74ca482dda9e9eb50183b8ef5))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-mpc-vm bumped from 0.1.0 to 0.1.1
  * dev-dependencies
    * circom-types bumped from 0.1.0 to 0.2.0
    * collaborative-groth16 bumped from 0.1.0 to 0.2.0
    * mpc-core bumped from 0.1.0 to 0.2.0

## [0.1.0](https://github.com/TaceoLabs/collaborative-circom/compare/circom-mpc-compiler-v0.0.1...circom-mpc-compiler-v0.1.0) (2024-06-14)


### Features

* added better assert message when assert fails ([ae0d8be](https://github.com/TaceoLabs/collaborative-circom/commit/ae0d8be33307f3db6f5c179069ffeed38f61abbb))
* emit pow/mod opcodes ([08f478e](https://github.com/TaceoLabs/collaborative-circom/commit/08f478e5236c6fe62dc4d26c32907a0319b7a270))
* fixed poseidonex_test ([f119394](https://github.com/TaceoLabs/collaborative-circom/commit/f1193948e1edbed19be7d9684b6f96a0e83d3045))
* implement shift right for public shift values ([7db3730](https://github.com/TaceoLabs/collaborative-circom/commit/7db3730d02624ec2f28dfd9d93f6bac174b88ff6))
* implemented plain/aby3 cmux and bool not for shared if handling ([e5701aa](https://github.com/TaceoLabs/collaborative-circom/commit/e5701aa8d967ab9d111556c8dfba3eeacfda4782))
* integrate witness extension via MPC VM into CLI binary ([f526081](https://github.com/TaceoLabs/collaborative-circom/commit/f526081a01e3faa6b48fb463f3690f968218a1a4))
* public inputs support ([#76](https://github.com/TaceoLabs/collaborative-circom/issues/76)) ([07cf260](https://github.com/TaceoLabs/collaborative-circom/commit/07cf26007285822ba42e8dce2439f676a2cf08ef))
* shared control flow test working for single return values ([6f4aabb](https://github.com/TaceoLabs/collaborative-circom/commit/6f4aabb3a842d47e148343a6b5e0c5b6d27b9b31))
* shared_control_flow arrays working except loops ([15cdecf](https://github.com/TaceoLabs/collaborative-circom/commit/15cdecf5d4dc6d0400367856a48f2571925745c3))
* VM if logic first draft ([cb9e525](https://github.com/TaceoLabs/collaborative-circom/commit/cb9e525e8ff4d96fb18a73a59589c09fcb756dff))


### Bug Fixes

* fixed array as paramters and return val for functions (escalarmulw4table_test) ([8f38648](https://github.com/TaceoLabs/collaborative-circom/commit/8f386487a40de20951d2124ed10d2ee76876e9bd))
* fixed smt and sha test cases (signal offset of components fixed) ([5442507](https://github.com/TaceoLabs/collaborative-circom/commit/54425070d5af1cdbca092fc365bdd2f66218b89b))
