# Changelog

* The following workspace dependencies were updated
  * dependencies
    * co-circom-snarks bumped from 0.1.0 to 0.1.1
    * mpc-core bumped from 0.3.0 to 0.4.0

* The following workspace dependencies were updated
  * dependencies
    * co-circom-snarks bumped from 0.1.1 to 0.1.2
    * mpc-core bumped from 0.4.0 to 0.5.0

## [0.9.0](https://github.com/TaceoLabs/co-snarks/compare/circom-mpc-vm-v0.8.0...circom-mpc-vm-v0.9.0) (2025-11-06)


### ⚠ BREAKING CHANGES

* rework co-circom input splitting (now same as co-noir)
* move witness and input parsing/sharing to new crates for wasm comp
* unify MPC networks, split protocol state and networking to allow fork of state without network, replace io::Error with eyre, merge mpc-core and mpc-types with feature gated mpc-net
* move MPC types and share/combine into new mpc-types crate, rename co-circom-snarks to co-circom-types

### Features

* add extension traits for REP3 and Shamir networks ([0c15da8](https://github.com/TaceoLabs/co-snarks/commit/0c15da81550f35c7aaef77d5143824a9436d5731))
* added calls so that mpc-vm doesnt consume compiled circuit ([6fee634](https://github.com/TaceoLabs/co-snarks/commit/6fee634ed4b2ea2f047675471a1e6795478497bf))
* dont use rayon::join for networking - added std::thread::scope based join functions ([758b069](https://github.com/TaceoLabs/co-snarks/commit/758b0699ad0ef7bca7401afe9063848eb084873f))
* move witness and input parsing/sharing to new crates for wasm comp ([333785e](https://github.com/TaceoLabs/co-snarks/commit/333785e275bc9256fb82fd8e2dcf18689bd92862))
* rework co-circom input splitting (now same as co-noir) ([933bead](https://github.com/TaceoLabs/co-snarks/commit/933bead6b06b5140089978814e8612fd871f4a0b))
* update rust edition to 2024 ([6ea0ba9](https://github.com/TaceoLabs/co-snarks/commit/6ea0ba9f9f34063e8ab859c1d4ae41d05629a1c0))


### Bug Fixes

* correct panic message ([ed340cf](https://github.com/TaceoLabs/co-snarks/commit/ed340cff358884748c5035f400b11003184a8860))


### Code Refactoring

* move MPC types and share/combine into new mpc-types crate, rename co-circom-snarks to co-circom-types ([31b773a](https://github.com/TaceoLabs/co-snarks/commit/31b773aa71a5e872c25754de7805b02647b65688))
* unify MPC networks, split protocol state and networking to allow fork of state without network, replace io::Error with eyre, merge mpc-core and mpc-types with feature gated mpc-net ([16dbf54](https://github.com/TaceoLabs/co-snarks/commit/16dbf546d8f2d80ad4fa9f5053da19edc7270d3c))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-circom-types bumped from 0.5.0 to 0.6.0
    * mpc-core bumped from 0.9.0 to 0.10.0
    * mpc-net bumped from 0.4.0 to 0.5.0

## [0.8.0](https://github.com/TaceoLabs/co-snarks/compare/circom-mpc-vm-v0.7.0...circom-mpc-vm-v0.8.0) (2025-04-03)


### ⚠ BREAKING CHANGES

* added a batched version for plain witness extension and a chacha test case for it

### Features

* Add missing int_div and mod code in the circom rep3 witext backend ([#357](https://github.com/TaceoLabs/co-snarks/issues/357)) ([5c54e5d](https://github.com/TaceoLabs/co-snarks/commit/5c54e5d59349e16cfbb9457d7ea748f9aa6eb359))
* added a batched version for plain witness extension and a chacha test case for it ([36e69cc](https://github.com/TaceoLabs/co-snarks/commit/36e69cc7621b8689e3c829c8f1489344a1298899))
* added rep3 version of batched wtns extension for chacha ([310a5dc](https://github.com/TaceoLabs/co-snarks/commit/310a5dc09fc93ab6070571bbe509097817bf2979))
* added run_and_return_net for batched wtns extension ([f299c85](https://github.com/TaceoLabs/co-snarks/commit/f299c85ef8f368baa9f90a904ec65942f110c41b))
* batched chacha working ([a4cb900](https://github.com/TaceoLabs/co-snarks/commit/a4cb900128dc231660623f16a4fdc02cf181dc10))
* make compiled circom circuit de/serializable ([f0c4427](https://github.com/TaceoLabs/co-snarks/commit/f0c4427e5522f565ed5409139e1fa8e5db827b24))


### Bug Fixes

* fixed a bug where large int divs for plain driver didn't work ([a87cac7](https://github.com/TaceoLabs/co-snarks/commit/a87cac70c7ac9e465d5c8e3a5b6b5fa25ab35beb))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-circom-snarks bumped from 0.4.0 to 0.5.0
    * mpc-core bumped from 0.8.0 to 0.9.0
    * mpc-net bumped from 0.3.0 to 0.4.0

## [0.7.0](https://github.com/Taceolabs/co-snarks/compare/circom-mpc-vm-v0.6.0...circom-mpc-vm-v0.7.0) (2025-02-20)


### ⚠ BREAKING CHANGES

* a lot of APIs and types changed
* Add rep3 and shamir implementations of poseidon2 to mpc-core

### Features

* Add rep3 and shamir implementations of poseidon2 to mpc-core ([0939053](https://github.com/Taceolabs/co-snarks/commit/09390537eac78086a1df7b49e17a3c8ae2eba8ff))


### Code Refactoring

* co-circom lib usability improvents, added lib usage examples ([5768011](https://github.com/Taceolabs/co-snarks/commit/576801192076a27c75cd07fe1ec62244700bb934))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-circom-snarks bumped from 0.3.0 to 0.4.0
    * mpc-core bumped from 0.7.0 to 0.8.0
    * mpc-net bumped from 0.2.1 to 0.3.0

## [0.6.0](https://github.com/TaceoLabs/co-snarks/compare/circom-mpc-vm-v0.5.0...circom-mpc-vm-v0.6.0) (2024-12-16)


### ⚠ BREAKING CHANGES

* Opcode:Eq now holds the number of elements to compare.

### Features

* implement new accelerators for IsZero and AddBits ([bbccad1](https://github.com/TaceoLabs/co-snarks/commit/bbccad18e2382a8141286189c7c7349423788f85))
* make the application of MPC accelerators configurable ([9f67c9a](https://github.com/TaceoLabs/co-snarks/commit/9f67c9accc4ca52c9c270ea48ca8bb28d724af5a))


### Bug Fixes

* fixed a bug where eq checks for array did not work properly ([#283](https://github.com/TaceoLabs/co-snarks/issues/283)) ([3193574](https://github.com/TaceoLabs/co-snarks/commit/319357417be28cbe4da82b3dc4d2903b4183afb1))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-circom-snarks bumped from 0.2.0 to 0.3.0
    * mpc-core bumped from 0.6.0 to 0.7.0
    * mpc-net bumped from 0.2.0 to 0.2.1

## [0.5.0](https://github.com/TaceoLabs/co-snarks/compare/circom-mpc-vm-v0.4.2...circom-mpc-vm-v0.5.0) (2024-11-12)


### ⚠ BREAKING CHANGES

* MPC accelerator changed public API. Also now stores #output signals in component
* Also added name of cmp to Component Init instead of only symbol
* Witness extension VM trait no longer has binary share type.
* run and run_with_flat methods on WitnessExtension now consume self again
* Creating a Rep3Witnessextension now requires an additional argument, the A2B strategy
* now uses new mpc-core and networking model. Also uses binary shares and does not convert to arithmetic shares everytime

### Features

* add a selector for choosing a2b and b2a implementations and expose ([bf12246](https://github.com/TaceoLabs/co-snarks/commit/bf1224613599919fc90d1a23eecfbabc9ca1f037))
* added run_and_get_network to CircomRep3VmWitnessExtension, changed run and run_with_flat back to consume self ([b362504](https://github.com/TaceoLabs/co-snarks/commit/b362504d8a5affa8a5e8eca3f214c04951ad5b50))
* added stub for cmp accelerator ([bc1525e](https://github.com/TaceoLabs/co-snarks/commit/bc1525effdd38e9308cc4a0050b7e20c97be1974))
* bit_inject_many ([4155f57](https://github.com/TaceoLabs/co-snarks/commit/4155f570cb5ad9b3325c70df48993c3fde33ffb4))
* Check that VM config is equal amongst parties ([0623d7d](https://github.com/TaceoLabs/co-snarks/commit/0623d7d716809969fa52fb18e995dd2bb2ee6543))
* implement num2bits function ([5db7532](https://github.com/TaceoLabs/co-snarks/commit/5db753293ccba4e67bebf08b8a4977c47f7cb7ca))
* num2bits accelerator working ([13cdf10](https://github.com/TaceoLabs/co-snarks/commit/13cdf100b79c642649d31501833ed182dd7e8b90))
* rewrite that witness extension for circom to use forked networking and implements binary shares ([4c7e9ff](https://github.com/TaceoLabs/co-snarks/commit/4c7e9ff09aaf533f54ac60222b7981c6000f1f1e))


### Bug Fixes

* use a2b selector everywhere ([6c40fd6](https://github.com/TaceoLabs/co-snarks/commit/6c40fd65a31caa2c24ef65c4701bc27b88a74028))


### Code Refactoring

* removed binary shares from wtnx extension ([1370a7a](https://github.com/TaceoLabs/co-snarks/commit/1370a7a7202f26d20dc1857f64e2fd6874bd2f56))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-circom-snarks bumped from 0.1.2 to 0.2.0
    * mpc-core bumped from 0.5.0 to 0.6.0
    * mpc-net bumped from 0.1.2 to 0.2.0

## [0.4.0](https://github.com/TaceoLabs/collaborative-circom/compare/circom-mpc-vm-v0.3.0...circom-mpc-vm-v0.4.0) (2024-08-14)


### ⚠ BREAKING CHANGES

* We renamed all crate names from collaborative-* to co-* for brevity, and also shortened `Collaborative` to `Co` in many types.

### Code Refactoring

* renamed crates to co-* ([#161](https://github.com/TaceoLabs/collaborative-circom/issues/161)) ([37f3493](https://github.com/TaceoLabs/collaborative-circom/commit/37f3493b25e41b43bbc8a89e281ae2dcb4b95484))

## [0.3.0](https://github.com/TaceoLabs/collaborative-circom/compare/circom-mpc-vm-v0.2.0...circom-mpc-vm-v0.3.0) (2024-08-14)


### ⚠ BREAKING CHANGES

* moved common code for PLONK and Groth16 into separate crate. Most notably the SharedWitness and SharedInput
* Make MPC-VM thread safe and implement better Clone for shared inputs and witnesses ([#158](https://github.com/TaceoLabs/collaborative-circom/issues/158))
* new config implementation, config option to allow leaking of secret values in logs ([#132](https://github.com/TaceoLabs/collaborative-circom/issues/132))
* the function signature of the two run methods of the witness extension now changed. To retrieve the shared witness now another call `into_shared_witness()` is necessary.

### Features

* can now retrieve certain outputs after witness extension by name ([d9e3399](https://github.com/TaceoLabs/collaborative-circom/commit/d9e33996d10cea5f8197d507a13ed9087f0f4c20))
* Make MPC-VM thread safe and implement better Clone for shared inputs and witnesses ([#158](https://github.com/TaceoLabs/collaborative-circom/issues/158)) ([a7ab3bb](https://github.com/TaceoLabs/collaborative-circom/commit/a7ab3bbecd93b393c08e18d8ea89a64a25bac3a3))
* plonk support ([9b65797](https://github.com/TaceoLabs/collaborative-circom/commit/9b6579724f6f5ba4fc6af8a98d386b96818dc08b))


### Bug Fixes

* **docs:** added &gt; for a block because of clippy ([f054999](https://github.com/TaceoLabs/collaborative-circom/commit/f054999ce60ddb3ef61bfdd5fe0b294919eacf3b))


### Code Refactoring

* added new crate co-circom-snarks ([ea3190f](https://github.com/TaceoLabs/collaborative-circom/commit/ea3190f4d731893e6fcce71976c32b3bbac6b89b))
* new config implementation, config option to allow leaking of secret values in logs ([#132](https://github.com/TaceoLabs/collaborative-circom/issues/132)) ([964b04f](https://github.com/TaceoLabs/collaborative-circom/commit/964b04f47e8d491ae140cb7c10c596e1c40b6b5c))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * mpc-core bumped from 0.2.1 to 0.3.0

## [0.2.0](https://github.com/TaceoLabs/collaborative-circom/compare/circom-mpc-vm-v0.1.1...circom-mpc-vm-v0.2.0) (2024-07-10)


### ⚠ BREAKING CHANGES

* removed constructor with MPC-accelerator for WitnessExtension
* has_inputs element for CreateCmp opcode
* removed unnecessary jump opcode
* removed pub visibility for InputList ([#109](https://github.com/TaceoLabs/collaborative-circom/issues/109))

### Code Refactoring

* has_inputs element for CreateCmp opcode ([3c88182](https://github.com/TaceoLabs/collaborative-circom/commit/3c8818205e60b765ffa70b0ddc59c939569209e6))
* removed constructor with MPC-accelerator for WitnessExtension ([f9b60c8](https://github.com/TaceoLabs/collaborative-circom/commit/f9b60c897a20dad43948de610e01212c8548c99e))
* removed pub visibility for InputList ([#109](https://github.com/TaceoLabs/collaborative-circom/issues/109)) ([b2e5d93](https://github.com/TaceoLabs/collaborative-circom/commit/b2e5d93139f52e85f12ba2ffb4c42162b2f4b050))
* removed unnecessary jump opcode ([870047d](https://github.com/TaceoLabs/collaborative-circom/commit/870047dfc1ad623af9c28c7a53495f11a70a9e7a))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * collaborative-groth16 bumped from 0.2.0 to 0.2.1
    * mpc-core bumped from 0.2.0 to 0.2.1

## [0.1.1](https://github.com/TaceoLabs/collaborative-circom/compare/circom-mpc-vm-v0.1.0...circom-mpc-vm-v0.1.1) (2024-07-09)


### Bug Fixes

* corrects the order of input array for sub_comp and naively creates all components even if not necessary ([6d40a94](https://github.com/TaceoLabs/collaborative-circom/commit/6d40a9465b5351f0d30ac9f19c2ee61f09ccdbbb))
* vector in/outputs for sub component ([#90](https://github.com/TaceoLabs/collaborative-circom/issues/90)) ([f148375](https://github.com/TaceoLabs/collaborative-circom/commit/f148375c3ca8674f1ecd08bb30c1e6bcf2dbb4a9))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * collaborative-groth16 bumped from 0.1.0 to 0.2.0
    * mpc-core bumped from 0.1.0 to 0.2.0

## [0.1.0](https://github.com/TaceoLabs/collaborative-circom/compare/circom-mpc-vm-v0.0.1...circom-mpc-vm-v0.1.0) (2024-06-14)


### Features

* added better assert message when assert fails ([ae0d8be](https://github.com/TaceoLabs/collaborative-circom/commit/ae0d8be33307f3db6f5c179069ffeed38f61abbb))
* added pow/mod opcodes for plain VM ([#50](https://github.com/TaceoLabs/collaborative-circom/issues/50)) ([eb6e55c](https://github.com/TaceoLabs/collaborative-circom/commit/eb6e55c5fdf5e650ba7cdab52acab0b4af392615))
* fixed poseidonex_test ([f119394](https://github.com/TaceoLabs/collaborative-circom/commit/f1193948e1edbed19be7d9684b6f96a0e83d3045))
* implement eq/neq in mpc vm ([1e32551](https://github.com/TaceoLabs/collaborative-circom/commit/1e3255108578635ac869a564a6fcf5fab854fb03))
* implement shift right for public shift values ([7db3730](https://github.com/TaceoLabs/collaborative-circom/commit/7db3730d02624ec2f28dfd9d93f6bac174b88ff6))
* implemented plain/aby3 cmux and bool not for shared if handling ([e5701aa](https://github.com/TaceoLabs/collaborative-circom/commit/e5701aa8d967ab9d111556c8dfba3eeacfda4782))
* integrate witness extension via MPC VM into CLI binary ([f526081](https://github.com/TaceoLabs/collaborative-circom/commit/f526081a01e3faa6b48fb463f3690f968218a1a4))
* mpc accelerator first draft ([#79](https://github.com/TaceoLabs/collaborative-circom/issues/79)) ([5f2709b](https://github.com/TaceoLabs/collaborative-circom/commit/5f2709b2e56277328180f9990f1f21c77cdac06e))
* public inputs support ([#76](https://github.com/TaceoLabs/collaborative-circom/issues/76)) ([07cf260](https://github.com/TaceoLabs/collaborative-circom/commit/07cf26007285822ba42e8dce2439f676a2cf08ef))
* shared control flow test working for single return values ([6f4aabb](https://github.com/TaceoLabs/collaborative-circom/commit/6f4aabb3a842d47e148343a6b5e0c5b6d27b9b31))
* shared_control_flow arrays working except loops ([15cdecf](https://github.com/TaceoLabs/collaborative-circom/commit/15cdecf5d4dc6d0400367856a48f2571925745c3))
* VM if logic first draft ([cb9e525](https://github.com/TaceoLabs/collaborative-circom/commit/cb9e525e8ff4d96fb18a73a59589c09fcb756dff))


### Bug Fixes

* ab3 is_shared function + fixed a typo in cmux ([c6e4576](https://github.com/TaceoLabs/collaborative-circom/commit/c6e4576ac22de7569a6433e2dc862783c3bb02e2))
* correct handling of is_zero in binary MPC protocol ([432326e](https://github.com/TaceoLabs/collaborative-circom/commit/432326e9f2c24bca7a3a2f795711d677d1d37503))
* fixed a bug that sub components were not invoked when they did not have inputs (mux test cases) ([825b8e3](https://github.com/TaceoLabs/collaborative-circom/commit/825b8e3d78e4e9702c40b1e5db16faf41caa1f28))
* fixed array as parameters and return value for functions (escalarmulw4table_test) ([8f38648](https://github.com/TaceoLabs/collaborative-circom/commit/8f386487a40de20951d2124ed10d2ee76876e9bd))
* fixed iszero for aby3 ([244072a](https://github.com/TaceoLabs/collaborative-circom/commit/244072a1c5f98501dc8ba8003684db792fda92db))
* fixed smt and sha test cases (signal offset of components fixed) ([5442507](https://github.com/TaceoLabs/collaborative-circom/commit/54425070d5af1cdbca092fc365bdd2f66218b89b))
* missing call to bool_or ([d1a3bb1](https://github.com/TaceoLabs/collaborative-circom/commit/d1a3bb13bc08a711d248fa65b47d8c68b49878e6))
* slightly better error message for internal assertions ([75d51be](https://github.com/TaceoLabs/collaborative-circom/commit/75d51bee43c92f79916e3ecac047e198e63e9a96))
