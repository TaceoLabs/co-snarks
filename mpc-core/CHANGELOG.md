# Changelog



## [0.6.0](https://github.com/TaceoLabs/co-snarks/compare/mpc-core-v0.5.0...mpc-core-v0.6.0) (2024-11-12)


### ⚠ BREAKING CHANGES

* serialization format of shared inputs has changed to allow for optional values used to indicate missing elements of an array
* Use ACVMType in co-builder
* Creating a Rep3Witnessextension now requires an additional argument, the A2B strategy
* breaks all interfaces. Removed Rep3Protocol monster struct. Added IOContext and split rep3/shamir better. Removed duplicated code. Added naive LUT

### Features

* Add a garbled circuit based soritng algorithm ([#252](https://github.com/TaceoLabs/co-snarks/issues/252)) ([7d38334](https://github.com/TaceoLabs/co-snarks/commit/7d38334902129acf5707b790aa9a28430babe999))
* add a selector for choosing a2b and b2a implementations and expose ([bf12246](https://github.com/TaceoLabs/co-snarks/commit/bf1224613599919fc90d1a23eecfbabc9ca1f037))
* Add functionality to decompose a shared fieldelement with yao ([3d7a37d](https://github.com/TaceoLabs/co-snarks/commit/3d7a37d2d12edf671a6bd78d1d876155e38a90f8))
* Add Rep3 compatible garbled circuit implementations and conversion methods for a2y, y2a, b2y, y2b, a2y2b, and b2y2a. ([#233](https://github.com/TaceoLabs/co-snarks/issues/233)) ([12c8713](https://github.com/TaceoLabs/co-snarks/commit/12c8713f88b30e04dd4ac2b7b9244ca28b749b56))
* add support for merging input arrays ([#260](https://github.com/TaceoLabs/co-snarks/issues/260)) ([2c72231](https://github.com/TaceoLabs/co-snarks/commit/2c722317efee4b07fef92dcc7c6218033a25f04b))
* added conversions a&lt;-&gt;b ([d1c806c](https://github.com/TaceoLabs/co-snarks/commit/d1c806c0d165569c16d11cc15fc9dbd4f908b807))
* added new rep3 impl ([d9b8412](https://github.com/TaceoLabs/co-snarks/commit/d9b8412d794fe9596a3292f717f00e11f2bc08f2))
* added plain prover shorthand function ([b365fcd](https://github.com/TaceoLabs/co-snarks/commit/b365fcd89390dad585933f39a2db32473081d060))
* bit_inject_many ([4155f57](https://github.com/TaceoLabs/co-snarks/commit/4155f570cb5ad9b3325c70df48993c3fde33ffb4))
* make yao the default for a2b ([b91e4ac](https://github.com/TaceoLabs/co-snarks/commit/b91e4ac9e854f2726bccf1064e91bdaaf93b143a))
* optimize arithmetic::is_zero() to have less communication rounds ([dc4152c](https://github.com/TaceoLabs/co-snarks/commit/dc4152c774140392f22a5cc580ec22a69f5c1448))
* optimize bit_inject and bit_inject many ([7fb2fee](https://github.com/TaceoLabs/co-snarks/commit/7fb2feecc7a9302427f97f25dc61877a4a460ab7))
* Optimize shamir double randomnes generation using seeds ([#214](https://github.com/TaceoLabs/co-snarks/issues/214)) ([f6ad386](https://github.com/TaceoLabs/co-snarks/commit/f6ad3863affb42754ae56935102d19af63a068b7))
* prepare functions for compressed rep3 sharing ([55bef10](https://github.com/TaceoLabs/co-snarks/commit/55bef10313378e8ca14f2f22f312c84462a92a7e))
* rewrite all mpc related functions ([ed8fcb7](https://github.com/TaceoLabs/co-snarks/commit/ed8fcb73aca24ee2dfda2770ef0512eba8695650))
* unify the 3-party and n-party shamir double-randomness generation case ([b4d4141](https://github.com/TaceoLabs/co-snarks/commit/b4d41411de001fb84ea953ea20360ebd36edb1cc))
* Update UltraHonk to BB v0.62.0, required to replace zeromorph with shplemini ([#251](https://github.com/TaceoLabs/co-snarks/issues/251)) ([f35cdd4](https://github.com/TaceoLabs/co-snarks/commit/f35cdd490f8a3daa8bb44f6aa502f42147efb4b6))


### Bug Fixes

* add gracefull shutdown ensure all data received from the quinn stack ([a9cbcbf](https://github.com/TaceoLabs/co-snarks/commit/a9cbcbf8a5fa00f01c94cd80eae45cbf7f65390f))
* change shamir preprocessing time log to float ([#249](https://github.com/TaceoLabs/co-snarks/issues/249)) ([c4c6a73](https://github.com/TaceoLabs/co-snarks/commit/c4c6a73d44eee62d37a196fa553ab795295ccc9b))
* fix a bug in y2b, send the correct values around ([564d498](https://github.com/TaceoLabs/co-snarks/commit/564d4984f421e1f15d65fa9ca96627e127479d91))
* fixed read task breaking too early, caused error during proof gen ([6a8e829](https://github.com/TaceoLabs/co-snarks/commit/6a8e82913b88414ee05a7159fbd390a32db70b9d))


### Code Refactoring

* Use ACVMType in co-builder ([e078c22](https://github.com/TaceoLabs/co-snarks/commit/e078c22e4d19580b4a0531c0ac4232e7dd9f3bae))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * mpc-net bumped from 0.1.2 to 0.2.0

## [0.5.0](https://github.com/TaceoLabs/collaborative-circom/compare/mpc-core-v0.4.0...mpc-core-v0.5.0) (2024-10-03)


### ⚠ BREAKING CHANGES

* removed acvm_impl. now uses old driver for ACVM
* added mpc-core trait for Acvm witness extension. Therfore, we changed trait bounds for Rep3Protocol

### Features

* Add co-noir binary ([#201](https://github.com/TaceoLabs/collaborative-circom/issues/201)) ([3163aec](https://github.com/TaceoLabs/collaborative-circom/commit/3163aec0795dd7b357f532e4da9e232ea164f064))
* Add co-oink prover ([#194](https://github.com/TaceoLabs/collaborative-circom/issues/194)) ([b5fbd85](https://github.com/TaceoLabs/collaborative-circom/commit/b5fbd85b32cdb01c8865777c2238e159fc9b2553))
* added LUT provider stub and plain impl for MemOps ([3d2377f](https://github.com/TaceoLabs/collaborative-circom/commit/3d2377f073a7a6b1c4b88e1d752ebc3ef60724ed))
* added predicate handling in memory op ([220414f](https://github.com/TaceoLabs/collaborative-circom/commit/220414fbc1084658ffa73f0171a4c4493a97d7ca))
* added rep3 implementation for AssertZeroOpCode ([8e51505](https://github.com/TaceoLabs/collaborative-circom/commit/8e515052539227cf44860390a8d6736f9e456c91))
* added sanity checks for memopcodes ([6914611](https://github.com/TaceoLabs/collaborative-circom/commit/6914611ad5a7597e4785f8ef67ecfbf479f3dd7c))
* added trivial LUT impl for Rep3. Also modified some code in MPC-core ([bcb4749](https://github.com/TaceoLabs/collaborative-circom/commit/bcb4749e168807f5f16ae80bd1aeaa6e1f9da157))
* Make builder generic for both shares and plain, add shared proving key and start with MPC prover ([#193](https://github.com/TaceoLabs/collaborative-circom/issues/193)) ([e3559a0](https://github.com/TaceoLabs/collaborative-circom/commit/e3559a0a38a61b1de4b29ea9fa820066ed00ddc0))
* started witness extension Noir ([43e6535](https://github.com/TaceoLabs/collaborative-circom/commit/43e653545cd6e797becefbb76f7757dde43a5030))


### Code Refactoring

* removed acvm_impl. now uses old driver for ACVM ([d37c5bb](https://github.com/TaceoLabs/collaborative-circom/commit/d37c5bbd00e932a97d64a6e924b8c092b71f30d2))

## [0.4.0](https://github.com/TaceoLabs/collaborative-circom/compare/mpc-core-v0.3.0...mpc-core-v0.4.0) (2024-08-21)


### ⚠ BREAKING CHANGES

* we fixed a bug, where the (i)ffts for bls12_381 had a different permutation than from snarkjs. We removed our band-aid fix (FFTPostProcessing). Therfore, it is a breaking change.

### Bug Fixes

* fixes the bls12_381 permutation from arkworks ([f100615](https://github.com/TaceoLabs/collaborative-circom/commit/f100615790c51227d89e886ee6977367e4d5a1ce))

## [0.3.0](https://github.com/TaceoLabs/collaborative-circom/compare/mpc-core-v0.2.1...mpc-core-v0.3.0) (2024-08-14)


### ⚠ BREAKING CHANGES

* Added functionality for MPC traits
* Add possibility to use Shamir secret sharing for proofing and

### Features

* Add possibility to use Shamir secret sharing for proofing and ([6205475](https://github.com/TaceoLabs/collaborative-circom/commit/6205475b78d4654c61f5058befe5d5990da19432))
* Added functionality for MPC traits ([0897066](https://github.com/TaceoLabs/collaborative-circom/commit/089706629ab863814276309b330744f909c976cd))

## [0.2.0](https://github.com/TaceoLabs/collaborative-circom/compare/mpc-core-v0.1.0...mpc-core-v0.2.0) (2024-07-09)


### ⚠ BREAKING CHANGES

* clean up visibility of interfaces and add docs

### Features

* expose promot_from_trivial for Rep3 ([b329a42](https://github.com/TaceoLabs/collaborative-circom/commit/b329a427031d4e787addbf37902c710ba0132ccf))


### Bug Fixes

* implement optional post-processing permutation for FFTs and correct root of unity calculation to match circom output ([5ab3292](https://github.com/TaceoLabs/collaborative-circom/commit/5ab329294959c85ea6e0823cbe651ba6efa747f8))


### Code Refactoring

* clean up visibility of interfaces and add docs ([8a4f085](https://github.com/TaceoLabs/collaborative-circom/commit/8a4f08582a950d11f88e1de8fb6c4e28279b2891))

## [0.1.0](https://github.com/TaceoLabs/collaborative-circom/compare/mpc-core-v0.0.1...mpc-core-v0.1.0) (2024-06-14)


### ⚠ BREAKING CHANGES

* remove slice and slicemut types from traits

### Features

* Add a bridge to translate Rep3 shares to Shamir shares ([7855e8d](https://github.com/TaceoLabs/collaborative-circom/commit/7855e8dc65c40b2f9b4da6e8e35aa5269fc1ab11))
* Add arithmetic&lt;-&gt;binary conversions for field elements in ABY3 ([#39](https://github.com/TaceoLabs/collaborative-circom/issues/39)) ([190622d](https://github.com/TaceoLabs/collaborative-circom/commit/190622def82fac9e17a9d5ce75cffc3fbad9bbaa))
* add bool_or opcode ([7018352](https://github.com/TaceoLabs/collaborative-circom/commit/7018352f1a8eba34e3abcdea9cf00ac6ff77d846))
* Add semi-honest GSZ (i.e., Shamir) ([#21](https://github.com/TaceoLabs/collaborative-circom/issues/21)) ([746edb4](https://github.com/TaceoLabs/collaborative-circom/commit/746edb45d14da4d8a54f7503848a4e62e2bfc899))
* added collaborative groth16 prover ([#18](https://github.com/TaceoLabs/collaborative-circom/issues/18)) ([6e5bb98](https://github.com/TaceoLabs/collaborative-circom/commit/6e5bb98afa5be816188bc019036ba4786f448749))
* added pow/mod opcodes for plain VM ([#50](https://github.com/TaceoLabs/collaborative-circom/issues/50)) ([eb6e55c](https://github.com/TaceoLabs/collaborative-circom/commit/eb6e55c5fdf5e650ba7cdab52acab0b4af392615))
* added skeleton for mpc/collab-groth16 ([#12](https://github.com/TaceoLabs/collaborative-circom/issues/12)) ([9c03331](https://github.com/TaceoLabs/collaborative-circom/commit/9c03331171429f061ead8cddda292cd97d498f1a))
* bool_or aby3 ([710b2af](https://github.com/TaceoLabs/collaborative-circom/commit/710b2affc684595654b2dcad788ac3dcd3f2730f))
* change plain semantics of comparisons for easier translation to mpc ([660656b](https://github.com/TaceoLabs/collaborative-circom/commit/660656bf093cfa8b79de3d60db7af4b8f1422311))
* comparison impls ([d470c82](https://github.com/TaceoLabs/collaborative-circom/commit/d470c82be3570e4b2103fe0f34d686a42561db41))
* Creating Proof from assignment in MPC ([#17](https://github.com/TaceoLabs/collaborative-circom/issues/17)) ([cc4f6f5](https://github.com/TaceoLabs/collaborative-circom/commit/cc4f6f5de873fea80bd51a724dbd001d6351f68d))
* First impl for Circom Parser to MPC.  ([#26](https://github.com/TaceoLabs/collaborative-circom/issues/26)) ([779682d](https://github.com/TaceoLabs/collaborative-circom/commit/779682d7d824d782109db8b4584604b23637dad7))
* first version of command line interface ([#36](https://github.com/TaceoLabs/collaborative-circom/issues/36)) ([6abe716](https://github.com/TaceoLabs/collaborative-circom/commit/6abe716268f1e165cdae07a10f4d2dafd010cc04))
* first version of mpc vm ([#42](https://github.com/TaceoLabs/collaborative-circom/issues/42)) ([6dcd5f4](https://github.com/TaceoLabs/collaborative-circom/commit/6dcd5f4ce7c8431b94dd7262a4219a3a63efd702))
* fixed poseidonex_test ([f119394](https://github.com/TaceoLabs/collaborative-circom/commit/f1193948e1edbed19be7d9684b6f96a0e83d3045))
* implement a basic variant of shift_right for ABY3 ([e17fc61](https://github.com/TaceoLabs/collaborative-circom/commit/e17fc614b358eeb884e56121154c98968c0e0ce4))
* implement eq/neq in mpc vm ([1e32551](https://github.com/TaceoLabs/collaborative-circom/commit/1e3255108578635ac869a564a6fcf5fab854fb03))
* implement mod and pow for public values in MPC VM, as well as pow of secret with public values ([75c70dd](https://github.com/TaceoLabs/collaborative-circom/commit/75c70dd096ab87ccadd59cc279b25dd1dc0d191c))
* implement more shared bit operations ([9e326de](https://github.com/TaceoLabs/collaborative-circom/commit/9e326de158b5219e7e93311d2357e74b597272c7))
* implement shift right for public shift values ([7db3730](https://github.com/TaceoLabs/collaborative-circom/commit/7db3730d02624ec2f28dfd9d93f6bac174b88ff6))
* implemented plain/aby3 cmux and bool not for shared if handling ([e5701aa](https://github.com/TaceoLabs/collaborative-circom/commit/e5701aa8d967ab9d111556c8dfba3eeacfda4782))
* integrate witness extension via MPC VM into CLI binary ([f526081](https://github.com/TaceoLabs/collaborative-circom/commit/f526081a01e3faa6b48fb463f3690f968218a1a4))
* make all comparisons based on LT ([6e8cbbf](https://github.com/TaceoLabs/collaborative-circom/commit/6e8cbbf5bf5472ef1eb7ffe3dfce89ed790f508b))
* mpc accelerator first draft ([#79](https://github.com/TaceoLabs/collaborative-circom/issues/79)) ([5f2709b](https://github.com/TaceoLabs/collaborative-circom/commit/5f2709b2e56277328180f9990f1f21c77cdac06e))
* naively implemented plain val() for bool expr ([3e6cabb](https://github.com/TaceoLabs/collaborative-circom/commit/3e6cabb0b3fa9b903f7d747393347f531d6516bf))
* public inputs support ([#76](https://github.com/TaceoLabs/collaborative-circom/issues/76)) ([07cf260](https://github.com/TaceoLabs/collaborative-circom/commit/07cf26007285822ba42e8dce2439f676a2cf08ef))
* shared control flow test working for single return values ([6f4aabb](https://github.com/TaceoLabs/collaborative-circom/commit/6f4aabb3a842d47e148343a6b5e0c5b6d27b9b31))
* shared_control_flow arrays working except loops ([15cdecf](https://github.com/TaceoLabs/collaborative-circom/commit/15cdecf5d4dc6d0400367856a48f2571925745c3))
* some more aby3 impls for bitops ([ff0ed61](https://github.com/TaceoLabs/collaborative-circom/commit/ff0ed612a0616fe864f85242956ec1ede0f76236))
* traits and implementations of aby3 shares, fft's, and msm ([#16](https://github.com/TaceoLabs/collaborative-circom/issues/16)) ([a6bf90e](https://github.com/TaceoLabs/collaborative-circom/commit/a6bf90e6d326df3e9caa2dbbabf7bd60acb50fbd))
* use CanonicalSerialize from ark for ser/de of arkworks structures, with additional serde compat layer on top level ([e3e7af3](https://github.com/TaceoLabs/collaborative-circom/commit/e3e7af340d1fbfc148fbe6614b004a8c70aba1f0))
* VM if logic first draft ([cb9e525](https://github.com/TaceoLabs/collaborative-circom/commit/cb9e525e8ff4d96fb18a73a59589c09fcb756dff))
* warning on opening shared values ([a276601](https://github.com/TaceoLabs/collaborative-circom/commit/a276601150bfc81c97c7e5c714be23cbabdbc1ba))


### Bug Fixes

* ab3 is_shared function + fixed a typo in cmux ([c6e4576](https://github.com/TaceoLabs/collaborative-circom/commit/c6e4576ac22de7569a6433e2dc862783c3bb02e2))
* broken impl of shifts ([0413ca0](https://github.com/TaceoLabs/collaborative-circom/commit/0413ca0af39f6786c6caca402311b56e5c5bccc6))
* correct handling of is_zero in binary MPC protocol ([432326e](https://github.com/TaceoLabs/collaborative-circom/commit/432326e9f2c24bca7a3a2f795711d677d1d37503))
* fix a2b for zero case ([53592b1](https://github.com/TaceoLabs/collaborative-circom/commit/53592b12756efa9c63c6e5185cafc13c2bd4154d))
* fixed array as paramters and return val for functions (escalarmulw4table_test) ([8f38648](https://github.com/TaceoLabs/collaborative-circom/commit/8f386487a40de20951d2124ed10d2ee76876e9bd))
* fixed iszero for aby3 ([244072a](https://github.com/TaceoLabs/collaborative-circom/commit/244072a1c5f98501dc8ba8003684db792fda92db))
* mixup for shift left and right ([a2757fc](https://github.com/TaceoLabs/collaborative-circom/commit/a2757fc63222b4a37d991533a0980e9be55023f3))
* only send what is needed in the AND gates of is_zero ([a84d36d](https://github.com/TaceoLabs/collaborative-circom/commit/a84d36d2c964f876527e9f9755a063bcef021eb0))


### Code Refactoring

* remove slice and slicemut types from traits ([d60cd06](https://github.com/TaceoLabs/collaborative-circom/commit/d60cd0645a397898cd997a516dc513c7f29ecb55))
