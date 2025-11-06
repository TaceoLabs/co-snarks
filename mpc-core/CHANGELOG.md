# Changelog



## [0.10.0](https://github.com/TaceoLabs/co-snarks/compare/mpc-core-v0.9.0...mpc-core-v0.10.0) (2025-11-06)


### ⚠ BREAKING CHANGES

* upgrade to Noir 1.0.0-beta.14 and BB 3.0.0-nightly.20250916 ([#480](https://github.com/TaceoLabs/co-snarks/issues/480))
* add MPC version of ECCVM builder and prover ([#456](https://github.com/TaceoLabs/co-snarks/issues/456))
* add u512 IntRing type ([#462](https://github.com/TaceoLabs/co-snarks/issues/462))
* unify MPC networks, split protocol state and networking to allow fork of state without network, replace io::Error with eyre, merge mpc-core and mpc-types with feature gated mpc-net
* Performance improvements and cleanup for blake2/blake3
* add BLAKE3 blackbox function to coNoir
* add BLAKE2s blackbox function to coNoir
* add Bristol Fashion parsing for GC, also adds the SHA256 blackbox ([#359](https://github.com/TaceoLabs/co-snarks/issues/359))
* Add the MSM blackbox function to co-noir, which allows to use pedersen hash/commitment
* rename io_mul_vec to reshare_vec
* move uncompress_shared_witness to co-circom
* move MPC types and share/combine into new mpc-types crate, rename co-circom-snarks to co-circom-types

### Features

* Add AES blackbox functionality ([fd7cd49](https://github.com/TaceoLabs/co-snarks/commit/fd7cd496a1fd21e85aa70c0bd2c5cd7aed69fece))
* add BLAKE2s blackbox function to coNoir ([e98fb7d](https://github.com/TaceoLabs/co-snarks/commit/e98fb7dd60f52d936f07b3e3a74797dfb091e9f3))
* add BLAKE3 blackbox function to coNoir ([ddcb10e](https://github.com/TaceoLabs/co-snarks/commit/ddcb10e5d685072279b8f11b6935636fb74ecaf0))
* add Bristol Fashion parsing for GC, also adds the SHA256 blackbox ([#359](https://github.com/TaceoLabs/co-snarks/issues/359)) ([f8509ef](https://github.com/TaceoLabs/co-snarks/commit/f8509ef8147bf29072ba67b4ac0f489546eea2c9))
* add extension traits for REP3 and Shamir networks ([0c15da8](https://github.com/TaceoLabs/co-snarks/commit/0c15da81550f35c7aaef77d5143824a9436d5731))
* add MAESTRO style lut protocol for curve points ([4da5f74](https://github.com/TaceoLabs/co-snarks/commit/4da5f74bed1350c4574bf3f3301c522ae068a096))
* add MPC version of ECCVM builder and prover ([#456](https://github.com/TaceoLabs/co-snarks/issues/456)) ([0230ccb](https://github.com/TaceoLabs/co-snarks/commit/0230ccb52bb52bf6ebe291103f8945e4fea61ed2))
* add plain ECCVM Prover ([#409](https://github.com/TaceoLabs/co-snarks/issues/409)) ([dc5f175](https://github.com/TaceoLabs/co-snarks/commit/dc5f175c1f1c61a95731129d10995b0f6122a1c1))
* Add the MSM blackbox function to co-noir, which allows to use pedersen hash/commitment ([ffeaa32](https://github.com/TaceoLabs/co-snarks/commit/ffeaa32f754fa16c77bf050486ce871a77908653))
* add u512 IntRing type ([#462](https://github.com/TaceoLabs/co-snarks/issues/462)) ([531d08c](https://github.com/TaceoLabs/co-snarks/commit/531d08cb3403b78fd3671de49c39dc97f34a4ccc))
* add vectorized implementations of b2a and dependencies ([#393](https://github.com/TaceoLabs/co-snarks/issues/393)) ([c734b9b](https://github.com/TaceoLabs/co-snarks/commit/c734b9bb0237f8b6ad80451d40860fcdc24f873c))
* also add send_prev and recv_next methods ([bee26f0](https://github.com/TaceoLabs/co-snarks/commit/bee26f026ef9d4364ed558a9d99017849bd7d98a))
* derive CanonicalSerialize and CanonicalDeserialize for Rep3RingShare ([3360969](https://github.com/TaceoLabs/co-snarks/commit/33609690dff2b6738f7bce5cd0482c4b8d3c68a3))
* derive Hash for rep3 PartyID ([a8620e5](https://github.com/TaceoLabs/co-snarks/commit/a8620e5422dc2a959d5f86a922c9b46b2089b9fe))
* dont use rayon::join for networking - added std::thread::scope based join functions ([758b069](https://github.com/TaceoLabs/co-snarks/commit/758b0699ad0ef7bca7401afe9063848eb084873f))
* initial MPC Translator prover and builder implementation ([#467](https://github.com/TaceoLabs/co-snarks/issues/467)) ([ff92fcb](https://github.com/TaceoLabs/co-snarks/commit/ff92fcbe8fa3f2cbc3904d3c28f0890aee3be7fb))
* Performance improvements and cleanup for blake2/blake3 ([435fcd3](https://github.com/TaceoLabs/co-snarks/commit/435fcd333080201c7c0274519ff6f6b26fb62d50))
* replace the bitinject algorithms in mpc-core ([ab7e894](https://github.com/TaceoLabs/co-snarks/commit/ab7e89457c5dc770ce9551e5d422895f996d723b))
* update rust edition to 2024 ([6ea0ba9](https://github.com/TaceoLabs/co-snarks/commit/6ea0ba9f9f34063e8ab859c1d4ae41d05629a1c0))


### Bug Fixes

* correct limbsize calculation for biguint sampling ([1b2db00](https://github.com/TaceoLabs/co-snarks/commit/1b2db005ee550c028af824b3ec4e811d6e8a3705))
* correct padding in aes circuit ([a2226c2](https://github.com/TaceoLabs/co-snarks/commit/a2226c2f5dd10b4ff7d595807324e92c2b9f9e67))
* incorrect extra multiply in pow_public for field and ring backends ([#461](https://github.com/TaceoLabs/co-snarks/issues/461)) ([7eaa830](https://github.com/TaceoLabs/co-snarks/commit/7eaa830fd845bfb8c013040a4ac04ebc4728d204))


### Miscellaneous Chores

* upgrade to Noir 1.0.0-beta.14 and BB 3.0.0-nightly.20250916 ([#480](https://github.com/TaceoLabs/co-snarks/issues/480)) ([9bdad27](https://github.com/TaceoLabs/co-snarks/commit/9bdad2793e3ca7f82a291f9e9932cf877ef657eb))


### Code Refactoring

* move MPC types and share/combine into new mpc-types crate, rename co-circom-snarks to co-circom-types ([31b773a](https://github.com/TaceoLabs/co-snarks/commit/31b773aa71a5e872c25754de7805b02647b65688))
* move uncompress_shared_witness to co-circom ([0462a2f](https://github.com/TaceoLabs/co-snarks/commit/0462a2fc2dd145e5306e353a227f66d8862712cb))
* rename io_mul_vec to reshare_vec ([7067486](https://github.com/TaceoLabs/co-snarks/commit/70674869e91950a59b68272127781ecf56d77094))
* unify MPC networks, split protocol state and networking to allow fork of state without network, replace io::Error with eyre, merge mpc-core and mpc-types with feature gated mpc-net ([16dbf54](https://github.com/TaceoLabs/co-snarks/commit/16dbf546d8f2d80ad4fa9f5053da19edc7270d3c))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * mpc-net bumped from 0.4.0 to 0.5.0

## [0.9.0](https://github.com/TaceoLabs/co-snarks/compare/mpc-core-v0.8.0...mpc-core-v0.9.0) (2025-04-03)


### ⚠ BREAKING CHANGES

* Public API of coGroth16 driver trait changed to include `HalfShare` types. ---------
* adds batched versions of relation in sumcheck for MPC friendliness

### Features

* Add missing int_div and mod code in the circom rep3 witext backend ([#357](https://github.com/TaceoLabs/co-snarks/issues/357)) ([5c54e5d](https://github.com/TaceoLabs/co-snarks/commit/5c54e5d59349e16cfbb9457d7ea748f9aa6eb359))
* add MPC ZK prover for coNoir ([#335](https://github.com/TaceoLabs/co-snarks/issues/335)) ([056b2b4](https://github.com/TaceoLabs/co-snarks/commit/056b2b4e10ef822de253ac646e88e2dd5f50edcb))
* added rep3 version of batched wtns extension for chacha ([310a5dc](https://github.com/TaceoLabs/co-snarks/commit/310a5dc09fc93ab6070571bbe509097817bf2979))
* adds batched versions of relation in sumcheck for MPC friendliness ([475cd84](https://github.com/TaceoLabs/co-snarks/commit/475cd841811be0ee38d76f82a8d5bec8d712cee0))
* batched chacha working ([a4cb900](https://github.com/TaceoLabs/co-snarks/commit/a4cb900128dc231660623f16a4fdc02cf181dc10))


### Code Refactoring

* Reduce work for Groth16 REP3 by working over un-replicated shares as much as possible ([#349](https://github.com/TaceoLabs/co-snarks/issues/349)) ([42068eb](https://github.com/TaceoLabs/co-snarks/commit/42068eb7a1f30f3af4a455f259336dcbabf57eb4))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * mpc-net bumped from 0.3.0 to 0.4.0

## [0.8.0](https://github.com/Taceolabs/co-snarks/compare/mpc-core-v0.7.0...mpc-core-v0.8.0) (2025-02-20)


### ⚠ BREAKING CHANGES

* optimize radix sort to take private and public inputs, such that public inputs do not have to be decomposed/bitinjected ([#319](https://github.com/Taceolabs/co-snarks/issues/319))
* a lot of APIs and types changed
* compressed inputs shares are no longer supported, only compressed witness shares are allowed
* add RAM operations on shared indices ([#314](https://github.com/Taceolabs/co-snarks/issues/314))
* Add rep3 and shamir implementations of poseidon2 to mpc-core
* Move poseidon2 from ultrahonk to mpc-core
* Add extra functionality to rewrite the lookup_read_counts_tags to shared LUTs
* Changed the interface of `LookupTableProvider` trait.
* implemented bitwise_and, bitwise_xor and bitwise_not in the

### Features

* add binary division in gc ([1e00651](https://github.com/Taceolabs/co-snarks/commit/1e00651d6e2d045ea357a80dcb1f74eb5fab3d7c))
* Add blackbox_poseidon2 handling to co-noir ([3c2e811](https://github.com/Taceolabs/co-snarks/commit/3c2e81133b2a5b3a360918bc7d597277d091fb15))
* Add extra functionality to rewrite the lookup_read_counts_tags to shared LUTs ([6fc80f7](https://github.com/Taceolabs/co-snarks/commit/6fc80f7a1a3a2a4f65180edccf03b6ef6b247c37))
* Add lookup table based on MAESTRO to the MPC core ([#307](https://github.com/Taceolabs/co-snarks/issues/307)) ([2eb6916](https://github.com/Taceolabs/co-snarks/commit/2eb691604c431fa19affe7812e135e5e7dcf5f2e))
* Add Merkle tree implemenations using Poseidon2 ([08b26a8](https://github.com/Taceolabs/co-snarks/commit/08b26a8e1d69ab9a1b2d1f081d37f7ebed482431))
* Add more poseidon2 instances (t=2, t=3, t=4) ([70b389e](https://github.com/Taceolabs/co-snarks/commit/70b389eedae3c7075f015f8ff86f155d4064cd3d))
* Add MPC functionality to slice a shared value ([595e33b](https://github.com/Taceolabs/co-snarks/commit/595e33bd0c6ca1b9dbbef9f3d41906b1e22ddfbb))
* Add packed rep3 version of poseidon2 ([027782f](https://github.com/Taceolabs/co-snarks/commit/027782f48618e68b732e0cf36b9cdf03072452f3))
* Add packed shamir version of poseidon2 ([3ca7426](https://github.com/Taceolabs/co-snarks/commit/3ca742683218d446cf8ce31ab010f33bfbbbe617))
* Add possibility to lazily initialize constants in garbled circuits to only send them once ([a0e0086](https://github.com/Taceolabs/co-snarks/commit/a0e008673bdffcfc0eb2326de2a8f355ef52ee82))
* add public/shared int division ([4286c6a](https://github.com/Taceolabs/co-snarks/commit/4286c6a7d7e42335c056c2b3a858a7dbd51bf107))
* add RAM operations on shared indices ([#314](https://github.com/Taceolabs/co-snarks/issues/314)) ([c3367a5](https://github.com/Taceolabs/co-snarks/commit/c3367a55b95c3132cfbb6401c6ec1230f46e099c))
* Add rep3 and shamir implementations of poseidon2 to mpc-core ([0939053](https://github.com/Taceolabs/co-snarks/commit/09390537eac78086a1df7b49e17a3c8ae2eba8ff))
* add shared/public int division ([d1d2121](https://github.com/Taceolabs/co-snarks/commit/d1d21215997e1a854d2919db47a8b7bbbc541747))
* add shared/shared to co-brillig ([b54b4ee](https://github.com/Taceolabs/co-snarks/commit/b54b4eeea091431a7f06eb0a87eb5e0e87ceb2b4))
* better network handling in poseidon bench binary ([5334f6f](https://github.com/Taceolabs/co-snarks/commit/5334f6fc3ce7e5ca67eacd1dcad5d1f51a233c72))
* Bridge the co-builder and adapted proving-key generation and fix ([9df797b](https://github.com/Taceolabs/co-snarks/commit/9df797b21af60b7fb3030c58a7739003a627f6fd))
* Cleanup the mpc-core and builder after shared LUT integration ([a691090](https://github.com/Taceolabs/co-snarks/commit/a691090d4933b2e93b9707a48ed430687d2911ba))
* Extend ROM access for coNoir to the MPC setting of having shared indices ([c50809e](https://github.com/Taceolabs/co-snarks/commit/c50809eb891bfa29cb93406781fa4431aec1205b))
* implemented bitwise_and, bitwise_xor and bitwise_not in the ([57b8fef](https://github.com/Taceolabs/co-snarks/commit/57b8fef7dd4ea837cbccdc30718833ba72767253))
* Move poseidon2 from ultrahonk to mpc-core ([380fc4d](https://github.com/Taceolabs/co-snarks/commit/380fc4d7541053c06992b13a1e9fb1c42d4600e2))
* optimize radix sort to take private and public inputs, such that public inputs do not have to be decomposed/bitinjected ([#319](https://github.com/Taceolabs/co-snarks/issues/319)) ([bd1b6b4](https://github.com/Taceolabs/co-snarks/commit/bd1b6b400c3342b40b40d2532d6fbde1135c109d))
* Starting to adapt the co-builder for handling shared LUTs ([5fda228](https://github.com/Taceolabs/co-snarks/commit/5fda22875cfaca240f23f2b5744997c5da4b93f2))
* to_radix for public radix ([8ccd753](https://github.com/Taceolabs/co-snarks/commit/8ccd753975d8a4e11fe8ed90cc757d9739d988dd))
* to_radix for public val/shared radix ([540780b](https://github.com/Taceolabs/co-snarks/commit/540780b81d4ee4772df09a7997c42af6f476ff6d))


### Bug Fixes

* enable parallelization for poseidon merkle tree implementations ([fde2704](https://github.com/Taceolabs/co-snarks/commit/fde270441dfcf66eb3eca76a0bd2199deccd26d5))
* Fix a bug preventing constants from being used in garbled circuits. TODO: Adapt the division circuits to use constants whenever possible ([9d1b4d3](https://github.com/Taceolabs/co-snarks/commit/9d1b4d339e8f69d256e78cc1451c440f87e9745f))
* Fix a bug with shifting BigUints in Range constraints ([#318](https://github.com/Taceolabs/co-snarks/issues/318)) ([06c114a](https://github.com/Taceolabs/co-snarks/commit/06c114a00a58a01ef777473bc8991334b561c3cc))


### Code Refactoring

* co-circom lib usability improvents, added lib usage examples ([5768011](https://github.com/Taceolabs/co-snarks/commit/576801192076a27c75cd07fe1ec62244700bb934))
* input shares are always rep3 and not compressed ([e760ec0](https://github.com/Taceolabs/co-snarks/commit/e760ec0c47f2432a137f1fa74e57d0c5bdbcf902))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * mpc-net bumped from 0.2.1 to 0.3.0

## [0.7.0](https://github.com/TaceoLabs/co-snarks/compare/mpc-core-v0.6.0...mpc-core-v0.7.0) (2024-12-16)


### ⚠ BREAKING CHANGES

* **!:** Added functionality to traits of brillig/acvm
* Added docs for brillig. Also updated the trait to better match the functionallity
* modified traits for ACVM
* Start adding replicated secret sharing for rings

### Features

* **!:** first version of shared if by forking brillig ([a25e4a5](https://github.com/TaceoLabs/co-snarks/commit/a25e4a5cb5cdc912197871803c5872c08777b8a7))
* Add casts bestween different ring-shares, and cast between rings ([e680da6](https://github.com/TaceoLabs/co-snarks/commit/e680da667434a03721bd0da3a50fce2a1aa52d78))
* Add functionality to reshare a vector of fieldshares from two parties to a 3rd ([#292](https://github.com/TaceoLabs/co-snarks/issues/292)) ([65f5be1](https://github.com/TaceoLabs/co-snarks/commit/65f5be1ae201e312e9b942e4edc1c5285be64d76))
* Add remaing rep3 ring implementations. Untested so far ([b8c9a12](https://github.com/TaceoLabs/co-snarks/commit/b8c9a1296fff697c7afaa43cea452ad8e061e2c4))
* Add tests for the REP3 ring implementation and fix minor bugs" ([ae3408a](https://github.com/TaceoLabs/co-snarks/commit/ae3408ab7d43ff1b40e31a846d0bda3c5edc5475))
* Allow on-the-fly preprocessing for Shamir ([699ea14](https://github.com/TaceoLabs/co-snarks/commit/699ea14d7b0e4366e10c43c6c7e758755a8ba3be))
* first plain unconstrained fn working ([56e1c80](https://github.com/TaceoLabs/co-snarks/commit/56e1c801e6d51c8e35f1f1b1b2b007d80f050999))
* implement a radix sort in MPC and use it for range checks in co-noir ([#290](https://github.com/TaceoLabs/co-snarks/issues/290)) ([bc8c458](https://github.com/TaceoLabs/co-snarks/commit/bc8c45859f02932666c5306c00d2666011311505))
* implement many featuers for the co-brillig rep3 backend ([#284](https://github.com/TaceoLabs/co-snarks/issues/284)) ([11e0b03](https://github.com/TaceoLabs/co-snarks/commit/11e0b03b8ca437e48e0ac80e2cff870f530c58c0))
* Start adding replicated secret sharing for rings ([f4dca00](https://github.com/TaceoLabs/co-snarks/commit/f4dca000f4c9e978c69af8684d69375d85641417))


### Bug Fixes

* Fix the GC for the ring-to-ring upcast ([b5bf8b1](https://github.com/TaceoLabs/co-snarks/commit/b5bf8b113fd493750766496f83e80fa643114317))


### Documentation

* Added docs for brillig. Also updated the trait to better match the functionallity ([a2df63a](https://github.com/TaceoLabs/co-snarks/commit/a2df63aa1048364e484bde31013a1c5bbe4a9da3))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * mpc-net bumped from 0.2.0 to 0.2.1

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
