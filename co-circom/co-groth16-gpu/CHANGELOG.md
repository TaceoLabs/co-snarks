# Changelog

* The following workspace dependencies were updated
  * dependencies
    * circom-types bumped from 0.2.0 to 0.3.0
    * mpc-core bumped from 0.2.0 to 0.2.1
    * mpc-net bumped from 0.1.1 to 0.1.2

* The following workspace dependencies were updated
  * dependencies
    * co-circom-snarks bumped from 0.1.1 to 0.1.2
    * mpc-core bumped from 0.4.0 to 0.5.0

## [0.10.0](https://github.com/TaceoLabs/co-snarks/compare/co-groth16-v0.9.0...co-groth16-v0.10.0) (2025-11-06)


### ⚠ BREAKING CHANGES

* unify MPC networks, split protocol state and networking to allow fork of state without network, replace io::Error with eyre, merge mpc-core and mpc-types with feature gated mpc-net
* move MPC types and share/combine into new mpc-types crate, rename co-circom-snarks to co-circom-types

### Features

* add extension traits for REP3 and Shamir networks ([0c15da8](https://github.com/TaceoLabs/co-snarks/commit/0c15da81550f35c7aaef77d5143824a9436d5731))
* check the number of witness variables in groth16 prove_inner ([2a6c0cf](https://github.com/TaceoLabs/co-snarks/commit/2a6c0cfff44db8ff2f9cfbdf59aded0719780042))
* dont use rayon::join for networking - added std::thread::scope based join functions ([758b069](https://github.com/TaceoLabs/co-snarks/commit/758b0699ad0ef7bca7401afe9063848eb084873f))
* libsnark reduction multithreading ([3b2b4e0](https://github.com/TaceoLabs/co-snarks/commit/3b2b4e0e46410719cf91294b2629406396e8aa11))
* update rust edition to 2024 ([6ea0ba9](https://github.com/TaceoLabs/co-snarks/commit/6ea0ba9f9f34063e8ab859c1d4ae41d05629a1c0))


### Bug Fixes

* align witness variable count with arkworks (only count the private ones here) ([2dfd9af](https://github.com/TaceoLabs/co-snarks/commit/2dfd9af84ebbcfe4be6c4e22fe58d78bde52172b))


### Code Refactoring

* move MPC types and share/combine into new mpc-types crate, rename co-circom-snarks to co-circom-types ([31b773a](https://github.com/TaceoLabs/co-snarks/commit/31b773aa71a5e872c25754de7805b02647b65688))
* unify MPC networks, split protocol state and networking to allow fork of state without network, replace io::Error with eyre, merge mpc-core and mpc-types with feature gated mpc-net ([16dbf54](https://github.com/TaceoLabs/co-snarks/commit/16dbf546d8f2d80ad4fa9f5053da19edc7270d3c))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-circom-types bumped from 0.5.0 to 0.6.0
    * mpc-core bumped from 0.9.0 to 0.10.0
    * mpc-net bumped from 0.4.0 to 0.5.0
  * dev-dependencies
    * circom-types bumped from 0.9.0 to 0.10.0

## [0.9.0](https://github.com/TaceoLabs/co-snarks/compare/co-groth16-v0.8.0...co-groth16-v0.9.0) (2025-04-03)


### ⚠ BREAKING CHANGES

* make only prove method generic over R1CSToQAP reduction trait
* reduce MPC related methods in Groth16
* adds a method to the MPC trait for Groth16
* factor out used R1CSToQAP reduction method into a trait for co-groth16
* rename Groth16Proof to CircomGroth16Proof
* change co-groth16 to no longer use circom types, use `ark-groth16` types instead wherever possible
* use ark_groth16 types on crate boundary
* Public API of coGroth16 driver trait changed to include `HalfShare` types. ---------

### Features

* add penumbra libsnark co-groth16 tests ([9ce032c](https://github.com/TaceoLabs/co-snarks/commit/9ce032c83857303a03c768339f34d468c49a15fe))
* add the libsnark R1CSToQAP reduction. ([ae9d468](https://github.com/TaceoLabs/co-snarks/commit/ae9d468d5663f300a49efd47f6a3666c41b71214))
* use ark-bls12-* as dev deps in co-groth16, enable features in dev dep ([95fa411](https://github.com/TaceoLabs/co-snarks/commit/95fa4113a86de6c8bc5ccb90ed7c4de5048cbb56))


### Code Refactoring

* change co-groth16 to no longer use circom types, use `ark-groth16` types instead wherever possible ([c558ce0](https://github.com/TaceoLabs/co-snarks/commit/c558ce0188fd70b290fb6342e7aa556ce880f3ff))
* factor out used R1CSToQAP reduction method into a trait for co-groth16 ([f0c26b0](https://github.com/TaceoLabs/co-snarks/commit/f0c26b092d3ae22ff29d783d0017f096fa7a2871))
* make only prove method generic over R1CSToQAP reduction trait ([e4cbe34](https://github.com/TaceoLabs/co-snarks/commit/e4cbe347a32a6ce89e238411c82fac860dfdb1d0))
* reduce MPC related methods in Groth16 ([e16f336](https://github.com/TaceoLabs/co-snarks/commit/e16f3360412b0e4c2b6a7c5b7cab411c4720ec54))
* Reduce work for Groth16 REP3 by working over un-replicated shares as much as possible ([#349](https://github.com/TaceoLabs/co-snarks/issues/349)) ([42068eb](https://github.com/TaceoLabs/co-snarks/commit/42068eb7a1f30f3af4a455f259336dcbabf57eb4))
* rename Groth16Proof to CircomGroth16Proof ([4b565c7](https://github.com/TaceoLabs/co-snarks/commit/4b565c7b6b80cd60203cd35e6e16cfae40ec2a11))
* use ark_groth16 types on crate boundary ([5c82a55](https://github.com/TaceoLabs/co-snarks/commit/5c82a550ba2cb6ab7f399c12461e4ce1c4949752))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-circom-snarks bumped from 0.4.0 to 0.5.0
    * mpc-core bumped from 0.8.0 to 0.9.0
    * mpc-net bumped from 0.3.0 to 0.4.0
  * dev-dependencies
    * circom-types bumped from 0.8.0 to 0.9.0

## [0.8.0](https://github.com/Taceolabs/co-snarks/compare/co-groth16-v0.7.0...co-groth16-v0.8.0) (2025-02-20)


### ⚠ BREAKING CHANGES

* ark to 0.5.0, co-noir witext works with 1.0.0-beta.2
* a lot of APIs and types changed

### Features

* ark to 0.5.0, co-noir witext works with 1.0.0-beta.2 ([8a466df](https://github.com/Taceolabs/co-snarks/commit/8a466dffde68d64bed8265e1336e454559898602))


### Code Refactoring

* co-circom lib usability improvents, added lib usage examples ([5768011](https://github.com/Taceolabs/co-snarks/commit/576801192076a27c75cd07fe1ec62244700bb934))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-types bumped from 0.7.0 to 0.8.0
    * co-circom-snarks bumped from 0.3.0 to 0.4.0
    * mpc-core bumped from 0.7.0 to 0.8.0
    * mpc-net bumped from 0.2.1 to 0.3.0

## [0.7.0](https://github.com/TaceoLabs/co-snarks/compare/co-groth16-v0.6.0...co-groth16-v0.7.0) (2024-12-16)


### ⚠ BREAKING CHANGES

* Now the verify impls from groth16/plonk circom return an error indicating whether it was a success or not
* Removed unnecessary parts of the zkey
* changed the traits for circom bridge. Also modified the from_reader impl for the two Zkeys
* Removes the zkey in the said function signature. We needed it earlier because we had to know domain size, which we now no longer need.
* the prover for Groth16/Plonk now expects an Arc<ZKey>. Cleaner than having multiple Arcs in ZKey
* the public interface of the Groth16MPCProver trait has changed.
* refactors everything that all groth16 specific functionallity is not in MPC-core anymore.

### Features

* added plain prover shorthand function ([b365fcd](https://github.com/TaceoLabs/co-snarks/commit/b365fcd89390dad585933f39a2db32473081d060))
* now can specify whether we want curve checks during zkey deser ([e1c03f3](https://github.com/TaceoLabs/co-snarks/commit/e1c03f3ba979bface5ea79062d95ffc088fdfda0))
* prepare functions for compressed rep3 sharing ([55bef10](https://github.com/TaceoLabs/co-snarks/commit/55bef10313378e8ca14f2f22f312c84462a92a7e))
* refactors all according to MPC-core + Rayon ([44a5d2d](https://github.com/TaceoLabs/co-snarks/commit/44a5d2d4f1e406331f127cd89de369a66d41b105))


### Bug Fixes

* added a check during groth16 prover for public inputs ([76466eb](https://github.com/TaceoLabs/co-snarks/commit/76466eb2d662efa4d5061e53e09470740763c77f))


### Code Refactoring

* make pointshare in Groth16 MPC trait generic over the curve ([dc5acd2](https://github.com/TaceoLabs/co-snarks/commit/dc5acd28db03920982de623f51dd4df236ff7381))
* prove for circom now expect Arc&lt;ZKey&gt; ([c2ac465](https://github.com/TaceoLabs/co-snarks/commit/c2ac465ebf6f3a28b902d9f0489e3f57c0843d7f))
* Removed ark_relations deps. Also changed verify impls to not return bool but a common error ([b4f4bf1](https://github.com/TaceoLabs/co-snarks/commit/b4f4bf16beaa83108bc2ae6c6f972ab4e4da4473))
* Removed unnecessary parts of the zkey ([0713260](https://github.com/TaceoLabs/co-snarks/commit/071326056a8d47aca9d72e8848773981a3cbbc89))
* with_network_config for ShamirGroth16 doesn't need zkey anymore ([2052d89](https://github.com/TaceoLabs/co-snarks/commit/2052d89cc4abb531702886daf70c47ee3b1ecf1a))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-types bumped from 0.6.0 to 0.7.0
    * co-circom-snarks bumped from 0.2.0 to 0.3.0
    * mpc-core bumped from 0.6.0 to 0.7.0
    * mpc-net bumped from 0.2.0 to 0.2.1

## [0.6.0](https://github.com/TaceoLabs/co-snarks/compare/co-groth16-v0.5.1...co-groth16-v0.6.0) (2024-11-12)


### ⚠ BREAKING CHANGES

* Removes the zkey in the said function signature. We needed it earlier because we had to know domain size, which we now no longer need.
* the prover for Groth16/Plonk now expects an Arc<ZKey>. Cleaner than having multiple Arcs in ZKey
* the public interface of the Groth16MPCProver trait has changed.
* refactors everything that all groth16 specific functionallity is not in MPC-core anymore.

### Features

* added plain prover shorthand function ([b365fcd](https://github.com/TaceoLabs/co-snarks/commit/b365fcd89390dad585933f39a2db32473081d060))
* prepare functions for compressed rep3 sharing ([55bef10](https://github.com/TaceoLabs/co-snarks/commit/55bef10313378e8ca14f2f22f312c84462a92a7e))
* refactors all according to MPC-core + Rayon ([44a5d2d](https://github.com/TaceoLabs/co-snarks/commit/44a5d2d4f1e406331f127cd89de369a66d41b105))


### Code Refactoring

* make pointshare in Groth16 MPC trait generic over the curve ([dc5acd2](https://github.com/TaceoLabs/co-snarks/commit/dc5acd28db03920982de623f51dd4df236ff7381))
* prove for circom now expect Arc&lt;ZKey&gt; ([c2ac465](https://github.com/TaceoLabs/co-snarks/commit/c2ac465ebf6f3a28b902d9f0489e3f57c0843d7f))
* with_network_config for ShamirGroth16 doesn't need zkey anymore ([2052d89](https://github.com/TaceoLabs/co-snarks/commit/2052d89cc4abb531702886daf70c47ee3b1ecf1a))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-types bumped from 0.5.0 to 0.6.0
    * co-circom-snarks bumped from 0.1.2 to 0.2.0
    * mpc-core bumped from 0.5.0 to 0.6.0
    * mpc-net bumped from 0.1.2 to 0.2.0

## [0.5.0](https://github.com/TaceoLabs/collaborative-circom/compare/co-groth16-v0.4.0...co-groth16-v0.5.0) (2024-08-21)


### ⚠ BREAKING CHANGES

* we fixed a bug, where the (i)ffts for bls12_381 had a different permutation than from snarkjs. We removed our band-aid fix (FFTPostProcessing). Therfore, it is a breaking change.

### Bug Fixes

* fixes the bls12_381 permutation from arkworks ([f100615](https://github.com/TaceoLabs/collaborative-circom/commit/f100615790c51227d89e886ee6977367e4d5a1ce))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-types bumped from 0.4.0 to 0.5.0
    * co-circom-snarks bumped from 0.1.0 to 0.1.1
    * mpc-core bumped from 0.3.0 to 0.4.0

## [0.4.0](https://github.com/TaceoLabs/collaborative-circom/compare/co-groth16-v0.3.0...co-groth16-v0.4.0) (2024-08-14)


### ⚠ BREAKING CHANGES

* We renamed all crate names from collaborative-* to co-* for brevity, and also shortened `Collaborative` to `Co` in many types.

### Code Refactoring

* renamed crates to co-* ([#161](https://github.com/TaceoLabs/collaborative-circom/issues/161)) ([37f3493](https://github.com/TaceoLabs/collaborative-circom/commit/37f3493b25e41b43bbc8a89e281ae2dcb4b95484))

## [0.3.0](https://github.com/TaceoLabs/collaborative-circom/compare/collaborative-groth16-v0.2.1...collaborative-groth16-v0.3.0) (2024-08-14)


### ⚠ BREAKING CHANGES

* moved common code for PLONK and Groth16 into separate crate. Most notably the SharedWitness and SharedInput
* Make MPC-VM thread safe and implement better Clone for shared inputs and witnesses ([#158](https://github.com/TaceoLabs/collaborative-circom/issues/158))
* PLONK uses the witness struct, therefore we moved it from Groth16 to one level higher
* removed files that were used by arkworks groth16
* we hide the modules defining the zkey, proof, vk, and witness and use pub use the re-export them
* the verifier (and the arkwork dep) is now hidden behind the "verifier" feature. Also we refactored some stuff in Groth16 to mirror PLONK.
* share_rep3 and share_shamir interfaces changed
* Adds a method to the ArkworksPairingBridge trait

### Features

* add deserialization of plonk circom types ([d1f0d4d](https://github.com/TaceoLabs/collaborative-circom/commit/d1f0d4dd5ac63e85523c139e573161bd2ff0061a))
* Make MPC-VM thread safe and implement better Clone for shared inputs and witnesses ([#158](https://github.com/TaceoLabs/collaborative-circom/issues/158)) ([a7ab3bb](https://github.com/TaceoLabs/collaborative-circom/commit/a7ab3bbecd93b393c08e18d8ea89a64a25bac3a3))
* plonk support ([9b65797](https://github.com/TaceoLabs/collaborative-circom/commit/9b6579724f6f5ba4fc6af8a98d386b96818dc08b))


### Code Refactoring

* added new crate co-circom-snarks ([ea3190f](https://github.com/TaceoLabs/collaborative-circom/commit/ea3190f4d731893e6fcce71976c32b3bbac6b89b))
* Added verifier feature for Groth16 ([489614c](https://github.com/TaceoLabs/collaborative-circom/commit/489614cf9242f63c9f9914aaf0b6cc6555deab4c))
* move the groth16 circom types ([fabc5e7](https://github.com/TaceoLabs/collaborative-circom/commit/fabc5e72343f08eea96efde4556dffac60d954cb))
* moved the witness struct ([9cee70b](https://github.com/TaceoLabs/collaborative-circom/commit/9cee70bc58f1980035d02e46e6ea9082a3368182))
* removed files that were used by arkworks groth16 ([d38e8a5](https://github.com/TaceoLabs/collaborative-circom/commit/d38e8a576d0f6375f1dc4f4d01d5fd59fa4c1438))
* share_rep3 and share_shamir interfaces changed ([5e7420f](https://github.com/TaceoLabs/collaborative-circom/commit/5e7420f95a46466304c2ab80de2069c2feb3432d))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-types bumped from 0.3.0 to 0.4.0
    * mpc-core bumped from 0.2.1 to 0.3.0

## [0.2.0](https://github.com/TaceoLabs/collaborative-circom/compare/collaborative-groth16-v0.1.0...collaborative-groth16-v0.2.0) (2024-07-09)


### ⚠ BREAKING CHANGES

* document collaborative-groth16

### Features

* added a lot tracings ([c4f24d1](https://github.com/TaceoLabs/collaborative-circom/commit/c4f24d15f0c7af0560fbffe4a4aaedda2fa515e8))
* added interfaces to add values to SharedInput ([abe8db7](https://github.com/TaceoLabs/collaborative-circom/commit/abe8db75911eea82fc00e8a981bfe093e0e0b3d4))


### Bug Fixes

* implement optional post-processing permutation for FFTs and correct root of unity calculation to match circom output ([5ab3292](https://github.com/TaceoLabs/collaborative-circom/commit/5ab329294959c85ea6e0823cbe651ba6efa747f8))


### Documentation

* document collaborative-groth16 ([56b873c](https://github.com/TaceoLabs/collaborative-circom/commit/56b873c6c60032dea27ee5640418b7e92bf837ec))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-types bumped from 0.1.0 to 0.2.0
    * mpc-core bumped from 0.1.0 to 0.2.0
    * mpc-net bumped from 0.1.0 to 0.1.1

## [0.1.0](https://github.com/TaceoLabs/collaborative-circom/compare/collaborative-groth16-v0.0.1...collaborative-groth16-v0.1.0) (2024-06-14)


### ⚠ BREAKING CHANGES

* remove slice and slicemut types from traits

### Features

* Add semi-honest GSZ (i.e., Shamir) ([#21](https://github.com/TaceoLabs/collaborative-circom/issues/21)) ([746edb4](https://github.com/TaceoLabs/collaborative-circom/commit/746edb45d14da4d8a54f7503848a4e62e2bfc899))
* added circuit definition and test for proving/verifying ([72a5ca7](https://github.com/TaceoLabs/collaborative-circom/commit/72a5ca7db0b6cd3e954d3736e2b1e6490e0bbba2))
* added collaborative groth16 prover ([#18](https://github.com/TaceoLabs/collaborative-circom/issues/18)) ([6e5bb98](https://github.com/TaceoLabs/collaborative-circom/commit/6e5bb98afa5be816188bc019036ba4786f448749))
* added skeleton for mpc/collab-groth16 ([#12](https://github.com/TaceoLabs/collaborative-circom/issues/12)) ([9c03331](https://github.com/TaceoLabs/collaborative-circom/commit/9c03331171429f061ead8cddda292cd97d498f1a))
* Creating Proof from assignment in MPC ([#17](https://github.com/TaceoLabs/collaborative-circom/issues/17)) ([cc4f6f5](https://github.com/TaceoLabs/collaborative-circom/commit/cc4f6f5de873fea80bd51a724dbd001d6351f68d))
* First impl for Circom Parser to MPC.  ([#26](https://github.com/TaceoLabs/collaborative-circom/issues/26)) ([779682d](https://github.com/TaceoLabs/collaborative-circom/commit/779682d7d824d782109db8b4584604b23637dad7))
* first version of command line interface ([#36](https://github.com/TaceoLabs/collaborative-circom/issues/36)) ([6abe716](https://github.com/TaceoLabs/collaborative-circom/commit/6abe716268f1e165cdae07a10f4d2dafd010cc04))
* first version of mpc vm ([#42](https://github.com/TaceoLabs/collaborative-circom/issues/42)) ([6dcd5f4](https://github.com/TaceoLabs/collaborative-circom/commit/6dcd5f4ce7c8431b94dd7262a4219a3a63efd702))
* integrate witness extension via MPC VM into CLI binary ([f526081](https://github.com/TaceoLabs/collaborative-circom/commit/f526081a01e3faa6b48fb463f3690f968218a1a4))
* proof and verify circom proofs ([#11](https://github.com/TaceoLabs/collaborative-circom/issues/11)) ([1b379b8](https://github.com/TaceoLabs/collaborative-circom/commit/1b379b85a7b9f622feed7a914ab8712d726d9760))
* public inputs support ([#76](https://github.com/TaceoLabs/collaborative-circom/issues/76)) ([07cf260](https://github.com/TaceoLabs/collaborative-circom/commit/07cf26007285822ba42e8dce2439f676a2cf08ef))
* serde for circom generated proofs ([#9](https://github.com/TaceoLabs/collaborative-circom/issues/9)) ([0f32d59](https://github.com/TaceoLabs/collaborative-circom/commit/0f32d59f88239b3cc5f5be06ad8c97945d79cb9b))
* support merging shared inputs from multiple parties + examples ([#75](https://github.com/TaceoLabs/collaborative-circom/issues/75)) ([1168488](https://github.com/TaceoLabs/collaborative-circom/commit/11684884b3e1d2be6309fd98e1603626d5e58c93))
* traits and implementations of aby3 shares, fft's, and msm ([#16](https://github.com/TaceoLabs/collaborative-circom/issues/16)) ([a6bf90e](https://github.com/TaceoLabs/collaborative-circom/commit/a6bf90e6d326df3e9caa2dbbabf7bd60acb50fbd))
* use CanonicalSerialize from ark for ser/de of arkworks structures, with additional serde compat layer on top level ([e3e7af3](https://github.com/TaceoLabs/collaborative-circom/commit/e3e7af340d1fbfc148fbe6614b004a8c70aba1f0))
* use existing information in zkey to not require regeneration of matrices ([c7b75c3](https://github.com/TaceoLabs/collaborative-circom/commit/c7b75c34e69479bea06583e9fc17f3b1dc8f3d9a))
* witness creation for plain vm ([#37](https://github.com/TaceoLabs/collaborative-circom/issues/37)) ([45f8cfa](https://github.com/TaceoLabs/collaborative-circom/commit/45f8cfad24f83d8e4bca405bb782db33936e8ce0))


### Bug Fixes

* clippy lints ([1baa7fa](https://github.com/TaceoLabs/collaborative-circom/commit/1baa7fabadea77a213f38b212d5019f6c06b0b2b))
* eddsa_verify does work now ([#29](https://github.com/TaceoLabs/collaborative-circom/issues/29)) ([1ab0a80](https://github.com/TaceoLabs/collaborative-circom/commit/1ab0a806b8a9f32d2783ce9838826fe71a48d78f))
* fix a lifetime issue ([432ff31](https://github.com/TaceoLabs/collaborative-circom/commit/432ff314f78aa73cae6a606d6835a70283ea41e0))
* removed unnecessary sharing impls ([fd11cf7](https://github.com/TaceoLabs/collaborative-circom/commit/fd11cf7ebfb48a44dae065b8f2881b845f9e0df2))
* return the result ([7a45009](https://github.com/TaceoLabs/collaborative-circom/commit/7a450091f6638524385efd20db059f98d6f9db47))


### Code Refactoring

* remove slice and slicemut types from traits ([d60cd06](https://github.com/TaceoLabs/collaborative-circom/commit/d60cd0645a397898cd997a516dc513c7f29ecb55))
