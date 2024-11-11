# Changelog

* The following workspace dependencies were updated
  * dependencies
    * co-circom-snarks bumped from 0.1.1 to 0.1.2
    * mpc-core bumped from 0.4.0 to 0.5.0

## [0.4.0](https://github.com/TaceoLabs/co-snarks/compare/co-plonk-v0.3.1...co-plonk-v0.4.0) (2024-11-11)


### ⚠ BREAKING CHANGES

* the prover for Groth16/Plonk now expects an Arc<ZKey>. Cleaner than having multiple Arcs in ZKey
* now uses new mpc-core and forked networking but NO rayon

### Features

* prepare functions for compressed rep3 sharing ([55bef10](https://github.com/TaceoLabs/co-snarks/commit/55bef10313378e8ca14f2f22f312c84462a92a7e))
* refactor to use new mpc-core ([43da344](https://github.com/TaceoLabs/co-snarks/commit/43da344be00f00a46849508cea1d279cf29a95b2))


### Code Refactoring

* prove for circom now expect Arc&lt;ZKey&gt; ([c2ac465](https://github.com/TaceoLabs/co-snarks/commit/c2ac465ebf6f3a28b902d9f0489e3f57c0843d7f))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-types bumped from 0.5.0 to 0.6.0
    * co-circom-snarks bumped from 0.1.2 to 0.2.0
    * mpc-net bumped from 0.1.2 to 0.2.0
    * mpc-core bumped from 0.5.0 to 0.6.0

## [0.3.0](https://github.com/TaceoLabs/collaborative-circom/compare/co-plonk-v0.2.0...co-plonk-v0.3.0) (2024-08-21)


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

## [0.2.0](https://github.com/TaceoLabs/collaborative-circom/compare/co-plonk-v0.1.0...co-plonk-v0.2.0) (2024-08-14)


### ⚠ BREAKING CHANGES

* We renamed all crate names from collaborative-* to co-* for brevity, and also shortened `Collaborative` to `Co` in many types.

### Code Refactoring

* renamed crates to co-* ([#161](https://github.com/TaceoLabs/collaborative-circom/issues/161)) ([37f3493](https://github.com/TaceoLabs/collaborative-circom/commit/37f3493b25e41b43bbc8a89e281ae2dcb4b95484))

## 0.1.0 (2024-08-14)


### ⚠ BREAKING CHANGES

* to unify Groth16 and PLONK we now take the zkey as ref in PLONK when calling prove
* moved common code for PLONK and Groth16 into separate crate. Most notably the SharedWitness and SharedInput
* PLONK uses the witness struct, therefore we moved it from Groth16 to one level higher
* we hide the modules defining the zkey, proof, vk, and witness and use pub use the re-export them
* the verifier (and the arkwork dep) is now hidden behind the "verifier" feature. Also we refactored some stuff in Groth16 to mirror PLONK.

### Features

* plonk support ([9b65797](https://github.com/TaceoLabs/collaborative-circom/commit/9b6579724f6f5ba4fc6af8a98d386b96818dc08b))


### Code Refactoring

* added new crate co-circom-snarks ([ea3190f](https://github.com/TaceoLabs/collaborative-circom/commit/ea3190f4d731893e6fcce71976c32b3bbac6b89b))
* Added verifier feature for Groth16 ([489614c](https://github.com/TaceoLabs/collaborative-circom/commit/489614cf9242f63c9f9914aaf0b6cc6555deab4c))
* move the groth16 circom types ([fabc5e7](https://github.com/TaceoLabs/collaborative-circom/commit/fabc5e72343f08eea96efde4556dffac60d954cb))
* moved the witness struct ([9cee70b](https://github.com/TaceoLabs/collaborative-circom/commit/9cee70bc58f1980035d02e46e6ea9082a3368182))
* PLONK now takes zkey as ref for prove ([6f613e6](https://github.com/TaceoLabs/collaborative-circom/commit/6f613e6feffece37435da3960afa4d017fe4baa0))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-types bumped from 0.3.0 to 0.4.0
    * mpc-core bumped from 0.2.1 to 0.3.0
