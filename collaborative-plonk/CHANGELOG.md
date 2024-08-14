# Changelog

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
