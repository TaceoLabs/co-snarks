# Changelog

## [0.10.0](https://github.com/TaceoLabs/co-snarks/compare/circom-types-v0.9.0...circom-types-v0.10.0) (2025-11-06)


### ⚠ BREAKING CHANGES

* move witness and input parsing/sharing to new crates for wasm comp
* unify MPC networks, split protocol state and networking to allow fork of state without network, replace io::Error with eyre, merge mpc-core and mpc-types with feature gated mpc-net

### Features

* add convert-zkey-to-ark binary ([#474](https://github.com/TaceoLabs/co-snarks/issues/474)) ([2fe2ccf](https://github.com/TaceoLabs/co-snarks/commit/2fe2ccf03b38d9f0a24c3764865e9787bf7b2ea8))
* move witness and input parsing/sharing to new crates for wasm comp ([333785e](https://github.com/TaceoLabs/co-snarks/commit/333785e275bc9256fb82fd8e2dcf18689bd92862))
* update rust edition to 2024 ([6ea0ba9](https://github.com/TaceoLabs/co-snarks/commit/6ea0ba9f9f34063e8ab859c1d4ae41d05629a1c0))


### Bug Fixes

* align witness variable count with arkworks (only count the private ones here) ([2dfd9af](https://github.com/TaceoLabs/co-snarks/commit/2dfd9af84ebbcfe4be6c4e22fe58d78bde52172b))
* circom ZKey parsing now also produces a valid VerifyingKey. ([118de75](https://github.com/TaceoLabs/co-snarks/commit/118de7595cbc34110226fc91a4aec68654d50e51))
* remove unwraps and replace new with new_unchecked to avoid panics in circom ark compat ([dd82cc8](https://github.com/TaceoLabs/co-snarks/commit/dd82cc8ef161b1c5dee69f6e9b79bde05aac0609))


### Code Refactoring

* unify MPC networks, split protocol state and networking to allow fork of state without network, replace io::Error with eyre, merge mpc-core and mpc-types with feature gated mpc-net ([16dbf54](https://github.com/TaceoLabs/co-snarks/commit/16dbf546d8f2d80ad4fa9f5053da19edc7270d3c))

## [0.9.0](https://github.com/TaceoLabs/co-snarks/compare/circom-types-v0.8.0...circom-types-v0.9.0) (2025-04-03)


### ⚠ BREAKING CHANGES

* rename Groth16Proof to CircomGroth16Proof
* change co-groth16 to no longer use circom types, use `ark-groth16` types instead wherever possible
* use more ark_groth16 types internally and provide conversions

### Features

* add optional support for bls12-377 ([87574ba](https://github.com/TaceoLabs/co-snarks/commit/87574ba792292d3df8f214d7f5a2d3ef2540c3ff))
* add penumbra libsnark co-groth16 tests ([9ce032c](https://github.com/TaceoLabs/co-snarks/commit/9ce032c83857303a03c768339f34d468c49a15fe))
* use ark-bls12-* as dev deps in co-groth16, enable features in dev dep ([95fa411](https://github.com/TaceoLabs/co-snarks/commit/95fa4113a86de6c8bc5ccb90ed7c4de5048cbb56))


### Code Refactoring

* change co-groth16 to no longer use circom types, use `ark-groth16` types instead wherever possible ([c558ce0](https://github.com/TaceoLabs/co-snarks/commit/c558ce0188fd70b290fb6342e7aa556ce880f3ff))
* rename Groth16Proof to CircomGroth16Proof ([4b565c7](https://github.com/TaceoLabs/co-snarks/commit/4b565c7b6b80cd60203cd35e6e16cfae40ec2a11))
* use more ark_groth16 types internally and provide conversions ([bf4572a](https://github.com/TaceoLabs/co-snarks/commit/bf4572a71349a9fedb81b2b5e0fa422da7d65a49))

## [0.8.0](https://github.com/Taceolabs/co-snarks/compare/circom-types-v0.7.0...circom-types-v0.8.0) (2025-02-20)


### ⚠ BREAKING CHANGES

* a lot of APIs and types changed

### Code Refactoring

* co-circom lib usability improvents, added lib usage examples ([5768011](https://github.com/Taceolabs/co-snarks/commit/576801192076a27c75cd07fe1ec62244700bb934))

## [0.7.0](https://github.com/TaceoLabs/co-snarks/compare/circom-types-v0.6.0...circom-types-v0.7.0) (2024-12-16)


### ⚠ BREAKING CHANGES

* Now the verify impls from groth16/plonk circom return an error indicating whether it was a success or not
* Removed unnecessary parts of the zkey
* changed the traits for circom bridge. Also modified the from_reader impl for the two Zkeys

### Features

* now can specify whether we want curve checks during zkey deser ([e1c03f3](https://github.com/TaceoLabs/co-snarks/commit/e1c03f3ba979bface5ea79062d95ffc088fdfda0))


### Bug Fixes

* added a check during groth16 prover for public inputs ([76466eb](https://github.com/TaceoLabs/co-snarks/commit/76466eb2d662efa4d5061e53e09470740763c77f))


### Code Refactoring

* Removed ark_relations deps. Also changed verify impls to not return bool but a common error ([b4f4bf1](https://github.com/TaceoLabs/co-snarks/commit/b4f4bf16beaa83108bc2ae6c6f972ab4e4da4473))
* Removed unnecessary parts of the zkey ([0713260](https://github.com/TaceoLabs/co-snarks/commit/071326056a8d47aca9d72e8848773981a3cbbc89))

## [0.6.0](https://github.com/TaceoLabs/co-snarks/compare/circom-types-v0.5.0...circom-types-v0.6.0) (2024-11-12)


### ⚠ BREAKING CHANGES

* the prover for Groth16/Plonk now expects an Arc<ZKey>. Cleaner than having multiple Arcs in ZKey

### Code Refactoring

* prove for circom now expect Arc&lt;ZKey&gt; ([c2ac465](https://github.com/TaceoLabs/co-snarks/commit/c2ac465ebf6f3a28b902d9f0489e3f57c0843d7f))

## [0.5.0](https://github.com/TaceoLabs/collaborative-circom/compare/circom-types-v0.4.0...circom-types-v0.5.0) (2024-08-21)


### ⚠ BREAKING CHANGES

* we hardcoded bn128 as prime for the compiler. We now give either bn128 or bls12381 depending on curve. Introduces new trait bounds therefore breaking change

### Bug Fixes

* fixed a bug in bls12_381 zkey parsing ([#165](https://github.com/TaceoLabs/collaborative-circom/issues/165)) ([0a8f35e](https://github.com/TaceoLabs/collaborative-circom/commit/0a8f35e4ca641423d73027e42e7b26f955964b8f))
* fixes prime for the mpc compiler ([5712184](https://github.com/TaceoLabs/collaborative-circom/commit/5712184748488b7bab735b456be25e9cbbdb5ff7))

## [0.4.0](https://github.com/TaceoLabs/collaborative-circom/compare/circom-types-v0.3.0...circom-types-v0.4.0) (2024-08-14)


### ⚠ BREAKING CHANGES

* renamed the method from_reader_unchecked and from_reader_unchecked_for_zkey to better names showing were to use them
* PLONK uses the witness struct, therefore we moved it from Groth16 to one level higher
* we hide the modules defining the zkey, proof, vk, and witness and use pub use the re-export them
* the verifier (and the arkwork dep) is now hidden behind the "verifier" feature. Also we refactored some stuff in Groth16 to mirror PLONK.
* removed Our* types from groth16 zkey
* groth16 zkey parsing is now multithreaded, added multithreaded g1/2_vec_from_reader
* circom-arkworks bridge trait now has a method to return name of curve
* Adds a method to the ArkworksPairingBridge trait

### Features

* add deserialization of plonk circom types ([d1f0d4d](https://github.com/TaceoLabs/collaborative-circom/commit/d1f0d4dd5ac63e85523c139e573161bd2ff0061a))
* circom-arkworks bridge trait now has a method to return name of curve ([b1e33dd](https://github.com/TaceoLabs/collaborative-circom/commit/b1e33dd52ccd422ce3197b670b83653c5eafecb9))
* groth16 zkey parsing is now multithreaded, added multithreaded g1/2_vec_from_reader ([b1e46f7](https://github.com/TaceoLabs/collaborative-circom/commit/b1e46f72df537b73e222b7d0dd7cdf17e549a9f0))
* plonk support ([9b65797](https://github.com/TaceoLabs/collaborative-circom/commit/9b6579724f6f5ba4fc6af8a98d386b96818dc08b))


### Bug Fixes

* clippy 1.80 introduces a wrong warning ([a593904](https://github.com/TaceoLabs/collaborative-circom/commit/a593904c98686f442b747173d70fc3d2aa991566))


### Code Refactoring

* Added verifier feature for Groth16 ([489614c](https://github.com/TaceoLabs/collaborative-circom/commit/489614cf9242f63c9f9914aaf0b6cc6555deab4c))
* clearer name for montgomery reader ([a9582b7](https://github.com/TaceoLabs/collaborative-circom/commit/a9582b713162d43b2de88b9d9ce2f0cfaeb5d9c8))
* move the groth16 circom types ([fabc5e7](https://github.com/TaceoLabs/collaborative-circom/commit/fabc5e72343f08eea96efde4556dffac60d954cb))
* moved the witness struct ([9cee70b](https://github.com/TaceoLabs/collaborative-circom/commit/9cee70bc58f1980035d02e46e6ea9082a3368182))
* removed Our* types from groth16 zkey ([1f1d1bc](https://github.com/TaceoLabs/collaborative-circom/commit/1f1d1bcc80eee037a803661f39cc5c5450ae5c14))

## [0.3.0](https://github.com/TaceoLabs/collaborative-circom/compare/circom-types-v0.2.0...circom-types-v0.3.0) (2024-07-10)


### ⚠ BREAKING CHANGES

* remove internal structs from public crate interface, removed unused code ([#120](https://github.com/TaceoLabs/collaborative-circom/issues/120))

### Code Refactoring

* remove internal structs from public crate interface, removed unused code ([#120](https://github.com/TaceoLabs/collaborative-circom/issues/120)) ([f5cabe6](https://github.com/TaceoLabs/collaborative-circom/commit/f5cabe679ef24cebe5e109a5bac9ba63401596b2))

## [0.2.0](https://github.com/TaceoLabs/collaborative-circom/compare/circom-types-v0.1.0...circom-types-v0.2.0) (2024-07-09)


### Features

* build own zkey that can ser/de ([5a9d055](https://github.com/TaceoLabs/collaborative-circom/commit/5a9d0555f196f4d3537623b6aa056476a466926c))
* can swap between ourzkey and old ([f1fcae2](https://github.com/TaceoLabs/collaborative-circom/commit/f1fcae2a7894aca5cec812c19dc2f4c5e1f5f8d6))

## [0.1.0](https://github.com/TaceoLabs/collaborative-circom/compare/circom-types-v0.0.1...circom-types-v0.1.0) (2024-06-14)


### Features

* added circuit definition and test for proving/verifying ([72a5ca7](https://github.com/TaceoLabs/collaborative-circom/commit/72a5ca7db0b6cd3e954d3736e2b1e6490e0bbba2))
* added collaborative groth16 prover ([#18](https://github.com/TaceoLabs/collaborative-circom/issues/18)) ([6e5bb98](https://github.com/TaceoLabs/collaborative-circom/commit/6e5bb98afa5be816188bc019036ba4786f448749))
* added deser for r1cs for bn254/bls12_381 ([cba944a](https://github.com/TaceoLabs/collaborative-circom/commit/cba944a917fbe346a20b1caafd192b3e212a892b))
* added support for bls12_381 ([3f589c2](https://github.com/TaceoLabs/collaborative-circom/commit/3f589c2e52b8f6c0a6392835374ce96c72e883e8))
* first version of command line interface ([#36](https://github.com/TaceoLabs/collaborative-circom/issues/36)) ([6abe716](https://github.com/TaceoLabs/collaborative-circom/commit/6abe716268f1e165cdae07a10f4d2dafd010cc04))
* first version of mpc vm ([#42](https://github.com/TaceoLabs/collaborative-circom/issues/42)) ([6dcd5f4](https://github.com/TaceoLabs/collaborative-circom/commit/6dcd5f4ce7c8431b94dd7262a4219a3a63efd702))
* proof and verify circom proofs ([#11](https://github.com/TaceoLabs/collaborative-circom/issues/11)) ([1b379b8](https://github.com/TaceoLabs/collaborative-circom/commit/1b379b85a7b9f622feed7a914ab8712d726d9760))
* public inputs support ([#76](https://github.com/TaceoLabs/collaborative-circom/issues/76)) ([07cf260](https://github.com/TaceoLabs/collaborative-circom/commit/07cf26007285822ba42e8dce2439f676a2cf08ef))
* serde for circom generated proofs ([#9](https://github.com/TaceoLabs/collaborative-circom/issues/9)) ([0f32d59](https://github.com/TaceoLabs/collaborative-circom/commit/0f32d59f88239b3cc5f5be06ad8c97945d79cb9b))
* witness deserialize done ([6a3f5d9](https://github.com/TaceoLabs/collaborative-circom/commit/6a3f5d99154032452de685ecee3de19e90c64843))
* z_key deser for bn254 working ([ca4b94f](https://github.com/TaceoLabs/collaborative-circom/commit/ca4b94f50e07c47fe8db94ada09e22ea2cfcdaa7))


### Bug Fixes

* correct deserialization of matrices in zkey ([a060575](https://github.com/TaceoLabs/collaborative-circom/commit/a0605758ea81f16df9cf3c7785a77c290e900f5c))
