# Changelog

* The following workspace dependencies were updated
  * dependencies
    * circom-mpc-compiler bumped from 0.6.0 to 0.6.1
    * circom-mpc-vm bumped from 0.4.1 to 0.4.2
    * co-circom-snarks bumped from 0.1.1 to 0.1.2
    * co-groth16 bumped from 0.5.0 to 0.5.1
    * co-plonk bumped from 0.3.0 to 0.3.1
    * mpc-core bumped from 0.4.0 to 0.5.0

## [0.7.0](https://github.com/TaceoLabs/co-snarks/compare/co-circom-v0.6.0...co-circom-v0.7.0) (2024-12-16)


### ⚠ BREAKING CHANGES

* Now the verify impls from groth16/plonk circom return an error indicating whether it was a success or not
* changed the traits for circom bridge. Also modified the from_reader impl for the two Zkeys
* serialization format of shared inputs has changed to allow for optional values used to indicate missing elements of an array
* MPC accelerator changed public API. Also now stores #output signals in component
* input to compiler now takes PathBuf
* run and run_with_flat methods on WitnessExtension now consume self again
* MpcNetworkHandler::establish now takes the config with already read certs and key.
* Removes the zkey in the said function signature. We needed it earlier because we had to know domain size, which we now no longer need.
* the prover for Groth16/Plonk now expects an Arc<ZKey>. Cleaner than having multiple Arcs in ZKey
* The serialized format of shares is now different.
* Refactor calls to other crates because of API changes

### Features

* add support for merging input arrays ([#260](https://github.com/TaceoLabs/co-snarks/issues/260)) ([2c72231](https://github.com/TaceoLabs/co-snarks/commit/2c722317efee4b07fef92dcc7c6218033a25f04b))
* Add the possibility to share co-circom inputs and witness in compressed form ([c3443e1](https://github.com/TaceoLabs/co-snarks/commit/c3443e1d6118f18c98c260b426307a16a2de9f76))
* added run_and_get_network to CircomRep3VmWitnessExtension, changed run and run_with_flat back to consume self ([b362504](https://github.com/TaceoLabs/co-snarks/commit/b362504d8a5affa8a5e8eca3f214c04951ad5b50))
* allow to set circom simplification level via CLI ([b0d64ba](https://github.com/TaceoLabs/co-snarks/commit/b0d64ba683c1dbab67102d31f1e1ab80108fb7d9))
* also allow circom-compatible way to handle link library via cli ([#285](https://github.com/TaceoLabs/co-snarks/issues/285)) ([48e6c0f](https://github.com/TaceoLabs/co-snarks/commit/48e6c0f704e9bcb623f714392691a3cc8fa6cfbe))
* can now parse bool inputs ([#236](https://github.com/TaceoLabs/co-snarks/issues/236)) ([d0147b6](https://github.com/TaceoLabs/co-snarks/commit/d0147b60810545d1a8796370b82c50eac1d7739d))
* now can specify whether we want curve checks during zkey deser ([e1c03f3](https://github.com/TaceoLabs/co-snarks/commit/e1c03f3ba979bface5ea79062d95ffc088fdfda0))
* num2bits accelerator working ([13cdf10](https://github.com/TaceoLabs/co-snarks/commit/13cdf100b79c642649d31501833ed182dd7e8b90))


### Bug Fixes

* added a check during groth16 prover for public inputs ([76466eb](https://github.com/TaceoLabs/co-snarks/commit/76466eb2d662efa4d5061e53e09470740763c77f))
* fixed path in zkey benches ([#231](https://github.com/TaceoLabs/co-snarks/issues/231)) ([99ab2de](https://github.com/TaceoLabs/co-snarks/commit/99ab2de32db9b27ca219fd93d7f8f17ab9692984))
* handle inputs that are &gt;= mod in the same way as snarkjs ([76f701b](https://github.com/TaceoLabs/co-snarks/commit/76f701b63fc94e9643aefb3ded9670843a0e716f))
* install rustls default crypto provider in our main binaries & examples ([#238](https://github.com/TaceoLabs/co-snarks/issues/238)) ([78757e4](https://github.com/TaceoLabs/co-snarks/commit/78757e46d8622360377d27c5d475d417bed95c5a))


### Code Refactoring

* input to compiler now takes PathBuf ([9f36774](https://github.com/TaceoLabs/co-snarks/commit/9f36774f0ff93c3c3abd28efae6599fc531bb1fb))
* prove for circom now expect Arc&lt;ZKey&gt; ([c2ac465](https://github.com/TaceoLabs/co-snarks/commit/c2ac465ebf6f3a28b902d9f0489e3f57c0843d7f))
* Refactor calls to other crates because of API changes ([6ed7c1a](https://github.com/TaceoLabs/co-snarks/commit/6ed7c1ad34e5dabd3ba1464cc805d5427d543f68))
* Removed ark_relations deps. Also changed verify impls to not return bool but a common error ([b4f4bf1](https://github.com/TaceoLabs/co-snarks/commit/b4f4bf16beaa83108bc2ae6c6f972ab4e4da4473))
* split network config into two types ([dca1756](https://github.com/TaceoLabs/co-snarks/commit/dca175603a5d6a2f75ccd987cb0b19cc3d965b00))
* with_network_config for ShamirGroth16 doesn't need zkey anymore ([2052d89](https://github.com/TaceoLabs/co-snarks/commit/2052d89cc4abb531702886daf70c47ee3b1ecf1a))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-mpc-compiler bumped from 0.7.0 to 0.8.0
    * circom-mpc-vm bumped from 0.5.0 to 0.6.0
    * circom-types bumped from 0.6.0 to 0.7.0
    * co-circom-snarks bumped from 0.2.0 to 0.3.0
    * co-groth16 bumped from 0.6.0 to 0.7.0
    * co-plonk bumped from 0.4.0 to 0.5.0
    * mpc-core bumped from 0.6.0 to 0.7.0
    * mpc-net bumped from 0.2.0 to 0.2.1

## [0.6.0](https://github.com/TaceoLabs/co-snarks/compare/co-circom-v0.5.1...co-circom-v0.6.0) (2024-11-12)


### ⚠ BREAKING CHANGES

* serialization format of shared inputs has changed to allow for optional values used to indicate missing elements of an array
* MPC accelerator changed public API. Also now stores #output signals in component
* input to compiler now takes PathBuf
* run and run_with_flat methods on WitnessExtension now consume self again
* MpcNetworkHandler::establish now takes the config with already read certs and key.
* Removes the zkey in the said function signature. We needed it earlier because we had to know domain size, which we now no longer need.
* the prover for Groth16/Plonk now expects an Arc<ZKey>. Cleaner than having multiple Arcs in ZKey
* The serialized format of shares is now different.
* Refactor calls to other crates because of API changes

### Features

* add support for merging input arrays ([#260](https://github.com/TaceoLabs/co-snarks/issues/260)) ([2c72231](https://github.com/TaceoLabs/co-snarks/commit/2c722317efee4b07fef92dcc7c6218033a25f04b))
* Add the possibility to share co-circom inputs and witness in compressed form ([c3443e1](https://github.com/TaceoLabs/co-snarks/commit/c3443e1d6118f18c98c260b426307a16a2de9f76))
* added run_and_get_network to CircomRep3VmWitnessExtension, changed run and run_with_flat back to consume self ([b362504](https://github.com/TaceoLabs/co-snarks/commit/b362504d8a5affa8a5e8eca3f214c04951ad5b50))
* allow to set circom simplification level via CLI ([b0d64ba](https://github.com/TaceoLabs/co-snarks/commit/b0d64ba683c1dbab67102d31f1e1ab80108fb7d9))
* can now parse bool inputs ([#236](https://github.com/TaceoLabs/co-snarks/issues/236)) ([d0147b6](https://github.com/TaceoLabs/co-snarks/commit/d0147b60810545d1a8796370b82c50eac1d7739d))
* num2bits accelerator working ([13cdf10](https://github.com/TaceoLabs/co-snarks/commit/13cdf100b79c642649d31501833ed182dd7e8b90))


### Bug Fixes

* fixed path in zkey benches ([#231](https://github.com/TaceoLabs/co-snarks/issues/231)) ([99ab2de](https://github.com/TaceoLabs/co-snarks/commit/99ab2de32db9b27ca219fd93d7f8f17ab9692984))
* handle inputs that are &gt;= mod in the same way as snarkjs ([76f701b](https://github.com/TaceoLabs/co-snarks/commit/76f701b63fc94e9643aefb3ded9670843a0e716f))
* install rustls default crypto provider in our main binaries & examples ([#238](https://github.com/TaceoLabs/co-snarks/issues/238)) ([78757e4](https://github.com/TaceoLabs/co-snarks/commit/78757e46d8622360377d27c5d475d417bed95c5a))


### Code Refactoring

* input to compiler now takes PathBuf ([9f36774](https://github.com/TaceoLabs/co-snarks/commit/9f36774f0ff93c3c3abd28efae6599fc531bb1fb))
* prove for circom now expect Arc&lt;ZKey&gt; ([c2ac465](https://github.com/TaceoLabs/co-snarks/commit/c2ac465ebf6f3a28b902d9f0489e3f57c0843d7f))
* Refactor calls to other crates because of API changes ([6ed7c1a](https://github.com/TaceoLabs/co-snarks/commit/6ed7c1ad34e5dabd3ba1464cc805d5427d543f68))
* split network config into two types ([dca1756](https://github.com/TaceoLabs/co-snarks/commit/dca175603a5d6a2f75ccd987cb0b19cc3d965b00))
* with_network_config for ShamirGroth16 doesn't need zkey anymore ([2052d89](https://github.com/TaceoLabs/co-snarks/commit/2052d89cc4abb531702886daf70c47ee3b1ecf1a))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-mpc-compiler bumped from 0.6.1 to 0.7.0
    * circom-mpc-vm bumped from 0.4.2 to 0.5.0
    * circom-types bumped from 0.5.0 to 0.6.0
    * co-circom-snarks bumped from 0.1.2 to 0.2.0
    * co-groth16 bumped from 0.5.1 to 0.6.0
    * co-plonk bumped from 0.3.1 to 0.4.0
    * mpc-core bumped from 0.5.0 to 0.6.0
    * mpc-net bumped from 0.1.2 to 0.2.0

## [0.5.0](https://github.com/TaceoLabs/collaborative-circom/compare/co-circom-v0.4.0...co-circom-v0.5.0) (2024-08-21)


### ⚠ BREAKING CHANGES

* we hardcoded bn128 as prime for the compiler. We now give either bn128 or bls12381 depending on curve. Introduces new trait bounds therefore breaking change
* Removed the builder step for the compiler as we now have a config anyways. Moved some stuff to the config
* we fixed a bug, where the (i)ffts for bls12_381 had a different permutation than from snarkjs. We removed our band-aid fix (FFTPostProcessing). Therfore, it is a breaking change.

### Bug Fixes

* fixes prime for the mpc compiler ([5712184](https://github.com/TaceoLabs/collaborative-circom/commit/5712184748488b7bab735b456be25e9cbbdb5ff7))
* fixes the bls12_381 permutation from arkworks ([f100615](https://github.com/TaceoLabs/collaborative-circom/commit/f100615790c51227d89e886ee6977367e4d5a1ce))
* removed unwrap ([a7dcc03](https://github.com/TaceoLabs/collaborative-circom/commit/a7dcc03b7901f1aaa92d42b93e634f553aa1ff2f))


### Code Refactoring

* Removed builder pattern for compiler ([260d5e8](https://github.com/TaceoLabs/collaborative-circom/commit/260d5e89d9ba5e3e4487b9f660bdac455f1fe450))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-mpc-compiler bumped from 0.5.0 to 0.6.0
    * circom-mpc-vm bumped from 0.4.0 to 0.4.1
    * circom-types bumped from 0.4.0 to 0.5.0
    * co-circom-snarks bumped from 0.1.0 to 0.1.1
    * co-groth16 bumped from 0.4.0 to 0.5.0
    * co-plonk bumped from 0.2.0 to 0.3.0
    * mpc-core bumped from 0.3.0 to 0.4.0

## [0.4.0](https://github.com/TaceoLabs/collaborative-circom/compare/co-circom-v0.3.0...co-circom-v0.4.0) (2024-08-14)


### ⚠ BREAKING CHANGES

* We renamed all crate names from collaborative-* to co-* for brevity, and also shortened `Collaborative` to `Co` in many types.

### Code Refactoring

* renamed crates to co-* ([#161](https://github.com/TaceoLabs/collaborative-circom/issues/161)) ([37f3493](https://github.com/TaceoLabs/collaborative-circom/commit/37f3493b25e41b43bbc8a89e281ae2dcb4b95484))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-mpc-compiler bumped from 0.4.0 to 0.5.0
    * circom-mpc-vm bumped from 0.3.0 to 0.4.0
    * co-groth16 bumped from 0.3.0 to 0.4.0
    * co-plonk bumped from 0.1.0 to 0.2.0

## [0.3.0](https://github.com/TaceoLabs/collaborative-circom/compare/collaborative-circom-v0.2.1...collaborative-circom-v0.3.0) (2024-08-14)


### ⚠ BREAKING CHANGES

* to unify Groth16 and PLONK we now take the zkey as ref in PLONK when calling prove
* moved common code for PLONK and Groth16 into separate crate. Most notably the SharedWitness and SharedInput
* PLONK uses the witness struct, therefore we moved it from Groth16 to one level higher
* we hide the modules defining the zkey, proof, vk, and witness and use pub use the re-export them
* the verifier (and the arkwork dep) is now hidden behind the "verifier" feature. Also we refactored some stuff in Groth16 to mirror PLONK.
* Add Plonk to the co-circom binary ([#147](https://github.com/TaceoLabs/collaborative-circom/issues/147))
* groth16 zkey parsing is now multithreaded, added multithreaded g1/2_vec_from_reader
* share_rep3 and share_shamir interfaces changed
* new config implementation, config option to allow leaking of secret values in logs ([#132](https://github.com/TaceoLabs/collaborative-circom/issues/132))
* Adds a method to the ArkworksPairingBridge trait
* the function signature of the two run methods of the witness extension now changed. To retrieve the shared witness now another call `into_shared_witness()` is necessary.
* Add the possibility to specify another curve in the co-circom binary
* Add possibility to use Shamir secret sharing for proofing and

### Features

* add deserialization of plonk circom types ([d1f0d4d](https://github.com/TaceoLabs/collaborative-circom/commit/d1f0d4dd5ac63e85523c139e573161bd2ff0061a))
* Add Plonk to the co-circom binary ([#147](https://github.com/TaceoLabs/collaborative-circom/issues/147)) ([ff05a2e](https://github.com/TaceoLabs/collaborative-circom/commit/ff05a2e45fb93f70c0ebb246e287e9302e4a7222))
* Add possibility to use Shamir secret sharing for proofing and ([6205475](https://github.com/TaceoLabs/collaborative-circom/commit/6205475b78d4654c61f5058befe5d5990da19432))
* Add runtime information to the co-circom binary ([84f2c6d](https://github.com/TaceoLabs/collaborative-circom/commit/84f2c6dbc1668b9b587729b22695c92700512428))
* Add the possibility to specify another curve in the co-circom binary ([fdd6bf2](https://github.com/TaceoLabs/collaborative-circom/commit/fdd6bf2f5274da790fd7cbe09ee48563b404d153))
* can now retrieve certain outputs after witness extension by name ([d9e3399](https://github.com/TaceoLabs/collaborative-circom/commit/d9e33996d10cea5f8197d507a13ed9087f0f4c20))
* groth16 zkey parsing is now multithreaded, added multithreaded g1/2_vec_from_reader ([b1e46f7](https://github.com/TaceoLabs/collaborative-circom/commit/b1e46f72df537b73e222b7d0dd7cdf17e549a9f0))
* now co-circom supports hex values ([d004d10](https://github.com/TaceoLabs/collaborative-circom/commit/d004d10b8a9b5c39e77abd37c8b862107aaa14c1))
* plonk support ([9b65797](https://github.com/TaceoLabs/collaborative-circom/commit/9b6579724f6f5ba4fc6af8a98d386b96818dc08b))


### Bug Fixes

* updated bench-co-circom for new config and plonk proof system ([#160](https://github.com/TaceoLabs/collaborative-circom/issues/160)) ([5722928](https://github.com/TaceoLabs/collaborative-circom/commit/5722928028a7ae348fa9c666ce1e7ccc1eb72ae7))


### Code Refactoring

* added new crate co-circom-snarks ([ea3190f](https://github.com/TaceoLabs/collaborative-circom/commit/ea3190f4d731893e6fcce71976c32b3bbac6b89b))
* Added verifier feature for Groth16 ([489614c](https://github.com/TaceoLabs/collaborative-circom/commit/489614cf9242f63c9f9914aaf0b6cc6555deab4c))
* move the groth16 circom types ([fabc5e7](https://github.com/TaceoLabs/collaborative-circom/commit/fabc5e72343f08eea96efde4556dffac60d954cb))
* moved the witness struct ([9cee70b](https://github.com/TaceoLabs/collaborative-circom/commit/9cee70bc58f1980035d02e46e6ea9082a3368182))
* new config implementation, config option to allow leaking of secret values in logs ([#132](https://github.com/TaceoLabs/collaborative-circom/issues/132)) ([964b04f](https://github.com/TaceoLabs/collaborative-circom/commit/964b04f47e8d491ae140cb7c10c596e1c40b6b5c))
* PLONK now takes zkey as ref for prove ([6f613e6](https://github.com/TaceoLabs/collaborative-circom/commit/6f613e6feffece37435da3960afa4d017fe4baa0))
* share_rep3 and share_shamir interfaces changed ([5e7420f](https://github.com/TaceoLabs/collaborative-circom/commit/5e7420f95a46466304c2ab80de2069c2feb3432d))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-mpc-compiler bumped from 0.3.0 to 0.4.0
    * circom-mpc-vm bumped from 0.2.0 to 0.3.0
    * circom-types bumped from 0.3.0 to 0.4.0
    * collaborative-groth16 bumped from 0.2.1 to 0.3.0
    * mpc-core bumped from 0.2.1 to 0.3.0

## [0.2.1](https://github.com/TaceoLabs/collaborative-circom/compare/collaborative-circom-v0.2.0...collaborative-circom-v0.2.1) (2024-07-10)


### Bug Fixes

* better handling of ipv4 and ipv6 in networking ([#119](https://github.com/TaceoLabs/collaborative-circom/issues/119)) ([090227d](https://github.com/TaceoLabs/collaborative-circom/commit/090227d372215e9459c06777064b04ec4865bdb6))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-types bumped from 0.2.0 to 0.3.0
    * circom-mpc-compiler bumped from 0.2.0 to 0.3.0
    * collaborative-groth16 bumped from 0.2.0 to 0.2.1
    * mpc-core bumped from 0.2.0 to 0.2.1

## [0.2.0](https://github.com/TaceoLabs/collaborative-circom/compare/collaborative-circom-v0.1.2...collaborative-circom-v0.2.0) (2024-07-09)


### Features

* added a lot tracings ([c4f24d1](https://github.com/TaceoLabs/collaborative-circom/commit/c4f24d15f0c7af0560fbffe4a4aaedda2fa515e8))
* added kyc example ([8b45982](https://github.com/TaceoLabs/collaborative-circom/commit/8b4598239fec55f4a4f6d87dfe12ea4aca19fddb))


### Bug Fixes

* now writes 0 instead of empty string when public inputs is zero ([eca6676](https://github.com/TaceoLabs/collaborative-circom/commit/eca667608774484733925632358dedd6608d318b))
* pushed input.json for kyc ([be46bc2](https://github.com/TaceoLabs/collaborative-circom/commit/be46bc28c3ff28a135754a72664ba5732b413345))
* pushed ver_key.json for kyc ([96d745d](https://github.com/TaceoLabs/collaborative-circom/commit/96d745df27894b81b391c36d957e0b2ab66b16d1))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * circom-types bumped from 0.1.0 to 0.2.0
    * circom-mpc-compiler bumped from 0.1.0 to 0.2.0
    * collaborative-groth16 bumped from 0.1.0 to 0.2.0
    * mpc-core bumped from 0.1.0 to 0.2.0

## [0.1.2](https://github.com/TaceoLabs/collaborative-circom/compare/collaborative-circom-v0.1.1...collaborative-circom-v0.1.2) (2024-06-14)


### Bug Fixes

* delete not needed impl ([f4dc747](https://github.com/TaceoLabs/collaborative-circom/commit/f4dc74770cd92531851b777dfaa1385b033b657c))

## [0.1.1](https://github.com/TaceoLabs/collaborative-circom/compare/collaborative-circom-v0.1.0...collaborative-circom-v0.1.1) (2024-06-14)


### Bug Fixes

* minor spelling ([e7f7178](https://github.com/TaceoLabs/collaborative-circom/commit/e7f7178b7e3c2605e0295a591eaa8b6e46499db1))

## [0.1.0](https://github.com/TaceoLabs/collaborative-circom/compare/collaborative-circom-v0.0.1...collaborative-circom-v0.1.0) (2024-06-14)


### Features

* First impl for Circom Parser to MPC.  ([#26](https://github.com/TaceoLabs/collaborative-circom/issues/26)) ([779682d](https://github.com/TaceoLabs/collaborative-circom/commit/779682d7d824d782109db8b4584604b23637dad7))
* first version of command line interface ([#36](https://github.com/TaceoLabs/collaborative-circom/issues/36)) ([6abe716](https://github.com/TaceoLabs/collaborative-circom/commit/6abe716268f1e165cdae07a10f4d2dafd010cc04))
* first version of mpc vm ([#42](https://github.com/TaceoLabs/collaborative-circom/issues/42)) ([6dcd5f4](https://github.com/TaceoLabs/collaborative-circom/commit/6dcd5f4ce7c8431b94dd7262a4219a3a63efd702))
* fixed poseidonex_test ([f119394](https://github.com/TaceoLabs/collaborative-circom/commit/f1193948e1edbed19be7d9684b6f96a0e83d3045))
* generate public input json file during proving ([2d20229](https://github.com/TaceoLabs/collaborative-circom/commit/2d20229e4e614354071cdb20a6207725b597fa28)), closes [#70](https://github.com/TaceoLabs/collaborative-circom/issues/70)
* integrate witness extension via MPC VM into CLI binary ([f526081](https://github.com/TaceoLabs/collaborative-circom/commit/f526081a01e3faa6b48fb463f3690f968218a1a4))
* make protocol argument in CLI an enum ([1c025a1](https://github.com/TaceoLabs/collaborative-circom/commit/1c025a1ef612603b31062c6a56b6dd15a0917c9e))
* negative numbers work, also added an example with negative numbers ([#80](https://github.com/TaceoLabs/collaborative-circom/issues/80)) ([1a54649](https://github.com/TaceoLabs/collaborative-circom/commit/1a54649ee859f2492a225ae3647f795852d7e368))
* network configuration structure + parsing ([7f1cb06](https://github.com/TaceoLabs/collaborative-circom/commit/7f1cb0645fe7d6319367f8846e5e5d05b7ff2ae9))
* public inputs support ([#76](https://github.com/TaceoLabs/collaborative-circom/issues/76)) ([07cf260](https://github.com/TaceoLabs/collaborative-circom/commit/07cf26007285822ba42e8dce2439f676a2cf08ef))
* skeleton of cli interface for coll-circom ([807a822](https://github.com/TaceoLabs/collaborative-circom/commit/807a822ac4b33c16540a32f4a34f7703b0fc134e))
* support merging shared inputs from multiple parties + examples ([#75](https://github.com/TaceoLabs/collaborative-circom/issues/75)) ([1168488](https://github.com/TaceoLabs/collaborative-circom/commit/11684884b3e1d2be6309fd98e1603626d5e58c93))
* use existing information in zkey to not require regeneration of matrices ([c7b75c3](https://github.com/TaceoLabs/collaborative-circom/commit/c7b75c34e69479bea06583e9fc17f3b1dc8f3d9a))


### Bug Fixes

* fix wrong argument name in example runner script ([244a72e](https://github.com/TaceoLabs/collaborative-circom/commit/244a72eeda2d6d8d31f8e9bc493565e076a12fc2))
