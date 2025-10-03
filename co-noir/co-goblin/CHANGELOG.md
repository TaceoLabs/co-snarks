# Changelog

## [0.2.0](https://github.com/TaceoLabs/co-snarks/compare/co-goblin-v0.1.0...co-goblin-v0.2.0) (2025-10-03)


### ⚠ BREAKING CHANGES

* move HonkProof and the corresponding field serde to noir-types
* move witness and input parsing/sharing to new crates for wasm comp
* moves several components from the `ultrahonk` and `co-ultrahonk` crates into the `common` crate

### Features

* add (co-)merge-prover and common crates ([f7eea60](https://github.com/TaceoLabs/co-snarks/commit/f7eea60e71e23ff31aa9e48c801eb3d193a3a4ad))
* add plain ECCVM Prover ([#409](https://github.com/TaceoLabs/co-snarks/issues/409)) ([dc5f175](https://github.com/TaceoLabs/co-snarks/commit/dc5f175c1f1c61a95731129d10995b0f6122a1c1))
* move HonkProof and the corresponding field serde to noir-types ([b9821e5](https://github.com/TaceoLabs/co-snarks/commit/b9821e5202855bb9cd931ae32fe9e7d3e5b01378))
* move witness and input parsing/sharing to new crates for wasm comp ([333785e](https://github.com/TaceoLabs/co-snarks/commit/333785e275bc9256fb82fd8e2dcf18689bd92862))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-builder bumped from 0.4.0 to 0.5.0
    * mpc-core bumped from 0.9.0 to 0.10.0
    * ultrahonk bumped from 0.5.0 to 0.6.0
    * goblin bumped from 0.1.0 to 0.2.0
    * mpc-net bumped from 0.4.0 to 0.5.0
    * common bumped from 0.1.0 to 0.2.0
  * dev-dependencies
    * mpc-net bumped from 0.4.0 to 0.5.0
