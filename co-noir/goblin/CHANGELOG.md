# Changelog

## [0.2.0](https://github.com/TaceoLabs/co-snarks/compare/goblin-v0.1.0...goblin-v0.2.0) (2025-10-10)


### ⚠ BREAKING CHANGES

* Introduce initial implementation of MegaCircuitBuilder for construct_hiding_circuit_key ([#443](https://github.com/TaceoLabs/co-snarks/issues/443))
* add MPC version of ECCVM builder and prover ([#456](https://github.com/TaceoLabs/co-snarks/issues/456))
* move HonkProof and the corresponding field serde to noir-types
* plain protogalaxy prover ([#410](https://github.com/TaceoLabs/co-snarks/issues/410))
* moves several components from the `ultrahonk` and `co-ultrahonk` crates into the `common` crate

### Features

* add (co-)merge-prover and common crates ([f7eea60](https://github.com/TaceoLabs/co-snarks/commit/f7eea60e71e23ff31aa9e48c801eb3d193a3a4ad))
* add MAESTRO style lut protocol for curve points ([4da5f74](https://github.com/TaceoLabs/co-snarks/commit/4da5f74bed1350c4574bf3f3301c522ae068a096))
* add MPC version of ECCVM builder and prover ([#456](https://github.com/TaceoLabs/co-snarks/issues/456)) ([0230ccb](https://github.com/TaceoLabs/co-snarks/commit/0230ccb52bb52bf6ebe291103f8945e4fea61ed2))
* add plain ECCVM Prover ([#409](https://github.com/TaceoLabs/co-snarks/issues/409)) ([dc5f175](https://github.com/TaceoLabs/co-snarks/commit/dc5f175c1f1c61a95731129d10995b0f6122a1c1))
* Introduce initial implementation of MegaCircuitBuilder for construct_hiding_circuit_key ([#443](https://github.com/TaceoLabs/co-snarks/issues/443)) ([c3104a1](https://github.com/TaceoLabs/co-snarks/commit/c3104a1cf28a34372e10a79a08d667b70000c737))
* move HonkProof and the corresponding field serde to noir-types ([b9821e5](https://github.com/TaceoLabs/co-snarks/commit/b9821e5202855bb9cd931ae32fe9e7d3e5b01378))
* plain protogalaxy prover ([#410](https://github.com/TaceoLabs/co-snarks/issues/410)) ([42d49f5](https://github.com/TaceoLabs/co-snarks/commit/42d49f55a93b48e01c133f7ca5d7fefc559fd470))
* plain translator prover ([#425](https://github.com/TaceoLabs/co-snarks/issues/425)) ([14167b3](https://github.com/TaceoLabs/co-snarks/commit/14167b33e5b15e3d35bc3971913573d29eb92da9))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * co-noir-common bumped from 0.1.0 to 0.2.0
    * co-builder bumped from 0.4.0 to 0.5.0
    * mpc-core bumped from 0.9.0 to 0.10.0
    * ultrahonk bumped from 0.5.0 to 0.6.0
    * noir-types bumped from 0.1.0 to 0.1.1
  * dev-dependencies
    * mpc-core bumped from 0.9.0 to 0.10.0
