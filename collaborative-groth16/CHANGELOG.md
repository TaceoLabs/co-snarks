# Changelog

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
