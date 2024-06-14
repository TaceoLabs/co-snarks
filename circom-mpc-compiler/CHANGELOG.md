# Changelog

## [0.1.0](https://github.com/TaceoLabs/collaborative-circom/compare/circom-mpc-compiler-v0.0.1...circom-mpc-compiler-v0.1.0) (2024-06-14)


### Features

* added better assert message when assert fails ([ae0d8be](https://github.com/TaceoLabs/collaborative-circom/commit/ae0d8be33307f3db6f5c179069ffeed38f61abbb))
* emit pow/mod opcodes ([08f478e](https://github.com/TaceoLabs/collaborative-circom/commit/08f478e5236c6fe62dc4d26c32907a0319b7a270))
* fixed poseidonex_test ([f119394](https://github.com/TaceoLabs/collaborative-circom/commit/f1193948e1edbed19be7d9684b6f96a0e83d3045))
* implement shift right for public shift values ([7db3730](https://github.com/TaceoLabs/collaborative-circom/commit/7db3730d02624ec2f28dfd9d93f6bac174b88ff6))
* implemented plain/aby3 cmux and bool not for shared if handling ([e5701aa](https://github.com/TaceoLabs/collaborative-circom/commit/e5701aa8d967ab9d111556c8dfba3eeacfda4782))
* integrate witness extension via MPC VM into CLI binary ([f526081](https://github.com/TaceoLabs/collaborative-circom/commit/f526081a01e3faa6b48fb463f3690f968218a1a4))
* public inputs support ([#76](https://github.com/TaceoLabs/collaborative-circom/issues/76)) ([07cf260](https://github.com/TaceoLabs/collaborative-circom/commit/07cf26007285822ba42e8dce2439f676a2cf08ef))
* shared control flow test working for single return values ([6f4aabb](https://github.com/TaceoLabs/collaborative-circom/commit/6f4aabb3a842d47e148343a6b5e0c5b6d27b9b31))
* shared_control_flow arrays working except loops ([15cdecf](https://github.com/TaceoLabs/collaborative-circom/commit/15cdecf5d4dc6d0400367856a48f2571925745c3))
* VM if logic first draft ([cb9e525](https://github.com/TaceoLabs/collaborative-circom/commit/cb9e525e8ff4d96fb18a73a59589c09fcb756dff))


### Bug Fixes

* fixed array as paramters and return val for functions (escalarmulw4table_test) ([8f38648](https://github.com/TaceoLabs/collaborative-circom/commit/8f386487a40de20951d2124ed10d2ee76876e9bd))
* fixed smt and sha test cases (signal offset of components fixed) ([5442507](https://github.com/TaceoLabs/collaborative-circom/commit/54425070d5af1cdbca092fc365bdd2f66218b89b))
