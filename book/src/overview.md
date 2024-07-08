# Overview

Collaborative Circom is an implementation of [collaborative SNARKs](./collsnarks.md), with a focus on the [Circom](https://circom.io) framework.

In contrast to traditional SNARKs, which are run by a single prover, collaborative SNARKs are executed using a [multiparty computation protocol](./mpc.md). This enables new use-cases, such as:

* outsourced proof generation, where a user that does not have a lot of computing resources can share its secret witness to a coalition of provers that compute the zero-knowledge proof for him.
* Auditable MPC, where multiple users have secret inputs to a common function and want to prove the correct execution of the function on these secret inputs to a third party.
