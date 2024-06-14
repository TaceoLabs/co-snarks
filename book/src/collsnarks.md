# Collaborative SNARKs

In this document we list some literature for collaborative SNARKs.

## Experimenting with Collaborative zk-SNARKs: Zero-Knowledge Proofs for Distributed Secrets

This is the first paper[^1] in this space. It experiments with the feasibility of evaluating SNARKs in MPC and implements Groth16[^4] and Plonk[^5] using SPDZ[^2] and GSZ[^3] (maliciously secure variants of additive secret sharing and Shamir secret sharing respectively).

[^1]: [https://eprint.iacr.org/2021/1530.pdf](https://eprint.iacr.org/2021/1530.pdf)
[^2]: SPDZ: [https://eprint.iacr.org/2011/535.pdf](https://eprint.iacr.org/2011/535.pdf)
[^3]: GSZ: [https://eprint.iacr.org/2020/189.pdf](https://eprint.iacr.org/2020/189.pdf)
[^4]: Groth16: [https://eprint.iacr.org/2016/260.pdf](https://eprint.iacr.org/2016/260.pdf)
[^5]: Plonk: [https://eprint.iacr.org/2019/953.pdf](https://eprint.iacr.org/2019/953.pdf)

## EOS: efficient private delegation of zkSNARK provers

This paper[^6] uses a delegator to speed up MPC computations and investigates using the SNARK as error-detecting computation to implement cheaper malicious security.

[^6]: [https://dl.acm.org/doi/10.5555/3620237.3620598](https://dl.acm.org/doi/10.5555/3620237.3620598)

## zkSaaS: Zero Knowledge SNARKs as a service

This paper[^7] uses packed secret sharing (PSS)[^8], i.e., a variant of Shamir secret sharing where multiple secrets are embedded into the same sharing polynomial, to speed up MPC computation. However, they encounter some problems with FFTs, since they cannot be implemented with the SIMD semantics of PSS naively.

[^7]: [https://eprint.iacr.org/2023/905.pdf](https://eprint.iacr.org/2023/905.pdf)
[^8]: PSS: [https://dl.acm.org/doi/pdf/10.1145/129712.129780](https://dl.acm.org/doi/pdf/10.1145/129712.129780)

## Scalable Collaborative zk-SNARK: Fully Distributed Proof Generation and Malicious Security

This paper[^9] is a followup to zkSaaS which replaces the used SNARK with GKR[^10], which is better suited for PSS.

[^9]: [https://eprint.iacr.org/2024/143.pdf](https://eprint.iacr.org/2024/143.pdf)
[^10]: GKR: [https://dl.acm.org/doi/10.1145/2699436](https://dl.acm.org/doi/10.1145/2699436)

## Confidential and Verifiable Machine Learning Delegations on the Cloud

This paper[^11] implements GKR in MPC using the well-known MP-SPDZ[^12] library. It focuses on efficient matrix multiplications, bit provides a generic construction as well.

[^11]: [https://eprint.iacr.org/2024/537.pdf](https://eprint.iacr.org/2024/537.pdf)
[^12]: MP-SPDZ: [Github](https://github.com/data61/MP-SPDZ), [Paper](https://eprint.iacr.org/2020/521.pdf)
