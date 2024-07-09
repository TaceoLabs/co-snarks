# Collaborative SNARKs Primer

Collaborative SNARKs are a very new line of work, emerging in 2022, that combines the best of MPC and SNARKs. They enable multiple parties to jointly create a proof of the correctness of a computation while keeping their individual inputs private. This approach solves the problem of computing on private shared state without relying on a trusted third party. Each party contributes to a distributed protocol that generates a single SNARK proof, attesting to the correctness of their combined computation without revealing any individual inputs. The resulting proof is succinct and can be verified efficiently by anyone, ensuring the integrity of the computation without exposing any sensitive data.