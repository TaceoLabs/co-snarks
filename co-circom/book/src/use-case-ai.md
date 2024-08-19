# AI

Bringing AI to Blockchains was a - until yet - unfulfilled promise. Verified offchain computation opened up this new design space now for the first time. In this case, the inference of ML models takes place offchain and only the results, alongside a Zero Knowledge Proof (zk proof) are posted back onchain. The zk proof guarantees the correct execution of the (correct) ML model, so that onchain contracts can rely on the output similarly as the execution would have taken place directly onchain.

A premise for zk-powered ML inference is:  the one who runs the actual computation and generates the zk proof must have all data at its hand. As long as this entity is the same as the one who owns IP rights for the (trained) model and user inputs contain no sensitive information zk is sufficient.

In cases where users send prompts to the ML model, which shouldn’t be shared with anyone additional encryption techniques need to be added to zk. With co-SNARKS user inputs can be fully shielded from AI service providers, while not restricting them in offering their services.

In general, zk proof generation is hardware intense and often requires specialized equipment. ZK cloud providers or proof markets offer proof computations as a service. As a side effect, all data needs to be shared with the prover, which could leak proprietary IP, like model weights.co-SNARKS could mitigate this issue by splitting up the sensitive data (e.g. model weights) in secret shares and distribute them among the MPC network
