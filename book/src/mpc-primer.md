# MPC Primer

MPC is a subfield of cryptography that enables multiple parties to jointly compute a function $f$ over their combined inputs, while keeping these inputs private.

Similar to ZK, the evaluated function is usually represented as an arithmetic circuit. The inputs are [secret-shared](https://en.wikipedia.org/wiki/Secret_sharing) among the parties. Every party evaluates the circuit locally on their shares and communicates with the other participants when necessary. After the parties finish their computation, they reconstruct the result of the function $f$ without ever telling anyone the secret inputs. In practice, the parties computing the function are not necessarily the same parties that provided the inputs.
