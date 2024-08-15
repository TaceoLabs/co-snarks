# MPC-VM

## Design Choices

## Problematic Circom Operations

The circom language was designed for zero-knowledge circuits and while its internal model is pretty similar to the arithmetic circuit model that is native to MPC, there are a few assumptions that the circom language makes that pose issues for execution in MPC. Most of them arise from conditional execution of code in circom. While there are some conditions placed upon conditional code in circom (it is not allowed to modify the structure of the circuit, i.e., the same circuit has to be produced regardless of the input), it allows conditional execution of *unconstrained* code. Unconstrained code is code that is producing *helper* variables that may later be used to constrain actual signal values. A common example is the bit-decomposition of a number, which gets computed using unconstrained code, and later on, it is proven by adding constraints that the sum of the individual bits multiplied by their respective powers of two is equal to the original value, as this is much cheaper in zero-knowledge compared to directly computing the bit-decomposition.

### Conditional Branches

### Ternary Operators

A special case of conditional branches is the ternary operator.

### Division in inactive branches

One further complication of executing both inactive and active branches is that all operations must be computable in both branches. A common operation that poses problems is field division, or more concretely, the associated *inversion* of the divisor, as this may fail if the divisor is 0.
We solve this by conditionally loading the real input or 1, depending on if the current branch is active or not, using a conditional multiplexer gate in the MPC circuit.
