# Secure Multiparty Computation (MPC)

Currently, proof generation is supported with two different MPC protocols:

* 3-Party replicated secret sharing (based on ABY3 [1]) with semi-honest security
* N-Party Shamir secret sharing [2] (based on DN07 [3]) with semi-honest security

## Notation

With $[x]$ we denote that $x$ is additively secret shared amongst $n$ parties, such that $[x] = (x_1, x_2, ..., x_1)$ and $x = \sum_i^n x_i$. With $[x]^B$ we denote that $x$ is binary secret shared amongst $n$ parties, such that $[x]^B = (x_1, x_2, ..., x_1)$ and $x = x_1 \oplus x_2 \oplus ... \oplus x_n$. Furthermore, indices of shares are taken modulo the number of parties.

## 3-Party Replicated Sharing

Replicated secret sharing is based on additive secret sharing, with the twist that each party has multiple additive shares. Thus, in the 3-party case a secret $x\in\mathbb F_p$ is shared the following way. First, the $x$ is split into three random shares $x_1, x_2, x_3\in\mathbb F_p$ such that $x=x_1+x_2+x_3 \mod p$ and each party gets two shares:
$$
    P_1: (x_1, x_3)\\
    P_2: (x_2, x_1)\\
    P_3: (x_3, x_2)
$$

### Supported operations

#### Linear Operations

Due to being based on additive secret sharing, linear operations can be performed on shares without party interaction.

* Constant addition: $[x] + y = (x_1 + y, x_2, x_3)$
* Share addition: $[x] + [y] = (x_1 + y_1, x_2 + y_2, x_3 + y_3)$
* Constant Multiplication: $[x] \cdot y = (x_1\cdot y, x_2\cdot y, x_3\cdot y)$

Similar, in the binary domain, the linear operations can be computed locally.

* Constant addition: $[x]^B \oplus y = (x_1 \oplus y, x_2, x_3)$
* Share addition: $[x]^B \oplus [y]^B = (x_1 \oplus y_1, x_2 \oplus y_2, x_3 \oplus y_3)$
* Constant Multiplication: $[x]^B \wedge y = (x_1\wedge y, x_2\wedge y, x_3\wedge y)$

#### Multiplications

One main advantage of replicated secret sharing is the presence of a simple multiplication protocol. First, due to having two additive shares, each party can calculate an additive share of the result without interaction.
For $[z] = [x] \cdot [y]$, $z_i = x_i \cdot y_i + x_i \cdot y_{i-1} + x_{i-1} \cdot y_i$ is a valid additive share of $z$.

Thus, multiplications involve a local operation followed by a resharing of the result to translate the additive share to a replicated share. Resharing requires to randomize the share to not leak any information to the other party. For that reason, a fresh random share of zero is added, which can be sampled locally without party interaction (see RNG setup).

Thus, party $P_i$ calculates:
$$
    r_i = \text{RNG}_i - \text{RNG}_{i-1}\\
    z_i = x_i \cdot y_i + x_i \cdot y_{i-1} + x_{i-1} \cdot y_i + r_i\\
    z_{i-1} = \text{SendReceive}(z_i)
$$

The resharing, thereby, is simply implemented as $P_i$ sending $z_i$ to $P_{i+1}$.

#### AND

AND gates follow directly from multiplications:

$$
    r_i = \text{RNG}_i \oplus \text{RNG}_{i-1}\\
    z_i = (x_i \wedge y_i) \oplus (x_i \wedge y_{i-1}) \oplus (x_{i-1} \wedge y_i) \oplus r_i\\
    z_{i-1} = \text{SendReceive}(z_i)
$$

### Reconstruction

Reconstruction of a value is implemented as $P_i$ sending $z_{i-1}$ to $P_{i+1}$. Then each party has all shares.

### Rng Setup

<TODO>

### Security

Our implementation provides semi-honest security with honest majority. I.e., the scheme is secure if all parties follow the protocol honestly and no two servers collude.

## Shamir Secret Sharing

Shamir secret sharing is a different way of instantiating a linear secret sharing scheme which is based on polynomials. To share a value $x\in\mathbb F_p$, one first has to sample a random polynomial of degree $t$, where $x$ is in the constant term. I.e., one samples $a_1, a_2, ..., a_t$ randomly from $\mathbb F_p$ and sets: $Q(X) = x + a_1 \cdot X + a_2 \cdot X^2 + ... + a_t \cdot X^t$.
The share of party $i$ then is $Q(i)$. In other words, $[x] = (x_1, x_2, ..., x_n)$, where $x_i=Q(i)$.

Reconstruction then works via lagrange interpolation of any $t+1$ shares: $x = \sum_i^{t+1} \lambda_i x_i$, where $\lambda_i$ is the corresponding lagrange coefficient.

### Supported operations

#### Linear Operations

Shamir's secret sharing allows, similar to additive sharing, to compute linear functions locally without party interaction:

* Constant addition: $[x] + y = (x_1 + y, x_2 + y, x_3 + y)$
* Share addition: $[x] + [y] = (x_1 + y_1, x_2 + y_2, x_3 + y_3)$
* Constant Multiplication: $[x] \cdot y = (x_1\cdot y, x_2\cdot y, x_3\cdot y)$

#### Multiplications

Shamir secret sharing comes with a native multiplication protocol: $z_i = x_i\cdot y_i$ is a valid share of $[z] = [x] \cdot [y]$. However, $z_i$ is a point on a polynomial with degree $2t$. In other words, the degree doubles after a multiplication and twice as many parties ($2t+1$) are required to reconstruct the secret $z$. Thus, one needs to perform a degree reduction step in MPC for further computations. In DN07, this is done by sampling a random value, which is shared as a degree-$t$ ($[r]_t$) and degree-$2t$ ($[r]_{2t}$) polynomial. Then, the parties open $[z]_{2t} + [r]_{2t}$ to $P_1$, who reconstructs it to $z' =z+r$. Then. $P_1$ shares $z'$ as a fresh degree-$t$ share to all parties, who calculate $[z]_t = [z']_t - [r]_t$.

#### Reconstruction

Reconstruction is currently implemented as $P_i$ sending its share $x_i$ to the next $t$ parties. Then, each party has $t+1$ shares to reconstruct the secret.

### Rng Setup

<TODO>

### Security

Our implementation provides semi-honest security with honest majority. I.e., the scheme is secure if all parties follow the protocol honestly and at most $t$ servers collude. $t$ can, thereby, be chosen to be $t\le \frac{n-1}{2}$.

## MPC for group operations

<TODO>

## Shamir vs Rep3

<TODO>

## Witness Extension

<TODO: b2a, a2b, bridges, comparisons (i.e., all circuits)>

[1] [https://eprint.iacr.org/2018/403.pdf](https://eprint.iacr.org/2018/403.pdf)\
[2] [https://web.mit.edu/6.857/OldStuff/Fall03/ref/Shamir-HowToShareASecret.pdf](https://web.mit.edu/6.857/OldStuff/Fall03/ref/Shamir-HowToShareASecret.pdf)\
[3] [https://iacr.org/archive/crypto2007/46220565/46220565.pdf](https://iacr.org/archive/crypto2007/46220565/46220565.pdf)
