# Secure Multiparty Computation (MPC)

Currently, proof generation is supported with two different MPC protocols:

* 3-Party replicated secret sharing (based on ABY3 [1]) with semi-honest security
* N-Party Shamir secret sharing [2] (based on DN07 [3]) with semi-honest security

## Notation

With $[x]$ we denote that $x\in\mathbb F_p$ is additively secret shared amongst $n$ parties, such that $[x] = (x_1, x_2, ..., x_1)$ and $x = \sum_i^n x_i$. With $[x]^B$ we denote that $x\in\mathbb F_p$ is binary secret shared amongst $n$ parties, such that $[x]^B = (x_1, x_2, ..., x_1)$ and $x = x_1 \oplus x_2 \oplus ... \oplus x_n$. Furthermore, indices of shares are taken modulo the number of parties. Similar, for a group element $X\in\mathbb G$ in an additive Group $\mathbb G$ (e.g., elliptic curve groups) we denote by $[X]$ its secret sharing amongst $n$ parties, such that $[X] = (X_1, X_2, ..., X_1)$ and $X = \sum_i^n X_i$.

## 3-Party Replicated Sharing

Replicated secret sharing is based on additive secret sharing, with the twist that each party has multiple additive shares. Thus, in the 3-party case a secret $x\in\mathbb F_p$ is shared the following way. First, the $x$ is split into three random shares $x_1, x_2, x_3\in\mathbb F_p$ such that $x=x_1+x_2+x_3 \mod p$ and each party gets two shares:
$$
    P_1: (x_1, x_3)\\
    P_2: (x_2, x_1)\\
    P_3: (x_3, x_2)
$$

### Rng Setup

Random values are required during many points of MPC executions. For cheaper randomness generation, correlated random number generators are set up before protocol execution.

#### Random Values

In order to create random shares $(r_i, r_{i-1})$, random additive shares of 0 $(r_i - r_{i-1})$, or random binary shares of 0 $(r_i \oplus r_{i-1})$ without interaction, Rep3 sets up a correlated random number generator during the setup phase. Each party $P_i$ chooses a seed $s_i$ and sends it to the next party $P_{i+1}$. Thus, each party has two seeds and can set up an RNG's, where two party are able to create the same random numbers:

$$
    P_1: (\text{RNG}_1, \text{RNG}_3)\\
    P_2: (\text{RNG}_2, \text{RNG}_1)\\
    P_3: (\text{RNG}_3, \text{RNG}_2)
$$


#### Binary To Arithmetic Conversion

For the binary to arithmetic conversion, we need correlated randomness as well. The goal is to setup RNG's, such that:

$$
    P_1: (\text{RNG1}_1, \text{RNG1}_3), (\text{RNG2}_1, \text{RNG2}_2, \text{RNG2}_3)\\
    P_1: (\text{RNG1}_1, \text{RNG1}_2, \text{RNG1}_3), (\text{RNG2}_2, \text{RNG2}_1)\\
    P_3: (\text{RNG1}_1, \text{RNG1}_2, \text{RNG1}_3), (\text{RNG2}_1, \text{RNG2}_2, \text{RNG2}_3)
$$
In other words, $P_2$ and $P_3$ can use RNG1 create the same field element, while all parties can sample valid shares for it. Similar, $P_1$ and $P_3$ can use RNG2 to create the same field element, while all parties can sample valid shares for it. This setup can be achieved by sampling seeds from the already set up RNG for shared random values and resharing the seeds correctly.

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

#### Arithmetic to Binary Conversion

<TODO>

#### Binary to Arithmetic Conversion

<TODO>

### Reconstruction

Reconstruction of a value is implemented as $P_i$ sending $z_{i-1}$ to $P_{i+1}$. Then each party has all shares.

### Security

Our implementation provides semi-honest security with honest majority. I.e., the scheme is secure if all parties follow the protocol honestly and no two servers collude.

## Shamir Secret Sharing

Shamir secret sharing is a different way of instantiating a linear secret sharing scheme which is based on polynomials. To share a value $x\in\mathbb F_p$, one first has to sample a random polynomial of degree $t$, where $x$ is in the constant term. I.e., one samples $a_1, a_2, ..., a_t$ randomly from $\mathbb F_p$ and sets: $Q(X) = x + a_1 \cdot X + a_2 \cdot X^2 + ... + a_t \cdot X^t$.
The share of party $i$ then is $Q(i)$. In other words, $[x] = (x_1, x_2, ..., x_n)$, where $x_i=Q(i)$.

Reconstruction then works via lagrange interpolation of any $t+1$ shares: $x = \sum_i^{t+1} \lambda_i x_i$, where $\lambda_i$ is the corresponding lagrange coefficient.

### Rng Setup

<TODO>

### Supported operations

#### Linear Operations

Shamir's secret sharing allows, similar to additive sharing, to compute linear functions locally without party interaction:

* Constant addition: $[x] + y = (x_1 + y, x_2 + y, x_3 + y)$
* Share addition: $[x] + [y] = (x_1 + y_1, x_2 + y_2, x_3 + y_3)$
* Constant Multiplication: $[x] \cdot y = (x_1\cdot y, x_2\cdot y, x_3\cdot y)$

#### Multiplications

Shamir secret sharing comes with a native multiplication protocol: $z_i = x_i\cdot y_i$ is a valid share of $[z] = [x] \cdot [y]$. However, $z_i$ is a point on a polynomial with degree $2t$. In other words, the degree doubles after a multiplication and twice as many parties ($2t+1$) are required to reconstruct the secret $z$. Thus, one needs to perform a degree reduction step in MPC for further computations. In DN07, this is done by sampling a random value, which is shared as a degree-$t$ ($[r]_t$) and degree-$2t$ ($[r]_{2t}$) polynomial. Then, the parties open $[z]_{2t} + [r]_{2t}$ to $P_1$, who reconstructs it to $z' =z+r$. Then. $P_1$ shares $z'$ as a fresh degree-$t$ share to all parties, who calculate $[z]_t = [z']_t - [r]_t$.

### Reconstruction

Reconstruction is currently implemented as $P_i$ sending its share $x_i$ to the next $t$ parties. Then, each party has $t+1$ shares to reconstruct the secret.

### Security

Our implementation provides semi-honest security with honest majority. I.e., the scheme is secure if all parties follow the protocol honestly and at most $t$ servers collude. $t$ can, thereby, be chosen to be $t\le \frac{n-1}{2}$.

## MPC for group operations

So far, we only discussed MPC for field elements $\mathbb F_p$. However, one can easily extend it to MPC over Group elements $\mathbb G$. W.l.o.g. we will use the notation for additive groups $\mathbb G$ (e.g., elliptic curve groups). A secret share $[x]\in\mathbb F_p$ can be translated to a shared group element by $[X] = [x] \cdot G$, where $G$ is a generator of $\mathbb G$. Then, $[X] = (X_1, X_2, ..., X_n)$ is a valid additive share of $x\cdot G = \sum_i X_i$. Linear operations directly follow from the used linear secret sharing scheme: $[Z] = a \cdot [X] + b\cdot [Y] + C = (a\cdot [x] + b\cdot [y] + c)\cdot G$. Shared scalar multiplications also follow from the secret sharing scheme: $[Z] = [x] \cdot [Y] = [x] \cdot [y] \cdot G$.

## Shamir vs Rep3

Shamir and Rep3 are both linear secret sharing schemes which provide semi-honest security with honest-majority. However, they have some important differences.

* Shamir can be instantiated with $n\ge 3$ parties, while Rep3 has a fixed size $n=3$
* In Shamir, each share is just one field element $\in\mathbb F_p$, while in Rep3 each share is composed of two field elements.
* In Shamir, the overhead on the CPU is significantly smaller compared to Rep3, where each operation is applied to two shares.
* Rep3 allows efficient arithmetic-to-binary conversions.

## Witness Extension

<TODO: b2a, a2b, bridges, comparisons (i.e., all circuits)>

[1] [https://eprint.iacr.org/2018/403.pdf](https://eprint.iacr.org/2018/403.pdf)\
[2] [https://web.mit.edu/6.857/OldStuff/Fall03/ref/Shamir-HowToShareASecret.pdf](https://web.mit.edu/6.857/OldStuff/Fall03/ref/Shamir-HowToShareASecret.pdf)\
[3] [https://iacr.org/archive/crypto2007/46220565/46220565.pdf](https://iacr.org/archive/crypto2007/46220565/46220565.pdf)
