# Secure Multiparty Computation (MPC)

Currently, proof generation is supported with two different MPC protocols:

* 3-party replicated secret sharing (based on ABY3[^1]) with semi-honest security
* N-party Shamir secret sharing[^2] (based on DN07[^3]) with semi-honest security

## Notation

With $[x]$ we denote that $x\in\mathbb F_p$ is additively secret shared amongst $n$ parties, such that $[x] = (x_1, x_2, ..., x_n)$ and $x = \sum_i^n x_i$. With $[x]^B$ we denote that $x\in\mathbb F_p$ is binary secret shared amongst $n$ parties, such that $[x]^B = (x_1, x_2, ..., x_n)$ and $x = x_1 \oplus x_2 \oplus ... \oplus x_n$. With $[x]_t$ we denote that $x\in\mathbb F_p$ is Shamir secret shared amongst $n$ parties, such that $[x] = (x_1, x_2, ..., x_n)$ and $x_i = Q(i)$ such that $Q(X)$ is a polynomial of degree $t$ with $x=Q(0)$. Similar, for a group element $X\in\mathbb G$ in an additive Group $\mathbb G$ (e.g., elliptic curve groups) we denote by $[X]$ its additive secret sharing amongst $n$ parties, and by $[X]_t$ its Shamir sharing, such that $[X] = (X_1, X_2, ..., X_n)$. Furthermore, indices of shares are taken modulo the number of parties.

## 3-Party Replicated Sharing

Replicated secret sharing is based on additive secret sharing, with the twist that each party has multiple additive shares. Thus, in the 3-party case a secret $x\in\mathbb F_p$ is shared the following way. First, the $x$ is split into three random shares $x_1, x_2, x_3\in\mathbb F_p$ such that $x=x_1+x_2+x_3 \mod p$ and each party gets two shares:
$$
    P_1: (x_1, x_3)\\
    P_2: (x_2, x_1)\\
    P_3: (x_3, x_2)
$$

### Rng Setup

Random values are required during many parts of MPC executions. For cheaper randomness generation, correlated random number generators are set up before protocol execution.

#### Random Values

In order to create random shares $(r_i, r_{i-1})$, random additive shares of $0$ (i.e., $r_i - r_{i-1}$), or random binary shares of $0$ (i.e., $r_i \oplus r_{i-1}$) without interaction, Rep3 sets up a correlated random number generator during the setup phase. Each party $P_i$ chooses a seed $s_i$ and sends it to the next party $P_{i+1}$. Thus, each party has two seeds and can set up an RNG's, where two party are able to create the same random numbers:

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

Similar, linear operations can be computed locally in the binary domain as well.

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

In replicated sharing over rings $\mathbb Z_{2^k}$ (e.g., ABY3), arithmetic to binary conversion of a share $[x]$ is implemented by first locally splitting the shares to valid binary sharings, i.e., $[x_1]^B = (x_1, 0, 0)$, $[x_2]^B = (0, x_2, 0)$, and $[x_3]^B = (0, 0, x_3)$ and combining them in MPC using binary addition circuits. Then $[x]^B = \text{BinAdd}(\text{BinAdd}([x_1]^B, [x_2]^B), [x_3]^B)$ is a valid binary sharing of $x$. This approach works because binary addition circuits implicitly perform modular reductions mod $2^k$.

Thus, in $\mathbb F_p$ we have to include the mod $p$ reductions manually in the circuit. For improved performance, we use the following protocol to translate $[x]$:

* $P_i$ samples $r_i$ to be a new random binary share of $0$
* Set $[x_3]^B = (0, 0, x_3)$
* $P_2$ calculates $t = (x_1 + x_2 \mod p) \oplus r_2$
  * It follows that $(r_1, t, r_3)$ is a valid binary sharing of $(x_1 + x_2 \mod p)$
* $P_i$ sends its share of $(r_1, t, r_3)$ to $P_{i+1}$
  * Each party now has a valid binary replicated sharing $[x_{1,2}]^B$ of $(x_1 + x_2 \mod p)$
* The parties compute a binary adder circuit of $k=\lceil \log_2(p)\rceil$ bits to sum up $[x_3]^B$ and $[x_{1,2}]^B$ to get $[t_1]^B$ with $k+1$ bits (including overflow bit).
* The parties compute the subtraction of $[t_1]^B - p$ inside a binary circuit to get $[t_2]^B$.
* The $(k+1)$-th bit of $[t_2]^B$ indicates an overflow of the subtraction. If an overflow occurs, the result should be the first $k$ bits of $[t_1]^B$, otherwise the first $k$ bits of $[t_2]^B$. This if statement can be computed with a CMUX gate.

#### Binary to Arithmetic Conversion

For the binary to arithmetic conversion, the general strategy for replicated sharing is the following. We sample random binary shares $[x'_2]^B$ and $[x'_3]^B$ using the special correlated randomness, such that $P_3$ gets both values in addition to it's shares, while $P_1$ and $P_2$ get $x'_3$ and $x'_2$ in clear respectively. Then we compute a binary circuit to add $[x_1]^B = \text{BinAdd}(\text{BinAdd}([x]^B, [x'_2]^B), [x'_3]^B)$. Finally, we open $[x_1]^B$ to $P_1$ and $P_2$. The arithmetic shares then are $[x] = (x_1, -x'_2, -x'_3)$.

To account for modular reductions in finite fields, we follow a similar strategy as for the arithmetic to binary conversion to translate $[x]^B$:

* $P_i$ samples $r_i$ to be a new random binary share of $0$
* $P_1$ samples $x'_3$ using RNG2 and sets $x_3 = -x'_3$;
* $P_2$ samples $x'_2$ using RNG1 and sets $x_2 = -x'_2$;
* $P_3$ samples $x'_2$ using RNG1 and $x'_3$ using RNG2, sets $x_2 = -x'_2$, $x_3 = -x'_3$, and $t = (x'_2 + x'_3 \mod p) \oplus r_3$;
  * It follows that $(r_1, t, r_3)$ is a valid binary sharing of $(x'_2 + x'_3 \mod p)$
* $P_i$ sends its share of $(r_1, t, r_3)$ to $P_{i+1}$
  * Each party now has a valid binary replicated sharing $[x'_{2,3}]^B$ of $(x'_2 + x'_3 \mod p)$
* The parties compute a binary adder circuit of $k=\lceil \log_2(p)\rceil$ bits to sum up $[x]^B$ and $[x'_{2,3}]^B$ to get $[t_1]^B$ with $k+1$ bits (including overflow bit).
* The parties compute the subtraction of $[t_1]^B - p$ inside a binary circuit to get $[t_2]^B$.
* The $(k+1)$-th bit of $[t_2]^B$ indicates an overflow of the subtraction. If an overflow occurs, $[x_1]^B$ should be the first $k$ bits of $[t_1]^B$, otherwise the first $k$ bits of $[t_2]^B$. This if statement can be computed with a CMUX gate.
* We open $[x_1]^B$ to $P_1$ and $P_2$
* The final sharing is $[x] = (x_1, x_2, x_3)$ and each party has (only) access to the shares it requires for the replication.

#### Bit Injection

To translate a single shared bit $[x]^B$ to a arithmetic sharing, we perform share splitting and create valid arithmetic shares of the shares: $[x_1] = (x_1, 0, 0)$, $[x_2] = (0, x_2, 0)$, and $[x_3] = (0, 0, x_3)$. Then, we combine the shares by calculating arithmetic XORs: $[x] = \text{AXor}(\text{AXor}([x_1], [x_2]), [x_3])$, where $\text{AXor}(a, b) = a + b - 2 \cdot a \cdot b$.

#### Binary Addition Circuits

As mentioned in the arithmetic to binary conversions, we need binary addition circuits. Since the bitlength of the used prime fields is large, we use depth-optimized carry-lookahead adders for the conversions. Currently, we implement Kogge-Stone adders, since these can be computed efficiently using shifts and AND/XOR gates without extracting specific bits.

The general structure of a Kogge-Stone adder to add two binary values $x, y$ is to first compute $p[i] = x[i] \oplus y[i]$ and $g[i] = x[i] \wedge y[i]$, where $x[i]$ is the $i$-th bit of $x$. Then, $p$ and $g$ are combined using a circuit with logarithmic depth (in the bitsize). This circuit is implemented in the `kogge_stone_inner` function.

For binary subtraction circuits, we basically compute an addition circuit with the two's complement of $y$. Thus, we essentially compute $2^k + x - y$. If $y$ is public, the $2^k - y$ can directly be computed and the result is just fed into the Kogge-Stone adder. If $y$ is shared, we invert all $k$ bits and set the carry-in flag for the Kogge-Stone adder. This simulates two's complement calculation. The set carry-in flag has the following effects: First, $g[0]$ must additionally be XORed by $p[0]$. Finally, the LSB of the result of the Kogge-Stone circuit needs to be flipped.

### Reconstruction

Reconstruction of a value is implemented as $P_i$ sending $z_{i-1}$ to $P_{i+1}$. Then each party has all shares.

### Security

Our implementation provides semi-honest security with honest majority, i.e., the scheme is secure if all parties follow the protocol honestly and no servers collude.

## Shamir Secret Sharing

Shamir secret sharing is a different way of instantiating a linear secret sharing scheme which is based on polynomials. To share a value $x\in\mathbb F_p$, one first has to sample a random polynomial of degree $t$, where $x$ is in the constant term. I.e., one samples $a_1, a_2, ..., a_t$ randomly from $\mathbb F_p$ and sets: $Q(X) = x + a_1 \cdot X + a_2 \cdot X^2 + ... + a_t \cdot X^t$.
The share of party $i$ then is $Q(i)$. In other words, $[x]_t = (x_1, x_2, ..., x_n)$, where $x_i=Q(i)$.

Reconstruction then works via lagrange interpolation of any $t+1$ shares: $x = \sum_i^{t+1} \lambda_i x_i$, where $\lambda_i$ is the corresponding lagrange coefficient.

### Supported operations

#### Linear Operations

Shamir's secret sharing allows, similar to additive sharing, to compute linear functions locally without party interaction:

* Constant addition: $[x]_t + y = (x_1 + y, x_2 + y, x_3 + y)$
* Share addition: $[x]_t + [y]_t = (x_1 + y_1, x_2 + y_2, x_3 + y_3)$
* Constant Multiplication: $[x]_t \cdot y = (x_1\cdot y, x_2\cdot y, x_3\cdot y)$

#### Multiplications

Shamir secret sharing comes with a native multiplication protocol: $z_i = x_i\cdot y_i$ is a valid share of $[z]_{2t} = [x]_t \cdot [y]_t$. However, $z_i$ is a point on a polynomial with degree $2t$. In other words, the degree doubles after a multiplication and twice as many parties ($2t+1$) are required to reconstruct the secret $z$. Thus, one needs to perform a degree reduction step in MPC for further computations. In DN07, this is done by sampling a random value, which is shared as a degree-$t$ ($[r]_t$) and degree-$2t$ ($[r]_{2t}$) polynomial. Then, the parties open $[z]_{2t} + [r]_{2t}$ to $P_1$, who reconstructs it to $z' =z+r$. Then. $P_1$ shares $z'$ as a fresh degree-$t$ share to all parties, who calculate $[z]_t = [z']_t - [r]_t$.

#### Rng Setup

For the degree reduction step after a multiplication we require degree-$t$ and degree-$2t$ sharings of the same random value $r$. We generate these values following the techniques proposed in DN07, to generate $t$ random pairs at once:

* Each party $P_i$ generates a random value $s_i$ and shares it as degree-$t$ share $[s_i]_t$ and degree-$2t$ share $[s_i]_{2t}$ to the other parties.
* After receiving the all shares, one sets $[\vec{s}]_t = ([s_1]_t, [s_2]_t, ..., [s_n]_t)^T$ and $[\vec{s}]_{2t} = ([s_1]_{2t}, [s_2]_{2t}, ..., [s_n]_{2t})^T$.
* Calculate $([r_1]_t, [r_2]_t, ..., [r_t]_t)^T = M \cdot [\vec{s}]_t$ and $([r_1]_{2t}, [r_2]_{2t}, ..., [r_t]_{2t})^T = M \cdot [\vec{s}]_{2t}$, where $M\in\mathbb F_p^{t\times n}$ is a Vandermonde matrix.
* The pairs $([r_i]_t, [r_i]_{2t})$ for $1\le i \le t$ are then valid random shares which can be used for resharing.

For simplicity we use the following Vandermonde matrix:
$$
    M = \left(\begin{array}{ccccc}
        1 & 1 & 1 & ... & 1 \\
        1 & 2 & 3 & ... & n \\
        1 & 2^2 & 3^2 & ... & n^2 \\
        \vdots & \vdots & \vdots & \ddots & \vdots  \\
        1 & 2^t & 3^t & ... & n^t \\
    \end{array}\right)
$$

### Reconstruction

Reconstruction is currently implemented as $P_i$ sending its share $x_i$ to the next $t$ parties. Then, each party has $t+1$ shares to reconstruct the secret.

### Security

Our implementation provides semi-honest security with honest majority, i.e., the scheme is secure if all parties follow the protocol honestly and at most $t$ servers collude. $t$ can, thereby, be chosen to be $t\le \frac{n-1}{2}$.

## MPC for group operations

So far, we only discussed MPC for field elements $\mathbb F_p$. However, one can easily extend it to MPC over Group elements $\mathbb G$. W.l.o.g. we will use the notation for additive groups $\mathbb G$ (e.g., elliptic curve groups). A secret share $[x]\in\mathbb F_p$ can be translated to a shared group element by $[X] = [x] \cdot G$, where $G$ is a generator of $\mathbb G$. Then, $[X] = (X_1, X_2, ..., X_n)$ is a valid share of $X=x\cdot G$. Linear operations directly follow from the used linear secret sharing scheme: $[Z] = a \cdot [X] + b\cdot [Y] + C = (a\cdot [x] + b\cdot [y] + c)\cdot G$. Shared scalar multiplications also follow from the secret sharing scheme: $[Z] = [x] \cdot [Y] = [x] \cdot [y] \cdot G$.

## Shamir vs Rep3

Shamir and Rep3 are both linear secret sharing schemes which provide semi-honest security with honest-majority. However, they have some important differences.

* Shamir can be instantiated with $n\ge 3$ parties, while Rep3 is limited to $n=3$ parties.
* In Shamir, each share is just one field element $\in\mathbb F_p$, while in Rep3 each share is composed of two field elements.
* In Shamir, the overhead on the CPU is significantly smaller compared to Rep3, where each operation is applied to two shares.
* Rep3 allows efficient arithmetic-to-binary conversions.

## Witness Extension

Due to not having an efficient arithmetic to binary conversion, we do not have a witness extension implementation for Shamir sharing at the moment. However, we provide a bridge implementation, which can translate Rep3 shares to 3-party Shamir shares (with threshold/poly-degree $t=1$).

This bridge works by first letting $P_i$ translate its first additive share $x_i$ to a Shamir share by dividing by the corresponding lagrange coefficient. This, however, creates a 3-party Shamir sharing with threshold/poly-degree $t=2$. Thus, we perform the same degree-reduction step, which is also required after a Shamir multiplication.

[^1]: ABY3: [https://eprint.iacr.org/2018/403.pdf](https://eprint.iacr.org/2018/403.pdf)
[^2]: Shamir: [https://web.mit.edu/6.857/OldStuff/Fall03/ref/Shamir-HowToShareASecret.pdf](https://web.mit.edu/6.857/OldStuff/Fall03/ref/Shamir-HowToShareASecret.pdf)
[^3]: DN07: [https://iacr.org/archive/crypto2007/46220565/46220565.pdf](https://iacr.org/archive/crypto2007/46220565/46220565.pdf)
