# SPDZ vs Rep3 -- Gap Analysis

## Protocol Comparison

| | Rep3 | SPDZ |
|---|---|---|
| **Parties** | 3 | 2 |
| **Security** | Honest majority (1 of 3 corrupt) | Dishonest majority (either party can cheat) |
| **Preprocessing** | Online (correlated RNG, no trusted dealer) | Beaver triples (KOS OT extension) |
| **Multiplication** | 1 reshare (local mask + send) | 1 Beaver triple + 1 open (2 messages) |
| **Garbled Circuits** | Full Yao GC (Bristol fashion + gate-level) | Yao GC (gate-level, wired into ACVM) |

## ACVM Solver (Witness Extension)

| Operation Category | Rep3 (109 methods) | SPDZ (93 methods) | Gap |
|---|---|---|---|
| **Field arithmetic** | Full | Full | None |
| **Comparisons (==, <, >)** | Via Yao GC | Via algebraic is_zero + bit decomp | None (different approach) |
| **Bitwise (AND, XOR)** | Via Yao GC | Via bit decomp + mul | None (witness correct) |
| **Poseidon2** | Full (precomp S-box) | Full (mask-and-evaluate S-box) | None |
| **SHA256** | Via Yao GC (Bristol circuit) | Via Yao GC (gate-level) | None |
| **Blake2s** | Via Yao GC (gate-level) | Via Yao GC (gate-level) | None |
| **Blake3** | Via Yao GC (gate-level) | Via Yao GC (gate-level) | None |
| **AES128** | Via Yao GC (Bristol circuit) | Panics on shared | **Gap** |
| **EC point ops** | Full (Grumpkin) | Public-only (shared panics) | **Gap** |
| **Pedersen hash/commit** | Full (uses EC) | Panics (needs Grumpkin) | **Gap** |
| **Non-native limbs** | Public-only (shared unimplemented) | Public-only (shared panics) | Same |
| **NAF entries** | Unimplemented for shared | Panics for shared | Same |
| **Sparse tables** | Via Yao GC | Panics | **Gap** |
| **LUT write** | Supported | Panics | **Gap** |
| **cmux_many** | Supported | Supported (batched) | None |
| **equal_many** | Via GC batch | Via algebraic batch | None |
| **Plookup slicing (AND/XOR)** | Via Yao GC | Via bit decomp | Witness correct, proof fails |

### Remaining gaps: 6 methods

1. **AES128** (1 method): Needs Bristol fashion circuit loader or gate-level AES implementation
2. **Grumpkin curve ops** (3 methods): EC point construction, Pedersen hash/commitment
3. **Sparse tables** (1 method): Complex lookup used by AES/SHA internally
4. **LUT write** (1 method): Lookup table write for shared index

## UltraHonk Driver (Proving)

| Method | Rep3 | SPDZ | Gap |
|---|---|---|---|
| All arithmetic (add, sub, mul, inv) | Full | Full | None |
| FFT/IFFT | Full | Full | None |
| MSM | Full | Full | None |
| Open (field + point) | Full | Full (unchecked) | None |
| Reshare | Full | Full | None |
| local_mul_vec | Local mask | Beaver via stored net ptr | None |
| `is_zero_many` | Full | Full | None |
| `pointshare_to_field_shares_many` | Full | **Panics** | **Gap** |
| Poseidon2 permutation | Full | Full | None |

### 1 method SPDZ is missing in UltraHonk:

- `pointshare_to_field_shares_many`: Point decomposition. Requires Grumpkin support. Not triggered by current circuits.

## Brillig Driver (Unconstrained Execution)

| | Rep3 (24 methods) | SPDZ (22 methods) | Gap |
|---|---|---|---|
| Public ops | Full | Full | None |
| Shared arithmetic | Panics (type mismatch) | Supported (add, sub, mul) | **SPDZ ahead** |
| Shared cmux | Supported | Supported | None |
| Shared division | Panics | Panics | Same |
| random() | Supported | Panics | **Gap** |

SPDZ's Brillig driver handles basic shared arithmetic (add/sub/mul) where Rep3 panics.

## Preprocessing

| | Rep3 | SPDZ |
|---|---|---|
| **Type** | Online (correlated RNG) | Offline (Beaver triples) |
| **Trusted dealer needed** | No | No (KOS OT extension) |
| **OT implementation** | N/A | KOS with Chou-Orlandi base OT, Gilboa multiplication |
| **Material** | Masking elements on-the-fly | Triples, random shares, random bits |
| **Memory** | Minimal (RNG state) | Lazy generation (12MB for 4K batch) |
| **Fork support** | Yes (split RNG state) | Yes (partition preprocessing) |

## Test Coverage

| Test Category | Rep3 | SPDZ |
|---|---|---|
| MPC core unit tests | 87 | 50 |
| Witness extension (circuit tests) | 31 | 19 |
| Proof tests (Keccak256, no ZK) | 3 | 19 |
| Proof tests (Keccak256, ZK) | 3 | 3 |
| Proof tests (Poseidon2Sponge) | 3 | 3 |
| Integration tests | -- | 6 |
| **Total** | **~130** | **~100** |

SPDZ has **6x more proof tests** (25 vs 4 that actually prove+verify).

## Plookup Proof Verification

Neither Rep3 nor SPDZ has passing proof tests for plookup-dependent circuits. This is a general co-snarks MPC+plookup issue, not protocol-specific.

| Plookup Circuit | Rep3 Witness | Rep3 Proof | SPDZ Witness | SPDZ Proof |
|---|---|---|---|---|
| blackbox_and | Pass | **Not tested** | Pass | Fail |
| blackbox_xor | Pass | **Not tested** | Pass | Fail |
| sha256 | Pass | **Not tested** | GC works | Fail (plookup) |
| blake2s | Pass | **Not tested** | GC works | Fail (plookup) |
| blake3 | Pass | **Not tested** | GC works | Fail (plookup) |
| random_access | Pass | **Not tested** | Pass | Fail |

## Remaining Gaps

### Priority 1: Grumpkin curve support (closes 4 gaps)

Need dual-field preprocessing for Grumpkin operations.

**Effort**: Large.

### Priority 2: AES128 via GC (closes 1 gap)

Implement AES round function as FancyBinary gates, or add Bristol circuit loader.

**Effort**: Medium.

### Priority 3: Plookup proof compatibility (closes proof verification)

Sorted polynomial construction in UltraHonk plookup doesn't work with MPC shares. Affects both Rep3 and SPDZ.

**Effort**: Large. Architectural issue in co-snarks.
