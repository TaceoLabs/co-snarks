# SPDZ vs Rep3 — Gap Analysis

## Protocol Comparison

| | Rep3 | SPDZ |
|---|---|---|
| **Parties** | 3 | 2 |
| **Security** | Honest majority (1 of 3 corrupt) | Dishonest majority (either party can cheat) |
| **Preprocessing** | Online (correlated RNG, no trusted dealer) | Beaver triples (currently trusted dealer, OT-based available) |
| **Multiplication** | 1 reshare (local mask + send) | 1 Beaver triple + 1 open (2 messages) |
| **Garbled Circuits** | Full Yao GC integration | Not integrated into ACVM (standalone GC available) |

## ACVM Solver (Witness Extension)

| Operation Category | Rep3 (109 methods) | SPDZ (93 methods) | Gap |
|---|---|---|---|
| **Field arithmetic** | Full | Full | None |
| **Comparisons (==, <, >)** | Via Yao GC | Via algebraic is_zero + bit decomp | Different approach, both work |
| **Bitwise (AND, XOR)** | Via Yao GC | Via bit decomp + mul | Both produce correct witnesses |
| **Poseidon2** | Full (precomp S-box) | Full (mask-and-evaluate S-box) | None |
| **SHA256** | Via Yao GC (Bristol circuit) | Panics on shared | **Gap** |
| **Blake2s/Blake3** | Via Yao GC (Bristol circuit) | Panics on shared | **Gap** |
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

### Summary: 16 methods Rep3 has that SPDZ doesn't

The gap comes from two root causes:

1. **No Yao GC in the ACVM** (12 methods): Rep3 uses garbled circuits for SHA256, Blake, AES, sparse tables, and bit-level operations. Our spdz-core has a standalone GC engine (`gadgets/yao2pc/`) but it's not wired into the ACVM solver's blackbox handlers.

2. **No Grumpkin curve support** (4 methods): EC point construction, Pedersen hash/commitment require Grumpkin field operations with shared coordinates. Rep3 handles these natively.

## UltraHonk Driver (Proving)

| Method | Rep3 | SPDZ | Gap |
|---|---|---|---|
| All arithmetic (add, sub, mul, inv) | Full | Full | None |
| FFT/IFFT | Full | Full | None |
| MSM | Full | Full | None |
| Open (field + point) | Full | Full (unchecked) | None |
| Reshare | Full | Full | None |
| local_mul_vec | Local mask | Beaver via stored net ptr | None (different approach) |
| `is_zero_many` | Full | **Panics** | **Gap** |
| `pointshare_to_field_shares_many` | Full | **Panics** | **Gap** |
| Poseidon2 permutation | Full | Full | None |

### 2 methods SPDZ is missing in UltraHonk:

- `is_zero_many`: Used during proof construction. Could be implemented using our algebraic is_zero gadget. Not triggered by current test circuits.
- `pointshare_to_field_shares_many`: Point decomposition. Requires Grumpkin support. Not triggered by current test circuits.

## Brillig Driver (Unconstrained Execution)

| | Rep3 (24 methods) | SPDZ (22 methods) | Gap |
|---|---|---|---|
| Public ops | Full | Full | None |
| Shared arithmetic | Panics (type mismatch) | Supported (add, sub, mul) | **SPDZ ahead** |
| Shared cmux | Supported | Supported | None |
| Shared division | Panics | Panics | Same |
| random() | Supported | Panics | **Gap** |

SPDZ's Brillig driver is actually **better** than Rep3's for basic shared arithmetic — Rep3 panics on shared add/sub/mul in Brillig, SPDZ handles them.

## Preprocessing

| | Rep3 | SPDZ |
|---|---|---|
| **Type** | Online (correlated RNG) | Offline (Beaver triples) |
| **Trusted dealer needed** | No | Yes (currently) |
| **OT-based alternative** | N/A | Available but not default |
| **Material** | Masking elements on-the-fly | Triples, random shares, random bits |
| **Memory** | Minimal (RNG state) | Lazy generation (12MB for 4K batch) |
| **Fork support** | Yes (split RNG state) | Yes (partition preprocessing) |

**Key difference**: Rep3 needs no preprocessing phase — randomness is generated online from correlated RNGs seeded during initialization. SPDZ requires Beaver triples generated before computation. Our `LazyDummyPreprocessing` generates them on-demand from a shared seed (equivalent to a trusted dealer). For production, OT-based triple generation is available.

## Test Coverage

| Test Category | Rep3 | SPDZ |
|---|---|---|
| MPC core unit tests | 87 | 46 |
| Witness extension (circuit tests) | 31 | 19 |
| Proof tests (Keccak256, no ZK) | 3 | 19 |
| Proof tests (Keccak256, ZK) | 3 | 3 |
| Proof tests (Poseidon2Sponge) | 3 | 3 |
| Integration tests | — | 6 |
| **Total** | **~130** | **~96** |

Rep3 has more MPC unit tests (87 vs 46) and more witness extension tests (31 vs 19). But SPDZ has **6x more proof tests** (25 vs 4 that actually prove+verify). Rep3's proof tests only cover poseidon, add3u64, and recursion.

## Plookup Proof Verification

Neither Rep3 nor SPDZ has passing proof tests for plookup-dependent circuits. Rep3 only tests witness extension for these (no prove+verify). We tested prove+verify and found they fail at verification — a general co-snarks MPC+plookup issue.

| Plookup Circuit | Rep3 Witness | Rep3 Proof | SPDZ Witness | SPDZ Proof |
|---|---|---|---|---|
| blackbox_and | Pass | **Not tested** | Pass | Fail |
| blackbox_xor | Pass | **Not tested** | Pass | Fail |
| sha256 | Pass | **Not tested** | N/A (panic) | N/A |
| blake2s | Pass | **Not tested** | N/A (panic) | N/A |
| blake3 | Pass | **Not tested** | N/A (panic) | N/A |
| random_access | Pass | **Not tested** | Pass | Fail |

## What Would Close the Gaps

### Priority 1: Wire GC into ACVM (closes 12 method gaps)

Our `spdz-core/gadgets/yao2pc/` has a working Yao GC engine with OT. Wiring it into the ACVM solver's blackbox handlers would enable:
- SHA256, Blake2s, Blake3 on shared values
- Sparse table operations
- AES S-box
- Bit-level slicing via GC (like Rep3 does)

**Effort**: Medium. The GC engine works (tested). Need to map ACVM blackbox calls to GC circuits.

### Priority 2: Grumpkin curve support (closes 4 method gaps)

Need dual-field preprocessing: Grumpkin scalars are BN254 base field elements. Requires:
- `SpdzPointShare` with Grumpkin coordinates
- EC addition/scalar-mul on shared Grumpkin points
- Pedersen hash using shared EC ops

**Effort**: Large. Requires new share types and preprocessing for a second field.

### Priority 3: UltraHonk `is_zero_many` (closes 1 gap)

Batch version of is_zero for the prover. Could delegate to our `gadgets::bits::is_zero` in a loop, or implement a batched algebraic version.

**Effort**: Small. Not triggered by current circuits but good for completeness.

### Priority 4: Plookup proof compatibility (closes proof verification failures)

The sorted polynomial construction in UltraHonk's plookup doesn't work correctly with MPC shares. This affects both Rep3 and SPDZ. Needs investigation at the co-builder level.

**Effort**: Large. Architectural issue in co-snarks.

### Priority 5: Production preprocessing (closes trusted dealer gap)

Replace `LazyDummyPreprocessing` with OT-based triple generation as the default. The OT infrastructure exists (`spdz-core/ot/`) but needs hardening.

**Effort**: Medium. Infrastructure exists, needs testing and integration.
