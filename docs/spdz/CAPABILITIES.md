# What Can SPDZ 2PC Prove?

## Supported Noir Operations (shared inputs)

These operations work correctly when both parties hold genuinely secret-shared inputs:

| Category | Operations | Status |
|---|---|---|
| **Field arithmetic** | `+`, `-`, `*`, `/`, `invert` | Full support |
| **Comparison** | `==`, `!=`, `>`, `<`, `>=`, `<=` | Full support (via bit decomposition) |
| **Bitwise** | `AND`, `XOR`, `shift`, `slice` | Full support (via bit decomposition) |
| **Control flow** | `if/else`, `assert`, loops | Full support |
| **Poseidon2** | `std::hash::poseidon2_permutation` | Full support (mask-and-evaluate S-box) |
| **SHA256** | `std::hash::sha256_compression` | Full support (~6.4K multiplications per block) |
| **Blake2s** | `std::hash::blake2s` | Full support (10-round G function) |
| **Blake3** | `std::hash::blake3` | Full support (single block) |
| **Bit decomposition** | `to_le_bits`, `to_be_bits`, `decompose` | Full support |
| **Sort** | Array sorting by shared key | Full support (oblivious bubble sort) |
| **LUT** | Lookup tables with shared index | Full support (one-hot vector approach) |
| **EC addition** | `embedded_curve_add` with shared coordinates | Full support (affine formulas) |
| **MAC verification** | Commitment-based cheating detection | Full support (on by default) |

## Partially Supported (public inputs only)

These operations work when the specific inputs are public, but panic on shared:

| Operation | What works | What doesn't |
|---|---|---|
| **NAF decomposition** | Public scalar decomposition | Shared scalar NAF |
| **EC point construction** | Public coordinate → point | Shared coordinate → point |
| **AES128** | Structure implemented | Full 10-round encryption (~400K muls) |
| **LUT write** | — | Writing to LUT at shared index |

## Not Supported (panics)

These operations will panic at runtime if called with shared inputs. They require infrastructure that SPDZ doesn't have:

### 1. Grumpkin Curve Operations (needs dual-field preprocessing)

| Operation | Why it fails | Used by |
|---|---|---|
| Grumpkin point arithmetic | Needs Beaver triples over BN254 base field (Fq), but SPDZ only has triples over scalar field (Fr) | `pedersen_hash`, `pedersen_commitment`, `schnorr_verify` |
| OtherAcvmType shared mul/inv | Same — base field MPC requires separate preprocessing | Grumpkin curve ops |
| Multi-scalar multiplication | Needs shared NAF + Grumpkin point doubling | `multi_scalar_mul`, ECDSA verify |

**Impact**: Circuits using Pedersen hash/commitment, ECDSA verification, or Schnorr signatures with shared inputs will fail. **Use Poseidon2 instead of Pedersen** for 2PC-compatible hashing.

### 2. AES S-box (needs garbled circuits)

| Operation | Why it fails | Used by |
|---|---|---|
| AES128 full encryption | S-box evaluation on shared bytes needs ~400K multiplications or garbled circuits | `std::aes128::aes128_encrypt` |

**Impact**: Circuits using AES128 on shared inputs. Workaround: use SHA256 or Poseidon2 instead.

### 3. Sparse Table Operations (needs garbled circuits)

| Operation | Why it fails | Used by |
|---|---|---|
| `slice_and_get_sparse_table` | Internal SHA256/AES circuit optimization using Bristol-fashion GC | UltraHonk constraint builder internals |
| `slice_and_get_sparse_norm` | Same | SHA256 constraint optimization |
| `aes_sbox`, `aes_sparse_norm` | Same | AES constraint optimization |

**Impact**: These are internal optimizations used by the circuit builder. If hit, they produce a clear panic message. Standard SHA256 compression via our bitwise implementation is not affected.

### 4. Non-Native Field Arithmetic (unimplemented everywhere)

| Operation | Status |
|---|---|
| Limb-based arithmetic (`add_limbs`, `sub_limbs`, etc.) | **Rep3 also panics on these** |
| `compute_naf_entries` on shared scalars | **Rep3 also panics** |

**Impact**: Non-native field arithmetic (e.g., doing BLS12-381 arithmetic inside a BN254 circuit) is unimplemented in both SPDZ and Rep3.

## Circuit Compatibility Guide

### Will work with SPDZ 2PC

```noir
// Arithmetic + assertions
fn main(x: Field, y: Field) {
    assert(x * y + x + y != 0);
}

// Poseidon2 hash
fn main(inputs: [Field; 4]) -> pub Field {
    std::hash::poseidon2_permutation(inputs, 4)[0]
}

// SHA256 compression
fn main(input: [u32; 16], state: [u32; 8]) -> pub [u32; 8] {
    std::hash::sha256_compression(input, state)
}

// Comparisons and conditionals
fn main(a: u64, b: u64) -> pub u64 {
    if a > b { a } else { b }
}

// Bitwise operations
fn main(x: u64, y: u64) -> pub u64 {
    (x & y) ^ (x | y)
}
```

### Will NOT work with SPDZ 2PC

```noir
// Pedersen hash (uses Grumpkin curve)
fn main(a: Field, b: Field) -> pub Field {
    std::hash::pedersen_hash([a, b])  // PANICS: needs Grumpkin MSM
}

// AES128 (S-box too expensive)
fn main(inputs: [u8; 4], iv: [u8; 16], key: [u8; 16]) -> pub [u8; 16] {
    std::aes128::aes128_encrypt(inputs, iv, key)  // PANICS: needs GC
}

// ECDSA verify (uses Grumpkin)
// Any circuit using std::ec::* operations on shared scalars
```

## Recommendations for 2PC-Compatible Circuits

1. **Use Poseidon2 for hashing** — it's algebraic and works natively with SPDZ
2. **Use SHA256 for interoperability** — works but slower (~6.4K muls per block)
3. **Avoid Pedersen** — uses Grumpkin curve which needs dual-field MPC
4. **Avoid AES128** — S-box is impractical without garbled circuits
5. **Keep EC operations on public data** — or use shared field arithmetic directly
6. **Use `assert` freely** — supported through Brillig
7. **Comparisons are fine** — but expensive (~40 bits × 2 rounds each)
