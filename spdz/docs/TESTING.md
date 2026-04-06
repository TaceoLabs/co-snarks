# Testing Strategy

## Test Categories

### 1. Share Arithmetic (spdz-core unit tests)

Verify that SPDZ share operations maintain mathematical invariants:

- **Reconstruction**: `share_0 + share_1 = original_value` after sharing
- **MAC consistency**: `mac_0 + mac_1 = alpha * value` through all operations
- **Linearity**: `share(a) + share(b) = share(a + b)` (shares of sum = sum of shares)
- **Scalar multiplication**: `share(a) * public_c = share(a * c)`
- **Negation**: `share(-a) = -share(a)`

### 2. Beaver Triple Correctness (spdz-core unit tests)

Verify the Beaver multiplication protocol:

- **Triple validity**: Generated triples satisfy `a * b = c`
- **MAC on triples**: All triple components have correct MACs
- **Multiplication output**: `open(mul([x], [y])) = x * y`
- **Batched multiplication**: Same correctness for `mul_many`
- **MAC preservation**: Multiplication output has correct MAC

### 3. Preprocessing Integrity (spdz-core unit tests)

- MAC key shares from both parties sum to the global MAC key
- Shared random bits are actually 0 or 1 (verified by reconstructing)
- Input masks: cleartext matches reconstructed shared value
- Exhaustion: proper error when preprocessing material runs out

### 4. Networked Operations (spdz-core integration tests)

Two-party tests using `LocalNetwork::new(2)`:

- **Open**: Both parties reconstruct the same value
- **Beaver mul**: Two-party multiplication produces correct result
- **Batched mul**: Multiple multiplications in single round
- **Inversion**: `a * inv(a) = 1`
- **Input sharing**: Sender's value correctly shared with receiver

### 5. End-to-End Proving (co-spdz-noir (crate name) integration tests)

Full pipeline from Noir circuit to verified proof:

| Test | What's Special |
|------|---------------|
| `test_spdz_e2e_keccak` | Baseline: trivially shared `addition_multiplication` circuit |
| `test_shared_x_shared_multiplication` | Custom circuit with `x * y` -- forces Beaver triples in the prover |
| `test_secret_shared_inputs` | **Key test**: genuinely random shares per party |

### The Secret-Shared Test in Detail

This test is the strongest correctness validation:

```
1. Load mul_shared circuit: assert(x * y != 0), x=3, y=7
2. Generate DummyPreprocessing for both parties (correlated)
3. Extract MAC key: alpha = alpha_0 + alpha_1
4. Secret-share witness with alpha:
     Party 0: (random_share_0, random_mac_0) for each value
     Party 1: (value - random_share_0, alpha*value - random_mac_0) for each value
5. Verify shares reconstruct: share_0 + share_1 == original (sanity check)
6. Verify MACs: mac_0 + mac_1 == alpha * value (sanity check)
7. Run 2-party proving with these genuinely different shares
8. Assert both parties produce identical proofs
9. Verify proof with standard UltraHonk verifier
```

If any step in the SPDZ protocol is incorrect (wrong Beaver multiplication, broken MAC tracking, incorrect reshare), the proof will fail to verify.

## What's NOT Tested (Yet)

- **Malicious behavior**: No test for a cheating party sending invalid shares
- **MAC verification**: No test that MAC checking catches corruption
- **Complex operations**: No test for circuits using comparison, bit decomposition, hashing on shared values (these operations panic)
- **Large circuits**: Only tested on small circuits (~100 constraints)
- **Performance**: No benchmarks for proving time vs single-prover or vs 3-party Rep3
- **Cross-protocol comparison**: No test comparing SPDZ proof bytes against Rep3/Shamir for same circuit

## Running Tests

```bash
# All 27 tests
cargo test

# Unit tests only (no CRS files needed)
cargo test -p spdz-core

# Integration tests (requires CRS files from co-snarks)
cargo test -p co-spdz-noir (crate name)

# Specific test with output
cargo test --test correctness -p co-spdz-noir (crate name) test_secret_shared -- --nocapture
```

## Test Dependencies

- CRS files: `co-noir/co-noir-common/src/crs/bn254_g1.dat` (65MB) and `bn254_g2.dat`
- Test vectors: `test_vectors/noir/addition_multiplication/kat/`
- Custom circuits: `test_vectors/noir/mul_shared/kat/` (compiled with nargo v1.0.0-beta.17)
