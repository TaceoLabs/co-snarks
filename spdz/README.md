# SPDZ — 2-Party MPC Protocol for co-snarks

Dishonest-majority 2-party computation using the SPDZ protocol, integrated with TACEO's co-snarks framework for collaborative Noir proving.

## What is this?

This adds a 2-party MPC backend to co-snarks, alongside the existing Rep3 (3-party) and Shamir (n-party) protocols. Two parties can collaboratively generate UltraHonk ZK proofs over shared private inputs — neither party learns the other's data.

## Structure

```
spdz/
├── core/          # SPDZ protocol: shares, Beaver multiplication, preprocessing, OT, gadgets
│   └── gadgets/
│       ├── bits.rs        # Algebraic is_zero, bit decomposition
│       ├── poseidon2.rs   # Mask-and-evaluate S-box
│       ├── yao2pc/        # Garbled circuit engine
│       │   ├── gc_blake2s.rs  # Blake2s via GC (0.05s)
│       │   ├── gc_blake3.rs   # Blake3 via GC (0.05s)
│       │   ├── gc_sha256.rs   # SHA256 via GC (0.39s)
│       │   └── gc_hash.rs     # 254-bit modular adder for share recovery
│       └── ...
├── acvm/          # ACVM witness extension solver
├── ultrahonk/     # UltraHonk prover driver
├── noir/          # Top-level API + integration tests
└── docs/          # Architecture, capabilities, testing, gap analysis
```

## Key Features

- **Full prove+verify pipeline**: Secret-share inputs -> ACVM solve -> UltraHonk prove -> verify
- **25 prove+verify tests** across Keccak256, Poseidon2Sponge, and ZK mode
- **Garbled circuit hashing**: Blake2s, Blake3, SHA256 evaluated via GC in 2-3 network rounds
- **KOS OT extension**: Amortized base OT for efficient Beaver triple generation
- **Poseidon2 on shared values**: Mask-and-evaluate S-box technique
- **Zero modifications to TACEO's code**: Everything in `spdz/`, clean upstream merges

## Usage

```rust
use co_spdz_noir::{generate_proving_key_spdz, prove_spdz};
use spdz_core::preprocessing::create_lazy_preprocessing;

// Each party:
let preprocessing = create_lazy_preprocessing::<Fr>(seed, party_id);
let pk = generate_proving_key_spdz(preprocessing, &constraint_system, witness, &net, &crs)?;
let (proof, public_inputs) = prove_spdz::<_, Keccak256, _>(&net, proving_prep, pk, &crs, zk, &vk)?;

// Standard UltraHonk proof -- verifiable by anyone
let valid = UltraHonk::<_, Keccak256>::verify(proof, &public_inputs, &vk, zk)?;
```

## Comparison with Rep3

| | Rep3 | SPDZ |
|---|---|---|
| Parties | 3 | 2 |
| Security | Honest majority | Dishonest majority |
| Preprocessing | Online (correlated RNG) | Beaver triples (KOS OT) |
| Hash GC (Blake2s, Blake3, SHA256) | Via Yao GC | Via Yao GC (wired into ACVM) |
| Prove+verify tests | 4 circuits | 25 circuits |

See `docs/SPDZ_VS_REP3.md` for the full gap analysis.

## Upstreaming

This code lives entirely in `spdz/` with zero changes to TACEO's crates. If integrated upstream:
- `core/` -> `mpc-core/src/protocols/spdz/`
- `acvm/src/solver.rs` -> `co-noir/co-acvm/src/mpc/spdz.rs`
- `ultrahonk/src/driver.rs` -> `co-noir/co-noir-common/src/mpc/spdz.rs`
- `noir/src/lib.rs` -> `co-noir/co-noir/src/lib.rs` (add spdz functions)
