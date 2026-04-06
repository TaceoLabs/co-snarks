# co-spdz — 2-Party SPDZ Protocol for co-snarks

Dishonest-majority 2-party computation using the SPDZ protocol, integrated with TACEO's co-snarks framework for collaborative Noir proving.

## What is this?

co-spdz adds a 2-party MPC backend to co-snarks, alongside the existing Rep3 (3-party) and Shamir (n-party) protocols. It enables two parties to collaboratively generate UltraHonk ZK proofs over shared private inputs — neither party learns the other's data.

## Structure

```
co-spdz/
├── core/          # SPDZ protocol primitives (shares, Beaver multiplication, preprocessing, gadgets)
├── acvm/          # ACVM witness extension solver (NoirWitnessExtensionProtocol)
├── ultrahonk/     # UltraHonk prover driver (NoirUltraHonkProver)
├── noir/          # Top-level API: generate_proving_key_spdz(), prove_spdz()
└── docs/          # Architecture, capabilities, testing, comparison with Rep3
```

Mirrors the `co-noir/` directory structure: separate crates for each layer, all under one folder.

## Usage

```rust
use co_spdz_noir::{generate_proving_key_spdz, prove_spdz};
use spdz_core::preprocessing::create_lazy_preprocessing;

// Each party:
let preprocessing = create_lazy_preprocessing::<Fr>(seed, party_id);
let pk = generate_proving_key_spdz(preprocessing, &constraint_system, witness, &net, &crs)?;
let (proof, public_inputs) = prove_spdz::<_, Keccak256, _>(&net, proving_prep, pk, &crs, zk, &vk)?;

// Standard UltraHonk proof — verifiable by anyone
let valid = UltraHonk::<_, Keccak256>::verify(proof, &public_inputs, &vk, zk)?;
```

## Comparison with Rep3

| | Rep3 | SPDZ |
|---|---|---|
| Parties | 3 | 2 |
| Security | Honest majority | Dishonest majority |
| Preprocessing | Online (correlated RNG) | Beaver triples (OT-based) |
| Garbled circuits | Full (Yao GC via Bristol) | Standalone engine (not wired into ACVM) |
| Supported Noir ops | 29 circuits tested | 25 circuits tested (19 prove+verify) |

See `docs/SPDZ_VS_REP3.md` for the full gap analysis.

## Upstreaming

This code is structured to be upstreamable to TACEO's co-snarks. If integrated:
- `core/` → `mpc-core/src/protocols/spdz/`
- `acvm/src/solver.rs` → `co-noir/co-acvm/src/mpc/spdz.rs`
- `ultrahonk/src/driver.rs` → `co-noir/co-noir-common/src/mpc/spdz.rs`
- `noir/src/lib.rs` → `co-noir/co-noir/src/lib.rs` (add spdz functions)

The only modification to existing co-snarks code: `Poseidon2Precomputations::new()` constructor in `mpc-core`.
