# Architecture: How SPDZ Plugs Into co-snarks

## The Proving Pipeline

```
Noir Circuit (.json)                 co-snarks framework
       │                                    │
       ▼                                    ▼
┌─────────────┐    ┌────────────────────────────────────────┐
│ Witness      │    │  NoirWitnessExtensionProtocol trait    │
│ (shared or   │───►│  SpdzAcvmSolver implements this       │
│  public)     │    │  Handles: add, sub, mul, cmux, open   │
└─────────────┘    └────────────┬───────────────────────────┘
                                │ Produces shared witness
                                ▼
                   ┌────────────────────────────────────────┐
                   │  GenericUltraCircuitBuilder              │
                   │  Parameterized by SpdzAcvmSolver        │
                   │  Builds constraint polynomials          │
                   └────────────┬───────────────────────────┘
                                │ Produces ProvingKey<SpdzUltraHonkDriver>
                                ▼
                   ┌────────────────────────────────────────┐
                   │  NoirUltraHonkProver trait               │
                   │  SpdzUltraHonkDriver implements this    │
                   │  Handles: mul, FFT, MSM, open, reshare  │
                   │                                         │
                   │  Sumcheck + OinkProver + DeciderProver  │
                   └────────────┬───────────────────────────┘
                                │
                                ▼
                   ┌────────────────────────────────────────┐
                   │  Standard UltraHonk Proof                │
                   │  Verifiable by any UltraHonk verifier   │
                   │  (Aztec-compatible)                      │
                   └────────────────────────────────────────┘
```

## Trait Implementation Map

### SpdzAcvmSolver -> NoirWitnessExtensionProtocol

```
Associated Types:
  ArithmeticShare = SpdzPrimeFieldShare<F>    // (share, mac) pair
  AcvmType        = SpdzAcvmType<F>          // Public(F) | Shared(share)
  AcvmPoint       = SpdzAcvmPoint<C>         // Public(C) | Shared(point_share)
  Lookup          = Rep3FieldLookupTable<F>   // reused from Rep3 (not yet functional)
  BrilligDriver   = SpdzBrilligDriver<F, N>

Key methods (implemented):
  add, sub, mul, mul_with_public       -- arithmetic dispatch on Public|Shared
  invert                               -- mask-and-open via Beaver
  cmux                                 -- cond * truthy + (1-cond) * falsy
  open_many                            -- exchange share components
  rand, promote_to_trivial_share       -- from preprocessing / trivial sharing
  add_assign_with_public               -- MAC-aware public addition
  get_shared, get_public, is_shared    -- value inspection

Not implemented (panic on shared inputs, matching Shamir):
  equal, gt, lt                        -- comparison
  decompose_arithmetic                 -- bit decomposition
  sort, slice, right_shift             -- bitwise operations
  sha256_compression, blake2s, aes128  -- hash/crypto
  poseidon2_permutation                -- Poseidon2 hash
  LUT operations                       -- lookup tables
  EC operations                        -- embedded curve arithmetic
```

### SpdzUltraHonkDriver -> NoirUltraHonkProver

```
Associated Types:
  ArithmeticShare = SpdzPrimeFieldShare<P::ScalarField>
  PointShare      = SpdzPointShare<P>
  State           = SpdzState<P::ScalarField>

Key methods:
  add, sub, neg, mul_with_public       -- local (no communication)
  mul, mul_many                        -- Beaver triple protocol (1 round)
  local_mul_vec                        -- full Beaver via stored network pointer
  reshare                              -- exchange half-shares, attach MACs
  fft, ifft                            -- component-wise on (share, mac)
  msm_public_points                    -- component-wise MSM
  open_many, open_point                -- exchange and sum
  inv_many                             -- mask-and-open
  eval_poly                            -- Horner's method on shares
  add_assign_public                    -- uses SpdzPartyID.mac_key_share
  promote_to_trivial_share             -- (value if party 0 else 0, mac_key_share * value)
```

## The local_mul_vec / reshare Challenge

co-snarks splits multiplication into two steps for batching efficiency:

1. `local_mul_vec(a, b, state) -> Vec<ScalarField>` -- "local" computation
2. `reshare(half_shares, net, state) -> Vec<ArithmeticShare>` -- network communication

For Rep3: `local_mul_vec` computes cross-products + random mask (truly local), `reshare` exchanges masks.

For Shamir: `local_mul_vec` computes `a.inner * b.inner` (degree-2t), `reshare` does degree reduction.

For SPDZ: **local multiplication is impossible** -- Beaver triples require communication to open masked values. Our solution:

- `local_mul_vec` runs the full Beaver protocol using a network pointer stored in `SpdzState`
- Returns the `.share` component of the SPDZ result
- The prover accumulates these with public scalars (preserving additive sharing)
- `reshare` exchanges accumulated half-shares and attaches MACs

This works because the accumulation between `local_mul_vec` and `reshare` only involves public-scalar operations (selector multiplications, additions), which preserve the additive sharing property.

## Share Type Design

### SpdzPrimeFieldShare<F>

```rust
struct SpdzPrimeFieldShare<F: PrimeField> {
    share: F,   // additive share of the value
    mac: F,     // additive share of alpha * value
}
```

Linear operations (add, sub, scalar mul) work on both components. The MAC tracks through all linear operations, enabling verification at open time (not currently enforced in semi-honest mode).

### SpdzPartyID<F>

```rust
struct SpdzPartyID<F: PrimeField> {
    id: usize,           // 0 or 1
    mac_key_share: F,    // this party's share of alpha
}
```

The `NoirUltraHonkProver` trait passes `PartyID` to methods like `add_assign_public` which need to update the MAC component. By encoding `mac_key_share` in the party ID, these methods have access to the MAC key without needing mutable state access.

## Network Communication Pattern

SPDZ is strictly 2-party. Communication uses the `SpdzNetworkExt` trait:

```
Party 0 sends first, then receives  ──►  Avoids deadlocks
Party 1 receives first, then sends  ◄──  Ordering determined by party ID
```

The `exchange` and `exchange_many` methods handle this automatically.

## Preprocessing Separation

The `SpdzPreprocessing` trait cleanly separates the offline and online phases:

```
Offline Phase                          Online Phase
(generate material)                    (use material for computation)
        │                                      │
        ▼                                      ▼
DummyPreprocessing ──implements──►  SpdzPreprocessing trait
   (trusted dealer,                    fn next_triple()
    for testing)                       fn next_shared_random()
                                       fn next_shared_bit()
Future: LowGearPreprocessing ──────►   fn next_input_mask()
   (BGV FHE, production)              fn mac_key_share()
```

The online phase code is identical regardless of preprocessing source.
