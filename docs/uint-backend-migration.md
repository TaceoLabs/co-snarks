# Draft: Replacing `BigUint` with a stack-allocated Uint backend in mpc-core

Status: rough draft / investigation result. Not implemented.

## 1. Current state

The binary-domain share type is heap-backed:

```rust
// mpc-core/src/protocols/rep3/binary/types.rs
pub struct Rep3BigUintShare<F: PrimeField> {
    pub a: BigUint,
    pub b: BigUint,
    phantom: PhantomData<F>,
}
```

- ~340 `BigUint` mentions in mpc-core; every a2b/b2a, binary AND/XOR, CMUX,
  is_zero, Kogge–Stone adder and GC bit-collapse allocates `BigUint` temporaries.
- The type carries no width invariant and never self-normalizes.
- `IntRing2k` bridges to the field world via `cast_to_biguint`/`cast_from_biguint`
  (32 call sites in rep3_ring casts/LUTs/yao/sort).
- Wire format is `ark-serialize`'s `BigUint` impl: `to_bytes_le()` as `Vec<u8>` —
  **length-prefixed and value-dependent** (leaks the top-set-bit position of a
  share to a network observer), with a no-op `Valid::check`.
- `rngs.rs` samples randomness as `BigUint::new(vec<u32>) & ((1<<bitlen)-1)`.
- Ironically, `int_ring.rs` already contains two hand-rolled ruint wrappers
  (`U512(Uint<512,8>)`, `U1024(Uint<1024,16>)`, ~330 duplicated lines) — the
  pattern we want, just not generic.

## 2. The width requirement (why `F::BigInt` alone is NOT enough)

Let `B = F::MODULUS_BIT_SIZE`. The binary add/sub-p pipeline transiently needs
**B + 2 bits**:

```
low_depth_binary_add_mod_p (detail.rs:76)
  └─ low_depth_binary_add(bitlen = B)            → B+1 bits   (kogge_stone `g <<= 1`, detail.rs:125 / :70)
  └─ low_depth_sub_p_cmux(bitlen = B + 1)        (detail.rs:84 / :26)
       └─ 2^(B+1) − p constant (detail.rs:297/:311), kogge_stone at B+1 → **B+2 bits**
       └─ reads bit index B+1 via `y >> bitlen` (detail.rs:174 / :140)
```

Every `a2b`/`b2a`(`_many`) hits this path. Consequences per field:

| Field                  | B   | B+2 | `F::BigInt` capacity | fits? |
|------------------------|-----|-----|----------------------|-------|
| BN254 Fr / Fq (=Grumpkin) | 254 | 256 | 256 (4 limbs)        | yes, zero headroom |
| BLS12-377 Fr           | 253 | 255 | 256                  | yes |
| BLS12-381 Fr           | 255 | 257 | 256                  | **no — needs a 5th limb** |
| BLS12-381 Fq           | 381 | 383 | 384 (6 limbs)        | yes |
| BLS12-377 Fq           | 377 | 379 | 384                  | yes |

So the backend width must be chosen **per field with a `>= B + 2` contract**,
not inherited from `F::BigInt`. Const-generic arithmetic (`BigInt<{N+1}>`)
doesn't work on stable, so the mapping is an explicitly implemented
associated type either way. That, plus ruint's much richer API
(`set_bit`, arbitrary widths, wrapping ops, `from_limbs`, serde, the
`ark-ff-05` conversion feature) and the existing U512/U1024 precedent, is why
ruint is the recommended concrete backend over raw `ark_ff::BigInt<N>`.

## 3. Proposed new traits

### 3.1 `UintBackend` — the operation surface (derived from the actual usage catalog)

```rust
// mpc-core/src/protocols/rep3/uint.rs (new module)

/// Fixed-width, stack-allocated unsigned integer backing binary-domain shares
/// and ring/field interchange. All shift/bit ops are mod 2^BITS.
pub trait UintBackend:
    Copy + Clone + Debug + Default + Display
    + Eq + Ord + std::hash::Hash
    + Send + Sync + 'static
    + Not<Output = Self>
    + BitXor<Output = Self> + BitXorAssign
    + BitAnd<Output = Self> + BitAndAssign
    + BitOr<Output = Self>  + BitOrAssign
    + Shl<usize, Output = Self> + ShlAssign<usize>
    + Shr<usize, Output = Self> + ShrAssign<usize>
    + CanonicalSerialize + CanonicalDeserialize   // fixed BYTES on the wire
{
    /// Total capacity in bits (multiple of 64 recommended).
    const BITS: usize;
    const LIMBS: usize;
    const BYTES: usize; // = BITS / 8; fixed wire size

    fn zero() -> Self;
    fn one() -> Self;
    fn is_zero(&self) -> bool;

    /// Position of highest set bit + 1 (0 for zero). Replaces `BigUint::bits()`.
    fn bit_len(&self) -> usize;
    fn bit(&self, i: usize) -> bool;         // conversion.rs bit_inject, sort.rs
    fn set_bit(&mut self, i: usize, v: bool); // is_zero padding, sha256 overflow bit

    /// `(1 << k) - 1` for k <= BITS — the ubiquitous mask idiom
    /// (rngs, is_zero, sub_p, casts, downstream num_bits masks).
    fn mask(k: usize) -> Self;

    /// Wrapping arithmetic mod 2^BITS. Needed for: `2^(B+1) - p` two's-complement
    /// constants (detail.rs, yao/circuits.rs), GC bit accumulation
    /// (`res <<= 1; res += lsb`, yao.rs), and `2^B - x2` (detail.rs:371).
    fn wrapping_add(&self, rhs: &Self) -> Self;
    fn wrapping_sub(&self, rhs: &Self) -> Self;
    fn wrapping_neg(&self) -> Self;

    /// Limb access — replaces `iter_u64_digits`/`to_u64_digits` and makes
    /// ring<->uint<->field casts allocation-free limb copies.
    fn as_limbs(&self) -> &[u64];
    fn from_limbs_truncating(limbs: &[u64]) -> Self;

    fn to_le_bytes_into(&self, out: &mut [u8]);   // out.len() == BYTES
    fn from_le_bytes(bytes: &[u8]) -> Self;

    /// Uniform value with `bitlen` random bits.
    /// Replaces Rep3Rand::random_biguint{,_rng1,_rng2}.
    fn random_bits<R: rand::Rng>(rng: &mut R, bitlen: usize) -> Self;

    fn try_to_usize(&self) -> Option<usize>;  // LUT indexing (lut.rs)
    fn to_u64_truncating(&self) -> u64;       // LSB reads (detail.rs:147,178)
}
```

### 3.2 `FieldUint` — per-field width selection

```rust
/// Associates a prime field with its binary-share backend.
///
/// CONTRACT: `Self::Uint::BITS >= Self::MODULUS_BIT_SIZE + 2`.
/// The +2 headroom is required by the Kogge–Stone carry-out (`g <<= 1`)
/// inside the `bitlen + 1` sub-p CMUX used by every a2b/b2a.
pub trait FieldUint: PrimeField {
    type Uint: UintBackend;

    /// Field -> uint, cheap limb copy via `into_bigint()`.
    fn to_uint(&self) -> Self::Uint;
    /// Uint -> field WITH implicit mod-p reduction (replaces `F::from(biguint)`).
    fn from_uint_reduced(u: &Self::Uint) -> Self;
    /// Uint -> field, caller guarantees `u < p` (debug_assert + `from_bigint`).
    fn from_uint_unchecked(u: &Self::Uint) -> Self;
    /// `F::MODULUS` as uint (replaces `F::MODULUS.into(): BigUint`).
    fn modulus_uint() -> Self::Uint;
}
```

A compile-time width check can be enforced in each impl via a const assert:

```rust
const _: () = assert!(U320::BITS >= 255 + 2); // per impl
```

### 3.3 Concrete backend: generalize the existing ruint wrappers

```rust
/// Generic ruint newtype (orphan rule: we own CanonicalSerialize, num_traits, IntRing2k impls).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RUint<const BITS: usize, const LIMBS: usize>(pub ruint::Uint<BITS, LIMBS>);

pub type U256  = RUint<256, 4>;
pub type U320  = RUint<320, 5>;
pub type U384  = RUint<384, 6>;
pub type U512  = RUint<512, 8>;     // replaces bespoke int_ring.rs::U512
pub type U1024 = RUint<1024, 16>;   // replaces bespoke int_ring.rs::U1024

impl<const BITS: usize, const LIMBS: usize> UintBackend for RUint<BITS, LIMBS> { ... }
impl<const BITS: usize, const LIMBS: usize> IntRing2k   for RUint<BITS, LIMBS> { ... }
```

This deletes ~330 lines of duplicated U512/U1024 code in `int_ring.rs` and
gives every width for free. The `ruint` `ark-ff-05` feature provides
`Uint <-> ark BigInt/Fp` conversions for the `FieldUint` impls.

`FieldUint` impls (all fields the workspace links):

| Field | Uint |
|---|---|
| `ark_bn254::Fr`, `ark_bn254::Fq` (= `ark_grumpkin::Fr`/`Fq`) | `U256` |
| `ark_bls12_377::Fr` | `U256` |
| `ark_bls12_381::Fr` | `U320` |
| `ark_bls12_377::Fq`, `ark_bls12_381::Fq` | `U384` |

(Recommend round 64-bit-multiple widths over exact `Uint<257,5>`: same limb
count, byte-aligned serialization, shareable across fields.)

### 3.4 The share type

```rust
pub struct Rep3UintShare<F: FieldUint> {
    pub a: F::Uint,
    pub b: F::Uint,
    pub(crate) phantom: PhantomData<F>,
}

#[deprecated = "renamed to Rep3UintShare"]
pub type Rep3BigUintShare<F> = Rep3UintShare<F>;
```

Operator impls in `binary/ops.rs` migrate 1:1 (`Share ^ &F::Uint`,
`Share & &F::Uint`, `Shl/Shr<usize>`, and the local-AND
`(a&a')^(a&b')^(b&a') -> F::Uint`).

### 3.5 `IntRing2k` bridge replacement

```rust
// on IntRing2k — replaces cast_to_biguint / cast_from_biguint (32 call sites)
fn cast_to_uint<U: UintBackend>(&self) -> U;        // limb copy, zero-extend
fn cast_from_uint<U: UintBackend>(u: &U) -> Self;   // limb copy, truncate
```

Same truncating semantics as today, no heap round-trip.

## 4. Problem sites

### 4.1 Capacity / overflow semantics (correctness-relevant)

1. **B+2 pipeline** (`detail.rs:70,125` + `:26,84` + `:297,311`): covered by the
   width contract, but BN254 sits at exactly zero headroom in U256. Add
   `debug_assert!(bitlen + 1 <= F::Uint::BITS)` at the `kogge_stone_inner`
   entry points to make the contract observable.
2. **`shift_l_public`** (`binary.rs:152-160`): today the `BigUint` grows
   unboundedly (doc comment claims a panic that does not exist; a shift of 1000
   yields a 1254-bit share). Fixed width would silently truncate instead —
   a behavior change either way. Recommendation: panic when
   `shift >= F::MODULUS_BIT_SIZE`, matching `arithmetic::pow_2_public`
   (`arithmetic.rs:732-737`). The current post-b2a behavior for oversized
   shifts is arguably already broken (b2a randomizes at only B bits).
3. **`is_zero`/`is_zero_many` odd-B padding** (`binary.rs:306-313, 342-350`):
   `set_bit(len-1)` reaches bit index B when B is odd (BLS12-381 Fr, B=255),
   while the AND randomness is masked at only B bits (`binary.rs:96,115`) and
   `binary::and` debug_asserts `bits() <= B` (`binary.rs:91`). Pre-existing
   inconsistency that typed widths will surface; fix during migration
   (randomize/mask at the padded width).
4. **`low_depth_binary_sub_by_const`** (`detail.rs:371`): `2^B - x2` equals
   exactly `2^B` (bit B set) when the public operand is zero, feeding a
   `bitlen = B` Kogge–Stone. Pre-existing edge case for
   `unsigned_ge_const_rhs`; audit while porting.
5. **Wire format change**: length-prefixed variable bytes -> flat
   `F::Uint::BYTES`. Breaking protocol change (coordinated upgrade, as usual);
   as a bonus it removes the value-dependent message-length side channel and
   the per-send `serialized_size` -> `to_bytes_le()` allocation in
   `network.rs` `send_both_many`/`send_many`.
6. **Correlated RNG change**: `random_biguint` samples u32 limbs;
   `F::Uint::random_bits` will consume the RNG stream differently. All parties
   must run the same version — already a requirement, but worth stating.

### 4.2 mpc-core API churn (mechanical, but wide)

- `binary/ops.rs`: all mixed `BigUint` operator impls -> `F::Uint`.
- `binary.rs`: `xor_public`, `or_public`, `and_with_public`,
  `promote_to_trivial_share` take `&F::Uint`; `open` returns `F::Uint`.
- `arithmetic.rs`: `open_bit` returns `F::Uint`; `pow_public`/`pow_2_public`
  exponent handling via `to_uint()` + `bit()`.
- `conversion.rs`: all a2b/b2a/bit_inject/y2b signatures switch share type;
  the `(x.a + x.b).into()` and `.into(): F` sites become
  `to_uint()` / `from_uint_reduced()`.
- `rngs.rs`: `random_biguint{,_rng1,_rng2}` -> `random_uint<F::Uint>(bitlen)`.
- `yao.rs`: `biguint_to_bits{,_as_u16}` (limb iteration), GC bit collapse
  (`res <<= 1; res += lsb` -> wrapping ops), range check
  `res >= F::MODULUS.into()` -> `cmp(modulus_uint())`.
- `lut.rs`: `usize::try_from(BigUint)` -> `try_to_usize()`.
- `rep3_ring/{casts,lut_field,lut_curve,yao,gadgets/*}.rs`: 32
  `cast_{to,from}_biguint` sites -> `cast_{to,from}_uint`.
- `rep3.rs`: `share_biguint`, `combine_binary_element(s)` -> `F::Uint`.
- `gadgets/mod.rs` `field_from_hex_string`: can stay on `BigUint` (public
  parsing) or use ruint's `from_str_radix`.

### 4.3 Downstream churn

Good news (verified): **no downstream trait** (`VmCircomWitnessExtension`,
`NoirWitnessExtensionProtocol`, `BrilligDriver`, `NoirUltraHonkProver`)
exposes `BigUint` or the share type in associated types or signatures. The
swap is confined to rep3 impl bodies. Sites:

- **Trait-bound propagation**: `F: PrimeField` -> `F: FieldUint` in
  `circom-mpc-vm/src/mpc/{rep3,batched_rep3}.rs`,
  `co-acvm/src/mpc/rep3.rs`, `co-brillig/src/mpc/rep3.rs`,
  `co-noir-common/src/mpc/rep3.rs`, and the `paste!` test macros.
- **Cross-field share re-labelling** (`co-acvm/src/mpc/rep3.rs:91-125, 2389`):
  `Rep3UintShare::<grumpkin::Fr>::new(x.a, x.b)` from a bn254-Fr share requires
  both fields to select the *same* `Uint` type. They do (both U256), but the
  type system only proves it at the concrete call site — keep the widths table
  aligned for curve/scalar-field pairs.
- **Raw bit surgery** (`co-acvm/src/mpc/rep3.rs:1716-1721` sha256 overflow bit;
  `:2188-2205` AES GF(2^8) s-box on shares;
  `co-noir-common/src/mpc/rep3.rs:349-359` 136-bit mask/shift/re-wrap): all
  expressible with `bit`/`set_bit`/`mask`/shifts — mechanical.
- **`Bit::cast_from_biguint(&x.a)` x8** in `co-brillig/src/mpc/rep3.rs` ->
  `cast_from_uint`.
- **Downstream mask idioms** (`(BigUint::one() << num_bits) - 1` in
  `co-acvm/src/mpc/rep3.rs:1034,1043,...`) -> `F::Uint::mask(num_bits)`.
- **Bit-extraction loops** (`circom-mpc-vm/src/mpc/rep3.rs:610,644`,
  `batched_rep3.rs:405`) -> `(share >> i) & one` or a dedicated
  `extract_bit(i)` helper on the share.
- **tests/**: `share_biguint` / `combine_binary_element(s)` callers,
  plus direct `.a &= BigUint::one()` mutations.

### 4.4 Deferred out of Plan C (public-value math)

Public-value arbitrary-precision math that never lives inside a share:

- co-acvm **plain** bigfield limb arithmetic (4x68-bit unreduced limbs,
  ~544-bit products in `madd_div_mod`, `modpow` inverse) — the rep3 shared
  paths currently `bail!("not implemented")`, so no share ever carries these.
  If the shared case is ever implemented it needs a wider share than
  `F::Uint`; the `FieldUint` design doesn't preclude adding a second, wider
  associated type later.
- `Utils::get_base_powers` / `slice_u256` / ultra_builder u256 masks
  (mod 2^256 on public values) — natural later candidates for plain
  `ruint::U256`, but orthogonal.
- `to_radix` div/mod in co-brillig plain, co-circom-types input parsing
  (`% modulus`), test-only `BigUint` division in `yao/circuits.rs:4540`.

The second and third bullets landed as Plan D (§8); the first is what remains.

## 5. Expected wins

- a2b/b2a/binary-AND hot paths lose dozens of heap allocations per element
  (every XOR/AND/shift on `BigUint` allocates; Kogge–Stone does ~log B rounds
  of them). `Copy` shares also remove most `.clone()` traffic.
- Fixed-size network messages; `serialized_size` becomes a constant instead of
  an allocation; BN254 share halves on the wire (2x(32+8) -> 2x32 bytes).
- Value-independent message sizes (side-channel fix).
- ~330 lines of U512/U1024 duplication deleted.

Benchmark a2b/b2a-heavy circuits A/B against main before landing.

## 6. Suggested phasing (each step compiles + tests green)

1. `RUint<BITS, LIMBS>` + `UintBackend` + generic `IntRing2k` impl; replace
   bespoke U512/U1024; unit tests for width contract, serialization, casts.
2. `FieldUint` impls for bn254/grumpkin/bls12-377/bls12-381 Fr+Fq with
   const width asserts.
3. Port mpc-core rep3 internals (types/ops, rngs, detail, binary, conversion,
   yao, lut, rep3_ring casts+LUTs+sort). Keep deprecated alias.
4. Port downstream drivers (circom-mpc-vm, co-acvm, co-brillig,
   co-noir-common) and tests.
5. Remove `BigUint` from mpc-core public API; `num-bigint` remains only in
   plain-driver public-value math (possible follow-up: ruint there too).

## 6b. Foundation status (2026-07-29)

Phases 1–2 landed on `dk/uint_backend` (commits `dc136b26..90086b5d`): `RUint`,
`UintBackend`, generic `IntRing2k` (bespoke U512/U1024 deleted), `FieldUint`
impls for bn254/bls12-377/bls12-381 Fr+Fq with compile-time width asserts.
`just check-pr` green. Notes for Plan B (from the final review):

- Decide before porting: make `num_traits::{WrappingAdd, WrappingSub,
  WrappingNeg}` supertraits of `UintBackend` instead of duplicate methods —
  the current duplication forces fully-qualified `wrapping_*` calls wherever
  both traits are in scope, and Plan B multiplies those call sites.
- Consider adding `From<u64> + From<bool>` bounds to `UintBackend` for
  constant-building ergonomics in generic code (RUint already implements both).
- Add a `LIMBS * 64 >= BigInt-width` const assert to the `impl_field_uint!`
  macro if a field with a padded `BigInt` is ever added.
- When adding the `kogge_stone_inner` entry asserts, consider a release-mode
  `assert!` in `mask()` (bn254 runs at zero headroom; `mask(k > BITS)`
  silently returns zero in release).
- `from_uint_unchecked` release builds silently truncate limbs beyond the
  field's `BigInt` width — hot-path callers must guarantee `< p`.

### Phase 3 (rep3 port) status (2026-07-29)

Landed on `dk/uint_backend` commits `893a16e2..2d3fbf1f`: Phase 3 completed rep3 binary-domain migration from `Rep3BigUintShare<F: PrimeField>` to `Rep3UintShare<F: FieldUint>`, fully porting rep3 and rep3_ring. Old type deleted.

**Semantic changes implemented:**

- `shift_l_public`: now panics when `shift >= F::MODULUS_BIT_SIZE` (matching `pow_2_public` semantics; prevents silent underuse of shared data).
- `binary::and` randomness: widened to full `F::Uint` width (was `B` bits, now all bits of padded width; fixes odd-B leakage in BLS12-381 Fr where `is_zero` set bit index B=255).
- `unsigned_ge_const_rhs(x, 0)` pre-existing panic: **fixed** (low_depth_binary_sub_by_const edge case where `2^B - 0 = 2^B`, feeding bitlen=B Kogge-Stone; now correctly handled).
- Wire-format break: binary shares serialize as fixed LIMBS*8 LE bytes (was variable-length BigUint) — all parties must run the same version; also removes the value-dependent message-length side channel.

**Characterization suite:** `mpc-core/src/protocols/rep3/port_tests.rs` — 24 tests, glue-isolated (generic over curve, not downstream types); all pass (`cargo test -p mpc-core --all-features --lib` → 92 passed).

**Lint gate:** fmt, clippy (-D warnings), rustdoc (-D warnings) all green.

**Workspace status:** mpc-core is sealed and green; downstream workspace red until Plan C (downstream crates require `F: FieldUint` trait bound propagation + API migrations). Per-crate red surface (cargo check --all-features):

| Crate               | Error count | Dominant signatures                                                          |
| ------------------- | ----------- | ---------------------------------------------------------------------------- |
| circom-mpc-vm       | 113         | F: FieldUint not satisfied (batched_rep3.rs, rep3.rs)                      |
| co-acvm             | 88          | F: FieldUint not satisfied; unresolved Rep3BigUintShare import             |
| co-brillig          | 75          | F: FieldUint not satisfied (rep3.rs)                                       |
| co-noir-common      | 13          | F: FieldUint not satisfied (ScalarField, BaseField bounds)                 |
| **Total workspace** | **201**     | 192 E0277 (FieldUint), 5 E0369 (ops), 1 E0432 (import)                   |

**Plan C scope:** Integrate downstream crate migrations (trait bounds, API rewiring); delete `IntRing2k::cast_{to,from}_biguint` and inline u64-limb copies; `num-bigint` remains for public-value arbitrary-precision (bigfield limbs, padding, radix conversions).

## 7. Open questions

- Oversized public shift: panic (recommended, matches `pow_2_public`) or mask?
- Round widths (U320) vs exact widths (`Uint<257,5>`)? Draft assumes round.
- Keep the deprecated `Rep3BigUintShare` alias for one release, or rename hard?
- Do we want `FieldUint` as a supertrait bound everywhere, or a blanket-ish
  sealed helper trait to reduce bound noise in downstream signatures?

## 8. Plan D — public-value math (2026-08-13)

Ports the §4.4 sites whose width is statically known onto `U256`, taking the
workspace from 446 `BigUint` mentions to 207. Everything ported was
public-value math on values that are 256-bit quantities by construction.

### 8.1 New surface: `mpc_core::uint`

```rust
pub fn field_to_u256<F: PrimeField>(value: &F) -> U256;
pub fn u256_to_field<F: PrimeField>(value: &U256) -> F;   // reduces mod p
pub fn modulus_u256<F: PrimeField>() -> U256;
```

These pin the width instead of deriving it from the field, for code that is
generic over `F: PrimeField` only. `FieldUint` would be the exact choice, but
co-builder alone has 196 `PrimeField` bounds and propagating `FieldUint`
through them is out of proportion to the win — and co-noir only ever
instantiates bn254/grumpkin `Fr`/`Fq` (254 bits). A `debug_assert` on
`MODULUS_BIT_SIZE <= 256` makes the assumption observable. Where a
`FieldUint` bound already existed (co-acvm rep3/shamir, co-brillig rep3) the
port uses `F::Uint` + `to_uint()`/`from_uint_*()` instead.

### 8.2 Ported

| Crate | Sites |
|---|---|
| co-noir-common | `Utils::{get_base_powers, map_into_sparse_form, map_from_sparse_form, slice_u256}` now `U256`; `honk_curve` fq↔2×fr limb split; `transcript::split_challenge`; `sponge_hasher` IV; `verification_key::from_buffer` |
| noir-types | `read_field_element` reads big-endian bytes directly; dead `read_biguint` deleted; **`num-bigint` dependency dropped** |
| co-acvm | plain: decompose/sort/slice/bitwise masks, grumpkin scalar recombination, sha256, NAF. rep3: base powers, LUT indices, `right_shift`, sha256. shamir: sort + bitwise masks |
| co-brillig | plain `int_div`/`to_radix`; rep3 power-of-two divisor test |
| co-builder | `field_ct` (pow, range checks, `split_unique`, `validate_split_in_field`, `CycleScalarCT`, byte arrays), `ultra_builder` (poseidon2 constants, range-constraint sublimbs, logic gates, nnf limbs), `rom_ram`, `plookup`, `aes128`, `sha_compression`, `poseidon2`, `generators`, `types`, `transcript_ct`, `plain_proving_key`, `oink_recursive_verifier`, biggroup powers of two |
| ultrahonk / co-ultrahonk / co-builder | `poseidon2_internal` + `non_native_field` relation constants |

Wrap-around safety: `map_into_sparse_form`'s accumulation and
`map_from_sparse_form`'s thresholds top out at 154 bits for the `BASE` values
in use (9, 16, 28), so replacing `BigUint`'s growth with `U256`'s mod-2^256
wrapping is not observable. The explicit `& ((1 << 256) - 1)` masks in
`get_base_powers` and the ultra_builder shifts are now implicit in `U256`.

### 8.3 Behaviour changes (all fix latent panics/bugs)

1. **`field_ct.rs` `byte_array` public decomposition**: was
   `value.to_bytes_be()` + `resize(num_bytes, 0)`. `to_bytes_be()` drops
   leading zeros, and `resize` pads at the *end*, i.e. the least-significant
   position of a big-endian buffer — so any value with fewer than `num_bytes`
   significant bytes was decomposed as `value << 8k` and failed the
   `assert_equal(&reconstructed)` that follows (~1/256 of random 32-byte
   inputs). Now a shift/mask over the `num_bytes` window, matching the shared
   branch's `decompose_arithmetic(..).rev()` ordering.
2. **`verification_key::from_buffer`**: `to_u64_digits()[0]` panics on zero
   (num-bigint stores no limbs for zero), so a VK with `num_public_inputs == 0`
   or `pub_inputs_offset == 0` could not be deserialized. Now
   `to_u64_truncating()`, which yields 0.
3. **`oink_recursive_verifier`**: same `to_u64_digits().first()` pattern,
   replaced with `try_to_usize()`.

### 8.4 Still on `BigUint` (207 mentions), and why

- **bigfield/biggroup emulation** — `big_field.rs` (151), `big_group*.rs` (18),
  co-acvm plain's bigfield block (12), `Utils::{field_limbs_to_biguint,
  biguint_to_field_limbs}` (8). `NUM_LIMBS * LIMB_SIZE` is 4×68 = 272 bits and
  `madd_div_mod` products reach ~544, so this needs `U512`/`U1024` and a
  per-expression bound analysis (ruint's `+`/`-`/`*` wrap silently). The
  `slice_u256` boundary into `big_field.rs` converts explicitly.
- **arbitrary-length hex parsing** — `gadgets::field_from_hex_string`,
  co-circom-types and tests' `parse_field`. These accept user input of
  unbounded length and deliberately reduce over-modulus values, so the width is
  genuinely not known.
- **the `uint` module's own bridges** — `RUint`'s `From`/`TryFrom<BigUint>`
  impls and their tests.
