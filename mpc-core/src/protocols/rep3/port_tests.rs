//! Characterization tests locking rep3 binary-domain behavior across the
//! BigUint -> F::Uint port. Test bodies are type-agnostic; ONLY the `glue`
//! module below may change when the share representation changes.
//!
//! Every test body interacts with shares only through:
//! - `F` values and plain `BigUint` expectations computed independently,
//! - the stable rep3 module API (`arithmetic::*`, `binary::*`,
//!   `conversion::*`, `detail::*`, `combine_*`), whose function names and
//!   `F`-facing signatures the port is expected to preserve,
//! - the `glue` helpers below, for the handful of spots that unavoidably
//!   construct or inspect the raw share representation directly.
//!
//! Run with: `cargo test -p mpc-core --all-features --lib port_tests`
//!
//! The share type is now `Copy`; the pre-port test bodies (which must stay
//! unchanged) still call `.clone()` on it in a few places.
#![allow(clippy::clone_on_copy)]

use super::*;
use crate::uint::{FieldUint, UintBackend};
use ark_ff::{One, PrimeField, Zero};
use glue::{binary, combine_binary_element};
use mpc_net::Network;
use mpc_net::local::LocalNetwork;
use num_bigint::BigUint;
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

const SEED: u64 = 0xdead_beef;
const SHIFTS: [usize; 4] = [0, 1, 7, 63];

/// The ONLY module the uint-port task may touch. Converts between the test
/// bodies' canonical types (`F`, `BigUint`, `bool`) and the fixed-width
/// `F::Uint`-backed share representation (`Rep3UintShare<F>`). Every spot
/// in this file that directly reads/writes a share's `.a`/`.b` fields, or
/// constructs a "public mask" value in the share's native domain, lives here.
///
/// Since the ported production API speaks `F::Uint` at the public-mask and
/// combine boundaries while the test bodies keep their canonical `BigUint`
/// expectations, this module also provides thin canonical<->native shims for
/// exactly those boundaries (`binary::{and_with_public, xor_public,
/// or_public}` and `combine_binary_element`); the explicit
/// `use glue::{binary, combine_binary_element}` at the top of the file makes
/// the unchanged test bodies resolve to them instead of the glob-imported
/// production items. Everything else in `glue::binary` is a plain re-export
/// of the production module.
mod glue {
    use super::*;

    /// Secret-shares a field element as a binary (rep3 XOR) sharing.
    pub fn share_binary<F: FieldUint, R: Rng + CryptoRng>(
        x: F,
        rng: &mut R,
    ) -> [Rep3UintShare<F>; 3] {
        super::share_binary(x, rng)
    }

    /// Canonical `BigUint` representation of a fixed-width uint.
    pub fn uint_to_biguint<U: UintBackend>(x: &U) -> BigUint {
        let mut bytes = vec![0u8; U::BYTES];
        x.to_le_bytes_into(&mut bytes);
        BigUint::from_bytes_le(&bytes)
    }

    /// Native `F::Uint` representation of a canonical `BigUint` mask value
    /// (must fit the backend width).
    pub fn biguint_to_uint<U: UintBackend>(x: &BigUint) -> U {
        U::from_limbs_truncating(&x.to_u64_digits())
    }

    /// Opens a binary share to its canonical [`BigUint`] value via the network.
    pub fn open_binary<F: FieldUint, N: Network>(share: &Rep3UintShare<F>, net: &N) -> BigUint {
        uint_to_biguint(&super::binary::open(share, net).unwrap())
    }

    /// Canonical `BigUint` representation of a field element.
    pub fn f_to_biguint<F: PrimeField>(x: F) -> BigUint {
        x.into()
    }

    /// Masks an already-XOR-shared value down to a share of just its LSB.
    /// This mirrors the "simulate sharing of just one bit" pattern used
    /// throughout the tests-package harness: `bit_inject` requires that each
    /// party's two additive components are themselves 0/1, not merely that
    /// their XOR is.
    pub fn mask_to_single_bit<F: FieldUint>(mut share: Rep3UintShare<F>) -> Rep3UintShare<F> {
        share.and_mask_assign(&F::Uint::one());
        share
    }

    /// Builds a public bit-mask with the lowest `k` bits set (value `2^k - 1`).
    pub fn low_mask(k: usize) -> BigUint {
        (BigUint::one() << k) - BigUint::one()
    }

    /// Shares a full-width boolean selector (the all-zero or all-ones bit
    /// pattern over `F::MODULUS_BIT_SIZE` bits), as required by `cmux`'s `c`
    /// input. Cannot reuse `share_binary` since the all-ones pattern is
    /// generally not a valid field element.
    pub fn share_bool_mask<F: FieldUint, R: Rng + CryptoRng>(
        bit: bool,
        rng: &mut R,
    ) -> [Rep3UintShare<F>; 3] {
        let mask = F::Uint::mask(F::MODULUS_BIT_SIZE as usize);
        let val = if bit { mask } else { F::Uint::zero() };
        let a = F::Uint::random_bits(rng, F::MODULUS_BIT_SIZE as usize);
        let b = F::Uint::random_bits(rng, F::MODULUS_BIT_SIZE as usize);
        let c = val ^ a ^ b;
        [
            Rep3UintShare::new(a, c),
            Rep3UintShare::new(b, a),
            Rep3UintShare::new(c, b),
        ]
    }

    /// Reconstructs a binary sharing to its canonical `BigUint` value
    /// (shim over the production `combine_binary_element`, which now
    /// returns `F::Uint`).
    pub fn combine_binary_element<F: FieldUint>(
        share1: Rep3UintShare<F>,
        share2: Rep3UintShare<F>,
        share3: Rep3UintShare<F>,
    ) -> BigUint {
        uint_to_biguint(&crate::protocols::rep3::combine_binary_element(
            share1, share2, share3,
        ))
    }

    /// Facade over the production `binary` module for the test bodies: a
    /// plain re-export of everything, with the three public-mask entry
    /// points shadowed by canonical-`BigUint`-taking shims (the production
    /// versions now take `&F::Uint`).
    pub mod binary {
        use super::*;
        pub use crate::protocols::rep3::binary::*;

        /// Shim: canonical `BigUint` mask -> native `F::Uint` mask.
        pub fn and_with_public<F: FieldUint>(
            shared: &Rep3UintShare<F>,
            public: &BigUint,
        ) -> Rep3UintShare<F> {
            crate::protocols::rep3::binary::and_with_public(shared, &biguint_to_uint(public))
        }

        /// Shim: canonical `BigUint` mask -> native `F::Uint` mask.
        pub fn xor_public<F: FieldUint>(
            shared: &Rep3UintShare<F>,
            public: &BigUint,
            id: PartyID,
        ) -> Rep3UintShare<F> {
            crate::protocols::rep3::binary::xor_public(shared, &biguint_to_uint(public), id)
        }

        /// Shim: canonical `BigUint` mask -> native `F::Uint` mask.
        pub fn or_public<F: FieldUint>(
            shared: &Rep3UintShare<F>,
            public: &BigUint,
            id: PartyID,
        ) -> Rep3UintShare<F> {
            crate::protocols::rep3::binary::or_public(shared, &biguint_to_uint(public), id)
        }
    }
}

/// Runs `op` on 3 threads, each with its own [`LocalNetwork`] end, a fresh
/// [`Rep3State`], and one element of `inputs`. Mirrors the thread-spawn +
/// join pattern used throughout `tests/tests/mpc/rep3.rs`, generalized so
/// each test body is a short, sequential-looking closure.
fn run3<In, Out, Op>(inputs: [In; 3], op: Op) -> [Out; 3]
where
    In: Send + 'static,
    Out: Send + 'static,
    Op: Fn(In, &LocalNetwork, &mut Rep3State) -> Out + Clone + Send + 'static,
{
    let nets = LocalNetwork::new_3_parties();
    let handles: Vec<_> = nets
        .into_iter()
        .zip(inputs)
        .map(|(net, input)| {
            let op = op.clone();
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, conversion::A2BType::default()).unwrap();
                op(input, &net, &mut state)
            })
        })
        .collect();
    let mut results = handles.into_iter().map(|h| h.join().unwrap());
    [
        results.next().unwrap(),
        results.next().unwrap(),
        results.next().unwrap(),
    ]
}

fn edge_field_values<F: PrimeField>() -> Vec<F> {
    vec![F::zero(), F::one(), -F::one()]
}

/// Test 1: Arithmetic share -> a2b -> b2a -> combine, roundtrips to the original
/// value. Edges: 0, 1, p-1.
fn case_a2b_b2a_roundtrip<F: FieldUint>() {
    let mut rng = ChaCha12Rng::seed_from_u64(SEED + 1);
    let mut xs: Vec<F> = (0..8).map(|_| F::rand(&mut rng)).collect();
    xs.extend(edge_field_values::<F>());

    for x in xs {
        let shares = share_field_element(x, &mut rng);
        let results = run3(shares, |share, net, state| {
            let bits = conversion::a2b(share, net, state).unwrap();
            conversion::b2a(&bits, net, state).unwrap()
        });
        let combined = combine_field_element(results[0], results[1], results[2]);
        assert_eq!(combined, x, "a2b/b2a roundtrip failed for x={x}");
    }
}

/// Test 2: a2b, opened via the network, matches the plain `BigUint` value of `x`.
/// Edges: 0, p-1.
fn case_a2b_opens_to_value<F: FieldUint>() {
    let mut rng = ChaCha12Rng::seed_from_u64(SEED + 2);
    let mut xs: Vec<F> = (0..8).map(|_| F::rand(&mut rng)).collect();
    xs.push(F::zero());
    xs.push(-F::one());

    for x in xs {
        let shares = share_field_element(x, &mut rng);
        let results = run3(shares, |share, net, state| {
            let bits = conversion::a2b(share, net, state).unwrap();
            glue::open_binary(&bits, net)
        });
        let expected = glue::f_to_biguint(x);
        for r in results {
            assert_eq!(r, expected, "a2b({x}) did not open to expected value");
        }
    }
}

/// Test 3: A binary sharing of `x`, run through b2a, combines back to `x`.
/// Edges: 0, p-1.
fn case_b2a_of_shared_bits<F: FieldUint>() {
    let mut rng = ChaCha12Rng::seed_from_u64(SEED + 3);
    let mut xs: Vec<F> = (0..8).map(|_| F::rand(&mut rng)).collect();
    xs.push(F::zero());
    xs.push(-F::one());

    for x in xs {
        let shares = glue::share_binary(x, &mut rng);
        let results = run3(shares, |share, net, state| {
            conversion::b2a(&share, net, state).unwrap()
        });
        let combined = combine_field_element(results[0], results[1], results[2]);
        assert_eq!(combined, x, "b2a(share_binary({x})) != {x}");
    }
}

/// Test 4: Binary xor/and/or between two shares, and and/xor/or against public
/// masks, all match plain `BigUint` bitwise arithmetic.
fn case_binary_xor_and_public_ops<F: FieldUint>() {
    let mut rng = ChaCha12Rng::seed_from_u64(SEED + 4);
    let bit_len = F::MODULUS_BIT_SIZE as usize;
    let mask_ks = [1usize, 63, bit_len - 1];

    let mut xs: Vec<F> = (0..8).map(|_| F::rand(&mut rng)).collect();
    xs.push(F::zero());
    xs.push(-F::one());

    for x in xs {
        let y = F::rand(&mut rng);
        let bx = glue::f_to_biguint(x);
        let by = glue::f_to_biguint(y);
        let masks: Vec<BigUint> = mask_ks.iter().map(|&k| glue::low_mask(k)).collect();

        let x_shares = glue::share_binary(x, &mut rng);
        let y_shares = glue::share_binary(y, &mut rng);
        let inputs =
            std::array::from_fn(|i| (x_shares[i].clone(), y_shares[i].clone(), masks.clone()));

        let results = run3(inputs, |(xs, ys, masks), net, state| {
            let xor = binary::xor(&xs, &ys);
            let and = binary::and(&xs, &ys, net, state).unwrap();
            let or = binary::or(&xs, &ys, net, state).unwrap();
            let xor_o = glue::open_binary(&xor, net);
            let and_o = glue::open_binary(&and, net);
            let or_o = glue::open_binary(&or, net);

            let mut and_pub = Vec::with_capacity(masks.len());
            let mut xor_pub = Vec::with_capacity(masks.len());
            let mut or_pub = Vec::with_capacity(masks.len());
            for m in &masks {
                let ap = binary::and_with_public(&xs, m);
                let xp = binary::xor_public(&xs, m, state.id);
                let op = binary::or_public(&xs, m, state.id);
                and_pub.push(glue::open_binary(&ap, net));
                xor_pub.push(glue::open_binary(&xp, net));
                or_pub.push(glue::open_binary(&op, net));
            }
            (xor_o, and_o, or_o, and_pub, xor_pub, or_pub)
        });

        for (xor_o, and_o, or_o, and_pub, xor_pub, or_pub) in results {
            assert_eq!(xor_o, &bx ^ &by, "xor({x},{y})");
            assert_eq!(and_o, &bx & &by, "and({x},{y})");
            assert_eq!(or_o, &bx | &by, "or({x},{y})");
            for (i, &k) in mask_ks.iter().enumerate() {
                let m = glue::low_mask(k);
                assert_eq!(and_pub[i], &bx & &m, "and_with_public({x}, mask_{k})");
                assert_eq!(xor_pub[i], &bx ^ &m, "xor_public({x}, mask_{k})");
                assert_eq!(or_pub[i], &bx | &m, "or_public({x}, mask_{k})");
            }
        }
    }
}

/// Test 5: Public left/right shifts of a bounded (< 2^64) shared value match
/// plain `BigUint` shifts, for a handful of shift amounts.
fn case_binary_shifts<F: FieldUint>() {
    let mut rng = ChaCha12Rng::seed_from_u64(SEED + 5);
    let mut vs: Vec<u64> = (0..8).map(|_| rng.r#gen()).collect();
    vs.extend([0u64, 1, u64::MAX]);

    for v in vs {
        let x = F::from(v);
        let bv = BigUint::from(v);
        let shares = glue::share_binary(x, &mut rng);
        let results = run3(shares, |share, net, _state| {
            SHIFTS
                .iter()
                .map(|&s| {
                    let r = binary::shift_r_public(&share, F::from(s as u64));
                    let l = binary::shift_l_public(&share, F::from(s as u64));
                    (glue::open_binary(&r, net), glue::open_binary(&l, net))
                })
                .collect::<Vec<_>>()
        });

        for per_party in results {
            for (i, &s) in SHIFTS.iter().enumerate() {
                let (r_open, l_open) = &per_party[i];
                assert_eq!(*r_open, &bv >> s, "shift_r_public({v}, {s})");
                assert_eq!(*l_open, &bv << s, "shift_l_public({v}, {s})");
            }
        }
    }
}

/// Test 6: `is_zero` opens to 1 exactly for a share of 0, and to 0 for random
/// nonzero shares and for a share of p-1. Exercises the odd-bitlen (bls
/// 12-381, B=255) padding branch of the AND tree just as much as the
/// even-bitlen (bn254, B=254) one.
fn case_is_zero_both_parities<F: FieldUint>() {
    let mut rng = ChaCha12Rng::seed_from_u64(SEED + 6);
    let mut cases: Vec<(F, bool)> = vec![(F::zero(), true)];
    for _ in 0..8 {
        let mut r = F::rand(&mut rng);
        while r.is_zero() {
            r = F::rand(&mut rng);
        }
        cases.push((r, false));
    }
    cases.push((-F::one(), false));

    for (x, expect_zero) in cases {
        let shares = glue::share_binary(x, &mut rng);
        let results = run3(shares, |share, net, state| {
            let bit = binary::is_zero(&share, net, state).unwrap();
            glue::open_binary(&bit, net)
        });
        let expected = if expect_zero {
            BigUint::one()
        } else {
            BigUint::zero()
        };
        for r in results {
            assert_eq!(r, expected, "is_zero({x}), expect_zero={expect_zero}");
        }
    }
}

/// Test 7: `cmux(c, x_t, x_f)` opens to `x_t` when `c` is an all-ones selector,
/// and to `x_f` when `c` is an all-zero selector.
fn case_cmux_selects<F: FieldUint>() {
    let mut rng = ChaCha12Rng::seed_from_u64(SEED + 7);
    let xs: Vec<F> = (0..8).map(|_| F::rand(&mut rng)).collect();

    for x in xs {
        let y = F::rand(&mut rng);
        let x_shares = glue::share_binary(x, &mut rng);
        let y_shares = glue::share_binary(y, &mut rng);

        for &c_bit in &[false, true] {
            let c_shares = glue::share_bool_mask::<F, _>(c_bit, &mut rng);
            let inputs = std::array::from_fn(|i| {
                (
                    c_shares[i].clone(),
                    x_shares[i].clone(),
                    y_shares[i].clone(),
                )
            });
            let results = run3(inputs, |(c, xt, xf), net, state| {
                let res = binary::cmux(&c, &xt, &xf, net, state).unwrap();
                glue::open_binary(&res, net)
            });
            let expected = if c_bit {
                glue::f_to_biguint(x)
            } else {
                glue::f_to_biguint(y)
            };
            for r in results {
                assert_eq!(r, expected, "cmux(c={c_bit}, x={x}, y={y})");
            }
        }
    }
}

/// Test 8: `bit_inject` of a single shared bit (0 or 1) recovers that bit
/// arithmetically. `bit_inject_many` does the same for a batch of 8 random
/// bits.
fn case_bit_inject_bits<F: FieldUint>() {
    let mut rng = ChaCha12Rng::seed_from_u64(SEED + 8);

    for &bit in &[false, true] {
        let bit_f = F::from(bit as u64);
        let shares = glue::share_binary(bit_f, &mut rng).map(glue::mask_to_single_bit);
        let results = run3(shares, |share, net, state| {
            conversion::bit_inject(&share, net, state).unwrap()
        });
        let combined = combine_field_element(results[0], results[1], results[2]);
        assert_eq!(combined, bit_f, "bit_inject({bit})");
    }

    // bit_inject_many over 8 random bits.
    let bits: Vec<bool> = (0..8).map(|_| rng.r#gen()).collect();
    let shares_per_bit: Vec<_> = bits
        .iter()
        .map(|&b| glue::share_binary(F::from(b as u64), &mut rng).map(glue::mask_to_single_bit))
        .collect();
    let inputs: [Vec<_>; 3] =
        std::array::from_fn(|i| shares_per_bit.iter().map(|s| s[i].clone()).collect());
    let results = run3(inputs, |vec, net, state| {
        conversion::bit_inject_many(&vec, net, state).unwrap()
    });
    let combined = combine_field_elements(&results[0], &results[1], &results[2]);
    let expected: Vec<F> = bits.iter().map(|&b| F::from(b as u64)).collect();
    assert_eq!(combined, expected, "bit_inject_many({bits:?})");
}

fn expected_ge(a: BigUint, b: BigUint) -> BigUint {
    if a >= b {
        BigUint::one()
    } else {
        BigUint::zero()
    }
}

/// Test 9: `detail::unsigned_ge` (shared vs shared) and `unsigned_ge_const_lhs`
/// (public vs shared) match plain integer comparison of the canonical
/// `BigUint` values. The `unsigned_ge_const_rhs(x, 0)` edge is covered
/// separately below (see `case_unsigned_ge_const_rhs_zero_edge`), since it
/// is the suspected pre-port bug called out in the task brief.
fn case_unsigned_ge_semantics<F: FieldUint>() {
    let mut rng = ChaCha12Rng::seed_from_u64(SEED + 9);

    // shared >= shared
    let mut pairs: Vec<(F, F)> = (0..8)
        .map(|_| (F::rand(&mut rng), F::rand(&mut rng)))
        .collect();
    pairs.push((F::zero(), F::zero()));
    pairs.push((F::zero(), F::one()));
    pairs.push((F::one(), F::zero()));
    pairs.push((-F::one(), F::zero()));
    pairs.push((F::zero(), -F::one()));
    pairs.push((-F::one(), -F::one()));

    for (a, b) in pairs {
        let a_shares = share_field_element(a, &mut rng);
        let b_shares = share_field_element(b, &mut rng);
        let inputs = std::array::from_fn(|i| (a_shares[i], b_shares[i]));
        let results = run3(inputs, |(a, b), net, state| {
            let bit = detail::unsigned_ge(a, b, net, state).unwrap();
            glue::open_binary(&bit, net)
        });
        let expected = expected_ge(glue::f_to_biguint(a), glue::f_to_biguint(b));
        for r in results {
            assert_eq!(r, expected, "unsigned_ge({a}, {b})");
        }
    }

    // public >= shared (const lhs). Required edge:
    // unsigned_ge_const_lhs(0, y) must equal (0 >= y), i.e. only true for y=0.
    let mut xs: Vec<F> = (0..8).map(|_| F::rand(&mut rng)).collect();
    xs.push(F::zero());
    xs.push(F::one());
    xs.push(-F::one());

    for x in xs {
        for y in [F::zero(), F::one(), -F::one(), F::from(42u64)] {
            let shares = share_field_element(y, &mut rng);
            let results = run3(shares, move |share, net, state| {
                let bit = detail::unsigned_ge_const_lhs(x, share, net, state).unwrap();
                glue::open_binary(&bit, net)
            });
            let expected = expected_ge(glue::f_to_biguint(x), glue::f_to_biguint(y));
            for r in results {
                assert_eq!(r, expected, "unsigned_ge_const_lhs({x}, {y})");
            }
        }
    }

    // shared >= public, for NON-zero public values (the y=0 edge is the
    // dedicated, potentially-#[ignore]'d test below).
    for x in [F::zero(), F::one(), -F::one(), F::from(7u64)] {
        for y in [F::one(), -F::one(), F::from(42u64)] {
            let shares = share_field_element(x, &mut rng);
            let results = run3(shares, move |share, net, state| {
                let bit = detail::unsigned_ge_const_rhs(share, y, net, state).unwrap();
                glue::open_binary(&bit, net)
            });
            let expected = expected_ge(glue::f_to_biguint(x), glue::f_to_biguint(y));
            for r in results {
                assert_eq!(r, expected, "unsigned_ge_const_rhs({x}, {y})");
            }
        }
    }
}

/// Test 9b: Required edge case from the task brief: `unsigned_ge_const_rhs(x, 0)`
/// must be 1 for every `x` (every field element is >= 0). This is split out
/// from `case_unsigned_ge_semantics` so that, if it fails against the
/// current implementation, only this case needs `#[ignore]`, without
/// weakening the rest of the suite's assertions.
///
/// CONFIRMED PRE-EXISTING BUG (both bn254 and bls12-381): `y=0` makes
/// `detail.rs:371`'s `x2_ = (1 << B) - x2` evaluate to exactly `2^B`, a
/// `B+1`-bit value. That extra high bit survives into `p` in
/// `low_depth_binary_sub_by_const` and blows the `bitlen`-bit assumption of
/// the Kogge-Stone adder, tripping `debug_assert!(a.a.bits() <= bitlen as
/// u64)` in `detail::and_twice` (detail.rs:272) rather than silently
/// returning a wrong bit. See the task report for the exact panic output.
fn case_unsigned_ge_const_rhs_zero_edge<F: FieldUint>() {
    let mut rng = ChaCha12Rng::seed_from_u64(SEED + 90);
    let mut xs: Vec<F> = (0..8).map(|_| F::rand(&mut rng)).collect();
    xs.push(F::zero());
    xs.push(F::one());
    xs.push(-F::one());

    for x in xs {
        let shares = share_field_element(x, &mut rng);
        let results = run3(shares, |share, net, state| {
            let bit = detail::unsigned_ge_const_rhs(share, F::zero(), net, state).unwrap();
            glue::open_binary(&bit, net)
        });
        for r in results {
            assert_eq!(r, BigUint::one(), "unsigned_ge_const_rhs({x}, 0) must be 1");
        }
    }
}

/// Test 10: Reconstructing a `share_binary` sharing via `combine_binary_element`
/// (no network involved) matches the canonical `BigUint` of the shared
/// value.
fn case_share_combine_roundtrip<F: FieldUint>() {
    let mut rng = ChaCha12Rng::seed_from_u64(SEED + 10);
    let mut xs: Vec<F> = (0..8).map(|_| F::rand(&mut rng)).collect();
    xs.extend(edge_field_values::<F>());

    for x in xs {
        let [s0, s1, s2] = glue::share_binary(x, &mut rng);
        let combined = combine_binary_element(s0, s1, s2);
        assert_eq!(
            combined,
            glue::f_to_biguint(x),
            "combine_binary_element({x})"
        );
    }
}

/// Test 11: Yao bridge round trips: `a2y2b` opens to the plain value of `x`, and
/// `b2y2a` of a binary sharing of `x` combines back to `x`.
fn case_y2b_b2y_roundtrip<F: FieldUint>() {
    let mut rng = ChaCha12Rng::seed_from_u64(SEED + 11);
    let mut xs: Vec<F> = (0..8).map(|_| F::rand(&mut rng)).collect();
    xs.extend(edge_field_values::<F>());

    for x in xs {
        let shares = share_field_element(x, &mut rng);
        let results = run3(shares, |share, net, state| {
            let bits = conversion::a2y2b(share, net, state).unwrap();
            glue::open_binary(&bits, net)
        });
        let expected = glue::f_to_biguint(x);
        for r in results {
            assert_eq!(r, expected, "a2y2b({x})");
        }

        let bshares = glue::share_binary(x, &mut rng);
        let results2 = run3(bshares, |share, net, state| {
            conversion::b2y2a(&share, net, state).unwrap()
        });
        let combined = combine_field_element(results2[0], results2[1], results2[2]);
        assert_eq!(combined, x, "b2y2a(share_binary({x}))");
    }
}

// Note on test 12 (LUT, `Rep3FieldLookupTable::get_from_public_lut_no_b2a_conversion`):
// SKIPPED. The only call site in the tests package (tests/tests/mpc/rep3.rs
// around line 2649) is embedded in a much larger AES-SBox test that needs
// two independent `LocalNetwork`s, a forked `Rep3State`, and a
// `PublicPrivateLut` built from an S-box table -- reproducing a minimal,
// faithful setup exceeds the ~40-line budget the brief allows for this test.
// The tests package already covers this path end-to-end (Plan C), so
// skipping it here does not leave a coverage gap for the port.

macro_rules! per_field_tests {
    ($mod_name:ident, $field:ty) => {
        mod $mod_name {
            use super::*;

            type F = $field;

            #[test]
            fn a2b_b2a_roundtrip() {
                case_a2b_b2a_roundtrip::<F>();
            }

            #[test]
            fn a2b_opens_to_value() {
                case_a2b_opens_to_value::<F>();
            }

            #[test]
            fn b2a_of_shared_bits() {
                case_b2a_of_shared_bits::<F>();
            }

            #[test]
            fn binary_xor_and_public_ops() {
                case_binary_xor_and_public_ops::<F>();
            }

            #[test]
            fn binary_shifts() {
                case_binary_shifts::<F>();
            }

            #[test]
            fn is_zero_both_parities() {
                case_is_zero_both_parities::<F>();
            }

            #[test]
            fn cmux_selects() {
                case_cmux_selects::<F>();
            }

            #[test]
            fn bit_inject_bits() {
                case_bit_inject_bits::<F>();
            }

            #[test]
            fn unsigned_ge_semantics() {
                case_unsigned_ge_semantics::<F>();
            }

            #[test]
            fn unsigned_ge_const_rhs_zero_edge() {
                case_unsigned_ge_const_rhs_zero_edge::<F>();
            }

            #[test]
            fn share_combine_roundtrip() {
                case_share_combine_roundtrip::<F>();
            }

            #[test]
            fn y2b_b2y_roundtrip() {
                case_y2b_b2y_roundtrip::<F>();
            }
        }
    };
}

per_field_tests!(bn254, ark_bn254::Fr);
per_field_tests!(bls12_381, ark_bls12_381::Fr);
