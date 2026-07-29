use super::PartyID;
use super::Rep3State;
use super::arithmetic;
use super::arithmetic::BinaryShare;
use super::conversion;
use crate::protocols::rep3::network::Rep3NetworkExt;
use crate::protocols::rep3::{Rep3BigUintShare, Rep3PrimeFieldShare, Rep3UintShare};
use crate::uint::{FieldUint, UintBackend};
use ark_ec::CurveGroup;
use ark_ff::One;
use ark_ff::PrimeField;
use ark_ff::Zero;
use itertools::Itertools as _;
use itertools::izip;
use mpc_net::Network;
use num_bigint::BigUint;
use num_traits::WrappingSub;
use std::any::TypeId;

// ---------------------------------------------------------------------
// Task-3 bridge: the crate-wide API below this point is generic over
// `F: PrimeField` and MUST stay that way -- it is called directly (with
// only `F: PrimeField` in scope) from `conversion.rs`, `arithmetic.rs`, and
// from the `port_tests` characterization suite, which the uint-port task is
// not allowed to touch beyond un-ignoring two tests. Tightening any of
// these signatures to `F: FieldUint` would make those callers fail to
// compile (a bound can never be "proven" for a generic caller from a
// stronger bound the callee happens to require).
//
// Not every `PrimeField` implements `FieldUint` (only the six concrete
// fields actually used anywhere in this workspace do, see
// `uint::field_uint`), so bridging from the generic entry points to the
// fixed-width native kernels has to happen at runtime: check the concrete
// `TypeId` of `F` and downcast to it. This mirrors the existing
// `TypeId`/`crate::downcast` dispatch already used by `point_from_xy` below.
macro_rules! dispatch_field_uint {
    ($f:ty, $body:block) => {{
        if TypeId::of::<$f>() == TypeId::of::<ark_bn254::Fr>() {
            type CF = ark_bn254::Fr;
            $body
        } else if TypeId::of::<$f>() == TypeId::of::<ark_bn254::Fq>() {
            type CF = ark_bn254::Fq;
            $body
        } else if TypeId::of::<$f>() == TypeId::of::<ark_bls12_377::Fr>() {
            type CF = ark_bls12_377::Fr;
            $body
        } else if TypeId::of::<$f>() == TypeId::of::<ark_bls12_377::Fq>() {
            type CF = ark_bls12_377::Fq;
            $body
        } else if TypeId::of::<$f>() == TypeId::of::<ark_bls12_381::Fr>() {
            type CF = ark_bls12_381::Fr;
            $body
        } else if TypeId::of::<$f>() == TypeId::of::<ark_bls12_381::Fq>() {
            type CF = ark_bls12_381::Fq;
            $body
        } else {
            panic!("Unsupported field {}", std::any::type_name::<$f>());
        }
    }};
}

// TEMPORARY Task-3 wrapper, removed in Task 4: converts a `BigUint`-backed
// share to the fixed-width native representation.
fn to_uint_share<F: FieldUint>(x: &Rep3BigUintShare<F>) -> Rep3UintShare<F> {
    Rep3UintShare::new(
        F::Uint::from_limbs_truncating(&x.a.to_u64_digits()),
        F::Uint::from_limbs_truncating(&x.b.to_u64_digits()),
    )
}

// TEMPORARY Task-3 wrapper, removed in Task 4: converts a fixed-width
// native share back to the `BigUint`-backed representation.
fn to_biguint_share<F: FieldUint>(x: &Rep3UintShare<F>) -> Rep3BigUintShare<F> {
    let mut bytes = vec![0u8; F::Uint::BYTES];
    x.a.to_le_bytes_into(&mut bytes);
    let a = BigUint::from_bytes_le(&bytes);
    x.b.to_le_bytes_into(&mut bytes);
    Rep3BigUintShare::new(a, BigUint::from_bytes_le(&bytes))
}

/// Constructs a trivial (publicly-known) [`Rep3UintShare`] of `public_value`,
/// mirroring [`super::binary::promote_to_trivial_share`].
fn promote_to_trivial_uint_share<F: FieldUint>(
    id: PartyID,
    public_value: F::Uint,
) -> Rep3UintShare<F> {
    match id {
        PartyID::ID0 => Rep3UintShare::new(public_value, F::Uint::zero()),
        PartyID::ID1 => Rep3UintShare::new(F::Uint::zero(), public_value),
        PartyID::ID2 => Rep3UintShare::zero_share(),
    }
}

/// Local re-implementation of [`super::binary::and`] for [`Rep3UintShare`].
/// Needed because `binary.rs` itself is not ported until Task 4; kept
/// private and scoped to this file's native kernels only.
fn and_uint<F: FieldUint, N: Network>(
    a: &Rep3UintShare<F>,
    b: &Rep3UintShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3UintShare<F>> {
    let bitlen = F::MODULUS_BIT_SIZE as usize;
    debug_assert!(a.a.bit_len() <= bitlen);
    debug_assert!(b.a.bit_len() <= bitlen);
    let (mut mask, mask_b) = state.rngs.rand.random_uint::<F::Uint>(bitlen);
    mask ^= mask_b;
    let local_a = (*a & *b) ^ mask;
    let local_b = net.reshare(local_a)?;
    Ok(Rep3UintShare::new(local_a, local_b))
}

/// Local re-implementation of [`super::binary::and_vec`] for [`Rep3UintShare`].
/// See [`and_uint`] for why this exists instead of calling into `binary.rs`.
fn and_vec_uint<F: FieldUint, N: Network>(
    a: &[Rep3UintShare<F>],
    b: &[Rep3UintShare<F>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3UintShare<F>>> {
    let bitlen = F::MODULUS_BIT_SIZE as usize;
    let local_a = izip!(a, b)
        .map(|(a, b)| {
            let (mut mask, mask_b) = state.rngs.rand.random_uint::<F::Uint>(bitlen);
            mask ^= mask_b;
            (*a & *b) ^ mask
        })
        .collect_vec();
    let local_b = net.reshare(local_a.clone())?;
    Ok(izip!(local_a, local_b)
        .map(|(a, b)| Rep3UintShare::new(a, b))
        .collect_vec())
}

/// Local re-implementation of [`super::binary::cmux`] for [`Rep3UintShare`].
/// See [`and_uint`] for why this exists instead of calling into `binary.rs`.
fn cmux_uint<F: FieldUint, N: Network>(
    c: &Rep3UintShare<F>,
    x_t: &Rep3UintShare<F>,
    x_f: &Rep3UintShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3UintShare<F>> {
    let xor = *x_f ^ *x_t;
    let mut and = and_uint(c, &xor, net, state)?;
    and ^= *x_f;
    Ok(and)
}

/// Local re-implementation of [`super::binary::cmux_many`] for [`Rep3UintShare`].
/// See [`and_uint`] for why this exists instead of calling into `binary.rs`.
fn cmux_many_uint<F: FieldUint, N: Network>(
    c: &[Rep3UintShare<F>],
    x_t: &[Rep3UintShare<F>],
    x_f: &[Rep3UintShare<F>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3UintShare<F>>> {
    assert_eq!(c.len(), x_t.len());
    assert_eq!(c.len(), x_f.len());
    let xor = izip!(x_f, x_t).map(|(x_f, x_t)| *x_f ^ *x_t).collect_vec();
    let mut and = and_vec_uint(c, &xor, net, state)?;
    for (and, x_f) in izip!(and.iter_mut(), x_f) {
        *and ^= *x_f;
    }
    Ok(and)
}

// TEMPORARY Task-3 wrapper, removed in Task 4
pub(super) fn low_depth_binary_add_mod_p_many<F: PrimeField, N: Network>(
    x1: &[BinaryShare<F>],
    x2: &[BinaryShare<F>],
    net: &N,
    state: &mut Rep3State,
    bitlen: usize,
) -> eyre::Result<Vec<Rep3BigUintShare<F>>> {
    dispatch_field_uint!(F, {
        let x1: Vec<Rep3UintShare<CF>> = x1
            .iter()
            .map(|x| to_uint_share::<CF>(crate::downcast(x).expect("checked type")))
            .collect();
        let x2: Vec<Rep3UintShare<CF>> = x2
            .iter()
            .map(|x| to_uint_share::<CF>(crate::downcast(x).expect("checked type")))
            .collect();
        let res = low_depth_binary_add_mod_p_uint_many::<CF, N>(&x1, &x2, net, state, bitlen)?;
        let res: Vec<Rep3BigUintShare<F>> = res
            .iter()
            .map(|r| {
                let r = to_biguint_share(r);
                crate::downcast::<Rep3BigUintShare<CF>, Rep3BigUintShare<F>>(&r)
                    .expect("checked type")
                    .clone()
            })
            .collect();
        Ok(res)
    })
}

fn low_depth_binary_add_uint_many<F: FieldUint, N: Network>(
    x1: &[Rep3UintShare<F>],
    x2: &[Rep3UintShare<F>],
    net: &N,
    state: &mut Rep3State,
    bitlen: usize,
) -> eyre::Result<Vec<Rep3UintShare<F>>> {
    // Add x1 + x2 via a packed Kogge-Stone adder
    let mut p = izip!(x1, x2).map(|(x1, x2)| *x1 ^ *x2).collect_vec();
    let mut g = and_vec_uint(x1, x2, net, state)?;
    kogge_stone_inner_uint_many(&mut p, &mut g, net, state, bitlen)?;
    Ok(g)
}

fn kogge_stone_inner_uint_many<F: FieldUint, N: Network>(
    p: &mut [Rep3UintShare<F>],
    g: &mut [Rep3UintShare<F>],
    net: &N,
    state: &mut Rep3State,
    bitlen: usize,
) -> eyre::Result<()> {
    debug_assert!(bitlen < F::Uint::BITS);
    let d = ceil_log2(bitlen);
    let s_ = p.to_owned();
    for i in 0..d {
        // The loop looks slightly different to the one for rep3 rings to have the and gates at the LSBs of the storage
        let shift = 1 << i;
        let mask = F::Uint::mask(bitlen - shift);
        let len = p.len();
        let p_ = p.iter().map(|p| p.and_mask(&mask));
        let g_ = g.iter().map(|g| g.and_mask(&mask));
        let p_shift = p.iter().map(|p| *p >> shift);

        let (r1, r2) = and_twice_uint_many_iter(p_shift, g_, p_, net, state, bitlen - shift, len)?;
        for (p, r2) in izip!(p.iter_mut(), r2.into_iter()) {
            *p = r2 << shift;
        }
        for (g, r1) in izip!(g.iter_mut(), r1.into_iter()) {
            *g ^= r1 << shift;
        }
    }
    for (g, s_) in izip!(g.iter_mut(), s_) {
        *g <<= 1;
        *g ^= s_;
    }
    Ok(())
}

// TEMPORARY Task-3 wrapper, removed in Task 4
pub(super) fn low_depth_binary_add_mod_p<F: PrimeField, N: Network>(
    x1: &Rep3BigUintShare<F>,
    x2: &Rep3BigUintShare<F>,
    net: &N,
    state: &mut Rep3State,
    bitlen: usize,
) -> eyre::Result<Rep3BigUintShare<F>> {
    dispatch_field_uint!(F, {
        let x1: &Rep3BigUintShare<CF> = crate::downcast(x1).expect("checked type");
        let x2: &Rep3BigUintShare<CF> = crate::downcast(x2).expect("checked type");
        let x1 = to_uint_share(x1);
        let x2 = to_uint_share(x2);
        let res = low_depth_binary_add_mod_p_uint::<CF, N>(&x1, &x2, net, state, bitlen)?;
        let res = to_biguint_share(&res);
        Ok(
            crate::downcast::<Rep3BigUintShare<CF>, Rep3BigUintShare<F>>(&res)
                .expect("checked type")
                .clone(),
        )
    })
}

fn low_depth_binary_add_mod_p_uint<F: FieldUint, N: Network>(
    x1: &Rep3UintShare<F>,
    x2: &Rep3UintShare<F>,
    net: &N,
    state: &mut Rep3State,
    bitlen: usize,
) -> eyre::Result<Rep3UintShare<F>> {
    let x = low_depth_binary_add_uint(x1, x2, net, state, bitlen)?;
    low_depth_sub_p_cmux_uint::<F, N>(&x, net, state, bitlen + 1)
}

fn low_depth_binary_add_mod_p_uint_many<F: FieldUint, N: Network>(
    x1: &[Rep3UintShare<F>],
    x2: &[Rep3UintShare<F>],
    net: &N,
    state: &mut Rep3State,
    bitlen: usize,
) -> eyre::Result<Vec<Rep3UintShare<F>>> {
    let x = low_depth_binary_add_uint_many(x1, x2, net, state, bitlen)?;
    low_depth_sub_p_cmux_uint_many::<F, N>(&x, net, state, bitlen + 1)
}

fn low_depth_binary_add_uint<F: FieldUint, N: Network>(
    x1: &Rep3UintShare<F>,
    x2: &Rep3UintShare<F>,
    net: &N,
    state: &mut Rep3State,
    bitlen: usize,
) -> eyre::Result<Rep3UintShare<F>> {
    // Add x1 + x2 via a packed Kogge-Stone adder
    let p = *x1 ^ *x2;
    let g = and_uint(x1, x2, net, state)?;
    kogge_stone_inner_uint(&p, &g, net, state, bitlen)
}

fn kogge_stone_inner_uint<F: FieldUint, N: Network>(
    p: &Rep3UintShare<F>,
    g: &Rep3UintShare<F>,
    net: &N,
    state: &mut Rep3State,
    bitlen: usize,
) -> eyre::Result<Rep3UintShare<F>> {
    debug_assert!(bitlen < F::Uint::BITS);
    let d = ceil_log2(bitlen);
    let s_ = *p;
    let mut p = s_;
    let mut g = *g;
    for i in 0..d {
        // The loop looks slightly different to the one for rep3 rings to have the and gates at the LSBs of the storage
        let shift = 1 << i;
        let mask = F::Uint::mask(bitlen - shift);
        let p_ = p.and_mask(&mask);
        let g_ = g.and_mask(&mask);
        let p_shift = p >> shift;

        // TODO: Make and more communication efficient, ATM we send the full element for each level, even though they reduce in size
        // maybe just input the mask into AND?
        let (r1, r2) = and_twice_uint(&p_shift, &g_, &p_, net, state, bitlen - shift)?;
        p = r2 << shift;
        g ^= r1 << shift;
    }
    g <<= 1;
    g ^= s_;
    Ok(g)
}

fn low_depth_sub_p_cmux_uint_many<F: FieldUint, N: Network>(
    x: &[Rep3UintShare<F>],
    net: &N,
    state: &mut Rep3State,
    bitlen: usize,
) -> eyre::Result<Vec<Rep3UintShare<F>>> {
    let original_bitlen = bitlen - 1; // before the potential overflow after an addition
    let mask = F::Uint::mask(original_bitlen);
    let mut y = low_depth_binary_sub_p_uint_many::<F, N>(x, net, state, bitlen)?;
    let x = x.iter().map(|x| x.and_mask(&mask)).collect_vec();
    let y_msb = y.iter().map(|y| *y >> bitlen).collect_vec();
    for y in y.iter_mut() {
        y.and_mask_assign(&mask);
    }
    // Spread the ov share to the whole uint
    let mut ov = Vec::with_capacity(y_msb.len());
    for y_msb in y_msb {
        let ov_a = if y_msb.a.to_u64_truncating() & 1 == 1 {
            mask
        } else {
            F::Uint::zero()
        };
        let ov_b = if y_msb.b.to_u64_truncating() & 1 == 1 {
            mask
        } else {
            F::Uint::zero()
        };
        ov.push(Rep3UintShare::<F>::new(ov_a, ov_b));
    }

    // one big multiplexer
    cmux_many_uint(&ov, &y, &x, net, state)
}

fn low_depth_sub_p_cmux_uint<F: FieldUint, N: Network>(
    x: &Rep3UintShare<F>,
    net: &N,
    state: &mut Rep3State,
    bitlen: usize,
) -> eyre::Result<Rep3UintShare<F>> {
    let original_bitlen = bitlen - 1; // before the potential overflow after an addition
    let mask = F::Uint::mask(original_bitlen);
    let mut y = low_depth_binary_sub_p_uint::<F, N>(x, net, state, bitlen)?;
    let x = x.and_mask(&mask);
    let y_msb = y >> bitlen;
    y.and_mask_assign(&mask);

    // Spread the ov share to the whole uint
    let ov_a = y_msb.a.to_u64_truncating() & 1;
    let ov_b = y_msb.b.to_u64_truncating() & 1;

    let ov_a = if ov_a == 1 { mask } else { F::Uint::zero() };
    let ov_b = if ov_b == 1 { mask } else { F::Uint::zero() };
    let ov = Rep3UintShare::<F>::new(ov_a, ov_b);

    // one big multiplexer
    let res = cmux_uint(&ov, &y, &x, net, state)?;
    Ok(res)
}

// Calculates 2^k + x1 - x2
fn low_depth_binary_sub_uint<F: FieldUint, N: Network>(
    x1: &Rep3UintShare<F>,
    x2: &Rep3UintShare<F>,
    net: &N,
    state: &mut Rep3State,
    bitlen: usize,
) -> eyre::Result<Rep3UintShare<F>> {
    // Let x2' = be the bit_not of x2
    // Add x1 + x2' via a packed Kogge-Stone adder, where carry_in = 1
    // This is equivalent to x1 - x2 = x1 + two's complement of x2
    let mask = F::Uint::mask(bitlen);
    // bitnot of x2
    let x2 = x2.xor_mask(&mask);
    // Now start the Kogge-Stone adder
    let p = *x1 ^ x2;
    let mut g = and_uint(x1, &x2, net, state)?;
    // Since carry_in = 1, we need to XOR the LSB of x1 and x2 to g (i.e., xor the LSB of p)
    g ^= p.and_mask(&F::Uint::one());

    let res = kogge_stone_inner_uint(&p, &g, net, state, bitlen)?;
    let res = res.xor_mask(&F::Uint::one()); // cin=1
    Ok(res)
}

fn ceil_log2(x: usize) -> usize {
    let mut y = 0;
    let mut x = x - 1;
    while x > 0 {
        x >>= 1;
        y += 1;
    }
    y
}

#[expect(clippy::type_complexity)]
fn and_twice_uint_many_iter<F: FieldUint, N: Network>(
    a: impl Iterator<Item = Rep3UintShare<F>>,
    b1: impl Iterator<Item = Rep3UintShare<F>>,
    b2: impl Iterator<Item = Rep3UintShare<F>>,
    net: &N,
    state: &mut Rep3State,
    bitlen: usize,
    len: usize,
) -> eyre::Result<(Vec<Rep3UintShare<F>>, Vec<Rep3UintShare<F>>)> {
    let mut local_a1 = Vec::with_capacity(len);
    let mut local_a2 = Vec::with_capacity(len);
    for (a, b1, b2) in izip!(a, b1, b2) {
        let (mut mask1, mask_b) = state.rngs.rand.random_uint::<F::Uint>(bitlen);
        mask1 ^= mask_b;

        let (mut mask2, mask_b) = state.rngs.rand.random_uint::<F::Uint>(bitlen);
        mask2 ^= mask_b;
        local_a1.push((b1 & a) ^ mask1);
        local_a2.push((a & b2) ^ mask2);
    }

    let [local_b1, local_b2] = net.reshare([local_a1.clone(), local_a2.clone()])?;

    let mut r1 = Vec::with_capacity(len);
    let mut r2 = Vec::with_capacity(len);

    for (local_a1, local_b1, local_a2, local_b2) in izip!(local_a1, local_b1, local_a2, local_b2) {
        r1.push(Rep3UintShare::new(local_a1, local_b1));
        r2.push(Rep3UintShare::new(local_a2, local_b2));
    }

    Ok((r1, r2))
}

fn and_twice_uint<F: FieldUint, N: Network>(
    a: &Rep3UintShare<F>,
    b1: &Rep3UintShare<F>,
    b2: &Rep3UintShare<F>,
    net: &N,
    state: &mut Rep3State,
    bitlen: usize,
) -> eyre::Result<(Rep3UintShare<F>, Rep3UintShare<F>)> {
    debug_assert!(a.a.bit_len() <= bitlen);
    debug_assert!(b1.a.bit_len() <= bitlen);
    debug_assert!(b2.a.bit_len() <= bitlen);
    let (mut mask1, mask_b) = state.rngs.rand.random_uint::<F::Uint>(bitlen);
    mask1 ^= mask_b;

    let (mut mask2, mask_b) = state.rngs.rand.random_uint::<F::Uint>(bitlen);
    mask2 ^= mask_b;

    let local_a1 = (*b1 & *a) ^ mask1;
    let local_a2 = (*a & *b2) ^ mask2;
    let [local_b1, local_b2] = net.reshare([local_a1, local_a2])?;

    let r1 = Rep3UintShare::new(local_a1, local_b1);
    let r2 = Rep3UintShare::new(local_a2, local_b2);

    Ok((r1, r2))
}

fn low_depth_binary_sub_p_uint<F: FieldUint, N: Network>(
    x: &Rep3UintShare<F>,
    net: &N,
    state: &mut Rep3State,
    bitlen: usize,
) -> eyre::Result<Rep3UintShare<F>> {
    let p_ = (F::Uint::one() << bitlen).wrapping_sub(&F::modulus_uint());

    // Add x1 + p_ via a packed Kogge-Stone adder
    let g = x.and_mask(&p_);
    let p = x.xor_mask(&p_);
    kogge_stone_inner_uint(&p, &g, net, state, bitlen)
}

fn low_depth_binary_sub_p_uint_many<F: FieldUint, N: Network>(
    x: &[Rep3UintShare<F>],
    net: &N,
    state: &mut Rep3State,
    bitlen: usize,
) -> eyre::Result<Vec<Rep3UintShare<F>>> {
    let p_ = (F::Uint::one() << bitlen).wrapping_sub(&F::modulus_uint());

    // Add x1 + p_ via a packed Kogge-Stone adder
    let mut g = x.iter().map(|x| x.and_mask(&p_)).collect_vec();
    let mut p = x.iter().map(|x| x.xor_mask(&p_)).collect_vec();
    kogge_stone_inner_uint_many(&mut p, &mut g, net, state, bitlen)?;
    Ok(g)
}

/// Computes a binary circuit to compare two shared values \[x\] > \[y\]. Thus, the inputs x and y are transformed from arithmetic to binary sharings using [Rep3Protocol::a2b] first. The output is a binary sharing of one bit.
// TEMPORARY Task-3 wrapper, removed in Task 4
pub(crate) fn unsigned_ge<F: PrimeField, N: Network>(
    x: Rep3PrimeFieldShare<F>,
    y: Rep3PrimeFieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3BigUintShare<F>> {
    dispatch_field_uint!(F, {
        let x: Rep3PrimeFieldShare<CF> = *crate::downcast(&x).expect("checked type");
        let y: Rep3PrimeFieldShare<CF> = *crate::downcast(&y).expect("checked type");
        let res = unsigned_ge_uint::<CF, N>(x, y, net, state)?;
        let res = to_biguint_share(&res);
        Ok(
            crate::downcast::<Rep3BigUintShare<CF>, Rep3BigUintShare<F>>(&res)
                .expect("checked type")
                .clone(),
        )
    })
}

fn unsigned_ge_uint<F: FieldUint, N: Network>(
    x: Rep3PrimeFieldShare<F>,
    y: Rep3PrimeFieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3UintShare<F>> {
    let a_bits = conversion::a2b_selector(x, net, state)?;
    let b_bits = conversion::a2b_selector(y, net, state)?;
    let a_bits = to_uint_share(&a_bits);
    let b_bits = to_uint_share(&b_bits);
    let diff =
        low_depth_binary_sub_uint(&a_bits, &b_bits, net, state, F::MODULUS_BIT_SIZE as usize)?;

    Ok((diff >> F::MODULUS_BIT_SIZE as usize).and_mask(&F::Uint::one()))
}

/// Computes a binary circuit to compare the shared value y to the public value x, i.e., x > \[y\]. Thus, the input y is transformed from arithmetic to binary sharings using [Rep3Protocol::a2b] first. The output is a binary sharing of one bit.
// TEMPORARY Task-3 wrapper, removed in Task 4
pub(crate) fn unsigned_ge_const_lhs<F: PrimeField, N: Network>(
    x: F,
    y: Rep3PrimeFieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3BigUintShare<F>> {
    dispatch_field_uint!(F, {
        let x: CF = *crate::downcast(&x).expect("checked type");
        let y: Rep3PrimeFieldShare<CF> = *crate::downcast(&y).expect("checked type");
        let res = unsigned_ge_uint_const_lhs::<CF, N>(x, y, net, state)?;
        let res = to_biguint_share(&res);
        Ok(
            crate::downcast::<Rep3BigUintShare<CF>, Rep3BigUintShare<F>>(&res)
                .expect("checked type")
                .clone(),
        )
    })
}

fn unsigned_ge_uint_const_lhs<F: FieldUint, N: Network>(
    x: F,
    y: Rep3PrimeFieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3UintShare<F>> {
    let b_bits = conversion::a2b_selector(y, net, state)?;
    let b_bits = to_uint_share(&b_bits);
    let diff = low_depth_binary_sub_from_const_uint(&x.to_uint(), &b_bits, net, state)?;

    Ok((diff >> F::MODULUS_BIT_SIZE as usize).and_mask(&F::Uint::one()))
}

/// Computes a binary circuit to compare the shared value x to the public value y, i.e., \[x\] > y. Thus, the input x is transformed from arithmetic to binary sharings using [Rep3Protocol::a2b] first. The output is a binary sharing of one bit.
// TEMPORARY Task-3 wrapper, removed in Task 4
pub(crate) fn unsigned_ge_const_rhs<F: PrimeField, N: Network>(
    x: Rep3PrimeFieldShare<F>,
    y: F,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3BigUintShare<F>> {
    dispatch_field_uint!(F, {
        let x: Rep3PrimeFieldShare<CF> = *crate::downcast(&x).expect("checked type");
        let y: CF = *crate::downcast(&y).expect("checked type");
        let res = unsigned_ge_uint_const_rhs::<CF, N>(x, y, net, state)?;
        let res = to_biguint_share(&res);
        Ok(
            crate::downcast::<Rep3BigUintShare<CF>, Rep3BigUintShare<F>>(&res)
                .expect("checked type")
                .clone(),
        )
    })
}

fn unsigned_ge_uint_const_rhs<F: FieldUint, N: Network>(
    x: Rep3PrimeFieldShare<F>,
    y: F,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3UintShare<F>> {
    if y.is_zero() {
        // Every field element is >= 0, so the comparison is unconditionally
        // true. Short-circuit instead of falling through to
        // `low_depth_binary_sub_by_const_uint`: for `y = 0` the two's
        // complement `2^B - 0` is exactly `2^B`, a `B+1`-bit value that
        // blows the `bitlen`-bit assumption of the Kogge-Stone adder below
        // (CONFIRMED pre-existing bug, see task-1 report).
        return Ok(promote_to_trivial_uint_share(state.id, F::Uint::one()));
    }
    let a_bits = conversion::a2b_selector(x, net, state)?;
    let a_bits = to_uint_share(&a_bits);
    let diff = low_depth_binary_sub_by_const_uint(&a_bits, &y.to_uint(), net, state)?;

    Ok((diff >> F::MODULUS_BIT_SIZE as usize).and_mask(&F::Uint::one()))
}

// Calculates 2^k + x1 - x2
fn low_depth_binary_sub_by_const_uint<F: FieldUint, N: Network>(
    x1: &Rep3UintShare<F>,
    x2: &F::Uint,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3UintShare<F>> {
    // two's complement
    let x2_ = (F::Uint::one() << F::MODULUS_BIT_SIZE as usize).wrapping_sub(x2);

    // Add x1 + x2_ via a packed Kogge-Stone adder
    let p = x1.xor_mask(&x2_);
    let g = x1.and_mask(&x2_);

    let res = kogge_stone_inner_uint(&p, &g, net, state, F::MODULUS_BIT_SIZE as usize)?;
    Ok(res)
}

// Calculates 2^k + x1 - x2
fn low_depth_binary_sub_from_const_uint<F: FieldUint, N: Network>(
    x1: &F::Uint,
    x2: &Rep3UintShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3UintShare<F>> {
    // Let x2' = be the bit_not of x2
    // Add x1 + x2' via a packed Kogge-Stone adder, where carry_in = 1
    // This is equivalent to x1 - x2 = x1 + two's complement of x2
    let mask = F::Uint::mask(F::MODULUS_BIT_SIZE as usize);
    // bitnot of x2
    let x2 = x2.xor_mask(&mask);
    // Now start the Kogge-Stone adder
    let p = x2.xor_mask(x1);
    let mut g = x2.and_mask(x1);
    // Since carry_in = 1, we need to XOR the LSB of x1 and x2 to g (i.e., xor the LSB of p)
    g ^= p.and_mask(&F::Uint::one());

    let res = kogge_stone_inner_uint(&p, &g, net, state, F::MODULUS_BIT_SIZE as usize)?;
    let res = res.xor_mask(&F::Uint::one());
    Ok(res)
}

/// For curves of the form y^2 = x^3 + ax + b, computes the addition of two points.
/// Note: This implementation assumes that at least one point is randomly chosen (as is e.g., the case for point_share_to_fieldshares). Thus, the special case that the x-coordinate of the two points are equal is only considered to be able to happen if the sum is infinity (as is the case when translating a share of the infinity point to fieldshares). Thus, we count the fact of the x coordinates being equal as infinity.
///
/// The output will be (x, y, is_infinity). Thereby no statement is made on x, y if is_infinity is true.
pub(crate) fn point_addition<F: PrimeField, N: Network>(
    a_x: Rep3PrimeFieldShare<F>,
    a_y: Rep3PrimeFieldShare<F>,
    b_x: Rep3PrimeFieldShare<F>,
    b_y: Rep3PrimeFieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<(
    Rep3PrimeFieldShare<F>,
    Rep3PrimeFieldShare<F>,
    Rep3PrimeFieldShare<F>,
)> {
    let mut diff_x = b_x - a_x;
    let diff_y = b_y - a_y;

    let zero_share = Rep3PrimeFieldShare::default();
    let is_zero = arithmetic::eq(zero_share, diff_x, net, state)?;
    diff_x += arithmetic::mul(
        arithmetic::add_public(-diff_x, F::one(), state.id),
        is_zero,
        net,
        state,
    )?;

    let inv = arithmetic::inv(diff_x, net, state)?;

    let lambda = arithmetic::mul(diff_y, inv, net, state)?;
    let lambda_square = arithmetic::mul(lambda, lambda, net, state)?;
    let x = lambda_square - a_x - b_x;
    let y = arithmetic::mul(lambda, a_x - x, net, state)? - a_y;

    Ok((x, y, is_zero))
}

/// Batched version of point_addition.
/// For curves of the form y^2 = x^3 + ax + b, computes the addition of two vecs of points.
/// Note: This implementation assumes that at least one point is randomly chosen (as is e.g., the case for point_share_to_fieldshares). Thus, the special case that the x-coordinate of the two points are equal is only considered to be able to happen if the sum is infinity (as is the case when translating a share of the infinity point to fieldshares). Thus, we count the fact of the x coordinates being equal as infinity.
///
/// The output will be (x, y, is_infinity). Thereby no statement is made on x, y if is_infinity is true.
#[expect(clippy::type_complexity)]
pub(crate) fn point_addition_many<F: PrimeField, N: Network>(
    a_x: &[Rep3PrimeFieldShare<F>],
    a_y: &[Rep3PrimeFieldShare<F>],
    b_x: &[Rep3PrimeFieldShare<F>],
    b_y: &[Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<(
    Vec<Rep3PrimeFieldShare<F>>,
    Vec<Rep3PrimeFieldShare<F>>,
    Vec<Rep3PrimeFieldShare<F>>,
)> {
    let mut diff_xs = izip!(b_x, a_x).map(|(b_x, a_x)| b_x - a_x).collect_vec(); //b_x - a_x;
    let diff_ys = izip!(b_y, a_y).map(|(b_y, a_y)| b_y - a_y).collect_vec(); // b_y - a_y;

    let zero_share = vec![Rep3PrimeFieldShare::default(); diff_xs.len()];
    let is_zero = arithmetic::eq_many(&zero_share, &diff_xs, net, state)?;
    let tmp = diff_xs
        .iter()
        .map(|diff_x| arithmetic::sub_public_by_shared(F::one(), *diff_x, state.id))
        .collect_vec();
    let mul = arithmetic::mul_vec(&tmp, &is_zero, net, state)?;
    for (diff_x, m) in izip!(diff_xs.iter_mut(), mul.into_iter()) {
        *diff_x += m;
    }

    let inv = arithmetic::inv_vec(&diff_xs, net, state)?;

    let lambda = arithmetic::mul_vec(&diff_ys, &inv, net, state)?;
    let lambda_square = arithmetic::mul_vec(&lambda, &lambda, net, state)?;

    let x = izip!(lambda_square.iter(), a_x, b_x)
        .map(|(lambda_square, a_x, b_x)| *lambda_square - *a_x - *b_x)
        .collect_vec();
    let ax_minus_x = izip!(a_x, x.iter()).map(|(a_x, x)| *a_x - *x).collect_vec();
    let y = arithmetic::mul_vec(&lambda, &ax_minus_x, net, state)?;
    let y = izip!(y.iter(), a_y).map(|(y, a_y)| *y - *a_y).collect_vec();

    Ok((x, y, is_zero))
}

// This function is necessary, since CurveGroup does not expose any way to create a point from x, y directly.
pub(crate) fn point_from_xy<C: CurveGroup>(
    x: C::BaseField,
    y: C::BaseField,
    is_infinity: C::BaseField,
) -> eyre::Result<C> {
    if is_infinity > C::BaseField::one() {
        eyre::bail!("Invalid is_infinity");
    }
    if is_infinity.is_one() {
        return Ok(C::zero());
    }

    let point = if TypeId::of::<C>() == TypeId::of::<ark_bn254::G1Projective>() {
        let x = *crate::downcast(&x).expect("We checked types");
        let y = *crate::downcast(&y).expect("We checked types");
        let result: ark_bn254::G1Projective = ark_bn254::G1Affine::new(x, y).into();
        *crate::downcast(&result).expect("We checked types")
    } else if TypeId::of::<C>() == TypeId::of::<ark_grumpkin::Projective>() {
        let x = *crate::downcast(&x).expect("We checked types");
        let y = *crate::downcast(&y).expect("We checked types");
        let result: ark_grumpkin::Projective = ark_grumpkin::Affine::new(x, y).into();
        *crate::downcast(&result).expect("We checked types")
    } else {
        panic!("Unsupported curve {}", std::any::type_name::<C>());
    };
    Ok(point)
}
