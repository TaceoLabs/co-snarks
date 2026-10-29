// Adapted from swanky (https://github.com/GaloisInc/swanky), rev
// 5ff648457218b74da9d8323b7ca47166ff5be4b3, crates `fancy-garbling` and `scuttlebutt`.
// Copyright © 2019-2022 Galois, Inc. Licensed under the MIT license, see
// THIRD_PARTY_NOTICES in the mpc-core crate root.

//! # Garbling primitives
//!
//! The small subset of [swanky](https://github.com/GaloisInc/swanky) (`fancy-garbling` and `scuttlebutt`, rev `5ff6484`) used by our garbled circuits. Wire labels, the fixed-key AES hash and the [`Fancy`]/[`FancyBinary`] traits are bit-compatible with that revision.

use aes::{
    Aes128,
    cipher::{BlockCipherEncrypt, KeyInit},
};
use rand::{CryptoRng, Rng, distributions::Standard, prelude::Distribution};
use std::{
    ops::{BitXor, BitXorAssign},
    sync::LazyLock,
};
use subtle::{Choice, ConditionallySelectable};

use super::bristol_fashion::CircuitExecutionError;

/// A 128-bit block, laid out as 16 little-endian bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(C, align(16))]
pub struct Block([u8; 16]);

impl Block {
    /// The block as a little-endian `u128`.
    pub fn to_u128(self) -> u128 {
        u128::from_le_bytes(self.0)
    }
}

impl From<u128> for Block {
    fn from(x: u128) -> Self {
        Self(x.to_le_bytes())
    }
}

impl From<[u8; 16]> for Block {
    fn from(x: [u8; 16]) -> Self {
        Self(x)
    }
}

impl From<Block> for [u8; 16] {
    fn from(x: Block) -> Self {
        x.0
    }
}

impl From<Block> for u128 {
    fn from(x: Block) -> Self {
        x.to_u128()
    }
}

impl AsRef<[u8]> for Block {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl BitXor for Block {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self {
        Self::from(self.to_u128() ^ rhs.to_u128())
    }
}

impl BitXorAssign for Block {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl ConditionallySelectable for Block {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let (a, b) = (a.to_u128(), b.to_u128());
        let mask = 0u128.wrapping_sub(u128::from(choice.unwrap_u8()));
        Self::from(a ^ (mask & (a ^ b)))
    }
}

impl Distribution<Block> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Block {
        let mut out = Block::default();
        rng.fill_bytes(&mut out.0);
        out
    }
}

/// The fixed AES-128 key of swanky's `Aes128EncryptOnly::FIXED_KEY`.
///
/// This key is public by design: fixed-key AES is used as a public random
/// permutation for the TCCR hash (cf. <https://eprint.iacr.org/2019/074>).
/// Security relies on the secrecy of the wire labels and delta, not this key.
const FIXED_KEY: [u8; 16] = [
    0xbd, 0x24, 0x00, 0xc1, 0x12, 0x41, 0xce, 0x33, 0xed, 0x3d, 0x7d, 0xc7, 0xa8, 0x56, 0x40, 0x25,
];

static AES: LazyLock<Aes128> = LazyLock::new(|| Aes128::new(&FIXED_KEY.into()));

/// Tweakable circular correlation robust hash function (cf. <https://eprint.iacr.org/2019/074>, §7.4) for `Q` inputs at once.
///
/// Computes `π(π(x) ⊕ i) ⊕ π(x)` for every `x` in `xs`.
fn tccr_hash_many<const Q: usize>(tweak: Block, xs: [Block; Q]) -> [Block; Q] {
    let mut y = xs.map(|x| aes::Block::from(x.0));
    AES.encrypt_blocks(&mut y);
    let mut z = y.map(|y| aes::Block::from((Block(y.into()) ^ tweak).0));
    AES.encrypt_blocks(&mut z);
    std::array::from_fn(|i| Block(y[i].into()) ^ Block(z[i].into()))
}

/// Hashes `Q` wires with the same tweak.
fn hash_wires<const Q: usize>(wires: [&WireMod2; Q], tweak: Block) -> [Block; Q] {
    tccr_hash_many(tweak, wires.map(WireMod2::as_block))
}

/// Tweak function for two items.
fn tweak2(i: u64, j: u64) -> Block {
    Block::from((u128::from(i) << 64) | u128::from(j))
}

/// Compute the output tweak for a garbled gate where `i` is the gate id and `k` is the value.
pub fn output_tweak(i: usize, k: u16) -> Block {
    Block::from(((i as u128) << 64) | u128::from(k))
}

/// A `mod-2` wire label. Its color is the least significant bit.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct WireMod2 {
    val: Block,
}

impl ConditionallySelectable for WireMod2 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            val: Block::conditional_select(&a.val, &b.val, choice),
        }
    }
}

impl BitXor for WireMod2 {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self {
        Self {
            val: self.val ^ rhs.val,
        }
    }
}

impl BitXorAssign for WireMod2 {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.val ^= rhs.val;
    }
}

impl WireMod2 {
    /// Unpack a wire from a `Block`.
    pub fn from_block(inp: Block) -> Self {
        Self { val: inp }
    }

    /// A random wire.
    pub fn rand<R: CryptoRng + Rng>(rng: &mut R) -> Self {
        Self { val: rng.r#gen() }
    }

    /// A random delta, i.e., a random wire with color 1.
    pub fn rand_delta<R: CryptoRng + Rng>(rng: &mut R) -> Self {
        let mut w = Self::rand(rng);
        w.val.0[0] |= 1;
        w
    }

    /// Pack the wire into a `Block`.
    pub fn as_block(&self) -> Block {
        self.val
    }

    /// The color digit of the wire.
    pub fn color(&self) -> u16 {
        u16::from(self.val.0[0] & 1)
    }

    /// Multiply the wire by a constant `c mod 2`, returning a new wire.
    pub fn cmul(&self, c: u16) -> Self {
        if c & 1 == 0 { Self::default() } else { *self }
    }

    /// Hash the wire with fixed-key AES.
    pub fn hash(&self, tweak: Block) -> Block {
        let [h] = tccr_hash_many(tweak, [self.val]);
        h
    }
}

/// Evaluates an 'and' gate given two inputs wires and two half-gates from the garbler.
///
/// Outputs C = A & B
///
/// Used internally as a subroutine to implement 'and' gates for [`FancyBinary`].
pub(crate) fn evaluate_and_gate(
    gate_num: usize,
    a: &WireMod2,
    b: &WireMod2,
    gate0: &Block,
    gate1: &Block,
) -> WireMod2 {
    let g = tweak2(gate_num as u64, 0);

    let [hash_a, hash_b] = hash_wires([a, b], g);

    // garbler's half gate
    let l = WireMod2::from_block(Block::conditional_select(
        &hash_a,
        &(hash_a ^ *gate0),
        (a.color() as u8).into(),
    ));

    // evaluator's half gate
    let r = WireMod2::from_block(Block::conditional_select(
        &hash_b,
        &(hash_b ^ *gate1),
        (b.color() as u8).into(),
    ));

    l ^ r ^ a.cmul(b.color())
}

/// Garbles an 'and' gate given two input wires and the delta.
///
/// Outputs a tuple consisting of the two gates (that should be transferred to the evaluator)
/// and the next wire label for the garbler.
///
/// Used internally as a subroutine to implement 'and' gates for [`FancyBinary`].
pub(crate) fn garble_and_gate(
    gate_num: usize,
    a: &WireMod2,
    b: &WireMod2,
    delta: &WireMod2,
) -> (Block, Block, WireMod2) {
    let d = delta;

    let r = b.color(); // secret value known only to the garbler (ev knows r+b)

    let g = tweak2(gate_num as u64, 0);

    // X = H(A+aD) + arD such that a + A.color == 0
    let alpha = a.color(); // alpha = -A.color
    let x1 = *a ^ d.cmul(alpha);

    // Y = H(B + bD) + (b + r)A such that b + B.color == 0
    let beta = b.color();
    let y1 = *b ^ d.cmul(beta);

    let ad = *a ^ *d;
    let bd = *b ^ *d;

    // idx is always boolean for binary gates, so it can be represented as a `u8`
    let a_selector = (a.color() as u8).into();
    let b_selector = (b.color() as u8).into();

    let b = WireMod2::conditional_select(&bd, b, b_selector);
    let new_a = WireMod2::conditional_select(&ad, a, a_selector);
    let idx = u8::conditional_select(&(r as u8), &0u8, a_selector);

    let [hash_a, hash_b, hash_x, hash_y] = hash_wires([&new_a, &b, &x1, &y1], g);

    let x = WireMod2::from_block(hash_x) ^ d.cmul(alpha & r);
    let y = WireMod2::from_block(hash_y);

    let gate0 = hash_a ^ Block::conditional_select(&x.as_block(), &(x ^ *d).as_block(), idx.into());
    let gate1 = hash_b ^ (y ^ *a).as_block();

    (gate0, gate1, x ^ y)
}

/// A bundle of binary wires, least significant bit first.
#[derive(Debug, Clone)]
pub struct BinaryBundle<W>(Vec<W>);

impl<W> BinaryBundle<W> {
    /// Create a bundle from the given wires.
    pub fn new(ws: Vec<W>) -> Self {
        Self(ws)
    }

    /// The wires of the bundle.
    pub fn wires(&self) -> &[W] {
        &self.0
    }

    /// Iterate over the wires of the bundle.
    pub fn iter(&self) -> std::slice::Iter<'_, W> {
        self.0.iter()
    }

    /// The number of wires in the bundle.
    pub fn size(&self) -> usize {
        self.0.len()
    }
}

/// Errors of the garblers and evaluators.
#[derive(Debug, thiserror::Error)]
pub enum GcError {
    /// Any other error, e.g., sending or receiving garbled circuit data failed.
    #[error(transparent)]
    Other(eyre::Report),
    /// An output wire could not be decoded.
    #[error("decoding an output wire failed")]
    DecodingFailed,
    /// Executing a Bristol fashion circuit failed.
    #[error(transparent)]
    Circuit(#[from] CircuitExecutionError),
    /// A Bristol fashion circuit produced no output.
    #[error("no output found in circuit evaluation")]
    NoCircuitOutput,
}

impl From<eyre::Report> for GcError {
    fn from(err: eyre::Report) -> Self {
        Self::Other(err)
    }
}

/// The basic operations of a garbled circuit.
pub trait Fancy {
    /// The underlying wire type.
    type Item: Clone + std::fmt::Debug;

    /// Create a constant `x`.
    fn constant(&mut self, x: u16) -> Result<Self::Item, GcError>;

    /// Process an output wire.
    fn output(&mut self, x: &Self::Item) -> Result<Option<u16>, GcError>;

    /// Process several output wires.
    fn outputs(&mut self, xs: &[Self::Item]) -> Result<Option<Vec<u16>>, GcError> {
        let mut zs = Vec::with_capacity(xs.len());
        for x in xs.iter() {
            zs.push(self.output(x)?);
        }
        Ok(zs.into_iter().collect())
    }
}

/// Binary operations on top of [`Fancy`].
pub trait FancyBinary: Fancy {
    /// Binary xor.
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, GcError>;

    /// Binary and.
    fn and(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, GcError>;

    /// Binary not.
    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, GcError>;

    /// Binary or, as `!(!x & !y)`.
    fn or(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, GcError> {
        let notx = self.negate(x)?;
        let noty = self.negate(y)?;
        let z = self.and(&notx, &noty)?;
        self.negate(&z)
    }

    /// If `b = 0` returns `x` else `y`.
    fn mux(
        &mut self,
        b: &Self::Item,
        x: &Self::Item,
        y: &Self::Item,
    ) -> Result<Self::Item, GcError> {
        let xor = self.xor(x, y)?;
        let and = self.and(b, &xor)?;
        self.xor(&and, x)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn garble_and_evaluate_and_gates() {
        let mut rng = thread_rng();
        for _ in 0..32 {
            let delta = WireMod2::rand_delta(&mut rng);
            assert_eq!(delta.color(), 1);
            let encode = |zero: &WireMod2, bit: bool| *zero ^ delta.cmul(bit as u16);

            // Chain the gates, so the output labels are used as inputs again
            let mut a_zero = WireMod2::rand(&mut rng);
            let mut b_zero = WireMod2::rand(&mut rng);
            let (mut a, mut b) = (true, false);
            for gate_num in 0..32 {
                let (gate0, gate1, c_zero) = garble_and_gate(gate_num, &a_zero, &b_zero, &delta);
                let c = a & b;
                let evaluated = evaluate_and_gate(
                    gate_num,
                    &encode(&a_zero, a),
                    &encode(&b_zero, b),
                    &gate0,
                    &gate1,
                );
                assert_eq!(evaluated, encode(&c_zero, c));
                // Decode via the color bit, as the output gates do
                assert_eq!(evaluated.color() ^ c_zero.color() == 1, c);

                (a_zero, b_zero) = (c_zero, a_zero ^ b_zero);
                (a, b) = (c ^ (gate_num % 3 == 0), a ^ b ^ (gate_num % 2 == 0));
            }
        }
    }

    // Reference values computed with swanky rev 5ff648457218b74da9d8323b7ca47166ff5be4b3
    #[test]
    fn matches_swanky() {
        let a = WireMod2::from_block(Block::from(0x0011_2233_4455_6677_8899_aabb_ccdd_eeff));
        let b = WireMod2::from_block(Block::from(0xfedc_ba98_7654_3210_0f1e_2d3c_4b5a_6978));
        assert_eq!(
            a.hash(output_tweak(7, 1)).to_u128(),
            0x45512f1e9836e2054f39c276916d3da9
        );
        let [x, y] = hash_wires([&a, &b], tweak2(42, 1));
        assert_eq!(x.to_u128(), 0x71d46645056383be70cbdccd4687ade3);
        assert_eq!(y.to_u128(), 0x8de2e5cb2b93c6b427596aac70400568);
    }
}
