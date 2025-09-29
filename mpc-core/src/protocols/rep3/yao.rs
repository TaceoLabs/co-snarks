//! Yao
//!
//! This module contains operations with Yao's garbled circuits

pub mod bristol_fashion;
pub mod circuits;
pub mod evaluator;
pub mod garbler;
pub mod streaming_evaluator;
pub mod streaming_garbler;

use super::{
    Rep3BigUintShare, Rep3PrimeFieldShare, Rep3State, id::PartyID, network::Rep3NetworkExt,
};
use ark_ff::{PrimeField, Zero};
use circuits::{GarbledCircuits, SHA256Table};
use fancy_garbling::{BinaryBundle, WireLabel, WireMod2, hash_wires, util::tweak2};
use itertools::Itertools;
use mpc_net::Network;
use num_bigint::BigUint;
use rand::{CryptoRng, Rng};
use scuttlebutt::Block;
use subtle::ConditionallySelectable;

/// A structure that contains both the garbler and the evaluators wires
pub struct GCInputs<F> {
    /// The wires of the garbler. These represent random keys x_0
    pub garbler_wires: BinaryBundle<F>,
    /// The wires of the evaluator. These represent the keys x_c = x_0 xor delta * val
    pub evaluator_wires: BinaryBundle<F>,
    /// The delta used for encoding known to the garbler
    pub delta: F,
}

/// This struct contains some useful utility functions for garbled circuits.
pub struct GCUtils {}

impl GCUtils {
    /// Evaluates an 'and' gate given two inputs wires and two half-gates from the garbler.
    ///
    /// Outputs C = A & B
    ///
    /// Used internally as a subroutine to implement 'and' gates for `FancyBinary`.
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
        let l = WireMod2::from_block(
            Block::conditional_select(&hash_a, &(hash_a ^ *gate0), (a.color() as u8).into()),
            2,
        );

        // evaluator's half gate
        let r = WireMod2::from_block(
            Block::conditional_select(&hash_b, &(hash_b ^ *gate1), (b.color() as u8).into()),
            2,
        );

        l.plus_mov(&r.plus_mov(&a.cmul(b.color())))
    }

    /// Garbles an 'and' gate given two input wires and the delta.
    ///
    /// Outputs a tuple consisting of the two gates (that should be transfered to the evaluator)
    /// and the next wire label for the garbler.
    ///
    /// Used internally as a subroutine to implement 'and' gates for `FancyBinary`.
    pub(crate) fn garble_and_gate(
        gate_num: usize,
        a: &WireMod2,
        b: &WireMod2,
        delta: &WireMod2,
    ) -> (Block, Block, WireMod2) {
        let q = 2;
        let d = delta;

        let r = b.color(); // secret value known only to the garbler (ev knows r+b)

        let g = tweak2(gate_num as u64, 0);

        // X = H(A+aD) + arD such that a + A.color == 0
        let alpha = a.color(); // alpha = -A.color
        let x1 = a.plus(&d.cmul(alpha));

        // Y = H(B + bD) + (b + r)A such that b + B.color == 0
        let beta = (q - b.color()) % q;
        let y1 = b.plus(&d.cmul(beta));

        let ad = a.plus(d);
        let bd = b.plus(d);

        // idx is always boolean for binary gates, so it can be represented as a `u8`
        let a_selector = (a.color() as u8).into();
        let b_selector = (b.color() as u8).into();

        let b = WireMod2::conditional_select(&bd, b, b_selector);
        let new_a = WireMod2::conditional_select(&ad, a, a_selector);
        let idx = u8::conditional_select(&(r as u8), &0u8, a_selector);

        let [hash_a, hash_b, hash_x, hash_y] = hash_wires([&new_a, &b, &x1, &y1], g);

        let x = WireMod2::hash_to_mod(hash_x, q).plus_mov(&d.cmul(alpha * r % q));
        let y = WireMod2::hash_to_mod(hash_y, q);

        let gate0 =
            hash_a ^ Block::conditional_select(&x.as_block(), &x.plus(d).as_block(), idx.into());
        let gate1 = hash_b ^ y.plus(a).as_block();

        (gate0, gate1, x.plus_mov(&y))
    }

    pub(crate) fn garbled_circuits_error<G, T>(input: Result<T, G>) -> eyre::Result<T> {
        input.or(Err(eyre::eyre!("Garbled Circuit failed")))
    }

    pub(crate) fn collapse_bundle_to_lsb_bits_as_biguint(input: BinaryBundle<WireMod2>) -> BigUint {
        let mut res = BigUint::zero();
        for wire in input.wires().iter().rev() {
            res <<= 1;
            let lsb = wire.color();
            debug_assert!(lsb < 2);
            res += lsb as u64;
        }
        res
    }

    fn receive_block_from<N: Network>(net: &N, id: PartyID) -> eyre::Result<Block> {
        let data: Vec<u8> = net.recv_from(id)?;
        if data.len() != 16 {
            eyre::bail!("To little elements received");
        }
        let mut v = Block::default();
        v.as_mut().copy_from_slice(&data);

        Ok(v)
    }

    pub(crate) fn receive_bundle_from<N: Network>(
        n_bits: usize,
        net: &N,
        id: PartyID,
    ) -> eyre::Result<BinaryBundle<WireMod2>> {
        let rcv: Vec<[u8; 16]> = net.recv_many(id)?;
        if rcv.len() != n_bits {
            eyre::bail!("Invalid number of elements received",);
        }
        let mut result = Vec::with_capacity(rcv.len());
        for block in rcv {
            let mut v = Block::default();
            v.as_mut().copy_from_slice(&block);
            result.push(WireMod2::from_block(v, 2));
        }
        Ok(BinaryBundle::new(result))
    }

    fn send_bundle_to<N: Network>(
        input: &BinaryBundle<WireMod2>,
        net: &N,
        id: PartyID,
    ) -> eyre::Result<()> {
        let mut blocks = Vec::with_capacity(input.size());
        for val in input.iter() {
            let block = val.as_block();
            let mut gate = [0; 16];
            gate.copy_from_slice(block.as_ref());
            blocks.push(gate);
        }
        net.send_many(id, &blocks)
    }

    pub(crate) fn send_inputs<N: Network>(
        input: &GCInputs<WireMod2>,
        net: &N,
        garbler_id: PartyID,
    ) -> eyre::Result<()> {
        debug_assert_ne!(garbler_id, PartyID::ID0);
        let (send0, send1) = mpc_net::join(
            || Self::send_bundle_to(&input.garbler_wires, net, garbler_id),
            || Self::send_bundle_to(&input.evaluator_wires, net, PartyID::ID0),
        );
        send0?;
        send1?;
        Ok(())
    }

    /// Samples a random delta
    pub fn random_delta<R: Rng + CryptoRng>(rng: &mut R) -> WireMod2 {
        WireMod2::rand_delta(rng, 2)
    }

    #[cfg(test)]
    fn u16_bits_to_field<F: PrimeField>(bits: Vec<u16>) -> eyre::Result<F> {
        let mut res = BigUint::zero();
        for bit in bits.iter().rev() {
            assert!(*bit < 2);
            res <<= 1;
            res += *bit as u64;
        }
        if res >= F::MODULUS.into() {
            eyre::bail!("Invalid field element");
        }
        Ok(F::from(res))
    }

    /// Converts bits into a field element
    pub fn bits_to_field<F: PrimeField>(bits: &[bool]) -> eyre::Result<F> {
        let mut res = BigUint::zero();
        for bit in bits.iter().rev() {
            res <<= 1;
            res += *bit as u64;
        }
        if res >= F::MODULUS.into() {
            eyre::bail!("Invalid field element");
        }
        Ok(F::from(res))
    }

    fn biguint_to_bits(input: &BigUint, n_bits: usize) -> Vec<bool> {
        let mut res = Vec::with_capacity(n_bits);
        let mut bits = 0;
        for mut el in input.to_u64_digits() {
            for _ in 0..64 {
                res.push(el & 1 == 1);
                el >>= 1;
                bits += 1;
                if bits == n_bits {
                    break;
                }
            }
        }
        res.resize(n_bits, false);
        res
    }

    fn field_to_bits<F: PrimeField>(field: F) -> Vec<bool> {
        let n_bits = F::MODULUS_BIT_SIZE as usize;
        let bigint: BigUint = field.into();

        Self::biguint_to_bits(&bigint, n_bits)
    }

    fn field_to_bits_as_u16<F: PrimeField>(field: F) -> Vec<u16> {
        let n_bits = F::MODULUS_BIT_SIZE as usize;
        let bigint: BigUint = field.into();

        Self::biguint_to_bits_as_u16(&bigint, n_bits)
    }

    fn biguint_to_bits_as_u16(input: &BigUint, n_bits: usize) -> Vec<u16> {
        let mut res = Vec::with_capacity(n_bits);
        let mut bits = 0;
        for mut el in input.to_u64_digits() {
            for _ in 0..64 {
                res.push((el & 1) as u16);
                el >>= 1;
                bits += 1;
                if bits == n_bits {
                    break;
                }
            }
        }
        res.resize(n_bits, 0);
        res
    }

    /// Encode a wire, producing the zero wire as well as the encoded value.
    pub fn encode_wire<R: Rng + CryptoRng>(
        rng: &mut R,
        delta: &WireMod2,
        val: u16,
    ) -> (WireMod2, WireMod2) {
        let zero = WireMod2::rand(rng, 2);
        let enc = zero.plus(&delta.cmul(val));
        (zero, enc)
    }

    /// This puts the X_0 values into garbler_wires and X_c values into evaluator_wires
    pub(crate) fn encode_bits_as_wires<R: Rng + CryptoRng>(
        bits: Vec<u16>,
        rng: &mut R,
        delta: WireMod2,
    ) -> (Vec<WireMod2>, Vec<WireMod2>) {
        let mut garbler_wires = Vec::with_capacity(bits.len());
        let mut evaluator_wires = Vec::with_capacity(bits.len());
        for bit in bits {
            let (mine, theirs) = Self::encode_wire(rng, &delta, bit);
            garbler_wires.push(mine);
            evaluator_wires.push(theirs);
        }
        (garbler_wires, evaluator_wires)
    }

    /// Makes a GCInput out of the wires
    pub(crate) fn wires_to_gcinput(
        garbler_wires: Vec<WireMod2>,
        evaluator_wires: Vec<WireMod2>,
        delta: WireMod2,
    ) -> GCInputs<WireMod2> {
        GCInputs {
            garbler_wires: BinaryBundle::new(garbler_wires),
            evaluator_wires: BinaryBundle::new(evaluator_wires),
            delta,
        }
    }

    /// This puts the X_0 values into garbler_wires and X_c values into evaluator_wires
    pub(crate) fn encode_bits<R: Rng + CryptoRng>(
        bits: Vec<u16>,
        rng: &mut R,
        delta: WireMod2,
    ) -> GCInputs<WireMod2> {
        let (garbler_wires, evaluator_wires) = Self::encode_bits_as_wires(bits, rng, delta);
        Self::wires_to_gcinput(garbler_wires, evaluator_wires, delta)
    }

    /// This puts the X_0 values into garbler_wires and X_c values into evaluator_wires
    pub fn encode_bigint<R: Rng + CryptoRng>(
        bigint: &BigUint,
        n_bits: usize,
        rng: &mut R,
        delta: WireMod2,
    ) -> GCInputs<WireMod2> {
        let bits = Self::biguint_to_bits_as_u16(bigint, n_bits);
        Self::encode_bits(bits, rng, delta)
    }

    /// This puts the X_0 values into garbler_wires and X_c values into evaluator_wires
    pub fn encode_field<F: PrimeField, R: Rng + CryptoRng>(
        field: F,
        rng: &mut R,
        delta: WireMod2,
    ) -> GCInputs<WireMod2> {
        let bits = Self::field_to_bits_as_u16(field);
        Self::encode_bits(bits, rng, delta)
    }
}

/// Transforms an arithmetically shared input x = (x_1, x_2, x_3) into three yao shares x_1^Y, x_2^Y, x_3^Y. The used delta is an input to the function to allow for the same delta to be used for multiple conversions.
pub fn joint_input_arithmetic<F: PrimeField, N: Network>(
    x: Rep3PrimeFieldShare<F>,
    delta: Option<WireMod2>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<[BinaryBundle<WireMod2>; 3]> {
    let n_bits = F::MODULUS_BIT_SIZE as usize;

    // x1 is known by both garblers, we can do a shortcut to share it without communication.
    // See https://eprint.iacr.org/2019/1168.pdf, p18, last paragraph of "Joint Yao Input".
    let mut x1 = (0..n_bits)
        .map(|_| WireMod2::from_block(state.rngs.generate_shared::<Block>(state.id), 2))
        .collect_vec();

    let (x0, x2) = match state.id {
        PartyID::ID0 => {
            // Receive x0
            let x0 = GCUtils::receive_bundle_from(n_bits, net, PartyID::ID1)?;

            // Receive x2
            let x2 = GCUtils::receive_bundle_from(n_bits, net, PartyID::ID2)?;
            (x0, x2)
        }
        PartyID::ID1 => {
            let delta = delta.ok_or(eyre::eyre!("No delta provided"))?;

            // Modify x1
            let x1_bits = GCUtils::field_to_bits_as_u16(x.a);
            x1.iter_mut().zip(x1_bits).for_each(|(x, bit)| {
                x.plus_eq(&delta.cmul(bit));
            });

            // Input x0
            let x0 = GCUtils::encode_field(x.b, &mut state.rng, delta);

            // Send x0 to the other parties
            GCUtils::send_inputs(&x0, net, PartyID::ID2)?;
            let x0 = x0.garbler_wires;

            // Receive x2
            let x2 = GCUtils::receive_bundle_from(n_bits, net, PartyID::ID2)?;
            (x0, x2)
        }
        PartyID::ID2 => {
            let delta = delta.ok_or(eyre::eyre!("No delta provided"))?;

            // Modify x1
            let x1_bits = GCUtils::field_to_bits_as_u16(x.b);
            x1.iter_mut().zip(x1_bits).for_each(|(x, bit)| {
                x.plus_eq(&delta.cmul(bit));
            });

            // Input x2
            let x2 = GCUtils::encode_field(x.a, &mut state.rng, delta);

            // Send x2 to the other parties
            GCUtils::send_inputs(&x2, net, PartyID::ID1)?;
            let x2 = x2.garbler_wires;

            // Receive x0
            let x0 = GCUtils::receive_bundle_from(n_bits, net, PartyID::ID1)?;
            (x0, x2)
        }
    };
    let x1 = BinaryBundle::new(x1);

    Ok([x0, x1, x2])
}

/// Transforms an arithmetically shared input x = (x_1, x_2, x_3) into two yao shares x_1^Y, (x_2 + x_3)^Y. The used delta is an input to the function to allow for the same delta to be used for multiple conversions.
pub fn joint_input_arithmetic_added<F: PrimeField, N: Network>(
    x: Rep3PrimeFieldShare<F>,
    delta: Option<WireMod2>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<[BinaryBundle<WireMod2>; 2]> {
    joint_input_arithmetic_added_many(&[x], delta, net, state)
}

/// Transforms a vector of arithmetically shared inputs x = (x_1, x_2, x_3) into two yao shares x_1^Y, (x_2 + x_3)^Y. The used delta is an input to the function to allow for the same delta to be used for multiple conversions.
pub fn joint_input_arithmetic_added_many<F: PrimeField, N: Network>(
    x: &[Rep3PrimeFieldShare<F>],
    delta: Option<WireMod2>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<[BinaryBundle<WireMod2>; 2]> {
    let n_inputs = x.len();
    let n_bits = F::MODULUS_BIT_SIZE as usize;
    let bits = n_inputs * n_bits;

    let (x01, x2) = match state.id {
        PartyID::ID0 => {
            // Receive x0
            let x01 = GCUtils::receive_bundle_from(bits, net, PartyID::ID1)?;

            // Receive x2
            let x2 = GCUtils::receive_bundle_from(bits, net, PartyID::ID2)?;
            (x01, x2)
        }
        PartyID::ID1 => {
            let delta = delta.ok_or(eyre::eyre!("No delta provided"))?;

            let mut garbler_bundle = Vec::with_capacity(bits);
            let mut evaluator_bundle = Vec::with_capacity(bits);

            // Input x01
            for x in x.iter() {
                let sum = x.a + x.b;
                let bits = GCUtils::field_to_bits_as_u16(sum);
                let (garbler, evaluator) =
                    GCUtils::encode_bits_as_wires(bits, &mut state.rng, delta);
                garbler_bundle.extend(garbler);
                evaluator_bundle.extend(evaluator);
            }
            let x01 = GCUtils::wires_to_gcinput(garbler_bundle, evaluator_bundle, delta);

            // Send x01 to the other parties
            GCUtils::send_inputs(&x01, net, PartyID::ID2)?;
            let x01 = x01.garbler_wires;

            // Receive x2
            let x2 = GCUtils::receive_bundle_from(bits, net, PartyID::ID2)?;
            (x01, x2)
        }
        PartyID::ID2 => {
            let delta = delta.ok_or(eyre::eyre!("No delta provided"))?;

            let mut garbler_bundle = Vec::with_capacity(bits);
            let mut evaluator_bundle = Vec::with_capacity(bits);

            // Input x2
            for x in x.iter() {
                let bits = GCUtils::field_to_bits_as_u16(x.a);
                let (garbler, evaluator) =
                    GCUtils::encode_bits_as_wires(bits, &mut state.rng, delta);
                garbler_bundle.extend(garbler);
                evaluator_bundle.extend(evaluator);
            }
            let x2 = GCUtils::wires_to_gcinput(garbler_bundle, evaluator_bundle, delta);

            // Send x2 to the other parties
            GCUtils::send_inputs(&x2, net, PartyID::ID1)?;
            let x2 = x2.garbler_wires;

            // Receive x01
            let x01 = GCUtils::receive_bundle_from(bits, net, PartyID::ID1)?;
            (x01, x2)
        }
    };

    Ok([x01, x2])
}

/// Transforms an binary shared input x = (x_1, x_2, x_3) into two yao shares x_1^Y, (x_2 xor x_3)^Y. The used delta is an input to the function to allow for the same delta to be used for multiple conversions.
pub fn joint_input_binary_xored<F: PrimeField, N: Network>(
    x: &Rep3BigUintShare<F>,
    delta: Option<WireMod2>,
    net: &N,
    state: &mut Rep3State,
    bitlen: usize,
) -> eyre::Result<[BinaryBundle<WireMod2>; 2]> {
    let (x01, x2) = match state.id {
        PartyID::ID0 => {
            // Receive x01
            let x01 = GCUtils::receive_bundle_from(bitlen, net, PartyID::ID1)?;

            // Receive x2
            let x2 = GCUtils::receive_bundle_from(bitlen, net, PartyID::ID2)?;
            (x01, x2)
        }
        PartyID::ID1 => {
            let delta = delta.ok_or(eyre::eyre!("No delta provided"))?;

            // Input x01
            let xor = &x.a ^ &x.b;
            let x01 = GCUtils::encode_bigint(&xor, bitlen, &mut state.rng, delta);

            // Send x01 to the other parties
            GCUtils::send_inputs(&x01, net, PartyID::ID2)?;
            let x01 = x01.garbler_wires;

            // Receive x2
            let x2 = GCUtils::receive_bundle_from(bitlen, net, PartyID::ID2)?;
            (x01, x2)
        }
        PartyID::ID2 => {
            let delta = delta.ok_or(eyre::eyre!("No delta provided"))?;

            // Input x2
            let x2 = GCUtils::encode_bigint(&x.a, bitlen, &mut state.rng, delta);

            // Send x2 to the other parties
            GCUtils::send_inputs(&x2, net, PartyID::ID1)?;
            let x2 = x2.garbler_wires;

            // Receive x01
            let x01 = GCUtils::receive_bundle_from(bitlen, net, PartyID::ID1)?;
            (x01, x2)
        }
    };

    Ok([x01, x2])
}

/// Lets the party with id2 input a vector field elements, which gets shared as Yao wires to the other parties.
pub fn input_field_id2_many<F: PrimeField, N: Network>(
    x: Option<Vec<F>>,
    delta: Option<WireMod2>,
    n_inputs: usize,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<BinaryBundle<WireMod2>> {
    let n_bits = F::MODULUS_BIT_SIZE as usize;
    let bits = n_inputs * n_bits;

    let x = match state.id {
        PartyID::ID0 | PartyID::ID1 => {
            // Receive x
            GCUtils::receive_bundle_from(bits, net, PartyID::ID2)?
        }
        PartyID::ID2 => {
            let delta = delta.ok_or(eyre::eyre!("No delta provided"))?;
            let x = x.ok_or(eyre::eyre!("No input provided"))?;

            if x.len() != n_inputs {
                eyre::bail!("Invalid number of inputs",);
            }

            let mut garbler_bundle = Vec::with_capacity(bits);
            let mut evaluator_bundle = Vec::with_capacity(bits);

            // Input x1
            for x in x {
                let bits = GCUtils::field_to_bits_as_u16(x);
                let (garbler, evaluator) =
                    GCUtils::encode_bits_as_wires(bits, &mut state.rng, delta);
                garbler_bundle.extend(garbler);
                evaluator_bundle.extend(evaluator);
            }
            let x = GCUtils::wires_to_gcinput(garbler_bundle, evaluator_bundle, delta);

            // Send x to the other parties
            GCUtils::send_inputs(&x, net, PartyID::ID1)?;
            x.garbler_wires
        }
    };
    Ok(x)
}

/// Lets the party with id2 input a field element, which gets shared as Yao wires to the other parties.
pub fn input_field_id2<F: PrimeField, N: Network>(
    x: Option<F>,
    delta: Option<WireMod2>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<BinaryBundle<WireMod2>> {
    let x = x.map(|x| vec![x]);
    input_field_id2_many(x, delta, 1, net, state)
}

/// Decomposes a shared field element into chunks, which are also represented as shared field elements. Per field element, the total bit size of the shared chunks is given by total_bit_size_per_field, whereas each chunk has at most (i.e, the last chunk can be smaller) decompose_bit_size bits.
pub fn decompose_arithmetic<F: PrimeField, N: Network>(
    input: Rep3PrimeFieldShare<F>,
    net: &N,
    state: &mut Rep3State,
    total_bit_size_per_field: usize,
    decompose_bit_size: usize,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    decompose_arithmetic_many(
        &[input],
        net,
        state,
        total_bit_size_per_field,
        decompose_bit_size,
    )
}

/// Slices a shared field element at given indices (msb, lsb), both included in the slice.
/// Only considers bitsize bits.
/// Result  is thus [lo, slice, hi], where slice has all bits from lsb to msb, lo all bits smaller than lsb, and hi all bits greater msb up to bitsize.
pub fn slice_arithmetic<F: PrimeField, N: Network>(
    input: Rep3PrimeFieldShare<F>,
    net: &N,
    state: &mut Rep3State,
    msb: usize,
    lsb: usize,
    bitsize: usize,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    slice_arithmetic_many(&[input], net, state, msb, lsb, bitsize)
}

/// Computes input % 2^divisor_bit.
pub fn field_mod_power_2<F: PrimeField, N: Network>(
    input: Rep3PrimeFieldShare<F>,
    net: &N,
    state: &mut Rep3State,
    mod_bit: usize,
) -> eyre::Result<Rep3PrimeFieldShare<F>> {
    let decomposed = decompose_arithmetic(input, net, state, mod_bit, mod_bit)?;
    debug_assert_eq!(decomposed.len(), 1);
    let res = decomposed[0];
    Ok(res)
}

/// Divides a vector of field elements by a power of 2, rounding down.
pub fn field_int_div_power_2_many<F: PrimeField, N: Network>(
    inputs: &[Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut Rep3State,
    divisor_bit: usize,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let num_inputs = inputs.len();

    if divisor_bit == 0 {
        return Ok(inputs.to_owned());
    }
    if divisor_bit >= F::MODULUS_BIT_SIZE as usize {
        return Ok(vec![Rep3PrimeFieldShare::zero_share(); num_inputs]);
    }

    decompose_circuit_compose_blueprint!(
        inputs,
        net,
        state,
        num_inputs,
        GarbledCircuits::field_int_div_power_2_many::<_, F>,
        (divisor_bit)
    )
}

/// Divides a field element by a power of 2, rounding down.
pub fn field_int_div_power_2<F: PrimeField, N: Network>(
    inputs: Rep3PrimeFieldShare<F>,
    net: &N,
    state: &mut Rep3State,
    divisor_bit: usize,
) -> eyre::Result<Rep3PrimeFieldShare<F>> {
    let res = field_int_div_power_2_many(&[inputs], net, state, divisor_bit)?;
    Ok(res[0])
}

/// Divides a vector of field elements by another, rounding down.
pub fn field_int_div_many<F: PrimeField, N: Network>(
    input1: &[Rep3PrimeFieldShare<F>],
    input2: &[Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let num_inputs = input1.len();
    debug_assert_eq!(input1.len(), input2.len());

    let mut combined_inputs = Vec::with_capacity(input1.len() + input2.len());
    combined_inputs.extend_from_slice(input1);
    combined_inputs.extend_from_slice(input2);
    decompose_circuit_compose_blueprint!(
        &combined_inputs,
        net,
        state,
        num_inputs,
        GarbledCircuits::field_int_div_many::<_, F>,
        ()
    )
}

/// Divides a field element by another, rounding down.
pub fn field_int_div<F: PrimeField, N: Network>(
    input1: Rep3PrimeFieldShare<F>,
    input2: Rep3PrimeFieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3PrimeFieldShare<F>> {
    let res = field_int_div_many(&[input1], &[input2], net, state)?;
    Ok(res[0])
}

/// Divides a vector of field elements by another, rounding down.
pub fn field_int_div_by_public_many<F: PrimeField, N: Network>(
    input: &[Rep3PrimeFieldShare<F>],
    divisors: &[F],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let num_inputs = input.len();
    debug_assert_eq!(input.len(), divisors.len());

    let mut divisors_as_bits = Vec::with_capacity(F::MODULUS_BIT_SIZE as usize * num_inputs);
    divisors
        .iter()
        .for_each(|y| divisors_as_bits.extend(GCUtils::field_to_bits::<F>(*y)));

    decompose_circuit_compose_blueprint!(
        &input,
        net,
        state,
        num_inputs,
        GarbledCircuits::field_int_div_by_public_many::<_, F>,
        (divisors_as_bits)
    )
}

/// Divides a field element by another, rounding down.
pub fn field_int_div_by_public<F: PrimeField, N: Network>(
    input: Rep3PrimeFieldShare<F>,
    divisor: F,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3PrimeFieldShare<F>> {
    let res = field_int_div_by_public_many(&[input], &[divisor], net, state)?;
    Ok(res[0])
}

/// Divides a vector of field elements by another, rounding down.
pub fn field_int_div_by_shared_many<F: PrimeField, N: Network>(
    input: &[F],
    divisors: &[Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let num_inputs = input.len();
    debug_assert_eq!(input.len(), divisors.len());

    let mut inputs_as_bits = Vec::with_capacity(F::MODULUS_BIT_SIZE as usize * num_inputs);
    input
        .iter()
        .for_each(|y| inputs_as_bits.extend(GCUtils::field_to_bits::<F>(*y)));

    decompose_circuit_compose_blueprint!(
        &divisors,
        net,
        state,
        num_inputs,
        GarbledCircuits::field_int_div_by_shared_many::<_, F>,
        (inputs_as_bits)
    )
}

/// Computes AES ciphertext from given plaintext, key and initialization vector using a bristol fashion circuit as a garbled circuit.
pub fn aes_from_bristol<F: PrimeField, N: Network>(
    plaintext: &[Rep3PrimeFieldShare<F>],
    key: &[Rep3PrimeFieldShare<F>],
    iv: &[Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    const AES_BLOCK_SIZE: usize = 16;
    const BIT_SIZE: usize = 8;
    debug_assert_eq!(key.len(), AES_BLOCK_SIZE);
    debug_assert_eq!(iv.len(), AES_BLOCK_SIZE);

    let mut combined_inputs = Vec::with_capacity(key.len() + plaintext.len() + iv.len());
    combined_inputs.extend_from_slice(plaintext);
    combined_inputs.extend_from_slice(key);
    combined_inputs.extend_from_slice(iv);

    let total_output_elements =
        plaintext.len() + AES_BLOCK_SIZE - (plaintext.len() % AES_BLOCK_SIZE);
    decompose_circuit_compose_blueprint!(
        &combined_inputs,
        net,
        state,
        total_output_elements,
        GarbledCircuits::aes128::<_, F>,
        (plaintext.len(), key.len(), BIT_SIZE)
    )
}

/// Divides a field element by another, rounding down.
pub fn field_int_div_by_shared<F: PrimeField, N: Network>(
    input: F,
    divisor: Rep3PrimeFieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3PrimeFieldShare<F>> {
    let res = field_int_div_by_shared_many(&[input], &[divisor], net, state)?;
    Ok(res[0])
}

macro_rules! decompose_circuit_compose_blueprint {
    ($inputs:expr, $net:expr, $state:expr, $output_size:expr, $circuit:expr, ($( $args:expr ),*)) => {{
        use itertools::izip;
        use $crate::protocols::rep3::yao;
        use $crate::protocols::rep3::Rep3PrimeFieldShare;
        use $crate::protocols::rep3::{PartyID};

        let delta = $state.rngs
            .generate_random_garbler_delta($state.id);

        let [x01, x2] = yao::joint_input_arithmetic_added_many($inputs, delta, $net, $state)?;

        let mut res = vec![Rep3PrimeFieldShare::zero_share(); $output_size];

        match $state.id {
            PartyID::ID0 => {
                for res in res.iter_mut() {
                    let k3 = $state.rngs.bitcomp2.random_fes_3keys::<F>();
                    res.b = (k3.0 + k3.1 + k3.2).neg();
                }

                // TODO this can be parallelized with joint_input_arithmetic_added_many
                let x23 = yao::input_field_id2_many::<F, _>(None, None, $output_size, $net, $state)?;

                let mut evaluator = yao::evaluator::Rep3Evaluator::new($net);
                evaluator.receive_circuit()?;

                let x1 = $circuit(&mut evaluator, &x01, &x2, &x23, $($args),*);
                let x1 = yao::GCUtils::garbled_circuits_error(x1)?;
                let x1 = evaluator.output_to_id0_and_id1(x1.wires())?;

                // Compose the bits
                for (res, x1) in izip!(res.iter_mut(), x1.chunks(F::MODULUS_BIT_SIZE as usize)) {
                    res.a = yao::GCUtils::bits_to_field(x1)?;
                }
            }
            PartyID::ID1 => {
                for res in res.iter_mut() {
                    let k2 = $state.rngs.bitcomp1.random_fes_3keys::<F>();
                    res.a = (k2.0 + k2.1 + k2.2).neg();
                }

                // TODO this can be parallelized with joint_input_arithmetic_added_many
                let x23 = yao::input_field_id2_many::<F, _>(None, None, $output_size, $net, $state)?;

                let mut garbler =
                    yao::garbler::Rep3Garbler::new_with_delta($net, $state, delta.expect("Delta not provided"));

                let x1 = $circuit(&mut garbler, &x01, &x2, &x23, $($args),*);
                let x1 = yao::GCUtils::garbled_circuits_error(x1)?;
                let x1 = garbler.output_to_id0_and_id1(x1.wires())?;
                let x1 = x1.ok_or(eyre::eyre!("No output received"))?;

                // Compose the bits
                for (res, x1) in izip!(res.iter_mut(), x1.chunks(F::MODULUS_BIT_SIZE as usize)) {
                    res.b = yao::GCUtils::bits_to_field(x1)?;
                }
            }
            PartyID::ID2 => {
                let mut x23 = Vec::with_capacity($output_size);
                for res in res.iter_mut() {
                    let k2 = $state.rngs.bitcomp1.random_fes_3keys::<F>();
                    let k3 = $state.rngs.bitcomp2.random_fes_3keys::<F>();
                    let k2_comp = k2.0 + k2.1 + k2.2;
                    let k3_comp = k3.0 + k3.1 + k3.2;
                    x23.push(k2_comp + k3_comp);
                    res.a = k3_comp.neg();
                    res.b = k2_comp.neg();
                }

                // TODO this can be parallelized with joint_input_arithmetic_added_many
                let x23 = yao::input_field_id2_many(Some(x23), delta, $output_size, $net, $state)?;

                let mut garbler =
                   yao::garbler::Rep3Garbler::new_with_delta($net, $state, delta.expect("Delta not provided"));

                let x1 = $circuit(&mut garbler, &x01, &x2, &x23, $($args),*);
                let x1 = yao::GCUtils::garbled_circuits_error(x1)?;
                let x1 = garbler.output_to_id0_and_id1(x1.wires())?;
                if x1.is_some() {
                    eyre::bail!(
                        "Unexpected output received",
                    );
                }
            }
        }

        Ok(res)
    }};
}
pub(crate) use decompose_circuit_compose_blueprint;

// Returns the output as binary share
#[expect(unused_macros)]
macro_rules! decompose_circuit_compose_blueprint_to_binary {
    ($inputs:expr, $io_context:expr, $output_size:expr, $circuit:expr, ($( $args:expr ),*)) => {{
   use $crate::protocols::rep3::yao;
        use mpc_types::protocols::rep3::{id::PartyID, };
        use crate::protocols::rep3::conversion::y2b_many;

        let delta = $io_context
            .rngs
            .generate_random_garbler_delta($io_context.id);

        let [x01, x2] = yao::joint_input_arithmetic_added_many($inputs, delta, $io_context)?;

      let res=  match $io_context.id {
            PartyID::ID0 => {
                // TODO this can be parallelized with joint_input_arithmetic_added_many
                let x23 = yao::input_field_id2_many::<F, _>(None, None, $output_size, $io_context)?;

                let mut evaluator = yao::evaluator::Rep3Evaluator::new($io_context);
                evaluator.receive_circuit()?;

                let x1 = $circuit(&mut evaluator, &x01, &x2, &x23, $($args),*);
                let x1 = yao::GCUtils::garbled_circuits_error(x1)?;
                let mut x1_vec= Vec::new();
                for chunk in x1.wires().chunks(F::MODULUS_BIT_SIZE as usize) {
                    x1_vec.push(BinaryBundle::new(chunk.to_vec()));
                }
                 y2b_many(x1_vec,  $io_context)?
            }
            PartyID::ID1 => {
                // TODO this can be parallelized with joint_input_arithmetic_added_many
                let x23 = yao::input_field_id2_many::<F, _>(None, None, $output_size, $io_context)?;

                let mut garbler =
                    yao::garbler::Rep3Garbler::new_with_delta($io_context, delta.expect("Delta not provided"));

                let x1 = $circuit(&mut garbler, &x01, &x2, &x23, $($args),*);
                let x1 = yao::GCUtils::garbled_circuits_error(x1)?;
                let mut x1_vec= Vec::new();
                for chunk in x1.wires().chunks(F::MODULUS_BIT_SIZE as usize) {
                    x1_vec.push(BinaryBundle::new(chunk.to_vec()));
                }
                y2b_many(x1_vec,  $io_context)?
            }
            PartyID::ID2 => {
                let mut x23 = Vec::with_capacity($output_size);
                for _ in 0..$output_size {
                    let k2 = $io_context.rngs.bitcomp1.random_fes_3keys::<F>();
                    let k3 = $io_context.rngs.bitcomp2.random_fes_3keys::<F>();
                    let k2_comp = k2.0 + k2.1 + k2.2;
                    let k3_comp = k3.0 + k3.1 + k3.2;
                    x23.push(k2_comp + k3_comp);
                }

                // TODO this can be parallelized with joint_input_arithmetic_added_many
                let x23 = yao::input_field_id2_many(Some(x23), delta, $output_size, $io_context)?;

                let mut garbler =
                   yao::garbler::Rep3Garbler::new_with_delta($io_context, delta.expect("Delta not provided"));

                let x1 = $circuit(&mut garbler, &x01, &x2, &x23, $($args),*);
                let x1 = yao::GCUtils::garbled_circuits_error(x1)?;
                let mut x1_vec= Vec::new();
                for chunk in x1.wires().chunks(F::MODULUS_BIT_SIZE as usize) {
                    x1_vec.push(BinaryBundle::new(chunk.to_vec()));
                }
                y2b_many(x1_vec,  $io_context)?
            }
        };

        Ok(res)
    }};
}

// TODO implement with a2b/b2a as well

/// Decomposes a vector of shared field element into chunks, which are also represented as shared field elements. Per field element, the total bit size of the shared chunks is given by total_bit_size_per_field, whereas each chunk has at most (i.e, the last chunk can be smaller) decompose_bit_size bits.
pub fn decompose_arithmetic_many<F: PrimeField, N: Network>(
    inputs: &[Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut Rep3State,
    total_bit_size_per_field: usize,
    decompose_bit_size: usize,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let num_inputs = inputs.len();
    let num_decomps_per_field = total_bit_size_per_field.div_ceil(decompose_bit_size);
    let total_output_elements = num_decomps_per_field * num_inputs;

    decompose_circuit_compose_blueprint!(
        inputs,
        net,
        state,
        total_output_elements,
        GarbledCircuits::decompose_field_element_many::<_, F>,
        (decompose_bit_size, total_bit_size_per_field)
    )
}

/// Slices a vector of shared field elements at given indices (msb, lsb), both included in the slice.
/// Only consideres bitsize bits.
/// Result (per input) is thus [lo, slice, hi], where slice has all bits from lsb to msb, lo all bits smaller than lsb, and hi all bits greater msb up to bitsize.
pub fn slice_arithmetic_many<F: PrimeField, N: Network>(
    inputs: &[Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut Rep3State,
    msb: usize,
    lsb: usize,
    bitsize: usize,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let num_inputs = inputs.len();
    let total_output_elements = 3 * num_inputs;
    decompose_circuit_compose_blueprint!(
        inputs,
        net,
        state,
        total_output_elements,
        GarbledCircuits::slice_field_element_many::<_, F>,
        (msb, lsb, bitsize)
    )
}

/// Slices two vectors of field elements, does XOR on the slices and then rotates them. The rotation is done on 64-bit values. Base_bit is the size of the slice, rotation the the length of the rotation and total_output_bitlen_per_field is the amount of bits per input.
pub fn slice_xor_with_filter_many<F: PrimeField, N: Network>(
    input1: &[Rep3PrimeFieldShare<F>],
    input2: &[Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut Rep3State,
    base_bits: &[u64],
    rotation: &[usize],
    filter: &[bool],
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let num_inputs = input1.len();
    debug_assert_eq!(num_inputs, input2.len());
    let num_decomps_per_field = base_bits.len();
    let total_output_elements = 3 * num_decomps_per_field * num_inputs;
    let mut combined_inputs = Vec::with_capacity(num_inputs + input2.len());
    combined_inputs.extend_from_slice(input1);
    combined_inputs.extend_from_slice(input2);

    decompose_circuit_compose_blueprint!(
        &combined_inputs,
        net,
        state,
        total_output_elements,
        GarbledCircuits::slice_and_get_xor_rotate_values_from_key_with_filter_many::<_, F>,
        (base_bits, rotation, filter)
    )
}

/// Slices two vectors of field elements, does XOR on the slices and then rotates them. The rotation is done on 64-bit values. Base_bit is the size of the slice, rotation the the length of the rotation and total_output_bitlen_per_field is the amount of bits per input.
pub fn slice_xor_many<F: PrimeField, N: Network>(
    input1: &[Rep3PrimeFieldShare<F>],
    input2: &[Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut Rep3State,
    base_bit: usize,
    rotation: usize,
    total_output_bitlen_per_field: usize,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let num_inputs = input1.len();
    debug_assert_eq!(num_inputs, input2.len());
    let num_decomps_per_field = total_output_bitlen_per_field.div_ceil(base_bit);
    let total_output_elements = 3 * num_decomps_per_field * num_inputs;

    let mut combined_inputs = Vec::with_capacity(num_inputs + input2.len());
    combined_inputs.extend_from_slice(input1);
    combined_inputs.extend_from_slice(input2);

    decompose_circuit_compose_blueprint!(
        &combined_inputs,
        net,
        state,
        total_output_elements,
        GarbledCircuits::slice_and_get_xor_rotate_values_from_key_many::<_, F>,
        (base_bit, rotation, total_output_bitlen_per_field)
    )
}

/// Slices two vectors of field elements, does AND on the slices and then rotates them. The rotation is done on 64-bit values. Base_bit is the size of the slice, rotation the the length of the rotation and total_output_bitlen_per_field is the amount of bits per input.
pub fn slice_and_many<F: PrimeField, N: Network>(
    input1: &[Rep3PrimeFieldShare<F>],
    input2: &[Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut Rep3State,
    base_bit: usize,
    rotation: usize,
    total_output_bitlen_per_field: usize,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let num_inputs = input1.len();
    debug_assert_eq!(num_inputs, input2.len());
    let num_decomps_per_field = total_output_bitlen_per_field.div_ceil(base_bit);
    let total_output_elements = 3 * num_decomps_per_field * num_inputs;
    let mut combined_inputs = Vec::with_capacity(num_inputs + input2.len());
    combined_inputs.extend_from_slice(input1);
    combined_inputs.extend_from_slice(input2);

    decompose_circuit_compose_blueprint!(
        &combined_inputs,
        net,
        state,
        total_output_elements,
        GarbledCircuits::slice_and_get_and_rotate_values_from_key_many::<_, F>,
        (base_bit, rotation, total_output_bitlen_per_field)
    )
}

/// Slices two field elements, does AND on the slices and then rotates them. The rotation is done on 64-bit values. Base_bit is the size of the slice, rotation the the length of the rotation and total_output_bitlen_per_field is the amount of bits per input.
pub fn slice_and<F: PrimeField, N: Network>(
    input1: Rep3PrimeFieldShare<F>,
    input2: Rep3PrimeFieldShare<F>,
    net: &N,
    state: &mut Rep3State,
    base_bit: usize,
    rotation: usize,
    total_output_bitlen_per_field: usize,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    slice_and_many(
        &[input1],
        &[input2],
        net,
        state,
        base_bit,
        rotation,
        total_output_bitlen_per_field,
    )
}

/// Slices two field elements, does XOR on the slices and then rotates them. The rotation is done on 64-bit values. Base_bit is the size of the slice, rotation the the length of the rotation and total_output_bitlen_per_field is the amount of bits per input.
pub fn slice_xor<F: PrimeField, N: Network>(
    input1: Rep3PrimeFieldShare<F>,
    input2: Rep3PrimeFieldShare<F>,
    net: &N,
    state: &mut Rep3State,
    base_bit: usize,
    rotation: usize,
    total_output_bitlen_per_field: usize,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    slice_xor_many(
        &[input1],
        &[input2],
        net,
        state,
        base_bit,
        rotation,
        total_output_bitlen_per_field,
    )
}

/// Computes the SHA256 compression function using a Bristol fashion garbled circuit.
pub fn sha256_from_bristol<F: PrimeField, N: Network>(
    state: &[Rep3PrimeFieldShare<F>; 8],
    message: &[Rep3PrimeFieldShare<F>; 16],
    net: &N,
    rep3_state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let mut combined_inputs = Vec::with_capacity(state.len() + message.len());
    combined_inputs.extend_from_slice(state);
    combined_inputs.extend_from_slice(message);
    let total_output_elements = state.len();

    decompose_circuit_compose_blueprint!(
        &combined_inputs,
        net,
        rep3_state,
        total_output_elements,
        GarbledCircuits::sha256_compression::<_, F>,
        (state.len())
    )
}

/// Slices two slices of field elements, does XOR on the slices and then rotates them. The rotation is done on 32-bit values. Base_bit is the size of the slices, rotation the the length of the rotation and total_output_bitlen_per_field is the amount of bits per input. It also prepares the (rotated) slices into 32 bits such that these can be multiplied with the base powers and then summed up. See get_sparse_table_with_rotation_values in co-noir/co-builder/src/types/plookup.rs for the intended functionality.
pub fn get_sparse_table_with_rotation_values_many<F: PrimeField, N: Network>(
    input1: &[Rep3PrimeFieldShare<F>],
    input2: &[Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut Rep3State,
    base_bits: &[u64],
    rotation: &[u32],
    total_input_bitlen_per_field: usize,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let num_inputs = input1.len() + input2.len();
    debug_assert_eq!(input1.len(), input2.len());
    let num_decomps_per_field = base_bits.len();
    let total_output_elements =
        num_inputs * num_decomps_per_field + 32 * 2 * (num_inputs / 2) * num_decomps_per_field;
    let mut combined_inputs = Vec::with_capacity(num_inputs + input2.len());
    combined_inputs.extend_from_slice(input1);
    combined_inputs.extend_from_slice(input2);

    decompose_circuit_compose_blueprint!(
        &combined_inputs,
        net,
        state,
        total_output_elements,
        GarbledCircuits::slice_and_get_sparse_table_with_rotation_values_many::<_, F>,
        (base_bits, rotation, total_input_bitlen_per_field)
    )
}

/// Slices two field elements, does XOR on the slices and then rotates them. The rotation is done on 32-bit values. Base_bit is the size of the slices, rotation the the length of the rotation and total_output_bitlen_per_field is the amount of bits per input. It also prepares the (rotated) slices into 32 bits such that these can be multiplied with the base powers and then summed up. See get_sparse_table_with_rotation_values in co-noir/co-builder/src/types/plookup.rs for the intended functionality.
pub fn get_sparse_table_with_rotation_values<F: PrimeField, N: Network>(
    input1: Rep3PrimeFieldShare<F>,
    input2: Rep3PrimeFieldShare<F>,
    net: &N,
    state: &mut Rep3State,
    base_bits: &[u64],
    rotation: &[u32],
    total_input_bitlen_per_field: usize,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    get_sparse_table_with_rotation_values_many(
        &[input1],
        &[input2],
        net,
        state,
        base_bits,
        rotation,
        total_input_bitlen_per_field,
    )
}

/// Slices two slices of field elements according to base_bits, and again slices these slices according to base. These slices are used as indices for the respective SHA256Table which is done via a Moebius Transformation Matrix.
#[expect(clippy::too_many_arguments)]
pub fn get_sparse_normalization_values_many<F: PrimeField, N: Network>(
    input1: &[Rep3PrimeFieldShare<F>],
    input2: &[Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut Rep3State,
    base_bits: &[u64],
    base: u64,
    total_input_bitlen_per_field: usize,
    table_type: &SHA256Table,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let num_inputs = input1.len() + input2.len();
    debug_assert_eq!(input1.len(), input2.len());
    let num_decomps_per_field = base_bits.len();
    let total_output_elements = 3 * num_decomps_per_field * (num_inputs / 2);
    let mut combined_inputs = Vec::with_capacity(num_inputs);
    combined_inputs.extend_from_slice(input1);
    combined_inputs.extend_from_slice(input2);

    decompose_circuit_compose_blueprint!(
        &combined_inputs,
        net,
        state,
        total_output_elements,
        GarbledCircuits::slice_and_get_sparse_normalization_values_many::<_, F>,
        (base_bits, base, total_input_bitlen_per_field, table_type)
    )
}

/// Slices two field elements according to base_bits, and again slices these slices according to base. These slices are used as indices for the respective SHA256Table which is done via a Moebius Transformation Matrix.
#[expect(clippy::too_many_arguments)]
pub fn get_sparse_normalization_values<F: PrimeField, N: Network>(
    input1: Rep3PrimeFieldShare<F>,
    input2: Rep3PrimeFieldShare<F>,
    net: &N,
    state: &mut Rep3State,
    base_bits: &[u64],
    base: u64,
    total_input_bitlen_per_field: usize,
    table_type: &SHA256Table,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    get_sparse_normalization_values_many(
        &[input1],
        &[input2],
        net,
        state,
        base_bits,
        base,
        total_input_bitlen_per_field,
        table_type,
    )
}

/// Slices two field elements, does XOR on the slices and then rotates them. The rotation is done on 64-bit values. Base_bit is the size of the slice, rotation the the length of the rotation and total_output_bitlen_per_field is the amount of bits per input.
pub fn slice_xor_with_filter<F: PrimeField, N: Network>(
    input1: Rep3PrimeFieldShare<F>,
    input2: Rep3PrimeFieldShare<F>,
    net: &N,
    state: &mut Rep3State,
    base_bit: &[u64],
    rotation: &[usize],
    filter: &[bool],
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    slice_xor_with_filter_many(&[input1], &[input2], net, state, base_bit, rotation, filter)
}

/// Computes the BLAKE2s hash of 'num_inputs' inputs, each of 'num_bits' bits (rounded to next multiple of 8). The output is then composed into size 32 Vec of field elements.
pub fn blake2s<F: PrimeField, N: Network>(
    input1: &[Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut Rep3State,
    num_bits: &[usize],
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let total_output_elements = 32;
    let num_inputs = input1.len();

    decompose_circuit_compose_blueprint!(
        &input1,
        net,
        state,
        total_output_elements,
        GarbledCircuits::blake2s::<_, F>,
        (num_inputs, num_bits)
    )
}

/// Computes the BLAKE3 hash of 'num_inputs' inputs, each of 'num_bits' bits (rounded to next multiple of 8). The output is then composed into size 32 Vec of field elements.
pub fn blake3<F: PrimeField, N: Network>(
    input1: &[Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut Rep3State,
    num_bits: &[usize],
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let total_output_elements = 32;
    let num_inputs = input1.len();

    decompose_circuit_compose_blueprint!(
        &input1,
        net,
        state,
        total_output_elements,
        GarbledCircuits::blake3::<_, F>,
        (num_inputs, num_bits)
    )
}

/// Slices two vecs of field elements according to base_bits, and again slices these slices according to base. These slices are then returned as arithmetic shares of the binary representation for the AES normalization values.
pub fn slice_and_map_from_sparse_form_many<F: PrimeField, N: Network>(
    input1: &[Rep3PrimeFieldShare<F>],
    input2: &[Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut Rep3State,
    base_bits: &[u64],
    base: u64,
    total_input_bitlen_per_field: usize,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let num_inputs = input1.len() + input2.len();
    debug_assert_eq!(input1.len(), input2.len());
    let num_decomps_per_field = base_bits.len();
    let total_output_elements =
        num_inputs * num_decomps_per_field + 8 * (num_inputs / 2) * num_decomps_per_field;
    let mut combined_inputs = Vec::with_capacity(num_inputs);
    combined_inputs.extend_from_slice(input1);
    combined_inputs.extend_from_slice(input2);

    decompose_circuit_compose_blueprint!(
        &combined_inputs,
        net,
        state,
        total_output_elements,
        GarbledCircuits::slice_and_map_from_sparse_form_many::<_, F>,
        (
            base_bits,
            base,
            total_input_bitlen_per_field,
            circuits::ReturnType::BinaryAsArithmetic
        )
    )
}

/// Slices two field elements according to base_bits, and again slices these slices according to base. These slices are then returned as arithmetic shares of the binary representation for the AES normalization values.
pub fn slice_and_map_from_sparse_form<F: PrimeField, N: Network>(
    input1: Rep3PrimeFieldShare<F>,
    input2: Rep3PrimeFieldShare<F>,
    net: &N,
    state: &mut Rep3State,
    base_bits: &[u64],
    base: u64,
    total_input_bitlen_per_field: usize,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    slice_and_map_from_sparse_form_many(
        &[input1],
        &[input2],
        net,
        state,
        base_bits,
        base,
        total_input_bitlen_per_field,
    )
}

/// Slices two vecs of field elements according to base_bits, and again slices these slices according to base. These slices are then used to compute the AES sbox values.
pub fn slice_and_map_from_sparse_form_many_sbox<F: PrimeField, N: Network>(
    input1: &[Rep3PrimeFieldShare<F>],
    input2: &[Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut Rep3State,
    base_bits: &[u64],
    base: u64,
    total_input_bitlen_per_field: usize,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let num_inputs = input1.len() + input2.len();
    debug_assert_eq!(input1.len(), input2.len());
    let num_decomps_per_field = base_bits.len();
    let total_output_elements =
        num_inputs * num_decomps_per_field + (num_inputs / 2) * num_decomps_per_field;
    let mut combined_inputs = Vec::with_capacity(num_inputs);
    combined_inputs.extend_from_slice(input1);
    combined_inputs.extend_from_slice(input2);

    decompose_circuit_compose_blueprint!(
        &combined_inputs,
        net,
        state,
        total_output_elements,
        GarbledCircuits::slice_and_map_from_sparse_form_many::<_, F>,
        (
            base_bits,
            base,
            total_input_bitlen_per_field,
            circuits::ReturnType::Arithmetic
        )
    )
}

/// Slices two field elements according to base_bits, and again slices these slices according to base. These slices are then used to compute the AES sbox values.
pub fn slice_and_map_from_sparse_form_sbox<F: PrimeField, N: Network>(
    input1: Rep3PrimeFieldShare<F>,
    input2: Rep3PrimeFieldShare<F>,
    net: &N,
    state: &mut Rep3State,
    base_bits: &[u64],
    base: u64,
    total_input_bitlen_per_field: usize,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    slice_and_map_from_sparse_form_many_sbox(
        &[input1],
        &[input2],
        net,
        state,
        base_bits,
        base,
        total_input_bitlen_per_field,
    )
}

/// Slices a vector of field elements according to base and computes an accumulator necessary for the AES argument.
pub fn accumulate_from_sparse_bytes<F: PrimeField, N: Network>(
    input: &[Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut Rep3State,
    input_bitsize: usize,
    output_bitsize: usize,
    base: u64,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let total_output_elements = 1;

    decompose_circuit_compose_blueprint!(
        &input,
        net,
        state,
        total_output_elements,
        GarbledCircuits::accumulate_from_sparse_bytes::<_, F>,
        (input_bitsize, output_bitsize, base)
    )
}

/// Computes wnaf digits and rows needed in the ECCVM builder.
pub fn compute_wnaf_digits_and_compute_rows_many<F: PrimeField, N: Network>(
    input: &[Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut Rep3State,
    input_bitsize: usize,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let total_output_elements = input.len() * (32 + 32 + 1 + 8 * 8 + 8 + 8);

    decompose_circuit_compose_blueprint!(
        &input,
        net,
        state,
        total_output_elements,
        GarbledCircuits::compute_wnaf_digits_many::<_, F>,
        (input_bitsize)
    )
}
