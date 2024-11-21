//! Yao
//!
//! This module contains operations with Yao's garbled circuits

use super::{
    arithmetic::types::Rep3RingShare,
    ring::{int_ring::IntRing2k, ring_impl::RingElement},
};
use crate::protocols::rep3::{
    id::PartyID,
    network::{IoContext, Rep3Network},
    yao::{GCInputs, GCUtils},
    IoResult,
};
use fancy_garbling::{BinaryBundle, WireLabel, WireMod2};
use num_traits::{One, Zero};
use rand::{CryptoRng, Rng};

impl GCUtils {
    /// Converts bits into a ring element
    pub fn bits_to_ring<T: IntRing2k>(bits: &[bool]) -> IoResult<RingElement<T>> {
        if bits.len() > T::K {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid number of bits",
            ));
        }

        let mut res = RingElement::zero();
        for bit in bits.iter().rev() {
            res <<= 1;
            res |= RingElement(T::from(*bit));
        }

        Ok(res)
    }

    fn ring_to_bits_as_u16<T: IntRing2k>(input: RingElement<T>) -> Vec<u16> {
        let mut res = Vec::with_capacity(T::K);
        let mut el = input;
        for _ in 0..T::K {
            res.push(((el & RingElement::one()) == RingElement::one()) as u16);
            el <<= 1;
        }
        res
    }

    /// This puts the X_0 values into garbler_wires and X_c values into evaluator_wires
    pub fn encode_ring<T: IntRing2k, R: Rng + CryptoRng>(
        ring: RingElement<T>,
        rng: &mut R,
        delta: WireMod2,
    ) -> GCInputs<WireMod2> {
        let bits = Self::ring_to_bits_as_u16(ring);
        Self::encode_bits(bits, rng, delta)
    }

    pub(crate) fn collapse_bundle_to_lsb_bits_as_ring<T: IntRing2k>(
        input: BinaryBundle<WireMod2>,
    ) -> IoResult<RingElement<T>> {
        let bitlen = input.size();
        if bitlen > T::K {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Bit length exceeds K",
            ));
        }

        let mut res = RingElement::zero();
        for wire in input.wires().iter().rev() {
            res <<= 1;
            let lsb = wire.color();
            debug_assert!(lsb < 2);
            res |= RingElement(T::from(lsb & 1 == 1));
        }
        Ok(res)
    }
}

/// Transforms an arithmetically shared input x = (x_1, x_2, x_3) into two yao shares x_1^Y, (x_2 + x_3)^Y. The used delta is an input to the function to allow for the same delta to be used for multiple conversions.
pub fn joint_input_arithmetic_added<T: IntRing2k, N: Rep3Network>(
    x: Rep3RingShare<T>,
    delta: Option<WireMod2>,
    io_context: &mut IoContext<N>,
) -> IoResult<[BinaryBundle<WireMod2>; 2]> {
    joint_input_arithmetic_added_many(&[x], delta, io_context)
}

/// Transforms a vector of arithmetically shared inputs x = (x_1, x_2, x_3) into two yao shares x_1^Y, (x_2 + x_3)^Y. The used delta is an input to the function to allow for the same delta to be used for multiple conversions.
pub fn joint_input_arithmetic_added_many<T: IntRing2k, N: Rep3Network>(
    x: &[Rep3RingShare<T>],
    delta: Option<WireMod2>,
    io_context: &mut IoContext<N>,
) -> IoResult<[BinaryBundle<WireMod2>; 2]> {
    let id = io_context.id;
    let n_inputs = x.len();
    let n_bits = T::K;
    let bits = n_inputs * n_bits;

    let (x01, x2) = match id {
        PartyID::ID0 => {
            // Receive x0
            let x01 = GCUtils::receive_bundle_from(bits, &mut io_context.network, PartyID::ID1)?;

            // Receive x2
            let x2 = GCUtils::receive_bundle_from(bits, &mut io_context.network, PartyID::ID2)?;
            (x01, x2)
        }
        PartyID::ID1 => {
            let delta = match delta {
                Some(delta) => delta,
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "No delta provided",
                ))?,
            };

            let mut garbler_bundle = Vec::with_capacity(bits);
            let mut evaluator_bundle = Vec::with_capacity(bits);

            // Input x01
            for x in x.iter() {
                let sum = x.a + x.b;
                let bits = GCUtils::ring_to_bits_as_u16(sum);
                let (garbler, evaluator) =
                    GCUtils::encode_bits_as_wires(bits, &mut io_context.rng, delta);
                garbler_bundle.extend(garbler);
                evaluator_bundle.extend(evaluator);
            }
            let x01 = GCUtils::wires_to_gcinput(garbler_bundle, evaluator_bundle, delta);

            // Send x01 to the other parties
            GCUtils::send_inputs(&x01, &mut io_context.network, PartyID::ID2)?;
            let x01 = x01.garbler_wires;

            // Receive x2
            let x2 = GCUtils::receive_bundle_from(bits, &mut io_context.network, PartyID::ID2)?;
            (x01, x2)
        }
        PartyID::ID2 => {
            let delta = match delta {
                Some(delta) => delta,
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "No delta provided",
                ))?,
            };

            let mut garbler_bundle = Vec::with_capacity(bits);
            let mut evaluator_bundle = Vec::with_capacity(bits);

            // Input x2
            for x in x.iter() {
                let bits = GCUtils::ring_to_bits_as_u16(x.a);
                let (garbler, evaluator) =
                    GCUtils::encode_bits_as_wires(bits, &mut io_context.rng, delta);
                garbler_bundle.extend(garbler);
                evaluator_bundle.extend(evaluator);
            }
            let x2 = GCUtils::wires_to_gcinput(garbler_bundle, evaluator_bundle, delta);

            // Send x2 to the other parties
            GCUtils::send_inputs(&x2, &mut io_context.network, PartyID::ID1)?;
            let x2 = x2.garbler_wires;

            // Receive x01
            let x01 = GCUtils::receive_bundle_from(bits, &mut io_context.network, PartyID::ID1)?;
            (x01, x2)
        }
    };

    Ok([x01, x2])
}

/// Lets the party with id2 input a vector field elements, which gets shared as Yao wires to the other parties.
pub fn input_ring_id2_many<T: IntRing2k, N: Rep3Network>(
    x: Option<Vec<RingElement<T>>>,
    delta: Option<WireMod2>,
    n_inputs: usize,
    io_context: &mut IoContext<N>,
) -> IoResult<BinaryBundle<WireMod2>> {
    let id = io_context.id;
    let n_bits = T::K;
    let bits = n_inputs * n_bits;

    let x = match id {
        PartyID::ID0 | PartyID::ID1 => {
            // Receive x
            GCUtils::receive_bundle_from(bits, &mut io_context.network, PartyID::ID2)?
        }
        PartyID::ID2 => {
            let delta = match delta {
                Some(delta) => delta,
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "No delta provided",
                ))?,
            };

            let x = match x {
                Some(x) => x,
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "No input provided",
                ))?,
            };

            if x.len() != n_inputs {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Invalid number of inputs",
                ));
            }

            let mut garbler_bundle = Vec::with_capacity(bits);
            let mut evaluator_bundle = Vec::with_capacity(bits);

            // Input x1
            for x in x {
                let bits = GCUtils::ring_to_bits_as_u16(x);
                let (garbler, evaluator) =
                    GCUtils::encode_bits_as_wires(bits, &mut io_context.rng, delta);
                garbler_bundle.extend(garbler);
                evaluator_bundle.extend(evaluator);
            }
            let x = GCUtils::wires_to_gcinput(garbler_bundle, evaluator_bundle, delta);

            // Send x to the other parties
            GCUtils::send_inputs(&x, &mut io_context.network, PartyID::ID1)?;
            x.garbler_wires
        }
    };
    Ok(x)
}

/// Lets the party with id2 input a field element, which gets shared as Yao wires to the other parties.
pub fn input_ring_id2<T: IntRing2k, N: Rep3Network>(
    x: Option<RingElement<T>>,
    delta: Option<WireMod2>,
    io_context: &mut IoContext<N>,
) -> IoResult<BinaryBundle<WireMod2>> {
    let x = x.map(|x| vec![x]);
    input_ring_id2_many(x, delta, 1, io_context)
}

/// Transforms an binary shared input x = (x_1, x_2, x_3) into two yao shares x_1^Y, (x_2 xor x_3)^Y. The used delta is an input to the function to allow for the same delta to be used for multiple conversions.
pub fn joint_input_binary_xored<T: IntRing2k, N: Rep3Network>(
    x: &Rep3RingShare<T>,
    delta: Option<WireMod2>,
    io_context: &mut IoContext<N>,
) -> IoResult<[BinaryBundle<WireMod2>; 2]> {
    let id = io_context.id;
    let bitlen = T::K;

    let (x01, x2) = match id {
        PartyID::ID0 => {
            // Receive x01
            let x01 = GCUtils::receive_bundle_from(bitlen, &mut io_context.network, PartyID::ID1)?;

            // Receive x2
            let x2 = GCUtils::receive_bundle_from(bitlen, &mut io_context.network, PartyID::ID2)?;
            (x01, x2)
        }
        PartyID::ID1 => {
            let delta = match delta {
                Some(delta) => delta,
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "No delta provided",
                ))?,
            };

            // Input x01
            let xor = x.a ^ x.b;
            let x01 = GCUtils::encode_ring(xor, &mut io_context.rng, delta);

            // Send x01 to the other parties
            GCUtils::send_inputs(&x01, &mut io_context.network, PartyID::ID2)?;
            let x01 = x01.garbler_wires;

            // Receive x2
            let x2 = GCUtils::receive_bundle_from(bitlen, &mut io_context.network, PartyID::ID2)?;
            (x01, x2)
        }
        PartyID::ID2 => {
            let delta = match delta {
                Some(delta) => delta,
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "No delta provided",
                ))?,
            };

            // Input x2
            let x2 = GCUtils::encode_ring(x.a, &mut io_context.rng, delta);

            // Send x2 to the other parties
            GCUtils::send_inputs(&x2, &mut io_context.network, PartyID::ID1)?;
            let x2 = x2.garbler_wires;

            // Receive x01
            let x01 = GCUtils::receive_bundle_from(bitlen, &mut io_context.network, PartyID::ID1)?;
            (x01, x2)
        }
    };

    Ok([x01, x2])
}
