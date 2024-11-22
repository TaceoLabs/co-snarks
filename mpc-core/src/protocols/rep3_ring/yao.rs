//! Yao
//!
//! This module contains operations with Yao's garbled circuits

use super::{
    arithmetic::types::Rep3RingShare,
    ring::{bit::Bit, int_ring::IntRing2k, ring_impl::RingElement},
};
use crate::protocols::{
    rep3::{
        self,
        id::PartyID,
        network::{IoContext, Rep3Network},
        yao::{
            circuits::GarbledCircuits, evaluator::Rep3Evaluator, garbler::Rep3Garbler, GCInputs,
            GCUtils,
        },
        IoResult, Rep3BigUintShare, Rep3PrimeFieldShare,
    },
    rep3_ring::conversion,
};
use ark_ff::PrimeField;
use fancy_garbling::{BinaryBundle, WireLabel, WireMod2};
use itertools::izip;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::{distributions::Standard, prelude::Distribution, CryptoRng, Rng};
use std::{any::TypeId, ops::Neg};

mod garbler;
mod streaming_garbler;

impl GCUtils {
    /// Converts bits into a ring element
    pub fn bits_to_ring<T: IntRing2k>(bits: &[bool]) -> IoResult<RingElement<T>> {
        if bits.len() > T::K {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Invalid number of bits: {}, should be: {}",
                    bits.len(),
                    T::K
                ),
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
            el >>= 1;
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
                format!("Bit length exceeds K={}: {}", T::K, bitlen),
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

/// A cast of a vector of Rep3RingShare to a vector of Rep3PrimeFieldShare
pub fn ring_to_field_many<T: IntRing2k, F: PrimeField, N: Rep3Network>(
    inputs: &[Rep3RingShare<T>],
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<Rep3PrimeFieldShare<F>>>
where
    Standard: Distribution<T>,
{
    // Special case for Bit
    if TypeId::of::<T>() == TypeId::of::<Bit>() {
        // SAFTEY: We already checked that the type matches
        let shares =
            unsafe { &*(inputs as *const [Rep3RingShare<T>] as *const [Rep3RingShare<Bit>]) };
        let biguint_shares = shares
            .iter()
            .map(|share| {
                Rep3BigUintShare::new(
                    BigUint::from(share.a.0.convert() as u64),
                    BigUint::from(share.b.0.convert() as u64),
                )
            })
            .collect::<Vec<_>>();

        return rep3::conversion::bit_inject_many(&biguint_shares, io_context);
    }

    // The actual garbled circuit implementation
    let num_inputs = inputs.len();
    let delta = io_context.rngs.generate_random_garbler_delta(io_context.id);

    let [x01, x2] = joint_input_arithmetic_added_many(inputs, delta, io_context)?;

    let mut res = vec![Rep3PrimeFieldShare::zero_share(); num_inputs];

    match io_context.id {
        PartyID::ID0 => {
            for res in res.iter_mut() {
                let k3 = io_context.rngs.bitcomp2.random_fes_3keys::<F>();
                res.b = (k3.0 + k3.1 + k3.2).neg();
            }

            // TODO this can be parallelized with joint_input_arithmetic_added_many
            let x23 = rep3::yao::input_field_id2_many::<F, _>(None, None, num_inputs, io_context)?;

            let mut evaluator = Rep3Evaluator::new(io_context);
            evaluator.receive_circuit()?;

            let x1 =
                GarbledCircuits::ring_to_field_many::<_, F>(&mut evaluator, &x01, &x2, &x23, T::K);
            let x1 = GCUtils::garbled_circuits_error(x1)?;
            let x1 = evaluator.output_to_id0_and_id1(x1.wires())?;

            // Compose the bits
            for (res, x1) in izip!(res.iter_mut(), x1.chunks(F::MODULUS_BIT_SIZE as usize)) {
                res.a = GCUtils::bits_to_field(x1)?;
            }
        }
        PartyID::ID1 => {
            for res in res.iter_mut() {
                let k2 = io_context.rngs.bitcomp1.random_fes_3keys::<F>();
                res.a = (k2.0 + k2.1 + k2.2).neg();
            }

            // TODO this can be parallelized with joint_input_arithmetic_added_many
            let x23 = rep3::yao::input_field_id2_many::<F, _>(None, None, num_inputs, io_context)?;

            let mut garbler =
                Rep3Garbler::new_with_delta(io_context, delta.expect("Delta not provided"));

            let x1 =
                GarbledCircuits::ring_to_field_many::<_, F>(&mut garbler, &x01, &x2, &x23, T::K);
            let x1 = GCUtils::garbled_circuits_error(x1)?;
            let x1 = garbler.output_to_id0_and_id1(x1.wires())?;
            let x1 = match x1 {
                Some(x1) => x1,
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "No output received",
                ))?,
            };

            // Compose the bits
            for (res, x1) in izip!(res.iter_mut(), x1.chunks(F::MODULUS_BIT_SIZE as usize)) {
                res.b = GCUtils::bits_to_field(x1)?;
            }
        }
        PartyID::ID2 => {
            let mut x23 = Vec::with_capacity(num_inputs);
            for res in res.iter_mut() {
                let k2 = io_context.rngs.bitcomp1.random_fes_3keys::<F>();
                let k3 = io_context.rngs.bitcomp2.random_fes_3keys::<F>();
                let k2_comp = k2.0 + k2.1 + k2.2;
                let k3_comp = k3.0 + k3.1 + k3.2;
                x23.push(k2_comp + k3_comp);
                res.a = k3_comp.neg();
                res.b = k2_comp.neg();
            }

            // TODO this can be parallelized with joint_input_arithmetic_added_many
            let x23 = rep3::yao::input_field_id2_many(Some(x23), delta, num_inputs, io_context)?;

            let mut garbler =
                Rep3Garbler::new_with_delta(io_context, delta.expect("Delta not provided"));

            let x1 =
                GarbledCircuits::ring_to_field_many::<_, F>(&mut garbler, &x01, &x2, &x23, T::K);
            let x1 = GCUtils::garbled_circuits_error(x1)?;
            let x1 = garbler.output_to_id0_and_id1(x1.wires())?;
            if x1.is_some() {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Unexpected output received",
                ))?;
            }
        }
    }

    Ok(res)
}

/// A cast of a vector of Rep3PrimeFieldShare to a vector of Rep3RingShare
pub fn field_to_ring_many<F: PrimeField, T: IntRing2k, N: Rep3Network>(
    inputs: &[Rep3PrimeFieldShare<F>],
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<Rep3RingShare<T>>>
where
    Standard: Distribution<T>,
{
    let num_inputs = inputs.len();
    let delta = io_context.rngs.generate_random_garbler_delta(io_context.id);

    let [x01, x2] = rep3::yao::joint_input_arithmetic_added_many(inputs, delta, io_context)?;

    let mut res = vec![Rep3RingShare::zero_share(); num_inputs];

    match io_context.id {
        PartyID::ID0 => {
            for res in res.iter_mut() {
                let k3 = io_context
                    .rngs
                    .bitcomp2
                    .random_elements_3keys::<RingElement<T>>();
                res.b = (k3.0 + k3.1 + k3.2).neg();
            }

            // TODO this can be parallelized with joint_input_arithmetic_added_many
            let x23 = input_ring_id2_many::<T, _>(None, None, num_inputs, io_context)?;

            let mut evaluator = Rep3Evaluator::new(io_context);
            evaluator.receive_circuit()?;

            let x1 =
                GarbledCircuits::field_to_ring_many::<_, F>(&mut evaluator, &x01, &x2, &x23, T::K);
            let x1 = GCUtils::garbled_circuits_error(x1)?;
            let x1 = evaluator.output_to_id0_and_id1(x1.wires())?;

            // Compose the bits
            for (res, x1) in izip!(res.iter_mut(), x1.chunks(T::K)) {
                res.a = GCUtils::bits_to_ring(x1)?;
            }
        }
        PartyID::ID1 => {
            for res in res.iter_mut() {
                let k2 = io_context
                    .rngs
                    .bitcomp1
                    .random_elements_3keys::<RingElement<T>>();
                res.a = (k2.0 + k2.1 + k2.2).neg();
            }

            // TODO this can be parallelized with joint_input_arithmetic_added_many
            let x23 = input_ring_id2_many::<T, _>(None, None, num_inputs, io_context)?;

            let mut garbler =
                Rep3Garbler::new_with_delta(io_context, delta.expect("Delta not provided"));

            let x1 =
                GarbledCircuits::field_to_ring_many::<_, F>(&mut garbler, &x01, &x2, &x23, T::K);
            let x1 = GCUtils::garbled_circuits_error(x1)?;
            let x1 = garbler.output_to_id0_and_id1(x1.wires())?;
            let x1 = match x1 {
                Some(x1) => x1,
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "No output received",
                ))?,
            };

            // Compose the bits
            for (res, x1) in izip!(res.iter_mut(), x1.chunks(T::K)) {
                res.b = GCUtils::bits_to_ring(x1)?;
            }
        }
        PartyID::ID2 => {
            let mut x23 = Vec::with_capacity(num_inputs);
            for res in res.iter_mut() {
                let k2 = io_context
                    .rngs
                    .bitcomp1
                    .random_elements_3keys::<RingElement<T>>();
                let k3 = io_context
                    .rngs
                    .bitcomp2
                    .random_elements_3keys::<RingElement<T>>();
                let k2_comp = k2.0 + k2.1 + k2.2;
                let k3_comp = k3.0 + k3.1 + k3.2;
                x23.push(k2_comp + k3_comp);
                res.a = k3_comp.neg();
                res.b = k2_comp.neg();
            }

            // TODO this can be parallelized with joint_input_arithmetic_added_many
            let x23 = input_ring_id2_many(Some(x23), delta, num_inputs, io_context)?;

            let mut garbler =
                Rep3Garbler::new_with_delta(io_context, delta.expect("Delta not provided"));

            let x1 =
                GarbledCircuits::field_to_ring_many::<_, F>(&mut garbler, &x01, &x2, &x23, T::K);
            let x1 = GCUtils::garbled_circuits_error(x1)?;
            let x1 = garbler.output_to_id0_and_id1(x1.wires())?;
            if x1.is_some() {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Unexpected output received",
                ))?;
            }
        }
    }

    Ok(res)
}

macro_rules! decompose_circuit_compose_blueprint {
    ($inputs:expr, $io_context:expr, $output_size:expr, $t:ty, $circuit:expr, ($( $args:expr ),*)) => {{
        use $crate::protocols::rep3::id::PartyID;
        use itertools::izip;
        use $crate::protocols::rep3_ring::yao;
        use $crate::protocols::rep3_ring::Rep3RingShare;

        let delta = $io_context
            .rngs
            .generate_random_garbler_delta($io_context.id);

        let [x01, x2] = yao::joint_input_arithmetic_added_many($inputs, delta, $io_context)?;

        let mut res = vec![Rep3RingShare::zero_share(); $output_size];

        match $io_context.id {
            PartyID::ID0 => {
                for res in res.iter_mut() {
                    let k3 = $io_context.rngs.bitcomp2.random_elements_3keys::<RingElement<$t>>();
                    res.b = (k3.0 + k3.1 + k3.2).neg();
                }

                // TODO this can be parallelized with joint_input_arithmetic_added_many
                let x23 = yao::input_ring_id2_many::<$t, _>(None, None, $output_size, $io_context)?;

                let mut evaluator = rep3::yao::evaluator::Rep3Evaluator::new($io_context);
                evaluator.receive_circuit()?;

                let x1 = $circuit(&mut evaluator, &x01, &x2, &x23, $($args),*);
                let x1 = yao::GCUtils::garbled_circuits_error(x1)?;
                let x1 = evaluator.output_to_id0_and_id1(x1.wires())?;

                // Compose the bits
                for (res, x1) in izip!(res.iter_mut(), x1.chunks(<$t>::K)) {
                    res.a = yao::GCUtils::bits_to_ring(x1)?;
                }
            }
            PartyID::ID1 => {
                for res in res.iter_mut() {
                    let k2 = $io_context.rngs.bitcomp1.random_elements_3keys::<RingElement<$t>>();
                    res.a = (k2.0 + k2.1 + k2.2).neg();
                }

                // TODO this can be parallelized with joint_input_arithmetic_added_many
                let x23 = yao::input_ring_id2_many::<$t, _>(None, None, $output_size, $io_context)?;

                let mut garbler =
                    rep3::yao::garbler::Rep3Garbler::new_with_delta($io_context, delta.expect("Delta not provided"));

                let x1 = $circuit(&mut garbler, &x01, &x2, &x23, $($args),*);
                let x1 = yao::GCUtils::garbled_circuits_error(x1)?;
                let x1 = garbler.output_to_id0_and_id1(x1.wires())?;
                let x1 = match x1 {
                    Some(x1) => x1,
                    None => Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "No output received",
                    ))?,
                };

                // Compose the bits
                for (res, x1) in izip!(res.iter_mut(), x1.chunks(<$t>::K)) {
                    res.b = yao::GCUtils::bits_to_ring(x1)?;
                }
            }
            PartyID::ID2 => {
                let mut x23 = Vec::with_capacity($output_size);
                for res in res.iter_mut() {
                    let k2 = $io_context.rngs.bitcomp1.random_elements_3keys::<RingElement<$t>>();
                    let k3 = $io_context.rngs.bitcomp2.random_elements_3keys::<RingElement<$t>>();
                    let k2_comp = k2.0 + k2.1 + k2.2;
                    let k3_comp = k3.0 + k3.1 + k3.2;
                    x23.push(k2_comp + k3_comp);
                    res.a = k3_comp.neg();
                    res.b = k2_comp.neg();
                }

                // TODO this can be parallelized with joint_input_arithmetic_added_many
                let x23 = yao::input_ring_id2_many(Some(x23), delta, $output_size, $io_context)?;

                let mut garbler =
                   rep3::yao::garbler::Rep3Garbler::new_with_delta($io_context, delta.expect("Delta not provided"));

                let x1 = $circuit(&mut garbler, &x01, &x2, &x23, $($args),*);
                let x1 = yao::GCUtils::garbled_circuits_error(x1)?;
                let x1 = garbler.output_to_id0_and_id1(x1.wires())?;
                if x1.is_some() {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Unexpected output received",
                    ))?;
                }
            }
        }

        Ok(res)
    }};
}
pub(crate) use decompose_circuit_compose_blueprint;

/// An upcast of a vector Rep3RingShares from a smaller ring to a larger ring
pub fn upcast_many<T: IntRing2k, U: IntRing2k, N: Rep3Network>(
    inputs: &[Rep3RingShare<T>],
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<Rep3RingShare<U>>>
where
    Standard: Distribution<U>,
{
    assert!(T::K < U::K);

    // Special case for Bit
    if TypeId::of::<T>() == TypeId::of::<Bit>() {
        // SAFTEY: We already checked that the type matches
        let shares =
            unsafe { &*(inputs as *const [Rep3RingShare<T>] as *const [Rep3RingShare<Bit>]) };
        return conversion::bit_inject_from_bits_many(shares, io_context);
    }

    // The actual garbled circuit implementation
    let num_inputs = inputs.len();

    decompose_circuit_compose_blueprint!(
        inputs,
        io_context,
        num_inputs,
        U,
        GarbledCircuits::ring_to_ring_upcast_many,
        (T::K, U::K)
    )
}
