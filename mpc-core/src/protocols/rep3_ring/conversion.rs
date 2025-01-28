//! Conversions
//!
//! This module contains conversions between share types

use super::{
    arithmetic::types::Rep3RingShare,
    detail,
    ring::{bit::Bit, int_ring::IntRing2k, ring_impl::RingElement},
    yao,
};
use crate::protocols::{
    rep3::{
        self,
        conversion::A2BType,
        id::PartyID,
        network::{IoContext, Rep3Network},
        yao::{
            circuits::GarbledCircuits, evaluator::Rep3Evaluator, garbler::Rep3Garbler,
            streaming_evaluator::StreamingRep3Evaluator, streaming_garbler::StreamingRep3Garbler,
            GCUtils,
        },
        IoResult, Rep3PrimeFieldShare,
    },
    rep3_ring::arithmetic,
};
use ark_ff::PrimeField;
use fancy_garbling::{BinaryBundle, WireMod2};
use itertools::izip;
use rand::{distributions::Standard, prelude::Distribution};
use std::ops::Neg;

/// Depending on the `A2BType` of the io_context, this function selects the appropriate implementation for the arithmetic-to-binary conversion.
pub fn a2b_selector<T: IntRing2k, N: Rep3Network>(
    x: Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> std::io::Result<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    match io_context.a2b_type {
        A2BType::Direct => a2b(x, io_context),
        A2BType::Yao => a2y2b(x, io_context),
    }
}

/// Depending on the `A2BType` of the io_context, this function selects the appropriate implementation for the binary-to-arithmetic conversion.
pub fn b2a_selector<T: IntRing2k, N: Rep3Network>(
    x: &Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> std::io::Result<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    match io_context.a2b_type {
        A2BType::Direct => b2a(x, io_context),
        A2BType::Yao => b2y2a(x, io_context),
    }
}

/// Transforms the replicated shared value x from an arithmetic sharing to a binary sharing. I.e., x = x_1 + x_2 + x_3 gets transformed into x = x'_1 xor x'_2 xor x'_3.
pub fn a2b<T: IntRing2k, N: Rep3Network>(
    x: Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    let mut x01 = Rep3RingShare::zero_share();
    let mut x2 = Rep3RingShare::zero_share();

    let (mut r, r2) = io_context.rngs.rand.random_elements::<RingElement<T>>();
    r ^= r2;

    match io_context.id {
        PartyID::ID0 => {
            x01.a = r;
            x2.b = x.b;
        }
        PartyID::ID1 => {
            let val = x.a + x.b;
            x01.a = val ^ r;
        }
        PartyID::ID2 => {
            x01.a = r;
            x2.a = x.a;
        }
    }

    // reshare x01
    io_context.network.send_next(x01.a.to_owned())?;
    let local_b = io_context.network.recv_prev()?;
    x01.b = local_b;

    detail::low_depth_binary_add(&x01, &x2, io_context)
}

/// Transforms the replicated shared value x from a binary sharing to an arithmetic sharing. I.e., x = x_1 xor x_2 xor x_3 gets transformed into x = x'_1 + x'_2 + x'_3.
pub fn b2a<T: IntRing2k, N: Rep3Network>(
    x: &Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    let mut y = Rep3RingShare::zero_share();
    let mut res = Rep3RingShare::zero_share();

    let (mut r, r2) = io_context.rngs.rand.random_elements::<RingElement<T>>();
    r ^= r2;

    match io_context.id {
        PartyID::ID0 => {
            let k3 = io_context
                .rngs
                .bitcomp2
                .random_elements_3keys::<RingElement<T>>();

            res.b = (k3.0 + k3.1 + k3.2).neg();
            y.a = r;
        }
        PartyID::ID1 => {
            let k2 = io_context
                .rngs
                .bitcomp1
                .random_elements_3keys::<RingElement<T>>();

            res.a = (k2.0 + k2.1 + k2.2).neg();
            y.a = r;
        }
        PartyID::ID2 => {
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
            let val = k2_comp + k3_comp;
            y.a = val ^ r;
            res.a = k3_comp.neg();
            res.b = k2_comp.neg();
        }
    }

    // reshare y
    io_context.network.send_next(y.a.to_owned())?;
    let local_b = io_context.network.recv_prev()?;
    y.b = local_b;

    let z = detail::low_depth_binary_add(x, &y, io_context)?;

    match io_context.id {
        PartyID::ID0 => {
            io_context.network.send_next(z.b.to_owned())?;
            let rcv: RingElement<T> = io_context.network.recv_prev()?;
            res.a = z.a ^ z.b ^ rcv;
        }
        PartyID::ID1 => {
            let rcv: RingElement<T> = io_context.network.recv_prev()?;
            res.b = z.a ^ z.b ^ rcv;
        }
        PartyID::ID2 => {
            io_context.network.send_next(z.b)?;
        }
    }
    Ok(res)
}

/// Translates one shared bit into an arithmetic sharing of the same bit. I.e., the shared bit x = x_1 xor x_2 xor x_3 gets transformed into x = x'_1 + x'_2 + x'_3, with x being either 0 or 1.
pub fn bit_inject<T: IntRing2k, N: Rep3Network>(
    x: &Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    // standard bit inject
    assert!(x.a.bits() <= 1);

    let mut b0 = Rep3RingShare::default();
    let mut b1 = Rep3RingShare::default();
    let mut b2 = Rep3RingShare::default();

    match io_context.id {
        PartyID::ID0 => {
            b0.a = x.a.to_owned();
            b2.b = x.b.to_owned();
        }
        PartyID::ID1 => {
            b1.a = x.a.to_owned();
            b0.b = x.b.to_owned();
        }
        PartyID::ID2 => {
            b2.a = x.a.to_owned();
            b1.b = x.b.to_owned();
        }
    };

    let d = arithmetic::arithmetic_xor(b0, b1, io_context)?;
    let e = arithmetic::arithmetic_xor(d, b2, io_context)?;
    Ok(e)
}

/// Translates a vector of shared bits into a vector of arithmetic sharings of the same bits. See [bit_inject] for details.
pub fn bit_inject_many<T: IntRing2k, N: Rep3Network>(
    x: &[Rep3RingShare<T>],
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<Rep3RingShare<T>>>
where
    Standard: Distribution<T>,
{
    // standard bit inject
    assert!(x.iter().all(|a| a.a.bits() <= 1));

    let mut b0 = vec![Rep3RingShare::default(); x.len()];
    let mut b1 = vec![Rep3RingShare::default(); x.len()];
    let mut b2 = vec![Rep3RingShare::default(); x.len()];

    match io_context.id {
        PartyID::ID0 => {
            for (b0, b2, x) in izip!(&mut b0, &mut b2, x.iter().cloned()) {
                b0.a = x.a;
                b2.b = x.b;
            }
        }
        PartyID::ID1 => {
            for (b1, b0, x) in izip!(&mut b1, &mut b0, x.iter().cloned()) {
                b1.a = x.a;
                b0.b = x.b;
            }
        }
        PartyID::ID2 => {
            for (b2, b1, x) in izip!(&mut b2, &mut b1, x.iter().cloned()) {
                b2.a = x.a;
                b1.b = x.b;
            }
        }
    };

    let d = arithmetic::arithmetic_xor_many(&b0, &b1, io_context)?;
    let e = arithmetic::arithmetic_xor_many(&d, &b2, io_context)?;
    Ok(e)
}

/// Translates one shared bit into an arithmetic sharing of the same bit. I.e., the shared bit x = x_1 xor x_2 xor x_3 gets transformed into x = x'_1 + x'_2 + x'_3, with x being either 0 or 1.
pub fn bit_inject_from_bit<T: IntRing2k, N: Rep3Network>(
    x: &Rep3RingShare<Bit>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    // standard bit inject

    let mut b0 = Rep3RingShare::default();
    let mut b1 = Rep3RingShare::default();
    let mut b2 = Rep3RingShare::default();

    match io_context.id {
        PartyID::ID0 => {
            b0.a = RingElement(T::from(x.a.0.convert()));
            b2.b = RingElement(T::from(x.b.0.convert()));
        }
        PartyID::ID1 => {
            b1.a = RingElement(T::from(x.a.0.convert()));
            b0.b = RingElement(T::from(x.b.0.convert()));
        }
        PartyID::ID2 => {
            b2.a = RingElement(T::from(x.a.0.convert()));
            b1.b = RingElement(T::from(x.b.0.convert()));
        }
    };

    let d = arithmetic::arithmetic_xor(b0, b1, io_context)?;
    let e = arithmetic::arithmetic_xor(d, b2, io_context)?;
    Ok(e)
}

/// Translates a vector of shared bits into a vector of arithmetic sharings of the same bits. See [bit_inject] for details.
pub fn bit_inject_from_bits_many<T: IntRing2k, N: Rep3Network>(
    x: &[Rep3RingShare<Bit>],
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<Rep3RingShare<T>>>
where
    Standard: Distribution<T>,
{
    let mut b0 = vec![Rep3RingShare::default(); x.len()];
    let mut b1 = vec![Rep3RingShare::default(); x.len()];
    let mut b2 = vec![Rep3RingShare::default(); x.len()];

    match io_context.id {
        PartyID::ID0 => {
            for (b0, b2, x) in izip!(&mut b0, &mut b2, x.iter().cloned()) {
                b0.a = RingElement(T::from(x.a.0.convert()));
                b2.b = RingElement(T::from(x.b.0.convert()));
            }
        }
        PartyID::ID1 => {
            for (b1, b0, x) in izip!(&mut b1, &mut b0, x.iter().cloned()) {
                b1.a = RingElement(T::from(x.a.0.convert()));
                b0.b = RingElement(T::from(x.b.0.convert()));
            }
        }
        PartyID::ID2 => {
            for (b2, b1, x) in izip!(&mut b2, &mut b1, x.iter().cloned()) {
                b2.a = RingElement(T::from(x.a.0.convert()));
                b1.b = RingElement(T::from(x.b.0.convert()));
            }
        }
    };

    let d = arithmetic::arithmetic_xor_many(&b0, &b1, io_context)?;
    let e = arithmetic::arithmetic_xor_many(&d, &b2, io_context)?;
    Ok(e)
}

/// Translates a vector of shared bits into a vector of arithmetic sharings of the same bits. See [bit_inject] for details.
pub fn bit_inject_from_bits_to_field_many<F: PrimeField, N: Rep3Network>(
    x: &[Rep3RingShare<Bit>],
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<Rep3PrimeFieldShare<F>>> {
    let mut b0 = vec![Rep3PrimeFieldShare::default(); x.len()];
    let mut b1 = vec![Rep3PrimeFieldShare::default(); x.len()];
    let mut b2 = vec![Rep3PrimeFieldShare::default(); x.len()];

    match io_context.id {
        PartyID::ID0 => {
            for (b0, b2, x) in izip!(&mut b0, &mut b2, x.iter().cloned()) {
                b0.a = F::from(x.a.0.convert() as u64);
                b2.b = F::from(x.b.0.convert() as u64);
            }
        }
        PartyID::ID1 => {
            for (b1, b0, x) in izip!(&mut b1, &mut b0, x.iter().cloned()) {
                b1.a = F::from(x.a.0.convert() as u64);
                b0.b = F::from(x.b.0.convert() as u64);
            }
        }
        PartyID::ID2 => {
            for (b2, b1, x) in izip!(&mut b2, &mut b1, x.iter().cloned()) {
                b2.a = F::from(x.a.0.convert() as u64);
                b1.b = F::from(x.b.0.convert() as u64);
            }
        }
    };

    let d = rep3::arithmetic::arithmetic_xor_many(&b0, &b1, io_context)?;
    let e = rep3::arithmetic::arithmetic_xor_many(&d, &b2, io_context)?;
    Ok(e)
}

/// Transforms the replicated shared value x from an arithmetic sharing to a yao sharing. I.e., x = x_1 + x_2 + x_3 gets transformed into wires, such that the garbler have keys (k_0, delta) for each bit of x, while the evaluator has k_x = k_0 xor delta * x.
pub fn a2y<T: IntRing2k, N: Rep3Network>(
    x: Rep3RingShare<T>,
    delta: Option<WireMod2>,
    io_context: &mut IoContext<N>,
) -> IoResult<BinaryBundle<WireMod2>> {
    let [x01, x2] = yao::joint_input_arithmetic_added(x, delta, io_context)?;

    let converted = match io_context.id {
        PartyID::ID0 => {
            let mut evaluator = Rep3Evaluator::new(io_context);
            evaluator.receive_circuit()?;
            let res = GarbledCircuits::adder_mod_2k(&mut evaluator, &x01, &x2);
            GCUtils::garbled_circuits_error(res)?
        }
        PartyID::ID1 | PartyID::ID2 => {
            let delta = match delta {
                Some(delta) => delta,
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "No delta provided",
                ))?,
            };
            let mut garbler = Rep3Garbler::new_with_delta(io_context, delta);
            let res = GarbledCircuits::adder_mod_2k(&mut garbler, &x01, &x2);
            let res = GCUtils::garbled_circuits_error(res)?;
            garbler.send_circuit()?;
            res
        }
    };

    Ok(converted)
}

/// Transforms the replicated shared value x from an arithmetic sharing to a yao sharing. I.e., x = x_1 + x_2 + x_3 gets transformed into wires, such that the garbler have keys (k_0, delta) for each bit of x, while the evaluator has k_x = k_0 xor delta * x. Uses the Streaming Garbler/Evaluator.
pub fn a2y_streaming<T: IntRing2k, N: Rep3Network>(
    x: Rep3RingShare<T>,
    delta: Option<WireMod2>,
    io_context: &mut IoContext<N>,
) -> IoResult<BinaryBundle<WireMod2>> {
    let [x01, x2] = yao::joint_input_arithmetic_added(x, delta, io_context)?;

    let converted = match io_context.id {
        PartyID::ID0 => {
            let mut evaluator = StreamingRep3Evaluator::new(io_context);
            let res = GarbledCircuits::adder_mod_2k(&mut evaluator, &x01, &x2);
            let res = GCUtils::garbled_circuits_error(res)?;
            evaluator.receive_hash()?;
            res
        }
        PartyID::ID1 | PartyID::ID2 => {
            let delta = match delta {
                Some(delta) => delta,
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "No delta provided",
                ))?,
            };
            let mut garbler = StreamingRep3Garbler::new_with_delta(io_context, delta);
            let res = GarbledCircuits::adder_mod_2k(&mut garbler, &x01, &x2);
            let res = GCUtils::garbled_circuits_error(res)?;
            garbler.send_hash()?;
            res
        }
    };

    Ok(converted)
}

macro_rules! y2a_impl_p1 {
    ($garbler:ty,$x:expr,$delta:expr,$io_context:expr,$res:expr) => {{
        let delta = match $delta {
            Some(delta) => delta,
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "No delta provided",
            ))?,
        };

        let k2 = $io_context
            .rngs
            .bitcomp1
            .random_elements_3keys::<RingElement<T>>();
        $res.a = (k2.0 + k2.1 + k2.2).neg();
        let x23 = yao::input_ring_id2::<T, _>(None, None, $io_context)?;

        let mut garbler = <$garbler>::new_with_delta($io_context, delta);
        let x1 = GarbledCircuits::adder_mod_2k(&mut garbler, &$x, &x23);
        let x1 = GCUtils::garbled_circuits_error(x1)?;
        let x1 = garbler.output_to_id0_and_id1(x1.wires())?;
        let x1 = match x1 {
            Some(x1) => x1,
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "No output received",
            ))?,
        };
        $res.b = GCUtils::bits_to_ring(&x1)?;
    }};
}

macro_rules! y2a_impl_p2 {
    ($garbler:ty,$x:expr,$delta:expr,$io_context:expr,$res:expr) => {{
        let delta = match $delta {
            Some(delta) => delta,
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "No delta provided",
            ))?,
        };

        let k2 = $io_context
            .rngs
            .bitcomp1
            .random_elements_3keys::<RingElement<T>>();
        let k3 = $io_context
            .rngs
            .bitcomp2
            .random_elements_3keys::<RingElement<T>>();
        let k2_comp = k2.0 + k2.1 + k2.2;
        let k3_comp = k3.0 + k3.1 + k3.2;
        let x23 = Some(k2_comp + k3_comp);
        $res.a = k3_comp.neg();
        $res.b = k2_comp.neg();
        let x23 = yao::input_ring_id2(x23, Some(delta), $io_context)?;

        let mut garbler = <$garbler>::new_with_delta($io_context, delta);
        let x1 = GarbledCircuits::adder_mod_2k(&mut garbler, &$x, &x23);
        let x1 = GCUtils::garbled_circuits_error(x1)?;
        let x1 = garbler.output_to_id0_and_id1(x1.wires())?;
        if x1.is_some() {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Unexpected output received",
            ))?;
        }
    }};
}

/// Transforms the shared value x from a yao sharing to an arithmetic sharing. I.e., the sharing such that the garbler have keys (k_0, delta) for each bit of x, while the evaluator has k_x = k_0 xor delta * x gets transformed into x = x_1 + x_2 + x_3.
pub fn y2a<T: IntRing2k, N: Rep3Network>(
    x: BinaryBundle<WireMod2>,
    delta: Option<WireMod2>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    let mut res = Rep3RingShare::zero_share();

    match io_context.id {
        PartyID::ID0 => {
            let k3 = io_context
                .rngs
                .bitcomp2
                .random_elements_3keys::<RingElement<T>>();
            res.b = (k3.0 + k3.1 + k3.2).neg();
            let x23 = yao::input_ring_id2::<T, _>(None, None, io_context)?;

            let mut evaluator = Rep3Evaluator::new(io_context);
            evaluator.receive_circuit()?;
            let x1 = GarbledCircuits::adder_mod_2k(&mut evaluator, &x, &x23);
            let x1 = GCUtils::garbled_circuits_error(x1)?;
            let x1 = evaluator.output_to_id0_and_id1(x1.wires())?;
            res.a = GCUtils::bits_to_ring(&x1)?;
        }
        PartyID::ID1 => {
            y2a_impl_p1!(Rep3Garbler<N>, x, delta, io_context, res)
        }
        PartyID::ID2 => {
            y2a_impl_p2!(Rep3Garbler<N>, x, delta, io_context, res)
        }
    };

    Ok(res)
}

/// Transforms the shared value x from a yao sharing to an arithmetic sharing. I.e., the sharing such that the garbler have keys (k_0, delta) for each bit of x, while the evaluator has k_x = k_0 xor delta * x gets transformed into x = x_1 + x_2 + x_3. Uses the Streaming Garbler/Evaluator.
pub fn y2a_streaming<T: IntRing2k, N: Rep3Network>(
    x: BinaryBundle<WireMod2>,
    delta: Option<WireMod2>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    let mut res = Rep3RingShare::zero_share();

    match io_context.id {
        PartyID::ID0 => {
            let k3 = io_context
                .rngs
                .bitcomp2
                .random_elements_3keys::<RingElement<T>>();
            res.b = (k3.0 + k3.1 + k3.2).neg();
            let x23 = yao::input_ring_id2::<T, _>(None, None, io_context)?;

            let mut evaluator = StreamingRep3Evaluator::new(io_context);
            let x1 = GarbledCircuits::adder_mod_2k(&mut evaluator, &x, &x23);
            let x1 = GCUtils::garbled_circuits_error(x1)?;
            let x1 = evaluator.output_to_id0_and_id1(x1.wires())?;
            res.a = GCUtils::bits_to_ring(&x1)?;
        }
        PartyID::ID1 => {
            y2a_impl_p1!(StreamingRep3Garbler<N>, x, delta, io_context, res)
        }
        PartyID::ID2 => {
            y2a_impl_p2!(StreamingRep3Garbler<N>, x, delta, io_context, res)
        }
    };

    Ok(res)
}

/// Transforms the replicated shared value x from a binary sharing to a yao sharing. I.e., x = x_1 xor x_2 xor x_3 gets transformed into wires, such that the garbler have keys (k_0, delta) for each bit of x, while the evaluator has k_x = k_0 xor delta * x.
pub fn b2y<T: IntRing2k, N: Rep3Network>(
    x: &Rep3RingShare<T>,
    delta: Option<WireMod2>,
    io_context: &mut IoContext<N>,
) -> IoResult<BinaryBundle<WireMod2>> {
    let [x01, x2] = yao::joint_input_binary_xored(x, delta, io_context)?;

    let converted = match io_context.id {
        PartyID::ID0 => {
            // There is no code difference between Rep3Evaluator and StreamingRep3Evaluator
            let mut evaluator = Rep3Evaluator::new(io_context);
            // evaluator.receive_circuit()?; // No network used here
            let res = GarbledCircuits::xor_many(&mut evaluator, &x01, &x2);
            GCUtils::garbled_circuits_error(res)?
        }
        PartyID::ID1 | PartyID::ID2 => {
            // There is no code difference between Rep3Garbler and StreamingRep3Garbler
            let delta = match delta {
                Some(delta) => delta,
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "No delta provided",
                ))?,
            };
            let mut garbler = Rep3Garbler::new_with_delta(io_context, delta);
            let res = GarbledCircuits::xor_many(&mut garbler, &x01, &x2);
            GCUtils::garbled_circuits_error(res)?
            // garbler.send_circuit()?; // No network used here
        }
    };

    Ok(converted)
}

/// Transforms the shared value x from a yao sharing to a binary sharing. I.e., the sharing such that the garbler have keys (k_0, delta) for each bit of x, while the evaluator has k_x = k_0 xor delta * x gets transformed into x = x_1 xor x_2 xor x_3.
pub fn y2b<T: IntRing2k, N: Rep3Network>(
    x: BinaryBundle<WireMod2>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    let collapsed = GCUtils::collapse_bundle_to_lsb_bits_as_ring(x)?;

    let converted = match io_context.id {
        PartyID::ID0 => {
            let x_xor_px = collapsed;
            let r = io_context.rngs.rand.random_element_rng1::<RingElement<T>>();
            let r_xor_x_xor_px = x_xor_px ^ r;
            io_context
                .network
                .send(PartyID::ID2, r_xor_x_xor_px.to_owned())?;
            Rep3RingShare::new_ring(r, r_xor_x_xor_px)
        }
        PartyID::ID1 => {
            let px = collapsed;
            let r = io_context.rngs.rand.random_element_rng2::<RingElement<T>>();
            Rep3RingShare::new_ring(px, r)
        }
        PartyID::ID2 => {
            let px = collapsed;
            let r_xor_x_xor_px = io_context.network.recv(PartyID::ID0)?;
            Rep3RingShare::new_ring(r_xor_x_xor_px, px)
        }
    };

    Ok(converted)
}

/// Transforms the replicated shared value x from an arithmetic sharing to a binary sharing. I.e., x = x_1 + x_2 + x_3 gets transformed into x = x'_1 xor x'_2 xor x'_3.
pub fn a2y2b<T: IntRing2k, N: Rep3Network>(
    x: Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    let delta = io_context.rngs.generate_random_garbler_delta(io_context.id);
    let y = a2y(x, delta, io_context)?;
    y2b(y, io_context)
}

/// Transforms the replicated shared value x from an arithmetic sharing to a binary sharing. I.e., x = x_1 + x_2 + x_3 gets transformed into x = x'_1 xor x'_2 xor x'_3. Uses the Streaming Garbler/Evaluator. Uses the Streaming Garbler/Evaluator.
pub fn a2y2b_streaming<T: IntRing2k, N: Rep3Network>(
    x: Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    let delta = io_context.rngs.generate_random_garbler_delta(io_context.id);
    let y = a2y_streaming(x, delta, io_context)?;
    y2b(y, io_context)
}

/// Transforms the replicated shared value x from a binary sharing to an arithmetic sharing. I.e., x = x_1 xor x_2 xor x_3 gets transformed into x = x'_1 + x'_2 + x'_3. This implementations goes through the yao protocol.
pub fn b2y2a<T: IntRing2k, N: Rep3Network>(
    x: &Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    let delta = io_context.rngs.generate_random_garbler_delta(io_context.id);
    let y = b2y(x, delta, io_context)?;
    y2a(y, delta, io_context)
}

/// Transforms the replicated shared value x from a binary sharing to an arithmetic sharing. I.e., x = x_1 xor x_2 xor x_3 gets transformed into x = x'_1 + x'_2 + x'_3. This implementations goes through the yao protocol. Uses the Streaming Garbler/Evaluator.
pub fn b2y2a_streaming<T: IntRing2k, N: Rep3Network>(
    x: &Rep3RingShare<T>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    let delta = io_context.rngs.generate_random_garbler_delta(io_context.id);
    let y = b2y(x, delta, io_context)?;
    y2a_streaming(y, delta, io_context)
}
