//! Conversions
//!
//! This module contains conversions between share types

use super::{
    Rep3RingShare, detail,
    ring::{bit::Bit, int_ring::IntRing2k, ring_impl::RingElement},
    yao,
};
use crate::protocols::{
    rep3::{
        self, Rep3PrimeFieldShare, Rep3State,
        conversion::A2BType,
        id::PartyID,
        network,
        yao::{
            GCUtils, circuits::GarbledCircuits, evaluator::Rep3Evaluator, garbler::Rep3Garbler,
            streaming_evaluator::StreamingRep3Evaluator, streaming_garbler::StreamingRep3Garbler,
        },
    },
    rep3_ring::arithmetic,
};
use ark_ff::PrimeField;
use fancy_garbling::{BinaryBundle, WireMod2};
use itertools::izip;
use mpc_net::Network;
use rand::{distributions::Standard, prelude::Distribution};
use std::ops::Neg;

/// Depending on the `A2BType` of the state, this function selects the appropriate implementation for the arithmetic-to-binary conversion.
pub fn a2b_selector<T: IntRing2k, N: Network>(
    x: Rep3RingShare<T>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    match state.a2b_type {
        A2BType::Direct => a2b(x, net, state),
        A2BType::Yao => a2y2b(x, net, state),
    }
}

/// Depending on the `A2BType` of the state, this function selects the appropriate implementation for the binary-to-arithmetic conversion.
pub fn b2a_selector<T: IntRing2k, N: Network>(
    x: &Rep3RingShare<T>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    match state.a2b_type {
        A2BType::Direct => b2a(x, net, state),
        A2BType::Yao => b2y2a(x, net, state),
    }
}

/// Transforms the replicated shared value x from an arithmetic sharing to a binary sharing. I.e., x = x_1 + x_2 + x_3 gets transformed into x = x'_1 xor x'_2 xor x'_3.
pub fn a2b<T: IntRing2k, N: Network>(
    x: Rep3RingShare<T>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    let mut x01 = Rep3RingShare::zero_share();
    let mut x2 = Rep3RingShare::zero_share();

    let (mut r, r2) = state.rngs.rand.random_elements::<RingElement<T>>();
    r ^= r2;

    match state.id {
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
    let local_b = network::reshare(net, x01.a.to_owned())?;
    x01.b = local_b;

    detail::low_depth_binary_add(&x01, &x2, net, state)
}

/// Transforms the replicated shared value x from an arithmetic sharing to a binary sharing. I.e., x = x_1 + x_2 + x_3 gets transformed into x = x'_1 xor x'_2 xor x'_3.
pub fn a2b_many<T: IntRing2k, N: Network>(
    x: &[Rep3RingShare<T>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3RingShare<T>>>
where
    Standard: Distribution<T>,
{
    let mut x2 = vec![Rep3RingShare::zero_share(); x.len()];

    let mut r_vec = Vec::with_capacity(x.len());
    for _ in 0..x.len() {
        let (mut r, r2) = state.rngs.rand.random_elements::<RingElement<T>>();
        r ^= &r2;
        r_vec.push(r);
    }

    let x01_a = match state.id {
        PartyID::ID0 => {
            for (x2, x) in izip!(x2.iter_mut(), x) {
                x2.b = x.b;
            }
            r_vec
        }

        PartyID::ID1 => izip!(x, r_vec)
            .map(|(x, r)| {
                let tmp = x.a + x.b;
                tmp ^ r
            })
            .collect(),
        PartyID::ID2 => {
            for (x2, x) in izip!(x2.iter_mut(), x) {
                x2.a = x.a;
            }
            r_vec
        }
    };

    // reshare x01
    let x01_b = network::reshare_many(net, &x01_a)?;
    let x01 = izip!(x01_a, x01_b)
        .map(|(a, b)| Rep3RingShare::new_ring(a, b))
        .collect::<Vec<_>>();
    detail::low_depth_binary_add_many(&x01, &x2, net, state)
}

/// Transforms the replicated shared value x from a binary sharing to an arithmetic sharing. I.e., x = x_1 xor x_2 xor x_3 gets transformed into x = x'_1 + x'_2 + x'_3.
pub fn b2a<T: IntRing2k, N: Network>(
    x: &Rep3RingShare<T>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    let mut y = Rep3RingShare::zero_share();
    let mut res = Rep3RingShare::zero_share();

    let (mut r, r2) = state.rngs.rand.random_elements::<RingElement<T>>();
    r ^= r2;

    match state.id {
        PartyID::ID0 => {
            let k3 = state
                .rngs
                .bitcomp2
                .random_elements_3keys::<RingElement<T>>();

            res.b = (k3.0 + k3.1 + k3.2).neg();
            y.a = r;
        }
        PartyID::ID1 => {
            let k2 = state
                .rngs
                .bitcomp1
                .random_elements_3keys::<RingElement<T>>();

            res.a = (k2.0 + k2.1 + k2.2).neg();
            y.a = r;
        }
        PartyID::ID2 => {
            let k2 = state
                .rngs
                .bitcomp1
                .random_elements_3keys::<RingElement<T>>();
            let k3 = state
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
    let local_b = network::reshare(net, y.a.to_owned())?;
    y.b = local_b;

    let z = detail::low_depth_binary_add(x, &y, net, state)?;

    match state.id {
        PartyID::ID0 => {
            network::send_next(net, z.b.to_owned())?;
            let rcv: RingElement<T> = network::recv_prev(net)?;
            res.a = z.a ^ z.b ^ rcv;
        }
        PartyID::ID1 => {
            let rcv: RingElement<T> = network::recv_prev(net)?;
            res.b = z.a ^ z.b ^ rcv;
        }
        PartyID::ID2 => {
            network::send_next(net, z.b)?;
        }
    }
    Ok(res)
}

/// A variant of [b2a] that operates on vectors of shared values instead.
pub fn b2a_many<T: IntRing2k, N: Network>(
    x: &[Rep3RingShare<T>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3RingShare<T>>>
where
    Standard: Distribution<T>,
{
    let mut res = vec![Rep3RingShare::zero_share(); x.len()];

    let mut r_vec = Vec::with_capacity(x.len());
    for _ in 0..x.len() {
        let (mut r, r2) = state.rngs.rand.random_elements::<RingElement<T>>();
        r ^= r2;
        r_vec.push(r);
    }
    match state.id {
        PartyID::ID0 => {
            for res in res.iter_mut() {
                let k3 = state
                    .rngs
                    .bitcomp2
                    .random_elements_3keys::<RingElement<T>>();

                res.b = (k3.0 + k3.1 + k3.2).neg();
            }
        }
        PartyID::ID1 => {
            for res in res.iter_mut() {
                let k2 = state
                    .rngs
                    .bitcomp1
                    .random_elements_3keys::<RingElement<T>>();

                res.a = (k2.0 + k2.1 + k2.2).neg();
            }
        }
        PartyID::ID2 => {
            for (res, y) in res.iter_mut().zip(r_vec.iter_mut()) {
                let k2 = state
                    .rngs
                    .bitcomp1
                    .random_elements_3keys::<RingElement<T>>();
                let k3 = state
                    .rngs
                    .bitcomp2
                    .random_elements_3keys::<RingElement<T>>();

                let k2_comp = k2.0 + k2.1 + k2.2;
                let k3_comp = k3.0 + k3.1 + k3.2;
                let val = k2_comp + k3_comp;
                *y ^= val;
                res.a = k3_comp.neg();
                res.b = k2_comp.neg();
            }
        }
    }

    // reshare y
    let y_a = r_vec;
    network::send_next_many(net, &y_a)?;
    let local_b = network::recv_prev_many(net)?;

    let y = izip!(y_a, local_b)
        .map(|(a, b)| Rep3RingShare::new_ring(a, b))
        .collect::<Vec<_>>();

    let z = detail::low_depth_binary_add_many(x, &y, net, state)?;

    match state.id {
        PartyID::ID0 => {
            let z_b = z.iter().cloned().map(|z| z.b).collect::<Vec<_>>();
            network::send_next_many(net, &z_b)?;
            let rcv: Vec<RingElement<T>> = network::recv_prev_many(net)?;

            for (res, z, rcv) in izip!(res.iter_mut(), z, rcv.iter()) {
                res.a = z.a ^ z.b ^ rcv;
            }
        }
        PartyID::ID1 => {
            let rcv: Vec<RingElement<T>> = network::recv_prev_many(net)?;
            for (res, z, rcv) in izip!(res.iter_mut(), z, rcv.iter()) {
                res.b = z.a ^ z.b ^ rcv;
            }
        }
        PartyID::ID2 => {
            let z_b = z.into_iter().map(|z| z.b).collect::<Vec<_>>();
            network::send_next_many(net, &z_b)?;
        }
    }
    Ok(res)
}

/// Translates one shared bit into an arithmetic sharing of the same bit. I.e., the shared bit x = x_1 xor x_2 xor x_3 gets transformed into x = x'_1 + x'_2 + x'_3, with x being either 0 or 1.
pub fn bit_inject<T: IntRing2k, N: Network>(
    x: &Rep3RingShare<T>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    // standard bit inject
    assert!(x.a.bits() <= 1);

    let mut b0 = Rep3RingShare::default();
    let mut b1 = Rep3RingShare::default();
    let mut b2 = Rep3RingShare::default();

    match state.id {
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

    let d = arithmetic::arithmetic_xor(b0, b1, net, state)?;
    let e = arithmetic::arithmetic_xor(d, b2, net, state)?;
    Ok(e)
}

/// Translates a vector of shared bits into a vector of arithmetic sharings of the same bits. See [bit_inject] for details.
pub fn bit_inject_many<T: IntRing2k, N: Network>(
    x: &[Rep3RingShare<T>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3RingShare<T>>>
where
    Standard: Distribution<T>,
{
    // standard bit inject
    assert!(x.iter().all(|a| a.a.bits() <= 1));

    let mut b0 = vec![Rep3RingShare::default(); x.len()];
    let mut b1 = vec![Rep3RingShare::default(); x.len()];
    let mut b2 = vec![Rep3RingShare::default(); x.len()];

    match state.id {
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

    let d = arithmetic::arithmetic_xor_many(&b0, &b1, net, state)?;
    let e = arithmetic::arithmetic_xor_many(&d, &b2, net, state)?;
    Ok(e)
}

/// Translates one shared bit into an arithmetic sharing of the same bit. I.e., the shared bit x = x_1 xor x_2 xor x_3 gets transformed into x = x'_1 + x'_2 + x'_3, with x being either 0 or 1.
pub fn bit_inject_from_bit<T: IntRing2k, N: Network>(
    x: &Rep3RingShare<Bit>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    // standard bit inject

    let mut b0 = Rep3RingShare::default();
    let mut b1 = Rep3RingShare::default();
    let mut b2 = Rep3RingShare::default();

    match state.id {
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

    let d = arithmetic::arithmetic_xor(b0, b1, net, state)?;
    let e = arithmetic::arithmetic_xor(d, b2, net, state)?;
    Ok(e)
}

/// Translates a vector of shared bits into a vector of arithmetic sharings of the same bits. See [bit_inject] for details.
pub fn bit_inject_from_bits_many<T: IntRing2k, N: Network>(
    x: &[Rep3RingShare<Bit>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3RingShare<T>>>
where
    Standard: Distribution<T>,
{
    let mut b0 = vec![Rep3RingShare::default(); x.len()];
    let mut b1 = vec![Rep3RingShare::default(); x.len()];
    let mut b2 = vec![Rep3RingShare::default(); x.len()];

    match state.id {
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

    let d = arithmetic::arithmetic_xor_many(&b0, &b1, net, state)?;
    let e = arithmetic::arithmetic_xor_many(&d, &b2, net, state)?;
    Ok(e)
}

/// Translates a vector of shared bits into a vector of arithmetic sharings of the same bits. See [bit_inject] for details.
pub fn bit_inject_from_bits_to_field_many<F: PrimeField, N: Network>(
    x: &[Rep3RingShare<Bit>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let mut b0 = vec![Rep3PrimeFieldShare::default(); x.len()];
    let mut b1 = vec![Rep3PrimeFieldShare::default(); x.len()];
    let mut b2 = vec![Rep3PrimeFieldShare::default(); x.len()];

    match state.id {
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

    let d = rep3::arithmetic::arithmetic_xor_many(&b0, &b1, net, state)?;
    let e = rep3::arithmetic::arithmetic_xor_many(&d, &b2, net, state)?;
    Ok(e)
}

/// Transforms the replicated shared value x from an arithmetic sharing to a yao sharing. I.e., x = x_1 + x_2 + x_3 gets transformed into wires, such that the garbler have keys (k_0, delta) for each bit of x, while the evaluator has k_x = k_0 xor delta * x.
pub fn a2y<T: IntRing2k, N: Network>(
    x: Rep3RingShare<T>,
    delta: Option<WireMod2>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<BinaryBundle<WireMod2>> {
    let [x01, x2] = yao::joint_input_arithmetic_added(x, delta, net, state)?;

    let converted = match state.id {
        PartyID::ID0 => {
            let mut evaluator = Rep3Evaluator::new(net);
            evaluator.receive_circuit()?;
            let res = GarbledCircuits::adder_mod_2k(&mut evaluator, &x01, &x2);
            GCUtils::garbled_circuits_error(res)?
        }
        PartyID::ID1 | PartyID::ID2 => {
            let delta = delta.ok_or(eyre::eyre!("No delta provided"))?;
            let mut garbler = Rep3Garbler::new_with_delta(net, state, delta);
            let res = GarbledCircuits::adder_mod_2k(&mut garbler, &x01, &x2);
            let res = GCUtils::garbled_circuits_error(res)?;
            garbler.send_circuit()?;
            res
        }
    };

    Ok(converted)
}

/// Transforms the replicated shared value x from an arithmetic sharing to a yao sharing. I.e., x = x_1 + x_2 + x_3 gets transformed into wires, such that the garbler have keys (k_0, delta) for each bit of x, while the evaluator has k_x = k_0 xor delta * x. Uses the Streaming Garbler/Evaluator.
pub fn a2y_streaming<T: IntRing2k, N: Network>(
    x: Rep3RingShare<T>,
    delta: Option<WireMod2>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<BinaryBundle<WireMod2>> {
    let [x01, x2] = yao::joint_input_arithmetic_added(x, delta, net, state)?;

    let converted = match state.id {
        PartyID::ID0 => {
            let mut evaluator = StreamingRep3Evaluator::new(net);
            let res = GarbledCircuits::adder_mod_2k(&mut evaluator, &x01, &x2);
            let res = GCUtils::garbled_circuits_error(res)?;
            evaluator.receive_hash()?;
            res
        }
        PartyID::ID1 | PartyID::ID2 => {
            let delta = delta.ok_or(eyre::eyre!("No delta provided"))?;
            let mut garbler = StreamingRep3Garbler::new_with_delta(net, state, delta);
            let res = GarbledCircuits::adder_mod_2k(&mut garbler, &x01, &x2);
            let res = GCUtils::garbled_circuits_error(res)?;
            garbler.send_hash()?;
            res
        }
    };

    Ok(converted)
}

macro_rules! y2a_impl_p1 {
    ($garbler:ty,$x:expr,$delta:expr,$net:expr,$state:expr,$res:expr) => {{
        let delta = $delta.ok_or(eyre::eyre!("No delta provided"))?;
        let k2 = $state
            .rngs
            .bitcomp1
            .random_elements_3keys::<RingElement<T>>();
        $res.a = (k2.0 + k2.1 + k2.2).neg();
        let x23 = yao::input_ring_id2::<T, _>(None, None, $net, $state)?;

        let mut garbler = <$garbler>::new_with_delta($net, $state, delta);
        let x1 = GarbledCircuits::adder_mod_2k(&mut garbler, &$x, &x23);
        let x1 = GCUtils::garbled_circuits_error(x1)?;
        let x1 = garbler.output_to_id0_and_id1(x1.wires())?;
        let x1 = x1.ok_or(eyre::eyre!("No output received"))?;
        $res.b = GCUtils::bits_to_ring(&x1)?;
    }};
}

macro_rules! y2a_impl_p2 {
    ($garbler:ty,$x:expr,$delta:expr,$net:expr,$state:expr,$res:expr) => {{
        let delta = $delta.ok_or(eyre::eyre!("No delta provided"))?;
        let k2 = $state
            .rngs
            .bitcomp1
            .random_elements_3keys::<RingElement<T>>();
        let k3 = $state
            .rngs
            .bitcomp2
            .random_elements_3keys::<RingElement<T>>();
        let k2_comp = k2.0 + k2.1 + k2.2;
        let k3_comp = k3.0 + k3.1 + k3.2;
        let x23 = Some(k2_comp + k3_comp);
        $res.a = k3_comp.neg();
        $res.b = k2_comp.neg();
        let x23 = yao::input_ring_id2(x23, Some(delta), $net, $state)?;

        let mut garbler = <$garbler>::new_with_delta($net, $state, delta);
        let x1 = GarbledCircuits::adder_mod_2k(&mut garbler, &$x, &x23);
        let x1 = GCUtils::garbled_circuits_error(x1)?;
        let x1 = garbler.output_to_id0_and_id1(x1.wires())?;
        if x1.is_some() {
            eyre::bail!("Unexpected output received");
        }
    }};
}

/// Transforms the shared value x from a yao sharing to an arithmetic sharing. I.e., the sharing such that the garbler have keys (k_0, delta) for each bit of x, while the evaluator has k_x = k_0 xor delta * x gets transformed into x = x_1 + x_2 + x_3.
pub fn y2a<T: IntRing2k, N: Network>(
    x: BinaryBundle<WireMod2>,
    delta: Option<WireMod2>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    let mut res = Rep3RingShare::zero_share();

    match state.id {
        PartyID::ID0 => {
            let k3 = state
                .rngs
                .bitcomp2
                .random_elements_3keys::<RingElement<T>>();
            res.b = (k3.0 + k3.1 + k3.2).neg();
            let x23 = yao::input_ring_id2::<T, _>(None, None, net, state)?;

            let mut evaluator = Rep3Evaluator::new(net);
            evaluator.receive_circuit()?;
            let x1 = GarbledCircuits::adder_mod_2k(&mut evaluator, &x, &x23);
            let x1 = GCUtils::garbled_circuits_error(x1)?;
            let x1 = evaluator.output_to_id0_and_id1(x1.wires())?;
            res.a = GCUtils::bits_to_ring(&x1)?;
        }
        PartyID::ID1 => {
            y2a_impl_p1!(Rep3Garbler<N>, x, delta, net, state, res)
        }
        PartyID::ID2 => {
            y2a_impl_p2!(Rep3Garbler<N>, x, delta, net, state, res)
        }
    };

    Ok(res)
}

/// Transforms the shared value x from a yao sharing to an arithmetic sharing. I.e., the sharing such that the garbler have keys (k_0, delta) for each bit of x, while the evaluator has k_x = k_0 xor delta * x gets transformed into x = x_1 + x_2 + x_3. Uses the Streaming Garbler/Evaluator.
pub fn y2a_streaming<T: IntRing2k, N: Network>(
    x: BinaryBundle<WireMod2>,
    delta: Option<WireMod2>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    let mut res = Rep3RingShare::zero_share();

    match state.id {
        PartyID::ID0 => {
            let k3 = state
                .rngs
                .bitcomp2
                .random_elements_3keys::<RingElement<T>>();
            res.b = (k3.0 + k3.1 + k3.2).neg();
            let x23 = yao::input_ring_id2::<T, _>(None, None, net, state)?;

            let mut evaluator = StreamingRep3Evaluator::new(net);
            let x1 = GarbledCircuits::adder_mod_2k(&mut evaluator, &x, &x23);
            let x1 = GCUtils::garbled_circuits_error(x1)?;
            let x1 = evaluator.output_to_id0_and_id1(x1.wires())?;
            res.a = GCUtils::bits_to_ring(&x1)?;
        }
        PartyID::ID1 => {
            y2a_impl_p1!(StreamingRep3Garbler<N>, x, delta, net, state, res)
        }
        PartyID::ID2 => {
            y2a_impl_p2!(StreamingRep3Garbler<N>, x, delta, net, state, res)
        }
    };

    Ok(res)
}

/// Transforms the replicated shared value x from a binary sharing to a yao sharing. I.e., x = x_1 xor x_2 xor x_3 gets transformed into wires, such that the garbler have keys (k_0, delta) for each bit of x, while the evaluator has k_x = k_0 xor delta * x.
pub fn b2y<T: IntRing2k, N: Network>(
    x: &Rep3RingShare<T>,
    delta: Option<WireMod2>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<BinaryBundle<WireMod2>> {
    let [x01, x2] = yao::joint_input_binary_xored(x, delta, net, state)?;

    let converted = match state.id {
        PartyID::ID0 => {
            // There is no code difference between Rep3Evaluator and StreamingRep3Evaluator
            let mut evaluator = Rep3Evaluator::new(net);
            // evaluator.receive_circuit()?; // No network used here
            let res = GarbledCircuits::xor_many(&mut evaluator, &x01, &x2);
            GCUtils::garbled_circuits_error(res)?
        }
        PartyID::ID1 | PartyID::ID2 => {
            // There is no code difference between Rep3Garbler and StreamingRep3Garbler
            let delta = delta.ok_or(eyre::eyre!("No delta provided"))?;
            let mut garbler = Rep3Garbler::new_with_delta(net, state, delta);
            let res = GarbledCircuits::xor_many(&mut garbler, &x01, &x2);
            GCUtils::garbled_circuits_error(res)?
            // garbler.send_circuit()?; // No network used here
        }
    };

    Ok(converted)
}

/// Transforms the shared value x from a yao sharing to a binary sharing. I.e., the sharing such that the garbler have keys (k_0, delta) for each bit of x, while the evaluator has k_x = k_0 xor delta * x gets transformed into x = x_1 xor x_2 xor x_3.
pub fn y2b<T: IntRing2k, N: Network>(
    x: BinaryBundle<WireMod2>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    let collapsed = GCUtils::collapse_bundle_to_lsb_bits_as_ring(x)?;

    let converted = match state.id {
        PartyID::ID0 => {
            let x_xor_px = collapsed;
            let r = state.rngs.rand.random_element_rng1::<RingElement<T>>();
            let r_xor_x_xor_px = x_xor_px ^ r;
            network::send(net, PartyID::ID2, r_xor_x_xor_px.to_owned())?;
            Rep3RingShare::new_ring(r, r_xor_x_xor_px)
        }
        PartyID::ID1 => {
            let px = collapsed;
            let r = state.rngs.rand.random_element_rng2::<RingElement<T>>();
            Rep3RingShare::new_ring(px, r)
        }
        PartyID::ID2 => {
            let px = collapsed;
            let r_xor_x_xor_px = network::recv(net, PartyID::ID0)?;
            Rep3RingShare::new_ring(r_xor_x_xor_px, px)
        }
    };

    Ok(converted)
}

/// Transforms the replicated shared value x from an arithmetic sharing to a binary sharing. I.e., x = x_1 + x_2 + x_3 gets transformed into x = x'_1 xor x'_2 xor x'_3.
pub fn a2y2b<T: IntRing2k, N: Network>(
    x: Rep3RingShare<T>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    let delta = state.rngs.generate_random_garbler_delta(state.id);
    let y = a2y(x, delta, net, state)?;
    y2b(y, net, state)
}

/// Transforms the replicated shared value x from an arithmetic sharing to a binary sharing. I.e., x = x_1 + x_2 + x_3 gets transformed into x = x'_1 xor x'_2 xor x'_3. Uses the Streaming Garbler/Evaluator. Uses the Streaming Garbler/Evaluator.
pub fn a2y2b_streaming<T: IntRing2k, N: Network>(
    x: Rep3RingShare<T>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    let delta = state.rngs.generate_random_garbler_delta(state.id);
    let y = a2y_streaming(x, delta, net, state)?;
    y2b(y, net, state)
}

/// Transforms the replicated shared value x from a binary sharing to an arithmetic sharing. I.e., x = x_1 xor x_2 xor x_3 gets transformed into x = x'_1 + x'_2 + x'_3. This implementations goes through the yao protocol.
pub fn b2y2a<T: IntRing2k, N: Network>(
    x: &Rep3RingShare<T>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    let delta = state.rngs.generate_random_garbler_delta(state.id);
    let y = b2y(x, delta, net, state)?;
    y2a(y, delta, net, state)
}

/// Transforms the replicated shared value x from a binary sharing to an arithmetic sharing. I.e., x = x_1 xor x_2 xor x_3 gets transformed into x = x'_1 + x'_2 + x'_3. This implementations goes through the yao protocol. Uses the Streaming Garbler/Evaluator.
pub fn b2y2a_streaming<T: IntRing2k, N: Network>(
    x: &Rep3RingShare<T>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3RingShare<T>>
where
    Standard: Distribution<T>,
{
    let delta = state.rngs.generate_random_garbler_delta(state.id);
    let y = b2y(x, delta, net, state)?;
    y2a_streaming(y, delta, net, state)
}
