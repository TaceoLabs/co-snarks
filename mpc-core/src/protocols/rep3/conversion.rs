//! Conversions
//!
//! This module contains conversions between share types

use crate::protocols::rep3::{PartyID, arithmetic::BinaryShare};

use super::{
    Rep3BigUintShare, Rep3PointShare, Rep3PrimeFieldShare, Rep3State, arithmetic, detail,
    network::Rep3NetworkExt,
    yao::{
        self, GCUtils, circuits::GarbledCircuits, evaluator::Rep3Evaluator, garbler::Rep3Garbler,
        streaming_evaluator::StreamingRep3Evaluator, streaming_garbler::StreamingRep3Garbler,
    },
};
use ark_ec::{AffineRepr as _, CurveGroup};
use ark_ff::PrimeField;
use fancy_garbling::{BinaryBundle, WireMod2};
use itertools::{Itertools as _, izip};
use mpc_net::Network;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

/// This enum defines which arithmetic-to-binary (and vice-versa) implementation of [ABY3](https://eprint.iacr.org/2018/403.pdf) is used.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash,
)]
pub enum A2BType {
    /// The arithmetic-to-binary conversion is directly done using "Bit Decomposition", while the binary-to-arithmetic conversion is done using "Bit Composition". This process has a larger number of communication rounds with less communicated bytes.
    Direct,
    /// The arithmetic-to-binary conversion is done by "Arithmetic to Yao" followed by "Yao to Binary", while the binary-to-arithmetic conversion is done using "Binary to Yao" followed by "Yao to Arithmetic". This process has a low number of communication rounds with more communicated bytes.
    #[default]
    Yao,
}

/// Depending on the `A2BType` of the state, this function selects the appropriate implementation for the arithmetic-to-binary conversion.
pub fn a2b_selector<F: PrimeField, N: Network>(
    x: Rep3PrimeFieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3BigUintShare<F>> {
    match state.a2b_type {
        A2BType::Direct => a2b(x, net, state),
        A2BType::Yao => a2y2b(x, net, state),
    }
}

/// Depending on the `A2BType` of the state, this function selects the appropriate implementation for the binary-to-arithmetic conversion.
pub fn b2a_selector<F: PrimeField, N: Network>(
    x: &Rep3BigUintShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3PrimeFieldShare<F>> {
    match state.a2b_type {
        A2BType::Direct => b2a(x, net, state),
        A2BType::Yao => b2y2a(x, net, state),
    }
}

/// Transforms the replicated shared value x from an arithmetic sharing to a binary sharing. I.e., x = x_1 + x_2 + x_3 gets transformed into x = x'_1 xor x'_2 xor x'_3.
pub fn a2b<F: PrimeField, N: Network>(
    x: Rep3PrimeFieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3BigUintShare<F>> {
    let mut x01 = Rep3BigUintShare::zero_share();
    let mut x2 = Rep3BigUintShare::zero_share();

    let (mut r, r2) = state.rngs.rand.random_biguint(F::MODULUS_BIT_SIZE as usize);
    r ^= r2;

    match state.id {
        PartyID::ID0 => {
            x01.a = r;
            x2.b = x.b.into();
        }
        PartyID::ID1 => {
            let val: BigUint = (x.a + x.b).into();
            x01.a = val ^ r;
        }
        PartyID::ID2 => {
            x01.a = r;
            x2.a = x.a.into();
        }
    }

    // reshare x01
    let local_b = net.reshare(x01.a.to_owned())?;
    x01.b = local_b;

    detail::low_depth_binary_add_mod_p::<F, N>(&x01, &x2, net, state, F::MODULUS_BIT_SIZE as usize)
}

/// A variant of [a2b] that operates on vectors of shared values instead.
pub fn a2b_many<F: PrimeField, N: Network>(
    x: &[Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3BigUintShare<F>>> {
    let mut x2 = vec![Rep3BigUintShare::zero_share(); x.len()];

    let mut r_vec = Vec::with_capacity(x.len());
    for _ in 0..x.len() {
        let (mut r, r2) = state.rngs.rand.random_biguint(F::MODULUS_BIT_SIZE as usize);
        r ^= &r2;
        r_vec.push(r);
    }

    let x01_a = match state.id {
        PartyID::ID0 => {
            for (x2, x) in izip!(x2.iter_mut(), x) {
                x2.b = x.b.into();
            }
            r_vec
        }

        PartyID::ID1 => izip!(x, r_vec)
            .map(|(x, r)| {
                let tmp: BigUint = (x.a + x.b).into();
                tmp ^ r
            })
            .collect(),
        PartyID::ID2 => {
            for (x2, x) in izip!(x2.iter_mut(), x) {
                x2.a = x.a.into();
            }
            r_vec
        }
    };

    // reshare x01
    let x01_b = net.reshare_many(&x01_a)?;
    let x01 = izip!(x01_a, x01_b)
        .map(|(a, b)| Rep3BigUintShare::new(a, b))
        .collect_vec();

    detail::low_depth_binary_add_mod_p_many::<F, N>(
        &x01,
        &x2,
        net,
        state,
        F::MODULUS_BIT_SIZE as usize,
    )
}

/// Transforms the replicated shared value x from a binary sharing to an arithmetic sharing. I.e., x = x_1 xor x_2 xor x_3 gets transformed into x = x'_1 + x'_2 + x'_3. This implementation currently works only for a binary sharing of a valid field element, i.e., x = x_1 xor x_2 xor x_3 < p.
///
/// Keep in mind: Only works if the input is actually a binary sharing of a valid field element
/// If the input has the correct number of bits, but is >= P, then either x can be reduced with self.low_depth_sub_p_cmux(x) first, or self.low_depth_binary_add_2_mod_p(x, y) is extended to subtract 2P in parallel as well. The second solution requires another multiplexer in the end.
pub fn b2a<F: PrimeField, N: Network>(
    x: &Rep3BigUintShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3PrimeFieldShare<F>> {
    let mut y = Rep3BigUintShare::zero_share();
    let mut res = Rep3PrimeFieldShare::zero_share();

    let (mut r, r2) = state.rngs.rand.random_biguint(F::MODULUS_BIT_SIZE as usize);
    r ^= r2;

    match state.id {
        PartyID::ID0 => {
            let k3 = state.rngs.bitcomp2.random_fes_3keys::<F>();

            res.b = (k3.0 + k3.1 + k3.2).neg();
            y.a = r;
        }
        PartyID::ID1 => {
            let k2 = state.rngs.bitcomp1.random_fes_3keys::<F>();

            res.a = (k2.0 + k2.1 + k2.2).neg();
            y.a = r;
        }
        PartyID::ID2 => {
            let k2 = state.rngs.bitcomp1.random_fes_3keys::<F>();
            let k3 = state.rngs.bitcomp2.random_fes_3keys::<F>();

            let k2_comp = k2.0 + k2.1 + k2.2;
            let k3_comp = k3.0 + k3.1 + k3.2;
            let val: BigUint = (k2_comp + k3_comp).into();
            y.a = val ^ r;
            res.a = k3_comp.neg();
            res.b = k2_comp.neg();
        }
    }

    // reshare y
    let local_b = net.reshare(y.a.to_owned())?;
    y.b = local_b;

    let z = detail::low_depth_binary_add_mod_p::<F, N>(
        x,
        &y,
        net,
        state,
        F::MODULUS_BIT_SIZE as usize,
    )?;

    match state.id {
        PartyID::ID0 => {
            let rcv: BigUint = net.reshare(z.b.to_owned())?;
            res.a = (z.a ^ z.b ^ rcv).into();
        }
        PartyID::ID1 => {
            let rcv: BigUint = net.recv_prev()?;
            res.b = (z.a ^ z.b ^ rcv).into();
        }
        PartyID::ID2 => {
            net.send_next(z.b)?;
        }
    }
    Ok(res)
}

/// A variant of [b2a] that operates on vectors of shared values instead.
pub fn b2a_many<F: PrimeField, N: Network>(
    x: &[Rep3BigUintShare<F>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let mut res = vec![Rep3PrimeFieldShare::zero_share(); x.len()];

    let mut r_vec = Vec::with_capacity(x.len());
    for _ in 0..x.len() {
        let (mut r, r2) = state.rngs.rand.random_biguint(F::MODULUS_BIT_SIZE as usize);
        r ^= r2;
        r_vec.push(r);
    }
    match state.id {
        PartyID::ID0 => {
            for res in res.iter_mut() {
                let k3 = state.rngs.bitcomp2.random_fes_3keys::<F>();

                res.b = (k3.0 + k3.1 + k3.2).neg();
            }
        }
        PartyID::ID1 => {
            for res in res.iter_mut() {
                let k2 = state.rngs.bitcomp1.random_fes_3keys::<F>();

                res.a = (k2.0 + k2.1 + k2.2).neg();
            }
        }
        PartyID::ID2 => {
            for (res, y) in res.iter_mut().zip(r_vec.iter_mut()) {
                let k2 = state.rngs.bitcomp1.random_fes_3keys::<F>();
                let k3 = state.rngs.bitcomp2.random_fes_3keys::<F>();

                let k2_comp = k2.0 + k2.1 + k2.2;
                let k3_comp = k3.0 + k3.1 + k3.2;
                let val: BigUint = (k2_comp + k3_comp).into();
                *y ^= val;
                res.a = k3_comp.neg();
                res.b = k2_comp.neg();
            }
        }
    }

    // reshare y
    let y_a = r_vec;
    net.send_next_many(&y_a)?;
    let local_b = net.recv_prev_many()?;

    let y = izip!(y_a, local_b)
        .map(|(a, b)| BinaryShare::new(a, b))
        .collect_vec();

    let z = detail::low_depth_binary_add_mod_p_many::<F, N>(
        x,
        &y,
        net,
        state,
        F::MODULUS_BIT_SIZE as usize,
    )?;

    match state.id {
        PartyID::ID0 => {
            let z_b = z.iter().cloned().map(|z| z.b).collect::<Vec<_>>();
            net.send_next_many(&z_b)?;
            let rcv: Vec<BigUint> = net.recv_prev_many()?;

            for (res, z, rcv) in izip!(res.iter_mut(), z, rcv.iter()) {
                res.a = (z.a ^ z.b ^ rcv).into();
            }
        }
        PartyID::ID1 => {
            let rcv: Vec<BigUint> = net.recv_prev_many()?;
            for (res, z, rcv) in izip!(res.iter_mut(), z, rcv.iter()) {
                res.b = (z.a ^ z.b ^ rcv).into();
            }
        }
        PartyID::ID2 => {
            let z_b = z.into_iter().map(|z| z.b).collect::<Vec<_>>();
            net.send_next_many(&z_b)?;
        }
    }
    Ok(res)
}

/// Translates one shared bits into an arithmetic sharing of the same bit. I.e., the shared bit x = x_1 xor x_2 xor x_3 gets transformed into x = x'_1 + x'_2 + x'_3, with x being either 0 or 1.
pub fn bit_inject<F: PrimeField, N: Network>(
    x: &Rep3BigUintShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3PrimeFieldShare<F>> {
    assert!(x.a.bits() <= 1);
    assert!(x.b.bits() <= 1);

    // Approach: Split the value into x and y and compute an arithmetic xor.
    // The multiplication in the arithmetic xor is done in a special way according to https://eprint.iacr.org/2025/919.pdf

    match state.id {
        PartyID::ID0 => {
            let x0: F = state.rngs.rand.masking_field_element();
            let y = if x.b.bit(0) { F::one() } else { F::zero() };
            let z0 = y * x0;
            let r0 = x0 + y - z0 - z0;
            let res_a = r0;
            // Send to P1
            net.send_next(res_a)?;

            // Receive from P2
            let res_b: F = net.recv_prev()?;
            Ok(Rep3PrimeFieldShare::new(res_a, res_b))
        }
        PartyID::ID1 => {
            let x1: F = state.rngs.rand.masking_field_element();
            let res_a = if x.a.bit(0) ^ x.b.bit(0) {
                x1 + F::one()
            } else {
                x1
            };
            // Send to P2
            net.send_next(res_a)?;

            // Receive from P0
            let res_b: F = net.recv_prev()?;
            Ok(Rep3PrimeFieldShare::new(res_a, res_b))
        }
        PartyID::ID2 => {
            // Receive from P1
            let res_b: F = net.recv_prev()?;
            let x2: F = state.rngs.rand.masking_field_element();
            let y = if x.a.bit(0) { F::one() } else { F::zero() };
            let z2 = y * (res_b + x2);
            let r2 = x2 - z2 - z2;
            let res_a = r2;

            // Send to P0
            net.send_next(res_a)?;
            Ok(Rep3PrimeFieldShare::new(res_a, res_b))
        }
    }
}

/// Translates a vector of shared bit into a vector of arithmetic sharings of the same bits. See [bit_inject] for details.
pub fn bit_inject_many<F: PrimeField, N: Network>(
    x: &[Rep3BigUintShare<F>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    assert!(x.iter().all(|a| a.a.bits() <= 1));
    assert!(x.iter().all(|a| a.b.bits() <= 1));

    let mut res_a = Vec::with_capacity(x.len());

    // Approach: Split the value into x and y and compute an arithmetic xor.
    // The multiplication in the arithmetic xor is done in a special way according to https://eprint.iacr.org/2025/919.pdf

    let res_b = match state.id {
        PartyID::ID0 => {
            for el in x.iter() {
                let x0: F = state.rngs.rand.masking_field_element();
                let y = if el.b.bit(0) { F::one() } else { F::zero() };
                let z0 = y * x0;
                let r0 = x0 + y - z0 - z0;
                res_a.push(r0);
            }
            // Send to P1
            net.send_next_many(&res_a)?;

            // Receive from P2
            let res_b: Vec<F> = net.recv_prev_many()?;
            if res_b.len() != x.len() {
                eyre::bail!("Received wrong number of elements");
            }
            res_b
        }
        PartyID::ID1 => {
            for el in x.iter() {
                let x1: F = state.rngs.rand.masking_field_element();
                res_a.push(if el.a.bit(0) ^ el.b.bit(0) {
                    x1 + F::one()
                } else {
                    x1
                });
            }
            // Send to P2
            net.send_next_many(&res_a)?;

            // Receive from P0
            let res_b: Vec<F> = net.recv_prev_many()?;
            if res_b.len() != x.len() {
                eyre::bail!("Received wrong number of elements");
            }
            res_b
        }
        PartyID::ID2 => {
            // Receive from P1
            let res_b: Vec<F> = net.recv_prev_many()?;
            if res_b.len() != x.len() {
                eyre::bail!("Received wrong number of elements");
            }

            for (el, x1) in izip!(x.iter(), res_b.iter()) {
                let x2: F = state.rngs.rand.masking_field_element();
                let y = if el.a.bit(0) { F::one() } else { F::zero() };
                let z2 = y * (*x1 + x2);
                let r2 = x2 - z2 - z2;
                res_a.push(r2);
            }

            // Send to P0
            net.send_next_many(&res_a)?;
            res_b
        }
    };

    Ok(res_a
        .into_iter()
        .zip(res_b)
        .map(|(a, b)| Rep3PrimeFieldShare::new(a, b))
        .collect())
}

/// Transforms the replicated shared value x from an arithmetic sharing to a yao sharing. I.e., x = x_1 + x_2 + x_3 gets transformed into wires, such that the garbler have keys (k_0, delta) for each bit of x, while the evaluator has k_x = k_0 xor delta * x.
pub fn a2y<F: PrimeField, N: Network>(
    x: Rep3PrimeFieldShare<F>,
    delta: Option<WireMod2>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<BinaryBundle<WireMod2>> {
    let [x01, x2] = yao::joint_input_arithmetic_added(x, delta, net, state)?;

    let converted = match state.id {
        PartyID::ID0 => {
            let mut evaluator = Rep3Evaluator::new(net);
            evaluator.receive_circuit()?;
            let res = GarbledCircuits::adder_mod_p::<_, F>(&mut evaluator, &x01, &x2);
            GCUtils::garbled_circuits_error(res)?
        }
        PartyID::ID1 | PartyID::ID2 => {
            let delta = delta.ok_or(eyre::eyre!("No delta provided"))?;
            let mut garbler = Rep3Garbler::new_with_delta(net, state, delta);
            let res = GarbledCircuits::adder_mod_p::<_, F>(&mut garbler, &x01, &x2);
            let res = GCUtils::garbled_circuits_error(res)?;
            garbler.send_circuit()?;
            res
        }
    };

    Ok(converted)
}

/// Transforms the replicated shared value x from an arithmetic sharing to a yao sharing. I.e., x = x_1 + x_2 + x_3 gets transformed into wires, such that the garbler have keys (k_0, delta) for each bit of x, while the evaluator has k_x = k_0 xor delta * x. Uses the Streaming Garbler/Evaluator.
pub fn a2y_streaming<F: PrimeField, N: Network>(
    x: Rep3PrimeFieldShare<F>,
    delta: Option<WireMod2>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<BinaryBundle<WireMod2>> {
    let [x01, x2] = yao::joint_input_arithmetic_added(x, delta, net, state)?;

    let converted = match state.id {
        PartyID::ID0 => {
            let mut evaluator = StreamingRep3Evaluator::new(net);
            let res = GarbledCircuits::adder_mod_p::<_, F>(&mut evaluator, &x01, &x2);
            let res = GCUtils::garbled_circuits_error(res)?;
            evaluator.receive_hash()?;
            res
        }
        PartyID::ID1 | PartyID::ID2 => {
            let delta = delta.ok_or(eyre::eyre!("No delta provided"))?;
            let mut garbler = StreamingRep3Garbler::new_with_delta(net, state, delta);
            let res = GarbledCircuits::adder_mod_p::<_, F>(&mut garbler, &x01, &x2);
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
        let k2 = $state.rngs.bitcomp1.random_fes_3keys::<F>();
        $res.a = (k2.0 + k2.1 + k2.2).neg();
        let x23 = yao::input_field_id2::<F, _>(None, None, $net, $state)?;

        let mut garbler = <$garbler>::new_with_delta($net, $state, delta);
        let x1 = GarbledCircuits::adder_mod_p::<_, F>(&mut garbler, &$x, &x23);
        let x1 = GCUtils::garbled_circuits_error(x1)?;
        let x1 = garbler.output_to_id0_and_id1(x1.wires())?;
        let x1 = x1.ok_or(eyre::eyre!("No output received"))?;
        $res.b = GCUtils::bits_to_field(&x1)?;
    }};
}

macro_rules! y2a_impl_p2 {
    ($garbler:ty,$x:expr,$delta:expr,$net:expr,$state:expr,$res:expr) => {{
        let delta = $delta.ok_or(eyre::eyre!("No delta provided"))?;
        let k2 = $state.rngs.bitcomp1.random_fes_3keys::<F>();
        let k3 = $state.rngs.bitcomp2.random_fes_3keys::<F>();
        let k2_comp = k2.0 + k2.1 + k2.2;
        let k3_comp = k3.0 + k3.1 + k3.2;
        let x23 = Some(k2_comp + k3_comp);
        $res.a = k3_comp.neg();
        $res.b = k2_comp.neg();
        let x23 = yao::input_field_id2(x23, Some(delta), $net, $state)?;

        let mut garbler = <$garbler>::new_with_delta($net, $state, delta);
        let x1 = GarbledCircuits::adder_mod_p::<_, F>(&mut garbler, &$x, &x23);
        let x1 = GCUtils::garbled_circuits_error(x1)?;
        let x1 = garbler.output_to_id0_and_id1(x1.wires())?;
        if x1.is_some() {
            eyre::bail!("Unexpected output received",);
        }
    }};
}

/// Transforms the shared value x from a yao sharing to an arithmetic sharing. I.e., the sharing such that the garbler have keys (k_0, delta) for each bit of x, while the evaluator has k_x = k_0 xor delta * x gets transformed into x = x_1 + x_2 + x_3.
///
/// Keep in mind: Only works if the input is actually a binary sharing of a valid field element
/// If the input has the correct number of bits, but is >= P, then either x can be reduced with self.low_depth_sub_p_cmux(x) first, or self.low_depth_binary_add_2_mod_p(x, y) is extended to subtract 2P in parallel as well. The second solution requires another multiplexer in the end. These adaptions need to be encoded into a garbled circuit.
pub fn y2a<F: PrimeField, N: Network>(
    x: BinaryBundle<WireMod2>,
    delta: Option<WireMod2>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3PrimeFieldShare<F>> {
    let mut res = Rep3PrimeFieldShare::zero_share();

    match state.id {
        PartyID::ID0 => {
            let k3 = state.rngs.bitcomp2.random_fes_3keys::<F>();
            res.b = (k3.0 + k3.1 + k3.2).neg();
            let x23 = yao::input_field_id2::<F, _>(None, None, net, state)?;

            let mut evaluator = Rep3Evaluator::new(net);
            evaluator.receive_circuit()?;
            let x1 = GarbledCircuits::adder_mod_p::<_, F>(&mut evaluator, &x, &x23);
            let x1 = GCUtils::garbled_circuits_error(x1)?;
            let x1 = evaluator.output_to_id0_and_id1(x1.wires())?;
            res.a = GCUtils::bits_to_field(&x1)?;
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
///
/// Keep in mind: Only works if the input is actually a binary sharing of a valid field element
/// If the input has the correct number of bits, but is >= P, then either x can be reduced with self.low_depth_sub_p_cmux(x) first, or self.low_depth_binary_add_2_mod_p(x, y) is extended to subtract 2P in parallel as well. The second solution requires another multiplexer in the end. These adaptions need to be encoded into a garbled circuit.
pub fn y2a_streaming<F: PrimeField, N: Network>(
    x: BinaryBundle<WireMod2>,
    delta: Option<WireMod2>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3PrimeFieldShare<F>> {
    let mut res = Rep3PrimeFieldShare::zero_share();

    match state.id {
        PartyID::ID0 => {
            let k3 = state.rngs.bitcomp2.random_fes_3keys::<F>();
            res.b = (k3.0 + k3.1 + k3.2).neg();
            let x23 = yao::input_field_id2::<F, _>(None, None, net, state)?;

            let mut evaluator = StreamingRep3Evaluator::new(net);
            let x1 = GarbledCircuits::adder_mod_p::<_, F>(&mut evaluator, &x, &x23);
            let x1 = GCUtils::garbled_circuits_error(x1)?;
            let x1 = evaluator.output_to_id0_and_id1(x1.wires())?;
            res.a = GCUtils::bits_to_field(&x1)?;
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
///
/// Keep in mind: Only works if the input is actually a binary sharing of a valid field element
/// If the input has the correct number of bits, but is >= P, then either x can be reduced with self.low_depth_sub_p_cmux(x) first, or self.low_depth_binary_add_2_mod_p(x, y) is extended to subtract 2P in parallel as well. The second solution requires another multiplexer in the end. These adaptions need to be encoded into a garbled circuit.
pub fn b2y<F: PrimeField, N: Network>(
    x: &Rep3BigUintShare<F>,
    delta: Option<WireMod2>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<BinaryBundle<WireMod2>> {
    let [x01, x2] =
        yao::joint_input_binary_xored(x, delta, net, state, F::MODULUS_BIT_SIZE as usize)?;

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
pub fn y2b<F: PrimeField, N: Network>(
    x: BinaryBundle<WireMod2>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3BigUintShare<F>> {
    let bitlen = x.size();
    let collapsed = GCUtils::collapse_bundle_to_lsb_bits_as_biguint(x);

    let converted = match state.id {
        PartyID::ID0 => {
            let x_xor_px = collapsed;
            let r = state.rngs.rand.random_biguint_rng1(bitlen);
            let r_xor_x_xor_px = x_xor_px ^ &r;
            net.send_to(PartyID::ID2, r_xor_x_xor_px.to_owned())?;
            Rep3BigUintShare::new(r, r_xor_x_xor_px)
        }
        PartyID::ID1 => {
            let px = collapsed;
            let r = state.rngs.rand.random_biguint_rng2(bitlen);
            Rep3BigUintShare::new(px, r)
        }
        PartyID::ID2 => {
            let px = collapsed;
            let r_xor_x_xor_px = net.recv_from(PartyID::ID0)?;
            Rep3BigUintShare::new(r_xor_x_xor_px, px)
        }
    };

    Ok(converted)
}

/// Transforms the shared values x from yao sharings to binary sharings. I.e., the sharing such that the garbler have keys (k_0, delta) for each bit of x, while the evaluator has k_x = k_0 xor delta * x gets transformed into x = x_1 xor x_2 xor x_3.
pub fn y2b_many<F: PrimeField, N: Network>(
    x: Vec<BinaryBundle<WireMod2>>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3BigUintShare<F>>> {
    let mut collapsed = Vec::with_capacity(x.len());
    let mut input_bitlengths = Vec::with_capacity(x.len());
    for chunk in x.iter() {
        input_bitlengths.push(chunk.size());
    }
    for chunk in x {
        collapsed.push(GCUtils::collapse_bundle_to_lsb_bits_as_biguint(chunk));
    }

    let mut result = Vec::with_capacity(collapsed.len());
    match state.id {
        PartyID::ID0 => {
            let mut r = Vec::with_capacity(collapsed.len());
            let mut r_xor_x_xor_px = Vec::with_capacity(collapsed.len());

            for (bitlen, x_xor_px) in izip!(input_bitlengths, collapsed) {
                let r_ = state.rngs.rand.random_biguint_rng1(bitlen);
                r_xor_x_xor_px.push(x_xor_px ^ &r_);
                r.push(r_);
            }

            net.send_many(PartyID::ID2, &r_xor_x_xor_px)?;
            for (r_xor_x_xor_px_, r_) in izip!(r_xor_x_xor_px, r) {
                result.push(Rep3BigUintShare::new(r_xor_x_xor_px_, r_));
            }
        }
        PartyID::ID1 => {
            for (bitlen, px) in izip!(input_bitlengths, collapsed) {
                result.push(Rep3BigUintShare::new(
                    px,
                    state.rngs.rand.random_biguint_rng2(bitlen),
                ));
            }
        }
        PartyID::ID2 => {
            let r_xor_x_xor_px = net.recv_many(PartyID::ID0)?;

            for (px, r_xor_x_xor_px_) in izip!(collapsed, r_xor_x_xor_px) {
                result.push(Rep3BigUintShare::new(px, r_xor_x_xor_px_));
            }
        }
    };

    Ok(result)
}

/// Transforms the replicated shared value x from an arithmetic sharing to a binary sharing. I.e., x = x_1 + x_2 + x_3 gets transformed into x = x'_1 xor x'_2 xor x'_3.
pub fn a2y2b<F: PrimeField, N: Network>(
    x: Rep3PrimeFieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3BigUintShare<F>> {
    let delta = state.rngs.generate_random_garbler_delta(state.id);
    let y = a2y(x, delta, net, state)?;
    y2b(y, net, state)
}

/// Transforms the replicated shared value x from an arithmetic sharing to a binary sharing. I.e., x = x_1 + x_2 + x_3 gets transformed into x = x'_1 xor x'_2 xor x'_3. Uses the Streaming Garbler/Evaluator.
pub fn a2y2b_streaming<F: PrimeField, N: Network>(
    x: Rep3PrimeFieldShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3BigUintShare<F>> {
    let delta = state.rngs.generate_random_garbler_delta(state.id);
    let y = a2y_streaming(x, delta, net, state)?;
    y2b(y, net, state)
}

/// Transforms the replicated shared value x from a binary sharing to an arithmetic sharing. I.e., x = x_1 xor x_2 xor x_3 gets transformed into x = x'_1 + x'_2 + x'_3. This implementations goes through the yao protocol and currently works only for a binary sharing of a valid field element, i.e., x = x_1 xor x_2 xor x_3 < p.
///
/// Keep in mind: Only works if the input is actually a binary sharing of a valid field element
/// If the input has the correct number of bits, but is >= P, then either x can be reduced with self.low_depth_sub_p_cmux(x) first, or self.low_depth_binary_add_2_mod_p(x, y) is extended to subtract 2P in parallel as well. The second solution requires another multiplexer in the end.
pub fn b2y2a<F: PrimeField, N: Network>(
    x: &Rep3BigUintShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3PrimeFieldShare<F>> {
    let delta = state.rngs.generate_random_garbler_delta(state.id);
    let y = b2y(x, delta, net, state)?;
    y2a(y, delta, net, state)
}

/// Transforms the replicated shared value x from a binary sharing to an arithmetic sharing. I.e., x = x_1 xor x_2 xor x_3 gets transformed into x = x'_1 + x'_2 + x'_3. This implementations goes through the yao protocol and currently works only for a binary sharing of a valid field element, i.e., x = x_1 xor x_2 xor x_3 < p. Uses the Streaming Garbler/Evaluator.
///
/// Keep in mind: Only works if the input is actually a binary sharing of a valid field element
/// If the input has the correct number of bits, but is >= P, then either x can be reduced with self.low_depth_sub_p_cmux(x) first, or self.low_depth_binary_add_2_mod_p(x, y) is extended to subtract 2P in parallel as well. The second solution requires another multiplexer in the end.
pub fn b2y2a_streaming<F: PrimeField, N: Network>(
    x: &Rep3BigUintShare<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3PrimeFieldShare<F>> {
    let delta = state.rngs.generate_random_garbler_delta(state.id);
    let y = b2y(x, delta, net, state)?;
    y2a_streaming(y, delta, net, state)
}

/// This function is the first local step of the point_sharing to sharing of the coordinates transformation. In essence, it is very similar to what is done in a2b. It takes a point share and produces two trivial shares of its x and y coordinates each. To create valid (x,y) coordinate shares from it, these shares need to be added according to the point_addition rules of elliptic curves.
#[expect(clippy::type_complexity)]
pub(crate) fn point_share_to_fieldshares_pre<C: CurveGroup, N: Network>(
    x: Rep3PointShare<C>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<(
    Rep3PrimeFieldShare<C::BaseField>,
    Rep3PrimeFieldShare<C::BaseField>,
    Rep3PrimeFieldShare<C::BaseField>,
    Rep3PrimeFieldShare<C::BaseField>,
)>
where
    C::BaseField: PrimeField,
{
    let mut x01_x = Rep3PrimeFieldShare::zero_share();
    let mut x01_y = Rep3PrimeFieldShare::zero_share();
    let mut x2_x = Rep3PrimeFieldShare::zero_share();
    let mut x2_y = Rep3PrimeFieldShare::zero_share();

    let r_x = state.rngs.rand.masking_field_element::<C::BaseField>();
    let r_y = state.rngs.rand.masking_field_element::<C::BaseField>();

    match state.id {
        PartyID::ID0 => {
            x01_x.a = r_x;
            x01_y.a = r_y;
            if let Some((x, y)) = x.b.into_affine().xy() {
                x2_x.b = x;
                x2_y.b = y;
            }
        }
        PartyID::ID1 => {
            let val = x.a + x.b;
            if let Some((x, y)) = val.into_affine().xy() {
                x01_x.a = x + r_x;
                x01_y.a = y + r_y;
            } else {
                x01_x.a = r_x;
                x01_y.a = r_y;
            }
        }
        PartyID::ID2 => {
            x01_x.a = r_x;
            x01_y.a = r_y;
            if let Some((x, y)) = x.a.into_affine().xy() {
                x2_x.a = x;
                x2_y.a = y;
            }
        }
    }

    // reshare x01
    let local_b = net.reshare_many(&[x01_x.a.to_owned(), x01_y.a.to_owned()])?;
    if local_b.len() != 2 {
        eyre::bail!("Expected 2 elements");
    }
    x01_x.b = local_b[0];
    x01_y.b = local_b[1];

    Ok((x01_x, x01_y, x2_x, x2_y))
}

/// Transforms a replicated point share to shares of its coordinates.
/// The output will be (x, y, is_infinity). Thereby no statement is made on x, y if is_infinity is true.
#[expect(clippy::type_complexity)]
pub fn point_share_to_fieldshares<C: CurveGroup, N: Network>(
    x: Rep3PointShare<C>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<(
    Rep3PrimeFieldShare<C::BaseField>,
    Rep3PrimeFieldShare<C::BaseField>,
    Rep3PrimeFieldShare<C::BaseField>,
)>
where
    C::BaseField: PrimeField,
{
    let (x01_x, x01_y, x2_x, x2_y) = point_share_to_fieldshares_pre(x, net, state)?;
    detail::point_addition(x01_x, x01_y, x2_x, x2_y, net, state)
}

/// Transforms shares of coordinates to a replicated point share.
pub fn fieldshares_to_pointshare<C: CurveGroup, N: Network>(
    x: Rep3PrimeFieldShare<C::BaseField>,
    y: Rep3PrimeFieldShare<C::BaseField>,
    is_infinity: Rep3PrimeFieldShare<C::BaseField>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3PointShare<C>>
where
    C::BaseField: PrimeField,
{
    let mut y_x = Rep3PrimeFieldShare::zero_share();
    let mut y_y = Rep3PrimeFieldShare::zero_share();
    let mut res = Rep3PointShare::new(C::zero(), C::zero());

    let r_x = state.rngs.rand.masking_field_element::<C::BaseField>();
    let r_y = state.rngs.rand.masking_field_element::<C::BaseField>();

    match state.id {
        PartyID::ID0 => {
            let k3 = state.rngs.bitcomp2.random_curves_3keys::<C>();

            res.b = (k3.0 + k3.1 + k3.2).neg();
            y_x.a = r_x;
            y_y.a = r_y;
        }
        PartyID::ID1 => {
            let k2 = state.rngs.bitcomp1.random_curves_3keys::<C>();

            res.a = (k2.0 + k2.1 + k2.2).neg();
            y_x.a = r_x;
            y_y.a = r_y;
        }
        PartyID::ID2 => {
            let k2 = state.rngs.bitcomp1.random_curves_3keys::<C>();
            let k3 = state.rngs.bitcomp2.random_curves_3keys::<C>();

            let k2_comp = k2.0 + k2.1 + k2.2;
            let k3_comp = k3.0 + k3.1 + k3.2;

            let val = k2_comp + k3_comp;
            if let Some((x, y)) = val.into_affine().xy() {
                y_x.a = x + r_x;
                y_y.a = y + r_y;
            } else {
                y_x.a = r_x;
                y_y.a = r_y;
            }

            res.a = k3_comp.neg();
            res.b = k2_comp.neg();
        }
    }

    // reshare y
    let local_b = net.reshare_many(&[y_x.a.to_owned(), y_y.a.to_owned()])?;
    if local_b.len() != 2 {
        eyre::bail!("Expected 2 elements");
    }
    y_x.b = local_b[0];
    y_y.b = local_b[1];

    let z = detail::point_addition(x, y, y_x, y_y, net, state)?;
    // If infinity then z should be y
    let cmux = arithmetic::cmux_vec(is_infinity, &[y_x, y_y], &[z.0, z.1], net, state)?;
    // Since y is randomly chosen, it is very unlikely that the x-coordinate matches the x-coodrinate of x. Thus z.2 is already 0

    let z_a = [cmux[0].a, cmux[1].a, z.2.a];
    let z_b = [cmux[0].b, cmux[1].b, z.2.b];

    match state.id {
        PartyID::ID0 => {
            net.send_next_many(&z_b)?;
            let rcv = net.recv_prev_many::<C::BaseField>()?;
            if rcv.len() != 3 {
                eyre::bail!("Expected 3 elements");
            }
            res.a = detail::point_from_xy(
                z_a[0] + z_b[0] + rcv[0],
                z_a[1] + z_b[1] + rcv[1],
                z_a[2] + z_b[2] + rcv[2],
            )?;
        }
        PartyID::ID1 => {
            let rcv = net.recv_prev_many::<C::BaseField>()?;
            if rcv.len() != 3 {
                eyre::bail!("Expected 3 elements");
            }
            res.b = detail::point_from_xy(
                z_a[0] + z_b[0] + rcv[0],
                z_a[1] + z_b[1] + rcv[1],
                z_a[2] + z_b[2] + rcv[2],
            )?;
        }
        PartyID::ID2 => {
            net.send_next_many(&z_b)?;
        }
    }

    Ok(res)
}
