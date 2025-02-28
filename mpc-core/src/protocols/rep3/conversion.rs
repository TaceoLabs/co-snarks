//! Conversions
//!
//! This module contains conversions between share types

use crate::{protocols::rep3::arithmetic::BinaryShare, IoResult};

use super::{
    arithmetic, detail,
    network::{IoContext, Rep3Network},
    yao::{
        self, circuits::GarbledCircuits, evaluator::Rep3Evaluator, garbler::Rep3Garbler,
        streaming_evaluator::StreamingRep3Evaluator, streaming_garbler::StreamingRep3Garbler,
        GCUtils,
    },
    PartyID, Rep3BigUintShare, Rep3PointShare, Rep3PrimeFieldShare,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use fancy_garbling::{BinaryBundle, WireMod2};
use itertools::{izip, Itertools as _};
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

/// Depending on the `A2BType` of the io_context, this function selects the appropriate implementation for the arithmetic-to-binary conversion.
pub fn a2b_selector<F: PrimeField, N: Rep3Network>(
    x: Rep3PrimeFieldShare<F>,
    io_context: &mut IoContext<N>,
) -> std::io::Result<Rep3BigUintShare<F>> {
    match io_context.a2b_type {
        A2BType::Direct => a2b(x, io_context),
        A2BType::Yao => a2y2b(x, io_context),
    }
}

/// Depending on the `A2BType` of the io_context, this function selects the appropriate implementation for the binary-to-arithmetic conversion.
pub fn b2a_selector<F: PrimeField, N: Rep3Network>(
    x: &Rep3BigUintShare<F>,
    io_context: &mut IoContext<N>,
) -> std::io::Result<Rep3PrimeFieldShare<F>> {
    match io_context.a2b_type {
        A2BType::Direct => b2a(x, io_context),
        A2BType::Yao => b2y2a(x, io_context),
    }
}

/// Transforms the replicated shared value x from an arithmetic sharing to a binary sharing. I.e., x = x_1 + x_2 + x_3 gets transformed into x = x'_1 xor x'_2 xor x'_3.
pub fn a2b<F: PrimeField, N: Rep3Network>(
    x: Rep3PrimeFieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3BigUintShare<F>> {
    let mut x01 = Rep3BigUintShare::zero_share();
    let mut x2 = Rep3BigUintShare::zero_share();

    let (mut r, r2) = io_context
        .rngs
        .rand
        .random_biguint(F::MODULUS_BIT_SIZE as usize);
    r ^= r2;

    match io_context.id {
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
    io_context.network.send_next(x01.a.to_owned())?;
    let local_b = io_context.network.recv_prev()?;
    x01.b = local_b;

    detail::low_depth_binary_add_mod_p::<F, N>(&x01, &x2, io_context, F::MODULUS_BIT_SIZE as usize)
}

/// Transforms the provided replicated shared values from an arithmetic sharing to a binary sharing. I.e., x = x_1 + x_2 + x_3 gets transformed into x = x'_1 xor x'_2 xor x'_3. Reduces the mul-depth by batching all elements together.
pub fn a2b_many<F: PrimeField, N: Rep3Network>(
    x: &[Rep3PrimeFieldShare<F>],
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<Rep3BigUintShare<F>>> {
    let mut x2 = vec![BinaryShare::<F>::zero_share(); x.len()];

    let mut r_vec = Vec::with_capacity(x.len());
    let mut r2_vec = Vec::with_capacity(x.len());
    for _ in 0..x.len() {
        let (mut r, r2) = io_context
            .rngs
            .rand
            .random_biguint(F::MODULUS_BIT_SIZE as usize);
        r ^= &r2;
        r_vec.push(r);
        r2_vec.push(r2);
    }

    let x01_a = match io_context.id {
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
    let x01_b = io_context.network.reshare_many(&x01_a)?;
    let x01 = izip!(x01_a, x01_b)
        .map(|(a, b)| BinaryShare::new(a, b))
        .collect_vec();

    detail::low_depth_binary_add_mod_p_many::<F, N>(
        &x01,
        &x2,
        io_context,
        F::MODULUS_BIT_SIZE as usize,
    )
}

/// Transforms the replicated shared value x from a binary sharing to an arithmetic sharing. I.e., x = x_1 xor x_2 xor x_3 gets transformed into x = x'_1 + x'_2 + x'_3. This implementation currently works only for a binary sharing of a valid field element, i.e., x = x_1 xor x_2 xor x_3 < p.
///
/// Keep in mind: Only works if the input is actually a binary sharing of a valid field element
/// If the input has the correct number of bits, but is >= P, then either x can be reduced with self.low_depth_sub_p_cmux(x) first, or self.low_depth_binary_add_2_mod_p(x, y) is extended to subtract 2P in parallel as well. The second solution requires another multiplexer in the end.
pub fn b2a<F: PrimeField, N: Rep3Network>(
    x: &Rep3BigUintShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3PrimeFieldShare<F>> {
    let mut y = Rep3BigUintShare::zero_share();
    let mut res = Rep3PrimeFieldShare::zero_share();

    let (mut r, r2) = io_context
        .rngs
        .rand
        .random_biguint(F::MODULUS_BIT_SIZE as usize);
    r ^= r2;

    match io_context.id {
        PartyID::ID0 => {
            let k3 = io_context.rngs.bitcomp2.random_fes_3keys::<F>();

            res.b = (k3.0 + k3.1 + k3.2).neg();
            y.a = r;
        }
        PartyID::ID1 => {
            let k2 = io_context.rngs.bitcomp1.random_fes_3keys::<F>();

            res.a = (k2.0 + k2.1 + k2.2).neg();
            y.a = r;
        }
        PartyID::ID2 => {
            let k2 = io_context.rngs.bitcomp1.random_fes_3keys::<F>();
            let k3 = io_context.rngs.bitcomp2.random_fes_3keys::<F>();

            let k2_comp = k2.0 + k2.1 + k2.2;
            let k3_comp = k3.0 + k3.1 + k3.2;
            let val: BigUint = (k2_comp + k3_comp).into();
            y.a = val ^ r;
            res.a = k3_comp.neg();
            res.b = k2_comp.neg();
        }
    }

    // reshare y
    io_context.network.send_next(y.a.to_owned())?;
    let local_b = io_context.network.recv_prev()?;
    y.b = local_b;

    let z = detail::low_depth_binary_add_mod_p::<F, N>(
        x,
        &y,
        io_context,
        F::MODULUS_BIT_SIZE as usize,
    )?;

    match io_context.id {
        PartyID::ID0 => {
            io_context.network.send_next(z.b.to_owned())?;
            let rcv: BigUint = io_context.network.recv_prev()?;
            res.a = (z.a ^ z.b ^ rcv).into();
        }
        PartyID::ID1 => {
            let rcv: BigUint = io_context.network.recv_prev()?;
            res.b = (z.a ^ z.b ^ rcv).into();
        }
        PartyID::ID2 => {
            io_context.network.send_next(z.b)?;
        }
    }
    Ok(res)
}

/// Translates one shared bits into an arithmetic sharing of the same bit. I.e., the shared bit x = x_1 xor x_2 xor x_3 gets transformed into x = x'_1 + x'_2 + x'_3, with x being either 0 or 1.
pub fn bit_inject<F: PrimeField, N: Rep3Network>(
    x: &Rep3BigUintShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3PrimeFieldShare<F>> {
    // standard bit inject
    assert!(x.a.bits() <= 1);

    let mut b0 = Rep3PrimeFieldShare::<F>::default();
    let mut b1 = Rep3PrimeFieldShare::<F>::default();
    let mut b2 = Rep3PrimeFieldShare::<F>::default();

    match io_context.id {
        PartyID::ID0 => {
            b0.a = x.a.to_owned().into();
            b2.b = x.b.to_owned().into();
        }
        PartyID::ID1 => {
            b1.a = x.a.to_owned().into();
            b0.b = x.b.to_owned().into();
        }
        PartyID::ID2 => {
            b2.a = x.a.to_owned().into();
            b1.b = x.b.to_owned().into();
        }
    };

    let d = arithmetic::arithmetic_xor(b0, b1, io_context)?;
    let e = arithmetic::arithmetic_xor(d, b2, io_context)?;
    Ok(e)
}

/// Translates a vector of shared bit into a vector of arithmetic sharings of the same bits. See [bit_inject] for details.
pub fn bit_inject_many<F: PrimeField, N: Rep3Network>(
    x: &[Rep3BigUintShare<F>],
    io_context: &mut IoContext<N>,
) -> IoResult<Vec<Rep3PrimeFieldShare<F>>> {
    // standard bit inject
    assert!(x.iter().all(|a| a.a.bits() <= 1));

    let mut b0 = vec![Rep3PrimeFieldShare::<F>::default(); x.len()];
    let mut b1 = vec![Rep3PrimeFieldShare::<F>::default(); x.len()];
    let mut b2 = vec![Rep3PrimeFieldShare::<F>::default(); x.len()];

    match io_context.id {
        PartyID::ID0 => {
            for (b0, b2, x) in izip!(&mut b0, &mut b2, x.iter().cloned()) {
                b0.a = x.a.into();
                b2.b = x.b.into();
            }
        }
        PartyID::ID1 => {
            for (b1, b0, x) in izip!(&mut b1, &mut b0, x.iter().cloned()) {
                b1.a = x.a.into();
                b0.b = x.b.into();
            }
        }
        PartyID::ID2 => {
            for (b2, b1, x) in izip!(&mut b2, &mut b1, x.iter().cloned()) {
                b2.a = x.a.into();
                b1.b = x.b.into();
            }
        }
    };

    let d = arithmetic::arithmetic_xor_many(&b0, &b1, io_context)?;
    let e = arithmetic::arithmetic_xor_many(&d, &b2, io_context)?;
    Ok(e)
}

/// Transforms the replicated shared value x from an arithmetic sharing to a yao sharing. I.e., x = x_1 + x_2 + x_3 gets transformed into wires, such that the garbler have keys (k_0, delta) for each bit of x, while the evaluator has k_x = k_0 xor delta * x.
pub fn a2y<F: PrimeField, N: Rep3Network>(
    x: Rep3PrimeFieldShare<F>,
    delta: Option<WireMod2>,
    io_context: &mut IoContext<N>,
) -> IoResult<BinaryBundle<WireMod2>> {
    let [x01, x2] = yao::joint_input_arithmetic_added(x, delta, io_context)?;

    let converted = match io_context.id {
        PartyID::ID0 => {
            let mut evaluator = Rep3Evaluator::new(io_context);
            evaluator.receive_circuit()?;
            let res = GarbledCircuits::adder_mod_p::<_, F>(&mut evaluator, &x01, &x2);
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
            let res = GarbledCircuits::adder_mod_p::<_, F>(&mut garbler, &x01, &x2);
            let res = GCUtils::garbled_circuits_error(res)?;
            garbler.send_circuit()?;
            res
        }
    };

    Ok(converted)
}

/// Transforms the replicated shared value x from an arithmetic sharing to a yao sharing. I.e., x = x_1 + x_2 + x_3 gets transformed into wires, such that the garbler have keys (k_0, delta) for each bit of x, while the evaluator has k_x = k_0 xor delta * x. Uses the Streaming Garbler/Evaluator.
pub fn a2y_streaming<F: PrimeField, N: Rep3Network>(
    x: Rep3PrimeFieldShare<F>,
    delta: Option<WireMod2>,
    io_context: &mut IoContext<N>,
) -> IoResult<BinaryBundle<WireMod2>> {
    let [x01, x2] = yao::joint_input_arithmetic_added(x, delta, io_context)?;

    let converted = match io_context.id {
        PartyID::ID0 => {
            let mut evaluator = StreamingRep3Evaluator::new(io_context);
            let res = GarbledCircuits::adder_mod_p::<_, F>(&mut evaluator, &x01, &x2);
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
            let res = GarbledCircuits::adder_mod_p::<_, F>(&mut garbler, &x01, &x2);
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

        let k2 = $io_context.rngs.bitcomp1.random_fes_3keys::<F>();
        $res.a = (k2.0 + k2.1 + k2.2).neg();
        let x23 = yao::input_field_id2::<F, _>(None, None, $io_context)?;

        let mut garbler = <$garbler>::new_with_delta($io_context, delta);
        let x1 = GarbledCircuits::adder_mod_p::<_, F>(&mut garbler, &$x, &x23);
        let x1 = GCUtils::garbled_circuits_error(x1)?;
        let x1 = garbler.output_to_id0_and_id1(x1.wires())?;
        let x1 = match x1 {
            Some(x1) => x1,
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "No output received",
            ))?,
        };
        $res.b = GCUtils::bits_to_field(&x1)?;
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

        let k2 = $io_context.rngs.bitcomp1.random_fes_3keys::<F>();
        let k3 = $io_context.rngs.bitcomp2.random_fes_3keys::<F>();
        let k2_comp = k2.0 + k2.1 + k2.2;
        let k3_comp = k3.0 + k3.1 + k3.2;
        let x23 = Some(k2_comp + k3_comp);
        $res.a = k3_comp.neg();
        $res.b = k2_comp.neg();
        let x23 = yao::input_field_id2(x23, Some(delta), $io_context)?;

        let mut garbler = <$garbler>::new_with_delta($io_context, delta);
        let x1 = GarbledCircuits::adder_mod_p::<_, F>(&mut garbler, &$x, &x23);
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
///
/// Keep in mind: Only works if the input is actually a binary sharing of a valid field element
/// If the input has the correct number of bits, but is >= P, then either x can be reduced with self.low_depth_sub_p_cmux(x) first, or self.low_depth_binary_add_2_mod_p(x, y) is extended to subtract 2P in parallel as well. The second solution requires another multiplexer in the end. These adaptions need to be encoded into a garbled circuit.
pub fn y2a<F: PrimeField, N: Rep3Network>(
    x: BinaryBundle<WireMod2>,
    delta: Option<WireMod2>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3PrimeFieldShare<F>> {
    let mut res = Rep3PrimeFieldShare::zero_share();

    match io_context.id {
        PartyID::ID0 => {
            let k3 = io_context.rngs.bitcomp2.random_fes_3keys::<F>();
            res.b = (k3.0 + k3.1 + k3.2).neg();
            let x23 = yao::input_field_id2::<F, _>(None, None, io_context)?;

            let mut evaluator = Rep3Evaluator::new(io_context);
            evaluator.receive_circuit()?;
            let x1 = GarbledCircuits::adder_mod_p::<_, F>(&mut evaluator, &x, &x23);
            let x1 = GCUtils::garbled_circuits_error(x1)?;
            let x1 = evaluator.output_to_id0_and_id1(x1.wires())?;
            res.a = GCUtils::bits_to_field(&x1)?;
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
///
/// Keep in mind: Only works if the input is actually a binary sharing of a valid field element
/// If the input has the correct number of bits, but is >= P, then either x can be reduced with self.low_depth_sub_p_cmux(x) first, or self.low_depth_binary_add_2_mod_p(x, y) is extended to subtract 2P in parallel as well. The second solution requires another multiplexer in the end. These adaptions need to be encoded into a garbled circuit.
pub fn y2a_streaming<F: PrimeField, N: Rep3Network>(
    x: BinaryBundle<WireMod2>,
    delta: Option<WireMod2>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3PrimeFieldShare<F>> {
    let mut res = Rep3PrimeFieldShare::zero_share();

    match io_context.id {
        PartyID::ID0 => {
            let k3 = io_context.rngs.bitcomp2.random_fes_3keys::<F>();
            res.b = (k3.0 + k3.1 + k3.2).neg();
            let x23 = yao::input_field_id2::<F, _>(None, None, io_context)?;

            let mut evaluator = StreamingRep3Evaluator::new(io_context);
            let x1 = GarbledCircuits::adder_mod_p::<_, F>(&mut evaluator, &x, &x23);
            let x1 = GCUtils::garbled_circuits_error(x1)?;
            let x1 = evaluator.output_to_id0_and_id1(x1.wires())?;
            res.a = GCUtils::bits_to_field(&x1)?;
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
///
/// Keep in mind: Only works if the input is actually a binary sharing of a valid field element
/// If the input has the correct number of bits, but is >= P, then either x can be reduced with self.low_depth_sub_p_cmux(x) first, or self.low_depth_binary_add_2_mod_p(x, y) is extended to subtract 2P in parallel as well. The second solution requires another multiplexer in the end. These adaptions need to be encoded into a garbled circuit.
pub fn b2y<F: PrimeField, N: Rep3Network>(
    x: &Rep3BigUintShare<F>,
    delta: Option<WireMod2>,
    io_context: &mut IoContext<N>,
) -> IoResult<BinaryBundle<WireMod2>> {
    let [x01, x2] =
        yao::joint_input_binary_xored(x, delta, io_context, F::MODULUS_BIT_SIZE as usize)?;

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
pub fn y2b<F: PrimeField, N: Rep3Network>(
    x: BinaryBundle<WireMod2>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3BigUintShare<F>> {
    let bitlen = x.size();
    let collapsed = GCUtils::collapse_bundle_to_lsb_bits_as_biguint(x);

    let converted = match io_context.id {
        PartyID::ID0 => {
            let x_xor_px = collapsed;
            let r = io_context.rngs.rand.random_biguint_rng1(bitlen);
            let r_xor_x_xor_px = x_xor_px ^ &r;
            io_context
                .network
                .send(PartyID::ID2, r_xor_x_xor_px.to_owned())?;
            Rep3BigUintShare::new(r, r_xor_x_xor_px)
        }
        PartyID::ID1 => {
            let px = collapsed;
            let r = io_context.rngs.rand.random_biguint_rng2(bitlen);
            Rep3BigUintShare::new(px, r)
        }
        PartyID::ID2 => {
            let px = collapsed;
            let r_xor_x_xor_px = io_context.network.recv(PartyID::ID0)?;
            Rep3BigUintShare::new(r_xor_x_xor_px, px)
        }
    };

    Ok(converted)
}

/// Transforms the replicated shared value x from an arithmetic sharing to a binary sharing. I.e., x = x_1 + x_2 + x_3 gets transformed into x = x'_1 xor x'_2 xor x'_3.
pub fn a2y2b<F: PrimeField, N: Rep3Network>(
    x: Rep3PrimeFieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3BigUintShare<F>> {
    let delta = io_context.rngs.generate_random_garbler_delta(io_context.id);
    let y = a2y(x, delta, io_context)?;
    y2b(y, io_context)
}

/// Transforms the replicated shared value x from an arithmetic sharing to a binary sharing. I.e., x = x_1 + x_2 + x_3 gets transformed into x = x'_1 xor x'_2 xor x'_3. Uses the Streaming Garbler/Evaluator.
pub fn a2y2b_streaming<F: PrimeField, N: Rep3Network>(
    x: Rep3PrimeFieldShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3BigUintShare<F>> {
    let delta = io_context.rngs.generate_random_garbler_delta(io_context.id);
    let y = a2y_streaming(x, delta, io_context)?;
    y2b(y, io_context)
}

/// Transforms the replicated shared value x from a binary sharing to an arithmetic sharing. I.e., x = x_1 xor x_2 xor x_3 gets transformed into x = x'_1 + x'_2 + x'_3. This implementations goes through the yao protocol and currently works only for a binary sharing of a valid field element, i.e., x = x_1 xor x_2 xor x_3 < p.
///
/// Keep in mind: Only works if the input is actually a binary sharing of a valid field element
/// If the input has the correct number of bits, but is >= P, then either x can be reduced with self.low_depth_sub_p_cmux(x) first, or self.low_depth_binary_add_2_mod_p(x, y) is extended to subtract 2P in parallel as well. The second solution requires another multiplexer in the end.
pub fn b2y2a<F: PrimeField, N: Rep3Network>(
    x: &Rep3BigUintShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3PrimeFieldShare<F>> {
    let delta = io_context.rngs.generate_random_garbler_delta(io_context.id);
    let y = b2y(x, delta, io_context)?;
    y2a(y, delta, io_context)
}

/// Transforms the replicated shared value x from a binary sharing to an arithmetic sharing. I.e., x = x_1 xor x_2 xor x_3 gets transformed into x = x'_1 + x'_2 + x'_3. This implementations goes through the yao protocol and currently works only for a binary sharing of a valid field element, i.e., x = x_1 xor x_2 xor x_3 < p. Uses the Streaming Garbler/Evaluator.
///
/// Keep in mind: Only works if the input is actually a binary sharing of a valid field element
/// If the input has the correct number of bits, but is >= P, then either x can be reduced with self.low_depth_sub_p_cmux(x) first, or self.low_depth_binary_add_2_mod_p(x, y) is extended to subtract 2P in parallel as well. The second solution requires another multiplexer in the end.
pub fn b2y2a_streaming<F: PrimeField, N: Rep3Network>(
    x: &Rep3BigUintShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3PrimeFieldShare<F>> {
    let delta = io_context.rngs.generate_random_garbler_delta(io_context.id);
    let y = b2y(x, delta, io_context)?;
    y2a_streaming(y, delta, io_context)
}

// The output will be (x, y, is_infinity). Thereby no statement is made on x, y if is_infinity is true.
pub fn point_share_to_fieldshares<C: CurveGroup, N: Rep3Network>(
    x: Rep3PointShare<C>,
    io_context: &mut IoContext<N>,
) -> IoResult<(
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

    let r_x = io_context.rngs.rand.masking_field_element::<C::BaseField>();
    let r_y = io_context.rngs.rand.masking_field_element::<C::BaseField>();

    match io_context.id {
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
    io_context
        .network
        .send_next_many(&[x01_x.a.to_owned(), x01_y.a.to_owned()])?;
    let local_b = io_context.network.recv_prev_many()?;
    if local_b.len() != 2 {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Expected 2 elements",
        ))?;
    }
    x01_x.b = local_b[0];
    x01_y.b = local_b[1];

    detail::point_addition(x01_x, x01_y, x2_x, x2_y, io_context)
}

pub fn fieldshares_to_pointshare<C: CurveGroup, N: Rep3Network>(
    x: Rep3PrimeFieldShare<C::BaseField>,
    y: Rep3PrimeFieldShare<C::BaseField>,
    is_infinity: Rep3PrimeFieldShare<C::BaseField>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3PointShare<C>>
where
    C::BaseField: PrimeField,
{
    let mut y_x = Rep3PrimeFieldShare::zero_share();
    let mut y_y = Rep3PrimeFieldShare::zero_share();
    let mut res = Rep3PointShare::new(C::zero(), C::zero());

    let r_x = io_context.rngs.rand.masking_field_element::<C::BaseField>();
    let r_y = io_context.rngs.rand.masking_field_element::<C::BaseField>();

    match io_context.id {
        PartyID::ID0 => {
            let k3 = io_context.rngs.bitcomp2.random_curves_3keys::<C>();

            res.b = (k3.0 + k3.1 + k3.2).neg();
            y_x.a = r_x;
            y_y.a = r_y;
        }
        PartyID::ID1 => {
            let k2 = io_context.rngs.bitcomp1.random_curves_3keys::<C>();

            res.a = (k2.0 + k2.1 + k2.2).neg();
            y_x.a = r_x;
            y_y.a = r_y;
        }
        PartyID::ID2 => {
            let k2 = io_context.rngs.bitcomp1.random_curves_3keys::<C>();
            let k3 = io_context.rngs.bitcomp2.random_curves_3keys::<C>();

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
    io_context
        .network
        .send_next_many(&[y_x.a.to_owned(), y_y.a.to_owned()])?;
    let local_b = io_context.network.recv_prev_many()?;
    if local_b.len() != 2 {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Expected 2 elements",
        ))?;
    }
    y_x.b = local_b[0];
    y_y.b = local_b[1];

    let z = detail::point_addition(x, y, y_x, y_y, io_context)?;
    let z_a = [z.0.a, z.1.a, z.2.a];
    let z_b = [z.0.b, z.1.b, z.2.b];

    match io_context.id {
        PartyID::ID0 => {
            io_context.network.send_next_many(&z_b)?;
            let rcv = io_context.network.recv_prev_many::<C::BaseField>()?;
            if rcv.len() != 3 {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Expected 3 elements",
                ))?;
            }
            res.a = detail::point_from_xy(
                z_a[0] + z_b[0] + rcv[0],
                z_a[1] + z_b[1] + rcv[1],
                z_a[2] + z_b[2] + rcv[2],
            )?;
        }
        PartyID::ID1 => {
            let rcv = io_context.network.recv_prev_many::<C::BaseField>()?;
            if rcv.len() != 3 {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Expected 3 elements",
                ))?;
            }
            res.b = detail::point_from_xy(
                z_a[0] + z_b[0] + rcv[0],
                z_a[1] + z_b[1] + rcv[1],
                z_a[2] + z_b[2] + rcv[2],
            )?;
        }
        PartyID::ID2 => {
            io_context.network.send_next_many(&z_b)?;
        }
    }

    // TODO maybe multiply with !is_ifinity?
    Ok(res)
}
