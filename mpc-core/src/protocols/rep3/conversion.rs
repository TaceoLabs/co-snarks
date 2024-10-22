//! Conversions
//!
//! This module contains conversions between share types

use super::{
    arithmetic, detail,
    id::PartyID,
    network::{IoContext, Rep3Network},
    yao::{self, circuits::GarbledCircuits, evaluator::Rep3Evaluator, garbler::Rep3Garbler},
    IoResult, Rep3BigUintShare, Rep3PrimeFieldShare,
};
use ark_ff::PrimeField;
use fancy_garbling::{BinaryBundle, WireMod2};
use num_bigint::BigUint;

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

/// Transforms the replicated shared value x from a binary sharing to an arithmetic sharing. I.e., x = x_1 xor x_2 xor x_3 gets transformed into x = x'_1 + x'_2 + x'_3. This implementation currently works only for a binary sharing of a valid field element, i.e., x = x_1 xor x_2 xor x_3 < p.
pub fn b2a_consume<F: PrimeField, N: Rep3Network>(
    x: Rep3BigUintShare<F>,
    io_context: &mut IoContext<N>,
) -> IoResult<Rep3PrimeFieldShare<F>> {
    b2a(&x, io_context)
}

/// Transforms the replicated shared value x from a binary sharing to an arithmetic sharing. I.e., x = x_1 xor x_2 xor x_3 gets transformed into x = x'_1 + x'_2 + x'_3. This implementation currently works only for a binary sharing of a valid field element, i.e., x = x_1 xor x_2 xor x_3 < p.

// Keep in mind: Only works if the input is actually a binary sharing of a valid field element
// If the input has the correct number of bits, but is >= P, then either x can be reduced with self.low_depth_sub_p_cmux(x) first, or self.low_depth_binary_add_2_mod_p(x, y) is extended to subtract 2P in parallel as well. The second solution requires another multiplexer in the end.
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

/// Translates one shared bit into an arithmetic sharing of the same bit. I.e., the shared bit x = x_1 xor x_2 xor x_3 gets transformed into x = x'_1 + x'_2 + x'_3, with x being either 0 or 1.
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

pub fn a2y<F: PrimeField, N: Rep3Network>(
    x: Rep3PrimeFieldShare<F>,
    delta: Option<WireMod2>,
    io_context: &mut IoContext<N>,
) -> IoResult<BinaryBundle<WireMod2>> {
    let [x01, x2] = yao::joint_input_arithmetic_added(x, delta, io_context)?;

    let converted = match io_context.id {
        PartyID::ID0 => {
            let mut evaluator = Rep3Evaluator::new(io_context);
            let res = GarbledCircuits::adder_mod_p::<_, F>(&mut evaluator, &x01, &x2)?;
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
            let mut garbler = Rep3Garbler::new_with_delta(io_context, delta);
            let res = GarbledCircuits::adder_mod_p::<_, F>(&mut garbler, &x01, &x2)?;
            garbler.send_hash()?;
            res
        }
    };

    Ok(converted)
}
