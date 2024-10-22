pub mod circuits;
pub mod evaluator;
pub mod garbler;

use super::{
    network::{IoContext, Rep3Network},
    IoResult, Rep3BigUintShare, Rep3PrimeFieldShare,
};
use crate::protocols::rep3::id::PartyID;
use ark_ff::{PrimeField, Zero};
use fancy_garbling::{BinaryBundle, WireLabel, WireMod2};
use itertools::Itertools;
use num_bigint::BigUint;
use rand::{CryptoRng, Rng};
use scuttlebutt::Block;

/// A structure that contains both the garbler and the evaluators
pub struct GCInputs<F> {
    pub garbler_wires: BinaryBundle<F>,
    pub evaluator_wires: BinaryBundle<F>,
    pub delta: F,
}

pub struct GCUtils {}

impl GCUtils {
    pub(crate) fn garbled_circuits_error<G, T>(input: Result<T, G>) -> IoResult<T> {
        input.or(Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Garbled Circuit failed",
        )))
    }

    fn receive_block_from<N: Rep3Network>(network: &mut N, id: PartyID) -> IoResult<Block> {
        let data: Vec<u8> = network.recv(id)?;
        if data.len() != 16 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "To little elements received",
            ));
        }
        let mut v = Block::default();
        v.as_mut().copy_from_slice(&data);

        Ok(v)
    }

    fn receive_bundle_from<N: Rep3Network>(
        n_bits: usize,
        network: &mut N,
        id: PartyID,
    ) -> IoResult<BinaryBundle<WireMod2>> {
        let mut x = Vec::with_capacity(n_bits);
        for _ in 0..n_bits {
            let block = GCUtils::receive_block_from(network, id)?;
            x.push(WireMod2::from_block(block, 2));
        }
        Ok(BinaryBundle::new(x))
    }

    fn send_inputs<N: Rep3Network>(
        input: &GCInputs<WireMod2>,
        network: &mut N,
        garbler_id: PartyID,
    ) -> IoResult<()> {
        for val in input.garbler_wires.iter() {
            network.send(garbler_id, val.as_block().as_ref())?;
        }
        for val in input.evaluator_wires.iter() {
            network.send(PartyID::ID0, val.as_block().as_ref())?;
        }

        Ok(())
    }

    /// Samples a random delta
    pub fn random_delta<R: Rng + CryptoRng>(rng: &mut R) -> WireMod2 {
        WireMod2::rand_delta(rng, 2)
    }

    #[cfg(test)]
    fn u16_bits_to_field<F: PrimeField>(bits: Vec<u16>) -> IoResult<F> {
        let mut res = BigUint::zero();
        for bit in bits.iter().rev() {
            assert!(*bit < 2);
            res <<= 1;
            res += *bit as u64;
        }

        if res >= F::MODULUS.into() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid field element",
            ));
        }
        Ok(F::from(res))
    }

    pub fn bits_to_field<F: PrimeField>(bits: Vec<bool>) -> IoResult<F> {
        let mut res = BigUint::zero();
        for bit in bits.iter().rev() {
            res <<= 1;
            res += *bit as u64;
        }
        if res >= F::MODULUS.into() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid field element",
            ));
        }
        Ok(F::from(res))
    }

    fn biguint_to_bits(input: BigUint, n_bits: usize) -> Vec<bool> {
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

    fn field_to_bits_as_u16<F: PrimeField>(field: F) -> Vec<u16> {
        let n_bits = F::MODULUS_BIT_SIZE as usize;
        let bigint: BigUint = field.into();

        Self::biguint_to_bits_as_u16(bigint, n_bits)
    }

    fn biguint_to_bits_as_u16(input: BigUint, n_bits: usize) -> Vec<u16> {
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
    fn encode_bits<R: Rng + CryptoRng>(
        bits: Vec<u16>,
        rng: &mut R,
        delta: WireMod2,
    ) -> GCInputs<WireMod2> {
        let mut garbler_wires = Vec::with_capacity(bits.len());
        let mut evaluator_wires = Vec::with_capacity(bits.len());
        for bit in bits {
            let (mine, theirs) = Self::encode_wire(rng, &delta, bit);
            garbler_wires.push(mine);
            evaluator_wires.push(theirs);
        }
        GCInputs {
            garbler_wires: BinaryBundle::new(garbler_wires),
            evaluator_wires: BinaryBundle::new(evaluator_wires),
            delta,
        }
    }

    /// This puts the X_0 values into garbler_wires and X_c values into evaluator_wires
    pub fn encode_bigint<R: Rng + CryptoRng>(
        bigint: BigUint,
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

/// Transforms an arithmetically shared input [x] = (x_1, x_2, x_3) into three yao shares [x_1]^Y, [x_2]^Y, [x_3]^Y. The used delta is an input to the function to allow for the same delta to be used for multiple conversions.
pub fn joint_input_arithmetic<F: PrimeField, N: Rep3Network, R: Rng + CryptoRng>(
    x: Rep3PrimeFieldShare<F>,
    delta: Option<WireMod2>,
    io_context: &mut IoContext<N>,
    rng: &mut R,
) -> IoResult<[BinaryBundle<WireMod2>; 3]> {
    let id = io_context.id;
    let n_bits = F::MODULUS_BIT_SIZE as usize;

    // x1 is known by both garblers, we can do a shortcut
    let mut x1 = (0..n_bits)
        .map(|_| WireMod2::from_block(io_context.rngs.generate_shared::<Block>(id), 2))
        .collect_vec();

    let (x0, x2) = match id {
        PartyID::ID0 => {
            // Receive x0
            let x0 = GCUtils::receive_bundle_from(n_bits, &mut io_context.network, PartyID::ID1)?;

            // Receive x2
            let x2 = GCUtils::receive_bundle_from(n_bits, &mut io_context.network, PartyID::ID2)?;
            (x0, x2)
        }
        PartyID::ID1 => {
            let delta = match delta {
                Some(delta) => delta,
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "No delta provided",
                ))?,
            };

            // Modify x1
            let x1_bits = GCUtils::field_to_bits_as_u16(x.a);
            x1.iter_mut().zip(x1_bits).for_each(|(x, bit)| {
                x.plus_eq(&delta.cmul(bit));
            });

            // Input x0
            let x0 = GCUtils::encode_field(x.b, rng, delta);

            // Send x0 to the other parties
            GCUtils::send_inputs(&x0, &mut io_context.network, PartyID::ID2)?;
            let x0 = x0.garbler_wires;

            // Receive x2
            let x2 = GCUtils::receive_bundle_from(n_bits, &mut io_context.network, PartyID::ID2)?;
            (x0, x2)
        }
        PartyID::ID2 => {
            let delta = match delta {
                Some(delta) => delta,
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "No delta provided",
                ))?,
            };

            // Modify x1
            let x1_bits = GCUtils::field_to_bits_as_u16(x.b);
            x1.iter_mut().zip(x1_bits).for_each(|(x, bit)| {
                x.plus_eq(&delta.cmul(bit));
            });

            // Input x2
            let x2 = GCUtils::encode_field(x.a, rng, delta);

            // Send x2 to the other parties
            GCUtils::send_inputs(&x2, &mut io_context.network, PartyID::ID1)?;
            let x2 = x2.garbler_wires;

            // Receive x0
            let x0 = GCUtils::receive_bundle_from(n_bits, &mut io_context.network, PartyID::ID1)?;
            (x0, x2)
        }
    };
    let x1 = BinaryBundle::new(x1);

    Ok([x0, x1, x2])
}

/// Transforms an arithmetically shared input [x] = (x_1, x_2, x_3) into two yao shares [x_1]^Y, [x_2 + x_3]^Y. The used delta is an input to the function to allow for the same delta to be used for multiple conversions.
pub fn joint_input_arithmetic_added<F: PrimeField, N: Rep3Network, R: Rng + CryptoRng>(
    x: Rep3PrimeFieldShare<F>,
    delta: Option<WireMod2>,
    io_context: &mut IoContext<N>,
    rng: &mut R,
) -> IoResult<[BinaryBundle<WireMod2>; 2]> {
    let id = io_context.id;
    let n_bits = F::MODULUS_BIT_SIZE as usize;

    let (x01, x2) = match id {
        PartyID::ID0 => {
            // Receive x0
            let x01 = GCUtils::receive_bundle_from(n_bits, &mut io_context.network, PartyID::ID1)?;

            // Receive x2
            let x2 = GCUtils::receive_bundle_from(n_bits, &mut io_context.network, PartyID::ID2)?;
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
            let sum = x.a + x.b;
            let x01 = GCUtils::encode_field(sum, rng, delta);

            // Send x01 to the other parties
            GCUtils::send_inputs(&x01, &mut io_context.network, PartyID::ID2)?;
            let x01 = x01.garbler_wires;

            // Receive x2
            let x2 = GCUtils::receive_bundle_from(n_bits, &mut io_context.network, PartyID::ID2)?;
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
            let x2 = GCUtils::encode_field(x.a, rng, delta);

            // Send x2 to the other parties
            GCUtils::send_inputs(&x2, &mut io_context.network, PartyID::ID1)?;
            let x2 = x2.garbler_wires;

            // Receive x01
            let x01 = GCUtils::receive_bundle_from(n_bits, &mut io_context.network, PartyID::ID1)?;
            (x01, x2)
        }
    };

    Ok([x01, x2])
}

/// Transforms an binary shared input [x] = (x_1, x_2, x_3) into two yao shares [x_1]^Y, [x_2 ^ x_3]^Y. The used delta is an input to the function to allow for the same delta to be used for multiple conversions.
pub fn joint_input_binary_xored<F: PrimeField, N: Rep3Network, R: Rng + CryptoRng>(
    x: Rep3BigUintShare<F>,
    delta: Option<WireMod2>,
    io_context: &mut IoContext<N>,
    rng: &mut R,
    bitlen: usize,
) -> IoResult<[BinaryBundle<WireMod2>; 2]> {
    let id = io_context.id;

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
            let x01 = GCUtils::encode_bigint(xor, bitlen, rng, delta);

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
            let x2 = GCUtils::encode_bigint(x.a, bitlen, rng, delta);

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

pub fn input_field_id2<F: PrimeField, N: Rep3Network, R: Rng + CryptoRng>(
    x: Option<F>,
    delta: Option<WireMod2>,
    io_context: &mut IoContext<N>,
    rng: &mut R,
) -> IoResult<BinaryBundle<WireMod2>> {
    let id = io_context.id;
    let n_bits = F::MODULUS_BIT_SIZE as usize;

    let x = match id {
        PartyID::ID0 | PartyID::ID1 => {
            // Receive x
            GCUtils::receive_bundle_from(n_bits, &mut io_context.network, PartyID::ID2)?
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

            let x = GCUtils::encode_field(x, rng, delta);

            // Send x to the other parties
            GCUtils::send_inputs(&x, &mut io_context.network, PartyID::ID1)?;
            x.garbler_wires
        }
    };
    Ok(x)
}
