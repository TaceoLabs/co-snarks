pub mod circuits;
pub mod evaluator;
pub mod garbler;

use super::{
    network::{IoContext, Rep3Network},
    IoResult, Rep3PrimeFieldShare,
};
use ark_ff::{PrimeField, Zero};
use fancy_garbling::{BinaryBundle, WireMod2};
use num_bigint::BigUint;

/// A structure that contains both the garbler and the evaluators
pub struct GCInputs<F> {
    pub garbler_wires: BinaryBundle<F>,
    pub evaluator_wires: BinaryBundle<F>,
    pub delta: F,
}

pub struct GCUtils {}

impl GCUtils {
    fn u16_bits_to_field<F: PrimeField>(bits: Vec<u16>) -> eyre::Result<F> {
        let mut res = BigUint::zero();
        for bit in bits.iter().rev() {
            assert!(*bit < 2);
            res <<= 1;
            res += *bit as u64;
        }

        if res >= F::MODULUS.into() {
            return Err(eyre::eyre!("Invalid field element"));
        }
        Ok(F::from(res))
    }

    pub fn bits_to_field<F: PrimeField>(bits: Vec<bool>) -> eyre::Result<F> {
        let mut res = BigUint::zero();
        for bit in bits.iter().rev() {
            res <<= 1;
            res += *bit as u64;
        }
        if res >= F::MODULUS.into() {
            return Err(eyre::eyre!("Invalid field element"));
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
}

/// Transforms an arithmetically shared input [x] = (x_1, x_2, x_3) into three yao shares [x_1]^Y, [x_2]^Y, [x_3]^Y. The used delta is an input to the function to allow for the same delta to be used for multiple conversions.
pub fn joint_input_arithmetic<F: PrimeField, N: Rep3Network>(
    x: Rep3PrimeFieldShare<F>,
    delta: Option<WireMod2>,
    io_context: &mut IoContext<N>,
) -> IoResult<[BinaryBundle<WireMod2>; 3]> {
    match io_context.id {
        crate::protocols::rep3::id::PartyID::ID0 => todo!(),
        crate::protocols::rep3::id::PartyID::ID1 => todo!(),
        crate::protocols::rep3::id::PartyID::ID2 => todo!(),
    }

    todo!()
}
