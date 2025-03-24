use crate::{crs::ProverCrs, HonkProofError, HonkProofResult};
use ark_ec::{pairing::Pairing, VariableBaseMSM};
use ark_ff::{One, PrimeField, Zero};
use eyre::Error;
use mpc_core::gadgets;
use num_bigint::BigUint;
use std::array;
pub struct Utils {}

impl Utils {
    // BASE 16 [
    //     1,
    //     16,
    //     256,
    //     4096,
    //     65536,
    //     1048576,
    //     16777216,
    //     268435456,
    //     4294967296,
    //     68719476736,
    //     1099511627776,
    //     17592186044416,
    //     281474976710656,
    //     4503599627370496,
    //     72057594037927936,
    //     1152921504606846976,
    //     18446744073709551616,
    //     295147905179352825856,
    //     4722366482869645213696,
    //     75557863725914323419136,
    //     1208925819614629174706176,
    //     19342813113834066795298816,
    //     309485009821345068724781056,
    //     4951760157141521099596496896,
    //     79228162514264337593543950336,
    //     1267650600228229401496703205376,
    //     20282409603651670423947251286016,
    //     324518553658426726783156020576256,
    //     5192296858534827628530496329220096,
    //     83076749736557242056487941267521536,
    //     1329227995784915872903807060280344576,
    //     21267647932558653966460912964485513216,
    // ];

    // BASE 28 [
    //     1,
    //     28,
    //     784,
    //     21952,
    //     614656,
    //     17210368,
    //     481890304,
    //     13492928512,
    //     377801998336,
    //     10578455953408,
    //     296196766695424,
    //     8293509467471872,
    //     232218265089212416,
    //     6502111422497947648,
    //     182059119829942534144,
    //     5097655355238390956032,
    //     142734349946674946768896,
    //     3996561798506898509529088,
    //     111903730358193158266814464,
    //     3133304450029408431470804992,
    //     87732524600823436081182539776,
    //     2456510688823056210273111113728,
    //     68782299287045573887647111184384,
    //     1925904380037276068854119113162752,
    //     53925322641043729927915335168557056,
    //     1509909033949224437981629384719597568,
    //     42277452950578284263485622772148731904,
    //     1183768682616191959377597437620164493312,
    //     33145523113253374862572728253364605812736,
    //     928074647171094496152036391094208962756608,
    //     25986090120790645892257018950637850957185024,
    //     727610523382138084983196530617859826801180672,
    // ];

    pub fn field_from_hex_string<F: PrimeField>(str: &str) -> Result<F, Error> {
        Ok(gadgets::field_from_hex_string(str)?)
    }

    pub fn batch_invert<F: PrimeField>(coeffs: &mut [F]) {
        ark_ff::batch_inversion(coeffs);
    }

    pub fn commit<P: Pairing>(
        poly: &[P::ScalarField],
        crs: &ProverCrs<P>,
    ) -> HonkProofResult<P::G1> {
        Self::msm::<P>(poly, crs.monomials.as_slice())
    }

    pub fn msm<P: Pairing>(poly: &[P::ScalarField], crs: &[P::G1Affine]) -> HonkProofResult<P::G1> {
        if poly.len() > crs.len() {
            return Err(HonkProofError::CrsTooSmall);
        }
        Ok(P::G1::msm_unchecked(crs, poly))
    }

    pub fn get_msb32(inp: u32) -> u32 {
        inp.ilog2()
    }

    pub fn round_up_power_2(inp: usize) -> usize {
        let lower_bound = 1usize << Self::get_msb64(inp as u64);
        if lower_bound == inp || lower_bound == 1 {
            inp
        } else {
            lower_bound * 2
        }
    }

    pub fn get_msb64(inp: u64) -> u32 {
        inp.ilog2()
    }

    pub fn rotate64(value: u64, rotation: u64) -> u64 {
        if rotation != 0 {
            (value >> rotation) | (value << (64 - rotation))
        } else {
            value
        }
    }

    pub fn rotate32(value: u32, rotation: u32) -> u32 {
        if rotation != 0 {
            (value >> rotation) | (value << (32 - rotation))
        } else {
            value
        }
    }

    pub fn get_base_powers<const BASE: u64, const NUM_SLICES: usize>() -> [BigUint; NUM_SLICES] {
        let mut output: [BigUint; NUM_SLICES] = array::from_fn(|_| BigUint::one());
        let base = BigUint::from(BASE);
        let mask = (BigUint::from(1u64) << 256) - BigUint::one();

        for i in 1..NUM_SLICES {
            let tmp = &output[i - 1] * &base;
            output[i] = tmp & &mask;
        }

        output
    }

    pub fn map_into_sparse_form<const BASE: u64>(input: u64) -> BigUint {
        let mut out: BigUint = BigUint::zero();
        let base_powers = Self::get_base_powers::<BASE, 32>();

        for (i, base_power) in base_powers.iter().enumerate() {
            let sparse_bit = (input >> i) & 1;
            if sparse_bit != 0 {
                out += base_power;
            }
        }
        out
    }
}
