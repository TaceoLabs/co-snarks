pub mod poseidon2_bn254;
pub mod poseidon2_params;
pub mod poseidon2_permutation;

use ark_ff::PrimeField;
use eyre::Error;
use num_bigint::BigUint;
use num_traits::Num;

pub(super) fn field_from_hex_string<F: PrimeField>(str: &str) -> Result<F, Error> {
    let tmp = match str.strip_prefix("0x") {
        Some(t) => BigUint::from_str_radix(t, 16),
        None => BigUint::from_str_radix(str, 16),
    };

    Ok(tmp?.into())
}
