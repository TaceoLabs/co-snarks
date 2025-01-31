//! Gadgets
//!
//! This module contains some commonly used gadgets.

pub mod poseidon2;

use ark_ff::PrimeField;
use num_bigint::{BigUint, ParseBigIntError};
use num_traits::Num;

/// Reads a field elemnent from a hexadecimal string. Therebey, the format can or can not include the 0x prefix, i.e., "0x2" and "2" give the same result.
pub fn field_from_hex_string<F: PrimeField>(str: &str) -> Result<F, ParseBigIntError> {
    let tmp = match str.strip_prefix("0x") {
        Some(t) => BigUint::from_str_radix(t, 16),
        None => BigUint::from_str_radix(str, 16),
    };

    Ok(tmp?.into())
}
