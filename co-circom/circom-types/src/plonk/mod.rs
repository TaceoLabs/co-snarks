//! This module defines types related to Plonk used in circom and utilities to read these types from files.

mod proof;
mod verification_key;
mod zkey;

pub use proof::PlonkProof;
pub use verification_key::JsonVerificationKey;
pub use zkey::Additions;
pub use zkey::CircomPolynomial;
pub use zkey::VerifyingKey;
pub use zkey::ZKey;

#[cfg(test)]
use crate::groth16::test_utils;
