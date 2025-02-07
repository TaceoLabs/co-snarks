//! Lookup table provider
//!
//! This module contains the abstraction to lookup tables

use ark_ff::PrimeField;
use num_bigint::BigUint;
use std::{io, marker::PhantomData};

/// This is some place holder definition. This will change most likely
pub trait LookupTableProvider<F: PrimeField>: Default {
    /// The type used in LUTs
    type SecretShare;
    /// An input/output LUT (like `Vector`).
    type LutType: Default;
    /// The network used
    type NetworkProvider;

    /// Initializes a LUT from the provided secret values.
    fn init_private(&self, values: Vec<Self::SecretShare>) -> Self::LutType;

    /// Initializes a LUT from the provided public values.
    fn init_public(&self, values: Vec<F>) -> Self::LutType;

    /// Reads a value from the LUT associated with the provided index. As we work over secret-shared
    /// values we can not check whether the index is actually in the LUT, the caller must ensure that the LUT is large enough.
    ///
    /// # Returns
    /// The secret-shared value associated with the index. A not known index results in undefined
    /// behaviour.
    ///
    /// Can fail due to networking problems.
    ///
    fn get_from_lut(
        &mut self,
        index: Self::SecretShare,
        lut: &Self::LutType,
        network0: &mut Self::NetworkProvider,
        network1: &mut Self::NetworkProvider,
    ) -> io::Result<Self::SecretShare>;

    /// Writes a value to the LUT.
    ///
    /// **IMPORTANT**: the implementation will NOT add
    /// the value to the LUT, if it is too small! The implementation
    /// overwrites an existing index, but a out-of-bounds index will be ignored.
    ///
    /// #Returns
    /// Can fail due to networking problems.
    fn write_to_lut(
        &mut self,
        index: Self::SecretShare,
        value: Self::SecretShare,
        lut: &mut Self::LutType,
        network0: &mut Self::NetworkProvider,
        network1: &mut Self::NetworkProvider,
    ) -> io::Result<()>;

    /// Returns the length of the LUT
    fn get_lut_len(lut: &Self::LutType) -> usize;

    /// Returns the LUT as a vec if public
    fn get_public_lut(lut: &Self::LutType) -> io::Result<&Vec<F>>;
}

/// LUT provider for public values
#[derive(Default)]
pub struct PlainLookupTableProvider<F: PrimeField> {
    phantom_data: PhantomData<F>,
}

impl<F: PrimeField> LookupTableProvider<F> for PlainLookupTableProvider<F> {
    type SecretShare = F;
    type LutType = Vec<F>;
    type NetworkProvider = ();

    fn init_private(&self, values: Vec<Self::SecretShare>) -> Self::LutType {
        values
    }

    fn init_public(&self, values: Vec<F>) -> Self::LutType {
        values
    }

    fn get_from_lut(
        &mut self,
        index: Self::SecretShare,
        lut: &Self::LutType,
        _network0: &mut Self::NetworkProvider,
        _network1: &mut Self::NetworkProvider,
    ) -> io::Result<F> {
        let index: BigUint = index.into();
        let index = usize::try_from(index).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Index can not be translated to usize",
            )
        })?;
        Ok(lut[index])
    }

    fn write_to_lut(
        &mut self,
        index: Self::SecretShare,
        value: Self::SecretShare,
        lut: &mut Self::LutType,
        _network0: &mut Self::NetworkProvider,
        _network1: &mut Self::NetworkProvider,
    ) -> io::Result<()> {
        let index: BigUint = index.into();
        let index = usize::try_from(index).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Index can not be translated to usize",
            )
        })?;

        lut[index] = value;
        Ok(())
    }

    fn get_lut_len(lut: &Self::LutType) -> usize {
        lut.len()
    }

    fn get_public_lut(lut: &Self::LutType) -> io::Result<&Vec<F>> {
        Ok(lut)
    }
}
