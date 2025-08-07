//! Lookup table provider
//!
//! This module contains the abstraction to lookup tables

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use mpc_net::Network;
use num_bigint::BigUint;
use std::marker::PhantomData;

/// This is some place holder definition. This will change most likely
pub trait LookupTableProvider<T: Default>: Default {
    /// The type used in LUTs
    type SecretShare;
    /// The type of the index
    type IndexSecretShare;
    /// An input/output LUT (like `Vector`).
    type LutType: Default;
    /// Internal state of used MPC protocol
    type State;

    /// Initializes a LUT from the provided secret values.
    fn init_private(&self, values: Vec<Self::SecretShare>) -> Self::LutType;

    /// Initializes a LUT from the provided public values.
    fn init_public(&self, values: Vec<T>) -> Self::LutType;

    /// Reads a value from the LUT associated with the provided index. As we work over secret-shared
    /// values we can not check whether the index is actually in the LUT, the caller must ensure that the LUT is large enough.
    ///
    /// # Returns
    /// The secret-shared value associated with the index. A not known index results in undefined
    /// behaviour.
    ///
    /// Can fail due to networking problems.
    ///
    fn get_from_lut<N: Network>(
        &mut self,
        index: Self::IndexSecretShare,
        lut: &Self::LutType,
        net0: &N,
        net1: &N,
        state0: &mut Self::State,
        state1: &mut Self::State,
    ) -> eyre::Result<Self::SecretShare>;

    /// Writes a value to the LUT.
    ///
    /// **IMPORTANT**: the implementation will NOT add
    /// the value to the LUT, if it is too small! The implementation
    /// overwrites an existing index, but a out-of-bounds index will be ignored.
    ///
    /// #Returns
    /// Can fail due to networking problems.
    #[expect(clippy::too_many_arguments)]
    fn write_to_lut<N: Network>(
        &mut self,
        index: Self::IndexSecretShare,
        value: Self::SecretShare,
        lut: &mut Self::LutType,
        net0: &N,
        net1: &N,
        state0: &mut Self::State,
        state1: &mut Self::State,
    ) -> eyre::Result<()>;

    /// Returns the length of the LUT
    fn get_lut_len(lut: &Self::LutType) -> usize;

    /// Returns the LUT as a vec if public
    fn get_public_lut(lut: &Self::LutType) -> eyre::Result<&Vec<T>>;
}

/// LUT provider for public values
#[derive(Default)]
pub struct PlainLookupTableProvider<F: PrimeField> {
    phantom_data: PhantomData<F>,
}

impl<F: PrimeField> LookupTableProvider<F> for PlainLookupTableProvider<F> {
    type SecretShare = F;
    type IndexSecretShare = F;
    type LutType = Vec<F>;
    type State = ();

    fn init_private(&self, values: Vec<Self::SecretShare>) -> Self::LutType {
        values
    }

    fn init_public(&self, values: Vec<F>) -> Self::LutType {
        values
    }

    fn get_from_lut<N: Network>(
        &mut self,
        index: Self::IndexSecretShare,
        lut: &Self::LutType,
        _net0: &N,
        _net1: &N,
        _state0: &mut (),
        _state1: &mut (),
    ) -> eyre::Result<F> {
        let index: BigUint = index.into();
        let index = usize::try_from(index)
            .map_err(|_| eyre::eyre!("Index can not be translated to usize"))?;
        Ok(lut[index])
    }

    fn write_to_lut<N: Network>(
        &mut self,
        index: Self::IndexSecretShare,
        value: Self::SecretShare,
        lut: &mut Self::LutType,
        _net0: &N,
        _net1: &N,
        _state0: &mut (),
        _state1: &mut (),
    ) -> eyre::Result<()> {
        let index: BigUint = index.into();
        let index = usize::try_from(index)
            .map_err(|_| eyre::eyre!("Index can not be translated to usize"))?;

        lut[index] = value;
        Ok(())
    }

    fn get_lut_len(lut: &Self::LutType) -> usize {
        lut.len()
    }

    fn get_public_lut(lut: &Self::LutType) -> eyre::Result<&Vec<F>> {
        Ok(lut)
    }
}

/// LUT provider for public values
#[derive(Default)]
pub struct PlainCurveLookupTableProvider<C: CurveGroup> {
    phantom_data: PhantomData<C>,
}

impl<C: CurveGroup> LookupTableProvider<C> for PlainCurveLookupTableProvider<C> {
    type SecretShare = C;

    type LutType = Vec<C>;
    type IndexSecretShare = C::ScalarField;

    type State = ();

    fn init_private(&self, values: Vec<Self::SecretShare>) -> Self::LutType {
        values
    }

    fn init_public(&self, values: Vec<C>) -> Self::LutType {
        values
    }

    fn get_from_lut<N: Network>(
        &mut self,
        index: Self::IndexSecretShare,
        lut: &Self::LutType,
        _net0: &N,
        _net1: &N,
        _state0: &mut Self::State,
        _state1: &mut Self::State,
    ) -> eyre::Result<Self::SecretShare> {
        let index: BigUint = index.into();
        let index = usize::try_from(index)
            .map_err(|_| eyre::eyre!("Index can not be translated to usize"))?;
        Ok(lut[index])
    }

    fn write_to_lut<N: Network>(
        &mut self,
        index: Self::IndexSecretShare,
        value: Self::SecretShare,
        lut: &mut Self::LutType,
        _net0: &N,
        _net1: &N,
        _state0: &mut Self::State,
        _state1: &mut Self::State,
    ) -> eyre::Result<()> {
        let index: BigUint = index.into();
        let index = usize::try_from(index)
            .map_err(|_| eyre::eyre!("Index can not be translated to usize"))?;

        lut[index] = value;
        Ok(())
    }

    fn get_lut_len(lut: &Self::LutType) -> usize {
        lut.len()
    }

    fn get_public_lut(lut: &Self::LutType) -> eyre::Result<&Vec<C>> {
        Ok(lut)
    }
}
