//! Lookup Table
//!
//! This module contains implementation of a LUT

use crate::lut::LookupTableProvider;
use ark_ff::PrimeField;

use super::{
    network::{IoContext, Rep3Network},
    IoResult, Rep3PrimeFieldShare,
};

/// Implements an enum which stores a lookup table, either consisting of public or private values.
pub enum PublicPrivateLut<F: PrimeField> {
    /// The lookup table has public values
    Public(Vec<F>),
    /// The lookup table has secret-shared values
    Shared(Vec<Rep3PrimeFieldShare<F>>),
}

impl<F: PrimeField> PublicPrivateLut<F> {
    /// Returns the number of elements contained in the lookup table
    pub fn len(&self) -> usize {
        match self {
            PublicPrivateLut::Public(lut) => lut.len(),
            PublicPrivateLut::Shared(lut) => lut.len(),
        }
    }

    /// Returns true if the lut is empty
    pub fn is_empty(&self) -> bool {
        match self {
            PublicPrivateLut::Public(lut) => lut.is_empty(),
            PublicPrivateLut::Shared(lut) => lut.is_empty(),
        }
    }
}

/// Rep3 lookup table
pub struct Rep3LookupTable<N: Rep3Network> {
    io_context: IoContext<N>,
}

impl<N: Rep3Network> Rep3LookupTable<N> {
    /// Construct a new [`Rep3LookupTable`]
    pub fn new(io_context: IoContext<N>) -> Self {
        Self { io_context }
    }

    /// Consumes self and returns the inner [`IoContext`]
    pub fn get_io_context(self) -> IoContext<N> {
        self.io_context
    }
}

impl<F: PrimeField, N: Rep3Network> LookupTableProvider<F> for Rep3LookupTable<N> {
    type SecretShare = Rep3PrimeFieldShare<F>;
    type LutType = PublicPrivateLut<F>;

    fn init_private(&self, values: Vec<Self::SecretShare>) -> Self::LutType {
        tracing::debug!("initiating LUT-map (private)");
        PublicPrivateLut::Shared(values)
    }

    fn init_public(&self, values: Vec<F>) -> Self::LutType {
        tracing::debug!("initiating LUT-map (public)");
        PublicPrivateLut::Public(values)
    }

    fn get_from_lut(
        &mut self,
        index: Self::SecretShare,
        lut: &Self::LutType,
    ) -> IoResult<Self::SecretShare> {
        tracing::debug!("doing read on LUT-map of size {}", lut.len());
        tracing::debug!("got a result!");
        todo!();
    }

    fn write_to_lut(
        &mut self,
        index: Self::SecretShare,
        value: Self::SecretShare,
        lut: &mut Self::LutType,
    ) -> IoResult<()> {
        tracing::debug!("doing write on LUT-map of size {}", lut.len());
        tracing::debug!("we are done");
        todo!();
    }
}
