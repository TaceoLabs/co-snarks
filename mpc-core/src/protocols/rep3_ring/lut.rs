//! Lookup Table
//!
//! This module contains implementation of a LUT

use std::marker::PhantomData;

use crate::{
    lut::LookupTableProvider,
    protocols::{
        rep3::{
            self, arithmetic,
            network::{IoContext, Rep3Network},
            IoResult, Rep3BigUintShare, Rep3PrimeFieldShare,
        },
        rep3_ring::{gadgets, ring::bit::Bit},
    },
};
use ark_ff::PrimeField;
use rand::{distributions::Standard, prelude::Distribution};

use super::{ring::int_ring::IntRing2k, Rep3RingShare};

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
    phantom: PhantomData<N>,
}

impl<N: Rep3Network> Default for Rep3LookupTable<N> {
    fn default() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<N: Rep3Network> Rep3LookupTable<N> {
    /// Construct a new [`Rep3LookupTable`]
    pub fn new() -> Self {
        Self::default()
    }

    fn get_from_lut_internal<T: IntRing2k, F: PrimeField>(
        index: Rep3BigUintShare<F>,
        lut: &PublicPrivateLut<F>,
        network0: &mut IoContext<N>,
        network1: &mut IoContext<N>,
    ) -> IoResult<Rep3PrimeFieldShare<F>>
    where
        Standard: Distribution<T>,
    {
        let a = T::cast_from_biguint(&index.a);
        let b = T::cast_from_biguint(&index.b);
        let share = Rep3RingShare::new(a, b);
        let val = match lut {
            PublicPrivateLut::Public(vec) => {
                let bin_a = gadgets::lut::read_public_lut_low_depth(
                    vec.as_ref(),
                    share,
                    network0,
                    network1,
                )?;
                let bin_b = network0.network.reshare(bin_a.to_owned())?;
                let bin = Rep3BigUintShare::new(bin_a, bin_b);
                rep3::conversion::b2a_selector(&bin, network0)?
            }
            PublicPrivateLut::Shared(vec) => {
                let f_a = gadgets::lut::read_shared_lut(vec.as_ref(), share, network0)?;
                let f_b = network0.network.reshare(f_a)?;
                Rep3PrimeFieldShare::new(f_a, f_b)
            }
        };

        Ok(val)
    }

    fn write_to_lut_internal<T: IntRing2k, F: PrimeField>(
        index: Rep3BigUintShare<F>,
        lut: &mut PublicPrivateLut<F>,
        value: &Rep3PrimeFieldShare<F>,
        network0: &mut IoContext<N>,
        _network1: &mut IoContext<N>,
    ) -> IoResult<()>
    where
        Standard: Distribution<T>,
    {
        let a = T::cast_from_biguint(&index.a);
        let b = T::cast_from_biguint(&index.b);
        let share = Rep3RingShare::new(a, b);
        match lut {
            PublicPrivateLut::Public(vec) => {
                // There is not really a performance difference (i.e., more multiplications) when both lut and value are secret shared compared to public lut and private value. Thus we promote
                let id = network0.id;
                let mut shared = vec
                    .iter()
                    .map(|v| arithmetic::promote_to_trivial_share(id, *v))
                    .collect::<Vec<_>>();
                gadgets::lut::write_lut(value, &mut shared, share, network0)?;
                *lut = PublicPrivateLut::Shared(shared);
            }
            PublicPrivateLut::Shared(shared) => {
                gadgets::lut::write_lut(value, shared, share, network0)?;
            }
        }
        Ok(())
    }
}

impl<F: PrimeField, N: Rep3Network> LookupTableProvider<F> for Rep3LookupTable<N> {
    type SecretShare = Rep3PrimeFieldShare<F>;
    type LutType = PublicPrivateLut<F>;
    type NetworkProvider = IoContext<N>;

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
        network0: &mut Self::NetworkProvider,
        network1: &mut Self::NetworkProvider,
    ) -> IoResult<Self::SecretShare> {
        let len = lut.len();
        tracing::debug!("doing read on LUT-map of size {}", len);
        let bits = rep3::conversion::a2b_selector(index, network0)?;
        let k = if len.is_power_of_two() {
            len.ilog2()
        } else {
            len.next_power_of_two().ilog2()
        };
        let result = if k == 1 {
            Self::get_from_lut_internal::<Bit, _>(bits, lut, network0, network1)?
        } else if k <= 8 {
            Self::get_from_lut_internal::<u8, _>(bits, lut, network0, network1)?
        } else if k <= 16 {
            Self::get_from_lut_internal::<u16, _>(bits, lut, network0, network1)?
        } else if k <= 32 {
            Self::get_from_lut_internal::<u32, _>(bits, lut, network0, network1)?
        } else {
            panic!("Table is too large")
        };
        tracing::debug!("got a result!");
        Ok(result)
    }

    fn write_to_lut(
        &mut self,
        index: Self::SecretShare,
        value: Self::SecretShare,
        lut: &mut Self::LutType,
        network0: &mut Self::NetworkProvider,
        network1: &mut Self::NetworkProvider,
    ) -> IoResult<()> {
        let len = lut.len();
        tracing::debug!("doing write on LUT-map of size {}", len);
        let bits = rep3::conversion::a2b_selector(index, network0)?;
        let k = if len.is_power_of_two() {
            len.ilog2()
        } else {
            len.next_power_of_two().ilog2()
        };

        if k == 1 {
            Self::write_to_lut_internal::<Bit, _>(bits, lut, &value, network0, network1)?
        } else if k <= 8 {
            Self::write_to_lut_internal::<u8, _>(bits, lut, &value, network0, network1)?
        } else if k <= 16 {
            Self::write_to_lut_internal::<u16, _>(bits, lut, &value, network0, network1)?
        } else if k <= 32 {
            Self::write_to_lut_internal::<u32, _>(bits, lut, &value, network0, network1)?
        } else {
            panic!("Table is too large")
        };

        tracing::debug!("we are done");
        Ok(())
    }
}
