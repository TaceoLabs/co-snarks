//! Lookup Table
//!
//! This module contains implementation of a LUT

use std::marker::PhantomData;

use crate::{
    IoResult,
    lut::LookupTableProvider,
    protocols::{
        rep3::{
            self, arithmetic,
            network::{IoContext, Rep3Network},
        },
        rep3_ring::{conversion, gadgets},
    },
};
use ark_ff::PrimeField;
use mpc_types::protocols::{
    rep3::{Rep3BigUintShare, Rep3PrimeFieldShare},
    rep3_ring::{
        Rep3RingShare,
        ring::{bit::Bit, int_ring::IntRing2k},
    },
};
use rand::{distributions::Standard, prelude::Distribution};

/// Implements an enum which stores a lookup table, either consisting of public or private values.
pub enum PublicPrivateLut<F: PrimeField> {
    /// The lookup table has public values
    Public(Vec<F>),
    /// The lookup table has secret-shared values
    Shared(Vec<Rep3PrimeFieldShare<F>>),
}

impl<F: PrimeField> Default for PublicPrivateLut<F> {
    fn default() -> Self {
        PublicPrivateLut::Public(Vec::new())
    }
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

    /// This is an optimized protocol that takes multiple public LUTs and looks them up with the same index. It only creates the OHV once.
    pub fn get_from_public_luts<F: PrimeField>(
        index: Rep3PrimeFieldShare<F>,
        luts: &[Vec<F>],
        network0: &mut IoContext<N>,
        network1: &mut IoContext<N>,
    ) -> IoResult<Vec<Rep3PrimeFieldShare<F>>> {
        let len = luts.iter().map(|l| l.len()).max().unwrap();
        tracing::debug!("doing read on LUT-map of size {}", len);
        let bits = rep3::conversion::a2b_selector(index, network0)?;
        let k = len.next_power_of_two().ilog2() as usize;

        let result = if k == 1 {
            Self::get_from_public_luts_internal::<Bit, _>(bits, luts, network0, network1)?
        } else if k <= 8 {
            Self::get_from_public_luts_internal::<u8, _>(bits, luts, network0, network1)?
        } else if k <= 16 {
            Self::get_from_public_luts_internal::<u16, _>(bits, luts, network0, network1)?
        } else if k <= 32 {
            Self::get_from_public_luts_internal::<u32, _>(bits, luts, network0, network1)?
        } else {
            panic!("Table is too large")
        };
        tracing::debug!("got a result!");
        Ok(result)
    }

    fn get_from_public_luts_internal<T: IntRing2k, F: PrimeField>(
        index: Rep3BigUintShare<F>,
        luts: &[Vec<F>],
        network0: &mut IoContext<N>,
        network1: &mut IoContext<N>,
    ) -> IoResult<Vec<Rep3PrimeFieldShare<F>>>
    where
        Standard: Distribution<T>,
    {
        let a = T::cast_from_biguint(&index.a);
        let b = T::cast_from_biguint(&index.b);
        let share = Rep3RingShare::new(a, b);

        let bins_a =
            gadgets::lut::read_multiple_public_lut_low_depth(luts, share, network0, network1)?;
        let bins_b = network0.network.reshare_many(&bins_a)?;

        let mut result = Vec::with_capacity(luts.len());

        // TODO parallelize this at some point
        for (bin_a, bin_b) in bins_a.into_iter().zip(bins_b.into_iter()) {
            let bin = Rep3BigUintShare::new(bin_a, bin_b);
            let res = rep3::conversion::b2a_selector(&bin, network0)?;
            result.push(res);
        }

        Ok(result)
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

    /// This is a protocol which reads from a public LUT without converting the result back to the arithmetic domain.
    pub fn get_from_public_lut_no_b2a_conversion<T: IntRing2k, F: PrimeField>(
        index: Rep3BigUintShare<F>,
        lut: &PublicPrivateLut<F>,
        network0: &mut IoContext<N>,
        network1: &mut IoContext<N>,
    ) -> IoResult<Rep3BigUintShare<F>>
    where
        Standard: Distribution<T>,
    {
        let a = T::cast_from_biguint(&index.a);
        let b = T::cast_from_biguint(&index.b);
        let share = Rep3RingShare::new(a, b);

        match lut {
            PublicPrivateLut::Public(vec) => {
                let bin_a = gadgets::lut::read_public_lut_low_depth(
                    vec.as_ref(),
                    share,
                    network0,
                    network1,
                )?;
                let bin_b = network0.network.reshare(bin_a.to_owned())?;
                Ok(Rep3BigUintShare::new(bin_a, bin_b))
            }
            PublicPrivateLut::Shared(_) => {
                panic!("LUT is not public")
            }
        }
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

    fn ohv_from_index_internal<T: IntRing2k, F: PrimeField>(
        index: Rep3BigUintShare<F>,
        k: usize,
        network0: &mut IoContext<N>,
        _network1: &mut IoContext<N>,
    ) -> IoResult<Vec<Rep3RingShare<Bit>>> {
        let a = T::cast_from_biguint(&index.a);
        let b = T::cast_from_biguint(&index.b);
        let bits = Rep3RingShare::new(a, b);

        gadgets::ohv::ohv(k, bits, network0)
    }

    /// Creates a shared one-hot-encoded vector from a given shared index
    pub fn ohv_from_index<F: PrimeField>(
        &mut self,
        index: Rep3PrimeFieldShare<F>,
        len: usize,
        network0: &mut IoContext<N>,
        network1: &mut IoContext<N>,
    ) -> IoResult<Vec<Rep3PrimeFieldShare<F>>> {
        let bits = rep3::conversion::a2b_selector(index, network0)?;
        let k = len.next_power_of_two().ilog2() as usize;

        let e = if k == 1 {
            Self::ohv_from_index_internal::<Bit, _>(bits, k, network0, network1)?
        } else if k <= 8 {
            Self::ohv_from_index_internal::<u8, _>(bits, k, network0, network1)?
        } else if k <= 16 {
            Self::ohv_from_index_internal::<u16, _>(bits, k, network0, network1)?
        } else if k <= 32 {
            Self::ohv_from_index_internal::<u32, _>(bits, k, network0, network1)?
        } else {
            panic!("Table is too large")
        };

        conversion::bit_inject_from_bits_to_field_many::<F, _>(&e, network0)
    }

    /// Writes to a shared lookup table with the index already being transformed into the shared one-hot-encoded vector
    pub fn write_to_shared_lut_from_ohv<F: PrimeField>(
        &mut self,
        ohv: &[Rep3PrimeFieldShare<F>],
        value: Rep3PrimeFieldShare<F>,
        lut: &mut [Rep3PrimeFieldShare<F>],
        network0: &mut IoContext<N>,
        _network1: &mut IoContext<N>,
    ) -> IoResult<()> {
        let len = lut.len();
        tracing::debug!("doing write on LUT-map of size {}", len);
        gadgets::lut::write_lut_from_ohv(&value, lut, ohv, network0)?;
        tracing::debug!("we are done");
        Ok(())
    }

    /// Returns true if LUT is public
    pub fn is_public_lut<F: PrimeField>(lut: &PublicPrivateLut<F>) -> bool {
        match lut {
            PublicPrivateLut::Public(_) => true,
            PublicPrivateLut::Shared(_) => false,
        }
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
        let k = len.next_power_of_two().ilog2() as usize;

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
        let k = len.next_power_of_two().ilog2();

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

    fn get_lut_len(lut: &Self::LutType) -> usize {
        match lut {
            PublicPrivateLut::Public(items) => items.len(),
            PublicPrivateLut::Shared(shares) => shares.len(),
        }
    }

    fn get_public_lut(lut: &Self::LutType) -> std::io::Result<&Vec<F>> {
        match lut {
            PublicPrivateLut::Public(items) => Ok(items),
            PublicPrivateLut::Shared(_) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Expected public LUT",
            )),
        }
    }
}
