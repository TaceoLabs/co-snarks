use ark_ff::PrimeField;

use crate::traits::LookupTableProvider;

use super::{network::Rep3Network, Rep3PrimeFieldShare, Rep3Protocol};

impl<F: PrimeField, N: Rep3Network> LookupTableProvider<F> for Rep3Protocol<F, N> {
    type LUT = ();

    fn init_lut(&mut self, _values: Vec<Rep3PrimeFieldShare<F>>) -> Self::LUT {
        todo!()
    }

    fn get_from_lut(&mut self, _index: &Self::FieldShare, _lut: &Self::LUT) -> Self::FieldShare {
        todo!()
    }

    fn write_to_lut(
        &mut self,
        _index: Self::FieldShare,
        _value: Self::FieldShare,
        _lut: &mut Self::LUT,
    ) {
        todo!()
    }

    fn public_get_from_lut(&mut self, _index: &F, _lut: &Self::LUT) -> Self::FieldShare {
        todo!()
    }

    fn public_write_to_lut(&mut self, _index: F, _value: Self::FieldShare, _lut: &mut Self::LUT) {
        todo!()
    }
}
