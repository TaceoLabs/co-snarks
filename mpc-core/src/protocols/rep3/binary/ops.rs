use std::marker::PhantomData;

use ark_ff::PrimeField;
use num_bigint::BigUint;

use crate::uint::FieldUint;

use super::types::{Rep3BigUintShare, Rep3UintShare};

impl<F: PrimeField> std::ops::BitXor for Rep3BigUintShare<F> {
    type Output = Rep3BigUintShare<F>;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Self::Output {
            a: self.a ^ rhs.a,
            b: self.b ^ rhs.b,
            phantom: PhantomData,
        }
    }
}

impl<F: PrimeField> std::ops::BitXor<&Rep3BigUintShare<F>> for &'_ Rep3BigUintShare<F> {
    type Output = Rep3BigUintShare<F>;

    fn bitxor(self, rhs: &Rep3BigUintShare<F>) -> Self::Output {
        Self::Output {
            a: &self.a ^ &rhs.a,
            b: &self.b ^ &rhs.b,
            phantom: PhantomData,
        }
    }
}

impl<F: PrimeField> std::ops::BitXor<BigUint> for Rep3BigUintShare<F> {
    type Output = Rep3BigUintShare<F>;

    fn bitxor(self, rhs: BigUint) -> Self::Output {
        Self::Output {
            a: &self.a ^ &rhs,
            b: &self.b ^ &rhs,
            phantom: PhantomData,
        }
    }
}

impl<F: PrimeField> std::ops::BitXor<&BigUint> for &Rep3BigUintShare<F> {
    type Output = Rep3BigUintShare<F>;

    fn bitxor(self, rhs: &BigUint) -> Self::Output {
        Self::Output {
            a: &self.a ^ rhs,
            b: &self.b ^ rhs,
            phantom: PhantomData,
        }
    }
}

impl<F: PrimeField> std::ops::BitXorAssign<Self> for Rep3BigUintShare<F> {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.a ^= &rhs.a;
        self.b ^= &rhs.b;
    }
}

impl<F: PrimeField> std::ops::BitXorAssign<&Self> for Rep3BigUintShare<F> {
    fn bitxor_assign(&mut self, rhs: &Self) {
        self.a ^= &rhs.a;
        self.b ^= &rhs.b;
    }
}

impl<F: PrimeField> std::ops::BitXorAssign<BigUint> for Rep3BigUintShare<F> {
    fn bitxor_assign(&mut self, rhs: BigUint) {
        self.a ^= &rhs;
        self.b ^= &rhs;
    }
}

impl<F: PrimeField> std::ops::BitXorAssign<&BigUint> for Rep3BigUintShare<F> {
    fn bitxor_assign(&mut self, rhs: &BigUint) {
        self.a ^= rhs;
        self.b ^= rhs;
    }
}

impl<F: PrimeField> std::ops::BitAnd<BigUint> for Rep3BigUintShare<F> {
    type Output = Rep3BigUintShare<F>;

    fn bitand(self, rhs: BigUint) -> Self::Output {
        Rep3BigUintShare {
            a: &self.a & &rhs,
            b: &self.b & &rhs,
            phantom: PhantomData,
        }
    }
}

impl<F: PrimeField> std::ops::BitAnd<&BigUint> for &Rep3BigUintShare<F> {
    type Output = Rep3BigUintShare<F>;

    fn bitand(self, rhs: &BigUint) -> Self::Output {
        Rep3BigUintShare {
            a: &self.a & rhs,
            b: &self.b & rhs,
            phantom: PhantomData,
        }
    }
}

impl<F: PrimeField> std::ops::BitAnd for Rep3BigUintShare<F> {
    type Output = BigUint;

    fn bitand(self, rhs: Self) -> Self::Output {
        (&self.a & &rhs.a) ^ (&self.a & &rhs.b) ^ (&self.b & &rhs.a)
    }
}

impl<F: PrimeField> std::ops::BitAnd<&Rep3BigUintShare<F>> for &'_ Rep3BigUintShare<F> {
    type Output = BigUint;

    fn bitand(self, rhs: &Rep3BigUintShare<F>) -> Self::Output {
        (&self.a & &rhs.a) ^ (&self.a & &rhs.b) ^ (&self.b & &rhs.a)
    }
}

impl<F: PrimeField> std::ops::BitAndAssign<&BigUint> for Rep3BigUintShare<F> {
    fn bitand_assign(&mut self, rhs: &BigUint) {
        self.a &= rhs;
        self.b &= rhs;
    }
}

impl<F: PrimeField> std::ops::BitAndAssign<BigUint> for Rep3BigUintShare<F> {
    fn bitand_assign(&mut self, rhs: BigUint) {
        self.a &= &rhs;
        self.b &= &rhs;
    }
}

impl<F: PrimeField> std::ops::ShlAssign<usize> for Rep3BigUintShare<F> {
    fn shl_assign(&mut self, rhs: usize) {
        self.a <<= rhs;
        self.b <<= rhs;
    }
}

impl<F: PrimeField> std::ops::Shl<usize> for Rep3BigUintShare<F> {
    type Output = Self;

    fn shl(self, rhs: usize) -> Self::Output {
        Rep3BigUintShare {
            a: &self.a << rhs,
            b: &self.b << rhs,
            phantom: PhantomData,
        }
    }
}

impl<F: PrimeField> std::ops::Shl<usize> for &Rep3BigUintShare<F> {
    type Output = Rep3BigUintShare<F>;

    fn shl(self, rhs: usize) -> Self::Output {
        Rep3BigUintShare {
            a: &self.a << rhs,
            b: &self.b << rhs,
            phantom: PhantomData,
        }
    }
}

impl<F: PrimeField> std::ops::Shr<usize> for Rep3BigUintShare<F> {
    type Output = Rep3BigUintShare<F>;

    fn shr(self, rhs: usize) -> Self::Output {
        Rep3BigUintShare {
            a: &self.a >> rhs,
            b: &self.b >> rhs,
            phantom: PhantomData,
        }
    }
}

impl<F: PrimeField> std::ops::Shr<usize> for &Rep3BigUintShare<F> {
    type Output = Rep3BigUintShare<F>;

    fn shr(self, rhs: usize) -> Self::Output {
        Rep3BigUintShare {
            a: &self.a >> rhs,
            b: &self.b >> rhs,
            phantom: PhantomData,
        }
    }
}

impl<F: FieldUint> std::ops::BitXor for Rep3UintShare<F> {
    type Output = Rep3UintShare<F>;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Self::Output {
            a: self.a ^ rhs.a,
            b: self.b ^ rhs.b,
            phantom: PhantomData,
        }
    }
}

impl<F: FieldUint> std::ops::BitXor<&Rep3UintShare<F>> for &'_ Rep3UintShare<F> {
    type Output = Rep3UintShare<F>;

    fn bitxor(self, rhs: &Rep3UintShare<F>) -> Self::Output {
        *self ^ *rhs
    }
}

impl<F: FieldUint> std::ops::BitXorAssign<Self> for Rep3UintShare<F> {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.a ^= rhs.a;
        self.b ^= rhs.b;
    }
}

impl<F: FieldUint> std::ops::BitXorAssign<&Self> for Rep3UintShare<F> {
    fn bitxor_assign(&mut self, rhs: &Self) {
        self.a ^= rhs.a;
        self.b ^= rhs.b;
    }
}

impl<F: FieldUint> std::ops::BitAnd for Rep3UintShare<F> {
    type Output = F::Uint;

    fn bitand(self, rhs: Self) -> Self::Output {
        (self.a & rhs.a) ^ (self.a & rhs.b) ^ (self.b & rhs.a)
    }
}

impl<F: FieldUint> std::ops::BitAnd<&Rep3UintShare<F>> for &'_ Rep3UintShare<F> {
    type Output = F::Uint;

    fn bitand(self, rhs: &Rep3UintShare<F>) -> Self::Output {
        *self & *rhs
    }
}

impl<F: FieldUint> std::ops::ShlAssign<usize> for Rep3UintShare<F> {
    fn shl_assign(&mut self, rhs: usize) {
        self.a <<= rhs;
        self.b <<= rhs;
    }
}

impl<F: FieldUint> std::ops::Shl<usize> for Rep3UintShare<F> {
    type Output = Self;

    fn shl(self, rhs: usize) -> Self::Output {
        Rep3UintShare {
            a: self.a << rhs,
            b: self.b << rhs,
            phantom: PhantomData,
        }
    }
}

impl<F: FieldUint> std::ops::Shl<usize> for &Rep3UintShare<F> {
    type Output = Rep3UintShare<F>;

    fn shl(self, rhs: usize) -> Self::Output {
        *self << rhs
    }
}

impl<F: FieldUint> std::ops::Shr<usize> for Rep3UintShare<F> {
    type Output = Rep3UintShare<F>;

    fn shr(self, rhs: usize) -> Self::Output {
        Rep3UintShare {
            a: self.a >> rhs,
            b: self.b >> rhs,
            phantom: PhantomData,
        }
    }
}

impl<F: FieldUint> std::ops::Shr<usize> for &Rep3UintShare<F> {
    type Output = Rep3UintShare<F>;

    fn shr(self, rhs: usize) -> Self::Output {
        *self >> rhs
    }
}
