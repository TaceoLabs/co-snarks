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

// NOTE (deviation from brief): the brief's sketch has these scalar ops
// (`Self op F::Uint`) implemented as `impl<F: FieldUint> Op<F::Uint> for
// Rep3UintShare<F>`, mirroring the `BigUint`-based ops verbatim. That does
// not compile: unlike `BigUint` (a concrete type unrelated to `F`), `F::Uint`
// is an associated-type *projection*. Rust's coherence checker cannot
// normalize `F::Uint` while type-checking a still-generic `F`, so it cannot
// prove `F::Uint` is never equal to `Self` (`Rep3UintShare<F>`) and rejects
// these impls as overlapping with the `Self op Self` impls above (and with
// each other's owned/reference variants).
//
// Fix: implement the scalar ops once per concrete uint backend width
// (`Uint = $u`) instead of over the bare projection. Binding the associated
// type to a concrete, non-projected type makes `$u` provably distinct from
// `Rep3UintShare<F>` for every `F`, which resolves the overlap. Call sites
// with a concrete `F` (as in the tests below, and as Tasks 3-4 will have
// after monomorphization) resolve to one of these impls transparently;
// fully generic code needs an explicit
// `where Rep3UintShare<F>: BitXor<F::Uint, Output = Rep3UintShare<F>>`
// (and the `BitAnd`/`*Assign` equivalents) bound, standard practice for
// working around this associated-type coherence limitation.
macro_rules! impl_rep3_uint_scalar_ops {
    ($u:ty) => {
        impl<F: FieldUint<Uint = $u>> std::ops::BitXor<$u> for Rep3UintShare<F> {
            type Output = Rep3UintShare<F>;

            fn bitxor(self, rhs: $u) -> Self::Output {
                Self::Output {
                    a: self.a ^ rhs,
                    b: self.b ^ rhs,
                    phantom: PhantomData,
                }
            }
        }

        impl<F: FieldUint<Uint = $u>> std::ops::BitXor<&$u> for &Rep3UintShare<F> {
            type Output = Rep3UintShare<F>;

            fn bitxor(self, rhs: &$u) -> Self::Output {
                *self ^ *rhs
            }
        }

        impl<F: FieldUint<Uint = $u>> std::ops::BitXorAssign<$u> for Rep3UintShare<F> {
            fn bitxor_assign(&mut self, rhs: $u) {
                self.a ^= rhs;
                self.b ^= rhs;
            }
        }

        impl<F: FieldUint<Uint = $u>> std::ops::BitXorAssign<&$u> for Rep3UintShare<F> {
            fn bitxor_assign(&mut self, rhs: &$u) {
                self.a ^= *rhs;
                self.b ^= *rhs;
            }
        }

        impl<F: FieldUint<Uint = $u>> std::ops::BitAnd<$u> for Rep3UintShare<F> {
            type Output = Rep3UintShare<F>;

            fn bitand(self, rhs: $u) -> Self::Output {
                Rep3UintShare {
                    a: self.a & rhs,
                    b: self.b & rhs,
                    phantom: PhantomData,
                }
            }
        }

        impl<F: FieldUint<Uint = $u>> std::ops::BitAnd<&$u> for &Rep3UintShare<F> {
            type Output = Rep3UintShare<F>;

            fn bitand(self, rhs: &$u) -> Self::Output {
                *self & *rhs
            }
        }

        impl<F: FieldUint<Uint = $u>> std::ops::BitAndAssign<&$u> for Rep3UintShare<F> {
            fn bitand_assign(&mut self, rhs: &$u) {
                self.a &= *rhs;
                self.b &= *rhs;
            }
        }

        impl<F: FieldUint<Uint = $u>> std::ops::BitAndAssign<$u> for Rep3UintShare<F> {
            fn bitand_assign(&mut self, rhs: $u) {
                self.a &= rhs;
                self.b &= rhs;
            }
        }
    };
}

// One macro invocation per fixed-width uint backend currently used by
// `FieldUint` impls (see `mpc-core/src/uint/field_uint.rs`). Add a new
// invocation here if a `FieldUint` impl for a new `Uint` width is added.
impl_rep3_uint_scalar_ops!(crate::uint::U256);
impl_rep3_uint_scalar_ops!(crate::uint::U320);
impl_rep3_uint_scalar_ops!(crate::uint::U384);

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
