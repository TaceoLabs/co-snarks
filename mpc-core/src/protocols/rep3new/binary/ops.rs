use num_bigint::BigUint;

use super::types::Rep3BigUintShare;

impl std::ops::BitXor<&Rep3BigUintShare> for &'_ Rep3BigUintShare {
    type Output = Rep3BigUintShare;

    fn bitxor(self, rhs: &Rep3BigUintShare) -> Self::Output {
        Self::Output {
            a: &self.a ^ &rhs.a,
            b: &self.b ^ &rhs.b,
        }
    }
}

impl std::ops::BitXor<&BigUint> for &Rep3BigUintShare {
    type Output = Rep3BigUintShare;

    fn bitxor(self, rhs: &BigUint) -> Self::Output {
        Self::Output {
            a: &self.a ^ rhs,
            b: &self.b ^ rhs,
        }
    }
}

impl std::ops::BitAnd<&BigUint> for &Rep3BigUintShare {
    type Output = Rep3BigUintShare;

    fn bitand(self, rhs: &BigUint) -> Self::Output {
        Rep3BigUintShare {
            a: &self.a & rhs,
            b: &self.b & rhs,
        }
    }
}

impl std::ops::BitAnd<&Rep3BigUintShare> for &'_ Rep3BigUintShare {
    type Output = BigUint;

    fn bitand(self, rhs: &Rep3BigUintShare) -> Self::Output {
        (&self.a & &rhs.a) ^ (&self.a & &rhs.b) ^ (&self.b & &rhs.a)
    }
}

impl std::ops::ShlAssign<usize> for Rep3BigUintShare {
    fn shl_assign(&mut self, rhs: usize) {
        self.a <<= rhs;
        self.b <<= rhs;
    }
}

impl std::ops::Shl<usize> for Rep3BigUintShare {
    type Output = Self;

    fn shl(self, rhs: usize) -> Self::Output {
        Rep3BigUintShare {
            a: &self.a << rhs,
            b: &self.b << rhs,
        }
    }
}

impl std::ops::Shr<usize> for &Rep3BigUintShare {
    type Output = Rep3BigUintShare;

    fn shr(self, rhs: usize) -> Self::Output {
        Rep3BigUintShare {
            a: &self.a >> rhs,
            b: &self.b >> rhs,
        }
    }
}
