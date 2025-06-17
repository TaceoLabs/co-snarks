use crate::protocols::rep3_ring::{
    arithmetic::types::Rep3RingShare,
    ring::{int_ring::IntRing2k, ring_impl::RingElement},
};

impl<T: IntRing2k> std::ops::BitXor for Rep3RingShare<T> {
    type Output = Rep3RingShare<T>;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Self::Output {
            a: self.a ^ rhs.a,
            b: self.b ^ rhs.b,
        }
    }
}

impl<T: IntRing2k> std::ops::BitXor<&Rep3RingShare<T>> for &'_ Rep3RingShare<T> {
    type Output = Rep3RingShare<T>;

    fn bitxor(self, rhs: &Rep3RingShare<T>) -> Self::Output {
        Self::Output {
            a: self.a ^ rhs.a,
            b: self.b ^ rhs.b,
        }
    }
}

impl<T: IntRing2k> std::ops::BitXor<RingElement<T>> for Rep3RingShare<T> {
    type Output = Rep3RingShare<T>;

    fn bitxor(self, rhs: RingElement<T>) -> Self::Output {
        Self::Output {
            a: self.a ^ rhs,
            b: self.b ^ rhs,
        }
    }
}

impl<T: IntRing2k> std::ops::BitXor<&RingElement<T>> for &Rep3RingShare<T> {
    type Output = Rep3RingShare<T>;

    fn bitxor(self, rhs: &RingElement<T>) -> Self::Output {
        Self::Output {
            a: self.a ^ rhs,
            b: self.b ^ rhs,
        }
    }
}

impl<T: IntRing2k> std::ops::BitXorAssign<Self> for Rep3RingShare<T> {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.a ^= rhs.a;
        self.b ^= rhs.b;
    }
}

impl<T: IntRing2k> std::ops::BitXorAssign<&Self> for Rep3RingShare<T> {
    fn bitxor_assign(&mut self, rhs: &Self) {
        self.a ^= &rhs.a;
        self.b ^= &rhs.b;
    }
}

impl<T: IntRing2k> std::ops::BitXorAssign<RingElement<T>> for Rep3RingShare<T> {
    fn bitxor_assign(&mut self, rhs: RingElement<T>) {
        self.a ^= rhs;
        self.b ^= rhs;
    }
}

impl<T: IntRing2k> std::ops::BitXorAssign<&RingElement<T>> for Rep3RingShare<T> {
    fn bitxor_assign(&mut self, rhs: &RingElement<T>) {
        self.a ^= rhs;
        self.b ^= rhs;
    }
}

impl<T: IntRing2k> std::ops::BitAnd<RingElement<T>> for Rep3RingShare<T> {
    type Output = Rep3RingShare<T>;

    fn bitand(self, rhs: RingElement<T>) -> Self::Output {
        Rep3RingShare {
            a: self.a & rhs,
            b: self.b & rhs,
        }
    }
}

impl<T: IntRing2k> std::ops::BitAnd<&RingElement<T>> for &Rep3RingShare<T> {
    type Output = Rep3RingShare<T>;

    fn bitand(self, rhs: &RingElement<T>) -> Self::Output {
        Rep3RingShare {
            a: self.a & rhs,
            b: self.b & rhs,
        }
    }
}

impl<T: IntRing2k> std::ops::BitAnd for Rep3RingShare<T> {
    type Output = RingElement<T>;

    fn bitand(self, rhs: Self) -> Self::Output {
        (self.a & rhs.a) ^ (self.a & rhs.b) ^ (self.b & rhs.a)
    }
}

impl<T: IntRing2k> std::ops::BitAnd<&Rep3RingShare<T>> for &'_ Rep3RingShare<T> {
    type Output = RingElement<T>;

    fn bitand(self, rhs: &Rep3RingShare<T>) -> Self::Output {
        (self.a & rhs.a) ^ (self.a & rhs.b) ^ (self.b & rhs.a)
    }
}

impl<T: IntRing2k> std::ops::BitAndAssign<&RingElement<T>> for Rep3RingShare<T> {
    fn bitand_assign(&mut self, rhs: &RingElement<T>) {
        self.a &= rhs;
        self.b &= rhs;
    }
}

impl<T: IntRing2k> std::ops::BitAndAssign<RingElement<T>> for Rep3RingShare<T> {
    fn bitand_assign(&mut self, rhs: RingElement<T>) {
        self.a &= &rhs;
        self.b &= rhs;
    }
}

impl<T: IntRing2k> std::ops::ShlAssign<usize> for Rep3RingShare<T> {
    fn shl_assign(&mut self, rhs: usize) {
        self.a <<= rhs;
        self.b <<= rhs;
    }
}

impl<T: IntRing2k> std::ops::Shl<usize> for Rep3RingShare<T> {
    type Output = Self;

    fn shl(self, rhs: usize) -> Self::Output {
        Rep3RingShare {
            a: self.a << rhs,
            b: self.b << rhs,
        }
    }
}

impl<T: IntRing2k> std::ops::Shl<usize> for &Rep3RingShare<T> {
    type Output = Rep3RingShare<T>;

    fn shl(self, rhs: usize) -> Self::Output {
        Rep3RingShare {
            a: self.a << rhs,
            b: self.b << rhs,
        }
    }
}

impl<T: IntRing2k> std::ops::Shr<usize> for Rep3RingShare<T> {
    type Output = Rep3RingShare<T>;

    fn shr(self, rhs: usize) -> Self::Output {
        Rep3RingShare {
            a: self.a >> rhs,
            b: self.b >> rhs,
        }
    }
}

impl<T: IntRing2k> std::ops::Shr<usize> for &Rep3RingShare<T> {
    type Output = Rep3RingShare<T>;

    fn shr(self, rhs: usize) -> Self::Output {
        Rep3RingShare {
            a: self.a >> rhs,
            b: self.b >> rhs,
        }
    }
}

impl<T: IntRing2k> std::ops::Not for Rep3RingShare<T> {
    type Output = Self;

    fn not(self) -> Self::Output {
        Rep3RingShare {
            a: !self.a,
            b: !self.b,
        }
    }
}

impl<T: IntRing2k> std::ops::Not for &Rep3RingShare<T> {
    type Output = Rep3RingShare<T>;

    fn not(self) -> Self::Output {
        Rep3RingShare {
            a: !self.a,
            b: !self.b,
        }
    }
}
