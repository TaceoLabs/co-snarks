use super::{network::Aby3Network, Aby3Protocol, IoResult};
use ark_ff::PrimeField;
use num_bigint::BigUint;

// TODO CanonicalDeserialize and CanonicalSerialize
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Aby3BigUintShare {
    pub(crate) a: BigUint,
    pub(crate) b: BigUint,
}

impl std::ops::BitXor for &Aby3BigUintShare {
    type Output = Aby3BigUintShare;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Self::Output {
            a: &self.a ^ &rhs.a,
            b: &self.b ^ &rhs.b,
        }
    }
}

impl std::ops::BitXorAssign<&Self> for Aby3BigUintShare {
    fn bitxor_assign(&mut self, rhs: &Self) {
        self.a ^= &rhs.a;
        self.b ^= &rhs.b;
    }
}

impl std::ops::BitXorAssign for Aby3BigUintShare {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.a ^= rhs.a;
        self.b ^= rhs.b;
    }
}

impl std::ops::BitAnd for Aby3BigUintShare {
    type Output = BigUint;

    // Local part of AND only
    fn bitand(self, rhs: Self) -> Self::Output {
        (&self.a & &rhs.a) ^ (self.a & rhs.b) ^ (self.b & rhs.a)
    }
}

impl std::ops::ShlAssign<usize> for Aby3BigUintShare {
    fn shl_assign(&mut self, rhs: usize) {
        self.a <<= rhs;
        self.b <<= rhs;
    }
}

impl<F: PrimeField, N: Aby3Network> Aby3Protocol<F, N> {
    fn ceil_log2(x: usize) -> usize {
        let mut y = 0;
        let mut x = x - 1;
        while x > 0 {
            x >>= 1;
            y += 1;
        }
        y
    }

    fn and(&mut self, a: Aby3BigUintShare, b: Aby3BigUintShare) -> IoResult<Aby3BigUintShare> {
        let (mut mask, mask_b) = self.rngs.random_biguint::<F>();
        mask ^= mask_b;
        let local_a = (a & b) ^ mask;
        self.network.send_next(local_a.to_owned())?;
        let local_b = self.network.recv_prev()?;
        Ok(Aby3BigUintShare {
            a: local_a,
            b: local_b,
        })
    }

    fn low_depth_binary_add_3_mod2k(
        &mut self,
        x1: Aby3BigUintShare,
        x2: Aby3BigUintShare,
        x3: Aby3BigUintShare,
    ) -> IoResult<()> {
        let bitlen: usize = F::MODULUS_BIT_SIZE as usize;
        let d = Self::ceil_log2(bitlen);
        let num_limbs = (bitlen + 63) / 64;
        let upper_mask = (1u64 << (bitlen % 64)) - 1;

        // Full adder to get 2 * c and s
        let mut x2x3 = x2;
        x2x3 ^= &x3;
        let mut s = &x1 ^ &x2x3;
        let mut x1x3 = x1;
        x1x3 ^= &x3;

        // 2 * c, could potentially safe one bit of communication here
        let mut c = self.and(x1x3, x2x3)?;
        c ^= x3;
        c <<= 1; // Todo can this be done better?

        // Add 2c + s via a packed Kogge-Stone adder
        let mut p = &s ^ &c;
        let mut g = self.and(s, c)?;
        let s_ = p.to_owned();
        for i in 0..d {
            // let p_ =
        }

        todo!()
    }
}
