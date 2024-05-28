use super::{network::Aby3Network, Aby3Protocol, IoResult};
use ark_ff::PrimeField;
use itertools::Itertools;
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

impl std::ops::BitAnd<&Self> for Aby3BigUintShare {
    type Output = BigUint;

    // Local part of AND only
    fn bitand(self, rhs: &Self) -> Self::Output {
        (&self.a & &rhs.a) ^ (self.a & &rhs.b) ^ (self.b & &rhs.a)
    }
}

impl std::ops::ShlAssign<usize> for Aby3BigUintShare {
    fn shl_assign(&mut self, rhs: usize) {
        self.a <<= rhs;
        self.b <<= rhs;
    }
}

impl<F: PrimeField, N: Aby3Network> Aby3Protocol<F, N> {
    const LIMB_BITS: usize = 64;
    const BITLEN: usize = F::MODULUS_BIT_SIZE as usize;
    const LIMBS: usize = (Self::BITLEN + 63) / 64;
    const UPPER_MASK: u64 = (1u64 << (Self::BITLEN % 64)) - 1;

    fn ceil_log2(x: usize) -> usize {
        let mut y = 0;
        let mut x = x - 1;
        while x > 0 {
            x >>= 1;
            y += 1;
        }
        y
    }

    fn shift_left_mod(x: &mut BigUint, shift: usize) {
        let n_unit = shift / Self::LIMB_BITS;
        let mut data = match n_unit {
            0 => x.to_u64_digits(),
            _ => {
                let x_iter = x.iter_u64_digits();
                let len = x_iter.len();
                let mut data = Vec::with_capacity(len);
                data.resize(n_unit, 0);
                for elem in x_iter.take(len - n_unit) {
                    data.push(elem);
                }
                data
            }
        };

        let n_bits = shift % Self::LIMB_BITS;
        if n_bits > 0 {
            let mut carry = 0;
            for elem in data[n_unit..].iter_mut() {
                let new_carry = *elem >> (Self::LIMB_BITS - n_bits);
                *elem = (*elem << n_bits) | carry;
                carry = new_carry;
            }
        }
        data[Self::LIMBS - 1] &= Self::UPPER_MASK;
        *x = BigUint::from_bytes_le(
            data.into_iter()
                .flat_map(|x| x.to_le_bytes())
                .collect_vec()
                .as_slice(),
        );
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

    fn and_twice(
        &mut self,
        a: Aby3BigUintShare,
        b1: Aby3BigUintShare,
        b2: Aby3BigUintShare,
    ) -> IoResult<(Aby3BigUintShare, Aby3BigUintShare)> {
        let (mut mask1, mask_b) = self.rngs.random_biguint::<F>();
        mask1 ^= mask_b;

        let (mut mask2, mask_b) = self.rngs.random_biguint::<F>();
        mask2 ^= mask_b;

        let local_a1 = (b1 & &a) ^ mask1;
        let local_a2 = (a & b2) ^ mask2;
        self.network.send_next(local_a1.to_owned())?;
        self.network.send_next(local_a2.to_owned())?;
        let local_b1 = self.network.recv_prev()?;
        let local_b2 = self.network.recv_prev()?;

        let r1 = Aby3BigUintShare {
            a: local_a1,
            b: local_b1,
        };
        let r2 = Aby3BigUintShare {
            a: local_a2,
            b: local_b2,
        };

        Ok((r1, r2))
    }

    fn low_depth_binary_add_2(
        &mut self,
        x1: Aby3BigUintShare,
        x2: Aby3BigUintShare,
    ) -> IoResult<()> {
        let d = Self::ceil_log2(Self::BITLEN);

        // Add x1 + x2 via a packed Kogge-Stone adder
        let mut p = &x1 ^ &x2;
        let mut g = self.and(x1, x2)?;
        let s_ = p.to_owned();
        for i in 0..d {
            let shift = 1 << i;
            let mut p_ = p.to_owned();
            let mut g_ = g.to_owned();
            Self::shift_left_mod(&mut p_.a, shift);
            Self::shift_left_mod(&mut p_.b, shift);
            Self::shift_left_mod(&mut g_.a, shift);
            Self::shift_left_mod(&mut g_.b, shift);

            // TODO shift right for optimized performance

            let (r1, r2) = self.and_twice(p, g_, p_)?;
            p = r2;
        }

        todo!()
    }
}
