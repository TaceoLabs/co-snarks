use super::{id::PartyID, network::Aby3Network, Aby3PrimeFieldShare, Aby3Protocol, IoResult};
use ark_ff::{One, PrimeField, Zero};
use itertools::Itertools;
use num_bigint::BigUint;

// TODO CanonicalDeserialize and CanonicalSerialize
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Aby3BigUintShare {
    pub(crate) a: BigUint,
    pub(crate) b: BigUint,
}

impl Aby3BigUintShare {
    fn new(a: BigUint, b: BigUint) -> Self {
        Self { a, b }
    }

    pub fn get_a(self) -> BigUint {
        self.a
    }

    fn xor_with_public(&self, a: &BigUint, id: PartyID) -> Aby3BigUintShare {
        let mut res = self.to_owned();
        match id {
            PartyID::ID0 => res.a ^= a,
            PartyID::ID1 => res.b ^= a,
            PartyID::ID2 => {}
        }
        res
    }
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

impl std::ops::BitAndAssign<&BigUint> for Aby3BigUintShare {
    fn bitand_assign(&mut self, rhs: &BigUint) {
        self.a &= rhs;
        self.b &= rhs;
    }
}

impl std::ops::BitAnd<&BigUint> for &Aby3BigUintShare {
    type Output = Aby3BigUintShare;

    fn bitand(self, rhs: &BigUint) -> Self::Output {
        Aby3BigUintShare {
            a: &self.a & rhs,
            b: &self.b & rhs,
        }
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

impl std::ops::Shl<usize> for Aby3BigUintShare {
    type Output = Self;

    fn shl(self, rhs: usize) -> Self::Output {
        Aby3BigUintShare {
            a: &self.a << rhs,
            b: &self.b << rhs,
        }
    }
}

impl std::ops::Shr<usize> for &Aby3BigUintShare {
    type Output = Aby3BigUintShare;

    fn shr(self, rhs: usize) -> Self::Output {
        Aby3BigUintShare {
            a: &self.a >> rhs,
            b: &self.b >> rhs,
        }
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
    ) -> IoResult<Aby3BigUintShare> {
        let d = usize::ilog2(Self::BITLEN);

        // Add x1 + x2 via a packed Kogge-Stone adder
        let mut p = &x1 ^ &x2;
        let mut g = self.and(x1, x2)?;
        let s_ = p.to_owned();

        for i in 0..d {
            let shift = 1 << i;
            let mut p_ = p.to_owned();
            let mut g_ = g.to_owned();
            let mask = (BigUint::from(1u64) << (Self::BITLEN - shift)) - BigUint::one();
            p_ &= &mask;
            g_ &= &mask;
            let p_shift = &p >> shift;

            let (r1, r2) = self.and_twice(p_shift, g_, p_)?;
            p = r2 << shift;
            g ^= r1 << shift;
        }
        g <<= 1;
        g ^= s_;
        Ok(g)
    }

    fn low_depth_binary_sub_p(&mut self, x: &Aby3BigUintShare) -> IoResult<Aby3BigUintShare> {
        let p_ = (BigUint::from(1u64) << Self::BITLEN) - F::MODULUS.into();
        let d = usize::ilog2(Self::BITLEN);

        // Add x1 + p_ via a packed Kogge-Stone adder
        let mut p = x.xor_with_public(&p_, self.network.get_id());
        let mut g = x & &p_;
        let s_ = p.to_owned();

        for i in 0..d {
            let shift = 1 << i;
            let mut p_ = p.to_owned();
            let mut g_ = g.to_owned();
            let mask = (BigUint::from(1u64) << (Self::BITLEN - shift)) - BigUint::one();
            p_ &= &mask;
            g_ &= &mask;
            let p_shift = &p >> shift;

            let (r1, r2) = self.and_twice(p_shift, g_, p_)?;
            p = r2 << shift;
            g ^= r1 << shift;
        }
        g <<= 1;
        g ^= s_;
        Ok(g)
    }

    fn cmux(
        &mut self,
        c: Aby3BigUintShare,
        x_t: Aby3BigUintShare,
        x_f: Aby3BigUintShare,
    ) -> IoResult<Aby3BigUintShare> {
        let mut xor = x_t;
        xor ^= &x_f;
        let mut and = self.and(c, xor)?;
        and ^= x_f;
        Ok(and)
    }

    pub fn a2b(&mut self, x: &Aby3PrimeFieldShare<F>) -> IoResult<Aby3BigUintShare> {
        let mut x01 = Aby3BigUintShare::default();
        let mut x2 = Aby3BigUintShare::default();

        let (mut r, r2) = self.rngs.random_biguint::<F>();
        r ^= r2;

        match self.network.get_id() {
            PartyID::ID0 => {
                x01.a = r;
                x2.b = x.b.into();
            }
            PartyID::ID1 => {
                let val: BigUint = (x.a + x.b).into();
                x01.a = val ^ r;
            }
            PartyID::ID2 => {
                x01.a = r;
                x2.a = x.a.into();
            }
        }

        // Reshare x01
        self.network.send_next(x01.a.to_owned())?;
        let local_b = self.network.recv_prev()?;
        x01.b = local_b;

        // Circuits
        let mask = (BigUint::from(1u64) << Self::BITLEN) - BigUint::one();
        let mut x = self.low_depth_binary_add_2(x01, x2)?;
        let x_msb = &x >> (Self::BITLEN);
        x &= &mask;
        let mut y = self.low_depth_binary_sub_p(&x)?;
        let y_msb = &y >> (Self::BITLEN);
        y &= &mask;

        // Spread the ov share to the whole biguint
        let ov_a = (x_msb.a.iter_u64_digits().next().unwrap()
            ^ y_msb.a.iter_u64_digits().next().unwrap())
            & 1;
        let ov_b = (x_msb.b.iter_u64_digits().next().unwrap()
            ^ y_msb.b.iter_u64_digits().next().unwrap())
            & 1;

        let ov_a = if ov_a == 1 {
            mask.to_owned()
        } else {
            BigUint::zero()
        };
        let ov_b = if ov_b == 1 { mask } else { BigUint::zero() };
        let ov = Aby3BigUintShare::new(ov_a, ov_b);

        // one big multiplexer
        let res = self.cmux(ov, x, y)?;
        Ok(res)
    }
}
