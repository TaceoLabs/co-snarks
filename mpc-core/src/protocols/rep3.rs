//! # Rep3 Protocol
//!
//! This module contains an implementation of semi-honest 3-party [replicated secret sharing](https://eprint.iacr.org/2018/403.pdf).

use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use eyre::Report;
use itertools::{izip, Itertools};
use rand::{Rng, SeedableRng};
use rngs::{Rep3CorrelatedRng, Rep3Rand, Rep3RandBitComp};
use std::{marker::PhantomData, thread, time::Duration};

#[cfg(doc)]
use crate::traits::CircomWitnessExtensionProtocol;
use crate::{
    traits::{
        EcMpcProtocol, FFTProvider, MSMProvider, PairingEcMpcProtocol, PrimeFieldMpcProtocol,
    },
    RngType,
};
pub use a2b::Rep3BigUintShare;
pub use fieldshare::Rep3PrimeFieldShare;

use self::{
    fieldshare::Rep3PrimeFieldShareVec, id::PartyID, network::Rep3Network,
    pointshare::Rep3PointShare,
};

pub(crate) mod a2b;
pub mod fieldshare;
pub mod id;
pub mod network;
pub mod pointshare;
pub(crate) mod rngs;
pub mod witness_extension_impl;

type IoResult<T> = std::io::Result<T>;

/// # Rep3 Utils
/// This module contains utility functions to work with replicated secret sharing. I.e., it contains code to share field elements and curve points, as well as code to reconstruct the secret-shares.
pub mod utils {
    use ark_ec::CurveGroup;
    use ark_ff::{One, PrimeField};
    use num_bigint::BigUint;
    use rand::{CryptoRng, Rng};

    use super::{
        a2b::Rep3BigUintShare, fieldshare::Rep3PrimeFieldShareVec, pointshare::Rep3PointShare,
        witness_extension_impl::Rep3VmType, Rep3PrimeFieldShare,
    };

    /// Secret shares a field element using replicated secret sharing and the provided random number generator. The field element is split into three additive shares, where each party holds two. The outputs are of type [Rep3PrimeFieldShare].
    pub fn share_field_element<F: PrimeField, R: Rng + CryptoRng>(
        val: F,
        rng: &mut R,
    ) -> [Rep3PrimeFieldShare<F>; 3] {
        let a = F::rand(rng);
        let b = F::rand(rng);
        let c = val - a - b;
        let share1 = Rep3PrimeFieldShare::new(a, c);
        let share2 = Rep3PrimeFieldShare::new(b, a);
        let share3 = Rep3PrimeFieldShare::new(c, b);
        [share1, share2, share3]
    }

    /// Secret shares a field element using replicated secret sharing and the provided random number generator. The field element is split into three binary shares, where each party holds two. The outputs are of type [Rep3BigUintShare].
    pub fn xor_share_biguint<F: PrimeField, R: Rng + CryptoRng>(
        val: F,
        rng: &mut R,
    ) -> [Rep3BigUintShare; 3] {
        let val: BigUint = val.into();
        let limbsize = (F::MODULUS_BIT_SIZE + 31) / 32;
        let mask = (BigUint::from(1u32) << F::MODULUS_BIT_SIZE) - BigUint::one();
        let a = BigUint::new((0..limbsize).map(|_| rng.gen()).collect()) & &mask;
        let b = BigUint::new((0..limbsize).map(|_| rng.gen()).collect()) & mask;

        let c = val ^ &a ^ &b;
        let share1 = Rep3BigUintShare::new(a.to_owned(), c.to_owned());
        let share2 = Rep3BigUintShare::new(b.to_owned(), a);
        let share3 = Rep3BigUintShare::new(c, b);
        [share1, share2, share3]
    }

    /// Reconstructs a field element from its arithmetic replicated shares.
    pub fn combine_field_element<F: PrimeField>(
        share1: Rep3PrimeFieldShare<F>,
        share2: Rep3PrimeFieldShare<F>,
        share3: Rep3PrimeFieldShare<F>,
    ) -> F {
        share1.a + share2.a + share3.a
    }

    /// Reconstructs a value (represented as [BigUint]) from its binary replicated shares. Since binary operations can lead to results >= p, the result is not guaranteed to be a valid field element.
    pub fn xor_combine_biguint(
        share1: Rep3BigUintShare,
        share2: Rep3BigUintShare,
        share3: Rep3BigUintShare,
    ) -> BigUint {
        share1.get_a() ^ share2.get_a() ^ share3.get_a()
    }

    /// Secret shares a vector of field element using replicated secret sharing and the provided random number generator. The field elements are split into three additive shares each, where each party holds two. The outputs are of type [Rep3VmType].
    pub fn share_field_elements_for_vm<F: PrimeField, R: Rng + CryptoRng>(
        vals: &[F],
        rng: &mut R,
    ) -> [Vec<Rep3VmType<F>>; 3] {
        let mut shares1 = Vec::with_capacity(vals.len());
        let mut shares2 = Vec::with_capacity(vals.len());
        let mut shares3 = Vec::with_capacity(vals.len());
        for val in vals {
            let [share1, share2, share3] = share_field_element(*val, rng);
            shares1.push(Rep3VmType::Shared(share1));
            shares2.push(Rep3VmType::Shared(share2));
            shares3.push(Rep3VmType::Shared(share3));
        }
        [shares1, shares2, shares3]
    }

    /// Secret shares a vector of field element using replicated secret sharing and the provided random number generator. The field elements are split into three additive shares each, where each party holds two. The outputs are of type [Rep3PrimeFieldShareVec].
    pub fn share_field_elements<F: PrimeField, R: Rng + CryptoRng>(
        vals: &[F],
        rng: &mut R,
    ) -> [Rep3PrimeFieldShareVec<F>; 3] {
        let mut shares1a = Vec::with_capacity(vals.len());
        let mut shares1b = Vec::with_capacity(vals.len());
        let mut shares2a = Vec::with_capacity(vals.len());
        let mut shares2b = Vec::with_capacity(vals.len());
        let mut shares3a = Vec::with_capacity(vals.len());
        let mut shares3b = Vec::with_capacity(vals.len());
        for val in vals {
            let a = F::rand(rng);
            let b = F::rand(rng);
            let c = -a - b + val;
            shares1a.push(a);
            shares1b.push(c);
            shares2a.push(b);
            shares2b.push(a);
            shares3a.push(c);
            shares3b.push(b);
        }
        [
            Rep3PrimeFieldShareVec::new(shares1a, shares1b),
            Rep3PrimeFieldShareVec::new(shares2a, shares2b),
            Rep3PrimeFieldShareVec::new(shares3a, shares3b),
        ]
    }

    /// Reconstructs a vector of field elements from its arithmetic replicated shares.
    pub fn combine_field_elements<F: PrimeField>(
        share1: Rep3PrimeFieldShareVec<F>,
        share2: Rep3PrimeFieldShareVec<F>,
        share3: Rep3PrimeFieldShareVec<F>,
    ) -> Vec<F> {
        debug_assert_eq!(share1.len(), share2.len());
        debug_assert_eq!(share2.len(), share3.len());

        let (share1a, share1b) = share1.get_ab();
        let (share2a, share2b) = share2.get_ab();
        let (share3a, share3b) = share3.get_ab();
        let a_result = itertools::multizip((
            share1a.into_iter(),
            share2a.into_iter(),
            share3a.into_iter(),
        ))
        .map(|(x1, x2, x3)| x1 + x2 + x3)
        .collect::<Vec<_>>();
        let b_result = itertools::multizip((
            share1b.into_iter(),
            share2b.into_iter(),
            share3b.into_iter(),
        ))
        .map(|(x1, x2, x3)| x1 + x2 + x3)
        .collect::<Vec<_>>();
        assert_eq!(a_result, b_result);
        a_result
    }

    /// Secret shares a curve point using replicated secret sharing and the provided random number generator. The point is split into three additive shares, where each party holds two. The outputs are of type [Rep3PointShare].
    pub fn share_curve_point<C: CurveGroup, R: Rng + CryptoRng>(
        val: C,
        rng: &mut R,
    ) -> [Rep3PointShare<C>; 3] {
        let a = C::rand(rng);
        let b = C::rand(rng);
        let c = val - a - b;
        let share1 = Rep3PointShare::new(a, c);
        let share2 = Rep3PointShare::new(b, a);
        let share3 = Rep3PointShare::new(c, b);
        [share1, share2, share3]
    }

    /// Reconstructs a curve point from its arithmetic replicated shares.
    pub fn combine_curve_point<C: CurveGroup>(
        share1: Rep3PointShare<C>,
        share2: Rep3PointShare<C>,
        share3: Rep3PointShare<C>,
    ) -> C {
        share1.a + share2.a + share3.a
    }
}

/// This struct handles the full Rep3 MPC protocol, including witness extension and proof generation. Thus, it implements the [PrimeFieldMpcProtocol], [EcMpcProtocol], [PairingEcMpcProtocol], [FFTProvider], [MSMProvider], and [CircomWitnessExtensionProtocol] traits.
#[derive(Debug)]
pub struct Rep3Protocol<F: PrimeField, N: Rep3Network> {
    rngs: Rep3CorrelatedRng,
    pub(crate) network: N,
    field: PhantomData<F>,
}

impl<F: PrimeField, N: Rep3Network> Rep3Protocol<F, N> {
    fn setup_prf(network: &mut N) -> Result<Rep3Rand, Report> {
        let seed1: [u8; crate::SEED_SIZE] = RngType::from_entropy().gen();
        network.send_next(seed1)?;
        let seed2: [u8; crate::SEED_SIZE] = network.recv_prev()?;

        Ok(Rep3Rand::new(seed1, seed2))
    }

    fn setup_bitcomp(
        network: &mut N,
        rands: &mut Rep3Rand,
    ) -> Result<(Rep3RandBitComp, Rep3RandBitComp), Report> {
        let (k1a, k1c) = rands.random_seeds();
        let (k2a, k2c) = rands.random_seeds();

        match network.get_id() {
            PartyID::ID0 => {
                network.send_next(k1c)?;
                let k2b: [u8; crate::SEED_SIZE] = network.recv_prev()?;
                let bitcomp1 = Rep3RandBitComp::new_2keys(k1a, k1c);
                let bitcomp2 = Rep3RandBitComp::new_3keys(k2a, k2b, k2c);
                Ok((bitcomp1, bitcomp2))
            }
            PartyID::ID1 => {
                network.send_next((k1c, k2c))?;
                let k1b: [u8; crate::SEED_SIZE] = network.recv_prev()?;
                let bitcomp1 = Rep3RandBitComp::new_3keys(k1a, k1b, k1c);
                let bitcomp2 = Rep3RandBitComp::new_2keys(k2a, k2c);
                Ok((bitcomp1, bitcomp2))
            }
            PartyID::ID2 => {
                network.send_next(k2c)?;
                let (k1b, k2b): ([u8; crate::SEED_SIZE], [u8; crate::SEED_SIZE]) =
                    network.recv_prev()?;
                let bitcomp1 = Rep3RandBitComp::new_3keys(k1a, k1b, k1c);
                let bitcomp2 = Rep3RandBitComp::new_3keys(k2a, k2b, k2c);
                Ok((bitcomp1, bitcomp2))
            }
        }
    }

    /// Constructs the Rep3 protocol from an established network.
    pub fn new(mut network: N) -> Result<Self, Report> {
        let mut rand = Self::setup_prf(&mut network)?;
        let bitcomps = Self::setup_bitcomp(&mut network, &mut rand)?;
        let rngs = Rep3CorrelatedRng::new(rand, bitcomps.0, bitcomps.1);

        Ok(Self {
            network,
            rngs,
            field: PhantomData,
        })
    }

    /// This algorithm produces asqrt of a shared value. Thereby, no guarantee is given on whether the result is the positive or negative square root (when interpreted as signed field element). This function requires network interaction.
    pub fn sqrt(&mut self, a: &Rep3PrimeFieldShare<F>) -> IoResult<Rep3PrimeFieldShare<F>> {
        let r_squ = self.rand()?;
        let r_inv = self.rand()?;

        let rr = self.mul(&r_squ, &r_squ)?;

        // parallel mul of rr with a and r_squ with r_inv
        let lhs = Rep3PrimeFieldShareVec::new(vec![rr.a, r_squ.a], vec![rr.b, r_squ.b]);
        let rhs = Rep3PrimeFieldShareVec::new(vec![a.a, r_inv.a], vec![a.b, r_inv.b]);
        let mul = self.mul_vec(&lhs, &rhs)?;

        // Open mul
        self.network.send_next(mul.b.to_owned())?;
        let c = self.network.recv_prev::<Vec<F>>()?;
        if c.len() != 2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "During execution of square root in MPC: invalid number of elements received",
            ));
        }
        let y_sq = (mul.a[0] + mul.b[0] + c[0]).sqrt();
        let y_inv = mul.a[1] + mul.b[1] + c[1];

        // postprocess the square and inverse
        let y_sq = match y_sq {
            Some(y) => y,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "During execution of square root in MPC: cannot compute square root",
                ));
            }
        };

        if y_inv.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "During execution of square root in MPC: cannot compute inverse of zero",
            ));
        }
        let y_inv = y_inv.inverse().unwrap();

        let r_squ_inv = r_inv * y_inv;
        let a_sqrt = r_squ_inv * y_sq;

        Ok(a_sqrt)
    }
}

impl<F: PrimeField, N: Rep3Network> PrimeFieldMpcProtocol<F> for Rep3Protocol<F, N> {
    type FieldShare = Rep3PrimeFieldShare<F>;
    type FieldShareVec = Rep3PrimeFieldShareVec<F>;

    fn add(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare {
        a + b
    }

    fn sub(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare {
        a - b
    }

    fn mul(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> IoResult<Self::FieldShare> {
        let local_a = a * b + self.rngs.rand.masking_field_element::<F>();
        self.network.send_next(local_a)?;
        let local_b = self.network.recv_prev()?;
        Ok(Self::FieldShare {
            a: local_a,
            b: local_b,
        })
    }

    fn inv(&mut self, a: &Self::FieldShare) -> IoResult<Self::FieldShare> {
        let r = self.rand()?;
        let tmp = self.mul(a, &r)?;
        let y = self.open(&tmp)?;
        if y.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "During execution of inverse in MPC: cannot compute inverse of zero",
            ));
        }
        let y_inv = y.inverse().unwrap();
        Ok(r * y_inv)
    }

    fn neg(&mut self, a: &Self::FieldShare) -> Self::FieldShare {
        -a
    }

    fn neg_vec_in_place(&mut self, vec: &mut Self::FieldShareVec) {
        for (a, b) in vec.a.iter_mut().zip(vec.b.iter_mut()) {
            a.neg_in_place();
            b.neg_in_place();
        }
    }

    fn rand(&mut self) -> std::io::Result<Self::FieldShare> {
        let (a, b) = self.rngs.rand.random_fes();
        Ok(Self::FieldShare { a, b })
    }

    fn add_with_public(&mut self, a: &F, b: &Self::FieldShare) -> Self::FieldShare {
        let mut res = b.to_owned();
        match self.network.get_id() {
            id::PartyID::ID0 => res.a += a,
            id::PartyID::ID1 => res.b += a,
            id::PartyID::ID2 => {}
        }
        res
    }

    fn mul_with_public(&mut self, a: &F, b: &Self::FieldShare) -> Self::FieldShare {
        b * a
    }

    fn open(&mut self, a: &Self::FieldShare) -> std::io::Result<F> {
        self.network.send_next(a.b)?;
        let c = self.network.recv_prev::<F>()?;
        Ok(a.a + a.b + c)
    }

    fn promote_to_trivial_share(&self, public_value: F) -> Self::FieldShare {
        Self::FieldShare::promote_from_trivial(&public_value, self.network.get_id())
    }

    fn promote_to_trivial_shares(&self, public_values: &[F]) -> Self::FieldShareVec {
        Self::FieldShareVec::promote_from_trivial(public_values, self.network.get_id())
    }

    fn add_vec(&mut self, a: &Self::FieldShareVec, b: &Self::FieldShareVec) -> Self::FieldShareVec {
        debug_assert_eq!(a.len(), b.len());
        let mut vec = Vec::with_capacity(a.len());
        for (aa, ab, ba, bb) in izip!(a.a.iter(), a.b.iter(), b.a.iter(), b.b.iter()) {
            vec.push(Rep3PrimeFieldShare {
                a: *aa + ba,
                b: *ab + bb,
            })
        }
        vec.into()
    }

    fn mul_vec(
        &mut self,
        a: &Self::FieldShareVec,
        b: &Self::FieldShareVec,
    ) -> std::io::Result<Self::FieldShareVec> {
        debug_assert_eq!(a.len(), b.len());
        let local_a = izip!(a.a.iter(), a.b.iter(), b.a.iter(), b.b.iter())
            .map(|(aa, ab, ba, bb)| {
                *aa * ba + *aa * bb + *ab * ba + self.rngs.rand.masking_field_element::<F>()
            })
            .collect_vec();
        self.network.send_next_many(&local_a)?;
        let local_b = self.network.recv_prev_many()?;
        if local_b.len() != local_a.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "During execution of mul_vec in MPC: Invalid number of elements received",
            ));
        }
        Ok(Self::FieldShareVec::new(local_a, local_b))
    }

    fn sub_assign_vec(&mut self, a: &mut Self::FieldShareVec, b: &Self::FieldShareVec) {
        for (a, b) in izip!(a.a.iter_mut(), &b.a) {
            *a -= b;
        }
        for (a, b) in izip!(a.b.iter_mut(), &b.b) {
            *a -= b;
        }
    }

    fn distribute_powers_and_mul_by_const(&mut self, coeffs: &mut Self::FieldShareVec, g: F, c: F) {
        let mut pow = c;
        for (a, b) in coeffs.a.iter_mut().zip(coeffs.b.iter_mut()) {
            *a *= pow;
            *b *= pow;
            pow *= g;
        }
    }

    fn evaluate_constraint(
        &mut self,
        lhs: &[(F, usize)],
        public_inputs: &[F],
        private_witness: &Self::FieldShareVec,
    ) -> Self::FieldShare {
        let mut acc = Rep3PrimeFieldShare::default();
        for (coeff, index) in lhs {
            if index < &public_inputs.len() {
                let val = public_inputs[*index];
                let mul_result = val * coeff;
                acc = self.add_with_public(&mul_result, &acc);
            } else {
                acc.a += *coeff * private_witness.a[*index - public_inputs.len()];
                acc.b += *coeff * private_witness.b[*index - public_inputs.len()];
            }
        }
        acc
    }

    fn clone_from_slice(
        &self,
        dst: &mut Self::FieldShareVec,
        src: &Self::FieldShareVec,
        dst_offset: usize,
        src_offset: usize,
        len: usize,
    ) {
        assert!(dst.a.len() >= dst_offset + len);
        assert!(dst.b.len() >= dst_offset + len);
        assert!(src.a.len() >= src_offset + len);
        assert!(src.b.len() >= src_offset + len);
        assert!(len > 0);
        dst.a[dst_offset..dst_offset + len].clone_from_slice(&src.a[src_offset..src_offset + len]);
        dst.b[dst_offset..dst_offset + len].clone_from_slice(&src.b[src_offset..src_offset + len]);
    }

    fn print(&self, to_print: &Self::FieldShareVec) {
        match self.network.get_id() {
            PartyID::ID0 => thread::sleep(Duration::from_millis(10)),
            PartyID::ID1 => thread::sleep(Duration::from_millis(100)),
            PartyID::ID2 => thread::sleep(Duration::from_millis(300)),
        }
        print!("[");
        for a in to_print.b.iter() {
            print!("{a}, ")
        }
        println!("]");
    }

    fn index_sharevec(sharevec: &Self::FieldShareVec, index: usize) -> Self::FieldShare {
        Self::FieldShare {
            a: sharevec.a[index],
            b: sharevec.b[index],
        }
    }

    fn set_index_sharevec(sharevec: &mut Self::FieldShareVec, val: Self::FieldShare, index: usize) {
        sharevec.a[index] = val.a;
        sharevec.a[index] = val.a;
    }

    fn sharevec_len(sharevec: &Self::FieldShareVec) -> usize {
        sharevec.len()
    }
}

impl<F: PrimeField> Default for Rep3PrimeFieldShare<F> {
    fn default() -> Self {
        Self {
            a: F::zero(),
            b: F::zero(),
        }
    }
}

impl<C: CurveGroup, N: Rep3Network> EcMpcProtocol<C> for Rep3Protocol<C::ScalarField, N> {
    type PointShare = Rep3PointShare<C>;

    fn add_points(&mut self, a: &Self::PointShare, b: &Self::PointShare) -> Self::PointShare {
        a + b
    }

    fn sub_points(&mut self, a: &Self::PointShare, b: &Self::PointShare) -> Self::PointShare {
        a - b
    }

    fn add_assign_points(&mut self, a: &mut Self::PointShare, b: &Self::PointShare) {
        *a += b;
    }

    fn sub_assign_points(&mut self, a: &mut Self::PointShare, b: &Self::PointShare) {
        *a -= b;
    }

    fn add_assign_points_public(&mut self, a: &mut Self::PointShare, b: &C) {
        match self.network.get_id() {
            id::PartyID::ID0 => a.a += b,
            id::PartyID::ID1 => a.b += b,
            id::PartyID::ID2 => {}
        }
    }

    fn sub_assign_points_public(&mut self, a: &mut Self::PointShare, b: &C) {
        match self.network.get_id() {
            id::PartyID::ID0 => a.a -= b,
            id::PartyID::ID1 => a.b -= b,
            id::PartyID::ID2 => {}
        }
    }

    fn add_assign_points_public_affine(&mut self, a: &mut Self::PointShare, b: &C::Affine) {
        match self.network.get_id() {
            id::PartyID::ID0 => a.a += b,
            id::PartyID::ID1 => a.b += b,
            id::PartyID::ID2 => {}
        }
    }

    fn sub_assign_points_public_affine(&mut self, a: &mut Self::PointShare, b: &C::Affine) {
        match self.network.get_id() {
            id::PartyID::ID0 => a.a -= b,
            id::PartyID::ID1 => a.b -= b,
            id::PartyID::ID2 => {}
        }
    }

    fn scalar_mul_public_point(&mut self, a: &C, b: &Self::FieldShare) -> Self::PointShare {
        Self::PointShare {
            a: a.mul(b.a),
            b: a.mul(b.b),
        }
    }

    fn scalar_mul_public_scalar(
        &mut self,
        a: &Self::PointShare,
        b: &<C>::ScalarField,
    ) -> Self::PointShare {
        a * b
    }

    fn scalar_mul(
        &mut self,
        a: &Self::PointShare,
        b: &Self::FieldShare,
    ) -> IoResult<Self::PointShare> {
        let local_a = b * a + self.rngs.rand.masking_ec_element::<C>();
        self.network.send_next(local_a)?;
        let local_b = self.network.recv_prev()?;
        Ok(Self::PointShare {
            a: local_a,
            b: local_b,
        })
    }

    fn open_point(&mut self, a: &Self::PointShare) -> std::io::Result<C> {
        self.network.send_next(a.b)?;
        let c = self.network.recv_prev::<C>()?;
        Ok(a.a + a.b + c)
    }
}

impl<P: Pairing, N: Rep3Network> PairingEcMpcProtocol<P> for Rep3Protocol<P::ScalarField, N> {
    fn open_two_points(
        &mut self,
        a: &<Self as EcMpcProtocol<P::G1>>::PointShare,
        b: &<Self as EcMpcProtocol<P::G2>>::PointShare,
    ) -> std::io::Result<(P::G1, P::G2)> {
        let s1 = a.b;
        let s2 = b.b;
        self.network.send_next((s1, s2))?;
        let (mut r1, mut r2) = self.network.recv_prev::<(P::G1, P::G2)>()?;
        r1 += a.a + a.b;
        r2 += b.a + b.b;
        Ok((r1, r2))
    }
}

impl<F: PrimeField + crate::traits::FFTPostProcessing, N: Rep3Network> FFTProvider<F>
    for Rep3Protocol<F, N>
{
    fn fft<D: EvaluationDomain<F>>(
        &mut self,
        data: Self::FieldShareVec,
        domain: &D,
    ) -> Self::FieldShareVec {
        let mut a = domain.fft(&data.a);
        let mut b = domain.fft(&data.b);
        crate::traits::FFTPostProcessing::fft_post_processing(&mut a);
        crate::traits::FFTPostProcessing::fft_post_processing(&mut b);
        Self::FieldShareVec::new(a, b)
    }

    fn fft_in_place<D: EvaluationDomain<F>>(&mut self, data: &mut Self::FieldShareVec, domain: &D) {
        domain.fft_in_place(&mut data.a);
        domain.fft_in_place(&mut data.b);
        crate::traits::FFTPostProcessing::fft_post_processing(&mut data.a);
        crate::traits::FFTPostProcessing::fft_post_processing(&mut data.b);
    }

    fn ifft<D: EvaluationDomain<F>>(
        &mut self,
        data: &Self::FieldShareVec,
        domain: &D,
    ) -> Self::FieldShareVec {
        let mut a = domain.ifft(&data.a);
        let mut b = domain.ifft(&data.b);
        crate::traits::FFTPostProcessing::fft_post_processing(&mut a);
        crate::traits::FFTPostProcessing::fft_post_processing(&mut b);
        Self::FieldShareVec::new(a, b)
    }

    fn ifft_in_place<D: EvaluationDomain<F>>(
        &mut self,
        data: &mut Self::FieldShareVec,
        domain: &D,
    ) {
        domain.ifft_in_place(&mut data.a);
        domain.ifft_in_place(&mut data.b);
        crate::traits::FFTPostProcessing::fft_post_processing(&mut data.a);
        crate::traits::FFTPostProcessing::fft_post_processing(&mut data.b);
    }
}

impl<C: CurveGroup, N: Rep3Network> MSMProvider<C> for Rep3Protocol<C::ScalarField, N> {
    fn msm_public_points(
        &mut self,
        points: &[C::Affine],
        scalars: &Self::FieldShareVec,
    ) -> Self::PointShare {
        debug_assert_eq!(points.len(), scalars.len());
        let res_a = C::msm_unchecked(points, &scalars.a);
        let res_b = C::msm_unchecked(points, &scalars.b);
        Self::PointShare { a: res_a, b: res_b }
    }
}
