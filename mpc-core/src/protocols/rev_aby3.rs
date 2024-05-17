use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use eyre::{bail, Report};
use itertools::{izip, Itertools};
use rand::{Rng, SeedableRng};
use std::{marker::PhantomData, thread, time::Duration};

use crate::{
    traits::{
        EcMpcProtocol, FFTProvider, MSMProvider, PairingEcMpcProtocol, PrimeFieldMpcProtocol,
    },
    RngType,
};

use self::{id::PartyID, network::Aby3Network};

use super::aby3::Aby3CorrelatedRng;

pub mod id;
pub mod network;

type IoResult<T> = std::io::Result<T>;

pub mod utils {
    use ark_ec::CurveGroup;
    use ark_ff::PrimeField;
    use itertools::izip;
    use rand::{CryptoRng, Rng};

    pub fn share_field_element<F: PrimeField, R: Rng + CryptoRng>(val: F, rng: &mut R) -> [F; 3] {
        let a = F::rand(rng);
        let b = F::rand(rng);
        let c = val - a - b;
        [a, b, c]
    }

    pub fn combine_field_element<F: PrimeField>(share1: F, share2: F, share3: F) -> F {
        share1 + share2 + share3
    }

    pub fn share_field_elements<F: PrimeField, R: Rng + CryptoRng>(
        vals: Vec<F>,
        rng: &mut R,
    ) -> [Vec<F>; 3] {
        let mut shares1 = Vec::with_capacity(vals.len());
        let mut shares2 = Vec::with_capacity(vals.len());
        let mut shares3 = Vec::with_capacity(vals.len());
        for val in vals {
            let a = F::rand(rng);
            let b = F::rand(rng);
            let c = val - a - b;
            shares1.push(a);
            shares2.push(b);
            shares3.push(c);
        }
        [shares1, shares2, shares3]
    }

    pub fn combine_field_elements<F: PrimeField>(
        share1: Vec<F>,
        share2: Vec<F>,
        share3: Vec<F>,
    ) -> Vec<F> {
        debug_assert_eq!(share1.len(), share2.len());
        debug_assert_eq!(share2.len(), share3.len());

        izip!(share1, share2, share3)
            .map(|(x1, x2, x3)| x1 + x2 + x3)
            .collect::<Vec<_>>()
    }

    pub fn share_curve_point<C: CurveGroup, R: Rng + CryptoRng>(val: C, rng: &mut R) -> [C; 3] {
        let a = C::rand(rng);
        let b = C::rand(rng);
        let c = val - a - b;
        [a, b, c]
    }

    pub fn combine_curve_point<C: CurveGroup>(share1: C, share2: C, share3: C) -> C {
        share1 + share2 + share3
    }
}

pub struct RevAby3Protocol<F: PrimeField, N: Aby3Network> {
    rngs: Aby3CorrelatedRng,
    network: N,
    field: PhantomData<F>,
}

impl<F: PrimeField, N: Aby3Network> RevAby3Protocol<F, N> {
    pub fn new(mut network: N) -> Result<Self, Report> {
        let seed1: [u8; crate::SEED_SIZE] = RngType::from_entropy().gen();
        let seed2_bytes = network.send_and_receive_seed(seed1.to_vec().into())?;
        if seed2_bytes.len() != crate::SEED_SIZE {
            bail!("Received seed is not {} bytes long", crate::SEED_SIZE);
        }
        let seed2 = {
            let mut buf = [0u8; crate::SEED_SIZE];
            buf[..].copy_from_slice(&seed2_bytes[..]);
            buf
        };
        Ok(Self {
            network,
            rngs: Aby3CorrelatedRng::new(seed1, seed2),
            field: PhantomData,
        })
    }
}

impl<F: PrimeField, N: Aby3Network> PrimeFieldMpcProtocol<F> for RevAby3Protocol<F, N> {
    type FieldShare = F;
    type FieldShareSlice<'a> = &'a Vec<F>;
    type FieldShareSliceMut<'a> = &'a mut Vec<F>;
    type FieldShareVec = Vec<F>;

    fn add(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare {
        *a + b
    }

    fn sub(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare {
        *a - b
    }

    fn mul(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> IoResult<Self::FieldShare> {
        self.network.send_next((*a, *b))?; // TODO: randomness
        let (a1, b1) = self.network.recv_prev::<(F, F)>()?;
        let res = *a * b + a1 * b + *a * b1 + self.rngs.masking_field_element::<F>();
        Ok(res)
    }

    fn inv(&mut self, a: &Self::FieldShare) -> IoResult<Self::FieldShare> {
        let r = self.rand()?;
        let tmp = self.mul(a, &r)?;
        let y = self.open(&tmp)?;
        if y.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Cannot invert zero",
            ));
        }
        let y_inv = y.inverse().unwrap();
        Ok(r * y_inv)
    }

    fn neg(&mut self, a: &Self::FieldShare) -> Self::FieldShare {
        -*a
    }

    fn rand(&mut self) -> std::io::Result<Self::FieldShare> {
        Ok(self.rngs.random_fes().0)
    }

    fn add_with_public(&mut self, a: &F, b: &Self::FieldShare) -> Self::FieldShare {
        let mut res = b.to_owned();
        match self.network.get_id() {
            id::PartyID::ID0 => res += a,
            id::PartyID::ID1 | id::PartyID::ID2 => {}
        }
        res
    }

    fn mul_with_public(&mut self, a: &F, b: &Self::FieldShare) -> Self::FieldShare {
        *b * a
    }

    fn open(&mut self, a: &Self::FieldShare) -> std::io::Result<F> {
        self.network.send_next(*a)?;
        self.network.send(self.network.get_id().prev_id(), *a)?;
        let b = self.network.recv_prev::<F>()?;
        let c = self.network.recv::<F>(self.network.get_id().next_id())?;
        Ok(c + b + a)
    }

    fn promote_to_trivial_share(&self, public_values: &[F]) -> Self::FieldShareVec {
        let mut vec = Vec::with_capacity(public_values.len());
        //additive share1 gets the value everyone else zero
        //therefore id1 and id2 needs the share
        for val in public_values {
            let share = match self.network.get_id() {
                PartyID::ID0 => *val,
                PartyID::ID1 => F::zero(),
                PartyID::ID2 => F::zero(),
            };
            vec.push(share);
        }
        vec
    }

    fn mul_vec(
        &mut self,
        a: &Self::FieldShareSlice<'_>,
        b: &Self::FieldShareSlice<'_>,
    ) -> std::io::Result<Self::FieldShareVec> {
        debug_assert_eq!(a.len(), b.len());
        self.network.send_next_many(a)?;
        self.network.send_next_many(b)?;
        let a_b = self.network.recv_prev_many::<F>()?;
        let b_b = self.network.recv_prev_many::<F>()?;
        let res = izip!(a.iter(), a_b.iter(), b.iter(), b_b.iter())
            .map(|(aa, ab, ba, bb)| {
                *aa * ba + *aa * bb + *ab * ba + self.rngs.masking_field_element::<F>()
            })
            .collect_vec();
        Ok(res)
    }

    fn sub_assign_vec(
        &mut self,
        a: &mut Self::FieldShareSliceMut<'_>,
        b: &Self::FieldShareSlice<'_>,
    ) {
        for (a, b) in izip!(a.iter_mut(), b.iter()) {
            *a -= b;
        }
    }

    fn distribute_powers_and_mul_by_const(
        &mut self,
        coeffs: &mut Self::FieldShareSliceMut<'_>,
        g: F,
        c: F,
    ) {
        let mut pow = c;
        for a in coeffs.iter_mut() {
            *a *= pow;
            pow *= g;
        }
    }

    fn evaluate_constraint(
        &mut self,
        lhs: &[(F, usize)],
        public_inputs: &[F],
        private_witness: &Self::FieldShareSlice<'_>,
    ) -> Self::FieldShare {
        let mut acc = F::default();
        for (coeff, index) in lhs {
            if index < &public_inputs.len() {
                let val = public_inputs[*index];
                let mul_result = val * coeff;
                acc = self.add_with_public(&mul_result, &acc);
            } else {
                acc += *coeff * private_witness[*index - public_inputs.len()];
            }
        }
        acc
    }

    fn clone_from_slice(
        &self,
        dst: &mut Self::FieldShareSliceMut<'_>,
        src: &Self::FieldShareSlice<'_>,
        dst_offset: usize,
        src_offset: usize,
        len: usize,
    ) {
        assert!(dst.len() >= dst_offset + len);
        assert!(src.len() >= src_offset + len);
        assert!(len > 0);
        dst[dst_offset..dst_offset + len].clone_from_slice(&src[src_offset..src_offset + len]);
    }

    fn print(&self, to_print: &Self::FieldShareVec) {
        match self.network.get_id() {
            PartyID::ID0 => thread::sleep(Duration::from_millis(10)),
            PartyID::ID1 => thread::sleep(Duration::from_millis(100)),
            PartyID::ID2 => thread::sleep(Duration::from_millis(300)),
        }
        print!("[");
        for a in to_print.iter() {
            print!("{a}, ")
        }
        println!("]");
    }

    fn print_slice(&self, to_print: &Self::FieldShareSlice<'_>) {
        match self.network.get_id() {
            PartyID::ID0 => {
                println!("==================");
                thread::sleep(Duration::from_millis(10));
            }
            PartyID::ID1 => thread::sleep(Duration::from_millis(100)),
            PartyID::ID2 => thread::sleep(Duration::from_millis(300)),
        }
        print!("[");
        for a in to_print.iter() {
            print!("{a}, ")
        }
        println!("]");
        let id = self.network.get_id();
        if id == PartyID::ID2 {
            println!("==================");
        };
    }
}

impl<C: CurveGroup, N: Aby3Network> EcMpcProtocol<C> for RevAby3Protocol<C::ScalarField, N> {
    type PointShare = C;

    fn add_points(&mut self, a: &Self::PointShare, b: &Self::PointShare) -> Self::PointShare {
        *a + b
    }

    fn sub_points(&mut self, a: &Self::PointShare, b: &Self::PointShare) -> Self::PointShare {
        *a - b
    }

    fn add_assign_points(&mut self, a: &mut Self::PointShare, b: &Self::PointShare) {
        *a += b;
    }

    fn sub_assign_points(&mut self, a: &mut Self::PointShare, b: &Self::PointShare) {
        *a -= b;
    }

    fn add_assign_points_public(&mut self, a: &mut Self::PointShare, b: &C) {
        match self.network.get_id() {
            id::PartyID::ID0 => *a += b,
            id::PartyID::ID1 | id::PartyID::ID2 => {}
        }
    }

    fn sub_assign_points_public(&mut self, a: &mut Self::PointShare, b: &C) {
        match self.network.get_id() {
            id::PartyID::ID0 => *a -= b,
            id::PartyID::ID1 | id::PartyID::ID2 => {}
        }
    }

    fn add_assign_points_public_affine(&mut self, a: &mut Self::PointShare, b: &C::Affine) {
        match self.network.get_id() {
            id::PartyID::ID0 => *a += b,
            id::PartyID::ID1 | id::PartyID::ID2 => {}
        }
    }

    fn sub_assign_points_public_affine(&mut self, a: &mut Self::PointShare, b: &C::Affine) {
        match self.network.get_id() {
            id::PartyID::ID0 => *a -= b,
            id::PartyID::ID1 | id::PartyID::ID2 => {}
        }
    }

    fn scalar_mul_public_point(&mut self, a: &C, b: &Self::FieldShare) -> Self::PointShare {
        a.mul(b)
    }

    fn scalar_mul_public_scalar(
        &mut self,
        a: &Self::PointShare,
        b: &<C>::ScalarField,
    ) -> Self::PointShare {
        *a * b
    }

    fn scalar_mul(
        &mut self,
        a: &Self::PointShare,
        b: &Self::FieldShare,
    ) -> IoResult<Self::PointShare> {
        self.network.send_next(*a)?;
        self.network.send_next(*b)?;
        let their_a = self.network.recv_prev::<C>()?;
        let their_b = self.network.recv_prev::<C::ScalarField>()?;
        let res = *a * b + their_a * b + *a * their_b;
        Ok(res)
    }

    fn open_point(&mut self, a: &Self::PointShare) -> std::io::Result<C> {
        self.network.send_next(*a)?;
        self.network.send(self.network.get_id().prev_id(), *a)?;
        let b = self.network.recv_prev::<C>()?;
        let c = self.network.recv::<C>(self.network.get_id().next_id())?;
        Ok(c + b + a)
    }
}

impl<P: Pairing, N: Aby3Network> PairingEcMpcProtocol<P> for RevAby3Protocol<P::ScalarField, N> {
    fn open_two_points(
        &mut self,
        a: &<Self as EcMpcProtocol<P::G1>>::PointShare,
        b: &<Self as EcMpcProtocol<P::G2>>::PointShare,
    ) -> std::io::Result<(P::G1, P::G2)> {
        let s1 = *a;
        let s2 = *b;
        self.network.send_next((s1, s2))?;
        self.network
            .send(self.network.get_id().prev_id(), (s1, s2))?;
        let (mut a1, mut b1) = self.network.recv_prev::<(P::G1, P::G2)>()?;
        let (a2, b2) = self
            .network
            .recv::<(P::G1, P::G2)>(self.network.get_id().next_id())?;
        a1 += a2 + a;
        b1 += b2 + b;
        Ok((a1, b1))
    }
}

impl<F: PrimeField, N: Aby3Network> FFTProvider<F> for RevAby3Protocol<F, N> {
    fn fft<D: EvaluationDomain<F>>(
        &mut self,
        data: Self::FieldShareSlice<'_>,
        domain: &D,
    ) -> Self::FieldShareVec {
        domain.fft(data)
    }

    fn fft_in_place<D: EvaluationDomain<F>>(
        &mut self,
        data: &mut Self::FieldShareSliceMut<'_>,
        domain: &D,
    ) {
        domain.fft_in_place(data);
    }

    fn ifft<D: EvaluationDomain<F>>(
        &mut self,
        data: &Self::FieldShareSlice<'_>,
        domain: &D,
    ) -> Self::FieldShareVec {
        domain.ifft(data)
    }

    fn ifft_in_place<D: EvaluationDomain<F>>(
        &mut self,
        data: &mut Self::FieldShareSliceMut<'_>,
        domain: &D,
    ) {
        domain.ifft_in_place(data);
    }
}

impl<C: CurveGroup, N: Aby3Network> MSMProvider<C> for RevAby3Protocol<C::ScalarField, N> {
    fn msm_public_points(
        &mut self,
        points: &[C::Affine],
        scalars: Self::FieldShareSlice<'_>,
    ) -> Self::PointShare {
        debug_assert_eq!(points.len(), scalars.len());
        C::msm_unchecked(points, scalars)
    }
}
