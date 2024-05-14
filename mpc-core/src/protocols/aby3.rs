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
pub use fieldshare::Aby3PrimeFieldShare;

use self::{
    fieldshare::{Aby3PrimeFieldShareSlice, Aby3PrimeFieldShareSliceMut, Aby3PrimeFieldShareVec},
    id::PartyID,
    network::Aby3Network,
    pointshare::Aby3PointShare,
};

pub mod fieldshare;
pub mod id;
pub mod network;
pub mod pointshare;

type IoResult<T> = std::io::Result<T>;

pub mod utils {
    use ark_ec::CurveGroup;
    use ark_ff::PrimeField;
    use rand::{CryptoRng, Rng};

    use super::{
        fieldshare::Aby3PrimeFieldShareVec, pointshare::Aby3PointShare, Aby3PrimeFieldShare,
    };

    pub fn share_field_element<F: PrimeField, R: Rng + CryptoRng>(
        val: F,
        rng: &mut R,
    ) -> [Aby3PrimeFieldShare<F>; 3] {
        let a = F::rand(rng);
        let b = F::rand(rng);
        let c = val - a - b;
        let share1 = Aby3PrimeFieldShare::new(a, c);
        let share2 = Aby3PrimeFieldShare::new(b, a);
        let share3 = Aby3PrimeFieldShare::new(c, b);
        [share1, share2, share3]
    }

    pub fn combine_field_element<F: PrimeField>(
        share1: Aby3PrimeFieldShare<F>,
        share2: Aby3PrimeFieldShare<F>,
        share3: Aby3PrimeFieldShare<F>,
    ) -> F {
        share1.a + share2.a + share3.a
    }

    pub fn share_field_elements<F: PrimeField, R: Rng + CryptoRng>(
        vals: Vec<F>,
        rng: &mut R,
    ) -> [Aby3PrimeFieldShareVec<F>; 3] {
        let mut shares1a = Vec::with_capacity(vals.len());
        let mut shares1b = Vec::with_capacity(vals.len());
        let mut shares2a = Vec::with_capacity(vals.len());
        let mut shares2b = Vec::with_capacity(vals.len());
        let mut shares3a = Vec::with_capacity(vals.len());
        let mut shares3b = Vec::with_capacity(vals.len());
        for val in vals {
            let a = F::rand(rng);
            let b = F::rand(rng);
            let c = val - a - b;
            shares1a.push(a);
            shares1b.push(c);
            shares2a.push(b);
            shares2b.push(a);
            shares3a.push(c);
            shares3b.push(b);
        }
        [
            Aby3PrimeFieldShareVec::new(shares1a, shares1b),
            Aby3PrimeFieldShareVec::new(shares2a, shares2b),
            Aby3PrimeFieldShareVec::new(shares3a, shares3b),
        ]
    }

    pub fn combine_field_elements<F: PrimeField>(
        share1: Aby3PrimeFieldShareVec<F>,
        share2: Aby3PrimeFieldShareVec<F>,
        share3: Aby3PrimeFieldShareVec<F>,
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

    pub fn share_curve_point<C: CurveGroup, R: Rng + CryptoRng>(
        val: C,
        rng: &mut R,
    ) -> [Aby3PointShare<C>; 3] {
        let a = C::rand(rng);
        let b = C::rand(rng);
        let c = val - a - b;
        let share1 = Aby3PointShare::new(a, c);
        let share2 = Aby3PointShare::new(b, a);
        let share3 = Aby3PointShare::new(c, b);
        [share1, share2, share3]
    }

    pub fn combine_curve_point<C: CurveGroup>(
        share1: Aby3PointShare<C>,
        share2: Aby3PointShare<C>,
        share3: Aby3PointShare<C>,
    ) -> C {
        share1.a + share2.a + share3.a
    }
}

pub struct Aby3Protocol<F: PrimeField, N: Aby3Network> {
    rngs: Aby3CorrelatedRng,
    network: N,
    field: PhantomData<F>,
}

impl<F: PrimeField, N: Aby3Network> Aby3Protocol<F, N> {
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

impl<F: PrimeField, N: Aby3Network> PrimeFieldMpcProtocol<F> for Aby3Protocol<F, N> {
    type FieldShare = Aby3PrimeFieldShare<F>;
    type FieldShareSlice<'a> = Aby3PrimeFieldShareSlice<'a, F>;
    type FieldShareSliceMut<'a> = Aby3PrimeFieldShareSliceMut<'a, F>;
    type FieldShareVec = Aby3PrimeFieldShareVec<F>;

    fn add(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare {
        a + b
    }

    fn sub(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare {
        a - b
    }

    fn mul(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> IoResult<Self::FieldShare> {
        let local_a = a * b + self.rngs.masking_field_element::<F>();
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
                "Cannot invert zero",
            ));
        }
        let y_inv = y.inverse().unwrap();
        Ok(r * y_inv)
    }

    fn neg(&mut self, a: &Self::FieldShare) -> Self::FieldShare {
        -a
    }

    fn rand(&mut self) -> std::io::Result<Self::FieldShare> {
        let (a, b) = self.rngs.random_fes();
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

    fn promote_to_trivial_share(&self, public_values: &[F]) -> Self::FieldShareVec {
        let mut vec = Vec::with_capacity(public_values.len());
        //additive share1 gets the value everyone else zero
        //therefore id1 and id2 needs the share
        for val in public_values {
            let share = match self.network.get_id() {
                PartyID::ID0 => Aby3PrimeFieldShare::new(*val, F::zero()),
                PartyID::ID1 => Aby3PrimeFieldShare::new(F::zero(), *val),
                PartyID::ID2 => Aby3PrimeFieldShare::default(),
            };
            vec.push(share);
        }
        Self::FieldShareVec::from(vec)
    }

    fn mul_vec(
        &mut self,
        a: &Self::FieldShareSlice<'_>,
        b: &Self::FieldShareSlice<'_>,
    ) -> std::io::Result<Self::FieldShareVec> {
        debug_assert_eq!(a.len(), b.len());
        let local_a = izip!(a.a.iter(), a.b.iter(), b.a.iter(), b.b.iter())
            .map(|(aa, ab, ba, bb)| {
                *aa * ba + *aa * bb + *ab * ba + self.rngs.masking_field_element::<F>()
            })
            .collect_vec();
        self.network.send_next_many(&local_a)?;
        let local_b = self.network.recv_prev_many()?;
        if local_b.len() != local_a.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid number of elements received",
            ));
        }
        Ok(Self::FieldShareVec::new(local_a, local_b))
    }

    fn sub_assign_vec(
        &mut self,
        a: &mut Self::FieldShareSliceMut<'_>,
        b: &Self::FieldShareSlice<'_>,
    ) {
        for (a, b) in izip!(a.a.iter_mut(), b.a) {
            *a -= b;
        }
        for (a, b) in izip!(a.b.iter_mut(), b.b) {
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
        private_witness: &Self::FieldShareSlice<'_>,
    ) -> Self::FieldShare {
        let mut acc = Aby3PrimeFieldShare::default();
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
        dst: &mut Self::FieldShareSliceMut<'_>,
        src: &Self::FieldShareSlice<'_>,
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
        for a in to_print.a.iter() {
            print!("{a}, ")
        }
        println!("]");
        let id = self.network.get_id();
        if id == PartyID::ID2 {
            println!("==================");
        };
    }
}

impl<F: PrimeField> Default for Aby3PrimeFieldShare<F> {
    fn default() -> Self {
        Self {
            a: F::zero(),
            b: F::zero(),
        }
    }
}

impl<C: CurveGroup, N: Aby3Network> EcMpcProtocol<C> for Aby3Protocol<C::ScalarField, N> {
    type PointShare = Aby3PointShare<C>;

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
        let local_a = b * a + self.rngs.masking_ec_element::<C>();
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

impl<P: Pairing, N: Aby3Network> PairingEcMpcProtocol<P> for Aby3Protocol<P::ScalarField, N> {
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

impl<F: PrimeField, N: Aby3Network> FFTProvider<F> for Aby3Protocol<F, N> {
    fn fft<D: EvaluationDomain<F>>(
        &mut self,
        data: Self::FieldShareSlice<'_>,
        domain: &D,
    ) -> Self::FieldShareVec {
        let a = domain.fft(data.a);
        let b = domain.fft(data.b);
        Self::FieldShareVec::new(a, b)
    }

    fn fft_in_place<D: EvaluationDomain<F>>(
        &mut self,
        data: &mut Self::FieldShareSliceMut<'_>,
        domain: &D,
    ) {
        domain.fft_in_place(data.a);
        domain.fft_in_place(data.b);
    }

    fn ifft<D: EvaluationDomain<F>>(
        &mut self,
        data: &Self::FieldShareSlice<'_>,
        domain: &D,
    ) -> Self::FieldShareVec {
        let a = domain.ifft(data.a);
        let b = domain.ifft(data.b);
        Self::FieldShareVec::new(a, b)
    }

    fn ifft_in_place<D: EvaluationDomain<F>>(
        &mut self,
        data: &mut Self::FieldShareSliceMut<'_>,
        domain: &D,
    ) {
        domain.ifft_in_place(data.a);
        domain.ifft_in_place(data.b);
    }
}

struct Aby3CorrelatedRng {
    rng1: RngType,
    rng2: RngType,
}

impl Aby3CorrelatedRng {
    pub fn new(seed1: [u8; crate::SEED_SIZE], seed2: [u8; crate::SEED_SIZE]) -> Self {
        let rng1 = RngType::from_seed(seed1);
        let rng2 = RngType::from_seed(seed2);
        Self { rng1, rng2 }
    }

    pub fn masking_field_element<F: PrimeField>(&mut self) -> F {
        let (a, b) = self.random_fes::<F>();
        a - b
    }

    pub fn random_fes<F: PrimeField>(&mut self) -> (F, F) {
        let a = F::rand(&mut self.rng1);
        let b = F::rand(&mut self.rng2);
        (a, b)
    }

    pub fn masking_ec_element<C: CurveGroup>(&mut self) -> C {
        let (a, b) = self.random_ecs::<C>();
        a - b
    }

    pub fn random_ecs<C: CurveGroup>(&mut self) -> (C, C) {
        let a = C::rand(&mut self.rng1);
        let b = C::rand(&mut self.rng2);
        (a, b)
    }
}

impl<C: CurveGroup, N: Aby3Network> MSMProvider<C> for Aby3Protocol<C::ScalarField, N> {
    fn msm_public_points(
        &mut self,
        points: &[C::Affine],
        scalars: Self::FieldShareSlice<'_>,
    ) -> Self::PointShare {
        debug_assert_eq!(points.len(), scalars.len());
        let res_a = C::msm_unchecked(points, scalars.a);
        let res_b = C::msm_unchecked(points, scalars.b);
        Self::PointShare { a: res_a, b: res_b }
    }
}
