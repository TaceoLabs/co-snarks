use self::{
    fieldshare::{
        GSZPrimeFieldShare, GSZPrimeFieldShareSlice, GSZPrimeFieldShareSliceMut,
        GSZPrimeFieldShareVec,
    },
    network::GSZNetwork,
    pointshare::GSZPointShare,
    shamir::Shamir,
};
use crate::traits::{
    EcMpcProtocol, FFTProvider, MSMProvider, PairingEcMpcProtocol, PrimeFieldMpcProtocol,
};
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use eyre::{bail, Report};
use itertools::izip;
use std::{marker::PhantomData, thread, time::Duration};

pub mod fieldshare;
pub mod network;
pub mod pointshare;
pub(crate) mod shamir;

pub mod utils {
    use self::{
        fieldshare::{GSZPrimeFieldShare, GSZPrimeFieldShareVec},
        pointshare::GSZPointShare,
        shamir::Shamir,
    };
    use super::*;
    use ark_ec::CurveGroup;
    use ark_ff::PrimeField;
    use eyre::bail;
    use itertools::izip;
    use rand::{CryptoRng, Rng};

    pub fn share_field_element<F: PrimeField, R: Rng + CryptoRng>(
        val: F,
        degree: usize,
        num_parties: usize,
        rng: &mut R,
    ) -> Vec<GSZPrimeFieldShare<F>> {
        let shares = Shamir::share(val, num_parties, degree, rng);

        GSZPrimeFieldShare::convert_vec_rev(shares)
    }

    pub fn combine_field_element<F: PrimeField>(
        shares: &[GSZPrimeFieldShare<F>],
        parties: &[usize],
        degree: usize,
    ) -> Result<F, Report> {
        if shares.len() != parties.len() {
            bail!(
                "Number of shares ({}) does not match number of party indices ({})",
                shares.len(),
                parties.len()
            );
        }
        if shares.len() <= degree {
            bail!(
                "Not enough shares to reconstruct the secret. Expected {}, got {}",
                degree + 1,
                shares.len()
            );
        }

        let lagrange = Shamir::lagrange_from_coeff(&parties[..=degree]);
        let shares = GSZPrimeFieldShare::convert_slice(shares);
        let rec = Shamir::reconstruct(&shares[..=degree], &lagrange);

        Ok(rec)
    }

    pub fn share_field_elements<F: PrimeField, R: Rng + CryptoRng>(
        vals: Vec<F>,
        degree: usize,
        num_parties: usize,
        rng: &mut R,
    ) -> Vec<GSZPrimeFieldShareVec<F>> {
        let mut result = (0..num_parties)
            .map(|_| GSZPrimeFieldShareVec::new(Vec::with_capacity(vals.len())))
            .collect::<Vec<_>>();

        for val in vals {
            let shares = Shamir::share(val, num_parties, degree, rng);

            for (r, s) in izip!(&mut result, shares) {
                r.a.push(s);
            }
        }

        result
    }

    pub fn combine_field_elements<F: PrimeField>(
        shares: &[GSZPrimeFieldShareVec<F>],
        parties: &[usize],
        degree: usize,
    ) -> Result<Vec<F>, Report> {
        if shares.len() != parties.len() {
            bail!(
                "Number of shares ({}) does not match number of party indices ({})",
                shares.len(),
                parties.len()
            );
        }
        if shares.len() <= degree {
            bail!(
                "Not enough shares to reconstruct the secret. Expected {}, got {}",
                degree + 1,
                shares.len()
            );
        }

        let num_vals = shares[0].len();
        for share in shares.iter().skip(1) {
            if share.len() != num_vals {
                bail!(
                    "Number of shares ({}) does not match number of shares in first party ({})",
                    share.len(),
                    num_vals
                );
            }
        }
        let mut result = Vec::with_capacity(num_vals);

        let lagrange = Shamir::lagrange_from_coeff(&parties[..=degree]);

        for i in 0..num_vals {
            let s = shares
                .iter()
                .take(degree + 1)
                .map(|s| s.a[i])
                .collect::<Vec<_>>();
            let rec = Shamir::reconstruct(&s, &lagrange);
            result.push(rec);
        }
        Ok(result)
    }

    pub fn share_curve_point<C: CurveGroup, R: Rng + CryptoRng>(
        val: C,
        degree: usize,
        num_parties: usize,
        rng: &mut R,
    ) -> Vec<GSZPointShare<C>> {
        let shares = Shamir::share_point(val, num_parties, degree, rng);

        GSZPointShare::convert_vec_rev(shares)
    }

    pub fn combine_curve_point<C: CurveGroup>(
        shares: &[GSZPointShare<C>],
        parties: &[usize],
        degree: usize,
    ) -> Result<C, Report> {
        if shares.len() != parties.len() {
            bail!(
                "Number of shares ({}) does not match number of party indices ({})",
                shares.len(),
                parties.len()
            );
        }
        if shares.len() <= degree {
            bail!(
                "Not enough shares to reconstruct the secret. Expected {}, got {}",
                degree + 1,
                shares.len()
            );
        }

        let lagrange = Shamir::lagrange_from_coeff(&parties[..=degree]);
        let shares = GSZPointShare::convert_slice(shares);
        let rec = Shamir::reconstruct_point(&shares[..=degree], &lagrange);

        Ok(rec)
    }
}

pub struct GSZProtocol<F: PrimeField, N: GSZNetwork> {
    threshold: usize, // degree of the polynomial
    lagrange_t: Vec<F>,
    lagrange_2t: Vec<F>,
    network: N,
    field: PhantomData<F>,
}

impl<F: PrimeField, N: GSZNetwork> GSZProtocol<F, N> {
    pub fn new(threshold: usize, network: N) -> Result<Self, Report> {
        let num_parties = network.get_num_parties();

        if 2 * threshold + 1 > num_parties {
            bail!("Threshold too large for number of parties")
        }

        let lagrange_t = Shamir::lagrange_from_coeff(&(0..=threshold).collect::<Vec<_>>());
        let lagrange_2t = Shamir::lagrange_from_coeff(&(0..=2 * threshold).collect::<Vec<_>>());

        Ok(Self {
            threshold,
            lagrange_t,
            lagrange_2t,
            network,
            field: PhantomData,
        })
    }

    // multiply followed by a opening, thus, no reshare required
    pub fn mul_open(
        &mut self,
        a: &<Self as PrimeFieldMpcProtocol<F>>::FieldShare,
        b: &<Self as PrimeFieldMpcProtocol<F>>::FieldShare,
    ) -> std::io::Result<F> {
        // TODO only receive enough?
        let mul = a * b;
        let rcv = self.network.broadcast(mul.a)?;
        let res = Shamir::reconstruct(&rcv[..=2 * self.threshold], &self.lagrange_2t);
        Ok(res)
    }
}

impl<F: PrimeField, N: GSZNetwork> PrimeFieldMpcProtocol<F> for GSZProtocol<F, N> {
    type FieldShare = GSZPrimeFieldShare<F>;
    type FieldShareSlice<'a> = GSZPrimeFieldShareSlice<'a, F>;
    type FieldShareSliceMut<'a> = GSZPrimeFieldShareSliceMut<'a, F>;
    type FieldShareVec = GSZPrimeFieldShareVec<F>;

    fn add(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare {
        a + b
    }

    fn sub(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare {
        a - b
    }

    fn add_with_public(&mut self, a: &F, b: &Self::FieldShare) -> Self::FieldShare {
        b + a
    }

    fn sub_assign_vec(
        &mut self,
        a: &mut Self::FieldShareSliceMut<'_>,
        b: &Self::FieldShareSlice<'_>,
    ) {
        for (a, b) in izip!(a.a.iter_mut(), b.a) {
            *a -= b;
        }
    }

    fn mul(
        &mut self,
        a: &Self::FieldShare,
        b: &Self::FieldShare,
    ) -> std::io::Result<Self::FieldShare> {
        let mul = a * b;
        todo!()
    }

    fn mul_with_public(&mut self, a: &F, b: &Self::FieldShare) -> Self::FieldShare {
        b * a
    }

    fn inv(&mut self, a: &Self::FieldShare) -> std::io::Result<Self::FieldShare> {
        let r = self.rand();
        let y = self.mul_open(a, &r)?;
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

    fn rand(&mut self) -> Self::FieldShare {
        todo!()
    }

    fn open(&mut self, a: &Self::FieldShare) -> std::io::Result<F> {
        // TODO only receive enough?
        let rcv = self.network.broadcast(a.a)?;
        let res = Shamir::reconstruct(&rcv[..=self.threshold], &self.lagrange_t);
        Ok(res)
    }

    fn mul_vec(
        &mut self,
        a: &Self::FieldShareSlice<'_>,
        b: &Self::FieldShareSlice<'_>,
    ) -> std::io::Result<Self::FieldShareVec> {
        todo!()
    }

    fn promote_to_trivial_share(&self, public_values: &[F]) -> Self::FieldShareVec {
        let shares = public_values.to_owned();
        Self::FieldShareVec::new(shares)
    }

    fn distribute_powers_and_mul_by_const(
        &mut self,
        coeffs: &mut Self::FieldShareSliceMut<'_>,
        g: F,
        c: F,
    ) {
        let mut pow = c;
        for a in coeffs.a.iter_mut() {
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
        let mut acc = GSZPrimeFieldShare::default();
        for (coeff, index) in lhs {
            if index < &public_inputs.len() {
                let val = public_inputs[*index];
                let mul_result = val * coeff;
                acc = self.add_with_public(&mul_result, &acc);
            } else {
                acc.a += *coeff * private_witness.a[*index - public_inputs.len()];
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
        assert!(src.a.len() >= src_offset + len);
        assert!(len > 0);
        dst.a[dst_offset..dst_offset + len].clone_from_slice(&src.a[src_offset..src_offset + len]);
    }

    fn print(&self, to_print: &Self::FieldShareVec) {
        thread::sleep(Duration::from_millis(
            200 * self.network.get_id() as u64 + 100,
        ));
        print!("[");
        for a in to_print.a.iter() {
            print!("{a}, ")
        }
        println!("]");
    }

    fn print_slice(&self, to_print: &Self::FieldShareSlice<'_>) {
        let my_id = self.network.get_id();
        if my_id == 0 {
            println!("==================");
        }
        thread::sleep(Duration::from_millis(200 * my_id as u64 + 100));
        print!("[");
        for a in to_print.a.iter() {
            print!("{a}, ")
        }
        println!("]");
        if my_id == self.network.get_num_parties() - 1 {
            println!("==================");
        };
    }
}

impl<C: CurveGroup, N: GSZNetwork> EcMpcProtocol<C> for GSZProtocol<C::ScalarField, N> {
    type PointShare = GSZPointShare<C>;

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
        a.a += b
    }

    fn sub_assign_points_public(&mut self, a: &mut Self::PointShare, b: &C) {
        a.a -= b
    }

    fn add_assign_points_public_affine(
        &mut self,
        a: &mut Self::PointShare,
        b: &<C as CurveGroup>::Affine,
    ) {
        a.a += b
    }

    fn sub_assign_points_public_affine(
        &mut self,
        a: &mut Self::PointShare,
        b: &<C as CurveGroup>::Affine,
    ) {
        a.a -= b
    }

    fn scalar_mul_public_point(&mut self, a: &C, b: &Self::FieldShare) -> Self::PointShare {
        Self::PointShare { a: a.mul(b.a) }
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
    ) -> std::io::Result<Self::PointShare> {
        // Use the randomness and just mul it onto the generator if required
        todo!()
    }

    fn open_point(&mut self, a: &Self::PointShare) -> std::io::Result<C> {
        // TODO only receive enough?
        let rcv = self.network.broadcast(a.a)?;
        let res = Shamir::reconstruct_point(&rcv[..=self.threshold], &self.lagrange_t);
        Ok(res)
    }
}

impl<P: Pairing, N: GSZNetwork> PairingEcMpcProtocol<P> for GSZProtocol<P::ScalarField, N> {
    fn open_two_points(
        &mut self,
        a: &<Self as EcMpcProtocol<P::G1>>::PointShare,
        b: &<Self as EcMpcProtocol<P::G2>>::PointShare,
    ) -> std::io::Result<(P::G1, P::G2)> {
        let s1 = a.a;
        let s2 = b.a;

        // TODO maybe better broadcast function
        let rcv: Vec<(P::G1, P::G2)> = self.network.broadcast((s1, s2))?;
        let (r1, r2): (Vec<P::G1>, Vec<P::G2>) = rcv.into_iter().unzip();

        let r1 = Shamir::reconstruct_point(&r1[..=self.threshold], &self.lagrange_t);
        let r2 = Shamir::reconstruct_point(&r2[..=self.threshold], &self.lagrange_t);

        Ok((r1, r2))
    }
}

impl<F: PrimeField, N: GSZNetwork> FFTProvider<F> for GSZProtocol<F, N> {
    fn fft<D: EvaluationDomain<F>>(
        &mut self,
        data: Self::FieldShareSlice<'_>,
        domain: &D,
    ) -> Self::FieldShareVec {
        let a = domain.fft(data.a);
        Self::FieldShareVec::new(a)
    }

    fn fft_in_place<D: EvaluationDomain<F>>(
        &mut self,
        data: &mut Self::FieldShareSliceMut<'_>,
        domain: &D,
    ) {
        domain.fft_in_place(data.a);
    }

    fn ifft<D: EvaluationDomain<F>>(
        &mut self,
        data: &Self::FieldShareSlice<'_>,
        domain: &D,
    ) -> Self::FieldShareVec {
        let a = domain.ifft(data.a);
        Self::FieldShareVec::new(a)
    }

    fn ifft_in_place<D: EvaluationDomain<F>>(
        &mut self,
        data: &mut Self::FieldShareSliceMut<'_>,
        domain: &D,
    ) {
        domain.ifft_in_place(data.a);
    }
}

impl<C: CurveGroup, N: GSZNetwork> MSMProvider<C> for GSZProtocol<C::ScalarField, N> {
    fn msm_public_points(
        &mut self,
        points: &[C::Affine],
        scalars: Self::FieldShareSlice<'_>,
    ) -> Self::PointShare {
        debug_assert_eq!(points.len(), scalars.len());
        let res = C::msm_unchecked(points, scalars.a);
        Self::PointShare { a: res }
    }
}
