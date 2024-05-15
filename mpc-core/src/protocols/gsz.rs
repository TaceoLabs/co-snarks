use self::{
    fieldshare::{
        GSZPrimeFieldShare, GSZPrimeFieldShareSlice, GSZPrimeFieldShareSliceMut,
        GSZPrimeFieldShareVec,
    },
    network::GSZNetwork,
    pointshare::GSZPointShare,
    shamir::Shamir,
};
use crate::{
    traits::{
        EcMpcProtocol, FFTProvider, MSMProvider, PairingEcMpcProtocol, PrimeFieldMpcProtocol,
    },
    RngType,
};
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use eyre::{bail, Report};
use itertools::{izip, Itertools};
use rand::{Rng as _, SeedableRng};
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
        coeffs: &[usize],
        degree: usize,
    ) -> Result<F, Report> {
        if shares.len() != coeffs.len() {
            bail!(
                "Number of shares ({}) does not match number of party indices ({})",
                shares.len(),
                coeffs.len()
            );
        }
        if shares.len() <= degree {
            bail!(
                "Not enough shares to reconstruct the secret. Expected {}, got {}",
                degree + 1,
                shares.len()
            );
        }

        let lagrange = Shamir::lagrange_from_coeff(&coeffs[..=degree]);
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
        coeffs: &[usize],
        degree: usize,
    ) -> Result<Vec<F>, Report> {
        if shares.len() != coeffs.len() {
            bail!(
                "Number of shares ({}) does not match number of party indices ({})",
                shares.len(),
                coeffs.len()
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

        let lagrange = Shamir::lagrange_from_coeff(&coeffs[..=degree]);

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
        coeffs: &[usize],
        degree: usize,
    ) -> Result<C, Report> {
        if shares.len() != coeffs.len() {
            bail!(
                "Number of shares ({}) does not match number of party indices ({})",
                shares.len(),
                coeffs.len()
            );
        }
        if shares.len() <= degree {
            bail!(
                "Not enough shares to reconstruct the secret. Expected {}, got {}",
                degree + 1,
                shares.len()
            );
        }

        let lagrange = Shamir::lagrange_from_coeff(&coeffs[..=degree]);
        let shares = GSZPointShare::convert_slice(shares);
        let rec = Shamir::reconstruct_point(&shares[..=degree], &lagrange);

        Ok(rec)
    }
}

pub struct GSZProtocol<F: PrimeField, N: GSZNetwork> {
    threshold: usize, // degree of the polynomial
    open_lagrange_t: Vec<F>,
    open_lagrange_2t: Vec<F>,
    mul_lagrange_2t: Vec<F>,
    rng_buffer: GSZRng<F>,
    network: N,
    field: PhantomData<F>,
}

impl<F: PrimeField, N: GSZNetwork> GSZProtocol<F, N> {
    const KING_ID: usize = 0;

    pub fn new(threshold: usize, network: N) -> Result<Self, Report> {
        let num_parties = network.get_num_parties();

        if 2 * threshold + 1 > num_parties {
            bail!("Threshold too large for number of parties")
        }

        let seed: [u8; crate::SEED_SIZE] = RngType::from_entropy().gen();

        // We send in circles, so we need to receive from the last parties
        let id = network.get_id();
        let open_lagrange_t = Shamir::lagrange_from_coeff(
            &(1..=threshold + 1)
                .map(|i| (id + num_parties - i) % num_parties + 1)
                .collect::<Vec<_>>(),
        );
        let open_lagrange_2t = Shamir::lagrange_from_coeff(
            &(1..=2 * threshold + 1)
                .map(|i| (id + num_parties - i) % num_parties + 1)
                .collect::<Vec<_>>(),
        );

        let mul_lagrange_2t =
            Shamir::lagrange_from_coeff(&(1..=2 * threshold + 1).collect::<Vec<_>>());

        Ok(Self {
            threshold,
            open_lagrange_t,
            open_lagrange_2t,
            mul_lagrange_2t,
            rng_buffer: GSZRng::new(seed, threshold, num_parties),
            network,
            field: PhantomData,
        })
    }

    // Generates amount * (self.threshold + 1) random double shares
    pub fn preprocess(&mut self, amount: usize) -> std::io::Result<()> {
        self.rng_buffer.buffer_triples(&mut self.network, amount)
    }

    // multiply followed by a opening, thus, no reshare required
    pub fn mul_open(
        &mut self,
        a: &<Self as PrimeFieldMpcProtocol<F>>::FieldShare,
        b: &<Self as PrimeFieldMpcProtocol<F>>::FieldShare,
    ) -> std::io::Result<F> {
        let mul = a * b;
        let rcv = self.network.broadcast_next(mul.a, 2 * self.threshold + 1)?;
        let res = Shamir::reconstruct(&rcv, &self.open_lagrange_2t);
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
        let (r_t, r_2t) = self.rng_buffer.get_pair(&mut self.network)?;

        let mul = a.a * b.a + r_2t;

        let my_id = self.network.get_id();
        let my_share = if my_id == Self::KING_ID {
            // Accumulate the result
            let mut acc = F::zero();
            for (other_id, lagrange) in self.mul_lagrange_2t.iter().enumerate() {
                if other_id == Self::KING_ID {
                    acc += mul * lagrange;
                } else {
                    let r = self.network.recv::<F>(other_id)?;
                    acc += r * lagrange;
                }
            }
            // So far parties who do not require sending, do not send, so no receive here

            // Send fresh shares
            let shares = Shamir::share(
                acc,
                self.network.get_num_parties(),
                self.threshold,
                &mut self.rng_buffer.rng,
            );
            let mut my_share = F::default();
            for (other_id, share) in shares.into_iter().enumerate() {
                if my_id == other_id {
                    my_share = share;
                } else {
                    self.network.send(other_id, share)?;
                }
            }
            my_share
        } else {
            if my_id <= self.threshold * 2 {
                // Only send if my items are required
                self.network.send(Self::KING_ID, mul)?;
            }
            self.network.recv(Self::KING_ID)?
        };

        Ok(Self::FieldShare::new(my_share - r_t))
    }

    fn mul_with_public(&mut self, a: &F, b: &Self::FieldShare) -> Self::FieldShare {
        b * a
    }

    fn inv(&mut self, a: &Self::FieldShare) -> std::io::Result<Self::FieldShare> {
        let r = self.rand()?;
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

    fn rand(&mut self) -> std::io::Result<Self::FieldShare> {
        let (r, _) = self.rng_buffer.get_pair(&mut self.network)?;
        Ok(Self::FieldShare::new(r))
    }

    fn open(&mut self, a: &Self::FieldShare) -> std::io::Result<F> {
        let rcv = self.network.broadcast_next(a.a, self.threshold + 1)?;
        let res = Shamir::reconstruct(&rcv, &self.open_lagrange_t);
        Ok(res)
    }

    fn mul_vec(
        &mut self,
        a: &Self::FieldShareSlice<'_>,
        b: &Self::FieldShareSlice<'_>,
    ) -> std::io::Result<Self::FieldShareVec> {
        let len = a.len();
        debug_assert_eq!(len, b.len());
        let mut r_ts = Vec::with_capacity(len);
        let mut muls = Vec::with_capacity(len);

        for (a, b) in izip!(a.a.iter(), b.a.iter()) {
            let (r_t, r_2t) = self.rng_buffer.get_pair(&mut self.network)?;
            let mul = *a * b + r_2t;
            muls.push(mul);
            r_ts.push(r_t);
        }
        let my_id = self.network.get_id();
        let mut my_shares = if my_id == Self::KING_ID {
            // Accumulate the result
            let mut acc = vec![F::zero(); len];
            for (other_id, lagrange) in self.mul_lagrange_2t.iter().enumerate() {
                if other_id == Self::KING_ID {
                    for (acc, muls) in izip!(&mut acc, &muls) {
                        *acc += *muls * lagrange;
                    }
                } else {
                    let r = self.network.recv_many::<F>(other_id)?;
                    if r.len() != len {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Invalid number of elements received",
                        ));
                    }
                    for (acc, muls) in izip!(&mut acc, r) {
                        *acc += muls * lagrange;
                    }
                }
            }
            // So far parties who do not require sending, do not send, so no receive here

            // Send fresh shares
            let mut shares = (0..self.network.get_num_parties())
                .map(|_| Vec::with_capacity(len))
                .collect::<Vec<_>>();

            for acc in acc {
                let s = Shamir::share(
                    acc,
                    self.network.get_num_parties(),
                    self.threshold,
                    &mut self.rng_buffer.rng,
                );
                for (des, src) in izip!(&mut shares, s) {
                    des.push(src);
                }
            }

            let mut my_share = Vec::new();
            for (other_id, share) in shares.into_iter().enumerate() {
                if my_id == other_id {
                    my_share = share;
                } else {
                    self.network.send_many(other_id, &share)?;
                }
            }
            my_share
        } else {
            if my_id <= self.threshold * 2 {
                // Only send if my items are required
                self.network.send_many(Self::KING_ID, &muls)?;
            }
            let r = self.network.recv_many::<F>(Self::KING_ID)?;
            if r.len() != len {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid number of elements received",
                ));
            }
            r
        };

        for (share, r) in izip!(&mut my_shares, r_ts) {
            *share -= r;
        }
        Ok(Self::FieldShareVec::new(my_shares))
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
        let (r_t, r_2t) = self.rng_buffer.get_pair(&mut self.network)?;
        let r_t = C::generator().mul(r_t);
        let r_2t = C::generator().mul(r_2t);

        let mul = (b * a).a + r_2t;
        let my_id = self.network.get_id();

        let my_share = if my_id == Self::KING_ID {
            // Accumulate the result
            let mut acc = C::zero();
            for (other_id, lagrange) in self.mul_lagrange_2t.iter().enumerate() {
                if other_id == Self::KING_ID {
                    acc += mul * lagrange;
                } else {
                    let r = self.network.recv::<C>(other_id)?;
                    acc += r * lagrange;
                }
            }
            // So far parties who do not require sending, do not send, so no receive here

            // Send fresh shares
            let shares = Shamir::share_point(
                acc,
                self.network.get_num_parties(),
                self.threshold,
                &mut self.rng_buffer.rng,
            );
            let mut my_share = C::default();
            for (other_id, share) in shares.into_iter().enumerate() {
                if my_id == other_id {
                    my_share = share;
                } else {
                    self.network.send(other_id, share)?;
                }
            }
            my_share
        } else {
            if my_id <= self.threshold * 2 {
                // Only send if my items are required
                self.network.send(Self::KING_ID, mul)?;
            }
            self.network.recv(Self::KING_ID)?
        };

        Ok(Self::PointShare::new(my_share - r_t))
    }

    fn open_point(&mut self, a: &Self::PointShare) -> std::io::Result<C> {
        let rcv = self.network.broadcast_next(a.a, self.threshold + 1)?;
        let res = Shamir::reconstruct_point(&rcv, &self.open_lagrange_t);
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

        let rcv: Vec<(P::G1, P::G2)> = self.network.broadcast_next((s1, s2), self.threshold + 1)?;
        let (r1, r2): (Vec<P::G1>, Vec<P::G2>) = rcv.into_iter().unzip();

        let r1 = Shamir::reconstruct_point(&r1, &self.open_lagrange_t);
        let r2 = Shamir::reconstruct_point(&r2, &self.open_lagrange_t);

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

struct GSZRng<F> {
    rng: RngType,
    threshold: usize,
    num_parties: usize,
    r_t: Vec<F>,
    r_2t: Vec<F>,
    remaining: usize,
}

impl<F: PrimeField> GSZRng<F> {
    const BATCH_SIZE: usize = 1024;

    pub fn new(seed: [u8; crate::SEED_SIZE], threshold: usize, num_parties: usize) -> Self {
        let r_t = Vec::with_capacity(Self::BATCH_SIZE * (threshold + 1));
        let r_2t = Vec::with_capacity(Self::BATCH_SIZE * (threshold + 1));
        Self {
            rng: RngType::from_seed(seed),
            threshold,
            num_parties,
            r_t,
            r_2t,
            remaining: 0,
        }
    }

    // I use the following matrix:
    // [1, 1  , 1  , 1  , ..., 1  ]
    // [1, 2  , 3  , 4  , ..., n  ]
    // [1, 2^2, 3^2, 4^2, ..., n^2]
    // ...
    // [1, 2^t, 3^t, 4^t, ..., n^t]
    fn vandermonde_mul(inputs: &[F], res: &mut [F], num_parties: usize, threshold: usize) {
        debug_assert_eq!(inputs.len(), num_parties);
        debug_assert_eq!(res.len(), threshold + 1);

        let row = (1..=num_parties as u64).map(F::from).collect::<Vec<_>>();
        let mut current_row = row.clone();

        res[0] = inputs.iter().sum();

        for ri in res.iter_mut().skip(1) {
            *ri = F::zero();
            for (c, r, i) in izip!(&mut current_row, &row, inputs) {
                *ri += *c * i;
                *c *= r; // Update current_row
            }
        }
    }

    // Generates amount * (self.threshold + 1) random double shares
    fn buffer_triples<N: GSZNetwork>(
        &mut self,
        network: &mut N,
        amount: usize,
    ) -> std::io::Result<()> {
        debug_assert_eq!(self.remaining, self.r_t.len());
        debug_assert_eq!(self.remaining, self.r_2t.len());

        let rand = (0..amount)
            .map(|_| F::rand(&mut self.rng))
            .collect::<Vec<_>>();

        let mut send = (0..self.num_parties)
            .map(|_| Vec::with_capacity(amount * 2))
            .collect::<Vec<_>>();

        for r in rand {
            let shares_t = Shamir::share(r, self.num_parties, self.threshold, &mut self.rng);
            let shares_2t = Shamir::share(r, self.num_parties, 2 * self.threshold, &mut self.rng);

            for (des, src1, src2) in izip!(&mut send, shares_t, shares_2t) {
                des.push(src1);
                des.push(src2);
            }
        }

        let my_id = network.get_id();
        let mut my_send = Vec::new();
        // Send
        for (other_id, shares) in send.into_iter().enumerate() {
            if my_id == other_id {
                my_send = shares;
            } else {
                network.send_many(other_id, &shares)?;
            }
        }
        // Receive
        let mut rcv_rt = (0..amount)
            .map(|_| Vec::with_capacity(self.num_parties))
            .collect_vec();
        let mut rcv_r2t = (0..amount)
            .map(|_| Vec::with_capacity(self.num_parties))
            .collect_vec();

        for other_id in 0..self.num_parties {
            if my_id == other_id {
                for (des_r, des_r2, src) in
                    izip!(&mut rcv_rt, &mut rcv_r2t, my_send.chunks_exact(2))
                {
                    des_r.push(src[0]);
                    des_r2.push(src[1]);
                }
            } else {
                let r = network.recv_many::<F>(other_id)?;
                if r.len() != 2 * amount {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid number of elements received",
                    ));
                }
                for (des_r, des_r2, src) in izip!(&mut rcv_rt, &mut rcv_r2t, r.chunks_exact(2)) {
                    des_r.push(src[0]);
                    des_r2.push(src[1]);
                }
            }
        }

        // reserve buffer
        self.r_t
            .resize(self.remaining + amount * (self.threshold + 1), F::default());
        self.r_2t
            .resize(self.remaining + amount * (self.threshold + 1), F::default());

        // Now make vandermonde multiplication
        let r_t_chunks = self.r_t[self.remaining..].chunks_exact_mut(self.threshold + 1);
        let r_2t_chunks = self.r_2t[self.remaining..].chunks_exact_mut(self.threshold + 1);

        for (r_t_des, r_2t_des, r_t_src, r_2t_src) in
            izip!(r_t_chunks, r_2t_chunks, rcv_rt, rcv_r2t)
        {
            Self::vandermonde_mul(&r_t_src, r_t_des, self.num_parties, self.threshold);
            Self::vandermonde_mul(&r_2t_src, r_2t_des, self.num_parties, self.threshold);
        }
        self.remaining += amount * (self.threshold + 1);

        Ok(())
    }

    fn get_pair<N: GSZNetwork>(&mut self, network: &mut N) -> std::io::Result<(F, F)> {
        if self.remaining == 0 {
            self.buffer_triples(network, Self::BATCH_SIZE)?;
            debug_assert_eq!(self.remaining, Self::BATCH_SIZE * (self.threshold + 1));
            debug_assert_eq!(self.r_t.len(), Self::BATCH_SIZE * (self.threshold + 1));
            debug_assert_eq!(self.r_2t.len(), Self::BATCH_SIZE * (self.threshold + 1));
        }

        let r1 = self.r_t.pop().unwrap();
        let r2 = self.r_2t.pop().unwrap();
        self.remaining -= 1;
        Ok((r1, r2))
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
