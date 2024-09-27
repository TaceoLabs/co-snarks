//! # Shamir Protocol
//!
//! This module contains an implementation of semi-honest n-party [Shamir secret sharing](https://www.iacr.org/archive/crypto2007/46220565/46220565.pdf).

use self::{
    fieldshare::{ShamirPrimeFieldShare, ShamirPrimeFieldShareVec},
    network::ShamirNetwork,
    pointshare::ShamirPointShare,
    shamir_core::ShamirCore,
};
use crate::{
    traits::{
        EcMpcProtocol, FFTProvider, FieldShareVecTrait, MSMProvider, PairingEcMpcProtocol,
        PrimeFieldMpcProtocol,
    },
    RngType,
};
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::PrimeField;
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, Polynomial};
use eyre::{bail, Report};
use itertools::{izip, Itertools};
use rand::{Rng as _, SeedableRng};
use std::marker::PhantomData;

pub mod fieldshare;
pub mod network;
pub mod pointshare;
pub(crate) mod shamir_core;

/// # Shamir Utils
/// This module contains utility functions to work with Shamir secret sharing. I.e., it contains code to share field elements and curve points, as well as code to reconstruct the secret-shares.
pub mod utils {
    use self::{
        fieldshare::{ShamirPrimeFieldShare, ShamirPrimeFieldShareVec},
        pointshare::ShamirPointShare,
        shamir_core::ShamirCore,
    };
    use super::*;
    use ark_ec::CurveGroup;
    use ark_ff::PrimeField;
    use eyre::bail;
    use itertools::izip;
    use rand::{CryptoRng, Rng};

    /// Secret shares a field element using Shamir secret sharing and the provided random number generator. The field element is split into num_parties shares, where each party holds just one. The outputs are of type [ShamirPrimeFieldShare]. The degree of the sharing polynomial (i.e., the threshold of maximum number of tolerated colluding parties) is specified by the degree parameter.
    pub fn share_field_element<F: PrimeField, R: Rng + CryptoRng>(
        val: F,
        degree: usize,
        num_parties: usize,
        rng: &mut R,
    ) -> Vec<ShamirPrimeFieldShare<F>> {
        let shares = ShamirCore::share(val, num_parties, degree, rng);

        ShamirPrimeFieldShare::convert_vec_rev(shares)
    }

    /// Reconstructs a field element from its Shamir shares and lagrange coefficients. Thereby at least `degree` + 1 shares need to be present.
    pub fn combine_field_element<F: PrimeField>(
        shares: &[ShamirPrimeFieldShare<F>],
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

        let lagrange = ShamirCore::lagrange_from_coeff(&coeffs[..=degree]);
        let shares = ShamirPrimeFieldShare::convert_slice(shares);
        let rec = ShamirCore::reconstruct(&shares[..=degree], &lagrange);

        Ok(rec)
    }

    /// Secret shares a vector of field element using Shamir secret sharing and the provided random number generator. The field elements are split into num_parties shares each, where each party holds just one. The outputs are of type [ShamirPrimeFieldShareVec]. The degree of the sharing polynomial (i.e., the threshold of maximum number of tolerated colluding parties) is specified by the degree parameter.
    pub fn share_field_elements<F: PrimeField, R: Rng + CryptoRng>(
        vals: &[F],
        degree: usize,
        num_parties: usize,
        rng: &mut R,
    ) -> Vec<ShamirPrimeFieldShareVec<F>> {
        let mut result = (0..num_parties)
            .map(|_| ShamirPrimeFieldShareVec::new(Vec::with_capacity(vals.len())))
            .collect::<Vec<_>>();

        for val in vals {
            let shares = ShamirCore::share(*val, num_parties, degree, rng);

            for (r, s) in izip!(&mut result, shares) {
                r.a.push(s);
            }
        }

        result
    }

    /// Reconstructs a vector of field elements from its Shamir shares and lagrange coefficients. The input is structured as one [ShamirPrimeFieldShareVec] per party. Thus, shares\[i\]\[j\] represents the j-th share of party i. Thereby at least `degree` + 1 shares need to be present per field element (i.e., i > degree).
    pub fn combine_field_elements<F: PrimeField>(
        shares: &[ShamirPrimeFieldShareVec<F>],
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

        let lagrange = ShamirCore::lagrange_from_coeff(&coeffs[..=degree]);

        for i in 0..num_vals {
            let s = shares
                .iter()
                .take(degree + 1)
                .map(|s| s.a[i])
                .collect::<Vec<_>>();
            let rec = ShamirCore::reconstruct(&s, &lagrange);
            result.push(rec);
        }
        Ok(result)
    }

    /// Secret shares a curve point using Shamir secret sharing and the provided random number generator. The point is split into num_parties shares, where each party holds just one. The outputs are of type [ShamirPointShare]. The degree of the sharing polynomial (i.e., the threshold of maximum number of tolerated colluding parties) is specified by the degree parameter.
    pub fn share_curve_point<C: CurveGroup, R: Rng + CryptoRng>(
        val: C,
        degree: usize,
        num_parties: usize,
        rng: &mut R,
    ) -> Vec<ShamirPointShare<C>> {
        let shares = ShamirCore::share_point(val, num_parties, degree, rng);

        ShamirPointShare::convert_vec_rev(shares)
    }

    /// Reconstructs a curve point from its Shamir shares and lagrange coefficients. Thereby at least `degree` + 1 shares need to be present.
    pub fn combine_curve_point<C: CurveGroup>(
        shares: &[ShamirPointShare<C>],
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

        let lagrange = ShamirCore::lagrange_from_coeff(&coeffs[..=degree]);
        let shares = ShamirPointShare::convert_slice(shares);
        let rec = ShamirCore::reconstruct_point(&shares[..=degree], &lagrange);

        Ok(rec)
    }
}

/// This struct handles the Shamir MPC protocol, including proof generation. Thus, it implements the [PrimeFieldMpcProtocol], [EcMpcProtocol], [PairingEcMpcProtocol], [FFTProvider], and [MSMProvider] traits.
pub struct ShamirProtocol<F: PrimeField, N: ShamirNetwork> {
    threshold: usize, // degree of the polynomial
    open_lagrange_t: Vec<F>,
    pub(crate) open_lagrange_2t: Vec<F>,
    mul_lagrange_2t: Vec<F>,
    rng_buffer: ShamirRng<F>,
    network: N,
    field: PhantomData<F>,
}

impl<F: PrimeField, N: ShamirNetwork> ShamirProtocol<F, N> {
    const KING_ID: usize = 0;

    /// Constructs the Shamir protocol from an established network. It also requires to specify the threshold t, which defines the maximum tolerated number of corrupted parties. The threshold t is thus equivalent to the degree of the sharing polynomials.
    pub fn new(threshold: usize, network: N) -> Result<Self, Report> {
        let num_parties = network.get_num_parties();

        if 2 * threshold + 1 > num_parties {
            bail!("Threshold too large for number of parties")
        }

        let seed: [u8; crate::SEED_SIZE] = RngType::from_entropy().gen();

        // We send in circles, so we need to receive from the last parties
        let id = network.get_id();
        let open_lagrange_t = ShamirCore::lagrange_from_coeff(
            &(0..threshold + 1)
                .map(|i| (id + num_parties - i) % num_parties + 1)
                .collect::<Vec<_>>(),
        );
        let open_lagrange_2t = ShamirCore::lagrange_from_coeff(
            &(0..2 * threshold + 1)
                .map(|i| (id + num_parties - i) % num_parties + 1)
                .collect::<Vec<_>>(),
        );

        let mul_lagrange_2t =
            ShamirCore::lagrange_from_coeff(&(1..=2 * threshold + 1).collect::<Vec<_>>());

        Ok(Self {
            threshold,
            open_lagrange_t,
            open_lagrange_2t,
            mul_lagrange_2t,
            rng_buffer: ShamirRng::new(seed, threshold, num_parties),
            network,
            field: PhantomData,
        })
    }

    /// This function generates and stores `amount * (threshold + 1)` doubly shared random values, which are required to evaluate the multiplication of two secret shares. Each multiplication consumes one of these preprocessed values.
    pub fn preprocess(&mut self, amount: usize) -> std::io::Result<()> {
        self.rng_buffer.buffer_triples(&mut self.network, amount)
    }

    pub(crate) fn degree_reduce(
        &mut self,
        mut input: F,
    ) -> std::io::Result<<Self as PrimeFieldMpcProtocol<F>>::FieldShare> {
        let (r_t, r_2t) = self.rng_buffer.get_pair(&mut self.network)?;
        input += r_2t;

        let my_id = self.network.get_id();
        let my_share = if my_id == Self::KING_ID {
            // Accumulate the result
            let mut acc = F::zero();
            for (other_id, lagrange) in self.mul_lagrange_2t.iter().enumerate() {
                if other_id == Self::KING_ID {
                    acc += input * lagrange;
                } else {
                    let r = self.network.recv::<F>(other_id)?;
                    acc += r * lagrange;
                }
            }
            // So far parties who do not require sending, do not send, so no receive here

            // Send fresh shares
            let shares = ShamirCore::share(
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
                self.network.send(Self::KING_ID, input)?;
            }
            self.network.recv(Self::KING_ID)?
        };

        Ok(<Self as PrimeFieldMpcProtocol<F>>::FieldShare::new(
            my_share - r_t,
        ))
    }

    pub(crate) fn degree_reduce_vec(
        &mut self,
        mut inputs: Vec<F>,
    ) -> std::io::Result<<Self as PrimeFieldMpcProtocol<F>>::FieldShareVec> {
        let len = inputs.len();
        let mut r_ts = Vec::with_capacity(len);

        for inp in inputs.iter_mut() {
            let (r_t, r_2t) = self.rng_buffer.get_pair(&mut self.network)?;
            *inp += r_2t;
            r_ts.push(r_t);
        }

        let my_id = self.network.get_id();
        let mut my_shares = if my_id == Self::KING_ID {
            // Accumulate the result
            let mut acc = vec![F::zero(); len];
            for (other_id, lagrange) in self.mul_lagrange_2t.iter().enumerate() {
                if other_id == Self::KING_ID {
                    for (acc, muls) in izip!(&mut acc, &inputs) {
                        *acc += *muls * lagrange;
                    }
                } else {
                    let r = self.network.recv_many::<F>(other_id)?;
                    if r.len() != len {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,"During execution of degree_reduce_vec in MPC: Invalid number of elements received",
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
                let s = ShamirCore::share(
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
                self.network.send_many(Self::KING_ID, &inputs)?;
            }
            let r = self.network.recv_many::<F>(Self::KING_ID)?;
            if r.len() != len {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,"During execution of degree_reduce_vec in MPC: Invalid number of elements received",
                ));
            }
            r
        };

        for (share, r) in izip!(&mut my_shares, r_ts) {
            *share -= r;
        }
        Ok(<Self as PrimeFieldMpcProtocol<F>>::FieldShareVec::new(
            my_shares,
        ))
    }

    pub(crate) fn degree_reduce_point<C>(
        &mut self,
        mut input: C,
    ) -> std::io::Result<ShamirPointShare<C>>
    where
        C: CurveGroup + std::ops::Mul<F, Output = C> + for<'a> std::ops::Mul<&'a F, Output = C>,
    {
        let (r_t, r_2t) = self.rng_buffer.get_pair(&mut self.network)?;
        let r_t = C::generator().mul(r_t);
        let r_2t = C::generator().mul(r_2t);

        input += r_2t;
        let my_id = self.network.get_id();

        let my_share = if my_id == Self::KING_ID {
            // Accumulate the result
            let mut acc = C::zero();
            for (other_id, lagrange) in self.mul_lagrange_2t.iter().enumerate() {
                if other_id == Self::KING_ID {
                    acc += input * lagrange;
                } else {
                    let r = self.network.recv::<C>(other_id)?;
                    acc += r * lagrange;
                }
            }
            // So far parties who do not require sending, do not send, so no receive here

            // Send fresh shares
            let shares = ShamirCore::share_point(
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
                self.network.send(Self::KING_ID, input)?;
            }
            self.network.recv(Self::KING_ID)?
        };

        Ok(ShamirPointShare::new(my_share - r_t))
    }
}

impl<F: PrimeField> FieldShareVecTrait for ShamirPrimeFieldShareVec<F> {
    type FieldShare = ShamirPrimeFieldShare<F>;

    fn index(&self, index: usize) -> Self::FieldShare {
        Self::FieldShare {
            a: self.a[index].to_owned(),
        }
    }

    fn set_index(&mut self, val: Self::FieldShare, index: usize) {
        self.a[index] = val.a;
    }

    fn get_len(&self) -> usize {
        self.len()
    }
}

impl<F: PrimeField, N: ShamirNetwork> PrimeFieldMpcProtocol<F> for ShamirProtocol<F, N> {
    type FieldShare = ShamirPrimeFieldShare<F>;
    type FieldShareVec = ShamirPrimeFieldShareVec<F>;

    fn add(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare {
        a + b
    }

    fn sub(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> Self::FieldShare {
        a - b
    }

    fn add_with_public(&mut self, a: &F, b: &Self::FieldShare) -> Self::FieldShare {
        b + a
    }

    fn sub_assign_vec(&mut self, a: &mut Self::FieldShareVec, b: &Self::FieldShareVec) {
        for (a, b) in izip!(a.a.iter_mut(), &b.a) {
            *a -= b;
        }
    }

    fn mul(
        &mut self,
        a: &Self::FieldShare,
        b: &Self::FieldShare,
    ) -> std::io::Result<Self::FieldShare> {
        let mul = a.a * b.a;
        self.degree_reduce(mul)
    }

    fn mul_many(
        &mut self,
        a: &[Self::FieldShare],
        b: &[Self::FieldShare],
    ) -> std::io::Result<Vec<Self::FieldShare>> {
        let mul = a
            .iter()
            .zip(b.iter())
            .map(|(a, b)| a.a * b.a)
            .collect::<Vec<_>>();
        let res = self.degree_reduce_vec(mul)?;
        Ok(ShamirPrimeFieldShare::convert_vec_rev(res.a))
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
                "During execution of inverse in MPC: cannot compute inverse of zero",
            ));
        }
        let y_inv = y.inverse().unwrap();
        Ok(r * y_inv)
    }

    fn inv_many(&mut self, a: &[Self::FieldShare]) -> std::io::Result<Vec<Self::FieldShare>> {
        let r = (0..a.len())
            .map(|_| self.rand())
            .collect::<Result<Vec<_>, _>>()?;
        let y = self.mul_open_many(a, &r)?;
        if y.iter().any(|y| y.is_zero()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "During execution of inverse in MPC: cannot compute inverse of zero",
            ));
        }

        let res = izip!(r, y).map(|(r, y)| r * y.inverse().unwrap()).collect();
        Ok(res)
    }

    fn inv_many_in_place(&mut self, a: &mut [Self::FieldShare]) -> std::io::Result<()> {
        let r = (0..a.len())
            .map(|_| self.rand())
            .collect::<Result<Vec<_>, _>>()?;
        let y = self.mul_open_many(a, &r)?;

        for (a, r, y) in izip!(a.iter_mut(), r, y) {
            if y.is_zero() {
                *a = Self::FieldShare::default();
            } else {
                *a = r * y.inverse().unwrap();
            }
        }

        Ok(())
    }

    fn neg(&mut self, a: &Self::FieldShare) -> Self::FieldShare {
        -a
    }

    fn neg_vec_in_place(&mut self, vec: &mut Self::FieldShareVec) {
        for a in vec.a.iter_mut() {
            a.neg_in_place();
        }
    }

    fn neg_vec_in_place_limit(&mut self, vec: &mut Self::FieldShareVec, limit: usize) {
        for a in vec.a.iter_mut().take(limit) {
            a.neg_in_place();
        }
    }

    fn rand(&mut self) -> std::io::Result<Self::FieldShare> {
        let (r, _) = self.rng_buffer.get_pair(&mut self.network)?;
        Ok(Self::FieldShare::new(r))
    }

    fn open(&mut self, a: &Self::FieldShare) -> std::io::Result<F> {
        let rcv = self.network.broadcast_next(a.a, self.threshold + 1)?;
        let res = ShamirCore::reconstruct(&rcv, &self.open_lagrange_t);
        Ok(res)
    }

    fn open_many(&mut self, a: &[Self::FieldShare]) -> std::io::Result<Vec<F>> {
        let a_a = ShamirPrimeFieldShare::convert_slice(a);

        let rcv = self
            .network
            .broadcast_next(a_a.to_owned(), self.threshold + 1)?;

        let mut transposed = vec![vec![F::zero(); self.threshold + 1]; a.len()];

        for (j, r) in rcv.into_iter().enumerate() {
            for (i, val) in r.into_iter().enumerate() {
                transposed[i][j] = val;
            }
        }

        let res = transposed
            .into_iter()
            .map(|r| ShamirCore::reconstruct(&r, &self.open_lagrange_t))
            .collect();
        Ok(res)
    }

    fn add_vec(&mut self, a: &Self::FieldShareVec, b: &Self::FieldShareVec) -> Self::FieldShareVec {
        Self::FieldShareVec {
            a: a.a.iter().zip(b.a.iter()).map(|(a, b)| *a + b).collect(),
        }
    }

    fn mul_vec(
        &mut self,
        a: &Self::FieldShareVec,
        b: &Self::FieldShareVec,
    ) -> std::io::Result<Self::FieldShareVec> {
        let len = a.len();
        debug_assert_eq!(len, b.len());
        let mut muls = Vec::with_capacity(len);

        for (a, b) in izip!(a.a.iter(), b.a.iter()) {
            let mul = *a * b;
            muls.push(mul);
        }
        self.degree_reduce_vec(muls)
    }

    fn promote_to_trivial_share(&self, public_value: F) -> Self::FieldShare {
        Self::FieldShare::new(public_value)
    }

    fn promote_to_trivial_shares(&self, public_values: &[F]) -> Self::FieldShareVec {
        let shares = public_values.to_owned();
        Self::FieldShareVec::new(shares)
    }

    fn distribute_powers_and_mul_by_const(&mut self, coeffs: &mut Self::FieldShareVec, g: F, c: F) {
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
        private_witness: &Self::FieldShareVec,
    ) -> Self::FieldShare {
        let mut acc = ShamirPrimeFieldShare::default();
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
        dst: &mut Self::FieldShareVec,
        src: &Self::FieldShareVec,
        dst_offset: usize,
        src_offset: usize,
        len: usize,
    ) {
        assert!(dst.a.len() >= dst_offset + len);
        assert!(src.a.len() >= src_offset + len);
        assert!(len > 0);
        dst.a[dst_offset..dst_offset + len].clone_from_slice(&src.a[src_offset..src_offset + len]);
    }

    /// This function performs a multiplication directly followed by an opening. This is preferred over Open(Mul(\[x\], \[y\])), since Mul performs resharing of the result for degree reduction. Thus, mul_open(\[x\], \[y\]) requires less communication in fewer rounds compared to Open(Mul(\[x\], \[y\])).
    fn mul_open(&mut self, a: &Self::FieldShare, b: &Self::FieldShare) -> std::io::Result<F> {
        let mul = a * b;
        let rcv = self.network.broadcast_next(mul.a, 2 * self.threshold + 1)?;
        let res = ShamirCore::reconstruct(&rcv, &self.open_lagrange_2t);
        Ok(res)
    }

    /// This function performs a multiplication directly followed by an opening. This is preferred over Open(Mul(\[x\], \[y\])), since Mul performs resharing of the result for degree reduction. Thus, mul_open(\[x\], \[y\]) requires less communication in fewer rounds compared to Open(Mul(\[x\], \[y\])).
    fn mul_open_many(
        &mut self,
        a: &[Self::FieldShare],
        b: &[Self::FieldShare],
    ) -> std::io::Result<Vec<F>> {
        let mul = a
            .iter()
            .zip(b.iter())
            .map(|(a, b)| a * b)
            .collect::<Vec<_>>();
        let mul = ShamirPrimeFieldShare::convert_vec(mul);

        let rcv = self.network.broadcast_next(mul, 2 * self.threshold + 1)?;

        let mut transposed = vec![vec![F::zero(); 2 * self.threshold + 1]; a.len()];

        for (j, r) in rcv.into_iter().enumerate() {
            for (i, val) in r.into_iter().enumerate() {
                transposed[i][j] = val;
            }
        }

        let res = transposed
            .into_iter()
            .map(|r| ShamirCore::reconstruct(&r, &self.open_lagrange_2t))
            .collect();
        Ok(res)
    }
}

impl<C: CurveGroup, N: ShamirNetwork> EcMpcProtocol<C> for ShamirProtocol<C::ScalarField, N> {
    type PointShare = ShamirPointShare<C>;

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
        let mul = (b * a).a;
        self.degree_reduce_point(mul)
    }

    fn open_point(&mut self, a: &Self::PointShare) -> std::io::Result<C> {
        let rcv = self.network.broadcast_next(a.a, self.threshold + 1)?;
        let res = ShamirCore::reconstruct_point(&rcv, &self.open_lagrange_t);
        Ok(res)
    }

    fn open_point_many(&mut self, a: &[Self::PointShare]) -> std::io::Result<Vec<C>> {
        let a_a = ShamirPointShare::convert_slice(a);

        let rcv = self
            .network
            .broadcast_next(a_a.to_owned(), self.threshold + 1)?;

        let mut transposed = vec![vec![C::zero(); self.threshold + 1]; a.len()];

        for (j, r) in rcv.into_iter().enumerate() {
            for (i, val) in r.into_iter().enumerate() {
                transposed[i][j] = val;
            }
        }

        let res = transposed
            .into_iter()
            .map(|r| ShamirCore::reconstruct_point(&r, &self.open_lagrange_t))
            .collect();
        Ok(res)
    }
}

impl<P: Pairing, N: ShamirNetwork> PairingEcMpcProtocol<P> for ShamirProtocol<P::ScalarField, N> {
    fn open_two_points(
        &mut self,
        a: &<Self as EcMpcProtocol<P::G1>>::PointShare,
        b: &<Self as EcMpcProtocol<P::G2>>::PointShare,
    ) -> std::io::Result<(P::G1, P::G2)> {
        let s1 = a.a;
        let s2 = b.a;

        let rcv: Vec<(P::G1, P::G2)> = self.network.broadcast_next((s1, s2), self.threshold + 1)?;
        let (r1, r2): (Vec<P::G1>, Vec<P::G2>) = rcv.into_iter().unzip();

        let r1 = ShamirCore::reconstruct_point(&r1, &self.open_lagrange_t);
        let r2 = ShamirCore::reconstruct_point(&r2, &self.open_lagrange_t);

        Ok((r1, r2))
    }
}

impl<F: PrimeField, N: ShamirNetwork> FFTProvider<F> for ShamirProtocol<F, N> {
    fn fft<D: EvaluationDomain<F>>(
        &mut self,
        data: Self::FieldShareVec,
        domain: &D,
    ) -> Self::FieldShareVec {
        tracing::trace!("> FFT for {} elements", data.len());
        let a = domain.fft(&data.a);
        tracing::trace!("< FFT for {} elements", data.len());
        Self::FieldShareVec::new(a)
    }

    fn fft_in_place<D: EvaluationDomain<F>>(&mut self, data: &mut Self::FieldShareVec, domain: &D) {
        tracing::trace!("> FFT (in place) for {} elements", data.len());
        domain.fft_in_place(&mut data.a);
        tracing::trace!("< FFT (in place) for {} elements", data.len());
    }

    fn ifft<D: EvaluationDomain<F>>(
        &mut self,
        data: &Self::FieldShareVec,
        domain: &D,
    ) -> Self::FieldShareVec {
        tracing::trace!("> IFFT for {} elements", data.len());
        let a = domain.ifft(&data.a);
        tracing::trace!("< IFFT for {} elements", data.len());
        Self::FieldShareVec::new(a)
    }

    fn ifft_in_place<D: EvaluationDomain<F>>(
        &mut self,
        data: &mut Self::FieldShareVec,
        domain: &D,
    ) {
        tracing::trace!("> IFFT (in place) for {} elements", data.len());
        domain.ifft_in_place(&mut data.a);
        tracing::trace!("< IFFT (in place) for {} elements", data.len());
    }

    fn evaluate_poly_public(&mut self, poly: Self::FieldShareVec, point: &F) -> Self::FieldShare {
        tracing::trace!("> evaluate poly public");
        let poly = DensePolynomial { coeffs: poly.a };
        tracing::trace!("< evaluate poly public");
        Self::FieldShare::new(poly.evaluate(point))
    }
}

struct ShamirRng<F> {
    rng: RngType,
    threshold: usize,
    num_parties: usize,
    r_t: Vec<F>,
    r_2t: Vec<F>,
    remaining: usize,
}

impl<F: PrimeField> ShamirRng<F> {
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
    fn buffer_triples<N: ShamirNetwork>(
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
            let shares_t = ShamirCore::share(r, self.num_parties, self.threshold, &mut self.rng);
            let shares_2t =
                ShamirCore::share(r, self.num_parties, 2 * self.threshold, &mut self.rng);

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
                        "During execution of buffer_triples in MPC: Invalid number of elements received",
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

    fn get_pair<N: ShamirNetwork>(&mut self, network: &mut N) -> std::io::Result<(F, F)> {
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

impl<C: CurveGroup, N: ShamirNetwork> MSMProvider<C> for ShamirProtocol<C::ScalarField, N> {
    fn msm_public_points(
        &mut self,
        points: &[C::Affine],
        scalars: &Self::FieldShareVec,
    ) -> Self::PointShare {
        tracing::trace!("> MSM public points for {} elements", points.len());
        debug_assert_eq!(points.len(), scalars.len());
        let res = C::msm_unchecked(points, &scalars.a);
        tracing::trace!("< MSM public points for {} elements", points.len());
        Self::PointShare { a: res }
    }
}
