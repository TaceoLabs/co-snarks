use self::network::GSZNetwork;
use ark_ff::PrimeField;
use eyre::Report;
use std::marker::PhantomData;

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
    network: N,
    field: PhantomData<F>,
}

impl<F: PrimeField, N: GSZNetwork> GSZProtocol<F, N> {
    pub fn new(network: N) -> Result<Self, Report> {
        Ok(Self {
            network,
            field: PhantomData,
        })
    }
}
