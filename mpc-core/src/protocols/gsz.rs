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
        fieldshare::{GSZPrimeFieldShareSlice, GSZPrimeFieldShareVec},
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
    ) -> GSZPrimeFieldShareVec<F> {
        let shares = Shamir::share(val, num_parties, degree, rng);

        GSZPrimeFieldShareVec::new(shares)
    }

    pub fn combine_field_element<F: PrimeField>(
        shares: GSZPrimeFieldShareSlice<F>,
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
        let rec = Shamir::reconstruct(&shares.a[..=degree], &lagrange);

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
        shares: Vec<GSZPrimeFieldShareSlice<F>>,
        parties: &[usize],
        degree: usize,
    ) -> Result<Vec<F>, Report> {
        if parties.len() <= degree {
            bail!(
                "Not enough parties to reconstruct the secret. Expected {}, got {}",
                degree + 1,
                parties.len()
            );
        }

        let lagrange = Shamir::lagrange_from_coeff(&parties[..=degree]);

        let num_vals = shares.len();
        let mut result = Vec::with_capacity(num_vals);

        for share in shares {
            if share.len() != parties.len() {
                bail!(
                    "Number of shares ({}) does not match number of party indices ({})",
                    share.len(),
                    parties.len()
                );
            }

            let rec = Shamir::reconstruct(&share.a[..=degree], &lagrange);
            result.push(rec);
        }
        Ok(result)
    }

    // pub fn share_curve_point<C: CurveGroup, R: Rng + CryptoRng>(
    //     val: C,
    //     rng: &mut R,
    // ) -> [Aby3PointShare<C>; 3] {
    //     let a = C::rand(rng);
    //     let b = C::rand(rng);
    //     let c = val - a - b;
    //     let share1 = Aby3PointShare::new(a, c);
    //     let share2 = Aby3PointShare::new(b, a);
    //     let share3 = Aby3PointShare::new(c, b);
    //     [share1, share2, share3]
    // }

    // pub fn combine_curve_point<C: CurveGroup>(
    //     share1: Aby3PointShare<C>,
    //     share2: Aby3PointShare<C>,
    //     share3: Aby3PointShare<C>,
    // ) -> C {
    //     share1.a + share2.a + share3.a
    // }
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
